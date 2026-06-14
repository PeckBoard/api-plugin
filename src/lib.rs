//! Peckboard public API plugin (WASM / Extism).
//!
//! This crate compiles to a `wasm32-unknown-unknown` Extism plugin that owns a
//! public, API-key-authenticated HTTP surface mounted by Peckboard core under
//! `/plugin-api/*`. Core does **no** authentication for that prefix — this
//! plugin owns auth (scoped API keys) and dispatch end to end. See
//! `peckboard/docs/architecture/plugins.md` ("HTTP Route Hooks").
//!
//! ## Plugin interface
//!
//! Core expects four exports (`peckboard/src/plugin/manager.rs`):
//!
//! - `manifest` — declares the hooks handled and the `http_routes` owned.
//! - `init` — called once on load with the plugin's `config` block from
//!   `<dataDir>/config.json` (the `plugins.api.config` object); parses API
//!   keys + scopes and stores them. Returns an `{"ok": ...}` envelope.
//! - `handle` — called per hook with `{ "hook", "payload" }`; returns a
//!   `Verdict`. For `http.request.before` the payload is the request and the
//!   returned `Verdict::Allow` payload is the full HTTP response.
//! - `shutdown` — teardown hook; no-op here.
//!
//! ## Auth model
//!
//! Every endpoint except `GET /plugin-api/v1/health` requires a valid API key,
//! presented either as `Authorization: Bearer <key>` or `X-API-Key: <key>`. A
//! missing/unknown key is `401`; a known key lacking the route's required
//! scope (`read` / `write` / `admin`) is `403`. Keys are compared in constant
//! time and never logged.
//!
//! ## Key management (runtime, persisted)
//!
//! Keys are no longer static config — they are a *managed set* persisted via
//! the plugin self-storage host functions under the setting key
//! [`SETTING_KEYS`]. On first run the managed set is **seeded** from the
//! `keys` in the plugin config (so existing config keys keep working); after
//! that, config `keys` no longer change the live set. Secrets are stored
//! **hashed** (SHA-256) — the plaintext is shown exactly once, on create, and
//! otherwise only as a short non-secret prefix.
//!
//! The management surface lives under `/plugin-api/v1/keys` and requires the
//! `admin` scope (a plain `read`/`write` key cannot manage keys). A config
//! `bootstrap_admin_key` is an always-valid break-glass that grants full
//! `[read, write, admin]`, so an operator can never lock themselves out.

use std::collections::BTreeMap;
use std::sync::Mutex;

use extism_pdk::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Data-access host functions provided by Peckboard core
/// (`peckboard/src/plugin/host.rs`). Each is JSON-string-in / JSON-string-out
/// and returns an `{"error": "..."}` envelope instead of trapping. They are
/// generic and **not** scope-aware — scope enforcement is this plugin's job.
/// The `*_plugin_setting` functions are namespaced by core to this plugin's
/// own id, giving the plugin durable private storage for its managed key set.
#[host_fn]
extern "ExtismHost" {
    /// `{}` → `{"projects": [...]}`.
    fn peckboard_list_projects(input: String) -> String;
    /// `{"project_id"?, "step"?}` → `{"cards": [...]}`.
    fn peckboard_list_cards(input: String) -> String;
    /// `{"project_id", "title", ...}` → `{"card": {...}}`.
    fn peckboard_create_card(input: String) -> String;
    /// `{"key"}` → `{"value": <json|null>}` (this plugin's own namespace).
    fn peckboard_get_plugin_setting(input: String) -> String;
    /// `{"key", "value"}` → `{"ok": true}`; a `null` value deletes the key.
    fn peckboard_set_plugin_setting(input: String) -> String;
}

// WASI imports the Extism host provides (core loads plugins with WASI
// enabled — `Plugin::new(manifest, functions, true)`). The sandbox has no
// other source of entropy or wall-clock time, so generated key secrets and
// `created` timestamps come from here. Both return a WASI errno (`0` = ok).
#[link(wasm_import_module = "wasi_snapshot_preview1")]
unsafe extern "C" {
    /// Fill `buf[0..buf_len]` with cryptographically secure random bytes.
    fn random_get(buf: *mut u8, buf_len: usize) -> i32;
    /// Write the current time (nanoseconds) for clock `id` to `*time`.
    /// `id = 0` is the realtime clock.
    fn clock_time_get(id: u32, precision: u64, time: *mut u64) -> i32;
}

/// Routes this plugin owns. Each is `"<METHOD> <PATH>"`. Core only dispatches
/// a request to this plugin when the method+path matches an entry here, so the
/// dispatch table in [`serve_http`] and this list must stay in sync.
const ROUTES: &[&str] = &[
    "GET /plugin-api/v1/health",
    "GET /plugin-api/v1/projects",
    "GET /plugin-api/v1/cards",
    "POST /plugin-api/v1/cards",
    "GET /plugin-api/v1/keys",
    "POST /plugin-api/v1/keys",
    "DELETE /plugin-api/v1/keys/:id",
];

/// Scope required to read data.
const SCOPE_READ: &str = "read";
/// Scope required to mutate data.
const SCOPE_WRITE: &str = "write";
/// Scope required to manage API keys (list/create/revoke).
const SCOPE_ADMIN: &str = "admin";

/// The scopes a key may carry. Unknown scopes are rejected on create.
const KNOWN_SCOPES: &[&str] = &[SCOPE_READ, SCOPE_WRITE, SCOPE_ADMIN];

/// The self-storage setting key under which the managed key set is persisted
/// (a JSON array of [`StoredKey`]). Namespaced to this plugin by core.
const SETTING_KEYS: &str = "managed_keys";

/// Prefix on generated key secrets — "peckboard api". Purely cosmetic; helps
/// an operator recognise a Peckboard API key at a glance.
const KEY_PREFIX: &str = "pba_";

/// A seed API key from config: the plaintext secret and the scopes it grants.
/// Only used to bootstrap the managed set on first run (see [`seed_keys`]); it
/// is never the live source of truth after seeding.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKey {
    key: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    label: Option<String>,
}

/// A managed key as persisted in self-storage. The secret itself is **not**
/// stored — only its SHA-256 `hash` (hex) and a non-secret `prefix` for
/// masked display. `id` is the opaque handle used to revoke it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    /// Hex SHA-256 of the secret. The plaintext is never persisted.
    hash: String,
    /// A short non-secret prefix of the secret, for masked display.
    #[serde(default)]
    prefix: String,
    /// Unix seconds the key was created/seeded.
    #[serde(default)]
    created: i64,
}

/// The authenticated identity a request resolved to: the scopes it may use.
struct Identity {
    scopes: Vec<String>,
}

impl Identity {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Parsed per-plugin config (the `plugins.api.config` object from
/// `config.json`). `keys` seed the managed set on first run;
/// `bootstrap_admin_key` is an always-valid break-glass admin secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApiConfig {
    #[serde(default)]
    keys: Vec<ApiKey>,
    #[serde(default)]
    bootstrap_admin_key: Option<String>,
}

/// Config parsed in `init` and read by `handle`. The WASM instance is reused
/// across calls for a loaded plugin, so this static persists between exports.
static CONFIG: Mutex<Option<ApiConfig>> = Mutex::new(None);

/// Snapshot the current config (cheap clone; key lists are tiny).
fn config_snapshot() -> ApiConfig {
    CONFIG
        .lock()
        .ok()
        .and_then(|c| c.clone())
        .unwrap_or_default()
}

/// `manifest` — declare the hooks handled and the routes owned.
#[plugin_fn]
pub fn manifest() -> FnResult<String> {
    let manifest = serde_json::json!({
        "hooks": ["http.request.before"],
        "http_routes": ROUTES,
    });
    Ok(manifest.to_string())
}

/// `init` — parse and store the per-plugin config block core passes in.
/// Returns an `{"ok": ...}` envelope; an unparseable config is reported as
/// `{"ok": false, "error": ...}` rather than trapping.
#[plugin_fn]
pub fn init(config: String) -> FnResult<String> {
    let trimmed = config.trim();
    let cfg: ApiConfig = if trimmed.is_empty() || trimmed == "{}" {
        ApiConfig::default()
    } else {
        match serde_json::from_str(trimmed) {
            Ok(c) => c,
            Err(e) => {
                return Ok(serde_json::json!({
                    "ok": false,
                    "error": format!("invalid plugin config: {e}"),
                })
                .to_string());
            }
        }
    };

    let key_count = cfg.keys.len();
    *CONFIG.lock().unwrap() = Some(cfg);

    Ok(serde_json::json!({ "ok": true, "keys": key_count }).to_string())
}

/// The `{ "hook", "payload" }` envelope core passes to `handle`.
#[derive(Debug, Deserialize)]
struct HookCall {
    hook: String,
    #[serde(default)]
    payload: serde_json::Value,
}

/// `handle` — dispatch on hook name. Returns a `Verdict` JSON string.
#[plugin_fn]
pub fn handle(input: String) -> FnResult<String> {
    let call: HookCall = serde_json::from_str(&input)?;

    match call.hook.as_str() {
        "http.request.before" => Ok(serve_http(call.payload)),
        // Any other hook: this plugin has no opinion.
        _ => Ok(serde_json::json!({ "verdict": "skip" }).to_string()),
    }
}

/// The plugin-served HTTP request (the `http.request.before` payload). Mirrors
/// core's `PluginHttpRequest` (`peckboard/src/plugin/hooks.rs`). Header keys
/// arrive lowercased.
#[derive(Debug, Default, Deserialize)]
struct HttpRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: String,
    /// Path params core captured from the matched route pattern (e.g. the
    /// `:id` in `DELETE /plugin-api/v1/keys/:id`).
    #[serde(default)]
    params: BTreeMap<String, String>,
}

/// Serve a plugin-owned HTTP request: parse it, route on method+path,
/// enforce scoped API-key auth on everything but `/health`, and return a
/// `Verdict::Allow` carrying the HTTP response.
fn serve_http(payload: serde_json::Value) -> String {
    let req: HttpRequest = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(e) => return error_response(400, format!("malformed request: {e}")),
    };

    let method = req.method.to_ascii_uppercase();
    match (method.as_str(), req.path.as_str()) {
        ("GET", "/plugin-api/v1/health") => health(),

        ("GET", "/plugin-api/v1/projects") => guard(&req, SCOPE_READ, |_| list_projects()),
        ("GET", "/plugin-api/v1/cards") => guard(&req, SCOPE_READ, list_cards),
        ("POST", "/plugin-api/v1/cards") => guard(&req, SCOPE_WRITE, create_card),

        // Key management — admin scope only.
        ("GET", "/plugin-api/v1/keys") => guard(&req, SCOPE_ADMIN, |_| list_keys()),
        ("POST", "/plugin-api/v1/keys") => guard(&req, SCOPE_ADMIN, create_key),
        ("DELETE", path) if is_key_item_path(path) => guard(&req, SCOPE_ADMIN, delete_key),

        // Core only routes declared methods/paths here, so this is defensive.
        _ => error_response(404, "not found"),
    }
}

/// Does `path` address a single managed key (`/plugin-api/v1/keys/<id>`)? Used
/// to dispatch the `DELETE /plugin-api/v1/keys/:id` route, whose dynamic
/// segment can't be matched by a literal tuple arm.
fn is_key_item_path(path: &str) -> bool {
    matches!(
        path.strip_prefix("/plugin-api/v1/keys/"),
        Some(rest) if !rest.is_empty() && !rest.contains('/')
    )
}

/// Authenticate + scope-check, then run `handler`. Centralizes the 401/403
/// policy so every protected route enforces it identically. Loads the managed
/// key set (seeding it from config on first run) for the auth check.
fn guard(
    req: &HttpRequest,
    required_scope: &str,
    handler: impl FnOnce(&HttpRequest) -> String,
) -> String {
    let cfg = config_snapshot();
    let keys = match load_keys() {
        Ok(k) => k,
        Err(e) => return error_response(500, format!("key store error: {e}")),
    };
    let identity = match authenticate(&cfg, &keys, &req.headers) {
        Some(id) => id,
        None => return unauthorized(),
    };
    if !identity.has_scope(required_scope) {
        return error_response(
            403,
            format!("api key is not authorized for scope '{required_scope}'"),
        );
    }
    handler(req)
}

/// Resolve the API key a request presents, if any, to an [`Identity`].
///
/// The key may be presented as `Authorization: Bearer <key>` or `X-API-Key:
/// <key>`. The config `bootstrap_admin_key` (plaintext) is checked first and
/// grants full `[read, write, admin]`; otherwise the presented key is hashed
/// and matched against the managed set's stored hashes. Returns `None` when
/// no key is presented or it matches nothing. Comparisons are constant time
/// and do not short-circuit across the set.
fn authenticate(
    cfg: &ApiConfig,
    keys: &[StoredKey],
    headers: &BTreeMap<String, String>,
) -> Option<Identity> {
    let presented = presented_key(headers)?;

    // Break-glass bootstrap admin: a plaintext, always-valid full-access key.
    if let Some(admin) = cfg.bootstrap_admin_key.as_deref() {
        let admin = admin.trim();
        if !admin.is_empty() && constant_time_eq(admin.as_bytes(), presented.as_bytes()) {
            return Some(Identity {
                scopes: vec![
                    SCOPE_READ.to_string(),
                    SCOPE_WRITE.to_string(),
                    SCOPE_ADMIN.to_string(),
                ],
            });
        }
    }

    let presented_hash = sha256_hex(presented.as_bytes());
    let presented_hash = presented_hash.as_bytes();
    let mut matched: Option<&StoredKey> = None;
    for k in keys {
        if constant_time_eq(k.hash.as_bytes(), presented_hash) {
            matched = Some(k);
        }
    }
    matched.map(|k| Identity {
        scopes: k.scopes.clone(),
    })
}

/// Extract the raw key a request presents from its headers (lowercased keys),
/// preferring `Authorization: Bearer <key>` over `X-API-Key: <key>`. Returns
/// `None` for a missing/blank value.
fn presented_key(headers: &BTreeMap<String, String>) -> Option<String> {
    if let Some(auth) = headers.get("authorization")
        && let Some((scheme, rest)) = auth.trim().split_once(' ')
        && scheme.eq_ignore_ascii_case("bearer")
        && !rest.trim().is_empty()
    {
        return Some(rest.trim().to_string());
    }
    if let Some(key) = headers.get("x-api-key") {
        let key = key.trim();
        if !key.is_empty() {
            return Some(key.to_string());
        }
    }
    None
}

/// Length-checked constant-time byte comparison. Differing lengths return
/// `false` immediately (a key's length is not a meaningful secret); equal
/// lengths are compared without an early exit so timing does not reveal how
/// many leading bytes matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- Endpoint handlers ----------------------------------------------------

/// `GET /plugin-api/v1/health` — liveness, no auth.
///
/// Reports how many keys exist and whether the managed set has been seeded.
/// This is side-effect free: it does **not** seed (an unauthenticated request
/// shouldn't trigger a write), so before the first managed access it reports
/// the config seed count with `"seeded": false`.
fn health() -> String {
    let (keys, seeded) = match host_get_setting(SETTING_KEYS) {
        Ok(serde_json::Value::Array(arr)) => (arr.len(), true),
        _ => (config_snapshot().keys.len(), false),
    };
    ok_response(serde_json::json!({
        "status": "ok",
        "plugin": "api",
        "version": env!("CARGO_PKG_VERSION"),
        "keys": keys,
        "seeded": seeded,
    }))
}

// ---- Key management -------------------------------------------------------

/// `GET /plugin-api/v1/keys` [admin] — list managed keys. Never returns a
/// secret or its hash, only the masked prefix and metadata.
fn list_keys() -> String {
    let keys = match load_keys() {
        Ok(k) => k,
        Err(e) => return error_response(500, format!("key store error: {e}")),
    };
    let out: Vec<serde_json::Value> = keys.iter().map(stored_key_view).collect();
    ok_response(serde_json::json!({ "keys": out }))
}

/// Body of `POST /plugin-api/v1/keys`.
#[derive(Debug, Default, Deserialize)]
struct CreateKeyBody {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

/// `POST /plugin-api/v1/keys` [admin] — mint a new key. Generates the secret,
/// stores only its hash, and returns the **full secret once** in the response.
fn create_key(req: &HttpRequest) -> String {
    let trimmed = req.body.trim();
    let body: CreateKeyBody = if trimmed.is_empty() {
        CreateKeyBody::default()
    } else {
        match serde_json::from_str(trimmed) {
            Ok(b) => b,
            Err(e) => return error_response(400, format!("invalid JSON body: {e}")),
        }
    };

    // Validate scopes: at least one, all known. Dedupe while preserving order.
    let mut scopes: Vec<String> = Vec::new();
    for s in &body.scopes {
        let s = s.trim();
        if !KNOWN_SCOPES.contains(&s) {
            return error_response(
                400,
                format!("unknown scope '{s}' (allowed: read, write, admin)"),
            );
        }
        if !scopes.iter().any(|e| e == s) {
            scopes.push(s.to_string());
        }
    }
    if scopes.is_empty() {
        return error_response(
            400,
            "scopes is required (one or more of read, write, admin)",
        );
    }

    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let mut keys = match load_keys() {
        Ok(k) => k,
        Err(e) => return error_response(500, format!("key store error: {e}")),
    };

    let secret = match gen_secret() {
        Some(s) => s,
        None => return error_response(500, "failed to generate key material"),
    };
    let id = match gen_id(&keys) {
        Some(id) => id,
        None => return error_response(500, "failed to generate key id"),
    };

    let stored = StoredKey {
        id,
        label,
        scopes,
        hash: sha256_hex(secret.as_bytes()),
        prefix: mask(&secret),
        created: now_unix_secs(),
    };
    keys.push(stored.clone());
    if let Err(e) = save_keys(&keys) {
        return error_response(500, format!("failed to persist key: {e}"));
    }

    // Return the full secret exactly once, alongside the stored view.
    let mut view = stored_key_view(&stored);
    if let serde_json::Value::Object(map) = &mut view {
        map.insert("key".to_string(), serde_json::json!(secret));
    }
    response(201, view)
}

/// `DELETE /plugin-api/v1/keys/:id` [admin] — revoke a key by id.
fn delete_key(req: &HttpRequest) -> String {
    let id = req
        .params
        .get("id")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        // Fall back to parsing the path if core didn't supply the param.
        .or_else(|| {
            req.path
                .strip_prefix("/plugin-api/v1/keys/")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
    let id = match id {
        Some(id) => id,
        None => return error_response(400, "missing key id"),
    };

    let mut keys = match load_keys() {
        Ok(k) => k,
        Err(e) => return error_response(500, format!("key store error: {e}")),
    };
    let before = keys.len();
    keys.retain(|k| k.id != id);
    if keys.len() == before {
        return error_response(404, format!("no key with id '{id}'"));
    }
    if let Err(e) = save_keys(&keys) {
        return error_response(500, format!("failed to persist key set: {e}"));
    }
    ok_response(serde_json::json!({ "deleted": id }))
}

/// The non-secret JSON view of a managed key (no secret, no hash).
fn stored_key_view(k: &StoredKey) -> serde_json::Value {
    serde_json::json!({
        "id": k.id,
        "label": k.label,
        "scopes": k.scopes,
        "created": format_unix_utc(k.created),
        "masked": k.prefix,
    })
}

/// `GET /plugin-api/v1/projects` [read].
fn list_projects() -> String {
    match unsafe { peckboard_list_projects("{}".to_string()) } {
        Ok(out) => host_read_response(out),
        Err(e) => error_response(500, format!("host error: {e}")),
    }
}

/// `GET /plugin-api/v1/cards?project_id=&step=` [read].
fn list_cards(req: &HttpRequest) -> String {
    let params = parse_query(&req.query);
    let mut body = serde_json::Map::new();
    if let Some(pid) = params.get("project_id") {
        body.insert("project_id".to_string(), serde_json::json!(pid));
    }
    if let Some(step) = params.get("step") {
        body.insert("step".to_string(), serde_json::json!(step));
    }
    let input = serde_json::Value::Object(body).to_string();

    match unsafe { peckboard_list_cards(input) } {
        Ok(out) => host_read_response(out),
        Err(e) => error_response(500, format!("host error: {e}")),
    }
}

/// `POST /plugin-api/v1/cards` [write] — validate the JSON body, then create.
fn create_card(req: &HttpRequest) -> String {
    let body: serde_json::Value = match serde_json::from_str(req.body.trim()) {
        Ok(v @ serde_json::Value::Object(_)) => v,
        Ok(_) => return error_response(400, "request body must be a JSON object"),
        Err(e) => return error_response(400, format!("invalid JSON body: {e}")),
    };

    let title = field_str(&body, "title");
    if title.is_empty() {
        return error_response(400, "title is required");
    }
    let project_id = field_str(&body, "project_id");
    if project_id.is_empty() {
        return error_response(400, "project_id is required");
    }

    match unsafe { peckboard_create_card(body.to_string()) } {
        Ok(out) => create_card_response(out),
        Err(e) => error_response(500, format!("host error: {e}")),
    }
}

/// Read a top-level string field, trimmed; `""` if absent or non-string.
fn field_str(obj: &serde_json::Value, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Map a read host-fn result (`{"projects"|"cards": ...}` or `{"error": ...}`)
/// to an HTTP response: data → 200, error envelope → 500 (these reads take no
/// client input that could be at fault), invalid JSON → 500.
fn host_read_response(out: String) -> String {
    match serde_json::from_str::<serde_json::Value>(&out) {
        Ok(v) if v.get("error").is_some() => response(500, v),
        Ok(v) => response(200, v),
        Err(e) => error_response(500, format!("host returned invalid json: {e}")),
    }
}

/// Map `peckboard_create_card`'s result to an HTTP response: `{"card": ...}` →
/// 201; an `{"error": ...}` envelope → 404 for a missing project, else 400
/// (the errors are client-caused: bad priority/workflow/title); invalid JSON
/// → 500.
fn create_card_response(out: String) -> String {
    match serde_json::from_str::<serde_json::Value>(&out) {
        Ok(v) => {
            if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
                let status = if err.contains("not found") { 404 } else { 400 };
                error_response(status, err)
            } else {
                response(201, v)
            }
        }
        Err(e) => error_response(500, format!("host returned invalid json: {e}")),
    }
}

// ---- Query parsing --------------------------------------------------------

/// Parse a raw `a=1&b=2` query string into a map, percent- and `+`-decoding
/// keys and values. Later duplicates win. Keys without `=` map to `""`.
fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

/// Minimal `application/x-www-form-urlencoded` decode: `+` → space and
/// `%XX` → byte; a malformed `%` escape is left verbatim. Lossy UTF-8.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---- Key store (self-storage host functions) ------------------------------

/// Load the managed key set, seeding it from config on first run.
///
/// Reads the [`SETTING_KEYS`] self-storage value. A `null` (unset) value means
/// the store has never been seeded — [`seed_keys`] migrates the config keys in
/// and persists them. Otherwise the stored JSON array is parsed.
fn load_keys() -> Result<Vec<StoredKey>, String> {
    let value = host_get_setting(SETTING_KEYS)?;
    if value.is_null() {
        return seed_keys();
    }
    serde_json::from_value(value).map_err(|e| format!("corrupt managed key store: {e}"))
}

/// Seed (bootstrap) the managed set from the config `keys` and persist it.
/// Runs exactly once — afterwards the persisted array (even if empty) is no
/// longer `null`, so this is not re-entered and config `keys` edits stop
/// affecting the live set.
fn seed_keys() -> Result<Vec<StoredKey>, String> {
    let cfg = config_snapshot();
    let mut keys: Vec<StoredKey> = Vec::new();
    let now = now_unix_secs();
    for ck in &cfg.keys {
        let secret = ck.key.trim();
        if secret.is_empty() {
            continue;
        }
        let hash = sha256_hex(secret.as_bytes());
        // Skip duplicates (same secret listed twice in config).
        if keys.iter().any(|k| k.hash == hash) {
            continue;
        }
        let id = gen_id(&keys).ok_or("failed to generate key id while seeding")?;
        keys.push(StoredKey {
            id,
            label: ck.label.clone(),
            // Keep config scopes verbatim; data routes only honour known ones.
            scopes: ck.scopes.clone(),
            hash,
            prefix: mask(secret),
            created: now,
        });
    }
    save_keys(&keys)?;
    Ok(keys)
}

/// Persist the managed key set to self-storage.
fn save_keys(keys: &[StoredKey]) -> Result<(), String> {
    let value = serde_json::to_value(keys).map_err(|e| format!("serialize key set: {e}"))?;
    host_set_setting(SETTING_KEYS, value)
}

/// Read one of this plugin's own settings; returns the inner value (or
/// `Value::Null` when unset). Maps an `{"error": ...}` envelope to `Err`.
fn host_get_setting(key: &str) -> Result<serde_json::Value, String> {
    let input = serde_json::json!({ "key": key }).to_string();
    let out = unsafe { peckboard_get_plugin_setting(input) }.map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|e| format!("host returned invalid json: {e}"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    Ok(v.get("value").cloned().unwrap_or(serde_json::Value::Null))
}

/// Write one of this plugin's own settings. Maps an `{"error": ...}` envelope
/// to `Err`.
fn host_set_setting(key: &str, value: serde_json::Value) -> Result<(), String> {
    let input = serde_json::json!({ "key": key, "value": value }).to_string();
    let out = unsafe { peckboard_set_plugin_setting(input) }.map_err(|e| e.to_string())?;
    let v: serde_json::Value =
        serde_json::from_str(&out).map_err(|e| format!("host returned invalid json: {e}"))?;
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    Ok(())
}

// ---- Crypto / entropy / time ----------------------------------------------

/// Hex-encode bytes (lowercase).
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex SHA-256 of `input`.
fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex(hasher.finalize().as_slice())
}

/// A short, non-secret prefix of a secret for masked display. Takes the first
/// 8 characters and appends `…` when the secret is longer.
fn mask(secret: &str) -> String {
    let head: String = secret.chars().take(8).collect();
    if secret.chars().nth(8).is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// `n` cryptographically secure random bytes from the WASI host, or `None` if
/// the host's RNG reports an error (so callers fail closed rather than emit a
/// predictable key).
fn random_bytes(n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let rc = unsafe { random_get(buf.as_mut_ptr(), buf.len()) };
    (rc == 0).then_some(buf)
}

/// Generate a new key secret: `pba_` + 24 random bytes (192 bits) as hex.
fn gen_secret() -> Option<String> {
    let bytes = random_bytes(24)?;
    Some(format!("{KEY_PREFIX}{}", hex(&bytes)))
}

/// Generate an opaque key id (8 random bytes, hex) not colliding with an
/// existing key. Retries a few times before giving up.
fn gen_id(existing: &[StoredKey]) -> Option<String> {
    for _ in 0..8 {
        let id = hex(&random_bytes(8)?);
        if !existing.iter().any(|k| k.id == id) {
            return Some(id);
        }
    }
    None
}

/// Current Unix time in seconds from the WASI realtime clock; `0` if the host
/// clock reports an error (`created` is display-only, so this degrades to the
/// epoch rather than failing the request).
fn now_unix_secs() -> i64 {
    let mut nanos: u64 = 0;
    let rc = unsafe { clock_time_get(0, 0, &mut nanos) };
    if rc != 0 {
        return 0;
    }
    (nanos / 1_000_000_000) as i64
}

/// Format Unix seconds as an RFC 3339 / ISO 8601 UTC string
/// (`YYYY-MM-DDTHH:MM:SSZ`). Pure date arithmetic (Howard Hinnant's
/// `civil_from_days`) so the plugin needs no date-library dependency.
fn format_unix_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3_600, (rem % 3_600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

// ---- Response helpers -----------------------------------------------------

/// Wrap an HTTP response (`status` + JSON `body`) as a `Verdict::Allow`
/// payload, the shape core's `serve_http` expects.
fn response(status: u16, body: serde_json::Value) -> String {
    serde_json::json!({
        "verdict": "allow",
        "payload": {
            "status": status,
            "headers": { "content-type": "application/json" },
            "body": body,
        },
    })
    .to_string()
}

/// A 200 response carrying `body`.
fn ok_response(body: serde_json::Value) -> String {
    response(200, body)
}

/// A JSON `{"error": ...}` response with the given status.
fn error_response(status: u16, message: impl std::fmt::Display) -> String {
    response(status, serde_json::json!({ "error": message.to_string() }))
}

/// A 401 with a `WWW-Authenticate` challenge. Built directly (not via
/// [`response`]) so it can carry the extra header.
fn unauthorized() -> String {
    serde_json::json!({
        "verdict": "allow",
        "payload": {
            "status": 401,
            "headers": {
                "content-type": "application/json",
                "www-authenticate": "Bearer realm=\"plugin-api\""
            },
            "body": { "error": "missing or invalid API key" },
        },
    })
    .to_string()
}

/// `shutdown` — teardown hook. Nothing to clean up.
#[plugin_fn]
pub fn shutdown() -> FnResult<String> {
    Ok("{}".to_string())
}

// NOTE: this crate compiles only to `wasm32-unknown-unknown` — the
// `#[plugin_fn]` / `#[host_fn]` exports and the WASI imports reference host
// functions that don't link on the host target, so there is no native
// `cargo test`. The auth/scope/dispatch and key-management behaviour is
// verified end to end against a real loaded plugin via the curl matrix in this
// card's handoff (no-key→401, wrong-scope→403, valid read→200, valid write→201,
// health unauthenticated, non-admin→403 on /keys, admin create→secret once,
// new key works on data routes, revoke→401), and the self-storage host
// functions are unit-tested in `peckboard/src/plugin/host.rs`.
