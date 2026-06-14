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
//! Every endpoint except `GET /plugin-api/v1/health` requires a configured
//! API key, presented either as `Authorization: Bearer <key>` or `X-API-Key:
//! <key>`. A missing/unknown key is `401`; a known key lacking the route's
//! required scope (`read` / `write`) is `403`. Keys are compared in constant
//! time and never logged.

use std::collections::BTreeMap;
use std::sync::Mutex;

use extism_pdk::*;
use serde::{Deserialize, Serialize};

/// Data-access host functions provided by Peckboard core
/// (`peckboard/src/plugin/host.rs`). Each is JSON-string-in / JSON-string-out
/// and returns an `{"error": "..."}` envelope instead of trapping. They are
/// generic and **not** scope-aware — scope enforcement is this plugin's job.
#[host_fn]
extern "ExtismHost" {
    /// `{}` → `{"projects": [...]}`.
    fn peckboard_list_projects(input: String) -> String;
    /// `{"project_id"?, "step"?}` → `{"cards": [...]}`.
    fn peckboard_list_cards(input: String) -> String;
    /// `{"project_id", "title", ...}` → `{"card": {...}}`.
    fn peckboard_create_card(input: String) -> String;
}

/// Routes this plugin owns. Each is `"<METHOD> <PATH>"`. Core only dispatches
/// a request to this plugin when the method+path matches an entry here, so the
/// dispatch table in [`serve_http`] and this list must stay in sync.
const ROUTES: &[&str] = &[
    "GET /plugin-api/v1/health",
    "GET /plugin-api/v1/projects",
    "GET /plugin-api/v1/cards",
    "POST /plugin-api/v1/cards",
];

/// Scope required to read data.
const SCOPE_READ: &str = "read";
/// Scope required to mutate data.
const SCOPE_WRITE: &str = "write";

/// A single API key and the scopes it grants (e.g. `["read"]`,
/// `["read", "write"]`). `label` is a human name for the key used in
/// operator-facing context; the secret `key` itself is never logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKey {
    key: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    label: Option<String>,
}

impl ApiKey {
    fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Parsed per-plugin config (the `plugins.api.config` object from
/// `config.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ApiConfig {
    #[serde(default)]
    keys: Vec<ApiKey>,
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

        // Core only routes declared methods/paths here, so this is defensive.
        _ => error_response(404, "not found"),
    }
}

/// Authenticate + scope-check, then run `handler`. Centralizes the 401/403
/// policy so every protected route enforces it identically.
fn guard(
    req: &HttpRequest,
    required_scope: &str,
    handler: impl FnOnce(&HttpRequest) -> String,
) -> String {
    let cfg = config_snapshot();
    let key = match authenticate(&cfg, &req.headers) {
        Some(k) => k,
        None => return unauthorized(),
    };
    if !key.has_scope(required_scope) {
        return error_response(
            403,
            format!("api key is not authorized for scope '{required_scope}'"),
        );
    }
    handler(req)
}

/// Resolve the API key a request presents, if any, to a configured key.
///
/// The key may be presented as `Authorization: Bearer <key>` or `X-API-Key:
/// <key>`. Returns the matching [`ApiKey`] (with its scopes), or `None` when
/// no key is presented or the presented key matches nothing. Comparison is
/// constant time and does not short-circuit across the configured set.
fn authenticate<'a>(cfg: &'a ApiConfig, headers: &BTreeMap<String, String>) -> Option<&'a ApiKey> {
    let presented = presented_key(headers)?;
    let presented = presented.as_bytes();

    let mut matched: Option<&ApiKey> = None;
    for k in &cfg.keys {
        if constant_time_eq(k.key.as_bytes(), presented) {
            matched = Some(k);
        }
    }
    matched
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
fn health() -> String {
    let configured_keys = config_snapshot().keys.len();
    ok_response(serde_json::json!({
        "status": "ok",
        "plugin": "api",
        "version": env!("CARGO_PKG_VERSION"),
        "configured_keys": configured_keys,
    }))
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
// `#[plugin_fn]` / `#[host_fn]` exports reference Extism host imports that
// don't link on the host target, so there is no native `cargo test`. The
// auth/scope/dispatch behaviour is verified end to end against a real loaded
// plugin via the curl matrix in this card's handoff (no-key→401,
// wrong-scope→403, valid read→200, valid write→201, health unauthenticated),
// and core's config delivery is unit-tested in
// `peckboard/src/plugin/manager.rs` (`read_plugin_config_*`).
