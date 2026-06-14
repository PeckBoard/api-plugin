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
//! - `init` — called once on load; parses per-plugin config (API keys +
//!   scopes) and stores it for later calls. Returns ok/error.
//! - `handle` — called per hook with `{ "hook", "payload" }`; returns a
//!   `Verdict`. For `http.request.before` the payload is the request and the
//!   returned `Verdict::Allow` payload is the full HTTP response.
//! - `shutdown` — teardown hook; no-op here.
//!
//! ## Scope of this crate today (scaffold)
//!
//! This is the scaffold: `handle` answers every claimed route with a 200
//! health response. The real key-auth + endpoint dispatch lands in the
//! "API-key auth + public endpoints" card, which extends [`ROUTES`] and
//! replaces [`serve_http`].

use std::sync::Mutex;

use extism_pdk::*;
use serde::{Deserialize, Serialize};

/// Data-access host functions provided by Peckboard core
/// (`peckboard/src/plugin/host.rs`). Only these three are implemented in core
/// today; they are JSON-string-in / JSON-string-out and return an
/// `{"error": "..."}` envelope instead of trapping.
///
/// Declared here so the endpoints card can call them. WASM drops imports that
/// are never referenced, so declaring an unused host fn costs nothing at load
/// time (and avoids an instantiation failure for an import core can't supply).
#[host_fn]
extern "ExtismHost" {
    /// `{}` → `{"projects": [...]}`.
    fn peckboard_list_projects(input: String) -> String;
    /// `{"project_id"?, "step"?}` → `{"cards": [...]}`.
    fn peckboard_list_cards(input: String) -> String;
    /// `{"project_id", "title", ...}` → `{"card": {...}}`.
    fn peckboard_create_card(input: String) -> String;
}

/// Routes this plugin owns. Each is `"<METHOD> <PATH>"`; `:param` segments and
/// a trailing `*name` catch-all are supported by core's matcher. Core only
/// dispatches a request to this plugin if the path matches an entry here.
///
/// The endpoints card extends this list (cards, projects, etc.).
const ROUTES: &[&str] = &["GET /plugin-api/v1/health"];

/// A single API key and the scopes it grants (e.g. `["read"]`,
/// `["read", "write"]`). Mirrors the user's scoped-key design.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKey {
    key: String,
    #[serde(default)]
    scopes: Vec<String>,
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

/// `manifest` — declare the hooks handled and the routes owned. Called by core
/// at load time with an empty input.
#[plugin_fn]
pub fn manifest() -> FnResult<String> {
    let manifest = serde_json::json!({
        "hooks": ["http.request.before"],
        "http_routes": ROUTES,
    });
    Ok(manifest.to_string())
}

/// `init` — parse and store per-plugin config. Returns an `{"ok": ...}`
/// envelope.
///
/// NOTE: core currently calls `init` with `"{}"` — the wiring that passes the
/// real `plugins.api.config` block through is a known core gap (there is no
/// `peckboard_get_config` host fn yet either). We parse defensively so the
/// plugin loads cleanly today and is ready for that config the moment core
/// supplies it.
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

/// Serve a plugin-owned HTTP request.
///
/// Scaffold behaviour: respond 200 with a health body for every claimed route.
/// The endpoints card replaces this with API-key authentication and real
/// per-route dispatch (using the host functions declared above).
fn serve_http(_payload: serde_json::Value) -> String {
    let key_count = CONFIG
        .lock()
        .ok()
        .and_then(|c| c.as_ref().map(|c| c.keys.len()))
        .unwrap_or(0);

    let response = serde_json::json!({
        "status": 200,
        "headers": { "content-type": "application/json" },
        "body": {
            "status": "ok",
            "plugin": "api",
            "version": env!("CARGO_PKG_VERSION"),
            "configured_keys": key_count,
        },
    });

    serde_json::json!({ "verdict": "allow", "payload": response }).to_string()
}

/// `shutdown` — teardown hook. Nothing to clean up.
#[plugin_fn]
pub fn shutdown() -> FnResult<String> {
    Ok("{}".to_string())
}
