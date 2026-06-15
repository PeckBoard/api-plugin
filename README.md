# Peckboard Public API Plugin

A self-contained [Extism](https://extism.org) WASM plugin that gives Peckboard a
public, **API-key-authenticated** HTTP surface over its data. Core mounts a
dedicated public prefix `/plugin-api/*` that is **not** behind the `/api/*` auth
middleware; this plugin owns authentication (scoped API keys) and dispatch for
that prefix end to end. Core does no auth and has no knowledge of any specific
endpoint.

See `peckboard/docs/architecture/plugins.md` ("HTTP Route Hooks" and "Plugin
API (Host Functions)") for the full contract.

## Endpoints

All paths are under `/plugin-api/v1`. The scope in brackets is the API-key
scope the route requires (see [Authentication](#authentication)).

| Method & path           | Scope   | Backed by                 | Description                                          |
| ----------------------- | ------- | ------------------------- | --------------------------------------------------- |
| `GET    /health`        | —       | (none)                    | Liveness. No auth.                                  |
| `GET    /projects`      | `read`  | `peckboard_list_projects` | List all projects.                                  |
| `GET    /cards`         | `read`  | `peckboard_list_cards`    | List cards. Optional `?project_id=&step=` filters.  |
| `POST   /cards`         | `write` | `peckboard_create_card`   | Create a card. JSON body (see below).               |
| `GET    /keys`          | `admin` | self-storage              | List managed keys (masked; no secret/hash).         |
| `POST   /keys`          | `admin` | self-storage              | Mint a key `{label?, scopes}`; returns secret once. |
| `DELETE /keys/:id`      | `admin` | self-storage              | Revoke a key by id.                                 |

`POST /cards` body — `project_id` and `title` are required; the rest are
optional and forwarded to core, which validates priority/workflow and that the
project exists (inheriting the project's workflow when none is given):

```json
{ "project_id": "<id>", "title": "My card", "description": "", "priority": 1,
  "step": "backlog", "workflow": "<id>", "model": null, "effort": null }
```

Status codes: `200` (read), `201` (card / key created), `400` (missing/invalid
body or scope), `401` (missing/unknown key), `403` (key lacks the route's
scope), `404` (unknown project / key id, or a path no plugin claims), `500`
(host/data error). Bodies are JSON; errors are `{ "error": "..." }`.

### Key management

Keys are **managed at runtime** and persisted — not read live from config (see
[Configuration](#configuration) for how config seeds them). All three `/keys`
endpoints require the `admin` scope; a plain `read`/`write` key gets `403`.

- `GET /keys` → `{ "keys": [ { "id", "label", "scopes", "created", "masked" } ] }`.
  Secrets and their hashes are **never** returned here — only `masked` (a short
  non-secret prefix like `pba_de72…`).
- `POST /keys` with body `{ "label"?: string, "scopes": ["read"|"write"|"admin", …] }`
  → `201` with the created key view **plus** the full secret in `key`. The
  secret is shown **exactly once** — it is stored only as a SHA-256 hash, so it
  can never be retrieved again. At least one known scope is required; unknown
  scopes are `400`.
- `DELETE /keys/:id` → `200 { "deleted": "<id>" }`, or `404` if no key has that
  id. The revoked key immediately stops authenticating.

Generated secrets look like `pba_` + 48 hex chars (24 random bytes).

## Authentication

Every endpoint except `GET /health` requires a valid API key, presented as
either header:

```
Authorization: Bearer <key>
X-API-Key: <key>
```

`Authorization: Bearer` wins if both are present. A missing or unknown key is
`401`; a known key that lacks the route's required scope is `403`. The
presented key is SHA-256-hashed and compared in constant time against the
stored hashes; the plaintext is never persisted and never written to logs (the
sandbox exposes no log host function today, so the plugin does not log at all).

Scopes are explicit — a key has exactly the scopes it was granted. `admin` does
**not** imply `read`/`write`: an `admin`-only key can manage keys but cannot
call the data routes, and a `read`/`write` key cannot manage keys. The one
exception is the config `bootstrap_admin_key`, which carries full
`[read, write, admin]`.

## Management UI page

The plugin serves its **own** management page — a small static site (HTML +
two same-origin assets) that lets an operator connect with an `admin` key and
list / create / revoke API keys from the browser:

| Method & path                  | Description                                  |
| ------------------------------ | -------------------------------------------- |
| `GET /plugin-api/v1/admin`     | The management page (HTML).                  |
| `GET /plugin-api/v1/admin.css` | Stylesheet (linked, not inlined).            |
| `GET /plugin-api/v1/admin.js`  | Script (linked, not inlined).                |
| `OPTIONS /plugin-api/v1/*`     | CORS preflight catch-all (returns `204`).    |

The CSS/JS are **separate routes**, not inlined, on purpose: Peckboard's
`security_headers` serves the page under a strict `script-src 'self';
style-src 'self'` CSP (no `'unsafe-inline'`), so linked same-origin assets load
but inline `<script>`/`<style>` would be blocked.

**Where it shows up.** The plugin's `manifest` declares a `ui_panels` entry:

```json
{ "id": "api-keys", "title": "API Keys", "path": "/plugin-api/v1/admin" }
```

Peckboard's generic `ui_panels` rendering surfaces this as a link in the
**user dropdown menu** (the avatar menu) — test id
`user-menu-plugin-api-api-keys`. Selecting it opens a modal containing a
sandboxed `<iframe>` pointed at `/plugin-api/v1/admin`. The iframe is sandboxed
**without** `allow-same-origin`, so the page runs with an opaque origin: it
cannot read the host app's session, and its `fetch` calls back to
`/plugin-api/*` are cross-origin (hence the permissive, credential-free CORS
headers + the `OPTIONS` preflight route above). The page therefore asks the
operator to **paste an `admin` key** (or the `bootstrap_admin_key`), kept in
memory only, to authorize the `/plugin-api/v1/keys` calls — nothing is read
from the host session. The same panels are also listed under Settings →
Plugins → "Plugin Pages".

> **Plugin-defined security headers.** Peckboard core stamps a strict
> `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` on `/api/*` responses,
> which would forbid framing this page. For the `/plugin-api/*` prefix, core
> instead **defers to the headers the plugin returns** (it applies the plugin's
> per-response headers verbatim and adds none of its own; it also skips its
> Origin/CSRF check there). So this plugin sets its **own** policy on the admin
> page — including `frame-ancestors 'self'` — which lets Peckboard frame it
> same-origin in the user-menu iframe while forbidding any foreign framer.
> `/api/*` is untouched. The management **endpoints** (`/plugin-api/v1/keys`)
> also work from any HTTP client (`curl`, etc.) independent of the UI.

## Build

The plugin targets `wasm32-unknown-unknown`.

```bash
rustup target add wasm32-unknown-unknown   # one-time
./build.sh
# or, equivalently:
cargo build --target wasm32-unknown-unknown --release
```

The artifact is:

```
target/wasm32-unknown-unknown/release/peckboard_api_plugin.wasm
```

## CI

GitHub Actions builds the plugin on every push and pull request
(`.github/workflows/build.yml`): it installs the `wasm32-unknown-unknown`
target, runs `cargo fmt --check` and `cargo clippy --all-targets -- -D
warnings`, builds the release WASM, and uploads it as a build artifact. The
cargo registry and `target/` are cached between runs.

Pushing a `v*` tag triggers `.github/workflows/release.yml`, which builds the
WASM and attaches it (as `api.wasm`) to the corresponding GitHub Release, so the
binary is downloadable without a local toolchain.

## Install

Peckboard loads `.wasm` files from `<dataDir>/plugins/` at startup. **The
plugin's config key is its file stem**, so name the file `api.wasm` to match the
`plugins.api` config block below:

```bash
cp target/wasm32-unknown-unknown/release/peckboard_api_plugin.wasm \
   <dataDir>/plugins/api.wasm
```

Restart Peckboard. You should see a load line like:

```
Loaded plugin 'api' with 1 hooks
```

Then:

```bash
curl http://<host>:<port>/plugin-api/v1/health
# {"status":"ok","plugin":"api","version":"0.2.0","keys":2,"seeded":false}
```

`keys` is how many keys exist; `seeded` is whether the managed key set has been
created yet (it is created lazily on the first authenticated request, by
copying the config `keys` — see [Configuration](#configuration)). Before that,
`keys` reflects the config seed count; after, the persisted set.

## Configuration

Per-plugin config lives under the `plugins.<stem>` key of
`<dataDir>/config.json`. For this plugin (`api.wasm`):

```json
{
  "plugins": {
    "api": {
      "enabled": true,
      "config": {
        "keys": [
          { "key": "REPLACE_WITH_A_SECRET", "scopes": ["read"] },
          { "key": "REPLACE_WITH_ANOTHER", "scopes": ["read", "write"] }
        ],
        "bootstrap_admin_key": "REPLACE_WITH_AN_ADMIN_SECRET"
      }
    }
  }
}
```

- `keys[].key` — the secret an API client presents (as a bearer token or
  `X-API-Key`).
- `keys[].scopes` — what the key may do. `read` for read-only endpoints,
  `write` for mutating ones, `admin` for key management (matching the
  scoped-key design used elsewhere).
- `keys[].label` — optional human name for the key (operator-facing only; the
  secret itself is never logged).
- `bootstrap_admin_key` — optional break-glass admin secret. It is **always**
  valid (even after seeding) and grants full `[read, write, admin]`, so an
  operator can always reach the `/keys` management endpoints to mint or rotate
  keys. Unlike `keys`, it is matched as plaintext against config on every
  request; keep it secret and rotate it by editing config + restarting.

### Seeding / migration (config → managed set)

`keys` are a **bootstrap seed**, not the live source of truth. On the first
authenticated request the plugin copies them into a persisted *managed set*
(stored via the plugin self-storage host functions, hashed). From then on:

- The managed set is authoritative. Editing `keys` in config **no longer**
  changes the live keys — manage them through `POST`/`DELETE /keys` instead.
- Re-seeding only happens against an empty store, so wiping the plugin's stored
  settings (or a fresh data dir) re-bootstraps from config.
- `bootstrap_admin_key` is the exception: it is honoured live on every request,
  so it is how you regain admin access if every managed `admin` key is lost.

Core reads the `plugins.<stem>.config` block from `<dataDir>/config.json` and
passes it to the plugin's `init` as a JSON string (see
`PluginManager::read_plugin_config` in `peckboard/src/plugin/manager.rs`). A
missing or malformed `config.json` is non-fatal — the plugin loads with zero
seed keys; with no `bootstrap_admin_key` either, every authenticated route
returns `401` until keys are seeded. Config changes are picked up on the next
Peckboard restart.

## Plugin interface

Core (`peckboard/src/plugin/manager.rs`) expects four exports:

| Export     | Input (from core)                 | This crate does                                              |
| ---------- | --------------------------------- | ----------------------------------------------------------- |
| `manifest` | `""`                              | Returns `{ "hooks": ["http.request.before"], "http_routes": [...], "ui_panels": [...] }` |
| `init`     | the `config` block (JSON string)  | Parses API keys + scopes, stores them, returns `{ "ok": ... }` |
| `handle`   | `{ "hook", "payload" }`           | Dispatches on hook; serves `http.request.before` with the full HTTP response |
| `shutdown` | `""`                              | No-op                                                        |

### Host functions

The plugin reads and writes Peckboard data only through host functions core
wires into the sandbox (`peckboard/src/plugin/host.rs`):

- `peckboard_list_projects` — `{}` → `{"projects": [...]}`
- `peckboard_list_cards` — `{"project_id"?, "step"?}` → `{"cards": [...]}`
- `peckboard_create_card` — `{"project_id", "title", ...}` → `{"card": {...}}`
- `peckboard_get_plugin_setting` — `{"key"}` → `{"value": <json|null>}`
- `peckboard_set_plugin_setting` — `{"key", "value"}` → `{"ok": true}` (a
  `null` value deletes the key)

Each is JSON-string-in / JSON-string-out and returns an `{"error": "..."}`
envelope on failure rather than trapping. The data functions are generic and
**not** scope-aware — scope enforcement is this plugin's responsibility (the
`guard` in `src/lib.rs`). The `*_plugin_setting` functions are namespaced by
core to this plugin's own id and hold the persisted managed key set.

Generated key secrets and `created` timestamps come from the WASI host
(`random_get` / `clock_time_get`), which core enables when it loads the plugin.

## Repository

This crate lives in its own repo (`git@github.com:PeckBoard/api-plugin.git`),
checked out as a sibling of the peckboard repo at
`peckboard/peck-plugins/api/`. It is intentionally **outside** the peckboard
Cargo workspace and self-contained: building it touches nothing in the peckboard
repo.
