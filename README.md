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

| Method & path    | Scope   | Backed by                 | Description                                          |
| ---------------- | ------- | ------------------------- | --------------------------------------------------- |
| `GET  /health`   | —       | (none)                    | Liveness. No auth.                                  |
| `GET  /projects` | `read`  | `peckboard_list_projects` | List all projects.                                  |
| `GET  /cards`    | `read`  | `peckboard_list_cards`    | List cards. Optional `?project_id=&step=` filters.  |
| `POST /cards`    | `write` | `peckboard_create_card`   | Create a card. JSON body (see below).               |

`POST /cards` body — `project_id` and `title` are required; the rest are
optional and forwarded to core, which validates priority/workflow and that the
project exists (inheriting the project's workflow when none is given):

```json
{ "project_id": "<id>", "title": "My card", "description": "", "priority": 1,
  "step": "backlog", "workflow": "<id>", "model": null, "effort": null }
```

Status codes: `200` (read), `201` (card created), `400` (missing/invalid
body), `401` (missing/unknown key), `403` (key lacks the route's scope), `404`
(unknown project, or a path no plugin claims), `500` (host/data error). Bodies
are JSON; errors are `{ "error": "..." }`.

## Authentication

Every endpoint except `GET /health` requires a configured API key, presented as
either header:

```
Authorization: Bearer <key>
X-API-Key: <key>
```

`Authorization: Bearer` wins if both are present. A missing or unknown key is
`401`; a known key that lacks the route's required scope is `403`. Keys are
compared in constant time and are never written to logs (the sandbox exposes no
log host function today, so the plugin does not log at all).

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
# {"status":"ok","plugin":"api","version":"0.1.0","configured_keys":2}
```

`configured_keys` reflects how many keys core delivered from `config.json` —
a quick way to confirm your config reached the plugin.

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
        ]
      }
    }
  }
}
```

- `keys[].key` — the secret an API client presents (as a bearer token or
  `X-API-Key`).
- `keys[].scopes` — what the key may do. `read` for read-only endpoints,
  `write` for mutating ones (matching the scoped-key design used elsewhere).
- `keys[].label` — optional human name for the key (operator-facing only; the
  secret itself is never logged).

Core reads the `plugins.<stem>.config` block from `<dataDir>/config.json` and
passes it to the plugin's `init` as a JSON string (see
`PluginManager::read_plugin_config` in `peckboard/src/plugin/manager.rs`). A
missing or malformed `config.json` is non-fatal — the plugin loads with zero
keys and every authenticated route returns `401`. Config changes are picked up
on the next Peckboard restart.

## Plugin interface

Core (`peckboard/src/plugin/manager.rs`) expects four exports:

| Export     | Input (from core)                 | This crate does                                              |
| ---------- | --------------------------------- | ----------------------------------------------------------- |
| `manifest` | `""`                              | Returns `{ "hooks": ["http.request.before"], "http_routes": [...] }` |
| `init`     | the `config` block (JSON string)  | Parses API keys + scopes, stores them, returns `{ "ok": ... }` |
| `handle`   | `{ "hook", "payload" }`           | Dispatches on hook; serves `http.request.before` with the full HTTP response |
| `shutdown` | `""`                              | No-op                                                        |

### Host functions

The plugin reads and writes Peckboard data only through data-access host
functions core wires into the sandbox (`peckboard/src/plugin/host.rs`). The
three this plugin uses:

- `peckboard_list_projects` — `{}` → `{"projects": [...]}`
- `peckboard_list_cards` — `{"project_id"?, "step"?}` → `{"cards": [...]}`
- `peckboard_create_card` — `{"project_id", "title", ...}` → `{"card": {...}}`

Each is JSON-string-in / JSON-string-out and returns an `{"error": "..."}`
envelope on failure rather than trapping. They are generic and **not**
scope-aware — scope enforcement is this plugin's responsibility (the `guard`
in `src/lib.rs`).

## Repository

This crate lives in its own repo (`git@github.com:PeckBoard/api-plugin.git`),
checked out as a sibling of the peckboard repo at
`peckboard/peck-plugins/api/`. It is intentionally **outside** the peckboard
Cargo workspace and self-contained: building it touches nothing in the peckboard
repo.
