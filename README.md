# Peckboard Public API Plugin

A self-contained [Extism](https://extism.org) WASM plugin that gives Peckboard a
public, **API-key-authenticated** HTTP surface over its data. Core mounts a
dedicated public prefix `/plugin-api/*` that is **not** behind the `/api/*` auth
middleware; this plugin owns authentication (scoped API keys) and dispatch for
that prefix end to end. Core does no auth and has no knowledge of any specific
endpoint.

See `peckboard/docs/architecture/plugins.md` ("HTTP Route Hooks" and "Plugin
API (Host Functions)") for the full contract.

> **Status: scaffold.** Today the plugin declares one route,
> `GET /plugin-api/v1/health`, and answers it (and any future claimed route)
> with a 200 health response. API-key authentication and the real endpoints
> land in a follow-up card.

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
# {"status":"ok","plugin":"api","version":"0.1.0","configured_keys":0}
```

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

- `keys[].key` — the secret an API client presents (e.g. as a bearer token).
- `keys[].scopes` — what the key may do. `read` for read-only endpoints,
  `write` for mutating ones (matching the scoped-key design used elsewhere).

> **Known core gap:** the plugin's `init` is wired to parse this `config`
> object, but core currently calls `init` with `"{}"` and exposes no
> `peckboard_get_config` host function — so configured keys are not yet
> delivered to the plugin. `init` parses defensively and the health endpoint
> reports `configured_keys`, so the wiring lights up the moment core passes the
> config. Closing that gap is tracked outside this scaffold card.

## Plugin interface

Core (`peckboard/src/plugin/manager.rs`) expects four exports:

| Export     | Input (from core)         | This crate does                                              |
| ---------- | ------------------------- | ----------------------------------------------------------- |
| `manifest` | `""`                      | Returns `{ "hooks": ["http.request.before"], "http_routes": [...] }` |
| `init`     | `"{}"` (per-plugin config) | Parses API keys + scopes, stores them, returns `{ "ok": ... }` |
| `handle`   | `{ "hook", "payload" }`   | Dispatches on hook; serves `http.request.before` (200 health stub) |
| `shutdown` | `""`                      | No-op                                                        |

### Host functions

Peckboard exposes data-access host functions to plugins
(`peckboard/src/plugin/host.rs`). Only three are implemented today and are
declared in `src/lib.rs` for the endpoints card to call:

- `peckboard_list_projects` — `{}` → `{"projects": [...]}`
- `peckboard_list_cards` — `{"project_id"?, "step"?}` → `{"cards": [...]}`
- `peckboard_create_card` — `{"project_id", "title", ...}` → `{"card": {...}}`

Each is JSON-string-in / JSON-string-out and returns an `{"error": "..."}`
envelope on failure rather than trapping. They are generic and **not**
scope-aware — scope enforcement is this plugin's responsibility.

## Repository

This crate lives in its own repo (`git@github.com:PeckBoard/api-plugin.git`),
checked out as a sibling of the peckboard repo at
`peckboard/peck-plugins/api/`. It is intentionally **outside** the peckboard
Cargo workspace and self-contained: building it touches nothing in the peckboard
repo.
