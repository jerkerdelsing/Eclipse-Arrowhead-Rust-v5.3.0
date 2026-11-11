# Rust LocalCloudManager

## Current implementation — secure Rust candidate cloud (2026-10-17)

The `LocalCloudManager` executable now uses `src/secure_main.rs` and `src/secure.rs`, **not the historical HTTP launcher/router described below**. It requires `--config CONFIG.json`. Automatic legacy binary discovery is disabled. The manager depends on the parent Rust support library for verified TLS, expected-provider CN/profile pinning, certificate-bound identity login/token refresh and bounded HTTPS requests.

Deployed console: **https://127.0.0.1:10590/**. System API: **https://127.0.0.1:10520/localcloud/** (mandatory mTLS). Deployment: `Arrowhead-test-cloud-rust/candidate-native/`, project `arrowhead-rust-candidate`. The older Rust cloud remains separate. During final verification it was recreated by a separate deployment change and its UI remapped from8590to10490; this work did not modify that project.

The browser console uses HTTPS plus a private-password login and Secure/HttpOnly/SameSite cookie. It does not require a browser client certificate. The candidate CA is private, so browsers may show a certificate warning; no global trust store was changed. Password is in `candidate-native/secrets/localcloudmanager/console-password` (private file; never logged). The manager's system listener requires a verified local sy/op certificate and a matching verified sysop identity token for management. Echo is certificate-only.

See [docs/SECURE-DEPLOYMENT.md](docs/SECURE-DEPLOYMENT.md) for the current configuration, service contracts, permission boundaries, test evidence and limitations. The manager now makes real revision-checked SysMonitor subscription writes, forwards plant POST/PUT/PATCH/DELETE correctly, manages simple-store rules, reads diagnostics/historian data and uses a scoped Rust Docker gateway rather than receiving a Docker socket.

The Markdown below, the relocation source manifest, the earlier generated LaTeX/PDF catalogue and `docs/legacy/` record the **superseded relocation snapshot**, not the active deployed secure contract. They do not supersede the new secure deployment documentation. Full Java equivalence, telemetry broker publishing and the cloud's missing federation/onboarding capabilities are still not claimed.

## Historical relocation record (superseded runtime)

Canonical relocated source: `ah5-support-rust/LocalCloudManager`. Target system version5.2.2; associated services `localCloudManagement` and legacy `monitor`, both1.0.0. The latest located cloud/workspace manager sources matched SHA256 `c3150daa4dd91e854439e31626895c5ff86e77881c338c5281306bda49f44d6b` before relocation.

This is a source/documentation relocation, **not a Java-parity upgrade or secure deployment**. The existing `Arrowhead-test-cloud-rust/core-systems` copy remains a deployment compatibility snapshot because other roles share its runtime and build context. No live source, cloud, container, key or state was removed or restarted. Develop against this canonical package instead of editing both copies independently.

## Critical boundary

The inherited manager is a development HTTP adapter: **no native inbound TLS, no configured mTLS provider identity and no native AMQP sysMonitor publisher**. It sends/accepts legacy `Bearer SYSTEM//...` identities in its shared runtime. Those are not cryptographic authentication. Do not expose this package directly or assume it meets the newer Rust support runtime's certificate-authenticated contract. A TLS proxy alone does not correct legacy provider authentication. See COMPATIBILITY.md before use.

The dedicated launcher defaults to `http://127.0.0.1:8480/` instead of the inherited all-interface bind. This is a packaging safeguard, not a complete security fix. Historical UI8590/API8580 mappings belong to cloud deployment forwarding and are not created here.

## Build and source layout

```
cargo build --locked --bin LocalCloudManager
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked --bin LocalCloudManager -- --help
```

This is an independent nested Cargo package, with its own Cargo.toml/lock and workspace boundary. Root Makefile build/test/check targets explicitly include it. Root `make localcloudmanager` builds it; `make localcloudmanager-docs` generates/compiles its documentation. The generic parent `arrowhead-support` launcher does not select this legacy manager profile.

`src/main.rs` is the dedicated launcher, rejecting roles other than localcloudmanager without mutating process environment. `src/localcloudmanager.rs` retains the existing Axum console handlers and compile-time embedded HTML/CSS/JavaScript in `src/ui`. `api.rs`, `registry.rs` and `state.rs` are the inherited shared runtime dependencies; retaining them avoids a dependency on the old checkout. Other role implementations remain source dependencies and are not selected by this executable. No Java/Go/Node process implements the manager.

Original manager business logic and UI are retained; deliberate packaging changes are the crate name/workspace boundary, library exports, role-default configuration helper, dedicated launcher and loopback default. Additional tests, documentation and source-provenance records are provided. The legacy `src/ui.html` remains an unused historical asset; active UI uses src/ui/index.html/app.js/styles.css.

## Configuration

| Environment | Actual source behavior |
|---|---|
| `ARROWHEAD_ROLE` | Omit or use localcloudmanager; other values rejected by dedicated launcher |
| `SYSTEM_NAME`, `DOMAIN_NAME` | Default LocalCloudManager/localcloudmanager; used as declared identity/advertised address, not validated certificate identities |
| `SERVER_PORT`, `LISTEN_ADDRESS` | Default8480 and loopback; explicit listen address can override it, but exposes inherited insecure transport |
| `DATA_FILE` | Independent JSON state, default /data/state.json; use a private dedicated path, never existing active cloud state |
| `SERVICE_REGISTRY_URL`, `AUTHENTICATION_URL` | Inherited HTTP defaults; HTTPS URLs alone do not provision a client certificate, expected-CN pin or identity-token login |
| `DATAMANAGER_URL`, `SIMPLE_ORCHESTRATION_URL`, `SYSMONITOR_URL`, `PLANT_DESCRIPTION_ENGINE_URL` | Provider adapter bases; shapes must be qualified against actual deployed providers |
| `MANAGEMENT_WHITELIST`, `TOKEN_SECRET` | Shared legacy runtime settings, not the console session boundary or proof of secure identity |
| `CONSOLE_PASSWORD_HASH` | scrypt:base64salt:base64hash, N16384/r8/p1; salt>=16bytes/hash>=32bytes; missing or invalid value returns503for console APIs |
| `CONSOLE_ALLOWED_HOSTS` | Host-name allowlist, default127.0.0.1,localhost,[::1]; ports are ignored |
| `CONSOLE_SESSION_SECONDS` | Default28800; positive bounded values should be provisioned; inherited implementation lacks robust range validation |
| `DOCKER_SOCKET`, `COMPOSE_PROJECT_NAME` | Unix Docker socket and project filter; static source allowlist controls lifecycle; MANAGED_SERVICES is not used |

Missing password fails closed for `/api/` but does not disable static assets, health or legacy Arrowhead routes. Sessions and history reset on restart. Keep this process in an isolated development environment with explicit trust boundaries.

## Documentation and provenance

`../documentation/LocalCloudManager/v5.2.2/` contains SysD, SysDD, two SDs and two HTTP IDDs, plus a combined catalogue. No sysMonitor AMQP SD/IDD is fabricated for an unimplemented publisher. The revised SysML variability model in docs/LocalCloudManager.sysml records Java-cloud, Go and Rust variants and the actual Rust qualification boundary. Historical Markdown/SysML is preserved unchanged under docs/legacy, not endorsed as evidence of interchangeability.

```
make docs
```

Run from this module. The original source defaults to ../../Arrowhead-test-cloud-rust/core-systems for read-only source hashing; override REFERENCE when needed. `docs/source-manifest.json` records original and relocated hashes plus the route inventory. Read VERIFICATION.md for actual test/build evidence. The repository's original Arrowhead LaTeX class/logo is reused.

## Listening port

System API default **127.0.0.1:8480**. Override with `"listen"` in CONFIG.json, `SERVER_PORT=N` or `--server.port N`. The HTTPS console listener (`"consoleListen"`) is configured separately. The console answers only loopback, the container's network gateways (a Docker-published port) and the optional `"consoleClients"` (IP addresses, CIDR ranges or DNS names, e.g. a TCP relay); other systems on a shared network are refused by source address before TLS, whatever `Host` and `Origin` they send.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
