# Eclipse Arrowhead 5.2.2 — Rust implementations

> **Primary source:** This is the primary Rust implementation tree for further updates in this Eclipse workspace, designated on 2026-10-30. See [primary-source policy](../PRIMARY-SOURCES.md). Historical source-copy notes below describe provenance, not current development ownership.

Native Rust implementations of the Arrowhead 5.2.2 core and support systems, organised like
[`Eclipse-Arrowhead-java`](../Eclipse-Arrowhead-java): one core folder with a subfolder per core
system, one `ah5-<System>-rust` folder per support system, and shared libraries alongside them.
Everything is one Cargo workspace.

```bash
cargo build
```

```bash
cargo test
```

`make build|test|check` at the top level runs the same with `--locked --workspace`.

## Layout

| Folder | What it is | Java counterpart |
|---|---|---|
| `ah5-core-rust/` | Crate `arrowhead-core-rust`: shared core library (`src/`), combined `arrowhead-core` binary, tests, docs, Dockerfile | `ah5-core-java-spring/` |
| `ah5-core-rust/<system>/` | Per core system: `src/main.rs` (entry point), `README.md`, links to its example config and documentation. Systems: `serviceregistry`, `authentication`, `consumer-authorization`, `serviceorchestration-dynamic`, `serviceorchestration-simple` | `ah5-core-java-spring/<system>/` |
| `ah5-<System>-rust/` | Per support system (AIGym, Blacklist, CertificateAuthority, Choreographer, Configuration, DataManager, DeviceQoSEvaluator, EventHandler, Gatekeeper, GateTunnel, Onboarding, PlantDescriptionEngine, SysMonitor, TimeManager, TranslationManager): `src/main.rs`, `examples/<system>.json`, `documentation/` link, `README.md` | `ah5-<System>-java-spring/` |
| `ah5-LocalCloudManager-rust/` | Crate `arrowhead-localcloudmanager-rust` (own crate as before) | `ah5-LocalCloudManager-java-spring/` |
| `ah5-support-runtime-rust/` | Crate `arrowhead-support-rust`: shared support library, combined `arrowhead-support` binary, `RandomDataProducer`, all support tests, the documentation sources for every support system, contract generator | `ah5-support-runtime-java/` |
| `ah5-messaging-rust/` | Crate `arrowhead-messaging-rust`: AMQP/MQTT messaging library used by core, support and LocalCloudManager | shared common library |

### How the per-system folders build

The support systems share one library and the process tests (`tests/process.rs`) need all
binaries in the same package (`CARGO_BIN_EXE_*`). So each system's `src/main.rs` lives in its own
folder but is declared as a `[[bin]]` of the shared crate, e.g. in
`ah5-support-runtime-rust/Cargo.toml`:

```toml
[[bin]]
name = "timemanager"
path = "../ah5-TimeManager-rust/src/main.rs"
```

Binary names are unchanged (`timemanager`, `serviceregistry`, …), so existing scripts and images
keep working. Build a single system with e.g. `cargo build -p arrowhead-support-rust --bin timemanager`.

`documentation/` in each system folder is a symlink into the shared crate's `documentation/`,
because the contract generators (`core-documentation`, `support-documentation`) write all systems
there and the master LaTeX documents (`Rust-Core-Systems.tex`, `Rust-Support-Systems.tex`) live
there. Per-system examples are copies; the generators read `ah5-*-rust/examples/` in the shared crate.

## Mapping from the old locations

Source: `../Arrowhead/ah5-core-rust` and `../Arrowhead/ah5-support-rust` (copied 2026-10-28; the
originals are untouched and still used by the running test clouds).

| Old | New |
|---|---|
| `ah5-core-rust/{src,tests,docs,documentation,examples,*.md,Makefile,Dockerfile}` | `ah5-core-rust/` (same) |
| `ah5-core-rust/src/bin/<system>.rs` | `ah5-core-rust/<system>/src/main.rs` |
| `ah5-core-rust/bin/` (prebuilt binaries) | not copied — `make -C ah5-core-rust build` recreates it |
| `ah5-core-rust/messaging/` | `ah5-messaging-rust/` |
| `ah5-support-rust/{src,tests,docs,documentation,examples,config,*.md,Makefile}` | `ah5-support-runtime-rust/` |
| `ah5-support-rust/src/bin/<system>.rs` | `ah5-<System>-rust/src/main.rs` |
| `ah5-support-rust/examples/<system>.json` | also copied to `ah5-<System>-rust/examples/` |
| `ah5-support-rust/LocalCloudManager/` | `ah5-LocalCloudManager-rust/` |
| per-crate `Cargo.lock` | one workspace `Cargo.lock` (seeded from the support lock) |
| `target/`, `output/`, `tmp/`, `.relocation-backups/`, `.secure-upgrade-backups/` | not copied |

## Changes made while copying

- Workspace `Cargo.toml` at the root; LocalCloudManager's stand-alone `[workspace]` removed.
- Path dependencies point to `ah5-messaging-rust` and `ah5-support-runtime-rust`.
- Documentation generator binaries renamed to avoid a workspace output collision:
  `arrowhead-documentation` → `core-documentation` (core) and `support-documentation` (support).
- Makefiles: workspace `target/`, renamed generator binaries, LocalCloudManager path, and Java
  reference sources at `../../Arrowhead/ah5-{support,common}-java-spring`; LocalCloudManager
  doc paths point into `ah5-support-runtime-rust/documentation`.
- `ah5-core-rust/Dockerfile` now builds from the workspace root
  (`docker build -f ah5-core-rust/Dockerfile .`). No image was built.
- LocalCloudManager `tests/secure_console.rs` uses the shared test helpers in
  `ah5-support-runtime-rust/tests/common`.

Status at copy time: `cargo build` clean (no warnings), `cargo test` 147 passed, 0 failed.

License: EPL-2.0 (see `LICENSE`, `NOTICE.md`).

## Listening port

Every core and support system has a configurable listening port (`server.port`, `SERVER_PORT`, `--server.port`) and a built-in default. The defaults, the precedence and the differences between languages are listed in this file.

See [LISTENING-PORTS.md](LISTENING-PORTS.md) for precedence and all systems.
