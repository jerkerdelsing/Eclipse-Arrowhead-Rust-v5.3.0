# Gatekeeper (Rust)

Arrowhead 5.2.2 Gatekeeper support system. Entry point `src/main.rs` is built as binary `gatekeeper` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/gatekeeper.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/Gatekeeper`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin gatekeeper -- <config.json>`

## Listening port

Default **127.0.0.1:8449** (Arrowhead default, role `gatekeeper`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
