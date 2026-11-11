# EventHandler (Rust)

Arrowhead 5.2.2 EventHandler support system. Entry point `src/main.rs` is built as binary `eventhandler` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/eventhandler.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/EventHandler`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin eventhandler -- <config.json>`

## Listening port

Default **127.0.0.1:8455** (Arrowhead default, role `eventhandler`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
