# AIGym (Rust)

Arrowhead 5.2.2 AIGym support system. Entry point `src/main.rs` is built as binary `aigym` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/aigym.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/AIGym`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin aigym -- <config.json>`

## Listening port

Default **127.0.0.1:8478** (Arrowhead default, role `aigym`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
