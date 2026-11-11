# PlantDescriptionEngine (Rust)

Arrowhead 5.2.2 PlantDescriptionEngine support system. Entry point `src/main.rs` is built as binary `plantdescriptionengine` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/plantdescriptionengine.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/PlantDescriptionEngine`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin plantdescriptionengine -- <config.json>`

## Listening port

Default **127.0.0.1:8432** (Arrowhead default, role `plantdescriptionengine`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
