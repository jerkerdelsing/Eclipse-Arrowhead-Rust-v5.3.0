# CertificateAuthority (Rust)

Arrowhead 5.2.2 CertificateAuthority support system. Entry point `src/main.rs` is built as binary `certificateauthority` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/certificateauthority.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/CertificateAuthority`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin certificateauthority -- <config.json>`

## Listening port

Default **127.0.0.1:8448** (Arrowhead default, role `certificateauthority`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
