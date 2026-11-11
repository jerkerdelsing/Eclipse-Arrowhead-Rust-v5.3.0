# DataManager (Rust)

Arrowhead 5.2.2 DataManager support system. Entry point `src/main.rs` is built as binary `datamanager` by the shared crate in [`../ah5-support-runtime-rust`](../ah5-support-runtime-rust) (`arrowhead-support-rust`).

- `examples/datamanager.json` — example configuration (master copy: `../ah5-support-runtime-rust/examples/`)
- `documentation/` — SysD/SysDD/IDD/SD sources (symlink into `../ah5-support-runtime-rust/documentation/DataManager`, where the contract generator writes)

Run: `cargo run -p arrowhead-support-rust --bin datamanager -- <config.json>`

## Listening port

Default **127.0.0.1:8461** (Arrowhead default, role `datamanager`). Override with `"listen": "host:port"` in the configuration, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.

## dataHistorian retention

The DataManager keeps its SenML records (dataHistorian) in its state file, which it holds in memory and rewrites on
every put. Two settings in the configuration file bound it:

| Key | Default | Range | Effect |
|---|---|---|---|
| `retentionDays` | 30 | 1..3650 | Records received more than this many days ago are deleted (same key and default as the Go DataManager). |
| `maxSenmlRecords` | 5000 | 1..1000000 | At most this many records are kept; the oldest received are deleted first. |

A loaded record takes about 4-7 KiB of memory (20,000 records peaked at 148 MB natively and about 250 MB under amd64
emulation), so the default fits a 256 MiB container. Raise `maxSenmlRecords` only together with the memory limit.

Retention runs at start-up and with every put. Writes stream the state to the file, and puts append in place, so a
put does not copy the state. Without these limits,
a cloud with continuous producers was OOM-killed under a 256 MiB memory limit (43,771 records, 2026-11-09).
