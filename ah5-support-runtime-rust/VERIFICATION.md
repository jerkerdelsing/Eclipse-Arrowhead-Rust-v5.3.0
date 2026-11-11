## Current evidence — 2026-10-19

The native candidate now has Linux-container, real broker, encrypted federation, producer/historian and manager evidence. See [current status](docs/REPLACEMENT-STATUS.md) and its final verification summary for exact results/revisions. The dated original source-only report below is retained as history, not the current deployment or current missing-feature list. Full replacement/production certification remains unproven.

# Verification — 2026-10-17

## Scope and result

Development code for 15 named support profiles, **not full Java replacement completion**. No Java source, certificate store, running cloud/container, broker or security evaluation report was modified. No deployment/restart was performed. The destination is `ah5-support rust` under the user-specified Arrowhead directory.

Environment: macOS ARM64, rustc1.99.0, cargo1.99.0. Dependencies locked in Cargo.lock. OpenSSL3.6.3 is built through the vendored Rust dependency, not taken from a live cloud. Tests use fresh temporary test CA/leaf keys; no live CA private key was copied.

## Executed checks

| Check | Result |
|---|---|
| `cargo build --locked --bins --offline` | Passed: 15 role binaries, unified launcher and documentation generator |
| `cargo fmt -- --check` | Passed |
| `cargo clippy --locked --all-targets --offline -- -D warnings` | Passed |
| `cargo test --locked --offline` | **40 tests passed**, zero failed |
| Source mapping audit | **107 Spring mappings represented**, zero missing/unresolved; route presence is not behavioral parity |
| Source inventory | SHA256 hashes for **910** Java support/common files; `_superseeded`/generated output excluded |
| Rust interface catalogue | **165** routes; **15 explicitly unported** routes; **62** advertised HTTPS definition groups, including common management/echo |
| Arrowhead LaTeX | **109** editable documents, all compiled successfully |
| Combined PDF | **35 pages**, compiled three passes; all pages rendered and visually inspected; no overfull boxes in latest document logs |

Test distribution:

- 26 business/security/state tests: blacklist atomicity/expiry, configuration ownership, kNN, SenML base context and rejected semantics, QoS missing metrics/ranking, plant DAG/active uniqueness, choreography validation/callback ownership, enrollment uniqueness/reserved names, absent adapters, no fake tunnel/federation, telemetry revisions/schema/routing/deduplication, file locks/durable reopen/corruption and strict configuration.
- 4 certificate tests: CSR signatures and issued profile/SANs, issuer/reserved-name policy, ownership-constrained revocation, trusted keys, signed populated/empty CRLs, and rejection of a leaf used as CA signer. Actual signed extension checks are used, not human-readable subject text.
- 8 isolated network tests: mutual-TLS echo for every profile and rejection without client certificate; certificate/token binding and management denial; authority substitution rejected before credentials; authorized HTTPS event delivery; denied event type never queued; raw configuration; explicit501; pinned translator adapter lifecycle and ownership.
- 2 executable tests: all15 named binaries/role mismatch; native listener, durable audit state and bounded graceful shutdown.

The runtime is native Rust (with linked cryptography), not an HTTP facade around Go/Java. Network tests use Rust TLS servers and mocked authorities/adapters, **not a real Java mixed-language cloud**. Direct business tests deliberately bypass HTTP guards; guards have separate isolated TLS tests. Passing tests do not establish complete branch coverage or compatibility.

## Explicitly not verified/delivered

No full Java golden differential DTO/error/policy suite, SQL migration, Linux/Windows build, performance/HA test, cargo-audit/advisory scan, coverage percentage, real AMQPS/MQTT broker tests or live federation qualification. Onboarding provisioning/offboarding, SysMonitor broker workers, federation/tunnel data planes, trusted SNTP and other profile-specific behavior remain incomplete (see COMPATIBILITY.md). Do not promote based solely on builds, route matching or these tests.

The PDF skill guided compilation/render inspection and the correction of long contract-field line wrapping; Arrowhead's own LaTeX class/logo were retained.
