2026-10-23: PDE now synchronizes durable DSO plant-rule snapshots. [API, deployment and verification guide](docs/PDE-DSO.md).

2026-10-19 functional candidate update: native federation, encrypted Java/Go interoperability, RandomDataProducer and monitoring are deployed and tested. The agreed workload is RandomDataProducer → DataManager, functionality only. Full Java replacement and ISO certification remain unproven. See [current status](docs/REPLACEMENT-STATUS.md) and [functional federation](docs/FUNCTIONAL-FEDERATION.md). Older dated evidence below is historical.

2026-10-18 broker upgrade: native AMQP publishers, SysMonitor/MQTT workers and SQLite history are deployed and tested. Full-cloud replacement equivalence is still **not established**. See [current replacement status](docs/REPLACEMENT-STATUS.md).

# Arrowhead support systems in Rust — development port

2026-10-18 candidate hardening: mandatory deployed CRLs, native CA publication, TLS-material reload and current-image test evidence. See [ISO/IEC 27001:2022 acceptance register](docs/SECURITY-ACCEPTANCE-ISO27001.md). This is not certification or full Java feature equivalence. Automatic leaf renewal and production load/soak qualification remain open.


## Relocated LocalCloudManager

The repository now additionally includes [LocalCloudManager/](LocalCloudManager/README.md), a standalone nested Cargo package relocated from the latest located Rust test-cloud source. Its dedicated launcher, shared dependencies, embedded UI, source-provenance record and SysD/SysDD/SD/IDD set are included. Root build/test/check targets explicitly include it; use `make localcloudmanager` or `make localcloudmanager-docs` for this package alone. The original fifteen-system catalogue remains separate from its dedicated catalogue.

**Secure candidate update (2026-10-17):** LocalCloudManager now has a dedicated native mTLS system listener, HTTPS/password browser console, pinned certificate-bound provider clients and a restricted Rust Docker gateway. It is deployed in `Arrowhead-test-cloud-rust/candidate-native/` at https://127.0.0.1:10590/. It uses shared parent TLS helpers but remains a separate nested package, not a sixteenth profile of the generic support launcher. The historical declared-SYSTEM router is not mounted. See `LocalCloudManager/docs/SECURE-DEPLOYMENT.md`; full Java parity remains unclaimed; native manager AMQP publishing is implemented. The original legacy cloud snapshot remains unchanged.

## Original fifteen-system port

Native Rust executables for all **15 active profiles** in the local `ah5-support-java-spring` tree. **The requested full implementation is not complete:** Onboarding provisioning and other listed integrations remain unported; native SysMonitor brokers and federation/tunnel workers are implemented; other roles have restrictions. Do not replace a working Java cloud with this package. The separate native candidate is deployed; existing cloud identities/data are not migrated.

See [COMPATIBILITY.md](COMPATIBILITY.md) before use and [VERIFICATION.md](VERIFICATION.md) for evidence. AIGym is a local extension. Historical `_superseeded` modules are excluded. Shared JavaSupportRuntime is a source reference, not an extra system.

## Build and isolated use

Requires Rust >=1.89, a native C toolchain, Perl/make for the vendored OpenSSL build, and provisioned PEM certificates/keys. Runtime logic uses Rust and the linked OpenSSL library; it does not delegate service behavior to Go/Java/Python or an OpenSSL subprocess. Tests alone use the OpenSSL command-line tool to generate isolated PKI.

```
cargo build --locked --bins
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
target/debug/blacklist --config examples/blacklist.json
```

Fifteen named binaries and `arrowhead-support` share one runtime; named executables enforce their configured role. `arrowhead-documentation` generates documentation. Example configurations use the default listening ports (see Listening port below); no services start automatically. Replace all example paths/origins with provisioned values; keep keys/passwords mode0600. Each system needs its own `sy` certificate `<System>.<Cloud>.<Organization>.arrowhead.eu`, trusted CA bundle and independent state file. Only CertificateAuthority may configure a CA signing key. No actual cloud keys are included.

All listeners require verified client TLS certificates (`sy`/`op`, local cloud). Onboarding bootstrap/on/de profiles are deliberately not accepted until their provisioning path is implemented. Identity APIs use `Bearer IDENTITY-TOKEN//...`; Authentication must verify the token against the TLS identity. Business calls fail closed through ConsumerAuthorization. Management requires verified sysop or explicit `managementWhitelist` (a broad trust grant). CA certificate-only APIs enforce named Java provisioning/management principals. Do not grant these names or CA keys to ordinary clients.

`authenticationUrl`, `registryUrl`, `authorizationUrl` and every `upstreams` entry must be bare HTTPS origins ending `/`. Outbound peers are checked for expected system CN/profile **before** credentials are sent, as well as normal chain/SAN validation. No redirects or insecure mode. `crlFile` optionally supplies PEM CRLs; the candidate enables mandatory checks and reloads changed TLS/CRL material for new connections, failing closed on invalid material. Without CRLs TLS revocation is not enforced. Role JSON is locked per process, fsynced and atomically renamed; SysMonitor uses native SQLite history/outbox; back it up and reconcile uncertain network effects before retrying.

Set `register:true` only with verified core dependencies and appropriate policies. Only implemented operations are advertised (partial services still need the compatibility review). Registry registration failures are logged and retried; listener startup does not imply dependency readiness. Callback/executor/provider/translator/measurement origins require explicit pinned `upstreams` entries. EventHandler additionally needs authorization to use ConsumerAuthorization management `check` for publisher/subscriber EVENT_TYPE decisions; absent permission fails closed.

## Documentation

Arrowhead-style editable LaTeX uses the repository's original `arrowhead.cls` and logo. Per profile: SysD, SysDD, HTTPS IDD, and produced-service SDs. `documentation/contracts.json` includes SHA256 Java source inventory, 107 Spring mapping comparisons and per-route implementation flags. Four shared-runtime systems use manual route review, not Spring extraction. Mapping coverage does not establish behavioral equivalence or provenance of an upstream v5.2.2 release.

```
make contracts JAVA_SUPPORT='../ah5-support-java-spring' JAVA_COMMON='../ah5-common-java-spring'
make docs
make docs-all
```

Compile from `documentation/` so the Arrowhead class/logo resolve. The combined PDF is `output/pdf/Rust-Support-Systems.pdf`; `Compatibility-Annex.tex` contains contract details and restrictions. The older generated LaTeX/PDF is historical. Current Linux container, real broker/federation and dated dependency evidence are indexed in docs/REPLACEMENT-STATUS.md. Exhaustive Java differential coverage, complete native/OS advisory clearance and production qualification remain unclaimed.

## Listening port

`"listen"` is optional. Override with `"listen": "host:port"`, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

| System | Role | Default |
|---|---|---|
| PlantDescriptionEngine | `plantdescriptionengine` | 127.0.0.1:8432 |
| Onboarding | `onboarding` | 127.0.0.1:8435 |
| CertificateAuthority | `certificateauthority` | 127.0.0.1:8448 |
| Gatekeeper | `gatekeeper` | 127.0.0.1:8449 |
| GateTunnel | `gatetunnel` | 127.0.0.1:8453 |
| EventHandler | `eventhandler` | 127.0.0.1:8455 |
| Choreographer | `choreographer` | 127.0.0.1:8457 |
| Configuration | `configuration` | 127.0.0.1:8459 |
| DataManager | `datamanager` | 127.0.0.1:8461 |
| TimeManager | `timemanager` | 127.0.0.1:8463 |
| Blacklist | `blacklist` | 127.0.0.1:8464 |
| TranslationManager | `translationmanager` | 127.0.0.1:8465 |
| DeviceQoSEvaluator | `deviceqosevaluator` | 127.0.0.1:8472 |
| SysMonitor | `sysmonitor` | 127.0.0.1:8475 |
| AIGym | `aigym` | 127.0.0.1:8478 |

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
