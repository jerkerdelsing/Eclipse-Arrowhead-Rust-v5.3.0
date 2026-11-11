2026-10-23: PDE now synchronizes durable DSO plant-rule snapshots. [API, deployment and verification guide](docs/PDE-DSO.md).

2026-10-19 functional candidate update: native federation, encrypted Java/Go interoperability, RandomDataProducer and monitoring are deployed and tested. The agreed workload is RandomDataProducer → DataManager, functionality only. Full Java replacement and ISO certification remain unproven. See [current status](docs/REPLACEMENT-STATUS.md) and [functional federation](docs/FUNCTIONAL-FEDERATION.md). Older dated evidence below is historical.

2026-10-18 broker upgrade: native AMQP publishers, SysMonitor/MQTT workers and SQLite history are deployed and tested. Full-cloud replacement equivalence is still **not established**. See [current replacement status](docs/REPLACEMENT-STATUS.md).

# Arrowhead core systems in Rust

2026-10-18 candidate hardening: mandatory deployed CRLs, native CA publication, TLS-material reload and current-image test evidence. See [ISO/IEC 27001:2022 acceptance register](docs/SECURITY-ACCEPTANCE-ISO27001.md). This is not certification or full Java feature equivalence. Automatic leaf renewal and production load/soak qualification remain open.


Native Rust implementations of the five active core modules in the local `ah5-core-java-spring` reference. Each system has a named executable and its own configuration, certificate identity, listen port and state file. No Java, Python or Go subprocess implements its services.

**Status: tested development HTTPS profile, not complete Java feature parity or a production-qualified interchangeable replacement.** All 91 extracted Java HTTP method/path mappings have handlers. That does not establish matching validation, DTO/error behavior, policy settings or every integration. In particular, advanced dynamic orchestration and MQTT APIs remain incomplete. Read [COMPATIBILITY.md](COMPATIBILITY.md) before substituting a Java system.

| Java module / Rust executable | Canonical identity | Implementation |
|---|---|---|
| `serviceregistry` | ServiceRegistry | `src/registry.rs` |
| `authentication` | Authentication | `src/authentication.rs` |
| `consumer-authorization` | ConsumerAuthorization | `src/authorization.rs`, `src/tokens.rs` |
| `serviceorchestration-dynamic` | DynamicServiceOrchestration | `src/orchestration.rs` |
| `serviceorchestration-simple` | SimpleStoreServiceOrchestration | `src/orchestration.rs` |

The orchestration variants share their API but implement different selection behavior. Normally choose one per cloud. Running both requires distinct identities, ports, state files and deliberate service selection. The named binaries reject a configuration for a different role; `arrowhead-core` is an optional unified launcher for the same native library.

## Build and verification

Requires Rust/Cargo 1.89 or newer, a C build toolchain for `ring`, and a Unix platform. Tested with Rust 1.99.0 on macOS ARM64. The later native candidate is built and functionally exercised in Linux containers; see current deployment evidence. OpenSSL is used **only by the tests** to generate isolated PKI and independent AES fixtures, not by the running core systems.

```sh
make build
make check
make test
make contracts
```

The five release executables are copied into `bin/`. Dependencies and exact versions are locked in `Cargo.lock`. Tests never target the deployed clouds: they generate temporary PKI/identities/state, open local ephemeral TLS listeners, and exercise a native child process. See [VERIFICATION.md](VERIFICATION.md) for measured results and limits.

## Configure and run

```sh
./bin/authentication --config examples/authentication.json
./bin/serviceregistry --config examples/serviceregistry.json
./bin/consumer-authorization --config examples/consumer-authorization.json
./bin/serviceorchestration-dynamic --config examples/serviceorchestration-dynamic.json
```

The examples are configuration templates, not a provisioned cloud. Replace the fictional cloud identity, endpoints, advertised addresses and file references. Keep `register: false` until trust, credentials, permissions and routing work. Example generation rewrites `examples/`; keep operational configurations in a separate private location.

Configuration is strict JSON with **Rust's actual field spelling**: `authenticationUrl`, `registryUrl`, `authorizationUrl`, `cloudSuffix`, `privateKey`, etc. It is not a Java `.properties` file or the earlier Go configuration schema. Unknown fields and trailing JSON are rejected. Public HTTP, declared `Bearer SYSTEM//...` identities, forwarded-certificate headers and TLS verification bypass switches are not supported.

### Provisioning order

1. Provision a trusted CA bundle and one system-profile certificate/key per system, with CN `<SystemName>.<Cloud>.<Organization>.arrowhead.eu`, DN qualifier `sy`, appropriate client/server usages and valid DNS/IP SANs. A Sysop client may use a trusted `sy` or `op` profile with the matching identity. Private key and password files must have owner-only permissions. The CA signing key is neither required nor loaded by these systems.
2. Bootstrap Authentication **only into an empty identity store**. Its example seeds Sysop from a referenced private password file. Add additional `bootstrapIdentities` deliberately, or use the verified Sysop identity-management API to provision core-system identities and their individual passwords. Each seed is an explicit `{systemName,passwordFile,sysop}` record. Bootstrap never overwrites an existing store; changing a seed file is not password rotation. Core processes need their own `passwordFile` when contacting authorities or registering.
3. Set all explicit authority HTTPS origins and resolvable addresses. Certificates are checked for normal chain/time/SAN validity **and** the expected Authentication, ServiceRegistry or ConsumerAuthorization system CN/profile before credentials are sent. A same-CA substitute with another system name is rejected.
4. ServiceRegistry authorized lookup uses ConsumerAuthorization management checks. Its configured `discoveryDirectAccess` names bypass lookup filtering and therefore must be deliberate, trusted core identities. The example lists Authentication, ConsumerAuthorization and the two orchestrators. The authorizer must be able to perform system lookup for metadata policies without a recursive lookup/authorization dependency.
5. ConsumerAuthorization's example explicitly whitelists ServiceRegistry and the orchestrators for management checks/token generation. **The current whitelist grants broad management access**, not per-operation least privilege. Treat it as a development-profile trust boundary. Grant business policies through verified Sysop management. Ordinary providers can manage only their provider-level policies; management policies take precedence.
6. Give each process a distinct private state directory/path. Existing Java databases and previous Rust cloud state are not compatible; do not replace or rename them into these paths. State uses process locking and atomic JSON snapshots, not SQL/JPA. Back up state and secrets separately; recovery after network side effects may need reconciliation.
7. Optionally configure `crlFile` with issuer-signed PEM CRLs. Revocation checks cover end-entity certificates and enforce CRL expiration; Changed TLS/CRL material is reloaded for new connections and clients, failing closed on invalid changes; TLS resumption is disabled in the candidate. Missing matching revocation information fails closed when CRLs are configured. With no CRL configured, ordinary chain/time verification **does not** check revocation. New trust material does not retroactively terminate established sessions/connections.
8. For authorization tokens, provision an owner-only `tokenSecretFile` containing at least 32 random bytes. It protects token references and encrypted provider-key records; retain it with the state backup. RSA JWT signing uses the system TLS RSA key unless a separate owner-only `signingKey` is explicitly configured; the public-key operation returns the corresponding SubjectPublicKeyInfo bytes as Base64 text. Do not rotate these keys blindly over retained token/key state.
9. Optionally enforce Blacklist (the Java `enable.blacklist.filter`): with `upstreams.Blacklist` set to the Blacklist's HTTPS origin, every requester except a verified sysop, the system itself, Blacklist and `blacklistExclude` is checked with Blacklist `check` and refused (403) when listed. While Blacklist cannot be reached the request is refused, unless `blacklistOptional` is set. Exclude the core systems so that their bootstrap does not depend on Blacklist. The unauthenticated identity bootstrap lookup is not checked.
10. After qualification, enable `register` with the correct `advertiseAddress`/`advertisePort`. Registration retries in the background. A successful echo or open listener is not proof that registration, all dependencies, policies or the cloud are ready.

All ordinary business/management calls require mutual TLS plus `Authorization: Bearer IDENTITY-TOKEN//<token>`. Verified token identity must equal the client certificate's local-cloud identity. Login/logout/change and echo are certificate-only; identity operations additionally check the supplied credentials against that certificate identity. Management requires a verified sysop or explicit whitelist, with additional owner rules in business handlers.

## Implemented behavior

- Registry device/system/service discovery and management, interface templates, expiry, provider ownership, authorization-filtered lookup and deletion cascades.
- Bcrypt PASSWORD identities, one active opaque session per identity, credential changes, session verification/revocation and management. Raw passwords and raw identity tokens are not stored.
- Management/provider policy precedence, scoped ALL/WHITELIST/BLACKLIST/SYS_METADATA policies, usage/time-limited tokens, Base64 self-contained tokens and RS256/RS512 JWTs. Usage counters are consumed atomically. Self-contained tokens must be verified by providers; the reference-token verification endpoint deliberately rejects them.
- AES ECB/CBC with Java-style PKCS5 padding for compatible self-contained-token transport, and AES-GCM wrapping of persisted provider encryption keys. ECB/CBC are legacy interoperability formats, not preferred designs for new protocols. Providers must use the correct wire format and verify identity, scope, expiry and signatures as applicable.
- Local dynamic discovery, consumer authorization, interface-operation filtering, preferred providers, matchmaking, token assignment and atomic exclusive locks.
- Simple-store candidate CRUD, unique positive priorities per consumer/service, preference and matchmaking selection, retaining the Java result DTO's historical field spellings `cloudIdentitifer` and `serviceDefinitition`.
- Orchestration subscriptions, explicit push triggers, persisted jobs/history and pinned HTTPS notifications. Restarted in-progress PUSH jobs are retried; side effects are at-least-once and consumers must tolerate duplicates. Callback failure is terminal ERROR for that attempt; a new trigger is explicit. This differs from full Java scheduling/event semantics.

Details and remaining work are in [COMPATIBILITY.md](COMPATIBILITY.md). This repository does not update LocalCloudManager, support-system implementations, cloud containers, trust stores or deployment configuration.

## Arrowhead LaTeX documentation

`documentation/` contains editable SysD, SysDD, SD and HTTPS IDD sources for all five systems, with the original Arrowhead class/logo assets. The combined catalogue is `Rust-Core-Systems.tex`; its compiled preview is under `output/pdf/`. Every document is marked DEVELOPMENT.

```sh
make docs
```

LaTeX needs the packages used by `arrowhead.cls`, plus `longtable`, `booktabs` and `xurl`. Compile individual documents from the `documentation/` directory so the class/logo resolve. These are multi-file LaTeX documents, not standalone built-in-editor compiler inputs.

The native Rust documentation generator reads the actual sibling Java core/common sources, hashes all Java files, extracts Spring mappings using **class-qualified constants**, audits method/path presence, and fails on unresolved or absent mappings. `documentation/contracts.json` records the source hashes, route inventory, services and limitations. It is not semantic-equivalence evidence or an assertion of a pristine upstream release tag. LaTeX documents are generated: edit the generator for durable changes; operational configs and handwritten verification notes are separate.

This delivery is source and documentation only. Existing Java, Go and Rust clouds, stored data and working federation remain unchanged. EPL-2.0 and reference attribution are in `LICENSE` and `NOTICE.md`.

## Listening port

`"listen"` is optional. Override with `"listen": "host:port"`, `SERVER_PORT=N` or `--server.port N`; the port overrides keep the configured host.

| System | Role | Default |
|---|---|---|
| DynamicServiceOrchestration | `serviceorchestration-dynamic` | 127.0.0.1:8441 |
| SimpleStoreServiceOrchestration | `serviceorchestration-simple` | 127.0.0.1:8442 |
| ServiceRegistry | `serviceregistry` | 127.0.0.1:8443 |
| Authentication | `authentication` | 127.0.0.1:8444 |
| ConsumerAuthorization | `consumer-authorization` | 127.0.0.1:8445 |

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
