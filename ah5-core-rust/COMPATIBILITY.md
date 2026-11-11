2026-10-19 functional candidate update: native federation, encrypted Java/Go interoperability, RandomDataProducer and monitoring are deployed and tested. The agreed workload is RandomDataProducer → DataManager, functionality only. Full Java replacement and ISO certification remain unproven. See [current status](docs/REPLACEMENT-STATUS.md) and [functional federation](docs/FUNCTIONAL-FEDERATION.md). Older dated evidence below is historical.

# Compatibility and remaining implementation work

Target: the five modules and local changes in `ah5-core-java-spring`, nominal system version 5.2.2. **Full Java equivalence remains incomplete.** The delivered Rust systems form a tested native HTTPS development profile; do not replace the Java deployment solely on route-count or build evidence.

| System | Delivered behavior | Material remaining work |
|---|---|---|
| ServiceRegistry | Device/system/service discovery and CRUD, templates, ownership, expiry, authorization-filtered lookup and cascades | Full Java interface-property validator catalogue, normalization/version-range/alive-time/address filtering, discovery-policy configuration, exclusivity integration semantics, framework events and Java SQL import |
| Authentication | Bcrypt PASSWORD identities, certificate/credential binding, opaque sessions, change/logout/revocation, sysop management | Complete Java query/time filters, all framework configuration/transport behaviors, SQL/session import, rate/soak/fuzz qualification |
| ConsumerAuthorization | Management-policy precedence, scoped rules, metadata policy evaluation, usage/time tokens, Base64/RS256/RS512 self-contained tokens, AES wire/key wrapping | Full DTO/error/filter semantics, exhaustive foreign-consumer/token DTO/crypto fixtures, MQTT services, database/key-state migration, comprehensive Java cryptographic interoperability fixtures |
| DynamicServiceOrchestration | Persistent PDE plant scopes/priorities, local/inter-cloud discovery and negotiation, authorization, operation filtering, token assignment, preferences, matchmaking, atomic exclusivity, history, explicit HTTPS push | Translation orchestration, QoS/blacklist pipelines, full Java matchmaking/filter options, automatic registry-event reevaluation and MQTT notification |
| SimpleStoreServiceOrchestration | Candidate CRUD/positive unique priorities, sparse Java-style results, preferences, matchmaking, history, subscriptions and explicit HTTPS push | Complete normalization/query/history semantics, registry-event scheduling/reevaluation, MQTT callbacks, SQL store/history import |

Dynamic requests that enable unimplemented integrations fail explicitly with 501. Foreign-consumer management token requests use explicit cloud-scoped policies; full Java DTO/crypto parity remains unproven. Unsupported custom template validators and metadata operators are rejected rather than treated as satisfied. Simple-store criteria that the Java simple-store design ignores generate warnings; this is not a promise to apply dynamic criteria in the simple variant.

## Security and operational boundaries

- Only the certificate verified by the native TLS listener supplies peer identity. Declared-identity and forwarded-certificate headers are not trusted. Authorization credentials are bound to certificate identity. Unknown configuration keys fail closed.
- Authorities are pinned by system CN/profile as well as normal certificate validation. Application JSON claims are not a substitute for that TLS check. Local name/profile parsing is a minimal DER subject parser operating **after** rustls/webpki cryptographic verification; it is not a general X.509 validator.
- System/client trust anchors, optional leaf CRLs, broker trust and consumer-side self-contained-token validation remain separate operator responsibilities. Configured TLS/CRL material reloads for new connections/clients; the candidate enables these checks and disables TLS resumption. There is no OCSP/CRL auto-download, intermediate-chain revocation promise or distributed key rotation service.
- Management whitelists and registry direct-discovery lists are broad powers. Per-operation least-privilege equivalence to every Java deployment policy is not established. Register only explicitly trusted core identities in these lists.
- Server connection/handshake/header/body limits and an eight-worker identity hashing limit constrain resources, but do not establish rate-limit, denial-of-service, load/soak or production readiness.
- JSON snapshots replace the Java databases. No automatic import, existing-session portability, multi-process shared state, clustered coordination or encryption of the entire database is provided. Passwords are bcrypt hashes; identity sessions and reference tokens are represented by digests/HMAC references; provider keys are authenticated ciphertext, not plaintext database entries.
- A successful local transaction cannot guarantee rollback of already completed network operations. Registration and token issuance across systems are not distributed transactions. Exclusive locks are local to one orchestration store, not globally coordinated across clouds or orchestration variants.
- Push jobs can be retried after an interrupted process and therefore callbacks are at-least-once across restart. Callback recipients must deduplicate or make side effects idempotent. Full Java callback payload/status/transport equivalence and all retry/error semantics need golden-contract tests.
- Generated service descriptors use the delivered generic HTTPS interfaces and operation names. They do not certify every Java interface-policy option, framework registration event, DTO constraint, exception code or Swagger behavior. No fake MQTT service endpoint is advertised.
- `Cargo.lock` fixes the versions used. Static checks/tests are not a vulnerability scan, formal proof or certification. The later candidate has Linux-container functional deployment evidence; this is not cross-platform/production qualification.

## Release gates before Java replacement

1. Complete the remaining implementation work required by that system's real deployment, including integrations that currently return 501.
2. Replay success, invalid, unauthorized, expiry and failure DTO/status/error fixtures against the exact hashed Java source and Rust implementations. Compare side effects, policies and service descriptors, not only URLs.
3. Test real Java/Rust/Go mixed-cloud dependencies, certificate profiles/rotation/revocation, token formats, broker ACLs, orchestration consumers and inter-cloud peers under least privilege.
4. Demonstrate database import, crash and duplicate-delivery recovery, backup/restore, secret rotation and a tested rollback to Java without losing data.
5. Perform dependency/advisory review on the actual locked dependencies and target toolchain, followed by Linux/container, load/soak/fuzz and operational qualification.
6. Confirm LocalCloudManager discovery, readiness, management and UI behavior before approving any deployment.

The original source-only delivery was followed by the separately identified native candidate deployment and approved scoped Java/Go/relay trust changes. Existing cloud data/identities are not migrated; current evidence is indexed in docs/REPLACEMENT-STATUS.md.
