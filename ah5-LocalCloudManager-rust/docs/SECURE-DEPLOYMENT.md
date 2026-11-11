# Current native federation update (2026-10-19)

The active native candidate additionally runs RandomDataProducer and real Gatekeeper/GateTunnel federation workers. The console displays actual relay/session and producer delivery state. Explicit peer bindings keep Java, Go and Rust identities/data separate. LocalCloudManager has explicit candidate GateTunnel management rights, matching its Java reference role. See [functional federation](../../docs/FUNCTIONAL-FEDERATION.md) and [replacement status](../../docs/REPLACEMENT-STATUS.md) for current evidence and image IDs. The older dated deployment/image/count narratives below are historical, not current verification claims. The user specified RandomDataProducer → DataManager and functional acceptance only; no performance/soak target is required for that acceptance.

# Historical broker deployment update

LocalCloudManager now publishes native AMQP monitoring data and displays actual broker-backed SysMonitor providers/history/subscriptions. Current code uses Java-compatible monitor envelopes and the shared native messaging crate. See [replacement status](../../docs/REPLACEMENT-STATUS.md). Statements below that broker workers/publishing are absent describe earlier deployments. Whole-cloud parity and certification remain unclaimed.

# Current hardening note (2026-10-18)

The current candidate uses `5.2.2-crl-20261018` images. The 2026-10-17 deployment/test narrative below is historical unless superseded by this note. Current tests: 28 core, 42 parent support (including TLS reload), 29 manager; 145 + 34 + 60 live functional checks; 47 live revocation checks and 433 deployment audit assertions. All passed. The two-minute, two-client echo baseline recorded 1,182 requests, zero errors and p95 32.6 ms; it is not a production workload or soak qualification. Timer-driven CRL refresh was observed and its signature verified. See the ISO acceptance register and current hardening evidence for present qualification. The manager console remains https://127.0.0.1:10590/.

# Secure Rust candidate manager — active contract

The active executable is `LocalCloudManager --config CONFIG.json`. Only `src/secure_main.rs` starts it. The legacy environment-based main/router remain reference/test code and are not exposed by this executable. `autobins=false` prevents accidentally building the old launcher as an implicit executable.

## Architecture and access

Browser → fixed TCP gateway → native HTTPS console, password/session guards → pinned native mTLS provider client → candidate core/support services. The separate native mTLS system API has certificate-bound sysop authorization. Manager → private token-protected Rust Docker gateway → local daemon. That gateway independently resolves candidate labels and validates role/action; the manager never gets the daemon socket.

Console: `https://127.0.0.1:10590/` (also localhost). System API: `https://127.0.0.1:10520/localcloud/`. Private configuration and credentials live under `Arrowhead-test-cloud-rust/candidate-native/config/` and `secrets/localcloudmanager/`. The console password is the owner-only `console-password` file; server configuration receives only its scrypt hash. Browser certificate trust is not bypassed by deployment. The private candidate root is `secrets/ca.pem`; do not install it globally without an operator trust decision.

The new manager certificate/identity is LocalCloudManager.RustDev.Lab.arrowhead.eu, profile sy. Candidate CA issues it; identity provisioning verifies existing credentials rather than overwriting conflicts. The account is not a sysop. Dedicated management whitelists grant access in ServiceRegistry, ConsumerAuthorization, both orchestration variants, PlantDescriptionEngine, SysMonitor and Gatekeeper. These are broad management grants, not per-operation least privilege. Provider-scoped policies permit dataHistorian and sysMonitorHistory reads. No credentials or trust were imported from Java, Go or legacy Rust clouds.

## Configuration

Strict camelCase JSON rejects unknown keys. Required fields: cloudSuffix, project, listen, consoleListen, certificate, privateKey, ca, passwordFile, consoleHashFile, consoleOrigins, upstreams, dockerUrl, dockerTokenFile, advertiseAddress, advertisePort. Optional crlFile enables issuer CRL checks; the candidate now configures it on all 21 microsystems. TLS material is reloaded for new connections and outbound clients. Invalid or missing changed material fails closed; session resumption is disabled. Existing connections have a 60-second lifetime limit, not instantaneous revocation cancellation. No insecure mode exists. Upstreams are explicit bare HTTPS origins mapped to expected system names. Origins must contain no user credentials, query, fragment or path. Browser consoleOrigins include exact HTTPS scheme, host and port. The console filters each connection by source address before the TLS handshake (SOS-1, 2026-11-10), because any program can set Host and Origin: it accepts loopback, the gateway of one of the container's directly connected IPv4 networks (where Docker forwards a published port from; no container holds that address) and the optional consoleClients list of IP addresses, CIDR ranges or DNS names. Names are resolved every 10 seconds through the deployment's resolver and fail closed. List a TCP relay that publishes the console (for example `["edge"]`), never a network that ordinary systems share, and make that relay accept only the host. The Docker URL is the explicit private control-network HTTP gateway, never a generic arbitrary proxy.

TLS verifies chain, validity, SAN and local identity/profile. Outbound authority CN/profile is additionally pinned before sending credentials. Password/identity tokens are not logged; tokens remain in memory and refresh on expiry/401. Requests have connect/total timeouts, no redirects and bounded responses. Only If-Match may be added to authenticated conditional requests; Authorization override and CR/LF injection are rejected. Manager certificates and private secrets must have owner-only permissions.

Console sessions are instance-local, bounded128, expire after one hour and reset on restart. Cookies are project-named `__Host-` Secure/HttpOnly/SameSite=Strict with Path=/. Exact origins are checked, not only host names. TCP ports are not an intrinsic browser cookie isolation boundary. Scrypt hashing uses two bounded blocking workers and failed-login lockout; this is not full denial-of-service qualification. Confirmed mutations require X-Arrowhead-Action: confirm; that header is an intent guard, not cryptographic replay protection.

## System SD / HTTPS IDD

Produced service: localCloudManagement1.0.0, system5.2.2, generic_https/CERT_AUTH, basePath/localcloud. Registered operations: GET /management/status, /management/systems and /management/services. All require mTLS plus matching IDENTITY-TOKEN and verified sysop status. GET /monitor/echo is certificate-only. Declared-SYSTEM and forwarded identity headers are not accepted. Registration is periodically attempted; displayed registration state comes from actual ServiceRegistry records, not synthetic success.

## Console adapters

| Console API | Candidate behavior |
|---|---|
| /api/session | HTTPS login/state/logout; private scrypt hash; bounded in-memory sessions |
| /api/overview and /api/service-registry-management | Actual registry and scoped Docker inventory; dependency errors surfaced; naming not falsely validated |
| /api/orchestration/rules | Native simple-store query/create/remove, using uuids for deletion; selections are candidates, not proof of client capability or provider authorization |
| /api/plantdescriptions[/id] | Native /plantdescriptionengine/mgmt/plant-descriptions; POST201, PUT replacement, PATCH partial update, DELETE |
| /api/sysmonitor | Actual /history/systems and per-system observations; no silent empty-success on provider failure |
| /api/sysmonitor/subscriptions[/provider] | Real GET/PUT/DELETE; If-Match forwarded, stale409 retained; UI supplies viewed revision |
| /api/datamanager | Real SenML historian reads; base-name/base-time context retained in chart adaptation |
| /api/consumers | Actual authorization policies and simple-store records, not hardcoded TestCloud data |
| /api/intercloud | Actual neighbour administration; explicitly unavailable federation/tunnel data plane |
| /api/logs and /api/containers/role/action | Private gateway resolves candidate labels; only core/support role logs and start/stop/restart; infrastructure and manager lifecycle excluded |

Registry inventory is capped1000rows per query, with truncation rejected rather than silently counted as complete. Historian fan-out is limited32streams; telemetry history requests are bounded. Rendering is a bounded overview, not a full export. Sessions/history have no persistence database; provider-owned configuration, subscriptions, rules and plant records persist in their native stores. Multi-provider writes are not distributed transactions.

## Deployment, rollback and evidence

Docker project `arrowhead-rust-candidate` gains manager and manager-docker-proxy containers, plus two fixed encrypted TCP listeners. Original core/support images are retained. Seven candidate services were restarted to load manager whitelists; TimeManager was restarted as a lifecycle test. The manager is on internal candidate and control networks; the proxy is only on the internal control network. No gateway port is published. Both run non-root with read-only root filesystems, dropped capabilities and resource limits. The Docker socket is mounted only into the proxy; access remains powerful and the gateway code/secret are part of the trusted boundary.

`candidate-native/test_manager.py` records live integration checks in manager-test-results.json. Tests cover authenticated reads, real subscription/provider side effects and revision conflict handling, plant POST/PATCH/DELETE, simple rules, a candidate TimeManager restart, prohibited lifecycle operations, TLS certificate/token binding and original cloud start times. `browser-test.cjs` tests rendering/login/navigation in a fresh test browser with a certificate-specific, process-local SPKI exception only; it does not change global trust. UI screenshots and results are retained with deployment evidence.

The29manager package tests include18historical relocation tests, seven new helper tests and four secure-console integration tests. The41parent support tests include the added pinned conditional-header regression. Strict lint checks are run separately. Passing legacy tests is not secure-runtime equivalence evidence. Current live/browser results and exact image/source hashes are saved with the deployment; consult them rather than treating documentation as a test result.

Rollback inputs are preserved privately under candidate-native/manager-upgrade-backup-20261017/. Stop the two new containers, restore backed-up Compose/edge/configuration files and restart only the affected candidate services. Candidate-only manager identity/policy/certificate records are not automatically deleted or revoked by restoring files; an operator must reconcile them. Restoring the previous candidate snapshot does not require restarting or restoring any original Java, Go or legacy Rust cloud.

## Remaining boundaries

Manager AMQP publishing, the monitoring pipeline and native discovery/negotiation/encrypted tunnel forwarding are implemented and tested; their former absence is no longer an open boundary. Full Java feature/DTO equivalence, onboarding provisioning and other incomplete support integrations, production/ISO certification, complete OS/native dependency advisory clearance and automatic key renewal/root rollover remain unclaimed. Functional producer/historian acceptance does not require an unspecified load/soak qualification. CRL checks and publication/reload remain active; prior 21-listener evidence is historical and later tests include the added native application. Root compromise and signed-CRL rollback protection remain outside that proof. See ../../docs/SECURITY-ACCEPTANCE-ISO27001.md for the ISO/IEC 27001:2022 evidence and open organisational gates. Former relocation LaTeX/PDF documentation is historical, not regenerated proof. SysML records the three implementations and the current Rust workers without claiming universal interchangeability or parser qualification.
