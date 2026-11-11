# Current engineering update

Native AMQP monitoring publishers, collector bindings, SQLite history/outbox, MQTT/AIGym consumption, native federation discovery/negotiation/encrypted forwarding and RandomDataProducer are deployed and tested. Earlier absence claims for these workers are superseded. Other broker integrations, provisioning, full DTO parity and organisational certification gates remain open. See REPLACEMENT-STATUS.md and FUNCTIONAL-FEDERATION.md beside this document for evidence and precise boundaries. The user specified RandomDataProducer → DataManager and functional acceptance only, with no performance requirements.

# Native Rust candidate: ISO/IEC 27001:2022 acceptance register

Date: 2026-10-19. Status: engineering evidence under development, **not certified and not production accepted**.

## Scope and authority

The user selected ISO/IEC 27001:2022. The proposed technical scope is the native Rust candidate at `Arrowhead-test-cloud-rust/candidate-native`, its 21 microsystems plus native test application, encrypted edge relay, Docker control gateway, source, dependencies, configuration, PKI and persisted state. Approved federation work additionally changes the shared relay's scoped ACL/public CRL/network configuration, Java/Go federation peer binaries and explicit neighbour/foreign-consumer permissions. Cloud identities and business data remain separate; the older Rust cloud is untouched. Disposable interoperability identities/certificates are removed/revoked after tests. Concurrent external Java core updates are recorded separately. This technical boundary is not an approved organisational ISMS scope.

ISO/IEC 27001 concerns an organisation's information security management system, risk assessment and treatment, not merely passing application tests. The [official ISO description](https://www.iso.org/standard/27001) is the public reference; the licensed standard and an assessor must govern any formal conformity assessment. The selected 2022 edition and any applicable amendments must be agreed with the assessor.

No certificate, independent audit, accredited assessor opinion or exhaustive clause-by-clause compliance statement is issued by this report. The index below is engineering input to an ISMS, **not a Statement of Applicability**. Control titles and applicability must be checked against the organisation's licensed standard.

## Evidence index and acceptance gates

| Area | Local evidence / implementation | Remaining acceptance gate |
|---|---|---|
| Asset and configuration inventory | Compose project, roles, private networks, image IDs, source hashes and deployment snapshots | Approve asset owners, information classifications, external dependencies and ISMS scope |
| Identity and access | Mandatory mTLS; local-cloud CN/profile binding; identity tokens bound to certificate; pinned upstream authority; manager sessions and confirmation guards | Independent access review, joiner/mover/leaver process, emergency access and periodic recertification |
| Cryptographic lifecycle | Native CA signed CRLs, publish-on-revocation, 60-second publication refresh; inbound/outbound TLS reload; disabled TLS session resumption; expiry checks | Automated leaf key renewal/rollover, root rollover ceremony, backup key custody, compromise drills and agreed cryptographic policy |
| Network isolation | Internal candidate and control networks; localhost-only edge ports; no application Docker socket; bounded control gateway | Host/firewall review, broker trust model and controlled inter-cloud threat testing |
| Vulnerability management | Four locked Rust dependency graphs audited with cargo-audit; evidence records database revision and lockfile hashes | OS and native-library advisory coverage, image SBOM, repeatable scan cadence, remediation SLA, signed release provenance |
| Secure development and verification | Unit, integration and process tests; negative TLS/auth tests; strict lint; live candidate smoke/regression checks | Independent review, Java differential DTO/behaviour suite, abuse/fuzz tests and approved release criteria |
| Logging and monitoring | Bounded container logs, native AMQP publishers/collector, SQLite history/outbox and MQTT/AIGym pipeline with recovery tests | Central retention/integrity, trusted time synchronisation, alert ownership and incident exercises |
| Availability and recovery | State retained across candidate upgrades; source/config backups; bounded resource and connection limits | Encrypted off-host backup, restore/RPO/RTO exercise, capacity planning, fault injection and sustained workload qualification |
| Operational governance | This risk and acceptance register; candid unsupported-feature reporting | Approved policies, training, supplier/legal requirements, internal audit, management review, corrective actions and independent certification process |

## Unclosed engineering boundaries

1. **Full Java feature/DTO interchangeability:** not established. Route presence is not behavioural equivalence. Compare validation, response envelopes, status codes, pagination, policy semantics, persistence and side effects against the Java sources and shared fixtures. Current explicit 501/degraded results remain truthful.
2. **Manager AMQP publisher and monitoring workers:** implemented and locally tested with mTLS/EXTERNAL authentication, hostname/CN checks, authorised bindings, bounded payloads, publisher confirms, durable outbox, deduplication and restart/reconnect tests. Other support-system broker integrations and independent operational acceptance remain open; see REPLACEMENT-STATUS.md.
3. **Federation and tunnel:** native workers and explicit Lab↔Company peer bindings are now active. Actual Java/Go↔Rust discovery, AH-GT-1 negotiation and encrypted SenML forwarding are exercised, with method/path and certificate/token denials, replay/crypto fixture tests and bounded reconnect/draining behaviour. The earlier transport-only checkpoint is historical. Full DTO/error/chaos coverage, independent cryptographic review and organisational relay-server CRL provisioning remain open; the existing shared broker's image/root execution is not cleared by application tests. See FUNCTIONAL-FEDERATION.md and the timestamped evidence.
4. **Onboarding provisioning:** approval records are not bootstrap authentication, credential/registry provisioning, renewal or offboarding. Require negative/replay tests, least-privilege CA permissions and compensating cleanup on partial failure.
5. **Dependency advisory clearance:** RustSec results cover known advisories in the locked Rust graphs only, not every native component or OS package, unknown flaws or future disclosures. Zero known matches is not a general security guarantee.
6. **Functional workload accepted:** the user selected RandomDataProducer → DataManager and explicitly set no performance requirement. Registration, authorised orchestration, values, persisted SenML and inter-cloud functionality are the acceptance scope. A low-rate sequence spanning credential refresh is a functional regression, not a throughput/soak qualification. Production workload/SLO selection remains a separate future operational decision, not a blocker to this functional acceptance.
7. **Automatic rotation:** TLS material reload is implemented; scheduled key generation, renewal, verified activation, old-certificate revocation and rollback are not. Existing individual certificate/key bind mounts must be replaced by a deliberately scoped atomic-generation mount design before claiming automatic rotation.
8. **Certification:** open until the organisation defines scope, owners, risk criteria, treatment and evidence, conducts its internal audit/management review, and arranges independent assessment.

## CRL enforcement contract

Every candidate microsystem is configured with `/run/trust/current.crl.pem`. Only CertificateAuthority can write the shared public trust directory. It publishes a new signed CRL after successful revocation operations and every 60 seconds. Other microsystems mount that directory read-only, avoiding stale single-file bind mounts after atomic replacement. Health checks also use the CRL. The file contains no private key.

New incoming connections and newly created outgoing clients fingerprint and reload certificate/key/CA/CRL material. An invalid or missing changed bundle rejects new connections/requests rather than silently retaining a last-known-good verifier. CRLs are checked for signatures, issuer and expiry during certificate verification. Session resumption is disabled to prevent a previously authenticated session bypassing a new revocation.

**Existing connections are not forcibly terminated by publication.** Production listeners bound connections to 60 seconds. Requests already in flight can finish within that bound; revocation is not an instantaneous cancellation mechanism. End-entity revocation is checked; root compromise requires trust-anchor rollover. A host/CA compromise can replace trust material, so filesystem ownership and key custody remain security boundaries. Monotonic anti-rollback of previously valid signed CRLs is not implemented.

Revocation API success now includes an attempted synchronous public CRL publication in the configured candidate. If publication fails, the request returns an error, although the revocation may already be durably recorded; publication retries in the background. The final live test proves fresh TLS rejection on all 22 configured microsystem/application listeners without container restart; connection lifetime and root-compromise limits still apply. These checks do not claim browser-client revocation enforcement on the password-based console, which does not accept client certificates.

## Organisational decisions needed

The standard and functional workload have been selected. The organisation still needs to name ISMS/risk owners, approve organisational scope/risk criteria and select an independent assessment route. Production workload/SLOs have not been requested for this functional deployment. Retain the candidate designation until the remaining engineering and organisational gates are satisfied.

## Evidence locations

Evidence progresses through `hardening-evidence-20261018/`, `replacement-evidence-20261018/` and the later `federation/` checkpoint. Live results include `revocation-results.json`, `smoke-results.json`, `support-smoke-results.json`, `manager-test-results.json`, `manager-deployment-snapshot.json` and `load-baseline-results.json` where present. Historical evidence is dated and must not be interpreted as a current-image result. Failed trials are retained separately, including the shared-login token collision when two host suites ran concurrently; the smoke suite was repeated alone. The dated backup directories preserve source/settings, not off-host disaster recovery.

[RustSec advisory database](https://github.com/RustSec/advisory-db) and [cargo-audit documentation](https://github.com/rustsec/rustsec/blob/main/cargo-audit/README.md) describe the dependency scanner's scope.

## Final functional checkpoint — 2026-10-19

Revision r5 passes the agreed functional producer/historian workload, all four encrypted Java/Go/Rust tunnel directions, the 65-write scheduled-reconnect regression, broker recovery, 22-listener TLS revocation, browser checks and source/deployment audit. Exact counts and scope are in REPLACEMENT-STATUS.md and candidate-native/functional-evidence-20261019/verification-summary.json. Broader engineering and organisational gates remain open.
