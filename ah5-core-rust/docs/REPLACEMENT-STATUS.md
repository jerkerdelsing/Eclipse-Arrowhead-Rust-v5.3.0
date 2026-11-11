# Rust candidate replacement status

Updated: 2026-10-19. Reference: separately running `arrowhead-v52-test-cloud`.

**The native producer/historian and federation workflows are implemented and functionally exercised. The cloud is still not proven to be a complete Java replacement.** Missing provisioning, support features and whole-cloud contract coverage must not be relabelled as certification or universal interchangeability.

## Deployed scope

The candidate keeps `RustDev.Lab.arrowhead.eu`, its own CA, identities and persisted data. It runs 21 native Rust core/support/manager microsystems, a native Rust RandomDataProducer, two brokers and two restricted gateways: 26 containers. No Java, Go or Python service implements a candidate microsystem. Host Python scripts are deployment/tests only; RabbitMQ and Mosquitto are infrastructure.

The current common application image and exact image ID are recorded in `replacement-source-manifest.json` and `manager-deployment-snapshot.json`. The final functional revision is `arrowhead-rust-candidate:5.2.2-functional-federation-r5-20261019`. Earlier dated image/test reports remain historical.

Java/Go Gatekeeper and GateTunnel now have explicit `RustDev=Lab` peer bindings and compatible federation binaries. The shared relay joins the internal Rust federation network, retaining its scoped subject ACLs and CRL mounts. Neighbour/foreign-consumer grants are additive and backed up; Java, Go and Rust identities/business data are not merged. Newer concurrent Java source changes were preserved, not overwritten. Separately observed Java core restarts are not attributed to this rollout. The older Rust cloud is untouched.

## Functional acceptance requested by the user

Workload: RandomDataProducer → DataManager. The producer offers random values in 0–100 and consumes DataManager's historian write operation. Acceptance concerns functionality only; no throughput, latency or soak requirements were specified.

- Native registration, local authorised orchestration and persisted local SenML are implemented.
- Real global discovery, AH-GT-1 negotiation and encrypted HTTP forwarding work with the Java and Go federation implementations. Separate foreign-cloud policies govern access; management APIs or broker connectivity alone are not counted as this proof.
- The native Rust producer delivers locally and into Go's DataManager. Go's existing producer delivers into the Rust DataManager. Historian API read-back confirms actual records rather than merely a successful publish counter. The existing Java/Go test-cloud producer applications are not silently reclassified as native Rust/Go/Java implementations by this work.
- Additional disposable Java/Go consumers exercise forwarding into Rust; the existing candidate TestConsumer exercises the reverse Java/Go paths. Disposable identities are removed and certificates revoked afterwards. Synthetic historian records remain as evidence.
- PUT-only sessions reject GET and unrelated API paths. Candidate identity tokens must match the client certificate. Crypto/reference-vector, replay-window and explicit peer/domain tests supplement live interoperability tests; they are not an exhaustive cryptographic or differential review.
- LocalCloudManager displays actual relay/session and producer delivery status. Its broad, explicit candidate GateTunnel management grant matches the reference operations-manager role. Ordinary identities remain denied management.

See [functional design and limitations](FUNCTIONAL-FEDERATION.md).

## Preserved security and monitoring controls

Mandatory local mTLS/CN/profile checks, certificate-bound tokens, pinned authorities, CRL publication/reload, disabled TLS resumption, console cookie/origin/session guards, private networks and restricted Docker control remain active. Candidate CA revocation is separately tested for fresh TLS rejection; API success is not used as a substitute for that test. Existing HTTPS connections are bounded, not instantaneously cancelled on revocation.

AH-GT-1 uses signed X25519 exchange, HKDF and directional AES-GCM with consumer/provider/cloud/operation/sequence bindings. Cloud-issued peer leaves have mandatory CRL validation. The organisation-issued relay server has CA/hostname/CN validation, but no organisational CRL is provisioned. Shared-broker image/root execution and organisational CA lifecycle remain infrastructure risks.

Relay work is bounded; unsent requests wait within the 128-slot/15-second request limit during reconnect. Credential refresh drains work and reconciles strict, size-bounded native MQTT protocol checkpoints. There is no non-strict broker-only session mode. MQTT may retransmit the same protocol packet; existing message/replay guards apply. A new application write is not automatically retried after an uncertain outcome. This is not distributed exactly-once delivery or automatic certificate renewal.

All 22 native publishers (including the application) feed the genuine AMQP → SysMonitor SQLite history/outbox → MQTT → AIGym path. Publisher confirms, persistent outbox, deduplication, authorised binding reconciliation and restart/reconnect tests remain in place. The earlier AIGym ACK/backpressure fix is retained.

## Verification and evidence

`functional-evidence-20261019/verification-summary.json` indexes exact final results and timestamps. Retained evidence distinguishes final-image checks from earlier revision regressions; counts are assertions, not numbers of completely equivalent systems.

The verification includes locked Rust core/support/manager tests, strict static checks, native cloud/support/console integration, all-publisher broker recovery, four-direction Java/Go/Rust encrypted tunnel probes, negative access cases, historian read-back, a functional reconnect-boundary sequence, fresh-connection certificate revocation and image/source/network audits. Existing RustSec results remain dated evidence: the four lockfiles are unchanged from the earlier zero-match audit, not newly cleared against every current advisory or OS/native package.

Failures are retained, including the initial producer-identity setup omission, policy-inheritance console regression, HTTP/2 origin-form incompatibility, reconnect/session checkpoint regression and a transient Java reference restart. Corrected tests are repeated; failed trials are not counted as passing evidence. A low-rate reconnect sequence is a functional regression, not a performance or soak benchmark.

## Final revision-r5 results

| Verification | Passed |
|---|---:|
| Core / support / manager Rust tests | 31 / 59 / 29 |
| Native cloud / support / manager integration | 153 / 34 / 60 |
| Monitoring pipeline and broker recovery | 56 |
| Fresh TLS revocation checks (22 listeners, including cleanup assertions) | 51 |
| Deployment/source/network audit (26 healthy containers) | 508 |
| Historian persistence/freshness assertions | 7 |
| Browser views / isolated UI rendering assertions | 7 / 6 |
| No-retry writes spanning scheduled relay reconnect | 65 |

All final checks pass. Four-direction encrypted interoperability includes negative operation/path/identity checks and disposable peer identity/certificate cleanup. Core/support/manager strict static checks pass. Counts describe assertions within their stated scope, not complete system equivalence. The browser test used a fresh process with an SPKI exception restricted to the candidate certificate; deployment trust was not weakened and no global CA was installed.

## Endpoints

| Interface | Endpoint |
|---|---|
| LocalCloudManager UI | https://127.0.0.1:10590/ |
| LocalCloudManager system API | https://127.0.0.1:10520/localcloud/ |
| Native RandomDataProducer | https://127.0.0.1:10550/random-data-producer/latest |
| SysMonitor | https://127.0.0.1:10517/sysmonitor/ |
| AMQP TLS / MQTT TLS | 127.0.0.1:10671 / 127.0.0.1:10883 |

The UI retains its existing console password/private CA. System APIs require appropriate candidate certificates and permissions. Dynamic tunnel ports are not published on the host. No root CA was installed globally.

## Remaining replacement blockers

| Area | Still open |
|---|---|
| Whole-cloud contracts | Exhaustive Java DTO, validation/error, pagination, policy, persistence and side-effect equivalence across all APIs. Successful monitoring/producer/federation paths do not establish this. |
| Federation completeness | Full nested DTO/filter parity, peer outage/chaos/exhaustive replay-abuse coverage, independent cryptographic review and organisational relay-server CRLs. Rust's segment-exact path grants are intentionally stricter than reference descendant matching. |
| Onboarding | Bootstrap certificate trust and device/system provisioning, renewal, offboarding and crash-recoverable distributed compensation remain unported; affected operations truthfully return 501. |
| Orchestration/choreography | Translation/QoS integration, complete simple-store contracts, multi-action/parallel/DAG scheduling and all associated callback/recovery semantics. |
| Support integrations | Full SenML/data-proxy/provider-MQTT behaviour, EventHandler MQTT/advanced retries, trusted SNTP, SNMP/QoS acquisition, translation-chain provisioning and Plant rule/orchestration synchronisation. |
| Lifecycle and supply chain | Automatic leaf-key renewal/verified activation/root rollover, complete OS/native advisory clearance/SBOM/provenance, off-host restore/HA and independent security review. |
| Organisational acceptance | ISO/IEC 27001:2022 ISMS scope, owners, risk treatment, internal audit/management review and independent assessment. No certification is claimed. |

Performance/soak targets are not a blocker for the functional acceptance requested here. They remain a future production qualification decision. Keep the candidate designation; do not advertise universal replacement readiness while the other gaps remain.

## Source and rollback

Canonical Rust sources are in `ah5-core-rust/` and `ah5-support-rust/`; the shared messaging crate is `ah5-core-rust/messaging/`. The locked, credential-excluding rebuild context is `candidate-native/replacement-build/`. The source manifest binds canonical and rebuild files to the configured image.

`blocker-backup-20261019/` retains original sources, configuration, policies and scoped peer/relay backups. Prior images remain available. Preserve later state before rollback; stop/revert only the affected candidate components, then reconcile added application/certificate/policy records explicitly. Merge any later unrelated Java/Go edits rather than restoring their entire files blindly. Shared-relay rollback briefly interrupts federation, not the independent cloud databases. Local backups are not off-host disaster-recovery certification.

The historical LaTeX/PDF documents are not regenerated equivalence proof. Current manager deployment documentation and the three-implementation SysML variability model point to this actual Rust deployment and its remaining limits.
