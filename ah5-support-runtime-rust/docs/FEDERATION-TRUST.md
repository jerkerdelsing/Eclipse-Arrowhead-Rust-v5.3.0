# Rust candidate federation trust checkpoint

Dates: 2026-10-18–19. This checkpoint is **transport trust preparation, not functional federation or replacement acceptance**.

## Applied changes

- The native Rust CertificateAuthority supports the optional Boolean `relay` on `POST /certificate-authority/sign`. It defaults to false. Only Sysop may set it to true, only for local Gatekeeper or GateTunnel with profile `sy`. Other requests are denied; non-Boolean values are rejected. It ignores arbitrary CSR subject extensions, derives O from the configured organisation and OU from the cloud name, and issues clientAuth-only certificates. Issuance is recorded in the existing certificate inventory and revocation/CRL workflow. This is a documented candidate-specific administration extension, not a claim of Java DTO equivalence.
- Separate RSA-3072 relay keys were generated for `Gatekeeper.RustDev.Lab.arrowhead.eu` and `GateTunnel.RustDev.Lab.arrowhead.eu`. The original cloud identities, keys, CA, accounts and data were retained. Ordinary application certificates were not replaced.
- A separate, 30-day cross-certificate of the existing candidate CA public key was signed by the existing relay trust authority. It has critical directory-name constraints `O=Lab,OU=RustDev`, CA path length zero and signing-only key usage. The two relay leaves expire within 29 days. This explicitly delegates only the Lab/RustDev relay namespace; it does not rename RustDev to Company, import Java/Go application trust roots or copy an authority's private key into any application/relay container.
- The shared relay ACL names the full verified Rust client subjects. Each role can read only its own RustDev inbox and write only to the corresponding TestCloud/GoCloud role below its own sender CN. Existing Java/Go ACLs remain intact.
- The shared relay mounts only the candidate's **public CRL directory**, read-only. All three CRL paths are explicit. The watcher now stops the broker if a required source disappears, rather than replacing the bundle with a partial set. Broker CRL validation remains enabled and reloads changes. Existing connections are not forcibly disconnected by revocation.
- The shared relay was recreated to activate its mount/configuration change. Java and Go application binaries, identities and data were not changed. The candidate applications were recreated with the updated native image; all 25 containers are healthy.

## Evidence

| Check | Passed | What it establishes |
|---|---:|---|
| Native Rust support tests | 48 | Includes relay issuance permissions, subjects, client-only purpose, issuance tracking and non-blocking MQTT ACK regression; isolated TLS/process regressions |
| Strict support lint | pass | All targets, warnings denied |
| Relay transport/security | 28 | Both roles, both directions with Java/Go, PKIX constraints, missing/ordinary-certificate rejection, spoofing and foreign-inbox denial, retained Java↔Go transport |
| Disposable relay revocation | 7 | Accepted before revocation, native CA API success, then actual fresh relay TLS rejection without restart; active Rust/Java/Go credentials still accepted |
| Monitoring restart recovery | 54 | Revised post-restart history/MQTT match, native consumer reconnect and retained history |
| MQTT burst regression | 3 before + 3 after restart | All 100 QoS-1 fixture messages durably consumed in each run; bounded ACK regression, not load/soak |
| Candidate deployment/source audit | 482 | 25 healthy containers; image/source hashes; unchanged isolation and restricted mounts |

The read-denial checks deliberately include repeated positive controls, so these are assertions, not counts of distinct features. Probes use unmatched `reply` messages with random correlations; they cannot initiate GSD, negotiations, sessions or provider writes. Test clients run on the host and are not service implementations.

The disposable revocation test's key is retained privately for reproducibility; its certificate is revoked. Active credentials remain private under `candidate-native/federation/{gatekeeper,gatetunnel}/`, with no new mounts into candidate applications. They are staged for native-worker integration, not used by a Java/Go/Python substitute.

Credential separation is not application capability separation: these relay leaves are issued by the candidate CA and retain the system CN/profile. ClientAuth-only does not itself prevent their acceptance at a local application TLS listener; local identity tokens/passwords and policy checks remain additional gates. A future worker must not treat a relay certificate as an unrestricted application credential. Distinct application/relay-purpose enforcement needs explicit review before operational acceptance.

## Not yet activated or implemented

The running Rust Gatekeeper/GateTunnel still have no native relay discovery, negotiation or tunnel worker. The Java and Go peer policy currently requires the same organisation (`Company`); the candidate remains `Lab`. Their neighbour rows and application peer policies have therefore **not** been changed to advertise an inactive/incompatible peer. User approval for scoped neighbour/relay trust changes has been received and is no longer a permission blocker.

Next integration must explicitly bind configured cloud/organisation identities at every layer: neighbour selection, MQTT sender/response correlation, expected relay certificate CN, ICN transcript, provider-side consumer authorisation and GateTunnel forwarding. It must port AH-GT-1 signed X25519 exchange, directional HKDF/AES-GCM protection, replay/expiry/body/operation limits and real local HTTPS tunnel listeners. No fallback to unprotected legacy traffic is permitted. Verify actual GSD, ICN and provider requests in both directions, negative authorisation and replay cases, plus existing Java↔Go application flows.

Broker transport success does not prove those functions. Rust federation operations still return their existing unsupported responses. No end-to-end or whole-cloud parity, production certification, automatic renewal, CRL-triggered cancellation of established sessions or load/soak acceptance is claimed.

## Recovery defect found during this checkpoint

The first final monitoring restart trial passed 53 assertions but timed out waiting for one MQTT observation at AIGym. Investigation found that its single event-loop task could await an ACK request into a full bounded channel while that same task was required to poll and drain it. Broker logs showed the collector reconnecting but no AIGym reconnect, consistent with the consumer waiting indefinitely rather than resource exhaustion.

The native subscriber now advertises a QoS receive maximum of four, below its eight-slot request capacity, and queues ACK/disconnect operations without waiting on its own driver. Excess channel pressure causes a bounded reconnect rather than a deadlock. The new unit test exercises the window/capacity invariant and immediate overflow rejection. Durable storage still precedes ACK. This change does not claim persistent MQTT subscriber sessions or guaranteed delivery through every broker outage.

The failed trial remains as `pipeline-before-ack-fix.json` and its log. The old test also timed out after the ACK fix, despite healthy reconnections and fresh matched history/MQTT data: its selected marker could precede the broker restart and fall into a clean-session disconnection gap. That result is retained as `pipeline-old-marker-after-ack-fix.json`. The revised test timestamps recovery and requires genuinely post-restart native TimeManager observations present in both durable history and AIGym, plus consumer reconnection. It tests restored delivery, not lossless delivery to an offline subscriber. Repeat evidence includes 100-message QoS-1 bursts before and after restart and the revised process/broker recovery pipeline. These bounded regressions are not throughput/soak qualification.

## Rebuild, evidence and rollback

Common native image: `arrowhead-rust-candidate:5.2.2-relay-recovery-20261018`. Canonical changes: `ah5-support-rust/src/ca.rs`, `src/aigym_mqtt.rs` and `tests/certificates.rs`. The locked rebuild context and `replacement-source-manifest.json` were updated consistently.

Evidence and host-only probes are retained in `candidate-native/federation/`. The public trust/issuance manifest contains no private keys or passwords. `candidate-native/federation-backup-20261018/` retains the previous candidate compose/source/manifest/report and shared relay compose/ACL/watcher/README.

To roll back relay configuration, restore only those backed-up shared relay files and recreate the relay; this briefly interrupts Java/Go relay sessions. Preserve all cloud state. Remove the Rust ACL entries/mount before retiring these relay credentials and explicitly revoke the two active issuance IDs if abandoning them. Do not delete the existing organisational authority, regenerate another cloud's CA or replace Java/Go application trust. Candidate image rollback restores the previous compose/image after preserving current state; do not restore an old CA state snapshot over later revocations.

Credentials need renewal before their recorded expiry; no automatic rotation has been introduced. This checkpoint supplies local technical evidence, not ISO/IEC 27001:2022 organisational certification.

## CRL publication interval (SOS-15, 2026-11-10)

The CertificateAuthority used to republish `crlPublishFile` every 60 s with a new `lastUpdate`, so every reader that
watches the file (the relay's `crl-watch.sh`) reloaded once a minute. It now publishes at start-up and right after a
revocation, as before, while the 60 s check (`ca::refresh_crl`) rewrites the file only when it is missing,
unreadable or not signed by this CA, when its revoked serials differ from the CA's revoked certificates, when it is
older than 24 h (`CRL_REFRESH_SECONDS`), or when it expires within a day. CRLs stay valid for 7 days. Test:
`tests/certificates.rs`, `periodic_crl_refresh_only_when_needed`.
