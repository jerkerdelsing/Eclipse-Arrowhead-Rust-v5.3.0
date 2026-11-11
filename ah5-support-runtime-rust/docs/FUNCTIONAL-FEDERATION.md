# Native federation and functional acceptance

Date: 2026-10-19. Scope: the isolated `arrowhead-rust-candidate`, with explicitly trusted Java `TestCloud|Company` and Go `GoCloud|Company` neighbours. Cloud identities, accounts and business data remain separate. This is engineering evidence, not whole-cloud equivalence or production certification.

## Workload agreed with the user

Use RandomDataProducer as the random-number service provider and DataManager as its consumer/storage system. The application also consumes DataManager's `dataHistorian.put-data` operation. Acceptance is functional: registration, authorised local orchestration, values in 0–100, SenML persistence, discovery, negotiation and encrypted inter-cloud delivery. No throughput, latency or soak threshold was specified or is asserted. Disposable test consumers additionally exercise protocol interoperability and access denials; they do not replace the requested application workload.

## Implemented native Rust path

- `RandomDataProducer` is a native executable in `ah5-support-rust/src/producer.rs`. It registers its `randomNumberProducer` service and three genuine AMQP monitoring offerings, generates values, and publishes SenML locally and through inter-cloud orchestration. Its status separates local delivery, registration and foreign delivery errors/counters.
- DynamicServiceOrchestration implements `ONLY_INTERCLOUD` and `ALLOW_INTERCLOUD` through local, pinned Gatekeeper calls. ConsumerAuthorization recognises explicit `Cloud|Organisation` policy domains. Requested operation scopes are checked independently. Foreign metadata is not inferred from an unrelated local system of the same short name.
- Gatekeeper runs actual MQTT global discovery and negotiation. A peer needs both an explicit cloud-to-organisation binding and an approved neighbour record. Discovery responses are bound to that peer's cloud. Scoped foreign-consumer permissions are rechecked before provisioning a provider tunnel.
- GateTunnel performs the AH-GT-1 signed exchange and encrypted HTTP forwarding. RSA-PSS/SHA-256, X25519, HKDF-SHA-256 and directional AES-256-GCM match the Java/Go reference fixture. Sequence, direction, timestamp, certificate, peer, consumer and negotiated-operation bindings are enforced. The provider endpoint and operations are revalidated against the local registry before execution.
- HTTP/2 authorities are translated into the protocol's origin-form path/query; they are never forwarded as an absolute target URL. Session IDs accept the Java/Go base64url alphabet. Rust applies segment-exact operation matching and rejects traversal/encoded separators; this is intentionally stricter than the reference's descendant matching.
- Incoming application calls still use the candidate CA and local identities. Only the authenticated local GateTunnel may assert a remote consumer to native DataManager. The shared relay's organisational CA does not become a general application trust root.
- LocalCloudManager displays real Gatekeeper/GateTunnel relay and session state and the native producer's inter-cloud counters. It has explicit candidate GateTunnel administration rights, matching the reference operations-manager role. No ordinary identity receives these management rights.

## Limits and failure behaviour

The relay has 128 correlated request slots, 32 dispatch jobs, a 2 MiB packet limit and a 15-second overall request deadline. Unsent requests can wait for a connection within those bounds. A published write is never automatically retried: an interrupted in-flight write can have an uncertain result and must be reconciled by its caller.

The relay revalidates credentials on a scheduled reconnect. It pauses new local publications, drains in-flight work and retains bounded-duration broker sessions for queued QoS-1 messages. The connection still has a hard 60-second lifetime. Invalid/missing/revoked material fails closed rather than keeping an old verifier alive. This reconnect is not automated key renewal or CA rollover.

Each tunnel request/response body is at most 1 MiB. Tunnel connections are globally bounded at 64, simultaneous forwarding work at 16, and listener ports at 8200–8299 inside the candidate network only. Provider sessions expire after 12 hours or one idle hour. Shutdown cancels dynamic listeners. Peer/domain checks, replay guards and CRLs remain mandatory. The candidate's federation bridge is internal and is joined only by its two federation roles and the shared relay.

The shared relay sees metadata and ciphertext, not the protected HTTP bodies. These checks do not assert protection after endpoint compromise, independent cryptographic review, distributed exactly-once writes or full service DTO parity.

Cloud-issued federation peer leaves have mandatory CRL checks. The organisation-issued relay server is validated against the configured organisational CA plus its hostname and exact common name; an organisational CRL has not been provisioned.

**2026-11-10 (security finding SOS-4):** the AH-GT-1 peer chain is now checked for revocation in full, as in the Java
and Go GateTunnels. OpenSSL path validation uses `CRL_CHECK_ALL`: the relay certificate needs a current CRL of its cloud
CA, and the cross-certificate a current CRL of the organisation CA. `federation.crlFiles` must therefore include the
organisation CA's CRL (PEM or DER) as well as the peer and own cloud CA CRLs; otherwise the own relay identity and
every peer are refused. Because OpenSSL uses only one CRL per issuer, a second check refuses a certificate that any
current, validly signed CRL of its issuer lists. Tests: `federation::crypto::revocation_tests`, with the fixture PKI
shared with Java and Go (`tests/fixtures/ahgt1-revocation`). The relay server's TLS certificate is still checked
without the organisational CRL (as SOS-6 for Java). The existing shared broker image/root execution and organisational CA lifecycle are separate infrastructure risks, not cleared by the native application tests.

## Compatibility changes in reference peers

Only Java/Go Gatekeeper and GateTunnel are upgraded for explicit `FEDERATION_PEER_ORGANIZATIONS=RustDev=Lab` bindings, preserving Company peer behaviour. The Java changes retain the newer canonical orchestration-based service consumption and registration contracts discovered during the rollout. The Go rebuild replaces only its two federation binaries. Both keep `ah-gt-1`; no legacy downgrade is enabled.

Neighbour records and narrow foreign historian permissions are additive. Operation-scoped changes retain previously inherited access; a console regression detected during testing was corrected. Existing identities and passwords are not changed. Short-lived interoperability identities are removed and their certificates revoked after testing. Their synthetic historian records remain as test evidence.

The Java core services were also restarted by external/concurrent work during this session. That activity is not attributed to this candidate deployment and caused an explicitly retained transient test failure. Reference results must be read with their timestamps, not presented as an unchanged Java baseline.

## Evidence and rollback

`functional-evidence-20261019/` retains final tests, source manifests and also failed development/rollout trials. Host Python scripts are test/deployment helpers only; no Python service implements a candidate microsystem. The existing dated monitoring evidence remains historical.

`blocker-backup-20261019/` contains original candidate sources, configuration, policies and scoped Java/Go/relay backups. Stop only the candidate before reverting its image/source/configuration. Preserve its later state first; do not erase the new native application's records. Revert peer bindings, images and neighbours deliberately against their saved originals, merging any later unrelated Java/Go edits. Reverting the shared relay briefly interrupts federation; no cloud CA, identity or database should be transplanted between clouds. The original images remain available locally. These local copies are not off-host recovery certification.

## Still outside the proven replacement boundary

Full Java DTO/error/side-effect parity, complete onboarding/provisioning/renewal/offboarding compensation, multi-action/parallel choreography, remaining support integrations, full SenML/data-proxy semantics, trusted SNTP/SNMP/QoS/translation/Plant integrations, automatic certificate renewal/root rollover, complete OS/native dependency clearance, off-host restore/HA and organisational ISO/IEC 27001:2022 acceptance remain open. Functional success of the requested producer/historian path does not close these unrelated gates. Performance/soak qualification is not a requirement for this functional acceptance.

**2026-11-10 (security finding SOS-7):** `federation.foreignTargets` lists the neighbours of another organisation this
cloud's consumers may use, as `Cloud|Organisation` (each a configured peer of that organisation). Default: empty, so
the Gatekeeper's `init_gsd` queries only peers of the own organisation (also for named `targetClouds`; refused ones in
`refusedClouds`) and `init_icn` refuses another organisation's cloud with 403. Test: `foreign_targets_are_explicit`.
