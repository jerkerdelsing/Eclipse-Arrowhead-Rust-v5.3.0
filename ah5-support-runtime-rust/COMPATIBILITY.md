2026-10-19 functional candidate update: native federation, encrypted Java/Go interoperability, RandomDataProducer and monitoring are deployed and tested. The agreed workload is RandomDataProducer → DataManager, functionality only. Full Java replacement and ISO certification remain unproven. See [current status](docs/REPLACEMENT-STATUS.md) and [functional federation](docs/FUNCTIONAL-FEDERATION.md). Older dated evidence below is historical.

# Compatibility and release gates

Target: the **local modified** Arrowhead support Java tree, nominal version 5.2.2. No upstream release-tag provenance is asserted. This is a native Rust **development port, not a complete interchangeable Java replacement**. The separate native candidate is deployed; no identity/database takeover is performed. The active scope is 15 profiles; `_superseeded`, generated output and shared JavaSupportRuntime are not additional systems. AIGym is a local extension.

| Profile | Native behavior delivered | Outstanding behavior / release gates |
|---|---|---|
| Blacklist | Create/revoke, expiry/check/lookup, filtered queries | Full normalization and historical query parity |
| Configuration | Durable base64/raw storage, owner-constrained proxy APIs | External fallback/discovery, complete MIME validation |
| DataManager | Bounded SenML historian, pinned HTTPS provider proxy | Full SenML normalization/base-value/sum semantics, signalCount, MQTT, provider configuration |
| TimeManager | Host UTC clock response | **SNTP and Java trust/cache evaluation absent; trusted=false** |
| AIGym | Persisted samples, kNN regression, observation history | Broker publishing; local extension only |
| EventHandler | Owned subscriptions, metadata filtering, HTTPS outbox | MQTT, full retry strategy; callback origins need explicit upstream allowlist; at-least-once delivery |
| DeviceQoSEvaluator | Windowed weighted-mean filter/sort, measurement adapter | Java SNMP/OID pipeline and normalization |
| PlantDescriptionEngine | Topology CRUD/include composition, named/metadata matching, periodic registration/mismatch alarms, atomic DSO snapshot synchronization, alarm acknowledgment | Monitoring-staleness alarms, full Java DTO normalization/state import and production qualification |
| Choreographer | Plan/executor CRUD, single local action/step starts, aborts and completion callbacks | Dependencies, parallel/multi-action execution, quantities, optimal selection, auto discovery, notifications, async orchestration, exact executor DTO parity |
| CertificateAuthority | Native CSR verification/signing, profiles, revocation, PEM CRLs, trusted keys | Explicit SANs only (no CSR extension copying); automatic key renewal/root rollover, OCSP/HSM/HA, full validity/DTO normalization |
| SysMonitor | Native mTLS AMQP intake, authorised binding reconciliation, revision subscriptions, SQLite history/outbox, confirmed MQTT output and retention | Full Java DTO/filter parity and wider operational qualification |
| Onboarding | Enrollment approval administration and unique fingerprint/system assignment | **Bootstrap/on/de TLS profiles and distributed provisioning/renewal/offboarding absent**; calls return501 |
| TranslationManager | Durable bridge lifecycle through pinned HTTPS InterfaceTranslator adapter | Java translator chaining/native conversion/discovery; absent adapter returns503; uncertain effects require reconciliation |
| Gatekeeper | Neighbour/relay administration, actual MQTT global discovery and negotiation with explicit cloud/organisation bindings | Exhaustive DTO/filter/failure parity and independent review |
| GateTunnel | Signed AH-GT-1 exchange, dynamic mTLS listeners, encrypted forwarding, bounded sessions, replay and scoped operation guards | Exhaustive DTO/chaos tests, independent review; segment-exact grants are stricter than reference descendant grants |

Route presence is not semantic coverage. The earlier `documentation/contracts.json` is a historical generated catalogue; current runtime routes, registration and deployment evidence describe the latest candidate. It is not a regenerated final-image contract catalogue. Unported operations are excluded from service registration. Even implemented operations can have the restrictions above. Changed configured TLS/CRL material is reloaded for new connections, with fail-closed validation and no TLS resumption in the candidate. Without CRLs certificate revocation is not enforced by the TLS listener.

Most profiles use separate locked atomic JSON state rather than Java SQL; SysMonitor uses native SQLite for history/outbox. No automatic data migration, clustering, backup policy, resource-scale qualification, production certification or Java golden differential suite is delivered. A rename followed by directory-sync failure is an uncertain durable commit, not a rollback. Remote effects are not distributed transactions. Interrupted translation/start state must be reconciled manually. The broad management whitelist is an explicit trust grant, not a fine-grained policy.

## Contract details

- Blacklist create uses `entities[{systemName,expiresAt,reason}]`; queries `pagination,systemNames,mode,issuers,revokers,reason,alivesAt`; check is a boolean; query is `count/entries`; remove uses `names` query values.
- Configuration store uses `systemName,fileName,contentType,data` (base64); response adds `id,size,createdAt,updatedAt`; list is `count/data`; raw response uses stored MIME type. Owner checks apply to non-management APIs.
- Historian PUT is a SenML array; accepted records require one `v/vs/vb/vd/s` value. GET supports numeric epoch `from,to,count,signals`. Filtered output reinserts `bn/bt` context. Unsupported base-value/sum semantics and `signalCount` return501. Proxy uses registry operation metadata and explicit pinned provider origins.
- Time returns `epoch,epochMs,tz,dst,trusted,offsetMs,timeSource,lastCheckTime`; source is explicitly `system-clock-unverified`.
- AIGym samples use `model,features,target`; predictions `model,features,neighbours`. Missing coordinates are zero; default model is `default`, k defaults3 and clamps to available samples.
- Event subscription: `eventType,notifyUri,matchMetadata,metadataFilter,startsAt,expiresAt`; publish: `eventType,payload` (**string**), `metadata,timestamp`; notification includes `sourceSystemName`; accept response `matchedSubscriptions,acceptedDeliveries`. Three attempts; an in-flight callback may race unsubscribe. Callbacks can return an empty body; nonempty replies currently need valid JSON.
- QoS request: `providers,configuration{metricNames,metricWeights,timeWindow,threshold}`; lower weighted scores rank first, missing metrics rank last/drop. Measurement adapter returns `systemName,metricGroup,timestamp,current`.
- Plant documents: `plantDescription,active,include` numeric IDs, `systems[{systemId,systemName,ports}]`, `connections[{consumer:{systemId,portName},producer:{...}}]`. Only one active; cycles/dangling ports rejected. Alarm PATCH uses `acknowledged` boolean.
- Choreography plans use `name,firstActionName,actions`; actions `name,nextActionName,firstStepNames,steps`; steps `name,quantity,serviceRequirement,staticParameters,nextStepNames`. Only one action/step profile executes. Executor uses `systemName,address,port,basePath,serviceDefinitionName`; callbacks require matching `sessionId,sessionStepId,status` from recorded executor. Starts use `planName` or numeric `planId`.
- CA sign: `encodedCSR`/`csr` PEM or base64DER, `profile` on/de/sy/op, explicit `addresses`, optional RFC3339 `validAfter,validBefore`; chain base64DER, decimal serial, numeric id and long profile names returned. CA-private-key permissions owner-only. CSR signature checked; CN local PascalCase; reserved names Sysop-only. Provisioning rights match named Java principals. CRL PEM endpoint uses `application/pkix-crl`.
- SysMonitor subscription writes accept Java-style creation without If-Match; supplied stale revisions return409; responses include ETag. Diagnostic management-only intake uses `routingKey,observation`. Routing `cloud.sysmonitor.provider.instance.type`; schema major1/value/UTC-Z sourceTime required; payload identities must match. The durable MQTT outbox removes records only after tracked completion; all 22 native providers advertise genuine AMQP monitoring services. See current runtime contracts and deployment evidence.
- Onboarding approval uses SHA256 DER `bootstrapFingerprint` (hex/optional colons), unique approved `systems`; reserved names denied. Only approval administration currently supported.
- Translation discovery adapter returns `candidates`; negotiation requires matching `bridgeId,bridgeInterface`; native records progress through DISCOVERED/NEGOTIATING/ACTIVE/ABORTING/ABORTED/ERROR. Uncertain side effects do not silently reset state.
- Federation/tunnel services are now registered and exercised with Java/Go peers. Native Rust performs actual encrypted forwarding; no backend Go/Java process or dummy successful tunnel implements a candidate service.

## PDE/DSO extension — 23 October 2026

The native PDE synchronizes the active plant at most 30 seconds after registry changes and normally within two seconds of plant changes. DSO applies scoped provider restrictions and nonnegative priorities while retaining authorization, interface and lock checks. Managed scopes never use inter-cloud fallback. The private JSON snapshot is atomic and survives restart. PDE can query registry systems/service instances and manage the new DSO snapshot only; it gains no general registry or DSO administration right. See [the deployment and API guide](docs/PDE-DSO.md).

## 2026-10-24: DataManager data models

The DataManager registers `dataHistorian` with the interface property `dataModels` (get-data output `senml`, put-data
input `senml`; `contracts::data_models`), as the Go DataManager does. Without this declaration the TranslationManager
cannot build data-model bridges (for example senml to simpleJson) to it, following the Java rule that the data models
of both sides must be declared.
