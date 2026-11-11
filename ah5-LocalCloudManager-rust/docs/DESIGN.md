# System design

> Historical relocation design. The active executable now uses native mTLS/HTTPS and certificate-bound provider clients, not the legacy router described below. Current design, SD/IDD contracts, deployed endpoints and limits: [SECURE-DEPLOYMENT.md](SECURE-DEPLOYMENT.md).

## Components and boundaries

The standalone executable runs Tokio and Axum, with request-ID, trace and panic-catching layers. The shared Config/App/Store model remains local to this package. The manager UI is already embedded with include_str; it needs no old checkout or Node server at runtime. Shared API, registration and state modules are retained so the package can build independently. The dedicated launcher rejects other ARROWHEAD_ROLE values.

The browser uses `/api/` console handlers. Host/Origin names and configured password are checked before session access. Session management is the exception to the authenticated-cookie requirement. Mutations additionally check `X-Arrowhead-Action: confirm`. Static assets and `/health` are not console-authenticated. Legacy Arrowhead routes are separate and accept declared SYSTEM identities through the inherited requester/manager path.

Provider adapters use a default reqwest Client and the manager's declared SYSTEM name. There is no configured client certificate, identity-token login, expected-CN pinning or explicit per-request timeout. Transport is HTTP unless an HTTPS provider URL is supplied, and HTTPS does not provision mTLS. The listener itself is plain HTTP. This is not equivalent to the parent Rust support runtime's secure transport.

## Collection and mutations

Overview queries registry systems/services and Docker containers concurrently, groups runtime state against known system names, and keeps the last60overview samples in memory. Several output collections/flags are placeholders; registration and naming booleans are not authoritative.

DataManager is queried through the inherited data-historian system/service/data paths and flattened for the dashboard. Rules use simple-store query/create/remove; creation validates consumer, service instance and positive priority against an inferred interoperability catalogue before forwarding a candidates array. Provider DTOs must be qualified against the versions actually deployed.

Plant creation/update/removal forwards to the inherited plant-description-engine path. PATCH currently forwards PUT, and create currently returns200. SysMonitor read errors are hidden behind empty arrays; subscription mutation acknowledges without forwarding. Intercloud is a static unavailable summary, not an active federation monitor.

Docker control uses a hand-written HTTP-over-Unix-socket client, supporting chunked replies and multiplexed logs. Lists carry a Compose project-label filter. Lifecycle accepts only start/stop/restart and static allowlisted services. Logs can include any project container. The raw socket remains a daemon-privilege boundary; there is no new constrained proxy, response-size limit or timeout.

## Registration, state and recovery

Registration retries every3seconds until one successful pass, then stops. It advertises localCloudManagement and legacy monitor1.0.0 over generic_http with policy NONE. Handler session/plant/subscription mutation routes are not all represented in registration metadata. No sysMonitor AMQP service or publisher is present.

Console sessions and history are process-global in-memory structures; restart loses them. Password verification uses scrypt under a mutex. Sessions expire on access; repeated failures cause a one-minute lockout. Cookie/Origin rules do not isolate localhost ports. Configure sensible session lifetimes because range validation remains incomplete.

The shared JSON Store reads corrupt JSON as default empty state and writes through a temporary sibling/rename. It does not provide the newer parent support runtime's process-lock/fsync guarantees. Network mutations are not atomic with local state. Use an independent private state file; this package must never be pointed at active cloud state as a migration mechanism.

## Variants and deployment

The revised SysML model distinguishes the Java-cloud Node.js adapter, native Go package and this Rust development package. It describes intended variability, not proven interchangeability. Original source remains in the cloud build context as an unchanged compatibility snapshot. This relocation does not rebuild/restart containers or create the historical UI8590/API8580 mappings.

Before deployment, implement secure identities/transport, close no-op and placeholder behavior, qualify provider contracts and runtime privileges, and test rollback. A TLS proxy alone does not fix legacy provider authentication. See COMPATIBILITY.md for the full inherited limitation list and VERIFICATION.md for executed checks.
