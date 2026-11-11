# Compatibility and inherited limits

## Active secure candidate mode

The executable now selects the new secure runtime. The inherited runtime limitations numbered below describe archived code paths that are **not mounted by the active launcher**. Current transport is native mTLS for system calls and HTTPS/password authentication for the browser console. Provider authority identities are pinned before credentials are sent. Subscription writes and plant/rule forwarding are real, bounded provider calls; origin validation includes scheme and port. Sessions/history belong to each manager instance, and hashing runs on bounded blocking workers.

Current remaining limits: not complete Java parity; no manager AMQP sysMonitor publisher; candidate federation/tunnel/provisioning/broker workers remain absent; management whitelists are broad grants; inventory/historian queries are bounded; sessions/history are in memory; no distributed transaction or automatic certificate rotation; cookies cannot be intrinsically isolated by TCP port; no production/load/advisory qualification. Docker gateway still holds powerful daemon-socket access, though the manager receives only a token-protected allowlisted candidate API. CRLs are optional/startup-loaded and not enabled in this candidate. Browser trust must be handled deliberately.

Current details and measured verification are in `docs/SECURE-DEPLOYMENT.md`. Earlier generated LaTeX/PDF documents remain relocation snapshots, not a verified specification of this new mode.

## Historical runtime limitations

This relocated module is not the parent Rust support runtime's native mTLS implementation. Packaging does not establish full Java equivalence or new security hardening.

1. The listener is plain HTTP. The dedicated launcher now defaults to loopback, but explicit LISTEN_ADDRESS may expose it. No native inbound TLS/mTLS certificate verification exists in this source.
2. Provider calls use reqwest defaults and legacy `Bearer SYSTEM//LocalCloudManager`, not authenticated identity-token login or a configured client certificate. No expected provider-CN pinning, CRL policy or explicit request timeout/response-size limit is added. HTTPS URLs alone do not solve this. Legacy management routes trust declared SYSTEM names.
3. `/api/sysmonitor/subscriptions/{provider}` PUT and DELETE only acknowledge updated=true after confirmation; neither forwards changes. Both methods return the same acknowledgement. This is not applied subscription configuration.
4. Intercloud is a static unavailable/no-relay view. Consumers have empty authorized/orchestrated collections and TestCloud labels. Overview includes synthetic registration/naming state and placeholder collections; subscription intake.connected=true is not broker readiness.
5. SysMonitor read failures are converted into empty data. Plant reads partly report provider failure, but all provider adapter paths/shapes still need current Java/Go/Rust interoperability testing. Plant PATCH is routed through a PUT forwarding handler. Plant POST currently returns200rather than201.
6. Console cookie `ah_console` is HttpOnly/SameSite=Strict but lacks Secure and localhost-port isolation. Host/Origin checks compare names without exact origin-port matching. Sessions/history are process-global in-memory state. Scrypt executes under a mutex on an async handler; abuse/capacity hardening is outstanding.
7. Invalid/missing password disables console APIs with503, but static UI/health and legacy interfaces remain accessible under their own weaker rules. A console session is not required for legacy declared-identity endpoints. Confirmation header is not cryptographic replay protection.
8. Docker uses a raw Unix socket with project-filtered list and static lifecycle allowlist. Logs may read any project container, not just lifecycle-allowed services. MANAGED_SERVICES is not consumed. Application checks do not constrain the daemon privilege conferred by the raw socket. Docker read/response parsing has no explicit timeout or size bound.
9. No native sysMonitor AMQP publisher or service registration exists here. Historical monitor1.0.0 is echo only, not the canonical telemetry contract. No claim of AMQPS publication, broker confirms or real broker qualification is made.
10. Registry metadata covers a subset of handler routes and advertises generic_http/policy NONE. Registration retries every3seconds until first success, then stops; no ongoing refresh is implemented. Displayed registered=true is synthetic.
11. Shared JSON state lacks a new process lock/fsync/encryption policy; corrupt JSON currently defaults to empty state. Do not open real deployment state with this package or use shared files between processes. No Java state migration is implemented.
12. The shared runtime retains additional roles for source dependencies and inherited tests. Only LocalCloudManager is selected by the dedicated executable. Original deployment source is retained unchanged so other roles/build contexts are not broken.
13. The revised SysML model describes intended variability, not proven substitution. Historical legacy docs claiming interchangeability are kept as provenance only. No SysML parser, full browser deployment suite, Java golden fixtures, vulnerability scan or production qualification is included.

Moving source and creating documentation does not resolve these limits. Close them and qualify security, provider DTOs, rollback and runtime isolation before selecting this package for a working cloud.
