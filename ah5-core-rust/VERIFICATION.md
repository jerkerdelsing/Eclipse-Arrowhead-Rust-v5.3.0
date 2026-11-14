## Current evidence — 2026-10-19

The native candidate now has Linux-container, real broker, encrypted federation, producer/historian and manager evidence. See [current status](docs/REPLACEMENT-STATUS.md) and its final verification summary for exact results/revisions. The dated original source-only report below is retained as history, not the current deployment or current missing-feature list. Full replacement/production certification remains unproven.

# Verification record — 2026-10-16

## Result and boundary

Five independently runnable native Rust core-system profiles and their Arrowhead LaTeX documentation are delivered. **Full Java feature parity remains incomplete.** This is a tested development HTTPS implementation, not certification or permission to replace the current clouds. Remaining implementation work and release gates are listed in `COMPATIBILITY.md` and the system documents.

Reference roots:

- `Arrowhead/ah5-core-java-spring/`
- `Arrowhead/ah5-common-java-spring/`

`documentation/contracts.json` records SHA-256 hashes of 873 local Java files, the extracted reference mappings, Rust mappings and service descriptors. The local reference includes workspace changes; a pristine upstream v5.2.2 tag was not asserted or independently verified.

## Executed checks

| Check | Result |
|---|---|
| Host | macOS ARM64; rustc 1.99.0, cargo 1.99.0 |
| Release build | All five named system binaries built successfully; unified launcher and documentation tool also compile |
| Delivered-copy verification | Formatting, strict static checks, all 28 tests, the route audit and five binary CLI checks repeated successfully from the requested `ah5-core rust` directory; the delivered PDF matches the visually checked copy |
| Formatting | `cargo fmt --check` passed after corrections |
| Static checks | `cargo clippy --locked --all-targets -- -D warnings` passed |
| Rust suite | 28 passing integration-test cases: 22 runtime/business/security cases, 3 local network cases, 3 executable/revocation cases; none ignored |
| Reference-route audit | All 91 extracted Java HTTP mappings present, zero missing/unresolved mappings |
| Service inventory | 26 produced HTTPS service definitions across the five profiles, including common management/echo where present in the scoped Java controllers |
| Configuration examples | All five generated JSON examples parse and validate against the strict Rust configuration schema; registration remains disabled |
| LaTeX | 42 SysD/SysDD/SD/IDD/catalogue sources compiled with local TeX Live 2023; overflow defects found during review were repaired |
| PDF | Combined catalogue compiled to stable references, rendered with Poppler and visually checked using the PDF skill workflow |

These counts are not line/branch coverage or proof of full functionality. No statement-coverage percentage is claimed: `cargo llvm-cov` is not installed. No current advisory-free claim is made: `cargo audit` is not installed. The exact dependency versions used are fixed in `Cargo.lock`.

## Concrete behaviors tested

- All five roles construct unique guarded routes and service-operation paths that resolve to the runtime inventory. All five named executables accept their CLI options and reject a mismatched configured role.
- Authentication credential/certificate binding, bcrypt passwords, single active session, credential-change revocation, raw-password/raw-session-token exclusion from snapshots, management denial for ordinary identities, and rejection of declared SYSTEM/forwarded identity headers.
- Strict configuration, malformed nested request batches, private-key permissions and DER identity parsing. Bad input returns errors rather than being interpreted as authorization success.
- Management-over-provider policy precedence, scoped rules, scopeless policy intersection, revocation fallback, and metadata policy lookup through the real pinned Registry dependency.
- Registry registration/lookup/cascade, ownership denial, metadata filtering, invalid interface ports/null requirements and atomic rollback of an invalid management batch.
- Atomic usage-limited-token consumption under concurrent tasks, raw-token exclusion from persisted state, real RS256/RS512 JWT signatures/claims, AES ECB/CBC bytes compared independently with OpenSSL, and authenticated wrapping/tamper rejection for persisted provider keys.
- Simple-store creation/selection, positive unique priorities, atomic rejection of duplicate-priority updates, subscription ownership, HTTPS-only callback validation and management subscription batches.
- Explicit 501 failure for unimplemented dynamic integrations rather than fabricated successful orchestration.
- Process state locking, rejection of corrupt state without resetting it, failure rollback, durable reopen, concurrent updates and snapshot isolation.

### Real local mutual-TLS interoperability

Five Rust systems run together on independent ephemeral local HTTPS listeners with generated test identities: ServiceRegistry, Authentication, ConsumerAuthorization, DynamicServiceOrchestration and SimpleStoreServiceOrchestration. The test logs in Sysop/provider/consumer identities and exercises:

1. Provider system/service registration.
2. Consumer discovery denied by default, then allowed after an actual management policy grant.
3. Dynamic orchestration through real Registry and Authorizer calls, operation filtering and an exclusive lock.
4. Simple-store management and consumer pull.
5. Management rejection and token/certificate mismatch rejection.
6. SYS_METADATA policy evaluation through the actual Registry connection.

A separate test delivers a persisted push job to a TLS-pinned subscriber and checks the received result and terminal DONE status. Missing client certificates and same-CA wrong-authority certificates are rejected.

### Native process and revocation

The Authentication **executable** is launched as an isolated child process using an empty temporary state file and explicitly seeded test Sysop. The test logs in over real mTLS, queries identities, sends SIGTERM, waits for successful termination, reopens its durable state, and confirms passwords/raw tokens are absent. No user process is signaled; only the test-owned child is stopped.

A separate issuer-signed CRL test revokes an isolated Consumer certificate. A server configured with that CRL rejects the revoked client while an unrevoked Sysop client can still call echo. This is evidence of the configured leaf-CRL path, not ecosystem-wide revocation/rotation qualification.

## Reproduction and observed corrections

Run `make build check test contracts` from this repository. Tests require OpenSSL for generated test PKI and independent AES comparison, plus permission to bind temporary local listeners. Runtime services use native Rust cryptography and do not execute OpenSSL.

During development, the source extractor initially mixed identically named unqualified Java constants. It was corrected to resolve class-qualified constants and now audits all five modules with zero unresolved mappings. A malformed-input regression initially stopped at a mock authentication failure because the mock did not decode escaped token paths; the fixture was corrected, and the test now reaches and confirms the intended 400 responses. Formatting/static-check corrections were applied and rechecked. Documentation review found long service-name paragraph overflows and a template-generated contents-depth override; the generator was corrected and the resulting sources recompiled.

A repeated native-process test exposed idle TLS connections waiting for the server's drain timeout. The runtime now propagates shutdown to each connection, cancels pending handshakes, invokes Hyper graceful shutdown, closes the listener, and aborts an overlong background worker explicitly. The process test allows margin beyond the documented internal connection-drain bound and verifies successful termination and durable-state reopen.

## Not established

- Completion of unported features identified in `COMPATIBILITY.md`—especially inter-cloud, QoS, translation and full blacklist/event-driven orchestration.
- Golden success/invalid/error/policy fixtures replayed against a running Java reference. Rust-to-Rust mTLS interoperability is not Java/Rust equivalence evidence.
- Existing-cloud/broker/federation tests, MQTT APIs, external deployment or LocalCloudManager UI compatibility.
- Java or earlier Rust database import, production backup/restore, multi-instance coordination, full crash/partial-network-side-effect recovery, key/secret rotation or rollback trials.
- Linux execution or cross-builds; only `aarch64-apple-darwin` is installed on the checked Rust toolchain.
- Load/soak/fuzz tests, complete rate/DoS protection, formal verification, quantified coverage or a current dependency vulnerability scan.

No deployed Java/Go/Rust cloud, Docker service, real CA key, identity database, trust store or working federation configuration was changed by this delivery.
