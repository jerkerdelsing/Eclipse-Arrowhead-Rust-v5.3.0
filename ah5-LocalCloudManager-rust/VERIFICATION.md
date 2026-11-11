# Rust LocalCloudManager relocation verification - 2026-10-17

## Secure candidate deployment — supersedes the relocation runtime below

The new native manager has been installed in ah5-support-rust/LocalCloudManager and deployed in Arrowhead-test-cloud-rust/candidate-native. Final Linux/ARM64 image: `sha256:6fe7383cf4d498304b90783002f2cf733ac12fc6cad0043f931ba7b8bc3a68ba`.

| Current check | Result |
|---|---|
| Installed manager tests |29passed,0failed (18historical tests;11new helper/secure-console tests) |
| Parent support regression tests |40existing tests plus1new conditional-header test passed |
| Strict manager and parent lint |Passed with warnings denied |
| Final live manager integration checks |60passed,0failed |
| Final browser checks |11completed; no page errors or unexpected failed API responses |
| Current candidate deployment/source/isolation assertions |348passed,0failed; includes source-file hashes, not348business-function tests |

Live checks verified real subscription writes/removals and stale-revision409, plant POST201/PATCH/DELETE, simple-store create/remove, native dynamic history access, historian/diagnostic reads, managed TimeManager restart and forbidden actions, exact-origin/session controls, system mTLS certificate/token binding and unchanged original Rust-cloud start times. Browser QA verified login, eight dashboard views, logout and stored SysMonitor selection/observation display; final screenshots were visually inspected. Browser QA used a fresh process with a candidate-certificate-only SPKI exception, never global certificate-verification disablement or persistent trust changes.

Evidence files: candidate-native/manager-test-results.json, manager-deployment-snapshot.json and manager-ui-qa/browser-results.json. At13:55UTC, the60live tests also confirmed the older Rust project's start times were unchanged. A later read-only audit observed that this separate project had subsequently been recreated and remapped to104xxports, including its UI at10490. That change was not performed by this candidate deployment. The current audit reports that changed external baseline as a warning instead of treating removed historical IDs as current containers; all23candidate containers remain healthy. Current design/limits are in docs/SECURE-DEPLOYMENT.md. Earlier source/relocation evidence below is historical.

## Source and boundaries

Canonical source is now `ah5-support-rust/LocalCloudManager`. The latest located source in Arrowhead-test-cloud-rust/core-systems matched the workspace manager (SHA256c3150daa4dd91e854439e31626895c5ff86e77881c338c5281306bda49f44d6b). Original deployment source remains unchanged because other roles share its package/build context. No running cloud, Compose file, credential, CA key or cloud state is moved/restarted/deployed.

The nested Cargo package retains the existing runtime, business handlers, UI and inherited tests. Packaging changes are the crate/workspace boundary, library exports, role-default configuration helper, dedicated role guard and loopback-default launcher. A private explicit-socket helper was extracted solely so the existing Unix Docker client can be tested without setting global environment or accessing the real daemon. Additional tests/docs/provenance were added; formatting is mechanical. The manifest records13original source/module/UI/legacy-document hashes and14relocated source/module/UI hashes.

## Executed checks

Environment: macOS ARM64, rustc1.99.0/cargo1.99.0. Existing locked cached dependencies were used offline; no Docker/cloud/provider access is needed to build or test.

| Check | Result |
|---|---|
| cargo build --locked --offline --bin LocalCloudManager | Passed |
| cargo fmt -- --check | Passed |
| cargo clippy --locked --offline --all-targets -- -D warnings | Passed |
| cargo test --locked --offline | **18 tests passed**, zero failed |
| Dedicated launcher | Help works without provisioning; non-manager role rejected in a separate process |
| Embedded UI | Index/JS/CSS and asset aliases served by compiled resources |
| Console | Login/session/logout, missing password, Host/Origin rejection, confirmation and lockout checked |
| Runtime control | Unsafe targets/actions rejected before socket effects; Unix HTTP client tested against a temporary mock socket only |
| Legacy restrictions | Tests explicitly preserve and expose declared-identity behavior, no-op subscription acknowledgements and placeholder intercloud |
| Arrowhead LaTeX | SysD, SysDD, two SDs and two HTTP IDDs plus combined catalogue; all7sources compiled |
| Combined PDF | **13 pages**, three-pass compilation; all pages rendered and visually checked; no overfull boxes in latest logs |

Six tests are inherited (three shared API and three manager helpers); twelve new checks cover relocation/console/runtime/launcher behavior. Tests use isolated state directories and a mock Unix socket. No real Docker socket, broker, private cloud CA, cloud secret or provider is contacted. HTTP handler tests are not evidence of TLS, which this source does not implement. The parent fifteen-profile suite was not rerun and is not included in the18test count.

The first mock-socket test encountered macOS's Unix path-length limit; its temporary directory was shortened under /tmp, and the full suite then passed. No runtime Docker path behavior was changed by this test adjustment.

## Repository integration and qualification

The parent Makefile now explicitly includes this independent module in build/test/check and documentation targets, plus localcloudmanager/localcloudmanager-docs shortcuts. Existing parent README/Makefile/NOTICE are backed up before update. Other support code/docs remain unchanged. Source hashes are provenance, not an upstream release signature.

No native TLS/mTLS identity, sysMonitor AMQP publisher, real broker test, full Java differential contract suite, deployment/browser qualification, vulnerability scan, Linux/Windows build or SysML parser validation is claimed. The13inherited limitations in COMPATIBILITY.md remain release blockers. A plain HTTP development source relocation is not a secure Java replacement.

The PDF skill guided compilation/render inspection and fixes to field-list wrapping, paragraph separation and orphaned headings. Original Arrowhead class/logo assets were reused.
