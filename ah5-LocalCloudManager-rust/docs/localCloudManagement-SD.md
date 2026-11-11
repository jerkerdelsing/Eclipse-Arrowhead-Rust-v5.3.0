# localCloudManagement service

> Historical relocation service description. The active candidate service and verified behavior are specified in [SECURE-DEPLOYMENT.md](SECURE-DEPLOYMENT.md); the old declared-identity router is not mounted.

Definition `localCloudManagement`, version1.0.0, producer LocalCloudManager, base `/api`. The actual source registers `generic_http`, protocol http, policy NONE. The console's password/session boundary is applied by the handlers, not expressed as certificate authentication by that descriptor.

## Purpose and operations

The service exposes session login/state/logout, registry/runtime overview and grouping, historian data, consumers, intercloud summary, SysMonitor views and subscriptions, plant descriptions, orchestration rules, container logs and lifecycle. Read and mutation HTTP bindings are defined in the HTTP IDD. The registration descriptor contains only a subset of these routes; it must not be treated as the complete handler inventory.

The operator authenticates with a scrypt-protected password and receives a random HttpOnly/SameSite=Strict cookie. Mutations require the explicit confirmation header. Missing password disables console APIs. A bearer identity token is not a substitute for an operator session.

## Delimitations

Subscription mutation is acknowledgement-only, intercloud is a placeholder, and several displayed flags are synthetic. Provider calls use legacy declared SYSTEM identities and no native mTLS. This service is not certified interchangeable with the Java-cloud or newer Go/Rust support implementations. The relocation retains these semantics and documents them instead of claiming a security or parity upgrade.
