# localCloudManagement HTTP interface

> Superseded relocation snapshot. The deployed manager uses a separate HTTPS console and mTLS system API with certificate-bound identity tokens. See [SECURE-DEPLOYMENT.md](SECURE-DEPLOYMENT.md) for the active HTTPS IDD and exact provider mappings.

The actual listener is plain HTTP; the dedicated launcher defaults to `http://127.0.0.1:8480/`. The inherited registry descriptor uses generic_http/policy NONE. Do not label this as a native HTTPS/mTLS interface. An external proxy and its certificates are outside this source relocation, and cannot repair legacy provider authentication by themselves.

## Actual handler inventory

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/health` | Text OK; not dependency readiness |
| GET | `/` and `/ui` | Embedded dashboard; no console session |
| GET | `/app.js`, `/assets/app.js` | Embedded JavaScript |
| GET | `/styles.css`, `/assets/styles.css` | Embedded CSS |
| GET | `/api/session` | authenticated/configured state |
| POST | `/api/session` | Password login, success204with cookie |
| DELETE | `/api/session` | Logout,200with expired cookie |
| GET | `/api/overview` | Registry/runtime aggregation |
| GET | `/api/service-registry-management` | Devices/systems/services/runtime grouping |
| GET | `/api/datamanager` | Historian adapter; limit1..1000, default240 |
| GET | `/api/consumers` | Inherited partial consumer view |
| GET | `/api/intercloud` | Static unavailable placeholder |
| GET | `/api/sysmonitor` | Inherited observation adapter, optional system query |
| GET | `/api/sysmonitor/subscriptions` | Read adapter, synthetic intake flags |
| PUT, DELETE | `/api/sysmonitor/subscriptions/{provider}` | Confirmed acknowledgement ONLY; no write |
| GET | `/api/plantdescriptions` | Plant/registry catalogue |
| POST | `/api/plantdescriptions` | Confirmed provider create; currently200 |
| PUT, PATCH | `/api/plantdescriptions/{id}` | Confirmed provider update; both forward PUT |
| DELETE | `/api/plantdescriptions/{id}` | Confirmed provider removal |
| GET | `/api/orchestration/rules` | Simple-store catalogue/rules |
| POST | `/api/orchestration/rules` | Confirmed validation then provider create |
| DELETE | `/api/orchestration/rules/{id}` | Confirmed provider removal |
| GET | `/api/logs` | Project-container logs, service/tail query |
| POST | `/api/containers/{service}/{action}` | Confirmed allowlisted project lifecycle |
| GET | `/localcloud/management/status` | Separate legacy requester status |
| GET | `/localcloud/management/systems` | Separate legacy management registry query |
| GET | `/localcloud/management/services` | Separate legacy management service query |
| GET | `/localcloud/monitor/echo` | Separate legacy echo |

## Session and access

All `/api/` requests require allowed Host/Origin host names and a configured password hash. Non-session routes also require a valid console cookie. Host-name matching ignores exact ports. Missing/invalid hash503, rejected Host/Origin403, absent/expired session401. Static UI/health and legacy routes are not covered by this console middleware.

POST session accepts JSON with password string. The configured hash is scrypt with N16384,r8,p1. A correct password returns204and sets `ah_console`, HttpOnly, SameSite=Strict, Path=/, Max-Age default28800. There is no Secure flag or port isolation. GET session returns authenticated/configured. DELETE removes the token and expires the cookie. Five wrong passwords in five minutes trigger one-minute lockout;429includes Retry-After60. Wrong password401.

Mutations require exactly `X-Arrowhead-Action: confirm`. Missing confirmation428with JSON error. Axum body/content-type extraction can reject malformed JSON before the handler checks confirmation. This header is not cryptographic replay protection.

## Mutation DTOs

Rule creation requires consumer, serviceInstanceId and positive unsigned priority. Unknown/incompatible producer choice409; invalid required values400. The provider body wraps the candidate in a candidates array. Remove uses ids query at the inherited simple-store endpoint. Provider success is returned as JSON, generally200; provider/network failures502with error. No distributed transaction or atomic rollback is guaranteed.

Plant create/update JSON is forwarded to the inherited provider path. PATCH also forwards PUT. Create currently returns200. Delete forwards DELETE. Subscription PUT and DELETE ignore the body and return providerSystem/updated=true without applying any provider change; a200response is not configuration confirmation.

Lifecycle action must be start, stop or restart. A static source allowlist and Compose project filter constrain selection. Unknown action400, unlisted target403, unknown returned project service404, Docker failure502. Success JSON contains service/action/accepted=true/at and currently returns200, not202. The raw Docker socket privilege is not reduced by these application checks.

## Read DTOs and errors

Overview includes collectedAt, cloud, summary, devices, systems, services, registryManagement, naming, infrastructure, orchestrations, containers, history, registration and errors. Some flags and collections are placeholders. Registry grouping uses devices, runtimeOnly and summary; no assurance of authoritative readiness follows from these fields.

Historian returns collectedAt/count/latest/entries/series; source data comes from inherited per-system/per-service SenML paths. Consumers uses TestCloud labels and empty authorized/orchestrated lists. Intercloud is static unavailable. SysMonitor reads group observations with sourceTime/value/quality, but upstream errors are hidden as empty data; subscription intake status is synthetic.

Logs accept service and tail (clamped1..500, default150). Response includes service/lines/collectedAt. Logs may include any container returned for the project, even if it is not lifecycle-allowed. Runtime rows include id/name/service/displayName/image/state/status/health/created/managed.

Console handler errors generally use a JSON error string. Legacy shared-runtime errors use errorMessage/errorCode/exceptionType/origin. Unknown routes404; unsupported methods405 through Axum. Exact Java DTO/error parity and a full browser deployment test are not established.
