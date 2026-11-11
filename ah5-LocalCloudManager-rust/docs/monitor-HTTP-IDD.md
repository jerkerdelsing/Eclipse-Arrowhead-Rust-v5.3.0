# Legacy monitor HTTP interface

Request `GET /localcloud/monitor/echo`, no body. Response200text `Got it!`. The source's legacy requester accepts `Authorization: Bearer SYSTEM//name` as a declared name; alternative bearer handling is inherited and does not establish certificate-bound authentication. No native TLS client certificate is required by this listener. Invalid or absent legacy requester yields401.

This route is separate from `/api/` console-cookie middleware. Console cookies do not protect or replace the legacy requester check. An echo response is not evidence of registry publication, trusted identities, provider health, AMQP publishing or production suitability.

The source registers monitor1.0.0 at `/localcloud/monitor` with GET/echo, generic_http/policy NONE. No sysMonitor AMQP binding exists in this implementation; do not infer one from the dashboard's SysMonitor view or invent an associated telemetry contract.
