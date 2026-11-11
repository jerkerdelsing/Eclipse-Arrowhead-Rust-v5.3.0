# Legacy monitor service

Definition `monitor`, version1.0.0, producer LocalCloudManager, base `/localcloud/monitor`, operation echo. This historical registration name is retained by source relocation; it is not the canonical sysMonitor telemetry contract or a recommendation for new services.

## Semantics

A valid legacy requester receives text `Got it!`. This proves only that the echo handler responded, not provider readiness, registration, federation or broker connectivity. The inherited requester accepts a declared `Bearer SYSTEM//name` without cryptographic proof.

No native sysMonitor AMQP publisher exists in this package. The dashboard can read SysMonitor data from a provider, but consuming monitoring data does not make this manager a telemetry publisher.
