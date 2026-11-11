// SPDX-License-Identifier: EPL-2.0
use crate::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::{BTreeMap, BTreeSet};
pub fn active(row: &Value) -> bool {
    row["active"] == true && (s(row, "expiresAt").is_empty() || !expired(s(row, "expiresAt")))
}
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    method: &str,
    path: &str,
    p: &BTreeMap<String, String>,
    q: &Value,
    req: &Value,
    caller: &Principal,
) -> Result<(u16, Value)> {
    match app.config.role.as_str() {
        "blacklist" => {
            if path.contains("/check/") {
                return Ok((
                    200,
                    active(&row(app, "blacklist", &p["systemName"]).unwrap_or(Value::Null)).into(),
                ));
            }
            if path.ends_with("/lookup") {
                let rows = app
                    .store
                    .rows("blacklist")
                    .into_iter()
                    .filter(active)
                    .collect::<Vec<_>>();
                return Ok((200, json!({"count":rows.len(),"entries":rows})));
            }
            if path.ends_with("/create") {
                let entities = array(req, "entities");
                if entities.is_empty() || entities.len() > 1000 {
                    return Err(Error::bad("entities must contain 1..1000 entries"));
                }
                let rows=app.store.update(|db|{let mut rows=Vec::new();let mut names=BTreeSet::new();for item in entities {let name=s(&item,"systemName");if !valid_name(name)||!names.insert(name.to_string()){return Err(Error::bad("Invalid or duplicate systemName"))}
if !s(&item,"expiresAt").is_empty()&&expired(s(&item,"expiresAt")){return Err(Error::bad("expiresAt must be a future timestamp"))}let row=json!({"systemName":name,"reason":item["reason"],"expiresAt":item["expiresAt"],"createdBy":caller.name,"createdAt":now(),"updatedAt":now(),"revokedBy":null,"active":true});table(db,"blacklist").insert(name.into(),row.clone());rows.push(row)}Ok(rows)})?;
                return Ok((201, json!({"count":rows.len(),"entries":rows})));
            }
            if path.ends_with("/remove") {
                let names = array(q, "names");
                if names.is_empty() {
                    return Err(Error::bad("names required"));
                }
                app.store.update(|db| {
                    for name in names {
                        if let Some(row) =
                            table(db, "blacklist").get_mut(name.as_str().unwrap_or(""))
                        {
                            row["active"] = false.into();
                            row["revokedBy"] = caller.name.clone().into();
                            row["updatedAt"] = now().into();
                        }
                    }
                    Ok(())
                })?;
                return Ok((200, Value::Null));
            }
            let mode = s(req, "mode");
            if !["", "ALL", "ACTIVE", "INACTIVE"].contains(&mode) {
                return Err(Error::bad("Invalid mode"));
            }
            let mut rows = Vec::new();
            for mut row in app.store.rows("blacklist") {
                let enabled = active(&row);
                if mode == "ACTIVE" && !enabled || mode == "INACTIVE" && enabled {
                    continue;
                }
                if !selected(req, "systemNames", s(&row, "systemName"))
                    || !selected(req, "issuers", s(&row, "createdBy"))
                    || !selected(req, "revokers", s(&row, "revokedBy"))
                    || !s(&row, "reason").contains(s(req, "reason"))
                {
                    continue;
                }
                if !s(req, "alivesAt").is_empty() {
                    let at = chrono::DateTime::parse_from_rfc3339(s(req, "alivesAt"))
                        .map_err(|_| Error::bad("Invalid alivesAt"))?;
                    let created =
                        chrono::DateTime::parse_from_rfc3339(s(&row, "createdAt")).unwrap();
                    if at < created
                        || !s(&row, "expiresAt").is_empty()
                            && chrono::DateTime::parse_from_rfc3339(s(&row, "expiresAt"))
                                .is_ok_and(|end| at >= end)
                    {
                        continue;
                    }
                }
                row["active"] = enabled.into();
                rows.push(row)
            }
            Ok((200, page(rows, req, "entries")?))
        }
        "configuration" => {
            let name = p
                .get("systemName")
                .map(String::as_str)
                .unwrap_or_else(|| s(req, "systemName"));
            let management = path.contains("/mgmt/");
            if method == "GET" && name.is_empty() {
                let rows = app.store.rows("configuration");
                return Ok((200, json!({"count":rows.len(),"data":rows})));
            }
            if !management {
                own(caller, name)?
            }
            if method == "GET" {
                return Ok((200, row(app, "configuration", name)?));
            }
            if method == "DELETE" {
                let removed = app.store.update(|db| {
                    table(db, "configuration")
                        .remove(name)
                        .ok_or_else(|| Error::new(404, "Configuration not found"))
                })?;
                return Ok((200, removed));
            }
            if !valid_name(name) || s(req, "systemName") != name {
                return Err(Error::bad("Path/body systemName mismatch or invalid name"));
            }
            required(req, &["fileName", "contentType"])?;
            let file = s(req, "fileName");
            if file.contains(['/', '\\', '\r', '\n']) || file.len() > 255 {
                return Err(Error::bad("Invalid fileName"));
            }
            let mime = s(req, "contentType");
            if !mime.contains('/') || mime.parse::<axum::http::HeaderValue>().is_err() {
                return Err(Error::bad("Invalid MIME type"));
            }
            let bytes = STANDARD
                .decode(s(req, "data"))
                .map_err(|_| Error::bad("data must be base64"))?;
            let value=app.store.update(|db|{let t=table(db,"configuration");let old=t.get(name);let row=json!({"id":old.map(|r|r["id"].clone()).unwrap_or_else(||id().into()),"createdAt":old.map(|r|r["createdAt"].clone()).unwrap_or_else(||now().into()),"updatedAt":now(),"systemName":name,"fileName":file,"contentType":mime,"data":s(req,"data"),"size":bytes.len()});t.insert(name.into(),row.clone());Ok(row)})?;
            Ok((200, value))
        }
        "timemanager" => {
            let trust = time::state().await;
            let t = chrono::Utc::now();
            Ok((
                200,
                json!({"epoch":t.timestamp(),"epochMs":t.timestamp_millis(),"tz":"UTC","dst":false,"trusted":trust.trusted,"offsetMs":trust.offset_ms,"timeSource":trust.server,"lastCheckTime":trust.checked_at}),
            ))
        }
        "aigym" => {
            if path == "/health" {
                return Ok((200, json!({"status":"up","system":"AIGym","time":now()})));
            }
            if path.ends_with("/status") {
                return Ok((
                    200,
                    json!({"system":"AIGym","implementation":"Rust","samples":app.store.rows("samples").len(),"brokerConnected":app.monitor_runtime.lock().map(|v|v["mqttConnected"]==true).unwrap_or(false),"status":if app.monitor_runtime.lock().map(|v|v["mqttConnected"]==true).unwrap_or(false){"running"}else{"degraded"}}),
                ));
            }
            if path.ends_with("/observations") {
                return Ok((200, app.store.rows("ai-observations").into()));
            }
            let model = if s(req, "model").is_empty() {
                "default"
            } else {
                s(req, "model")
            };
            let features = req["features"]
                .as_object()
                .filter(|f| !f.is_empty() && f.len() <= 1000)
                .ok_or_else(|| Error::bad("Nonempty features required"))?;
            if features
                .values()
                .any(|v| v.as_f64().is_none_or(|f| !f.is_finite()))
            {
                return Err(Error::bad("Finite numeric features required"));
            }
            if path.ends_with("/samples") {
                let target = req["target"]
                    .as_f64()
                    .filter(|v| v.is_finite())
                    .ok_or_else(|| Error::bad("Finite target required"))?;
                let sample = json!({"id":id(),"model":model,"features":features,"target":target,"createdAt":now()});
                app.store.update(|db| {
                    table(db, "samples").insert(s(&sample, "id").into(), sample.clone());
                    Ok(())
                })?;
                return Ok((201, sample));
            }
            let mut neighbours = Vec::new();
            for sample in app
                .store
                .rows("samples")
                .into_iter()
                .filter(|r| s(r, "model") == model)
            {
                let other = sample["features"]
                    .as_object()
                    .ok_or_else(|| Error::new(500, "Corrupt sample"))?;
                let keys = features.keys().chain(other.keys()).collect::<BTreeSet<_>>();
                let distance = keys
                    .into_iter()
                    .map(|k| {
                        let d = features.get(k).and_then(Value::as_f64).unwrap_or(0.)
                            - other.get(k).and_then(Value::as_f64).unwrap_or(0.);
                        d * d
                    })
                    .sum::<f64>();
                if !distance.is_finite() {
                    return Err(Error::bad("Feature magnitude exceeds calculation range"));
                }
                neighbours.push((distance, sample));
            }
            if neighbours.is_empty() {
                return Err(Error::bad("Model has no training samples"));
            }
            neighbours.sort_by(|a, b| a.0.total_cmp(&b.0).then(s(&a.1, "id").cmp(s(&b.1, "id"))));
            let k = integer(req, "neighbours", 3).clamp(1, neighbours.len() as u64) as usize;
            let value = neighbours
                .iter()
                .take(k)
                .map(|(_, r)| r["target"].as_f64().unwrap() / k as f64)
                .sum::<f64>();
            if !value.is_finite() {
                return Err(Error::bad("Prediction exceeds range"));
            }
            let prediction = json!({"model":model,"value":value,"neighbours":k,"timestamp":now()});
            app.store.update(|db| {
                let t = table(db, "ai-observations");
                if t.len() >= 1000
                    && let Some(key) = t.keys().next().cloned()
                {
                    t.remove(&key);
                }
                t.insert(format!("{}-{}", now(), id()), prediction.clone());
                Ok(())
            })?;
            Ok((200, prediction))
        }
        _ => Err(Error::new(404, "Unknown operation")),
    }
}

// TimeManager clock trust (port of the Java SntpClient/TimeTrustService). Config comes from the
// environment because the role config is shared: AH_NTP_SERVER_LIST (default pool.ntp.org),
// AH_TIME_OFFSET_THRESHOLD (ms, 5000), AH_NTP_CHECK_INTERVAL (ms, 60000), AH_NTP_TIMEOUT (ms, 10000).
pub mod time {
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use tokio::sync::RwLock;
    pub const NTP_PORT: u16 = 123;
    const NTP_EPOCH_OFFSET_SECONDS: i64 = 2_208_988_800;
    const PACKET_SIZE: usize = 48;
    const ORIGINATE: usize = 24;
    const RECEIVE: usize = 32;
    const TRANSMIT: usize = 40;
    #[derive(Clone, Debug, PartialEq)]
    pub struct Measurement {
        pub server: String,
        pub offset_ms: i64,
        pub delay_ms: i64,
        pub stratum: u8,
    }
    #[derive(Clone, Debug, Default)]
    pub struct TrustState {
        pub trusted: bool,
        pub offset_ms: Option<i64>,
        pub delay_ms: Option<i64>,
        pub server: Option<String>,
        pub checked_at: Option<String>,
        pub detail: String,
    }
    #[derive(Clone, Debug)]
    pub struct Settings {
        pub servers: Vec<String>,
        pub threshold_ms: i64,
        pub interval_ms: u64,
        pub timeout_ms: u64,
    }
    impl Settings {
        pub fn from_env() -> Self {
            let num = |k: &str, d: u64| {
                std::env::var(k)
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(d)
            };
            Self {
                servers: std::env::var("AH_NTP_SERVER_LIST")
                    .unwrap_or_else(|_| "pool.ntp.org".into())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                threshold_ms: num("AH_TIME_OFFSET_THRESHOLD", 5000) as i64,
                interval_ms: num("AH_NTP_CHECK_INTERVAL", 60000).max(1000),
                timeout_ms: num("AH_NTP_TIMEOUT", 10000).max(1),
            }
        }
    }
    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
    pub fn write_timestamp(buf: &mut [u8], at: usize, epoch_ms: i64) {
        let seconds = (epoch_ms.div_euclid(1000) + NTP_EPOCH_OFFSET_SECONDS) as u32;
        let fraction = ((epoch_ms.rem_euclid(1000) as u64) * 0x1_0000_0000 / 1000) as u32;
        buf[at..at + 4].copy_from_slice(&seconds.to_be_bytes());
        buf[at + 4..at + 8].copy_from_slice(&fraction.to_be_bytes());
    }
    pub fn read_timestamp(buf: &[u8], at: usize) -> i64 {
        let seconds = u32::from_be_bytes(buf[at..at + 4].try_into().unwrap()) as i64;
        let fraction = u32::from_be_bytes(buf[at + 4..at + 8].try_into().unwrap()) as i64;
        (seconds - NTP_EPOCH_OFFSET_SECONDS) * 1000 + fraction * 1000 / 0x1_0000_0000
    }
    pub fn offset(t1: i64, t2: i64, t3: i64, t4: i64) -> i64 {
        ((t2 - t1) + (t3 - t4)) / 2
    }
    pub fn delay(t1: i64, t2: i64, t3: i64, t4: i64) -> i64 {
        (t4 - t1) - (t3 - t2)
    }
    pub fn request(t1: i64) -> [u8; PACKET_SIZE] {
        let mut r = [0u8; PACKET_SIZE];
        r[0] = 0x23; // LI 0, version 4, mode 3 (client)
        write_timestamp(&mut r, TRANSMIT, t1);
        r
    }
    pub fn evaluate(
        host: &str,
        req: &[u8],
        resp: &[u8],
        t1: i64,
        t4: i64,
    ) -> Result<Measurement, String> {
        if resp.len() < PACKET_SIZE {
            return Err(format!("Short NTP response from {host}"));
        }
        let mode = resp[0] & 0x07;
        if mode != 4 && mode != 5 {
            return Err(format!("Unexpected NTP mode {mode} from {host}"));
        }
        let stratum = resp[1];
        if stratum == 0 || stratum > 15 {
            return Err(format!(
                "Unsynchronized or kiss-o'-death NTP response (stratum {stratum}) from {host}"
            ));
        }
        // The server echoes our transmit timestamp; a mismatch indicates a stale or forged reply.
        if resp[ORIGINATE..ORIGINATE + 8] != req[TRANSMIT..TRANSMIT + 8] {
            return Err(format!("NTP originate timestamp mismatch from {host}"));
        }
        let (t2, t3) = (
            read_timestamp(resp, RECEIVE),
            read_timestamp(resp, TRANSMIT),
        );
        Ok(Measurement {
            server: host.into(),
            offset_ms: offset(t1, t2, t3, t4),
            delay_ms: delay(t1, t2, t3, t4),
            stratum,
        })
    }
    pub async fn query(host: &str, port: u16, timeout_ms: u64) -> Result<Measurement, String> {
        let exchange = async {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| e.to_string())?;
            socket
                .connect((host, port))
                .await
                .map_err(|e| e.to_string())?;
            let t1 = now_ms();
            let req = request(t1);
            socket.send(&req).await.map_err(|e| e.to_string())?;
            let mut resp = [0u8; 512];
            let n = socket.recv(&mut resp).await.map_err(|e| e.to_string())?;
            evaluate(host, &req, &resp[..n], t1, now_ms())
        };
        tokio::time::timeout(Duration::from_millis(timeout_ms), exchange)
            .await
            .map_err(|_| format!("NTP query to {host} timed out"))?
    }
    // The first server that answers decides; the others are fallbacks.
    pub async fn check(settings: &Settings, port: u16) -> TrustState {
        let checked_at =
            Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        let mut failures = Vec::new();
        for server in &settings.servers {
            match query(server, port, settings.timeout_ms).await {
                Ok(m) => {
                    let trusted = m.offset_ms.abs() < settings.threshold_ms;
                    let detail = format!(
                        "Clock offset {} ms to {server} {} {} ms",
                        m.offset_ms,
                        if trusted { "is within" } else { "exceeds" },
                        settings.threshold_ms
                    );
                    return TrustState {
                        trusted,
                        offset_ms: Some(m.offset_ms),
                        delay_ms: Some(m.delay_ms),
                        server: Some(m.server),
                        checked_at,
                        detail,
                    };
                }
                Err(e) => failures.push(format!("{server}: {e}")),
            }
        }
        let detail = if settings.servers.is_empty() {
            "No NTP server configured".into()
        } else {
            format!("No NTP server reachable ({})", failures.join("; "))
        };
        TrustState {
            checked_at,
            detail,
            ..Default::default()
        }
    }
    static STATE: OnceLock<Arc<RwLock<Option<TrustState>>>> = OnceLock::new();
    // Starts the periodic check on first use and waits for the first result (bounded by the timeouts).
    pub async fn state() -> TrustState {
        let mut first = false;
        let cell = STATE.get_or_init(|| {
            first = true;
            Arc::new(RwLock::new(None))
        });
        if first {
            let cell = cell.clone();
            let settings = Settings::from_env();
            let mut guard = cell.clone().write_owned().await;
            *guard = Some(check(&settings, NTP_PORT).await);
            drop(guard);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(settings.interval_ms)).await;
                    let next = check(&settings, NTP_PORT).await;
                    let mut slot = cell.write().await;
                    if slot.as_ref().map(|p| p.trusted) != Some(next.trusted) {
                        eprintln!("Time trust changed to {}: {}", next.trusted, next.detail);
                    }
                    *slot = Some(next);
                }
            });
        }
        cell.read().await.clone().unwrap_or_else(|| TrustState {
            detail: "No time check completed yet".into(),
            ..Default::default()
        })
    }
}
