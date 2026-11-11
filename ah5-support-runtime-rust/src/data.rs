// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
pub fn first<'a>(q: &'a Value, key: &str) -> &'a str {
    q[key]
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .unwrap_or("")
}
pub fn count(q: &Value, default: usize) -> Result<usize> {
    let raw = first(q, "count");
    let n = if raw.is_empty() {
        default
    } else {
        raw.parse().map_err(|_| Error::bad("Invalid count"))?
    };
    if n == 0 || n > 1000 {
        return Err(Error::bad("count must be 1..1000"));
    }
    Ok(n)
}
pub fn in_range(timestamp: &str, from: &str, to: &str) -> Result<bool> {
    let t = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| Error::bad("Invalid timestamp"))?;
    if !from.is_empty()
        && t < chrono::DateTime::parse_from_rfc3339(from)
            .map_err(|_| Error::bad("Invalid from timestamp"))?
    {
        return Ok(false);
    }
    if !to.is_empty()
        && t > chrono::DateTime::parse_from_rfc3339(to)
            .map_err(|_| Error::bad("Invalid to timestamp"))?
    {
        return Ok(false);
    }
    Ok(true)
}
/// dataHistorian retention: deletes SenML rows received before `now - retention_days`, then the oldest received rows
/// beyond `max_records`. Rows without a readable receivedAt are kept by age (as in Go) but count towards the cap.
/// Returns the number of deleted rows.
pub fn prune_senml(
    db: &mut crate::store::Database,
    retention_days: u32,
    max_records: usize,
) -> usize {
    let Some(rows) = db.get_mut("senml") else {
        return 0;
    };
    let before = rows.len();
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days.into());
    let received = |row: &Value| chrono::DateTime::parse_from_rfc3339(s(row, "receivedAt")).ok();
    rows.retain(|_, row| received(row).is_none_or(|t| t >= cutoff));
    if rows.len() > max_records {
        // unreadable times sort first, so they go before any dated row
        let mut order = rows
            .iter()
            .map(|(id, row)| (received(row), id.clone()))
            .collect::<Vec<_>>();
        order.sort();
        for (_, id) in order.into_iter().take(rows.len() - max_records) {
            rows.remove(&id);
        }
    }
    before - rows.len()
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
    let system = p.get("systemName").map(String::as_str).unwrap_or("");
    let service = p.get("serviceName").map(String::as_str).unwrap_or("");
    let proxy = path.contains("/data-proxy/");
    if path.ends_with("/systems") || path.ends_with("/services") {
        let list_systems = path.ends_with("/systems");
        let mut names = BTreeSet::new();
        app.store.visit("senml", |row| {
            if list_systems {
                names.insert(s(row, "system").to_owned());
            } else if s(row, "system") == system {
                names.insert(s(row, "service").to_owned());
            }
        });
        if proxy {
            let area = if list_systems { "system" } else { "service" };
            let result = app
                .remote
                .call(
                    "ServiceRegistry",
                    "POST",
                    &format!("/serviceregistry/{area}-discovery/lookup"),
                    &if list_systems {
                        json!({})
                    } else {
                        json!({"providerNames":[system]})
                    },
                )
                .await?;
            for row in array(&result, "entries") {
                let name = if list_systems {
                    s(&row, "name")
                } else {
                    s(&row["serviceDefinition"], "name")
                };
                if !name.is_empty() {
                    names.insert(name.into());
                }
            }
        }
        return Ok((
            200,
            json!({if list_systems{"systems"}else{"services"}:names}),
        ));
    }
    if !valid_name(system) || service.is_empty() {
        return Err(Error::bad("Invalid system/service"));
    }
    if proxy {
        let query = app
            .remote
            .call(
                "ServiceRegistry",
                "POST",
                "/serviceregistry/service-discovery/lookup",
                &json!({"providerNames":[system],"serviceDefinitionNames":[service]}),
            )
            .await?;
        let entries = array(&query, "entries");
        let instance = entries
            .first()
            .ok_or_else(|| Error::new(404, "Provider service absent"))?;
        let operation = if method == "GET" {
            "get-data"
        } else {
            "put-data"
        };
        let interfaces = array(instance, "interfaces");
        let iface = interfaces
            .iter()
            .find(|i| {
                s(i, "protocol").eq_ignore_ascii_case("https")
                    && i["properties"]["operations"][operation].is_object()
            })
            .ok_or_else(|| Error::unavailable("Provider has no compatible HTTPS operation"))?;
        let properties = &iface["properties"];
        let op = &properties["operations"][operation];
        if s(op, "method") != method {
            return Err(Error::new(502, "Registry operation method mismatch"));
        }
        let target = format!(
            "{}/{}",
            s(properties, "basePath").trim_end_matches('/'),
            s(op, "path").trim_start_matches('/')
        );
        if target.contains('{') {
            return Err(Error::unsupported(
                "Templated provider data operation needs binding",
            ));
        }
        let suffix = if method == "GET" {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            for key in ["from", "to", "count", "signals", "signalCount"] {
                for val in array(q, key) {
                    encoded.append_pair(key, val.as_str().unwrap_or(""));
                }
            }
            let query = encoded.finish();
            if query.is_empty() {
                String::new()
            } else {
                format!("?{query}")
            }
        } else {
            String::new()
        };
        return Ok((
            200,
            app.remote
                .call(
                    system,
                    method,
                    &format!("{target}{suffix}"),
                    if method == "GET" { &Value::Null } else { req },
                )
                .await?,
        ));
    }
    if method == "PUT" {
        own(caller, system)?;
        let pack = req
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 1000)
            .ok_or_else(|| Error::bad("SenML pack must contain 1..1000 records"))?;
        // RFC 8428 base fields apply to the record that carries them and to all later records.
        // validated completely before anything is stored; then appended in place (no copy of the state)
        let new_rows = (|| -> Result<Vec<(String, Value)>> {
            let mut rows = Vec::with_capacity(pack.len());
            let mut bt = chrono::Utc::now().timestamp_millis() as f64 / 1000.;
            let mut bn = String::new();
            let (mut bu, mut bv, mut bs, mut bver) =
                (Value::Null, Value::Null, Value::Null, Value::Null);
            for record in pack {
                if !record.is_object() {
                    return Err(Error::bad("SenML record must be an object"));
                }
                if let Some(v) = record["bt"].as_f64() {
                    bt = v
                }
                if record["bn"].is_string() {
                    bn = s(record, "bn").into()
                }
                if record["bu"].is_string() {
                    bu = record["bu"].clone()
                }
                for (key, slot) in [("bv", &mut bv), ("bs", &mut bs)] {
                    if !record[key].is_null() {
                        let v = record[key]
                            .as_f64()
                            .filter(|v| v.is_finite())
                            .ok_or_else(|| Error::bad("SenML bv/bs must be finite numbers"))?;
                        *slot = v.into();
                    }
                }
                for key in ["bver", "ver"] {
                    if !record[key].is_null() {
                        let v = record[key]
                            .as_u64()
                            .filter(|v| (1..=10).contains(v))
                            .ok_or_else(|| Error::bad("Unsupported SenML version"))?;
                        bver = v.into();
                    }
                }
                let values = ["v", "vs", "vb", "vd"]
                    .iter()
                    .filter(|key| record.get(**key).is_some())
                    .count();
                let has_sum = record.get("s").is_some();
                if values > 1 || (values == 0 && !has_sum && bv.is_null() && bs.is_null()) {
                    return Err(Error::bad("SenML record requires exactly one value"));
                }
                if ["v", "s"].iter().any(|key| {
                    record
                        .get(*key)
                        .is_some_and(|v| v.as_f64().is_none_or(|f| !f.is_finite()))
                }) {
                    return Err(Error::bad("SenML v/s must be numbers"));
                }
                let epoch = bt + record["t"].as_f64().unwrap_or(0.);
                if !epoch.is_finite() || epoch < 0. {
                    return Err(Error::bad("Invalid SenML time"));
                }
                // Resolved numeric value and sum, so readers need not apply bv/bs themselves.
                let resolved_value = match (record["v"].as_f64(), bv.as_f64()) {
                    (Some(v), b) => Some(v + b.unwrap_or(0.)),
                    (None, Some(b)) if values == 0 => Some(b),
                    _ => None,
                };
                let resolved_sum = match (record["s"].as_f64(), bs.as_f64()) {
                    (Some(v), b) => Some(v + b.unwrap_or(0.)),
                    (None, Some(b)) if values == 0 && !has_sum => Some(b),
                    _ => None,
                };
                let id = id();
                rows.push((id.clone(), json!({"id":id,"system":system,"service":service,"signal":format!("{bn}{}",s(record,"n")),"epoch":epoch,"record":record,"baseTime":bt,"baseName":bn,"baseUnit":bu,"baseValue":bv,"baseSum":bs,"baseVersion":bver,"value":resolved_value,"sum":resolved_sum,"receivedAt":now()})));
            }
            Ok(rows)
        })()?;
        app.store.append("senml", new_rows, |db| {
            prune_senml(db, app.config.retention_days, app.config.max_senml_records)
        })?;
        return Ok((200, Value::Null));
    }
    // signalCount caps the records returned per requested signal (Java: default 1 when signals are given).
    let signal_count = match first(q, "signalCount") {
        "" => None,
        raw => Some(
            raw.parse::<usize>()
                .ok()
                .filter(|n| (1..=1000).contains(n))
                .ok_or_else(|| Error::bad("signalCount must be 1..1000"))?,
        ),
    };
    let from = if first(q, "from").is_empty() {
        0.
    } else {
        first(q, "from")
            .parse::<f64>()
            .map_err(|_| Error::bad("Invalid from"))?
    };
    let to = if first(q, "to").is_empty() {
        f64::MAX
    } else {
        first(q, "to")
            .parse::<f64>()
            .map_err(|_| Error::bad("Invalid to"))?
    };
    if !from.is_finite() || !to.is_finite() || to < from {
        return Err(Error::bad("Invalid time range"));
    }
    let mut rows = app.store.select("senml", |r| {
        s(r, "system") == system
            && s(r, "service") == service
            && r["epoch"].as_f64().is_some_and(|t| t >= from && t <= to)
            && selected(q, "signals", s(r, "signal"))
    });
    rows.sort_by(|a, b| {
        b["epoch"]
            .as_f64()
            .unwrap()
            .total_cmp(&a["epoch"].as_f64().unwrap())
            .then(s(a, "id").cmp(s(b, "id")))
    });
    let limit = count(q, 100)?;
    if let Some(per_signal) = signal_count.filter(|_| !array(q, "signals").is_empty()) {
        let mut seen = BTreeMap::<String, usize>::new();
        rows.retain(|r| {
            let n = seen.entry(s(r, "signal").to_owned()).or_default();
            *n += 1;
            *n <= per_signal
        });
    } else {
        rows.truncate(limit);
    }
    // Reintroduce context per record so filtering a pack cannot change absolute names or times.
    let pack = rows
        .into_iter()
        .map(|r| {
            let mut v = r["record"].clone();
            v["bn"] = r["baseName"].clone();
            v["bt"] = r["baseTime"].clone();
            let obj = v.as_object_mut().unwrap();
            obj.remove("ver");
            for (key, field) in [
                ("bu", "baseUnit"),
                ("bv", "baseValue"),
                ("bs", "baseSum"),
                ("bver", "baseVersion"),
            ] {
                if r[field].is_null() {
                    obj.remove(key);
                } else {
                    obj.insert(key.into(), r[field].clone());
                }
            }
            v
        })
        .collect::<Vec<_>>();
    Ok((200, pack.into()))
}

#[cfg(test)]
mod retention_tests {
    use super::prune_senml;
    use crate::store::{Database, Store};
    use serde_json::json;

    fn historian(ages_days: &[i64]) -> Database {
        let mut db = Database::new();
        let rows = db.entry("senml".into()).or_default();
        for (i, age) in ages_days.iter().enumerate() {
            let at = (chrono::Utc::now() - chrono::Duration::days(*age))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            rows.insert(
                format!("r{i}"),
                json!({"id": format!("r{i}"), "receivedAt": at}),
            );
        }
        db
    }

    #[test]
    fn records_past_the_retention_period_are_deleted() {
        let mut db = historian(&[0, 10, 31, 400]);
        assert_eq!(prune_senml(&mut db, 30, 100), 2);
        assert!(db["senml"].contains_key("r0") && db["senml"].contains_key("r1"));
    }

    #[test]
    fn the_oldest_records_beyond_the_cap_are_deleted() {
        let mut db = historian(&[5, 1, 3, 0, 2]);
        assert_eq!(prune_senml(&mut db, 30, 3), 2);
        let kept: Vec<_> = db["senml"].keys().cloned().collect();
        assert_eq!(kept, ["r1", "r3", "r4"]);
    }

    #[test]
    fn unreadable_times_survive_age_but_count_towards_the_cap() {
        let mut db = historian(&[0, 1]);
        db.get_mut("senml")
            .unwrap()
            .insert("odd".into(), json!({"id": "odd"}));
        assert_eq!(prune_senml(&mut db, 30, 10), 0);
        assert_eq!(prune_senml(&mut db, 30, 2), 1);
        assert!(!db["senml"].contains_key("odd"));
    }

    #[test]
    fn append_prunes_in_place_and_select_clones_only_matches() {
        let dir = std::env::temp_dir().join(format!("dm-append-{}", uuid::Uuid::new_v4()));
        let path = dir.join("state.json");
        let store = Store::open(&path).unwrap();
        store
            .update(|db| {
                *db = historian(&[0, 1, 2]);
                Ok(())
            })
            .unwrap();
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        store
            .append(
                "senml",
                vec![("new".into(), json!({"id": "new", "receivedAt": now}))],
                |db| prune_senml(db, 30, 3),
            )
            .unwrap();
        let ids = store
            .select("senml", |_| true)
            .into_iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["new", "r0", "r1"]);
        assert_eq!(store.select("senml", |r| r["id"] == "r1").len(), 1);
        drop(store);
        assert_eq!(Store::open(&path).unwrap().rows("senml").len(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_prune_persists_without_cloning_and_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("dm-retention-{}", uuid::Uuid::new_v4()));
        let path = dir.join("state.json");
        {
            let store = Store::open(&path).unwrap();
            store
                .update(|db| {
                    *db = historian(&[0, 40, 50]);
                    Ok(())
                })
                .unwrap();
            assert_eq!(store.prune(|db| prune_senml(db, 30, 100)).unwrap(), 2);
            assert_eq!(store.prune(|db| prune_senml(db, 30, 100)).unwrap(), 0);
            assert_eq!(store.rows("senml").len(), 1);
        }
        let reopened = Store::open(&path).unwrap();
        assert_eq!(reopened.rows("senml").len(), 1);
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".state-")
            })
            .count();
        assert_eq!(leftovers, 0);
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
