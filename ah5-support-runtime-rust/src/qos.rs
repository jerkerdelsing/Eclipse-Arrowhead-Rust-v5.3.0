// SPDX-License-Identifier: EPL-2.0
use crate::*;
use std::collections::BTreeMap;
#[allow(clippy::too_many_arguments)]
pub async fn handle(
    app: &App,
    _method: &str,
    path: &str,
    _p: &BTreeMap<String, String>,
    _q: &Value,
    req: &Value,
    _caller: &Principal,
) -> Result<(u16, Value)> {
    if path.ends_with("/reload") {
        let result = app
            .remote
            .call(
                "DeviceMeasurementAgent",
                "GET",
                "/measurements",
                &Value::Null,
            )
            .await?;
        let records = result
            .as_array()
            .filter(|a| a.len() <= 10000)
            .ok_or_else(|| Error::new(502, "Agent must return bounded measurement array"))?;
        app.store.update(|db| {
            for record in records {
                required(record, &["systemName", "metricGroup", "timestamp"])?;
                if !valid_name(s(record, "systemName"))
                    || record["current"].as_f64().is_none()
                    || chrono::DateTime::parse_from_rfc3339(s(record, "timestamp")).is_err()
                {
                    return Err(Error::new(502, "Invalid agent measurement"));
                }
                table(db, "measurements").insert(id(), record.clone());
            }
            Ok(())
        })?;
        return Ok((200, json!({"loaded":records.len()})));
    }
    if path.ends_with("/query") {
        let mut rows = Vec::new();
        for record in app.store.rows("measurements") {
            if selected(req, "systemNames", s(&record, "systemName"))
                && (s(req, "metricGroup").is_empty()
                    || s(req, "metricGroup") == s(&record, "metricGroup"))
                && data::in_range(s(&record, "timestamp"), s(req, "from"), s(req, "to"))?
            {
                rows.push(record)
            }
        }
        return Ok((200, page(rows, req, "records")?));
    }
    let providers = array(req, "providers");
    let cfg = &req["configuration"];
    let metrics = array(cfg, "metricNames");
    let weights = array(cfg, "metricWeights");
    if providers.is_empty()
        || providers.len() > 1000
        || metrics.is_empty()
        || metrics.len() != weights.len()
    {
        return Err(Error::bad(
            "providers and equally sized metricNames/metricWeights required",
        ));
    }
    let window = integer(cfg, "timeWindow", 300);
    if window == 0 || window > 86400 * 365 {
        return Err(Error::bad("Invalid timeWindow"));
    }
    let measurements = app.store.rows("measurements");
    let mut scores = Vec::new();
    let mut warnings = json!({});
    for provider in providers {
        let name = provider
            .as_str()
            .filter(|n| valid_name(n))
            .ok_or_else(|| Error::bad("Invalid provider"))?;
        let mut score = 0.;
        let mut missing = Vec::new();
        for (metric, weight) in metrics.iter().zip(&weights) {
            let metric = metric
                .as_str()
                .ok_or_else(|| Error::bad("Invalid metric"))?;
            let weight = weight
                .as_f64()
                .filter(|w| w.is_finite())
                .ok_or_else(|| Error::bad("Invalid weight"))?;
            let values = measurements
                .iter()
                .filter(|r| {
                    s(r, "systemName") == name
                        && s(r, "metricGroup") == metric
                        && chrono::DateTime::parse_from_rfc3339(s(r, "timestamp")).is_ok_and(|t| {
                            let age = chrono::Utc::now().signed_duration_since(t).num_seconds();
                            age >= 0 && age <= window as i64
                        })
                })
                .filter_map(|r| r["current"].as_f64())
                .collect::<Vec<_>>();
            if values.is_empty() {
                missing.push(metric.to_string())
            } else {
                score += values.iter().sum::<f64>() / values.len() as f64 * weight
            }
        }
        if !score.is_finite() {
            return Err(Error::bad("Metric magnitude exceeds range"));
        }
        if !missing.is_empty() {
            warnings[name] = json!(missing);
            score = f64::MAX
        }
        scores.push((name.to_string(), score, missing.is_empty()));
    }
    if path.ends_with("/sort") {
        scores.sort_by(|a, b| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0)));
        return Ok((
            200,
            json!({"sortedProviders":scores.into_iter().map(|s|s.0).collect::<Vec<_>>(),"warnings":warnings}),
        ));
    }
    let threshold = cfg["threshold"]
        .as_f64()
        .ok_or_else(|| Error::bad("threshold required"))?;
    let (passed, dropped): (Vec<_>, Vec<_>) =
        scores.into_iter().partition(|s| s.2 && s.1 <= threshold);
    Ok((
        200,
        json!({"passedProviders":passed.into_iter().map(|s|s.0).collect::<Vec<_>>(),"droppedProviders":dropped.into_iter().map(|s|s.0).collect::<Vec<_>>(),"warnings":warnings}),
    ))
}
