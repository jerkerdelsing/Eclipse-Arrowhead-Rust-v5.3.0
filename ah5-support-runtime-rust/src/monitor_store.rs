// SPDX-License-Identifier: EPL-2.0
//! Bounded, transactional telemetry history and QoS-1 durable outbox.
use crate::*;
use rusqlite::{Connection, params};
use std::{path::Path, sync::Mutex};
pub struct MonitorDb(Mutex<Connection>);
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Error::unavailable("Monitoring database operation failed")
    }
}
impl MonitorDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = path.as_ref();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(Error::bad("Monitoring database must be owner-only"));
        }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,provider TEXT NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,received TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS observations_provider ON observations(provider,kind,source);
        CREATE INDEX IF NOT EXISTS observations_received ON observations(received);
        CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,topic TEXT NOT NULL,payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS meta(name TEXT PRIMARY KEY,value TEXT NOT NULL);")?;
        Ok(Self(Mutex::new(db)))
    }
    pub fn import(&self, store: &Store) -> Result<()> {
        let mut db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let transaction = db.transaction()?;
        let imported = transaction.query_row(
            "SELECT count(*) FROM meta WHERE name='json-imported-v1'",
            [],
            |r| r.get::<_, u32>(0),
        )?;
        if imported == 0 {
            for value in store.rows("observations") {
                transaction.execute(
                    "INSERT INTO observations VALUES(?,?,?,?,?,?)",
                    params![
                        s(&value, "observationId"),
                        s(&value, "providerSystem"),
                        s(&value, "observationType"),
                        s(&value, "sourceTime"),
                        s(&value, "receivedTime"),
                        serde_json::to_string(&value)?
                    ],
                )?;
            }
            for row in store.rows("monitor-outbox") {
                transaction.execute(
                    "INSERT INTO outbox VALUES(?,?,?)",
                    params![
                        s(&row["observation"], "observationId"),
                        s(&row, "topic"),
                        serde_json::to_string(&row["observation"])?
                    ],
                )?;
            }
            transaction.execute("INSERT INTO meta VALUES('json-imported-v1','complete')", [])?;
        }
        transaction.commit()?;
        Ok(())
    }
    pub fn append(&self, row: &Value, topic: &str) -> Result<Value> {
        let mut db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let transaction = db.transaction()?;
        let mut old = transaction.prepare("SELECT payload FROM observations WHERE id=?")?;
        if let Some(payload) = old
            .query_map([s(row, "observationId")], |r| r.get::<_, String>(0))?
            .next()
        {
            let previous: Value = serde_json::from_str(&payload?)?;
            for key in [
                "providerSystem",
                "serviceInstance",
                "observationType",
                "sourceTime",
                "value",
            ] {
                if previous[key] != row[key] {
                    return Err(Error::new(
                        409,
                        "Observation ID reused with different content",
                    ));
                }
            }
            return Ok(previous);
        }
        drop(old);
        if transaction.query_row("SELECT count(*) FROM outbox", [], |r| r.get::<_, u32>(0))?
            >= 100000
        {
            return Err(Error::unavailable("MQTT outbox capacity reached"));
        }
        let payload = serde_json::to_string(row)?;
        transaction.execute(
            "INSERT INTO observations VALUES(?,?,?,?,?,?)",
            params![
                s(row, "observationId"),
                s(row, "providerSystem"),
                s(row, "observationType"),
                s(row, "sourceTime"),
                s(row, "receivedTime"),
                payload
            ],
        )?;
        transaction.execute(
            "INSERT INTO outbox VALUES(?,?,?)",
            params![s(row, "observationId"), topic, payload],
        )?;
        transaction.commit()?;
        Ok(row.clone())
    }
    pub fn history(
        &self,
        system: &str,
        types: &[String],
        from: &str,
        to: &str,
        count: usize,
    ) -> Result<Vec<Value>> {
        let db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let mut args = vec![system.to_string()];
        let mut sql = String::from("SELECT payload FROM observations WHERE provider=?");
        if !types.is_empty() {
            sql.push_str(&format!(
                " AND kind IN ({})",
                vec!["?"; types.len()].join(",")
            ));
            args.extend_from_slice(types);
        }
        for (bound, op) in [(from, ">="), (to, "<=")] {
            if !bound.is_empty() {
                sql.push_str(&format!(" AND julianday(source){op}julianday(?)"));
                args.push(bound.into());
            }
        }
        sql.push_str(" ORDER BY julianday(source) DESC,id LIMIT ?");
        args.push(count.to_string());
        let mut query = db.prepare(&sql)?;
        query
            .query_map(rusqlite::params_from_iter(args), |r| r.get::<_, String>(0))?
            .map(|row| Ok(serde_json::from_str(&row?)?))
            .collect()
    }
    pub fn latest(&self, system: &str) -> Result<Value> {
        let db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let mut statement=db.prepare("SELECT payload FROM observations o WHERE provider=? AND id=(SELECT id FROM observations n WHERE n.provider=o.provider AND n.kind=o.kind ORDER BY julianday(source) DESC,id LIMIT 1)")?;
        let mut latest = json!({});
        for row in statement.query_map([system], |r| r.get::<_, String>(0))? {
            let value: Value = serde_json::from_str(&row?)?;
            latest[s(&value, "observationType")] = value.clone();
        }
        Ok(latest)
    }
    pub fn systems(&self) -> Result<Vec<Value>> {
        let db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let mut statement=db.prepare("SELECT provider,count(*),min(source),max(source) FROM observations GROUP BY provider ORDER BY provider")?;
        statement.query_map([],|r|Ok(json!({"systemName":r.get::<_,String>(0)?,"observationCount":r.get::<_,i64>(1)?,"firstObservationTime":r.get::<_,String>(2)?,"lastObservationTime":r.get::<_,String>(3)?})))?.map(|r|r.map_err(Error::from)).collect()
    }
    pub fn counts(&self) -> Result<Value> {
        let db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        Ok(
            json!({"stored":db.query_row("SELECT count(*) FROM observations",[],|r|r.get::<_,i64>(0))?,"pending":db.query_row("SELECT count(*) FROM outbox",[],|r|r.get::<_,i64>(0))?}),
        )
    }
    pub fn pending(&self) -> Result<Vec<(String, Value)>> {
        let db = self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?;
        let mut statement =
            db.prepare("SELECT id,topic,payload FROM outbox ORDER BY rowid LIMIT 50")?;
        statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .map(|row| {
                let (id, topic, payload) = row?;
                Ok((
                    id,
                    json!({"topic":topic,"observation":serde_json::from_str::<Value>(&payload)?}),
                ))
            })
            .collect()
    }
    pub fn published(&self, id: &str) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?
            .execute("DELETE FROM outbox WHERE id=?", [id])?;
        Ok(())
    }
    pub fn prune(&self, days: u32) -> Result<usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days.into());
        Ok(self
            .0
            .lock()
            .map_err(|_| Error::unavailable("Monitoring database lock"))?
            .execute(
                "DELETE FROM observations WHERE received<?",
                [cutoff.to_rfc3339()],
            )?)
    }
}
