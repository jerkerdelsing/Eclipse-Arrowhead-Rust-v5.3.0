// SPDX-License-Identifier: EPL-2.0
use crate::{Error, Result};
use serde_json::Value;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

pub type Database = BTreeMap<String, BTreeMap<String, Value>>;
pub struct Store {
    data: Mutex<Database>,
    path: Option<PathBuf>,
    _lock: Option<File>,
}
impl Store {
    pub fn memory() -> Self {
        Self {
            data: Mutex::new(Database::new()),
            path: None,
            _lock: None,
        }
    }
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path.with_extension("lock"))?;
        lock.try_lock()
            .map_err(|_| Error::new(409, "State is already owned by another process"))?;
        let data = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b)
                .map_err(|_| Error::new(500, "Corrupt state; refusing to reset"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Database::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            data: Mutex::new(data),
            path: Some(path),
            _lock: Some(lock),
        })
    }
    pub fn snapshot(&self) -> Database {
        self.data.lock().expect("state mutex poisoned").clone()
    }
    pub fn rows(&self, table: &str) -> Vec<Value> {
        self.snapshot()
            .get(table)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
    pub fn update<T>(&self, action: impl FnOnce(&mut Database) -> Result<T>) -> Result<T> {
        let mut guard = self
            .data
            .lock()
            .map_err(|_| Error::new(500, "State unavailable"))?;
        let mut next = guard.clone();
        let result = action(&mut next)?;
        if let Some(path) = &self.path {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let temp = parent.join(format!(".state-{}", uuid::Uuid::new_v4()));
            let write = (|| -> Result<()> {
                let mut f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&temp)?;
                f.set_permissions(fs::Permissions::from_mode(0o600))?;
                f.write_all(&serde_json::to_vec(&next)?)?;
                f.sync_all()?;
                fs::rename(&temp, path)?;
                Ok(())
            })();
            if let Err(e) = write {
                let _ = fs::remove_file(&temp);
                return Err(e);
            }
            *guard = next; // Rename is the commit point; a later directory-sync failure is an uncertain durable commit.
            File::open(parent)?.sync_all()?;
        } else {
            *guard = next;
        }
        Ok(result)
    }
}
pub fn table<'a>(db: &'a mut Database, key: &str) -> &'a mut BTreeMap<String, Value> {
    db.entry(key.into()).or_default()
}
