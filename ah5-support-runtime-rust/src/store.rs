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
impl Drop for Store {
    fn drop(&mut self) {
        // Explicit release also handles a concurrent fork retaining the lock fd
        // briefly before exec (test fixture/tool processes).
        if let Some(lock) = &self._lock {
            let _ = lock.unlock();
        }
    }
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
        // streamed: the file is not held in memory next to the parsed state
        let data = match File::open(&path) {
            Ok(f) => serde_json::from_reader(std::io::BufReader::with_capacity(64 * 1024, f))
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
    /// Copies of one table's rows; only that table is cloned, not the whole database.
    pub fn rows(&self, table: &str) -> Vec<Value> {
        self.data
            .lock()
            .expect("state mutex poisoned")
            .get(table)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
    /// The rows of one table that `keep` accepts; only those are cloned.
    pub fn select(&self, table: &str, keep: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.data
            .lock()
            .expect("state mutex poisoned")
            .get(table)
            .map(|m| m.values().filter(|v| keep(v)).cloned().collect())
            .unwrap_or_default()
    }
    /// Visits the rows of one table without cloning them.
    pub fn visit(&self, table: &str, mut each: impl FnMut(&Value)) {
        if let Some(m) = self.data.lock().expect("state mutex poisoned").get(table) {
            m.values().for_each(&mut each);
        }
    }
    /// Appends rows to one table, lets `prune` delete in place, and persists, all without cloning the database (unlike
    /// `update`). If the write fails the appended rows are taken out again and the error returned; pruned rows stay
    /// deleted in memory (as with `prune`).
    pub fn append(
        &self,
        name: &str,
        rows: Vec<(String, Value)>,
        prune: impl FnOnce(&mut Database) -> usize,
    ) -> Result<()> {
        let mut guard = self
            .data
            .lock()
            .map_err(|_| Error::new(500, "State unavailable"))?;
        let ids = rows.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        table(&mut guard, name).extend(rows);
        prune(&mut guard);
        if let Some(path) = &self.path {
            if let Err(e) = persist(path, &guard) {
                let t = table(&mut guard, name);
                ids.iter().for_each(|id| {
                    t.remove(id);
                });
                return Err(e);
            }
            sync_parent(path)?;
        }
        Ok(())
    }
    /// Deletes in place and persists: `action` removes rows and returns how many. Unlike `update` the database is not
    /// cloned, so pruning a large table needs no second copy of it (DataManager OOM, 2026-11-09). Deletions only: if
    /// the write fails, memory holds fewer rows than the file, and the next write or prune persists them.
    pub fn prune(&self, action: impl FnOnce(&mut Database) -> usize) -> Result<usize> {
        let mut guard = self
            .data
            .lock()
            .map_err(|_| Error::new(500, "State unavailable"))?;
        let removed = action(&mut guard);
        if let Some(path) = self.path.as_ref().filter(|_| removed > 0) {
            persist(path, &guard)?;
            sync_parent(path)?;
        }
        Ok(removed)
    }
    pub fn update<T>(&self, action: impl FnOnce(&mut Database) -> Result<T>) -> Result<T> {
        let mut guard = self
            .data
            .lock()
            .map_err(|_| Error::new(500, "State unavailable"))?;
        let mut next = guard.clone();
        let result = action(&mut next)?;
        if let Some(path) = &self.path {
            persist(path, &next)?;
            *guard = next; // Rename is the commit point; a later directory-sync failure is an uncertain durable commit.
            sync_parent(path)?;
        } else {
            *guard = next;
        }
        Ok(result)
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
// Atomic replacement of the state file: temp file, fsync, rename (the commit point); `sync_parent` follows.
fn persist(path: &Path, db: &Database) -> Result<()> {
    let parent = parent(path);
    let temp = parent.join(format!(".state-{}", uuid::Uuid::new_v4()));
    let write = (|| -> Result<()> {
        let f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        // streamed: no in-memory copy of the serialized state (several MiB per write, retained by the allocator)
        let mut out = std::io::BufWriter::with_capacity(64 * 1024, f);
        serde_json::to_writer(&mut out, db)?;
        out.flush()?;
        let f = out
            .into_inner()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(&temp);
        return Err(e);
    }
    Ok(())
}
fn sync_parent(path: &Path) -> Result<()> {
    File::open(parent(path))?.sync_all()?;
    Ok(())
}
pub fn table<'a>(db: &'a mut Database, key: &str) -> &'a mut BTreeMap<String, Value> {
    db.entry(key.into()).or_default()
}
