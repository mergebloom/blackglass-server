use crate::{
    auth,
    model::{NewRevision, PullInfo, Revision, Vault},
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use std::{
    fs::File,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("open database {}", path.display()))?;
        secure_file(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate(&conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    fn with<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut conn = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        f(&mut conn)
    }

    pub fn ready(&self) -> bool {
        self.with(|c| {
            c.query_row("SELECT 1", [], |_| Ok(()))?;
            Ok(())
        })
        .is_ok()
    }

    pub fn issue_session(&self, ttl_secs: i64) -> Result<String> {
        let token = auth::new_token();
        let hash = auth::token_hash(&token);
        let now = now_ms();
        self.with(|c| { c.execute("DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL", [now])?; c.execute("INSERT INTO sessions(token_hash, created_at, expires_at, revoked_at) VALUES(?,?,?,NULL)", params![hash, now, now + ttl_secs * 1000])?; Ok(()) })?;
        Ok(token)
    }

    pub fn valid_session(&self, token: &str) -> bool {
        if token.len() != 64 {
            return false;
        }
        let hash = auth::token_hash(token);
        let now = now_ms();
        self.with(|c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL)", params![hash, now], |r| r.get::<_,i64>(0))? == 1)).unwrap_or(false)
    }

    pub fn revoke_session(&self, token: &str) -> Result<()> {
        let hash = auth::token_hash(token);
        self.with(|c| {
            c.execute(
                "UPDATE sessions SET revoked_at=? WHERE token_hash=?",
                params![now_ms(), hash],
            )?;
            Ok(())
        })
    }

    pub fn revoke_all_sessions(&self) -> Result<usize> {
        self.with(|c| {
            Ok(c.execute(
                "UPDATE sessions SET revoked_at=? WHERE revoked_at IS NULL",
                [now_ms()],
            )?)
        })
    }

    pub fn create_vault(&self, vault: &Vault) -> Result<()> {
        self.with(|c| { c.execute("INSERT INTO vaults(id,name,keyhash,salt,host,region,encryption_version,size,created,password,version) VALUES(?,?,?,?,?,?,?,?,?,NULL,0)", params![vault.id,vault.name,vault.keyhash,vault.salt,vault.host,vault.region,vault.encryption_version,vault.size,vault.created])?; Ok(()) })
    }
    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        self.with(|c| { let mut q=c.prepare("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created FROM vaults ORDER BY created ASC")?; Ok(q.query_map([], vault_row)?.collect::<rusqlite::Result<Vec<_>>>()?) })
    }
    pub fn find_vault(&self, id: &str) -> Result<Option<Vault>> {
        self.with(|c| Ok(c.query_row("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created FROM vaults WHERE id=?",[id],vault_row).optional()?))
    }
    pub fn rename_vault(&self, id: &str, name: &str) -> Result<bool> {
        self.with(|c| Ok(c.execute("UPDATE vaults SET name=? WHERE id=?", params![name, id])? == 1))
    }
    pub fn delete_vault(&self, id: &str) -> Result<bool> {
        self.with(|c| Ok(c.execute("DELETE FROM vaults WHERE id=?", [id])? == 1))
    }
    pub fn current_version(&self, id: &str) -> Result<i64> {
        self.with(|c| {
            Ok(
                c.query_row("SELECT version FROM vaults WHERE id=?", [id], |r| r.get(0))
                    .optional()?
                    .unwrap_or(0),
            )
        })
    }
    pub fn total_size(&self) -> Result<i64> {
        self.with(
            |c| Ok(c.query_row("SELECT COALESCE(SUM(size),0) FROM vaults", [], |r| r.get(0))?),
        )
    }
    pub fn vault_size(&self, id: &str) -> Result<i64> {
        self.with(|c| vault_size(c, id))
    }

    pub fn add_empty_revision(&self, revision: &NewRevision) -> Result<Revision> {
        self.with(|c| add_revision(c, revision, None))
    }

    pub fn add_file_revision(&self, revision: &NewRevision, file_path: &Path) -> Result<Revision> {
        self.with(|c| {
            let tx=c.transaction()?; let ts=now_ms();
            tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?)",
                params![revision.vault_id,revision.path,revision.relatedpath,revision.extension,revision.hash,revision.ctime,revision.mtime,revision.folder as i64,revision.deleted as i64,revision.size,revision.pieces,revision.device,revision.user_id,ts])?;
            let uid=tx.last_insert_rowid();
            tx.execute("INSERT INTO revision_content(uid,content) VALUES(?,zeroblob(?))",params![uid,revision.size])?;
            {
                let mut input=File::open(file_path)?;
                let mut blob=tx.blob_open("main","revision_content","content",uid,false)?;
                let copied=io::copy(&mut input,&mut blob)?;
                if copied != revision.size as u64 { bail!("staged upload changed size before commit"); }
            }
            refresh_vault(&tx,&revision.vault_id,uid)?; tx.commit()?;
            Ok(c.query_row(&format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE uid=?"),[uid],revision_row)?)
        })
    }

    pub fn pull_info(&self, uid: i64) -> Result<Option<PullInfo>> {
        self.with(|c|Ok(c.query_row("SELECT vault_id,hash,size,pieces,folder,deleted,content IS NOT NULL OR EXISTS(SELECT 1 FROM revision_content WHERE revision_content.uid=revisions.uid) FROM revisions WHERE uid=?",[uid],|r|Ok(PullInfo{vault_id:r.get(0)?,hash:r.get(1)?,size:r.get(2)?,pieces:r.get(3)?,folder:r.get::<_,i64>(4)?==1,deleted:r.get::<_,i64>(5)?==1,has_content:r.get::<_,i64>(6)?==1})).optional()?))
    }
    pub fn content_chunk(&self, uid: i64, offset: i64, length: i64) -> Result<Vec<u8>> {
        self.with(|c| {
            Ok(c.query_row(
                "SELECT COALESCE((SELECT substr(content,?,?) FROM revision_content WHERE revision_content.uid=revisions.uid),substr(content,?,?)) FROM revisions WHERE uid=?",
                params![offset + 1, length, offset + 1, length, uid],
                |r| r.get(0),
            )?)
        })
    }

    pub fn list_changes(&self, vault: &str, after: i64) -> Result<Vec<Revision>> {
        self.query_revisions(&format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE vault_id=? AND uid>? ORDER BY uid ASC"),vec![Value::Text(vault.into()),Value::Integer(after)])
    }
    pub fn initial_snapshot(&self, vault: &str) -> Result<Vec<Revision>> {
        self.query_revisions(&format!("SELECT {cols} FROM revisions r JOIN (SELECT path,MAX(uid) uid FROM revisions WHERE vault_id=? GROUP BY path) heads ON heads.uid=r.uid WHERE r.deleted=0 ORDER BY r.uid ASC",cols=prefixed_columns("r")),vec![Value::Text(vault.into())])
    }
    pub fn list_deleted(&self, vault: &str, suppress: bool) -> Result<Vec<Revision>> {
        self.query_revisions(&format!("SELECT {cols} FROM revisions r JOIN (SELECT path,MAX(uid) uid FROM revisions WHERE vault_id=? GROUP BY path) heads ON heads.uid=r.uid WHERE r.deleted=1 AND (?=0 OR NOT EXISTS (SELECT 1 FROM revisions live JOIN (SELECT path,MAX(uid) uid FROM revisions WHERE vault_id=r.vault_id GROUP BY path) live_heads ON live_heads.uid=live.uid WHERE live.deleted=0 AND live.relatedpath=r.path)) ORDER BY r.uid ASC",cols=prefixed_columns("r")),vec![Value::Text(vault.into()),Value::Integer(suppress as i64)])
    }
    pub fn history(
        &self,
        vault: &str,
        path: &str,
        last: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Revision>> {
        self.query_revisions(&format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE vault_id=? AND path=? AND (? IS NULL OR uid<?) ORDER BY uid DESC LIMIT ?"),vec![Value::Text(vault.into()),Value::Text(path.into()),last.map(Value::Integer).unwrap_or(Value::Null),last.map(Value::Integer).unwrap_or(Value::Null),Value::Integer(limit)])
    }

    fn query_revisions(&self, sql: &str, values: Vec<Value>) -> Result<Vec<Revision>> {
        self.with(|c| {
            let mut q = c.prepare(sql)?;
            Ok(
                q.query_map(rusqlite::params_from_iter(values), revision_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            )
        })
    }

    pub fn restore(&self, vault: &str, uid: i64, device: &str) -> Result<Option<Revision>> {
        self.with(|c|{
        let tx=c.transaction()?;
        let target:Option<(String,bool)>=tx.query_row("SELECT path,deleted FROM revisions WHERE uid=? AND vault_id=?",params![uid,vault],|r|Ok((r.get(0)?,r.get::<_,i64>(1)?==1))).optional()?;
        let Some((path,deleted))=target else{return Ok(None)};
        let source_uid=if deleted {tx.query_row("SELECT uid FROM revisions WHERE vault_id=? AND path=? AND uid<? AND deleted=0 ORDER BY uid DESC LIMIT 1",params![vault,path,uid],|r|r.get(0)).optional()?}else{Some(uid)};
        let Some(source_uid)=source_uid else{return Ok(None)}; let ts=now_ms();
        tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) SELECT vault_id,?,NULL,extension,hash,ctime,mtime,folder,0,size,pieces,NULL,?,1,? FROM revisions WHERE uid=?",params![path,device,ts,source_uid])?;
        let new_uid=tx.last_insert_rowid();
        let source_size:i64=tx.query_row("SELECT size FROM revisions WHERE uid=?",[source_uid],|r|r.get(0))?;
        if source_size>0 {
            tx.execute("INSERT INTO revision_content(uid,content) VALUES(?,zeroblob(?))",params![new_uid,source_size])?;
            let external=tx.query_row("SELECT EXISTS(SELECT 1 FROM revision_content WHERE uid=?)",[source_uid],|r|Ok(r.get::<_,i64>(0)?==1))?;
            let mut source=tx.blob_open("main",if external{"revision_content"}else{"revisions"},"content",source_uid,true)?;
            let mut destination=tx.blob_open("main","revision_content","content",new_uid,false)?;
            let copied=io::copy(&mut source,&mut destination)?;
            if copied!=source_size as u64 { bail!("restored content size changed during copy"); }
        }
        refresh_vault(&tx,vault,new_uid)?; tx.commit()?;
        Ok(Some(c.query_row(&format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE uid=?"),[new_uid],revision_row)?))
    })
    }

    pub fn purge(&self, vault: &str) -> Result<()> {
        self.with(|c|{let tx=c.transaction()?;tx.execute("DELETE FROM revisions WHERE vault_id=? AND uid NOT IN (SELECT r.uid FROM revisions r JOIN (SELECT path,MAX(uid) uid FROM revisions WHERE vault_id=? GROUP BY path) heads ON heads.uid=r.uid WHERE r.deleted=0)",params![vault,vault])?;let version: i64=tx.query_row("SELECT version FROM vaults WHERE id=?",[vault],|r|r.get(0))?;refresh_vault(&tx,vault,version)?;tx.commit()?;Ok(())})
    }
    pub fn checkpoint(&self) -> Result<()> {
        self.with(|c| {
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })
    }
}

const REVISION_COLUMNS: &str = "uid,vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,device,user_id,ts";
fn prefixed_columns(p: &str) -> String {
    REVISION_COLUMNS
        .split(',')
        .map(|c| format!("{p}.{c}"))
        .collect::<Vec<_>>()
        .join(",")
}
fn vault_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Vault> {
    Ok(Vault {
        id: r.get(0)?,
        name: r.get(1)?,
        keyhash: r.get(2)?,
        salt: r.get(3)?,
        host: r.get(4)?,
        region: r.get(5)?,
        encryption_version: r.get(6)?,
        size: r.get(7)?,
        created: r.get(8)?,
    })
}
fn revision_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Revision> {
    Ok(Revision {
        uid: r.get(0)?,
        vault_id: r.get(1)?,
        path: r.get(2)?,
        relatedpath: r.get(3)?,
        extension: r.get(4)?,
        hash: r.get(5)?,
        ctime: r.get(6)?,
        mtime: r.get(7)?,
        folder: r.get::<_, i64>(8)? == 1,
        deleted: r.get::<_, i64>(9)? == 1,
        size: r.get(10)?,
        _pieces: r.get(11)?,
        device: r.get(12)?,
        user_id: r.get(13)?,
        ts: r.get(14)?,
    })
}
fn vault_size(c: &Connection, id: &str) -> Result<i64> {
    Ok(c.query_row("SELECT COALESCE(SUM(size),0) FROM revisions WHERE uid IN (SELECT MAX(uid) FROM revisions WHERE vault_id=? GROUP BY path) AND deleted=0 AND folder=0",[id],|r|r.get(0))?)
}
fn refresh_vault(c: &Connection, vault: &str, version: i64) -> Result<()> {
    let size = vault_size(c, vault)?;
    c.execute(
        "UPDATE vaults SET size=?,version=? WHERE id=?",
        params![size, version, vault],
    )?;
    Ok(())
}
fn add_revision(c: &mut Connection, r: &NewRevision, content: Option<&[u8]>) -> Result<Revision> {
    let tx = c.transaction()?;
    let ts = now_ms();
    tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![r.vault_id,r.path,r.relatedpath,r.extension,r.hash,r.ctime,r.mtime,r.folder as i64,r.deleted as i64,r.size,r.pieces,content,r.device,r.user_id,ts])?;
    let uid = tx.last_insert_rowid();
    refresh_vault(&tx, &r.vault_id, uid)?;
    tx.commit()?;
    Ok(c.query_row(
        &format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE uid=?"),
        [uid],
        revision_row,
    )?)
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn migrate(c: &Connection) -> Result<()> {
    c.execute_batch("BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY,name TEXT NOT NULL,keyhash TEXT,salt TEXT,host TEXT NOT NULL,region TEXT NOT NULL,encryption_version INTEGER NOT NULL,size INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,password TEXT,version INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS revisions(uid INTEGER PRIMARY KEY AUTOINCREMENT,vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,path TEXT NOT NULL,relatedpath TEXT,extension TEXT NOT NULL,hash TEXT NOT NULL,ctime INTEGER NOT NULL,mtime INTEGER NOT NULL,folder INTEGER NOT NULL,deleted INTEGER NOT NULL,size INTEGER NOT NULL,pieces INTEGER NOT NULL,content BLOB,device TEXT NOT NULL,user_id INTEGER NOT NULL,ts INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS revision_content(uid INTEGER PRIMARY KEY REFERENCES revisions(uid) ON DELETE CASCADE,content BLOB NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER);
      CREATE INDEX IF NOT EXISTS revisions_vault_uid ON revisions(vault_id,uid);
      CREATE INDEX IF NOT EXISTS revisions_vault_path ON revisions(vault_id,path,uid);
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
      INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,unixepoch()*1000);
      INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,unixepoch()*1000);
      UPDATE revisions SET ts=CASE WHEN mtime>0 THEN mtime ELSE unixepoch()*1000 END WHERE ts=0;
      UPDATE vaults SET version=COALESCE((SELECT MAX(uid) FROM revisions WHERE vault_id=vaults.id),version,0) WHERE version=0;
      COMMIT;")?;
    Ok(())
}

pub fn backup_database(source: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        bail!("backup destination already exists: {}", output.display())
    }
    let src = Connection::open(source)?;
    let mut dst = Connection::open(output)?;
    secure_file(output)?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
    backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
    drop(backup);
    set_portable_journal(&dst)?;
    verify_connection(&dst)
}
pub fn verify_database(path: &Path) -> Result<()> {
    let c = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    verify_connection(&c)
}
fn verify_connection(c: &Connection) -> Result<()> {
    let result: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if result != "ok" {
        bail!("SQLite integrity_check failed: {result}")
    }
    Ok(())
}
pub fn restore_database(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!(
            "restore destination already exists: {}",
            destination.display()
        )
    }
    verify_database(source)?;
    let src = Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut dst = Connection::open(destination)?;
    secure_file(destination)?;
    let backup = rusqlite::backup::Backup::new(&src, &mut dst)?;
    backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
    drop(backup);
    set_portable_journal(&dst)?;
    verify_connection(&dst)
}

fn set_portable_journal(c: &Connection) -> Result<()> {
    let mode: String = c.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        bail!("failed to set portable SQLite journal mode: {mode}")
    }
    Ok(())
}

pub fn revoke_all_sessions(path: &Path) -> Result<usize> {
    Db::open(path)?.revoke_all_sessions()
}

fn secure_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Vault;
    #[test]
    fn sessions_revisions_and_backup_restore_survive_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("primary.sqlite");
        let db = Db::open(&primary).unwrap();
        let token = db.issue_session(60).unwrap();
        assert!(db.valid_session(&token));
        db.revoke_session(&token).unwrap();
        assert!(!db.valid_session(&token));
        let expired = db.issue_session(-1).unwrap();
        assert!(!db.valid_session(&expired));
        let active = db.issue_session(60).unwrap();
        assert_eq!(db.revoke_all_sessions().unwrap(), 1);
        assert!(!db.valid_session(&active));
        let vault = Vault {
            id: "v1".into(),
            name: "Vault".into(),
            keyhash: Some("key".into()),
            salt: Some("salt".into()),
            host: "localhost:3003".into(),
            region: "Blackglass Server".into(),
            encryption_version: 3,
            size: 0,
            created: 1,
        };
        db.create_vault(&vault).unwrap();
        let rev = NewRevision {
            vault_id: "v1".into(),
            path: "opaque".into(),
            relatedpath: None,
            extension: "md".into(),
            hash: "hash".into(),
            ctime: 1,
            mtime: 2,
            folder: false,
            deleted: false,
            size: 0,
            pieces: 0,
            device: "test".into(),
            user_id: 1,
        };
        let stored = db.add_empty_revision(&rev).unwrap();
        assert_eq!(stored.uid, 1);
        assert_eq!(db.current_version("v1").unwrap(), 1);
        db.checkpoint().unwrap();
        let backup = dir.path().join("backup.sqlite");
        backup_database(&primary, &backup).unwrap();
        verify_database(&backup).unwrap();
        assert!(!dir.path().join("backup.sqlite-wal").exists());
        assert!(!dir.path().join("backup.sqlite-shm").exists());
        let restored = dir.path().join("restored.sqlite");
        restore_database(&backup, &restored).unwrap();
        assert!(!dir.path().join("restored.sqlite-wal").exists());
        assert!(!dir.path().join("restored.sqlite-shm").exists());
        let copy = Db::open(&restored).unwrap();
        assert_eq!(copy.list_vaults().unwrap().len(), 1);
        assert_eq!(copy.current_version("v1").unwrap(), 1);
    }
}
