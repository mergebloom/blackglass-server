use crate::{
    auth,
    model::{NewRevision, PullInfo, Revision, Vault},
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const CURRENT_SCHEMA_VERSION: i64 = 2;
const SUPPORTED_MIGRATIONS: &[i64] = &[1, 2];

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let existed = match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    bail!("server database is not a regular file: {}", path.display())
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect server database: {}", path.display()));
            }
        };

        if !existed {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            for sidecar in sqlite_sidecars(path) {
                if path_entry_exists(&sidecar)? {
                    bail!(
                        "server database sidecar exists without its database: {}",
                        sidecar.display()
                    )
                }
            }
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(path)
                .with_context(|| format!("create server database: {}", path.display()))?;
        }

        let result = (|| {
            let conn = open_existing_read_write(path, "server database")?;
            if existed {
                if !table_exists(&conn, "schema_migrations")? {
                    bail!(
                        "existing database has no Blackglass migration metadata; use `blackglass-server migrate-legacy <source> <new-database>`"
                    )
                }
                // Validate every byte-level and logical contract before chmod,
                // journal changes, or migrations can modify an existing file.
                verify_connection(&conn).context("existing server database validation failed")?;
            }
            secure_file(path)?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            // A successful Sync acknowledgement is a durability promise. FULL
            // makes a WAL commit survive an operating-system crash or power loss.
            conn.pragma_update(None, "synchronous", "FULL")?;
            conn.busy_timeout(std::time::Duration::from_secs(5))?;
            if !existed {
                migrate(&conn)?;
            }
            verify_connection(&conn)?;
            Ok(Self(Arc::new(Mutex::new(conn))))
        })();

        if result.is_err() && !existed {
            let _ = remove_database_files(path);
        }
        result
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
        self.valid_session_hash(&auth::token_hash(token))
    }

    pub fn valid_session_hash(&self, hash: &str) -> bool {
        if hash.len() != 64 {
            return false;
        }
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
        self.with(|c| { c.execute("INSERT INTO vaults(id,name,keyhash,salt,host,region,encryption_version,size,created,password,version) VALUES(?,?,?,?,?,?,?,?,?,?,0)", params![vault.id,vault.name,vault.keyhash,vault.salt,vault.host,vault.region,vault.encryption_version,vault.size,vault.created,vault.password])?; Ok(()) })
    }
    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        self.with(|c| { let mut q=c.prepare("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password FROM vaults ORDER BY created ASC")?; Ok(q.query_map([], vault_row)?.collect::<rusqlite::Result<Vec<_>>>()?) })
    }
    pub fn find_vault(&self, id: &str) -> Result<Option<Vault>> {
        self.with(|c| Ok(c.query_row("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password FROM vaults WHERE id=?",[id],vault_row).optional()?))
    }
    pub fn bind_managed_keyhash(&self, id: &str, keyhash: &str) -> Result<Option<String>> {
        self.with(|c| {
            c.execute(
                "UPDATE vaults SET keyhash=? WHERE id=? AND password IS NOT NULL AND keyhash IS NULL",
                params![keyhash, id],
            )?;
            Ok(c.query_row("SELECT keyhash FROM vaults WHERE id=?", [id], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten())
        })
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
        if revision.size != 0 || revision.pieces != 0 {
            bail!("metadata-only revision must have zero size and pieces")
        }
        self.with(|c| add_revision(c, revision, None))
    }

    pub fn add_file_revision(&self, revision: &NewRevision, file_path: &Path) -> Result<Revision> {
        if revision.folder
            || revision.deleted
            || revision.size <= 0
            || revision.pieces != (revision.size + REVISION_PIECE_SIZE - 1) / REVISION_PIECE_SIZE
        {
            bail!("file revision metadata is inconsistent")
        }
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

    pub fn list_changes_page(
        &self,
        vault: &str,
        after: i64,
        through: i64,
        limit: i64,
    ) -> Result<Vec<Revision>> {
        self.query_revisions(
            &format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE vault_id=? AND uid>? AND uid<=? ORDER BY uid ASC LIMIT ?"),
            vec![
                Value::Text(vault.into()),
                Value::Integer(after),
                Value::Integer(through),
                Value::Integer(limit.clamp(1, 1024)),
            ],
        )
    }
    pub fn initial_snapshot_page(
        &self,
        vault: &str,
        after: i64,
        through: i64,
        limit: i64,
    ) -> Result<Vec<Revision>> {
        self.query_revisions(
            &format!("SELECT {cols} FROM revisions r JOIN (SELECT path,MAX(uid) uid FROM revisions WHERE vault_id=? AND uid<=? GROUP BY path) heads ON heads.uid=r.uid WHERE r.deleted=0 AND r.uid>? ORDER BY r.uid ASC LIMIT ?",cols=prefixed_columns("r")),
            vec![
                Value::Text(vault.into()),
                Value::Integer(through),
                Value::Integer(after),
                Value::Integer(limit.clamp(1, 1024)),
            ],
        )
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
        password: r.get(9)?,
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

fn validate_migration_history_for_upgrade(c: &Connection) -> Result<()> {
    if !table_exists(c, "schema_migrations")? {
        return Ok(());
    }

    let versions = migration_versions(c)?;
    reject_newer_migrations(&versions)?;
    if !SUPPORTED_MIGRATIONS.starts_with(&versions) {
        bail!(
            "unsupported Blackglass migration history: expected a prefix of {:?}, found {:?}",
            SUPPORTED_MIGRATIONS,
            versions
        )
    }
    Ok(())
}

pub fn backup_database(source: &Path, output: &Path) -> Result<()> {
    let src = open_existing_read_only(source, "backup source")?;
    verify_connection(&src).context("backup source validation failed")?;
    copy_database(&src, output, "backup destination")
}

pub fn verify_database(path: &Path) -> Result<()> {
    let c = open_existing_read_only(path, "database")?;
    verify_connection(&c)
}

fn verify_connection(c: &Connection) -> Result<()> {
    verify_sqlite_integrity(c)?;
    if table_exists(c, "schema_migrations")? {
        verify_migration_history(c)?;
    }
    verify_blackglass_schema(c)?;
    verify_foreign_keys(c)?;
    verify_logical_invariants(c, true)?;
    Ok(())
}

fn verify_sqlite_integrity(c: &Connection) -> Result<()> {
    let mut integrity = c
        .prepare("PRAGMA integrity_check")
        .context("prepare SQLite integrity_check")?;
    let results = integrity
        .query_map([], |row| row.get::<_, String>(0))
        .context("run SQLite integrity_check")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("read SQLite integrity_check results")?;
    if results.as_slice() != ["ok"] {
        bail!("SQLite integrity_check failed: {}", results.join("; "))
    }
    Ok(())
}

pub fn restore_database(source: &Path, destination: &Path) -> Result<()> {
    let src = open_existing_read_only(source, "restore source")?;
    verify_connection(&src).context("restore source validation failed")?;
    copy_database(&src, destination, "restore destination")
}

fn copy_database(source: &Connection, destination: &Path, label: &str) -> Result<()> {
    with_new_database(destination, label, |dst| {
        run_online_backup(source, dst)?;
        set_portable_journal(dst)?;
        verify_connection(dst)
    })
}

pub fn migrate_legacy_database(source: &Path, destination: &Path) -> Result<()> {
    let source = open_existing_read_only(source, "legacy migration source")?;
    verify_legacy_connection(&source).context("legacy migration source validation failed")?;

    with_new_database(destination, "legacy migration destination", |target| {
        run_online_backup(&source, target)?;
        verify_legacy_connection(target).context("copied legacy database validation failed")?;
        validate_migration_history_for_upgrade(target)?;
        target.pragma_update(None, "foreign_keys", "ON")?;
        migrate(target)?;
        set_portable_journal(target)?;
        verify_connection(target)
    })
}

fn run_online_backup(source: &Connection, destination: &mut Connection) -> Result<()> {
    let backup = rusqlite::backup::Backup::new(source, destination)?;
    backup.run_to_completion(128, std::time::Duration::from_millis(10), None)?;
    drop(backup);
    Ok(())
}

fn open_existing_read_only(path: &Path, label: &str) -> Result<Connection> {
    let resolved = resolve_existing_regular_file(path, label)?;
    let connection = Connection::open_with_flags(
        resolved,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .with_context(|| format!("open {label} read-only: {}", path.display()))?;
    configure_connection_safety(&connection)?;
    Ok(connection)
}

fn open_existing_read_write(path: &Path, label: &str) -> Result<Connection> {
    let resolved = resolve_existing_regular_file(path, label)?;
    let connection = Connection::open_with_flags(
        resolved,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .with_context(|| format!("open {label} read-write: {}", path.display()))?;
    configure_connection_safety(&connection)?;
    Ok(connection)
}

fn configure_connection_safety(connection: &Connection) -> Result<()> {
    connection.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

fn resolve_existing_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| {
        format!(
            "{label} must be an existing regular file: {}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        bail!("{label} is not a regular file: {}", path.display())
    }
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("resolve {label}: {}", path.display()))?;
    let resolved_metadata = std::fs::symlink_metadata(&resolved)
        .with_context(|| format!("inspect resolved {label}: {}", resolved.display()))?;
    if !resolved_metadata.is_file() {
        bail!(
            "resolved {label} is not a regular file: {}",
            resolved.display()
        )
    }
    Ok(resolved)
}

fn with_new_database(
    path: &Path,
    label: &str,
    operation: impl FnOnce(&mut Connection) -> Result<()>,
) -> Result<()> {
    let sidecars = sqlite_sidecars(path);
    for sidecar in &sidecars {
        if path_entry_exists(sidecar)
            .with_context(|| format!("inspect {label} sidecar: {}", sidecar.display()))?
        {
            bail!(
                "{label} sidecar already exists; refusing to overwrite it: {}",
                sidecar.display()
            )
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create new {label}: {}", path.display()))?;

    let result = (|| {
        secure_file(path)?;
        let mut connection = open_existing_read_write(path, label)?;
        operation(&mut connection)?;
        drop(connection);
        for sidecar in &sidecars {
            if path_entry_exists(sidecar)
                .with_context(|| format!("inspect completed {label}: {}", sidecar.display()))?
            {
                bail!(
                    "completed {label} retained a SQLite sidecar: {}",
                    sidecar.display()
                )
            }
        }
        Ok(())
    })();

    if let Err(error) = result {
        if let Err(cleanup_error) = remove_database_files(path) {
            return Err(error.context(format!(
                "also failed to remove incomplete {label}: {cleanup_error:#}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

fn set_portable_journal(c: &Connection) -> Result<()> {
    let mode: String = c.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        bail!("failed to set portable SQLite journal mode: {mode}")
    }
    Ok(())
}

pub fn revoke_all_sessions(path: &Path) -> Result<usize> {
    let connection = open_existing_read_write(path, "session database")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    verify_connection(&connection).context("session database validation failed")?;
    Db(Arc::new(Mutex::new(connection))).revoke_all_sessions()
}

fn verify_blackglass_schema(c: &Connection) -> Result<()> {
    verify_schema_objects(
        c,
        &[
            ("index", "revisions_vault_path", "revisions"),
            ("index", "revisions_vault_uid", "revisions"),
            ("index", "sessions_expiry", "sessions"),
            ("index", "sqlite_autoindex_sessions_1", "sessions"),
            ("index", "sqlite_autoindex_vaults_1", "vaults"),
            ("table", "revision_content", "revision_content"),
            ("table", "revisions", "revisions"),
            ("table", "schema_migrations", "schema_migrations"),
            ("table", "sessions", "sessions"),
            ("table", "sqlite_sequence", "sqlite_sequence"),
            ("table", "vaults", "vaults"),
        ],
        "Blackglass",
    )?;
    verify_exact_table(
        c,
        "schema_migrations",
        SCHEMA_MIGRATION_COLUMNS,
        "Blackglass",
    )?;
    verify_exact_table(c, "vaults", VAULT_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "revisions", REVISION_TABLE_COLUMNS, "Blackglass")?;
    verify_exact_table(
        c,
        "revision_content",
        REVISION_CONTENT_COLUMNS,
        "Blackglass",
    )?;
    verify_exact_table(c, "sessions", SESSION_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "sqlite_sequence", SQLITE_SEQUENCE_COLUMNS, "Blackglass")?;

    verify_exact_indexes(c, "schema_migrations", &[], "Blackglass")?;
    verify_exact_indexes(
        c,
        "vaults",
        &[IndexExpectation::primary_key(
            "sqlite_autoindex_vaults_1",
            &["id"],
        )],
        "Blackglass",
    )?;
    verify_exact_indexes(
        c,
        "revisions",
        &[
            IndexExpectation::ordinary("revisions_vault_path", &["vault_id", "path", "uid"]),
            IndexExpectation::ordinary("revisions_vault_uid", &["vault_id", "uid"]),
        ],
        "Blackglass",
    )?;
    verify_exact_indexes(c, "revision_content", &[], "Blackglass")?;
    verify_exact_indexes(
        c,
        "sessions",
        &[
            IndexExpectation::ordinary("sessions_expiry", &["expires_at"]),
            IndexExpectation::primary_key("sqlite_autoindex_sessions_1", &["token_hash"]),
        ],
        "Blackglass",
    )?;
    verify_exact_indexes(c, "sqlite_sequence", &[], "Blackglass")?;

    verify_exact_foreign_keys(c, "schema_migrations", &[], "Blackglass")?;
    verify_exact_foreign_keys(c, "vaults", &[], "Blackglass")?;
    verify_exact_foreign_keys(
        c,
        "revisions",
        &[ForeignKeyExpectation::cascade("vaults", "vault_id", "id")],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(
        c,
        "revision_content",
        &[ForeignKeyExpectation::cascade("revisions", "uid", "uid")],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(c, "sessions", &[], "Blackglass")?;
    verify_exact_foreign_keys(c, "sqlite_sequence", &[], "Blackglass")?;
    Ok(())
}

fn verify_legacy_connection(c: &Connection) -> Result<()> {
    verify_sqlite_integrity(c)?;
    if table_exists(c, "schema_migrations")? {
        let versions = migration_versions(c)?;
        reject_newer_migrations(&versions)?;
        bail!(
            "legacy migration source already has Blackglass migration metadata; use backup and restore"
        )
    }

    verify_schema_objects(
        c,
        &[
            ("index", "revisions_vault_path", "revisions"),
            ("index", "revisions_vault_uid", "revisions"),
            ("index", "sqlite_autoindex_vaults_1", "vaults"),
            ("table", "revisions", "revisions"),
            ("table", "sqlite_sequence", "sqlite_sequence"),
            ("table", "vaults", "vaults"),
        ],
        "legacy Blackglass",
    )?;
    verify_exact_table(c, "vaults", VAULT_COLUMNS, "legacy Blackglass")?;
    verify_exact_table(c, "revisions", REVISION_TABLE_COLUMNS, "legacy Blackglass")?;
    verify_exact_table(
        c,
        "sqlite_sequence",
        SQLITE_SEQUENCE_COLUMNS,
        "legacy Blackglass",
    )?;
    verify_exact_indexes(
        c,
        "vaults",
        &[IndexExpectation::primary_key(
            "sqlite_autoindex_vaults_1",
            &["id"],
        )],
        "legacy Blackglass",
    )?;
    verify_exact_indexes(
        c,
        "revisions",
        &[
            IndexExpectation::ordinary("revisions_vault_path", &["vault_id", "path", "uid"]),
            IndexExpectation::ordinary("revisions_vault_uid", &["vault_id", "uid"]),
        ],
        "legacy Blackglass",
    )?;
    verify_exact_indexes(c, "sqlite_sequence", &[], "legacy Blackglass")?;
    verify_exact_foreign_keys(c, "vaults", &[], "legacy Blackglass")?;
    verify_exact_foreign_keys(
        c,
        "revisions",
        &[ForeignKeyExpectation::cascade("vaults", "vault_id", "id")],
        "legacy Blackglass",
    )?;
    verify_exact_foreign_keys(c, "sqlite_sequence", &[], "legacy Blackglass")?;
    verify_foreign_keys(c)?;
    verify_logical_invariants(c, false)
}

fn table_exists(c: &Connection, table: &str) -> Result<bool> {
    Ok(c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
        [table],
        |row| row.get::<_, i64>(0),
    )? == 1)
}

type ExpectedColumn = (&'static str, &'static str, bool, Option<&'static str>, i64);

const SCHEMA_MIGRATION_COLUMNS: &[ExpectedColumn] = &[
    ("version", "INTEGER", false, None, 1),
    ("applied_at", "INTEGER", true, None, 0),
];
const VAULT_COLUMNS: &[ExpectedColumn] = &[
    ("id", "TEXT", false, None, 1),
    ("name", "TEXT", true, None, 0),
    ("keyhash", "TEXT", false, None, 0),
    ("salt", "TEXT", false, None, 0),
    ("host", "TEXT", true, None, 0),
    ("region", "TEXT", true, None, 0),
    ("encryption_version", "INTEGER", true, None, 0),
    ("size", "INTEGER", true, Some("0"), 0),
    ("created", "INTEGER", true, None, 0),
    ("password", "TEXT", false, None, 0),
    ("version", "INTEGER", true, Some("0"), 0),
];
const REVISION_TABLE_COLUMNS: &[ExpectedColumn] = &[
    ("uid", "INTEGER", false, None, 1),
    ("vault_id", "TEXT", true, None, 0),
    ("path", "TEXT", true, None, 0),
    ("relatedpath", "TEXT", false, None, 0),
    ("extension", "TEXT", true, None, 0),
    ("hash", "TEXT", true, None, 0),
    ("ctime", "INTEGER", true, None, 0),
    ("mtime", "INTEGER", true, None, 0),
    ("folder", "INTEGER", true, None, 0),
    ("deleted", "INTEGER", true, None, 0),
    ("size", "INTEGER", true, None, 0),
    ("pieces", "INTEGER", true, None, 0),
    ("content", "BLOB", false, None, 0),
    ("device", "TEXT", true, None, 0),
    ("user_id", "INTEGER", true, None, 0),
    ("ts", "INTEGER", true, Some("0"), 0),
];
const REVISION_CONTENT_COLUMNS: &[ExpectedColumn] = &[
    ("uid", "INTEGER", false, None, 1),
    ("content", "BLOB", true, None, 0),
];
const SESSION_COLUMNS: &[ExpectedColumn] = &[
    ("token_hash", "TEXT", false, None, 1),
    ("created_at", "INTEGER", true, None, 0),
    ("expires_at", "INTEGER", true, None, 0),
    ("revoked_at", "INTEGER", false, None, 0),
];
const SQLITE_SEQUENCE_COLUMNS: &[ExpectedColumn] =
    &[("name", "", false, None, 0), ("seq", "", false, None, 0)];

#[derive(Debug, PartialEq, Eq)]
struct ColumnDefinition {
    name: String,
    declared_type: String,
    not_null: bool,
    default_value: Option<String>,
    primary_key: i64,
    hidden: i64,
}

fn verify_schema_objects(
    c: &Connection,
    expected: &[(&str, &str, &str)],
    label: &str,
) -> Result<()> {
    let mut query = c.prepare("SELECT type,name,tbl_name FROM sqlite_schema ORDER BY type,name")?;
    let actual = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .map(|(kind, name, table)| ((*kind).to_owned(), (*name).to_owned(), (*table).to_owned()))
        .collect::<Vec<_>>();
    if actual != expected {
        bail!("unexpected {label} schema objects: expected {expected:?}, found {actual:?}")
    }
    Ok(())
}

fn verify_exact_table(
    c: &Connection,
    table: &str,
    expected: &[ExpectedColumn],
    label: &str,
) -> Result<()> {
    if !table_exists(c, table)? {
        bail!("not a {label} database: missing required table {table}")
    }
    // table_xinfo also exposes generated and hidden columns. table_info would
    // silently omit those and let a schema with extra columns pass verification.
    let sql = format!("PRAGMA table_xinfo(\"{table}\")");
    let mut query = c.prepare(&sql)?;
    let actual = query
        .query_map([], |row| {
            Ok(ColumnDefinition {
                name: row.get(1)?,
                declared_type: row.get(2)?,
                not_null: row.get::<_, i64>(3)? == 1,
                default_value: row.get(4)?,
                primary_key: row.get(5)?,
                hidden: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if actual.len() != expected.len() {
        bail!(
            "invalid {label} table {table}: expected {} columns, found {} ({actual:?})",
            expected.len(),
            actual.len()
        )
    }
    for (position, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        let expected_definition = ColumnDefinition {
            name: expected.0.to_owned(),
            declared_type: expected.1.to_owned(),
            not_null: expected.2,
            default_value: expected.3.map(str::to_owned),
            primary_key: expected.4,
            hidden: 0,
        };
        if *actual != expected_definition {
            bail!(
                "invalid {label} table {table} column {position}: expected {expected_definition:?}, found {actual:?}"
            )
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct IndexExpectation {
    name: &'static str,
    unique: bool,
    origin: &'static str,
    partial: bool,
    columns: &'static [&'static str],
}

impl IndexExpectation {
    const fn ordinary(name: &'static str, columns: &'static [&'static str]) -> Self {
        Self {
            name,
            unique: false,
            origin: "c",
            partial: false,
            columns,
        }
    }

    const fn primary_key(name: &'static str, columns: &'static [&'static str]) -> Self {
        Self {
            name,
            unique: true,
            origin: "pk",
            partial: false,
            columns,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct IndexDefinition {
    name: String,
    unique: bool,
    origin: String,
    partial: bool,
    columns: Vec<IndexColumnDefinition>,
}

#[derive(Debug, PartialEq, Eq)]
struct IndexColumnDefinition {
    name: Option<String>,
    descending: bool,
    collation: String,
}

fn verify_exact_indexes(
    c: &Connection,
    table: &str,
    expected: &[IndexExpectation],
    label: &str,
) -> Result<()> {
    let sql = format!("PRAGMA index_list(\"{table}\")");
    let mut query = c.prepare(&sql)?;
    let mut metadata = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? == 1,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)? == 1,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    metadata.sort_by(|left, right| left.0.cmp(&right.0));
    drop(query);

    let mut actual = Vec::with_capacity(metadata.len());
    for (name, unique, origin, partial) in metadata {
        let escaped = name.replace('"', "\"\"");
        let mut columns = c.prepare(&format!("PRAGMA index_xinfo(\"{escaped}\")"))?;
        let columns = columns
            .query_map([], |row| {
                Ok((
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)? == 1,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)? == 1,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter(|(_, _, _, key)| *key)
            .map(|(name, descending, collation, _)| IndexColumnDefinition {
                name,
                descending,
                collation,
            })
            .collect();
        actual.push(IndexDefinition {
            name,
            unique,
            origin,
            partial,
            columns,
        });
    }

    let mut expected = expected
        .iter()
        .map(|index| IndexDefinition {
            name: index.name.to_owned(),
            unique: index.unique,
            origin: index.origin.to_owned(),
            partial: index.partial,
            columns: index
                .columns
                .iter()
                .map(|column| IndexColumnDefinition {
                    name: Some((*column).to_owned()),
                    descending: false,
                    collation: "BINARY".to_owned(),
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    expected.sort_by(|left, right| left.name.cmp(&right.name));
    if actual != expected {
        bail!("invalid {label} indexes for {table}: expected {expected:?}, found {actual:?}")
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ForeignKeyExpectation {
    parent: &'static str,
    from: &'static str,
    to: &'static str,
    on_update: &'static str,
    on_delete: &'static str,
    match_clause: &'static str,
}

impl ForeignKeyExpectation {
    const fn cascade(parent: &'static str, from: &'static str, to: &'static str) -> Self {
        Self {
            parent,
            from,
            to,
            on_update: "NO ACTION",
            on_delete: "CASCADE",
            match_clause: "NONE",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ForeignKeyDefinition {
    id: i64,
    sequence: i64,
    parent: String,
    from: String,
    to: String,
    on_update: String,
    on_delete: String,
    match_clause: String,
}

fn verify_exact_foreign_keys(
    c: &Connection,
    table: &str,
    expected: &[ForeignKeyExpectation],
    label: &str,
) -> Result<()> {
    let sql = format!("PRAGMA foreign_key_list(\"{table}\")");
    let mut query = c.prepare(&sql)?;
    let actual = query
        .query_map([], |row| {
            Ok(ForeignKeyDefinition {
                id: row.get(0)?,
                sequence: row.get(1)?,
                parent: row.get(2)?,
                from: row.get(3)?,
                to: row.get(4)?,
                on_update: row.get(5)?,
                on_delete: row.get(6)?,
                match_clause: row.get(7)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .enumerate()
        .map(|(id, foreign_key)| ForeignKeyDefinition {
            id: id as i64,
            sequence: 0,
            parent: foreign_key.parent.to_owned(),
            from: foreign_key.from.to_owned(),
            to: foreign_key.to.to_owned(),
            on_update: foreign_key.on_update.to_owned(),
            on_delete: foreign_key.on_delete.to_owned(),
            match_clause: foreign_key.match_clause.to_owned(),
        })
        .collect::<Vec<_>>();
    if actual != expected {
        bail!("invalid {label} foreign keys for {table}: expected {expected:?}, found {actual:?}")
    }
    Ok(())
}

fn verify_logical_invariants(c: &Connection, external_content: bool) -> Result<()> {
    reject_invalid_row(
        c,
        "SELECT id FROM vaults WHERE
            typeof(id) <> 'text' OR length(id) = 0 OR
            typeof(name) <> 'text' OR length(name) = 0 OR
            (keyhash IS NOT NULL AND typeof(keyhash) <> 'text') OR
            (salt IS NOT NULL AND typeof(salt) <> 'text') OR
            typeof(host) <> 'text' OR length(host) = 0 OR
            typeof(region) <> 'text' OR length(region) = 0 OR
            typeof(encryption_version) <> 'integer' OR encryption_version NOT BETWEEN 0 AND 3 OR
            typeof(size) <> 'integer' OR size < 0 OR
            typeof(created) <> 'integer' OR created < 0 OR
            (password IS NOT NULL AND typeof(password) <> 'text') OR
            typeof(version) <> 'integer' OR version < 0
         LIMIT 1",
        "vault field types and ranges",
    )?;
    let revision_metadata = format!(
        "SELECT CAST(uid AS TEXT) FROM revisions WHERE
            typeof(uid) <> 'integer' OR uid <= 0 OR
            typeof(vault_id) <> 'text' OR length(vault_id) = 0 OR
            typeof(path) <> 'text' OR length(path) = 0 OR
            (relatedpath IS NOT NULL AND typeof(relatedpath) <> 'text') OR
            typeof(extension) <> 'text' OR
            typeof(hash) <> 'text' OR
            typeof(ctime) <> 'integer' OR typeof(mtime) <> 'integer' OR
            typeof(folder) <> 'integer' OR folder NOT IN (0,1) OR
            typeof(deleted) <> 'integer' OR deleted NOT IN (0,1) OR
            typeof(size) <> 'integer' OR size < 0 OR
            typeof(pieces) <> 'integer' OR pieces < 0 OR
            pieces <> CASE WHEN size=0 THEN 0 ELSE (size + {overhead}) / {piece_size} END OR
            ((folder=1 OR deleted=1) AND (size <> 0 OR pieces <> 0)) OR
            (content IS NOT NULL AND typeof(content) <> 'blob') OR
            typeof(device) <> 'text' OR length(device) = 0 OR
            typeof(user_id) <> 'integer' OR user_id <> 1 OR
            typeof(ts) <> 'integer' OR ts < 0
         LIMIT 1",
        overhead = REVISION_PIECE_SIZE - 1,
        piece_size = REVISION_PIECE_SIZE,
    );
    reject_invalid_row(c, &revision_metadata, "revision metadata")?;

    if external_content {
        reject_invalid_row(
            c,
            "SELECT CAST(r.uid AS TEXT)
               FROM revisions r
               LEFT JOIN revision_content rc ON rc.uid=r.uid
              WHERE (r.size=0 AND (r.content IS NOT NULL OR rc.uid IS NOT NULL))
                 OR (r.size>0 AND
                     ((CASE WHEN r.content IS NOT NULL THEN 1 ELSE 0 END) +
                      (CASE WHEN rc.uid IS NOT NULL THEN 1 ELSE 0 END)) <> 1)
                 OR (r.content IS NOT NULL AND length(r.content) <> r.size)
                 OR (rc.uid IS NOT NULL AND
                     (typeof(rc.content) <> 'blob' OR length(rc.content) <> r.size))
              LIMIT 1",
            "revision content location and byte length",
        )?;
    } else {
        reject_invalid_row(
            c,
            "SELECT CAST(uid AS TEXT) FROM revisions
              WHERE (size=0 AND content IS NOT NULL)
                 OR (size>0 AND
                     (content IS NULL OR typeof(content) <> 'blob' OR length(content) <> size))
              LIMIT 1",
            "legacy revision content and byte length",
        )?;
    }

    reject_invalid_row(
        c,
        "SELECT name FROM sqlite_sequence
          WHERE name <> 'revisions' OR typeof(seq) <> 'integer' OR seq < 0
          LIMIT 1",
        "revision sequence",
    )?;
    reject_invalid_row(
        c,
        "SELECT 'revisions' WHERE
           (SELECT COUNT(*) FROM sqlite_sequence WHERE name='revisions') > 1",
        "revision sequence uniqueness",
    )?;
    reject_invalid_row(
        c,
        "SELECT id FROM vaults v
          WHERE v.version < COALESCE(
                  (SELECT MAX(r.uid) FROM revisions r WHERE r.vault_id=v.id),0
                )
             OR v.version > COALESCE(
                  (SELECT seq FROM sqlite_sequence WHERE name='revisions'),0
                )
          LIMIT 1",
        "vault version is a valid revision high-water mark",
    )?;
    reject_invalid_row(
        c,
        "SELECT id FROM vaults v
          WHERE v.size <> (
            SELECT COALESCE(SUM(r.size),0)
              FROM revisions r
             WHERE r.vault_id=v.id
               AND r.uid IN (
                 SELECT MAX(head.uid) FROM revisions head
                  WHERE head.vault_id=v.id GROUP BY head.path
               )
               AND r.deleted=0 AND r.folder=0
          )
          LIMIT 1",
        "vault size equals current live file heads",
    )?;

    if table_exists(c, "schema_migrations")? {
        reject_invalid_row(
            c,
            "SELECT CAST(version AS TEXT) FROM schema_migrations
              WHERE typeof(version) <> 'integer' OR
                    typeof(applied_at) <> 'integer' OR applied_at < 0
              LIMIT 1",
            "migration metadata",
        )?;
    }
    if table_exists(c, "sessions")? {
        reject_invalid_row(
            c,
            "SELECT token_hash FROM sessions
              WHERE typeof(token_hash) <> 'text' OR length(token_hash) <> 64 OR
                    token_hash GLOB '*[^0-9a-f]*' OR
                    typeof(created_at) <> 'integer' OR created_at < 0 OR
                    typeof(expires_at) <> 'integer' OR expires_at <= created_at OR
                    (revoked_at IS NOT NULL AND
                     (typeof(revoked_at) <> 'integer' OR revoked_at < created_at))
              LIMIT 1",
            "session token and timestamps",
        )?;
    }
    Ok(())
}

const REVISION_PIECE_SIZE: i64 = 2 * 1024 * 1024;

fn reject_invalid_row(c: &Connection, sql: &str, invariant: &str) -> Result<()> {
    let invalid = c
        .query_row(sql, [], |row| row.get::<_, String>(0))
        .optional()?;
    if let Some(identity) = invalid {
        bail!("database logical invariant failed ({invariant}): {identity}")
    }
    Ok(())
}

fn verify_migration_history(c: &Connection) -> Result<()> {
    let versions = migration_versions(c)?;
    reject_newer_migrations(&versions)?;
    if versions != SUPPORTED_MIGRATIONS {
        bail!(
            "unsupported Blackglass migration history: expected {:?}, found {:?}",
            SUPPORTED_MIGRATIONS,
            versions
        )
    }
    Ok(())
}

fn migration_versions(c: &Connection) -> Result<Vec<i64>> {
    let mut query = c
        .prepare("SELECT version FROM schema_migrations ORDER BY version")
        .context("read Blackglass migration history")?;
    Ok(query
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn reject_newer_migrations(versions: &[i64]) -> Result<()> {
    if let Some(version) = versions
        .iter()
        .copied()
        .find(|version| *version > CURRENT_SCHEMA_VERSION)
    {
        bail!(
            "database schema version {version} is newer than this server supports ({CURRENT_SCHEMA_VERSION})"
        )
    }
    Ok(())
}

fn verify_foreign_keys(c: &Connection) -> Result<()> {
    let mut query = c.prepare("PRAGMA foreign_key_check")?;
    let mut rows = query.query([])?;
    if let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        let parent: String = row.get(2)?;
        let constraint: i64 = row.get(3)?;
        bail!(
            "SQLite foreign_key_check failed: table={table}, rowid={row_id:?}, parent={parent}, constraint={constraint}"
        )
    }
    Ok(())
}

fn sqlite_sidecars(path: &Path) -> [PathBuf; 3] {
    [
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
        sqlite_sidecar(path, "-journal"),
    ]
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn remove_database_files(path: &Path) -> Result<()> {
    let mut first_error = None;
    for candidate in std::iter::once(path.to_path_buf()).chain(sqlite_sidecars(path)) {
        match std::fs::remove_file(&candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if first_error.is_none() => {
                first_error = Some(anyhow::Error::new(error).context(format!(
                    "remove incomplete database file {}",
                    candidate.display()
                )));
            }
            Err(_) => {}
        }
    }
    first_error.map_or(Ok(()), Err)
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

    fn assert_error_contains<T>(result: Result<T>, expected: &str) {
        let error = result.err().expect("operation unexpectedly succeeded");
        let message = format!("{error:#}");
        assert!(
            message.contains(expected),
            "expected error containing {expected:?}, got {message:?}"
        );
    }

    fn create_current_database(path: &Path) {
        let database = Db::open(path).unwrap();
        database.checkpoint().unwrap();
        drop(database);
    }

    fn create_legacy_database(path: &Path) {
        let connection = Connection::open(path).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        connection
            .execute_batch(
                "CREATE TABLE vaults(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    keyhash TEXT,
                    salt TEXT,
                    host TEXT NOT NULL,
                    region TEXT NOT NULL,
                    encryption_version INTEGER NOT NULL,
                    size INTEGER NOT NULL DEFAULT 0,
                    created INTEGER NOT NULL,
                    password TEXT,
                    version INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE revisions(
                    uid INTEGER PRIMARY KEY AUTOINCREMENT,
                    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                    path TEXT NOT NULL,
                    relatedpath TEXT,
                    extension TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    ctime INTEGER NOT NULL,
                    mtime INTEGER NOT NULL,
                    folder INTEGER NOT NULL,
                    deleted INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    pieces INTEGER NOT NULL,
                    content BLOB,
                    device TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    ts INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE INDEX revisions_vault_uid ON revisions(vault_id,uid);
                 CREATE INDEX revisions_vault_path ON revisions(vault_id,path,uid);
                 INSERT INTO vaults(
                    id,name,keyhash,salt,host,region,encryption_version,size,created,password,version
                 ) VALUES(
                    'legacy-vault','Legacy','key','salt','localhost:3003','Blackglass Server',3,3,1,NULL,1
                 );
                 INSERT INTO revisions(
                    vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,
                    content,device,user_id,ts
                 ) VALUES(
                    'legacy-vault','opaque',NULL,'md','hash',1,2,0,0,3,1,x'010203','legacy',1,2
                 );",
            )
            .unwrap();
        drop(connection);
    }

    fn execute_sql(path: &Path, sql: &str) {
        let connection = Connection::open(path).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
    }

    fn create_migrated_database(root: &Path, name: &str) -> PathBuf {
        let legacy = root.join(format!("{name}-legacy.sqlite"));
        let current = root.join(format!("{name}-current.sqlite"));
        create_legacy_database(&legacy);
        migrate_legacy_database(&legacy, &current).unwrap();
        current
    }

    #[test]
    fn startup_creates_only_a_missing_database_with_full_durability() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.sqlite");
        let database = Db::open(&path).unwrap();
        database
            .with(|connection| {
                let foreign_keys: i64 =
                    connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
                let journal: String =
                    connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
                let synchronous: i64 =
                    connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
                let trusted_schema: i64 =
                    connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
                assert_eq!(foreign_keys, 1);
                assert_eq!(journal.to_ascii_lowercase(), "wal");
                assert_eq!(synchronous, 2, "SQLite synchronous mode is not FULL");
                assert_eq!(trusted_schema, 0, "SQLite trusted_schema is enabled");
                assert!(
                    connection.set_db_config(
                        rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE,
                        true
                    )?
                );
                Ok(())
            })
            .unwrap();
        verify_database(&path).unwrap();
        database.checkpoint().unwrap();
        drop(database);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn startup_rejects_empty_and_legacy_existing_databases_without_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.sqlite");
        File::create(&empty).unwrap();
        let empty_before = std::fs::read(&empty).unwrap();
        assert_error_contains(Db::open(&empty), "has no Blackglass migration metadata");
        assert_eq!(std::fs::read(&empty).unwrap(), empty_before);
        for sidecar in sqlite_sidecars(&empty) {
            assert!(!sidecar.exists());
        }

        let legacy = dir.path().join("legacy.sqlite");
        create_legacy_database(&legacy);
        let legacy_before = std::fs::read(&legacy).unwrap();
        assert_error_contains(Db::open(&legacy), "migrate-legacy");
        assert_eq!(std::fs::read(&legacy).unwrap(), legacy_before);
        let connection = Connection::open(&legacy).unwrap();
        assert!(!table_exists(&connection, "schema_migrations").unwrap());
    }

    #[test]
    fn startup_rejects_invalid_current_database_before_modifying_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-current.sqlite");
        create_current_database(&path);
        execute_sql(&path, "CREATE TABLE unexpected(value TEXT);");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        assert_error_contains(
            Db::open(&path),
            "existing server database validation failed",
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let connection = Connection::open(&path).unwrap();
        assert!(table_exists(&connection, "unexpected").unwrap());
        drop(connection);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644,
                "a rejected database had its permissions changed"
            );
        }
    }

    #[test]
    fn startup_rejects_symlinks_and_stale_sidecars_without_touching_targets() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.sqlite");
        create_current_database(&target);
        let target_before = std::fs::read(&target).unwrap();

        #[cfg(unix)]
        {
            let symlink = dir.path().join("database-link.sqlite");
            std::os::unix::fs::symlink(&target, &symlink).unwrap();
            assert_error_contains(Db::open(&symlink), "is not a regular file");
            assert_eq!(std::fs::read(&target).unwrap(), target_before);
        }

        let missing = dir.path().join("missing.sqlite");
        let stale = sqlite_sidecar(&missing, "-wal");
        std::fs::write(&stale, b"stale wal").unwrap();
        assert_error_contains(Db::open(&missing), "sidecar exists without its database");
        assert!(!missing.exists());
        assert_eq!(std::fs::read(&stale).unwrap(), b"stale wal");

        #[cfg(unix)]
        {
            let dangling_database = dir.path().join("dangling-sidecar.sqlite");
            let dangling_sidecar = sqlite_sidecar(&dangling_database, "-journal");
            let dangling_target = dir.path().join("must-not-be-created");
            std::os::unix::fs::symlink(&dangling_target, &dangling_sidecar).unwrap();
            assert_error_contains(
                Db::open(&dangling_database),
                "sidecar exists without its database",
            );
            assert!(!dangling_database.exists());
            assert!(!dangling_target.exists());
            assert!(
                std::fs::symlink_metadata(&dangling_sidecar)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }

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
            password: None,
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
        assert!(!dir.path().join("backup.sqlite-journal").exists());
        let restored = dir.path().join("restored.sqlite");
        restore_database(&backup, &restored).unwrap();
        assert!(!dir.path().join("restored.sqlite-wal").exists());
        assert!(!dir.path().join("restored.sqlite-shm").exists());
        assert!(!dir.path().join("restored.sqlite-journal").exists());
        let copy = Db::open(&restored).unwrap();
        assert_eq!(copy.list_vaults().unwrap().len(), 1);
        assert_eq!(copy.current_version("v1").unwrap(), 1);
    }

    #[test]
    fn missing_operational_sources_fail_without_creating_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sqlite");
        let backup = dir.path().join("backup.sqlite");
        let restored = dir.path().join("restored.sqlite");
        let migrated = dir.path().join("migrated.sqlite");

        assert_error_contains(
            backup_database(&missing, &backup),
            "must be an existing regular file",
        );
        assert_error_contains(
            verify_database(&missing),
            "must be an existing regular file",
        );
        assert_error_contains(
            restore_database(&missing, &restored),
            "must be an existing regular file",
        );
        assert_error_contains(
            revoke_all_sessions(&missing),
            "must be an existing regular file",
        );
        assert_error_contains(
            migrate_legacy_database(&missing, &migrated),
            "must be an existing regular file",
        );

        assert!(!missing.exists(), "source typo created an empty database");
        assert!(!backup.exists(), "failed backup created a destination");
        assert!(!restored.exists(), "failed restore created a destination");
        assert!(!migrated.exists(), "failed migration created a destination");
    }

    #[test]
    fn non_regular_operational_sources_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source_directory = dir.path().join("database-directory");
        std::fs::create_dir(&source_directory).unwrap();

        assert_error_contains(verify_database(&source_directory), "is not a regular file");
        assert_error_contains(
            backup_database(&source_directory, &dir.path().join("backup.sqlite")),
            "is not a regular file",
        );
        assert_error_contains(
            revoke_all_sessions(&source_directory),
            "is not a regular file",
        );
        assert_error_contains(
            migrate_legacy_database(&source_directory, &dir.path().join("migrated.sqlite")),
            "is not a regular file",
        );

        #[cfg(unix)]
        {
            let database = dir.path().join("database.sqlite");
            create_current_database(&database);
            let symlink = dir.path().join("database-link.sqlite");
            std::os::unix::fs::symlink(&database, &symlink).unwrap();
            assert_error_contains(verify_database(&symlink), "is not a regular file");
            assert_error_contains(revoke_all_sessions(&symlink), "is not a regular file");
        }
    }

    #[test]
    fn operational_session_revocation_updates_only_a_valid_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sessions.sqlite");
        let database = Db::open(&source).unwrap();
        let first = database.issue_session(60).unwrap();
        let second = database.issue_session(60).unwrap();
        database.checkpoint().unwrap();
        drop(database);

        assert_eq!(revoke_all_sessions(&source).unwrap(), 2);
        let database = Db::open(&source).unwrap();
        assert!(!database.valid_session(&first));
        assert!(!database.valid_session(&second));
        assert_eq!(revoke_all_sessions(&source).unwrap(), 0);
    }

    #[test]
    fn verification_rejects_empty_and_wrong_schema_databases() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.sqlite");
        File::create(&empty).unwrap();
        assert_error_contains(
            verify_database(&empty),
            "unexpected Blackglass schema objects",
        );

        let wrong = dir.path().join("wrong.sqlite");
        let connection = Connection::open(&wrong).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
                 INSERT INTO schema_migrations(version, applied_at) VALUES(1, 1), (2, 2);
                 CREATE TABLE unrelated(value TEXT);",
            )
            .unwrap();
        drop(connection);
        assert_error_contains(
            verify_database(&wrong),
            "unexpected Blackglass schema objects",
        );

        let backup = dir.path().join("wrong-backup.sqlite");
        assert_error_contains(
            backup_database(&wrong, &backup),
            "backup source validation failed",
        );
        assert!(!backup.exists());
    }

    #[test]
    fn verification_rejects_unexpected_objects_and_index_drift() {
        let dir = tempfile::tempdir().unwrap();
        for (name, mutation, expected) in [
            (
                "table",
                "CREATE TABLE unexpected(value TEXT);",
                "unexpected Blackglass schema objects",
            ),
            (
                "view",
                "CREATE VIEW unexpected AS SELECT id FROM vaults;",
                "unexpected Blackglass schema objects",
            ),
            (
                "trigger",
                "CREATE TRIGGER unexpected AFTER INSERT ON vaults BEGIN SELECT 1; END;",
                "unexpected Blackglass schema objects",
            ),
            (
                "index",
                "DROP INDEX revisions_vault_uid;
                 CREATE INDEX revisions_vault_uid ON revisions(uid);",
                "invalid Blackglass indexes",
            ),
        ] {
            let path = dir.path().join(format!("{name}.sqlite"));
            create_current_database(&path);
            execute_sql(&path, mutation);
            assert_error_contains(verify_database(&path), expected);
        }
    }

    #[test]
    fn verification_rejects_column_type_nullability_default_and_key_drift() {
        let dir = tempfile::tempdir().unwrap();
        for (name, table, old, new) in [
            (
                "type",
                "vaults",
                "size INTEGER NOT NULL DEFAULT 0",
                "size TEXT NOT NULL DEFAULT 0",
            ),
            ("nullability", "vaults", "name TEXT NOT NULL", "name TEXT"),
            (
                "default",
                "vaults",
                "version INTEGER NOT NULL DEFAULT 0",
                "version INTEGER NOT NULL DEFAULT 1",
            ),
            (
                "primary-key",
                "revision_content",
                "uid INTEGER PRIMARY KEY",
                "uid INTEGER",
            ),
        ] {
            let path = dir.path().join(format!("column-{name}.sqlite"));
            create_current_database(&path);
            let connection = Connection::open(&path).unwrap();
            let definition: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(definition.contains(old));
            connection
                .pragma_update(None, "writable_schema", "ON")
                .unwrap();
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql=? WHERE type='table' AND name=?",
                    params![definition.replacen(old, new, 1), table],
                )
                .unwrap();
            connection
                .pragma_update(None, "writable_schema", "OFF")
                .unwrap();
            drop(connection);
            assert!(
                verify_database(&path).is_err(),
                "column {name} drift passed verification"
            );
        }

        let generated = dir.path().join("column-generated.sqlite");
        create_current_database(&generated);
        let connection = Connection::open(&generated).unwrap();
        let definition: String = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='vaults'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let definition = format!(
            "{}, generated_name TEXT GENERATED ALWAYS AS (name) VIRTUAL)",
            definition.strip_suffix(')').unwrap()
        );
        connection
            .pragma_update(None, "writable_schema", "ON")
            .unwrap();
        connection
            .execute(
                "UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='vaults'",
                [definition],
            )
            .unwrap();
        connection
            .pragma_update(None, "writable_schema", "OFF")
            .unwrap();
        drop(connection);
        assert!(
            verify_database(&generated).is_err(),
            "generated column drift passed verification"
        );
    }

    #[test]
    fn verification_rejects_logically_inconsistent_current_rows() {
        let dir = tempfile::tempdir().unwrap();
        for (name, mutation, expected) in [
            (
                "vault-size",
                "UPDATE vaults SET size=4;",
                "vault size equals current live file heads",
            ),
            (
                "vault-version-low",
                "UPDATE vaults SET version=0;",
                "vault version is a valid revision high-water mark",
            ),
            (
                "vault-version-high",
                "UPDATE vaults SET version=2;",
                "vault version is a valid revision high-water mark",
            ),
            (
                "boolean",
                "UPDATE revisions SET folder=2;",
                "revision metadata",
            ),
            (
                "pieces",
                "UPDATE revisions SET pieces=2;",
                "revision metadata",
            ),
            (
                "sequence-duplicate",
                "INSERT INTO sqlite_sequence(name,seq)
                 SELECT name,seq FROM sqlite_sequence WHERE name='revisions';",
                "revision sequence uniqueness",
            ),
            (
                "content-length",
                "UPDATE revisions SET content=x'0102';",
                "revision content location and byte length",
            ),
            (
                "missing-content",
                "UPDATE revisions SET content=NULL;",
                "revision content location and byte length",
            ),
            (
                "duplicate-content",
                "INSERT INTO revision_content(uid,content)
                 SELECT uid,content FROM revisions;",
                "revision content location and byte length",
            ),
            (
                "session",
                "INSERT INTO sessions(token_hash,created_at,expires_at,revoked_at)
                 VALUES('short',10,9,NULL);",
                "session token and timestamps",
            ),
            (
                "session-revocation",
                "INSERT INTO sessions(token_hash,created_at,expires_at,revoked_at)
                 VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',10,20,9);",
                "session token and timestamps",
            ),
        ] {
            let path = create_migrated_database(dir.path(), name);
            execute_sql(&path, mutation);
            assert_error_contains(verify_database(&path), expected);
        }
    }

    #[test]
    fn corrupt_database_is_rejected_without_creating_destinations() {
        let dir = tempfile::tempdir().unwrap();
        let corrupt = dir.path().join("corrupt.sqlite");
        std::fs::write(&corrupt, b"not a sqlite database").unwrap();
        let backup = dir.path().join("backup.sqlite");
        let restored = dir.path().join("restored.sqlite");

        assert!(verify_database(&corrupt).is_err());
        assert!(backup_database(&corrupt, &backup).is_err());
        assert!(restore_database(&corrupt, &restored).is_err());
        assert!(!backup.exists());
        assert!(!restored.exists());
    }

    #[test]
    fn newer_schema_is_rejected_before_backup_restore_or_session_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("future.sqlite");
        let database = Db::open(&source).unwrap();
        database.issue_session(60).unwrap();
        database.checkpoint().unwrap();
        drop(database);

        let connection = Connection::open(&source).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(3, 3)",
                [],
            )
            .unwrap();
        drop(connection);

        let backup = dir.path().join("backup.sqlite");
        let restored = dir.path().join("restored.sqlite");
        for result in [
            verify_database(&source),
            backup_database(&source, &backup),
            restore_database(&source, &restored),
            revoke_all_sessions(&source).map(|_| ()),
            Db::open(&source).map(|_| ()),
        ] {
            assert_error_contains(result, "schema version 3 is newer");
        }
        assert!(!backup.exists());
        assert!(!restored.exists());

        let connection =
            Connection::open_with_flags(&source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        let active: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE revoked_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active, 1, "failed revoke changed a future-schema database");
    }

    #[test]
    fn incomplete_migration_history_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("migration-gap.sqlite");
        create_current_database(&source);
        let connection = Connection::open(&source).unwrap();
        connection
            .execute("DELETE FROM schema_migrations WHERE version=1", [])
            .unwrap();
        drop(connection);

        assert_error_contains(
            verify_database(&source),
            "unsupported Blackglass migration history",
        );
        assert_error_contains(
            Db::open(&source),
            "unsupported Blackglass migration history",
        );
    }

    #[test]
    fn foreign_key_violations_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("orphan.sqlite");
        create_current_database(&source);
        let connection = Connection::open(&source).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection
            .execute(
                "INSERT INTO revision_content(uid, content) VALUES(999, x'00')",
                [],
            )
            .unwrap();
        drop(connection);

        assert_error_contains(verify_database(&source), "foreign_key_check failed");
        let backup = dir.path().join("backup.sqlite");
        assert_error_contains(
            backup_database(&source, &backup),
            "foreign_key_check failed",
        );
        assert!(!backup.exists());
    }

    #[test]
    fn existing_destinations_and_sidecars_are_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.sqlite");
        create_current_database(&source);

        let existing = dir.path().join("existing.sqlite");
        std::fs::write(&existing, b"preserve me").unwrap();
        assert!(backup_database(&source, &existing).is_err());
        assert!(restore_database(&source, &existing).is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"preserve me");

        let blocked = dir.path().join("blocked.sqlite");
        let stale_wal = sqlite_sidecar(&blocked, "-wal");
        std::fs::write(&stale_wal, b"preserve sidecar").unwrap();
        assert_error_contains(backup_database(&source, &blocked), "sidecar already exists");
        assert!(!blocked.exists());
        assert_eq!(std::fs::read(stale_wal).unwrap(), b"preserve sidecar");
    }

    #[test]
    fn failed_destination_creation_removes_partial_database_and_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("partial.sqlite");
        assert_error_contains(
            with_new_database(&output, "test database", |connection| {
                connection.execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE partial(value TEXT);
                     INSERT INTO partial(value) VALUES('partial');",
                )?;
                bail!("forced validation failure")
            }),
            "forced validation failure",
        );
        assert!(!output.exists());
        assert!(!sqlite_sidecar(&output, "-wal").exists());
        assert!(!sqlite_sidecar(&output, "-shm").exists());
        assert!(!sqlite_sidecar(&output, "-journal").exists());
    }

    #[test]
    fn legacy_migration_preserves_source_and_produces_verified_current_database() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("legacy.sqlite");
        let destination = dir.path().join("current.sqlite");
        create_legacy_database(&source);
        let source_before = std::fs::read(&source).unwrap();

        migrate_legacy_database(&source, &destination).unwrap();

        assert_eq!(
            std::fs::read(&source).unwrap(),
            source_before,
            "legacy migration modified its source database"
        );
        assert!(!table_exists(&Connection::open(&source).unwrap(), "schema_migrations").unwrap());
        verify_database(&destination).unwrap();
        for sidecar in sqlite_sidecars(&destination) {
            assert!(
                !sidecar.exists(),
                "migration retained {}",
                sidecar.display()
            );
        }

        let migrated = Db::open(&destination).unwrap();
        let vaults = migrated.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, "legacy-vault");
        let through = migrated.current_version("legacy-vault").unwrap();
        let revisions = migrated
            .list_changes_page("legacy-vault", 0, through, 1024)
            .unwrap();
        assert_eq!(revisions.len(), 1);
        assert_eq!(
            migrated.content_chunk(revisions[0].uid, 0, 3).unwrap(),
            [1, 2, 3]
        );
    }

    #[test]
    fn legacy_migration_rejects_unexpected_current_and_newer_schemas() {
        let dir = tempfile::tempdir().unwrap();

        let unexpected = dir.path().join("unexpected.sqlite");
        create_legacy_database(&unexpected);
        let connection = Connection::open(&unexpected).unwrap();
        connection
            .execute("ALTER TABLE revisions ADD COLUMN unexpected TEXT", [])
            .unwrap();
        drop(connection);
        let unexpected_destination = dir.path().join("unexpected-destination.sqlite");
        assert_error_contains(
            migrate_legacy_database(&unexpected, &unexpected_destination),
            "expected 16 columns",
        );
        assert!(!unexpected_destination.exists());

        let unexpected_view = dir.path().join("legacy-view.sqlite");
        create_legacy_database(&unexpected_view);
        execute_sql(
            &unexpected_view,
            "CREATE VIEW unexpected AS SELECT id FROM vaults;",
        );
        assert_error_contains(
            migrate_legacy_database(
                &unexpected_view,
                &dir.path().join("legacy-view-destination.sqlite"),
            ),
            "unexpected legacy Blackglass schema objects",
        );

        let wrong_index = dir.path().join("legacy-index.sqlite");
        create_legacy_database(&wrong_index);
        execute_sql(
            &wrong_index,
            "DROP INDEX revisions_vault_uid;
             CREATE INDEX revisions_vault_uid ON revisions(uid);",
        );
        assert_error_contains(
            migrate_legacy_database(
                &wrong_index,
                &dir.path().join("legacy-index-destination.sqlite"),
            ),
            "invalid legacy Blackglass indexes",
        );

        let inconsistent = dir.path().join("legacy-inconsistent.sqlite");
        create_legacy_database(&inconsistent);
        execute_sql(&inconsistent, "UPDATE vaults SET size=99;");
        assert_error_contains(
            migrate_legacy_database(
                &inconsistent,
                &dir.path().join("legacy-inconsistent-destination.sqlite"),
            ),
            "vault size equals current live file heads",
        );

        let current = dir.path().join("current.sqlite");
        create_current_database(&current);
        let current_destination = dir.path().join("current-destination.sqlite");
        assert_error_contains(
            migrate_legacy_database(&current, &current_destination),
            "already has Blackglass migration metadata",
        );
        assert!(!current_destination.exists());

        let connection = Connection::open(&current).unwrap();
        connection
            .execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(3, 3)",
                [],
            )
            .unwrap();
        drop(connection);
        let future_destination = dir.path().join("future-destination.sqlite");
        assert_error_contains(
            migrate_legacy_database(&current, &future_destination),
            "schema version 3 is newer",
        );
        assert!(!future_destination.exists());
    }
}
