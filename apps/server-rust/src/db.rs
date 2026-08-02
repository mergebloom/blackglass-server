use crate::{
    auth,
    model::{AuthContext, NewRevision, PullInfo, PushNotice, Revision, UserCredential, Vault},
};
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params, types::Value};
use std::{
    collections::HashSet,
    error::Error as StdError,
    fmt,
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const CURRENT_SCHEMA_VERSION: i64 = 5;
const SUPPORTED_MIGRATIONS: &[i64] = &[1, 2, 3, 4, 5];
pub(crate) const MAX_VAULTS: i64 = 100;
pub(crate) const MAX_JS_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub(crate) const MAX_USERS: i64 = 256;
const MAX_RETIRED_VAULTS: i64 = 8_192;
const MAX_RETIRED_VAULTS_PER_OWNER: i64 = 512;
const MAX_SESSIONS: i64 = 1024;
const MAX_SESSIONS_PER_USER: i64 = 64;
pub(crate) const CURRENT_SCHEMA_VERSION_PUBLIC: i64 = CURRENT_SCHEMA_VERSION;

#[derive(Clone, Debug)]
pub(crate) struct InitialUser {
    pub email_canonical: String,
    pub email: String,
    pub name: String,
    pub password_hash: String,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserSummary {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub status: String,
    pub owned_vaults: i64,
    pub sessions: i64,
}

impl InitialUser {
    pub(crate) fn new(email: &str, name: &str, password_hash: &str) -> Result<Self> {
        let email = auth::canonicalize_email(email)?;
        let name = auth::normalize_display_name(name)?;
        if !auth::password_hash_is_production_grade(password_hash) {
            bail!("initial user password hash does not meet the production Argon2 policy")
        }
        Ok(Self {
            email_canonical: email.canonical,
            email: email.display,
            name,
            password_hash: password_hash.to_owned(),
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminVault {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub encryption_mode: String,
    pub encryption_version: i64,
    pub current_revision: i64,
    pub live_bytes: i64,
    pub retained_bytes: i64,
    pub file_count: i64,
    pub deleted_count: i64,
    pub latest_activity_at: Option<i64>,
    pub latest_device: Option<String>,
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminActivity {
    pub timestamp: i64,
    pub vault_id: String,
    pub vault_name: String,
    pub device: String,
    pub event_type: String,
    pub extension: String,
    pub size: i64,
    pub revision: i64,
}
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminSession {
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
}
pub(crate) struct AdminDatabaseSnapshot {
    pub schema_version: i64,
    pub max_sessions: i64,
    pub vaults: Vec<AdminVault>,
    pub activity: Vec<AdminActivity>,
    pub sessions: Vec<AdminSession>,
    pub active_sessions: i64,
    pub session_count: i64,
    pub logical_bytes: i64,
    pub retained_bytes: i64,
    pub vault_count: i64,
    pub activity_count: i64,
    pub mismatched_data_hosts: i64,
}

#[derive(Debug)]
struct StorageQuotaExceeded;

impl fmt::Display for StorageQuotaExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("stored ciphertext quota exceeded")
    }
}

impl StdError for StorageQuotaExceeded {}

pub(crate) fn is_storage_quota_exceeded(error: &anyhow::Error) -> bool {
    error.downcast_ref::<StorageQuotaExceeded>().is_some()
}

#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
    path: Arc<PathBuf>,
}

impl Db {
    fn open_internal(path: &Path, initial_user: Option<&InitialUser>) -> Result<Self> {
        let existed = match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() {
                    bail!("server database is not a regular file: {}", path.display())
                }
                reject_hardlinked_file(&metadata, path, "server database")?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect server database: {}", path.display()));
            }
        };

        if !existed && initial_user.is_none() {
            bail!(
                "server database does not exist; initialize it offline with `blackglass-server user create <database> <email> <name>`"
            )
        }

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
                migrate(&conn, initial_user)?;
            }
            verify_connection(&conn)?;
            initialize_runtime_storage_usage(&conn)?;
            if !existed {
                sync_parent_directory(path)?;
            }
            Ok(Self {
                connection: Arc::new(Mutex::new(conn)),
                path: Arc::new(path.to_path_buf()),
            })
        })();

        if result.is_err() && !existed {
            let _ = remove_database_files(path);
        }
        result
    }

    #[cfg(test)]
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_internal(path, Some(&test_initial_user()))
    }

    pub(crate) fn open_existing(path: &Path) -> Result<Self> {
        Self::open_internal(path, None)
    }

    pub(crate) fn initialize(path: &Path, initial_user: &InitialUser) -> Result<Self> {
        Self::open_internal(path, Some(initial_user))
    }

    pub(crate) fn open_offline_under_lock(path: &Path) -> Result<Self> {
        let connection = open_existing_read_write(path, "offline user database")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        verify_connection(&connection).context("offline user database validation failed")?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            path: Arc::new(path.to_path_buf()),
        })
    }

    pub(crate) fn list_users(&self) -> Result<Vec<UserSummary>> {
        self.with(|connection| {
            let mut query = connection.prepare(
                "SELECT u.id,u.email,u.name,u.status,
                        (SELECT COUNT(*) FROM vaults v WHERE v.owner_user_id=u.id),
                        (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id)
                   FROM users u ORDER BY u.id LIMIT ?",
            )?;
            Ok(query
                .query_map([MAX_USERS], |row| {
                    Ok(UserSummary {
                        id: row.get(0)?,
                        email: row.get(1)?,
                        name: row.get(2)?,
                        status: row.get(3)?,
                        owned_vaults: row.get(4)?,
                        sessions: row.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    pub(crate) fn create_user(&self, email: &str, name: &str, password_hash: &str) -> Result<i64> {
        let email = auth::canonicalize_email(email)?;
        let name = auth::normalize_display_name(name)?;
        if !auth::password_hash_is_production_grade(password_hash) {
            bail!("password hash does not meet the production Argon2 policy")
        }
        self.with(|connection| {
            let transaction = connection.transaction()?;
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
            if count >= MAX_USERS {
                bail!("user limit reached")
            }
            let sequence: i64 = transaction.query_row(
                "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='users'),0)",
                [],
                |row| row.get(0),
            )?;
            if sequence >= MAX_JS_SAFE_INTEGER {
                bail!("user ID sequence exhausted")
            }
            let now = now_ms();
            transaction.execute(
                "INSERT INTO users(
                    email_canonical,email,name,password_hash,status,created_at,updated_at
                 ) VALUES(?,?,?,?,'active',?,?)",
                params![
                    email.canonical,
                    email.display,
                    name,
                    password_hash,
                    now,
                    now
                ],
            )?;
            let id = transaction.last_insert_rowid();
            transaction.commit()?;
            Ok(id)
        })
    }

    pub(crate) fn set_user_password(&self, user_id: i64, password_hash: &str) -> Result<()> {
        if !auth::password_hash_is_production_grade(password_hash) {
            bail!("password hash does not meet the production Argon2 policy")
        }
        self.update_user_and_revoke(user_id, |transaction, now| {
            transaction.execute(
                "UPDATE users SET password_hash=?,updated_at=? WHERE id=?",
                params![password_hash, now, user_id],
            )
        })
    }

    pub(crate) fn set_user_email(&self, user_id: i64, value: &str) -> Result<()> {
        let email = auth::canonicalize_email(value)?;
        self.update_user_and_revoke(user_id, |transaction, now| {
            transaction.execute(
                "UPDATE users SET email_canonical=?,email=?,updated_at=? WHERE id=?",
                params![email.canonical, email.display, now, user_id],
            )
        })
    }

    pub(crate) fn set_user_name(&self, user_id: i64, value: &str) -> Result<()> {
        let name = auth::normalize_display_name(value)?;
        self.with(|connection| {
            let changed = connection.execute(
                "UPDATE users SET name=?,updated_at=? WHERE id=?",
                params![name, now_ms(), user_id],
            )?;
            if changed != 1 {
                bail!("user not found")
            }
            Ok(())
        })
    }

    pub(crate) fn set_user_status(&self, user_id: i64, status: &str) -> Result<()> {
        if !matches!(status, "active" | "disabled") {
            bail!("user status must be active or disabled")
        }
        if status == "disabled" {
            self.update_user_and_revoke(user_id, |transaction, now| {
                transaction.execute(
                    "UPDATE users SET status='disabled',updated_at=? WHERE id=?",
                    params![now, user_id],
                )
            })
        } else {
            self.with(|connection| {
                let changed = connection.execute(
                    "UPDATE users SET status='active',updated_at=? WHERE id=?",
                    params![now_ms(), user_id],
                )?;
                if changed != 1 {
                    bail!("user not found")
                }
                Ok(())
            })
        }
    }

    pub(crate) fn revoke_user_sessions(&self, user_id: i64) -> Result<usize> {
        self.with(|connection| {
            let exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?)",
                [user_id],
                |row| Ok(row.get::<_, i64>(0)? == 1),
            )?;
            if !exists {
                bail!("user not found")
            }
            Ok(connection.execute(
                "UPDATE sessions SET revoked_at=MAX(?,created_at)
                  WHERE user_id=? AND revoked_at IS NULL",
                params![now_ms(), user_id],
            )?)
        })
    }

    fn update_user_and_revoke(
        &self,
        user_id: i64,
        update: impl FnOnce(&rusqlite::Transaction<'_>, i64) -> rusqlite::Result<usize>,
    ) -> Result<()> {
        self.with(|connection| {
            let transaction = connection.transaction()?;
            let now = now_ms();
            if update(&transaction, now)? != 1 {
                bail!("user not found")
            }
            transaction.execute(
                "UPDATE sessions SET revoked_at=MAX(?,created_at)
                  WHERE user_id=? AND revoked_at IS NULL",
                params![now, user_id],
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    fn with<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock poisoned"))?;
        f(&mut conn)
    }

    pub fn ready(&self) -> bool {
        let Ok(connection) = self.connection.try_lock() else {
            return false;
        };
        connection.query_row("SELECT 1", [], |_| Ok(())).is_ok()
    }

    pub(crate) fn admin_snapshot(&self, expected_host: &str) -> Result<AdminDatabaseSnapshot> {
        // Never queue behind or hold the Sync writer mutex for admin reporting.
        // Each snapshot has isolated busy/progress state and is discarded after use.
        let c = open_admin_connection(&self.path)?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        c.progress_handler(1_000, Some(move || std::time::Instant::now() >= deadline));
        let result = (|| {
            let mut vault_query = c.prepare(
                "WITH latest_path AS (SELECT vault_id,path,MAX(uid) uid FROM revisions GROUP BY vault_id,path), per_vault AS (SELECT r.vault_id,SUM(r.size) retained_bytes,SUM(CASE WHEN lp.uid=r.uid AND r.deleted=0 AND r.folder=0 THEN 1 ELSE 0 END) file_count,SUM(CASE WHEN lp.uid=r.uid AND r.deleted=1 THEN 1 ELSE 0 END) deleted_count FROM revisions r LEFT JOIN latest_path lp ON lp.uid=r.uid GROUP BY r.vault_id), latest_revision AS (SELECT r.vault_id,r.ts,r.device FROM revisions r JOIN (SELECT vault_id,MAX(uid) uid FROM revisions GROUP BY vault_id) x ON x.uid=r.uid) SELECT v.id,v.name,v.created,CASE WHEN v.password IS NULL THEN 'custom-password' ELSE 'managed' END,v.encryption_version,v.version,v.size,COALESCE(p.retained_bytes,0),COALESCE(p.file_count,0),COALESCE(p.deleted_count,0),l.ts,l.device FROM vaults v LEFT JOIN per_vault p ON p.vault_id=v.id LEFT JOIN latest_revision l ON l.vault_id=v.id ORDER BY v.created ASC LIMIT 100"
            )?;
            let vaults = vault_query
                .query_map([], |r| {
                    Ok(AdminVault {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        created_at: r.get(2)?,
                        encryption_mode: r.get(3)?,
                        encryption_version: r.get(4)?,
                        current_revision: r.get(5)?,
                        live_bytes: r.get(6)?,
                        retained_bytes: r.get(7)?,
                        file_count: r.get(8)?,
                        deleted_count: r.get(9)?,
                        latest_activity_at: r.get(10)?,
                        latest_device: r.get(11)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut activity_query = c.prepare("SELECT r.ts,r.vault_id,v.name,r.device,CASE WHEN r.deleted=1 THEN 'deleted' WHEN r.folder=1 THEN 'folder' ELSE 'revision' END,r.extension,r.size,r.uid FROM revisions r JOIN vaults v ON v.id=r.vault_id ORDER BY r.uid DESC LIMIT 100")?;
            let activity = activity_query
                .query_map([], |r| {
                    Ok(AdminActivity {
                        timestamp: r.get(0)?,
                        vault_id: r.get(1)?,
                        vault_name: r.get(2)?,
                        device: r.get(3)?,
                        event_type: r.get(4)?,
                        extension: r.get(5)?,
                        size: r.get(6)?,
                        revision: r.get(7)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut session_query=c.prepare("SELECT created_at,expires_at,revoked_at FROM sessions ORDER BY created_at DESC LIMIT 100")?;
            let sessions = session_query
                .query_map([], |r| {
                    Ok(AdminSession {
                        created_at: r.get(0)?,
                        expires_at: r.get(1)?,
                        revoked_at: r.get(2)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let now = now_ms();
            let (session_count,active_sessions)=c.query_row("SELECT COUNT(*),COALESCE(SUM(CASE WHEN revoked_at IS NULL AND expires_at>? THEN 1 ELSE 0 END),0) FROM sessions",[now],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let logical_bytes =
                c.query_row("SELECT COALESCE(SUM(size),0) FROM vaults", [], |r| r.get(0))?;
            let retained_bytes =
                c.query_row("SELECT COALESCE(SUM(size),0) FROM revisions", [], |r| {
                    r.get(0)
                })?;
            let mismatched_data_hosts = c.query_row(
                "SELECT COUNT(*) FROM vaults WHERE host<>?",
                [expected_host],
                |r| r.get(0),
            )?;
            let vault_count = c.query_row("SELECT COUNT(*) FROM vaults", [], |r| r.get(0))?;
            let activity_count = c.query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get(0))?;
            Ok(AdminDatabaseSnapshot {
                schema_version: CURRENT_SCHEMA_VERSION_PUBLIC,
                max_sessions: MAX_SESSIONS,
                vaults,
                activity,
                sessions,
                active_sessions,
                session_count,
                logical_bytes,
                retained_bytes,
                vault_count,
                activity_count,
                mismatched_data_hosts,
            })
        })();
        c.progress_handler(0, None::<fn() -> bool>);
        result
    }

    #[cfg(test)]
    pub fn issue_session(&self, ttl_secs: i64) -> Result<String> {
        self.issue_session_for_user(1, ttl_secs)
    }

    pub fn issue_session_for_user(&self, user_id: i64, ttl_secs: i64) -> Result<String> {
        let token = auth::new_token();
        let hash = auth::token_hash(&token);
        let now = now_ms();
        self.with(|c| {
            let transaction = c.transaction()?;
            transaction.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                [now],
            )?;
            let count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
            if count >= MAX_SESSIONS {
                bail!("active session limit reached")
            }
            let active_user: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND status='active')",
                [user_id],
                |row| Ok(row.get::<_, i64>(0)? == 1),
            )?;
            if !active_user {
                bail!("user is unavailable")
            }
            let user_count: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM sessions
                  WHERE user_id=? AND revoked_at IS NULL AND expires_at>?",
                params![user_id, now],
                |row| row.get(0),
            )?;
            if user_count >= MAX_SESSIONS_PER_USER {
                bail!("active user session limit reached")
            }
            transaction.execute(
                "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,revoked_at) VALUES(?,?,?,?,NULL)",
                params![hash, user_id, now, now + ttl_secs * 1000],
            )?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(token)
    }

    pub fn signin_candidate(&self, canonical_email: &str) -> Result<Option<UserCredential>> {
        self.with(|connection| {
            Ok(connection
                .query_row(
                    "SELECT id,email,name,password_hash,status='active'
                       FROM users WHERE email_canonical=?",
                    [canonical_email],
                    |row| {
                        Ok(UserCredential {
                            id: row.get(0)?,
                            email: row.get(1)?,
                            name: row.get(2)?,
                            password_hash: row.get(3)?,
                            active: row.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    pub fn auth_context(&self, token: &str) -> Result<Option<AuthContext>> {
        if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(None);
        }
        self.auth_context_hash(&auth::token_hash(token))
    }

    pub fn auth_context_hash(&self, token_hash: &str) -> Result<Option<AuthContext>> {
        if token_hash.len() != 64 || !token_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(None);
        }
        let now = now_ms();
        self.with(|connection| {
            Ok(connection
                .query_row(
                    "SELECT u.id,u.email,u.name,s.token_hash,s.expires_at
                       FROM sessions s JOIN users u ON u.id=s.user_id
                      WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL
                        AND u.status='active'",
                    params![token_hash, now],
                    |row| {
                        Ok(AuthContext {
                            user_id: row.get(0)?,
                            email: row.get(1)?,
                            name: row.get(2)?,
                            token_hash: row.get(3)?,
                            expires_at: row.get(4)?,
                        })
                    },
                )
                .optional()?)
        })
    }

    #[cfg(test)]
    pub fn valid_session(&self, token: &str) -> bool {
        if token.len() != 64 {
            return false;
        }
        self.valid_session_hash(&auth::token_hash(token))
    }

    #[cfg(test)]
    pub fn valid_session_hash(&self, hash: &str) -> bool {
        self.auth_context_hash(hash)
            .map(|context| context.is_some())
            .unwrap_or(false)
    }

    pub fn valid_session_for_vault(&self, hash: &str, vault: &str) -> bool {
        if hash.len() != 64 || vault.is_empty() {
            return false;
        }
        let now = now_ms();
        self.with(|c| {
            Ok(c.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sessions s
                    JOIN users u ON u.id=s.user_id AND u.status='active'
                    JOIN vaults v ON v.owner_user_id=s.user_id
                     WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL
                       AND v.id=?
                 )",
                params![hash, now, vault],
                |row| row.get::<_, i64>(0),
            )? == 1)
        })
        .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn is_retired_vault(&self, vault: &str) -> Result<bool> {
        self.with(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM retired_vaults WHERE id=?)",
                [vault],
                |row| row.get::<_, i64>(0),
            )? == 1)
        })
    }

    pub fn is_retired_vault_for_user(&self, user_id: i64, vault: &str) -> Result<bool> {
        self.with(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM retired_vaults WHERE id=? AND owner_user_id=?)",
                params![vault, user_id],
                |row| row.get::<_, i64>(0),
            )? == 1)
        })
    }

    pub fn usernames_for_vault(
        &self,
        vault: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        self.with(|connection| {
            let mut query = connection.prepare(
                "SELECT u.id,u.name FROM users u
                  WHERE u.id=(SELECT owner_user_id FROM vaults WHERE id=?)
                     OR u.id IN (SELECT DISTINCT user_id FROM revisions WHERE vault_id=?)
                  ORDER BY u.id LIMIT ?",
            )?;
            Ok(query
                .query_map(params![vault, vault, MAX_USERS], |row| {
                    Ok((row.get::<_, i64>(0)?.to_string(), row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()?)
        })
    }

    pub fn revoke_session(&self, token: &str) -> Result<()> {
        let hash = auth::token_hash(token);
        self.with(|c| {
            c.execute(
                "UPDATE sessions SET revoked_at=MAX(?,created_at) WHERE token_hash=?",
                params![now_ms(), hash],
            )?;
            Ok(())
        })
    }

    pub fn revoke_all_sessions(&self) -> Result<usize> {
        self.with(|c| {
            Ok(c.execute(
                "UPDATE sessions SET revoked_at=MAX(?,created_at) WHERE revoked_at IS NULL",
                [now_ms()],
            )?)
        })
    }

    #[cfg(test)]
    pub fn create_vault(&self, vault: &Vault) -> Result<()> {
        self.create_vault_for_user(1, vault)
    }
    pub fn create_vault_for_user(&self, user_id: i64, vault: &Vault) -> Result<()> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM vaults", [], |row| row.get(0))?;
            if count >= MAX_VAULTS {
                bail!("vault limit reached")
            }
            let owner_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM vaults WHERE owner_user_id=?",
                [user_id],
                |row| row.get(0),
            )?;
            if owner_count >= MAX_VAULTS {
                bail!("vault limit reached")
            }
            tx.execute("INSERT INTO vaults(id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id) VALUES(?,?,?,?,?,?,?,?,?,?,0,?)", params![vault.id,vault.name,vault.keyhash,vault.salt,vault.host,vault.region,vault.encryption_version,vault.size,vault.created,vault.password,user_id])?;
            tx.commit()?;
            Ok(())
        })
    }
    #[cfg(test)]
    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        self.list_vaults_for_user(1)
    }
    pub fn list_vaults_for_user(&self, user_id: i64) -> Result<Vec<Vault>> {
        self.with(|c| { let mut q=c.prepare("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password FROM vaults WHERE owner_user_id=? ORDER BY created ASC,id ASC LIMIT ?")?; Ok(q.query_map(params![user_id,MAX_VAULTS], vault_row)?.collect::<rusqlite::Result<Vec<_>>>()?) })
    }
    pub fn mismatched_data_hosts(&self, expected: &str) -> Result<Vec<String>> {
        self.with(|c| {
            let mut query =
                c.prepare("SELECT DISTINCT host FROM vaults WHERE host<>? ORDER BY host")?;
            Ok(query
                .query_map([expected], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }
    #[cfg(test)]
    pub fn find_vault(&self, id: &str) -> Result<Option<Vault>> {
        self.with(|c| Ok(c.query_row("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password FROM vaults WHERE id=?",[id],vault_row).optional()?))
    }
    pub fn find_owned_vault(&self, user_id: i64, id: &str) -> Result<Option<Vault>> {
        self.with(|c| Ok(c.query_row("SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password FROM vaults WHERE id=? AND owner_user_id=?",params![id,user_id],vault_row).optional()?))
    }
    pub fn bind_managed_keyhash_for_user(
        &self,
        user_id: i64,
        id: &str,
        keyhash: &str,
    ) -> Result<Option<String>> {
        self.with(|c| {
            c.execute(
                "UPDATE vaults SET keyhash=? WHERE id=? AND owner_user_id=? AND password IS NOT NULL AND keyhash IS NULL",
                params![keyhash, id, user_id],
            )?;
            Ok(c.query_row("SELECT keyhash FROM vaults WHERE id=? AND owner_user_id=?", params![id,user_id], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten())
        })
    }
    pub fn rename_vault_for_user(&self, user_id: i64, id: &str, name: &str) -> Result<bool> {
        self.with(|c| {
            Ok(c.execute(
                "UPDATE vaults SET name=? WHERE id=? AND owner_user_id=?",
                params![name, id, user_id],
            )? == 1)
        })
    }
    #[cfg(test)]
    pub fn delete_vault(&self, id: &str) -> Result<bool> {
        self.delete_vault_for_user(1, id)
    }
    pub fn delete_vault_for_user(&self, user_id: i64, id: &str) -> Result<bool> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM vaults WHERE id=? AND owner_user_id=?)",
                params![id, user_id],
                |row| row.get::<_, i64>(0),
            )? == 1;
            if !exists {
                return Ok(false);
            }
            retire_vault_identity(&tx, id, now_ms())?;
            tx.execute(
                "DELETE FROM vaults WHERE id=? AND owner_user_id=?",
                params![id, user_id],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }
    #[cfg(test)]
    pub fn migrate_vault(&self, source_id: &str, replacement: &Vault) -> Result<bool> {
        self.migrate_vault_for_user(1, source_id, replacement)
    }
    pub fn migrate_vault_for_user(
        &self,
        user_id: i64,
        source_id: &str,
        replacement: &Vault,
    ) -> Result<bool> {
        self.with(|c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM vaults WHERE id=? AND owner_user_id=?)",
                params![source_id,user_id],
                |row| row.get::<_, i64>(0),
            )? == 1;
            if !exists {
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO vaults(id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id)
                 VALUES(?,?,?,?,?,?,?,?,?,?,0,?)",
                params![
                    replacement.id,
                    replacement.name,
                    replacement.keyhash,
                    replacement.salt,
                    replacement.host,
                    replacement.region,
                    replacement.encryption_version,
                    replacement.size,
                    replacement.created,
                    replacement.password,
                    user_id
                ],
            )?;
            retire_vault_identity(&tx, source_id, now_ms())?;
            tx.execute("DELETE FROM vaults WHERE id=? AND owner_user_id=?", params![source_id,user_id])?;
            tx.commit()?;
            Ok(true)
        })
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
    pub fn stored_ciphertext_size(&self) -> Result<i64> {
        self.with(|connection| stored_ciphertext_size(connection))
    }
    pub fn stored_ciphertext_size_for_owner(&self, user_id: i64) -> Result<i64> {
        self.with(|connection| owner_stored_ciphertext_size(connection, user_id))
    }
    pub fn vault_size(&self, id: &str) -> Result<i64> {
        self.with(|c| vault_size(c, id))
    }

    pub fn add_empty_revision(
        &self,
        revision: &NewRevision,
        storage_quota_bytes: i64,
        owner_storage_quota_bytes: i64,
    ) -> Result<Revision> {
        if revision.size != 0 || revision.pieces != 0 {
            bail!("metadata-only revision must have zero size and pieces")
        }
        self.with(|c| {
            add_revision(
                c,
                revision,
                None,
                storage_quota_bytes,
                owner_storage_quota_bytes,
            )
        })
    }

    pub fn add_file_revision(
        &self,
        revision: &NewRevision,
        file_path: &Path,
        storage_quota_bytes: i64,
        owner_storage_quota_bytes: i64,
    ) -> Result<Revision> {
        if revision.folder
            || revision.deleted
            || revision.size <= 0
            || revision.pieces != (revision.size + REVISION_PIECE_SIZE - 1) / REVISION_PIECE_SIZE
        {
            bail!("file revision metadata is inconsistent")
        }
        self.with(|c| {
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?; let ts=now_ms();
            enforce_storage_quotas(
                &tx,
                &revision.vault_id,
                revision.user_id,
                revision.size,
                storage_quota_bytes,
                owner_storage_quota_bytes,
            )?;
            tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?)",
                params![revision.vault_id,revision.path,revision.relatedpath,revision.extension,revision.hash,revision.ctime,revision.mtime,revision.folder as i64,revision.deleted as i64,revision.size,revision.pieces,revision.device,revision.user_id,ts])?;
            let uid=tx.last_insert_rowid();
            if uid > MAX_JS_SAFE_INTEGER {
                bail!("revision UID exceeds the JavaScript safe-integer range")
            }
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
            if offset < 0 || !(0..=REVISION_PIECE_SIZE).contains(&length) {
                bail!("invalid revision content chunk bounds")
            }
            let end = offset
                .checked_add(length)
                .context("revision content chunk bounds overflow")?;
            let (declared_size, external, external_blob, inline, inline_blob): (
                i64,
                bool,
                bool,
                bool,
                bool,
            ) = c
                .query_row(
                    "SELECT r.size,
                        EXISTS(SELECT 1 FROM revision_content rc WHERE rc.uid=r.uid),
                        EXISTS(SELECT 1 FROM revision_content rc
                                WHERE rc.uid=r.uid AND typeof(rc.content)='blob'),
                        r.content IS NOT NULL,
                        typeof(r.content)='blob'
                   FROM revisions r WHERE r.uid=?",
                    [uid],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get::<_, i64>(1)? == 1,
                            row.get::<_, i64>(2)? == 1,
                            row.get::<_, i64>(3)? == 1,
                            row.get::<_, i64>(4)? == 1,
                        ))
                    },
                )
                .optional()?
                .context("revision content metadata not found")?;
            if end > declared_size {
                bail!("revision content chunk exceeds declared size")
            }
            if external != external_blob || inline != inline_blob || external == inline {
                bail!("revision content storage is missing, duplicated, or not a BLOB")
            }

            // SQL substr() first materializes the complete BLOB. That makes a
            // 2 MiB pull allocate as much as the configured per-file maximum.
            // Incremental BLOB I/O reads only the bounded wire piece instead.
            let table = if external {
                "revision_content"
            } else {
                "revisions"
            };
            let blob = c.blob_open("main", table, "content", uid, true)?;
            if i64::try_from(blob.len()).context("revision content length exceeds i64")?
                != declared_size
            {
                bail!("revision content length changed after validation")
            }
            let offset =
                usize::try_from(offset).context("revision content offset exceeds usize")?;
            let length =
                usize::try_from(length).context("revision content length exceeds usize")?;
            let mut chunk = vec![0; length];
            blob.read_at_exact(&mut chunk, offset)?;
            Ok(chunk)
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
    pub fn list_deleted_page(
        &self,
        vault: &str,
        suppress: bool,
        after: i64,
        limit: i64,
    ) -> Result<Vec<Revision>> {
        self.query_revisions(
            &format!(
                "SELECT {cols}
                   FROM revisions r
                   JOIN (
                       SELECT path,MAX(uid) uid
                         FROM revisions
                        WHERE vault_id=?
                        GROUP BY path
                   ) heads ON heads.uid=r.uid
                  WHERE r.deleted=1
                    AND r.uid>?
                    AND EXISTS (
                        SELECT 1 FROM revisions prior
                         WHERE prior.vault_id=r.vault_id
                           AND prior.path=r.path
                           AND prior.uid<r.uid
                           AND prior.deleted=0
                    )
                    AND (?=0 OR NOT EXISTS (
                        SELECT 1
                          FROM revisions live
                          JOIN (
                              SELECT path,MAX(uid) uid
                                FROM revisions
                               WHERE vault_id=r.vault_id
                               GROUP BY path
                          ) live_heads ON live_heads.uid=live.uid
                         WHERE live.deleted=0 AND live.relatedpath=r.path
                    ))
                  ORDER BY r.uid ASC
                  LIMIT ?",
                cols = prefixed_columns("r")
            ),
            vec![
                Value::Text(vault.into()),
                Value::Integer(after.max(0)),
                Value::Integer(suppress as i64),
                Value::Integer(limit.clamp(1, 1024)),
            ],
        )
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

    #[cfg(test)]
    pub fn restore(
        &self,
        vault: &str,
        uid: i64,
        device: &str,
        storage_quota_bytes: i64,
    ) -> Result<Option<Revision>> {
        self.restore_for_user(
            1,
            vault,
            uid,
            device,
            storage_quota_bytes,
            storage_quota_bytes,
        )
    }

    pub fn restore_for_user(
        &self,
        user_id: i64,
        vault: &str,
        uid: i64,
        device: &str,
        storage_quota_bytes: i64,
        owner_storage_quota_bytes: i64,
    ) -> Result<Option<Revision>> {
        self.with(|c|{
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let target:Option<(String,bool)>=tx.query_row("SELECT r.path,r.deleted FROM revisions r JOIN vaults v ON v.id=r.vault_id WHERE r.uid=? AND r.vault_id=? AND v.owner_user_id=?",params![uid,vault,user_id],|r|Ok((r.get(0)?,r.get::<_,i64>(1)?==1))).optional()?;
        let Some((path,deleted))=target else{return Ok(None)};
        let source_uid=if deleted {tx.query_row("SELECT uid FROM revisions WHERE vault_id=? AND path=? AND uid<? AND deleted=0 ORDER BY uid DESC LIMIT 1",params![vault,path,uid],|r|r.get(0)).optional()?}else{Some(uid)};
        let Some(source_uid)=source_uid else{return Ok(None)}; let ts=now_ms();
        let source_size:i64=tx.query_row("SELECT size FROM revisions WHERE uid=?",[source_uid],|r|r.get(0))?;
        enforce_storage_quotas(&tx, vault, user_id, source_size, storage_quota_bytes, owner_storage_quota_bytes)?;
        tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) SELECT vault_id,?,NULL,extension,hash,ctime,mtime,folder,0,size,pieces,NULL,?,?,? FROM revisions WHERE uid=?",params![path,device,user_id,ts,source_uid])?;
        let new_uid=tx.last_insert_rowid();
        if new_uid > MAX_JS_SAFE_INTEGER {
            bail!("revision UID exceeds the JavaScript safe-integer range")
        }
        if source_size>0 {
            tx.execute("INSERT INTO revision_content(uid,content) VALUES(?,zeroblob(?))",params![new_uid,source_size])?;
            let external=tx.query_row("SELECT EXISTS(SELECT 1 FROM revision_content WHERE uid=?)",[source_uid],|r|Ok(r.get::<_,i64>(0)?==1))?;
            let mut source=tx.blob_open("main",if external{"revision_content"}else{"revisions"},"content",source_uid,true)?;
            let mut destination=tx.blob_open("main","revision_content","content",new_uid,false)?;
            let copied=io::copy(&mut source,&mut destination)?;
            if copied!=source_size as u64 { bail!("restored content size changed during copy"); }
        }
        let restored = tx.query_row(
            &format!("SELECT {REVISION_COLUMNS} FROM revisions WHERE uid=?"),
            [new_uid],
            revision_row,
        )?;
        let notice_size = serde_json::to_vec(&PushNotice::from(restored.clone()))?.len();
        if notice_size > crate::server::MAX_EVENT_BYTES {
            bail!("restored revision metadata exceeds the bounded event size")
        }
        refresh_vault(&tx,vault,new_uid)?; tx.commit()?;
        Ok(Some(restored))
    })
    }

    #[cfg(test)]
    pub fn purge(&self, vault: &str) -> Result<()> {
        self.purge_for_user(1, vault)
    }
    pub fn purge_for_user(&self, user_id: i64, vault: &str) -> Result<()> {
        self.with(|c|{let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;let authorized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM vaults WHERE id=? AND owner_user_id=?)",params![vault,user_id],|r|Ok(r.get::<_,i64>(0)?==1))?;if !authorized{return Ok(())};tx.execute("DELETE FROM revisions WHERE vault_id=? AND uid NOT IN (SELECT MAX(uid) FROM revisions WHERE vault_id=? GROUP BY path)",params![vault,vault])?;let version: i64=tx.query_row("SELECT version FROM vaults WHERE id=?",[vault],|r|r.get(0))?;refresh_vault(&tx,vault,version)?;tx.commit()?;Ok(())})
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
fn stored_ciphertext_size(c: &Connection) -> Result<i64> {
    Ok(c.query_row(
        "SELECT ciphertext_bytes FROM temp.blackglass_runtime_storage_usage WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}

fn owner_stored_ciphertext_size(c: &Connection, user_id: i64) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COALESCE(SUM(r.size),0)
           FROM revisions r JOIN vaults v ON v.id=r.vault_id
          WHERE v.owner_user_id=?",
        [user_id],
        |row| row.get(0),
    )?)
}

fn initialize_runtime_storage_usage(c: &Connection) -> Result<()> {
    let ciphertext_bytes =
        c.query_row("SELECT COALESCE(SUM(size),0) FROM revisions", [], |row| {
            row.get::<_, i64>(0)
        })?;
    c.execute_batch(
        "CREATE TEMP TABLE blackglass_runtime_storage_usage(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            ciphertext_bytes INTEGER NOT NULL CHECK(ciphertext_bytes>=0)
         ) STRICT;
         CREATE TEMP TRIGGER blackglass_runtime_storage_insert
         AFTER INSERT ON main.revisions
         BEGIN
            UPDATE blackglass_runtime_storage_usage
               SET ciphertext_bytes=ciphertext_bytes+NEW.size
             WHERE singleton=1;
         END;
         CREATE TEMP TRIGGER blackglass_runtime_storage_delete
         AFTER DELETE ON main.revisions
         BEGIN
            UPDATE blackglass_runtime_storage_usage
               SET ciphertext_bytes=ciphertext_bytes-OLD.size
             WHERE singleton=1;
         END;",
    )?;
    c.execute(
        "INSERT INTO temp.blackglass_runtime_storage_usage(singleton,ciphertext_bytes) VALUES(1,?)",
        [ciphertext_bytes],
    )?;
    Ok(())
}

fn enforce_storage_quotas(
    c: &Connection,
    vault_id: &str,
    acting_user_id: i64,
    additional: i64,
    global_limit: i64,
    owner_limit: i64,
) -> Result<()> {
    if additional < 0 || global_limit < 0 || owner_limit < 0 {
        bail!("invalid stored ciphertext quota accounting input")
    }
    let owner_user_id = c
        .query_row(
            "SELECT owner_user_id FROM vaults WHERE id=? AND owner_user_id=?",
            params![vault_id, acting_user_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .context("vault is unavailable")?;
    // Zero-byte tombstones and folder metadata remain available while over
    // quota so an owner can delete and purge data to recover.
    if additional == 0 {
        return Ok(());
    }
    if global_limit == 0 || owner_limit == 0 {
        return Err(StorageQuotaExceeded.into());
    }
    let global_used = stored_ciphertext_size(c)?;
    let owner_used = owner_stored_ciphertext_size(c, owner_user_id)?;
    if global_used > global_limit
        || additional > global_limit - global_used
        || owner_used > owner_limit
        || additional > owner_limit - owner_used
    {
        return Err(StorageQuotaExceeded.into());
    }
    Ok(())
}

fn add_revision(
    c: &mut Connection,
    r: &NewRevision,
    content: Option<&[u8]>,
    storage_quota_bytes: i64,
    owner_storage_quota_bytes: i64,
) -> Result<Revision> {
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    enforce_storage_quotas(
        &tx,
        &r.vault_id,
        r.user_id,
        r.size,
        storage_quota_bytes,
        owner_storage_quota_bytes,
    )?;
    let ts = now_ms();
    tx.execute("INSERT INTO revisions(vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,content,device,user_id,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",params![r.vault_id,r.path,r.relatedpath,r.extension,r.hash,r.ctime,r.mtime,r.folder as i64,r.deleted as i64,r.size,r.pieces,content,r.device,r.user_id,ts])?;
    let uid = tx.last_insert_rowid();
    if uid > MAX_JS_SAFE_INTEGER {
        bail!("revision UID exceeds the JavaScript safe-integer range")
    }
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

#[cfg(test)]
fn test_initial_user() -> InitialUser {
    static PASSWORD_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    InitialUser::new(
        "owner@example.test",
        "Test owner",
        PASSWORD_HASH.get_or_init(|| auth::hash_password("test-password").unwrap()),
    )
    .unwrap()
}

fn migrate(c: &Connection, initial_user: Option<&InitialUser>) -> Result<()> {
    let versions = if table_exists(c, "schema_migrations")? {
        migration_versions(c)?
    } else {
        Vec::new()
    };
    reject_newer_migrations(&versions)?;
    if !SUPPORTED_MIGRATIONS.starts_with(&versions) {
        bail!(
            "unsupported Blackglass migration history: expected a prefix of {:?}, found {:?}",
            SUPPORTED_MIGRATIONS,
            versions
        )
    }
    for version in SUPPORTED_MIGRATIONS.iter().skip(versions.len()).copied() {
        if version == 5 {
            apply_v5_migration(
                c,
                initial_user.context("schema v5 migration requires an initial owner")?,
            )?;
            continue;
        }
        let sql = match version {
            1 => MIGRATION_1_SQL,
            2 => MIGRATION_2_SQL,
            3 => MIGRATION_3_SQL,
            4 => MIGRATION_4_SQL,
            _ => bail!("no implementation for database migration {version}"),
        };
        apply_migration(c, version, sql)?;
    }
    Ok(())
}

const MIGRATION_1_SQL: &str = "
    CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY,name TEXT NOT NULL,keyhash TEXT,salt TEXT,host TEXT NOT NULL,region TEXT NOT NULL,encryption_version INTEGER NOT NULL,size INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,password TEXT,version INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS revisions(uid INTEGER PRIMARY KEY AUTOINCREMENT,vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,path TEXT NOT NULL,relatedpath TEXT,extension TEXT NOT NULL,hash TEXT NOT NULL,ctime INTEGER NOT NULL,mtime INTEGER NOT NULL,folder INTEGER NOT NULL,deleted INTEGER NOT NULL,size INTEGER NOT NULL,pieces INTEGER NOT NULL,content BLOB,device TEXT NOT NULL,user_id INTEGER NOT NULL,ts INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS revisions_vault_uid ON revisions(vault_id,uid);
    CREATE INDEX IF NOT EXISTS revisions_vault_path ON revisions(vault_id,path,uid);
    UPDATE revisions SET ts=CASE WHEN mtime>0 THEN mtime ELSE unixepoch()*1000 END WHERE ts=0;
    UPDATE vaults SET version=COALESCE((SELECT MAX(uid) FROM revisions WHERE vault_id=vaults.id),version,0) WHERE version=0;
";
const MIGRATION_2_SQL: &str = "
    CREATE TABLE revision_content(uid INTEGER PRIMARY KEY REFERENCES revisions(uid) ON DELETE CASCADE,content BLOB NOT NULL);
    CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER);
    CREATE INDEX sessions_expiry ON sessions(expires_at);
";
// Version 3 shipped without schema objects. Never rewrite applied migrations.
const MIGRATION_3_SQL: &str = "";
// Version 4 persists bounded recovery markers so an exact client holding a
// retired vault identity receives the renderer's required `Vault not found`
// signal even though restore also invalidates every bearer session.
const MIGRATION_4_SQL: &str = "
    CREATE TABLE retired_vaults(
        id TEXT PRIMARY KEY,
        retired_at INTEGER NOT NULL
    );
";

const MIGRATION_5_AFTER_USER_SQL: &str = "
    CREATE TABLE vaults_v5(
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
        version INTEGER NOT NULL DEFAULT 0,
        owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE NO ACTION
    );
    INSERT INTO vaults_v5(
        id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id
    ) SELECT id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,1
        FROM vaults;
    CREATE TABLE revisions_v5(
        uid INTEGER PRIMARY KEY AUTOINCREMENT,
        vault_id TEXT NOT NULL REFERENCES vaults_v5(id) ON DELETE CASCADE,
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
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
        ts INTEGER NOT NULL DEFAULT 0
    );
    INSERT INTO revisions_v5(
        uid,vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,
        content,device,user_id,ts
    ) SELECT uid,vault_id,path,relatedpath,extension,hash,ctime,mtime,folder,deleted,size,pieces,
        content,device,1,ts FROM revisions;
    CREATE TABLE sessions_v5(
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER
    );
    INSERT INTO sessions_v5(token_hash,user_id,created_at,expires_at,revoked_at)
        SELECT token_hash,1,created_at,expires_at,revoked_at FROM sessions;
    CREATE TABLE retired_vaults_v5(
        id TEXT PRIMARY KEY,
        owner_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE NO ACTION,
        retired_at INTEGER NOT NULL
    );
    INSERT INTO retired_vaults_v5(id,owner_user_id,retired_at)
        SELECT id,1,retired_at FROM retired_vaults;

    DROP TABLE sessions;
    DROP TABLE revisions;
    DROP TABLE vaults;
    DROP TABLE retired_vaults;
    ALTER TABLE vaults_v5 RENAME TO vaults;
    ALTER TABLE revisions_v5 RENAME TO revisions;
    ALTER TABLE sessions_v5 RENAME TO sessions;
    ALTER TABLE retired_vaults_v5 RENAME TO retired_vaults;

    CREATE INDEX vaults_owner ON vaults(owner_user_id,created,id);
    CREATE INDEX revisions_vault_uid ON revisions(vault_id,uid);
    CREATE INDEX revisions_vault_path ON revisions(vault_id,path,uid);
    CREATE INDEX sessions_expiry ON sessions(expires_at);
    CREATE INDEX sessions_user ON sessions(user_id,expires_at);
    CREATE INDEX retired_vaults_owner ON retired_vaults(owner_user_id,retired_at,id);

    DELETE FROM sqlite_sequence
     WHERE name IN ('users','vaults_v5','revisions','revisions_v5','sessions_v5','retired_vaults_v5');
    INSERT INTO sqlite_sequence(name,seq) VALUES('users',1);
    INSERT INTO sqlite_sequence(name,seq)
        SELECT 'revisions',COALESCE(MAX(uid),0) FROM revisions;
";

fn apply_migration(c: &Connection, version: i64, sql: &str) -> Result<()> {
    let tx = c.unchecked_transaction()?;
    tx.execute_batch(sql)?;
    tx.execute(
        "INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)",
        params![version, now_ms()],
    )?;
    verify_schema_at_version(&tx, version)?;
    tx.commit()?;
    Ok(())
}

fn apply_v5_migration(c: &Connection, initial_user: &InitialUser) -> Result<()> {
    c.pragma_update(None, "foreign_keys", "OFF")?;
    let result = (|| {
        let tx = c.unchecked_transaction()?;
        tx.execute_batch(
            "CREATE TABLE users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_canonical TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );",
        )?;
        let now = now_ms();
        tx.execute(
            "INSERT INTO users(
                id,email_canonical,email,name,password_hash,status,created_at,updated_at
             ) VALUES(1,?,?,?,?, 'active',?,?)",
            params![
                initial_user.email_canonical,
                initial_user.email,
                initial_user.name,
                initial_user.password_hash,
                now,
                now
            ],
        )?;
        tx.execute_batch(MIGRATION_5_AFTER_USER_SQL)?;
        tx.execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES(5,?)",
            [now],
        )?;
        verify_schema_at_version(&tx, 5)?;
        tx.commit()?;
        Ok(())
    })();
    let foreign_keys = c.pragma_update(None, "foreign_keys", "ON");
    match (result, foreign_keys) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error.into()),
    }
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
    let version = verify_recorded_schema(c)?;
    if version != CURRENT_SCHEMA_VERSION {
        bail!(
            "database schema version {version} requires offline migration to version {CURRENT_SCHEMA_VERSION}; use `blackglass-server migrate <source> <new-database>`"
        )
    }
    Ok(())
}

fn verify_recorded_schema(c: &Connection) -> Result<i64> {
    if !table_exists(c, "schema_migrations")? {
        bail!("database has no Blackglass migration metadata")
    }
    let versions = migration_versions(c)?;
    reject_newer_migrations(&versions)?;
    if versions.is_empty() || !SUPPORTED_MIGRATIONS.starts_with(&versions) {
        bail!(
            "unsupported Blackglass migration history: expected a non-empty prefix of {:?}, found {:?}",
            SUPPORTED_MIGRATIONS,
            versions
        )
    }
    let version = *versions.last().unwrap();
    verify_schema_at_version(c, version)?;
    Ok(version)
}

fn verify_schema_at_version(c: &Connection, version: i64) -> Result<()> {
    match version {
        1 => {
            verify_v1_schema(c)?;
            verify_foreign_keys(c)?;
            verify_logical_invariants(c, false, false)?;
        }
        2 => {
            verify_blackglass_schema(c)?;
            verify_foreign_keys(c)?;
            verify_logical_invariants(c, true, false)?;
        }
        3 => {
            verify_blackglass_schema(c)?;
            verify_foreign_keys(c)?;
            verify_logical_invariants(c, true, false)?;
        }
        4 => {
            verify_v4_schema(c)?;
            verify_foreign_keys(c)?;
            verify_logical_invariants(c, true, false)?;
        }
        5 => {
            verify_v5_schema(c)?;
            verify_foreign_keys(c)?;
            verify_logical_invariants(c, true, true)?;
        }
        _ => bail!("no validator for database schema version {version}"),
    }
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
    with_new_database(destination, "restore destination", |target| {
        run_online_backup(&src, target)?;
        set_portable_journal(target)?;
        verify_connection(target).context("copied restore source validation failed")?;
        rotate_recovery_epoch(target)?;
        verify_connection(target)
    })
}

#[cfg(test)]
pub fn migrate_versioned_database_with_initial_user(
    source: &Path,
    destination: &Path,
    initial_user: &InitialUser,
) -> Result<()> {
    let _state_lock = crate::server::acquire_database_lock(source)?;
    migrate_versioned_database_under_lock(source, destination, initial_user)
}

pub(crate) fn migrate_versioned_database_under_lock(
    source: &Path,
    destination: &Path,
    initial_user: &InitialUser,
) -> Result<()> {
    let source = open_existing_read_only(source, "versioned migration source")?;
    verify_sqlite_integrity(&source).context("versioned migration source validation failed")?;
    let source_version =
        verify_recorded_schema(&source).context("versioned migration source validation failed")?;
    if source_version == CURRENT_SCHEMA_VERSION {
        bail!(
            "database is already at schema version {CURRENT_SCHEMA_VERSION}; use `backup` for a byte-preserving copy or `restore` to establish a new recovery epoch"
        )
    }

    with_new_database(destination, "versioned migration destination", |target| {
        run_online_backup(&source, target)?;
        verify_sqlite_integrity(target).context("copied migration source validation failed")?;
        verify_recorded_schema(target).context("copied migration source validation failed")?;
        target.pragma_update(None, "foreign_keys", "ON")?;
        migrate(target, Some(initial_user))?;
        if source_version < 3 {
            rotate_recovery_epoch(target)?;
        }
        set_portable_journal(target)?;
        verify_connection(target)
    })
}

#[cfg(test)]
pub fn migrate_versioned_database(source: &Path, destination: &Path) -> Result<()> {
    migrate_versioned_database_with_initial_user(source, destination, &test_initial_user())
}

fn copy_database(source: &Connection, destination: &Path, label: &str) -> Result<()> {
    with_new_database(destination, label, |dst| {
        run_online_backup(source, dst)?;
        set_portable_journal(dst)?;
        verify_connection(dst)
    })
}

pub fn migrate_legacy_database_with_initial_user(
    source: &Path,
    destination: &Path,
    initial_user: &InitialUser,
) -> Result<()> {
    let source = open_existing_read_only(source, "legacy migration source")?;
    verify_legacy_connection(&source).context("legacy migration source validation failed")?;

    with_new_database(destination, "legacy migration destination", |target| {
        run_online_backup(&source, target)?;
        verify_legacy_connection(target).context("copied legacy database validation failed")?;
        validate_migration_history_for_upgrade(target)?;
        target.pragma_update(None, "foreign_keys", "ON")?;
        migrate(target, Some(initial_user))?;
        rotate_recovery_epoch(target)?;
        set_portable_journal(target)?;
        verify_connection(target)
    })
}

#[cfg(test)]
pub fn migrate_legacy_database(source: &Path, destination: &Path) -> Result<()> {
    migrate_legacy_database_with_initial_user(source, destination, &test_initial_user())
}

/// Establish a new recovery epoch after restoring or upgrading a copied
/// database. Vault IDs are protocol identities, so rotating them prevents a
/// stale device whose revision cursor is ahead of the restored history from
/// silently skipping data even after the new server's global UID counter has
/// overtaken that cursor. Sessions are cleared in the same transaction so a
/// token captured in an older backup can never be resurrected by restore.
fn rotate_recovery_epoch(connection: &mut Connection) -> Result<usize> {
    let vault_ids = {
        let mut query = connection.prepare("SELECT id,owner_user_id FROM vaults ORDER BY id")?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut reserved = {
        let mut query =
            connection.prepare("SELECT id FROM vaults UNION SELECT id FROM retired_vaults")?;
        query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?
    };
    let replacements = vault_ids
        .into_iter()
        .map(|(old_id, owner_user_id)| {
            let new_id = loop {
                let candidate = Uuid::new_v4().to_string();
                if reserved.insert(candidate.clone()) {
                    break candidate;
                }
            };
            (old_id, new_id, owner_user_id)
        })
        .collect::<Vec<_>>();

    let transaction = connection.transaction()?;
    let retirement_time = now_ms();
    let mut replacements_per_owner = std::collections::HashMap::<i64, i64>::new();
    for (_, _, owner_user_id) in &replacements {
        *replacements_per_owner.entry(*owner_user_id).or_default() += 1;
    }
    for (owner_user_id, replacement_count) in replacements_per_owner {
        if replacement_count > MAX_RETIRED_VAULTS_PER_OWNER {
            bail!("owner recovery set exceeds retired vault marker limit")
        }
        transaction.execute(
            "DELETE FROM retired_vaults
              WHERE owner_user_id=? AND id IN (
                  SELECT id FROM retired_vaults WHERE owner_user_id=?
                   ORDER BY retired_at DESC,id DESC
                   LIMIT -1 OFFSET ?
              )",
            params![
                owner_user_id,
                owner_user_id,
                MAX_RETIRED_VAULTS_PER_OWNER - replacement_count
            ],
        )?;
    }
    let global_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM retired_vaults", [], |row| row.get(0))?;
    if global_count + replacements.len() as i64 > MAX_RETIRED_VAULTS {
        bail!("recovery would exceed the global retired vault marker limit")
    }
    for (old_id, new_id, owner_user_id) in &replacements {
        transaction.execute(
            "INSERT OR REPLACE INTO retired_vaults(id,owner_user_id,retired_at) VALUES(?,?,?)",
            params![old_id, owner_user_id, retirement_time],
        )?;
        transaction.execute(
            "INSERT INTO vaults(
                 id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id
             )
             SELECT ?,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id
               FROM vaults WHERE id=?",
            params![new_id, old_id],
        )?;
        transaction.execute(
            "UPDATE revisions SET vault_id=? WHERE vault_id=?",
            params![new_id, old_id],
        )?;
        transaction.execute("DELETE FROM vaults WHERE id=?", [old_id])?;
    }
    transaction.execute("DELETE FROM sessions", [])?;
    transaction.commit()?;
    Ok(replacements.len())
}

fn retire_vault_identity(
    transaction: &rusqlite::Transaction<'_>,
    vault_id: &str,
    retired_at: i64,
) -> Result<()> {
    let owner_user_id: i64 = transaction.query_row(
        "SELECT owner_user_id FROM vaults WHERE id=?",
        [vault_id],
        |row| row.get(0),
    )?;
    // Prune before inserting so a clock rollback or a future-dated marker
    // cannot push the table over its verified hard bound.
    transaction.execute(
        "DELETE FROM retired_vaults
          WHERE owner_user_id=? AND id IN (
              SELECT id FROM retired_vaults WHERE owner_user_id=?
               ORDER BY retired_at DESC,id DESC
               LIMIT -1 OFFSET ?
          )",
        params![
            owner_user_id,
            owner_user_id,
            MAX_RETIRED_VAULTS_PER_OWNER - 1
        ],
    )?;
    let global_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM retired_vaults", [], |row| row.get(0))?;
    if global_count >= MAX_RETIRED_VAULTS {
        bail!("retired vault marker limit reached")
    }
    transaction.execute(
        "INSERT OR REPLACE INTO retired_vaults(id,owner_user_id,retired_at) VALUES(?,?,?)",
        params![vault_id, owner_user_id, retired_at],
    )?;
    Ok(())
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

fn open_admin_connection(path: &Path) -> Result<Connection> {
    // SQLITE_OPEN_URI is deliberately absent above, so URI metacharacters in
    // configured paths cannot become SQLite connection options.
    let connection = open_existing_read_only(path, "admin snapshot database")?;
    connection.busy_timeout(std::time::Duration::from_millis(50))?;
    connection.pragma_update(None, "query_only", "ON")?;
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
    reject_hardlinked_file(&metadata, path, label)?;
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
    sync_parent_directory(path)?;
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
    Db {
        connection: Arc::new(Mutex::new(connection)),
        path: Arc::new(path.to_path_buf()),
    }
    .revoke_all_sessions()
}

pub fn rebind_data_host(path: &Path, new_host: &str, backup: &Path) -> Result<usize> {
    crate::config::validate_public_data_host(new_host)?;
    let _state_lock = crate::server::acquire_database_lock(path)?;
    backup_database(path, backup).context("pre-rebind backup failed")?;

    let mut connection = open_existing_read_write(path, "data-host rebind database")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    verify_connection(&connection).context("data-host rebind database validation failed")?;
    let transaction = connection.transaction()?;
    let changed = transaction.execute(
        "UPDATE vaults SET host=? WHERE host<>?",
        params![new_host, new_host],
    )?;
    transaction.commit()?;
    verify_connection(&connection).context("post-rebind database validation failed")?;
    Ok(changed)
}

pub fn purge_deleted_history(path: &Path, vault: &str, backup: &Path) -> Result<usize> {
    if vault.is_empty() || vault.len() > 64 {
        bail!("vault ID must be between 1 and 64 bytes")
    }
    let _state_lock = crate::server::acquire_database_lock(path)?;
    backup_database(path, backup).context("pre-purge backup failed")?;
    let mut connection = open_existing_read_write(path, "deleted-history purge database")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    verify_connection(&connection).context("deleted-history purge database validation failed")?;
    let transaction = connection.transaction()?;
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM vaults WHERE id=?)",
        [vault],
        |row| row.get(0),
    )?;
    if exists != 1 {
        bail!("vault not found")
    }
    let changed = transaction.execute(
        "WITH heads(path,uid) AS (
             SELECT history.path,MAX(history.uid)
               FROM revisions history
              WHERE history.vault_id=?
              GROUP BY history.path
         ), deleted_heads(path,uid) AS (
             SELECT heads.path,heads.uid
               FROM heads
               JOIN revisions head ON head.uid=heads.uid
              WHERE head.deleted=1
         )
         DELETE FROM revisions
          WHERE vault_id=?
            AND EXISTS(
                SELECT 1 FROM deleted_heads
                 WHERE deleted_heads.path=revisions.path
                   AND deleted_heads.uid<>revisions.uid
            )",
        params![vault, vault],
    )?;
    let version: i64 =
        transaction.query_row("SELECT version FROM vaults WHERE id=?", [vault], |row| {
            row.get(0)
        })?;
    refresh_vault(&transaction, vault, version)?;
    transaction.commit()?;
    verify_connection(&connection).context("post-purge database validation failed")?;
    Ok(changed)
}

fn verify_v1_schema(c: &Connection) -> Result<()> {
    verify_schema_objects(
        c,
        &[
            ("index", "revisions_vault_path", "revisions"),
            ("index", "revisions_vault_uid", "revisions"),
            ("index", "sqlite_autoindex_vaults_1", "vaults"),
            ("table", "revisions", "revisions"),
            ("table", "schema_migrations", "schema_migrations"),
            ("table", "sqlite_sequence", "sqlite_sequence"),
            ("table", "vaults", "vaults"),
        ],
        "Blackglass v1",
    )?;
    verify_exact_table(
        c,
        "schema_migrations",
        SCHEMA_MIGRATION_COLUMNS,
        "Blackglass v1",
    )?;
    verify_exact_table(c, "vaults", VAULT_COLUMNS, "Blackglass v1")?;
    verify_exact_table(c, "revisions", REVISION_TABLE_COLUMNS, "Blackglass v1")?;
    verify_exact_table(
        c,
        "sqlite_sequence",
        SQLITE_SEQUENCE_COLUMNS,
        "Blackglass v1",
    )?;
    verify_exact_indexes(c, "schema_migrations", &[], "Blackglass v1")?;
    verify_exact_indexes(
        c,
        "vaults",
        &[IndexExpectation::primary_key(
            "sqlite_autoindex_vaults_1",
            &["id"],
        )],
        "Blackglass v1",
    )?;
    verify_exact_indexes(
        c,
        "revisions",
        &[
            IndexExpectation::ordinary("revisions_vault_path", &["vault_id", "path", "uid"]),
            IndexExpectation::ordinary("revisions_vault_uid", &["vault_id", "uid"]),
        ],
        "Blackglass v1",
    )?;
    verify_exact_indexes(c, "sqlite_sequence", &[], "Blackglass v1")?;
    verify_exact_foreign_keys(c, "schema_migrations", &[], "Blackglass v1")?;
    verify_exact_foreign_keys(c, "vaults", &[], "Blackglass v1")?;
    verify_exact_foreign_keys(
        c,
        "revisions",
        &[ForeignKeyExpectation::cascade("vaults", "vault_id", "id")],
        "Blackglass v1",
    )?;
    verify_exact_foreign_keys(c, "sqlite_sequence", &[], "Blackglass v1")?;
    Ok(())
}

fn verify_blackglass_schema(c: &Connection) -> Result<()> {
    verify_blackglass_schema_with_recovery_epoch(c, false)
}

fn verify_v4_schema(c: &Connection) -> Result<()> {
    verify_blackglass_schema_with_recovery_epoch(c, true)
}

fn verify_v5_schema(c: &Connection) -> Result<()> {
    verify_schema_objects(
        c,
        &[
            ("index", "retired_vaults_owner", "retired_vaults"),
            ("index", "revisions_vault_path", "revisions"),
            ("index", "revisions_vault_uid", "revisions"),
            ("index", "sessions_expiry", "sessions"),
            ("index", "sessions_user", "sessions"),
            (
                "index",
                "sqlite_autoindex_retired_vaults_1",
                "retired_vaults",
            ),
            ("index", "sqlite_autoindex_sessions_1", "sessions"),
            ("index", "sqlite_autoindex_users_1", "users"),
            ("index", "sqlite_autoindex_vaults_1", "vaults"),
            ("index", "vaults_owner", "vaults"),
            ("table", "retired_vaults", "retired_vaults"),
            ("table", "revision_content", "revision_content"),
            ("table", "revisions", "revisions"),
            ("table", "schema_migrations", "schema_migrations"),
            ("table", "sessions", "sessions"),
            ("table", "sqlite_sequence", "sqlite_sequence"),
            ("table", "users", "users"),
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
    verify_exact_table(c, "users", USER_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "vaults", VAULT_V5_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "revisions", REVISION_TABLE_COLUMNS, "Blackglass")?;
    verify_exact_table(
        c,
        "revision_content",
        REVISION_CONTENT_COLUMNS,
        "Blackglass",
    )?;
    verify_exact_table(c, "sessions", SESSION_V5_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "retired_vaults", RETIRED_VAULT_V5_COLUMNS, "Blackglass")?;
    verify_exact_table(c, "sqlite_sequence", SQLITE_SEQUENCE_COLUMNS, "Blackglass")?;

    verify_exact_indexes(c, "schema_migrations", &[], "Blackglass")?;
    verify_exact_indexes(
        c,
        "users",
        &[IndexExpectation::unique(
            "sqlite_autoindex_users_1",
            &["email_canonical"],
        )],
        "Blackglass",
    )?;
    verify_exact_indexes(
        c,
        "vaults",
        &[
            IndexExpectation::primary_key("sqlite_autoindex_vaults_1", &["id"]),
            IndexExpectation::ordinary("vaults_owner", &["owner_user_id", "created", "id"]),
        ],
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
            IndexExpectation::ordinary("sessions_user", &["user_id", "expires_at"]),
            IndexExpectation::primary_key("sqlite_autoindex_sessions_1", &["token_hash"]),
        ],
        "Blackglass",
    )?;
    verify_exact_indexes(
        c,
        "retired_vaults",
        &[
            IndexExpectation::ordinary(
                "retired_vaults_owner",
                &["owner_user_id", "retired_at", "id"],
            ),
            IndexExpectation::primary_key("sqlite_autoindex_retired_vaults_1", &["id"]),
        ],
        "Blackglass",
    )?;
    verify_exact_indexes(c, "sqlite_sequence", &[], "Blackglass")?;

    verify_exact_foreign_keys(c, "schema_migrations", &[], "Blackglass")?;
    verify_exact_foreign_keys(c, "users", &[], "Blackglass")?;
    verify_exact_foreign_keys(
        c,
        "vaults",
        &[ForeignKeyExpectation::no_action(
            "users",
            "owner_user_id",
            "id",
        )],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(
        c,
        "revisions",
        &[
            ForeignKeyExpectation::no_action("users", "user_id", "id"),
            ForeignKeyExpectation::cascade("vaults", "vault_id", "id"),
        ],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(
        c,
        "revision_content",
        &[ForeignKeyExpectation::cascade("revisions", "uid", "uid")],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(
        c,
        "sessions",
        &[ForeignKeyExpectation::cascade("users", "user_id", "id")],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(
        c,
        "retired_vaults",
        &[ForeignKeyExpectation::no_action(
            "users",
            "owner_user_id",
            "id",
        )],
        "Blackglass",
    )?;
    verify_exact_foreign_keys(c, "sqlite_sequence", &[], "Blackglass")?;
    Ok(())
}

fn verify_blackglass_schema_with_recovery_epoch(
    c: &Connection,
    recovery_epoch: bool,
) -> Result<()> {
    let mut objects = vec![
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
    ];
    if recovery_epoch {
        objects.push((
            "index",
            "sqlite_autoindex_retired_vaults_1",
            "retired_vaults",
        ));
        objects.push(("table", "retired_vaults", "retired_vaults"));
        objects.sort_unstable();
    }
    verify_schema_objects(c, &objects, "Blackglass")?;
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
    if recovery_epoch {
        verify_exact_table(c, "retired_vaults", RETIRED_VAULT_COLUMNS, "Blackglass")?;
    }
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
    if recovery_epoch {
        verify_exact_indexes(
            c,
            "retired_vaults",
            &[IndexExpectation::primary_key(
                "sqlite_autoindex_retired_vaults_1",
                &["id"],
            )],
            "Blackglass",
        )?;
    }
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
    if recovery_epoch {
        verify_exact_foreign_keys(c, "retired_vaults", &[], "Blackglass")?;
    }
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
    verify_logical_invariants(c, false, false)
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
const USER_COLUMNS: &[ExpectedColumn] = &[
    ("id", "INTEGER", false, None, 1),
    ("email_canonical", "TEXT", true, None, 0),
    ("email", "TEXT", true, None, 0),
    ("name", "TEXT", true, None, 0),
    ("password_hash", "TEXT", true, None, 0),
    ("status", "TEXT", true, None, 0),
    ("created_at", "INTEGER", true, None, 0),
    ("updated_at", "INTEGER", true, None, 0),
];
const VAULT_V5_COLUMNS: &[ExpectedColumn] = &[
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
    ("owner_user_id", "INTEGER", true, None, 0),
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
const SESSION_V5_COLUMNS: &[ExpectedColumn] = &[
    ("token_hash", "TEXT", false, None, 1),
    ("user_id", "INTEGER", true, None, 0),
    ("created_at", "INTEGER", true, None, 0),
    ("expires_at", "INTEGER", true, None, 0),
    ("revoked_at", "INTEGER", false, None, 0),
];
const RETIRED_VAULT_COLUMNS: &[ExpectedColumn] = &[
    ("id", "TEXT", false, None, 1),
    ("retired_at", "INTEGER", true, None, 0),
];
const RETIRED_VAULT_V5_COLUMNS: &[ExpectedColumn] = &[
    ("id", "TEXT", false, None, 1),
    ("owner_user_id", "INTEGER", true, None, 0),
    ("retired_at", "INTEGER", true, None, 0),
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
    let creation_sql: String = c.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name=?",
        [table],
        |row| row.get(0),
    )?;
    let normalized_sql = creation_sql.to_ascii_uppercase();
    for unsupported in ["CHECK", "COLLATE", "DEFERRABLE", "WITHOUT ROWID", "STRICT"] {
        if normalized_sql.contains(unsupported) {
            bail!("invalid {label} table {table}: unsupported schema clause {unsupported}")
        }
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

    const fn unique(name: &'static str, columns: &'static [&'static str]) -> Self {
        Self {
            name,
            unique: true,
            origin: "u",
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

    const fn no_action(parent: &'static str, from: &'static str, to: &'static str) -> Self {
        Self {
            parent,
            from,
            to,
            on_update: "NO ACTION",
            on_delete: "NO ACTION",
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

fn verify_logical_invariants(
    c: &Connection,
    external_content: bool,
    multi_user: bool,
) -> Result<()> {
    if multi_user {
        reject_invalid_row(
            c,
            &format!(
                "SELECT CAST(id AS TEXT) FROM users WHERE
                    typeof(id) <> 'integer' OR id NOT BETWEEN 1 AND {max_safe} OR
                    typeof(email_canonical) <> 'text' OR
                    length(email_canonical) NOT BETWEEN 3 AND {max_email} OR
                    email_canonical GLOB '*[^!-~]*' OR
                    length(email_canonical)-length(replace(email_canonical,'@','')) <> 1 OR
                    instr(email_canonical,'@') IN (1,length(email_canonical)) OR
                    email_canonical <> lower(email_canonical) OR
                    typeof(email) <> 'text' OR length(email) NOT BETWEEN 3 AND {max_email} OR
                    email GLOB '*[^!-~]*' OR lower(email) <> email_canonical OR
                    typeof(name) <> 'text' OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND {max_name} OR
                    typeof(password_hash) <> 'text' OR length(password_hash) NOT BETWEEN 1 AND 512 OR
                    typeof(status) <> 'text' OR status NOT IN ('active','disabled') OR
                    typeof(created_at) <> 'integer' OR created_at NOT BETWEEN 0 AND {max_safe} OR
                    typeof(updated_at) <> 'integer' OR updated_at NOT BETWEEN created_at AND {max_safe}
                 LIMIT 1",
                max_safe = MAX_JS_SAFE_INTEGER,
                max_email = auth::MAX_EMAIL_BYTES,
                max_name = auth::MAX_DISPLAY_NAME_BYTES,
            ),
            "user field types and ranges",
        )?;
        reject_invalid_row(
            c,
            &format!(
                "SELECT CAST(COUNT(*) AS TEXT) FROM users HAVING COUNT(*) > {}",
                MAX_USERS
            ),
            "user count limit",
        )?;
        let mut hashes = c.prepare("SELECT password_hash FROM users ORDER BY id LIMIT ?")?;
        for hash in hashes.query_map([MAX_USERS], |row| row.get::<_, String>(0))? {
            if !auth::password_hash_is_production_grade(&hash?) {
                bail!("database logical invariant failed (user password hash policy)")
            }
        }
    }
    let owner_predicate = if multi_user {
        format!(
            " OR typeof(owner_user_id) <> 'integer' OR owner_user_id NOT BETWEEN 1 AND {}",
            MAX_JS_SAFE_INTEGER
        )
    } else {
        String::new()
    };
    reject_invalid_row(
        c,
        &format!(
            "SELECT id FROM vaults WHERE
            typeof(id) <> 'text' OR length(id) NOT BETWEEN 1 AND 64 OR
            typeof(name) <> 'text' OR length(name) NOT BETWEEN 1 AND 256 OR
            (keyhash IS NOT NULL AND typeof(keyhash) <> 'text') OR
            (salt IS NOT NULL AND typeof(salt) <> 'text') OR
            typeof(host) <> 'text' OR length(host) NOT BETWEEN 1 AND 255 OR
            typeof(region) <> 'text' OR length(region) NOT BETWEEN 1 AND 256 OR
            typeof(encryption_version) <> 'integer' OR encryption_version NOT BETWEEN 0 AND 3 OR
            typeof(size) <> 'integer' OR size NOT BETWEEN 0 AND {max_safe} OR
            typeof(created) <> 'integer' OR created NOT BETWEEN 0 AND {max_safe} OR
            (password IS NOT NULL AND typeof(password) <> 'text') OR
            typeof(version) <> 'integer' OR version NOT BETWEEN 0 AND {max_safe}
            {owner_predicate}
         LIMIT 1",
            max_safe = MAX_JS_SAFE_INTEGER,
        ),
        "vault field types and ranges",
    )?;
    reject_invalid_row(
        c,
        "SELECT id FROM vaults WHERE NOT (
            (
                password IS NULL AND
                keyhash IS NOT NULL AND typeof(keyhash) = 'text' AND
                length(keyhash) BETWEEN 1 AND 4096 AND
                salt IS NOT NULL AND typeof(salt) = 'text' AND
                length(salt) BETWEEN 1 AND 4096
            ) OR (
                password IS NOT NULL AND typeof(password) = 'text' AND
                length(password) = 64 AND password NOT GLOB '*[^0-9a-f]*' AND
                salt IS NOT NULL AND typeof(salt) = 'text' AND
                length(salt) = 32 AND salt NOT GLOB '*[^0-9a-f]*' AND
                (
                    keyhash IS NULL OR
                    (typeof(keyhash) = 'text' AND length(keyhash) BETWEEN 1 AND 4096)
                )
            )
         ) LIMIT 1",
        "vault encryption credential shape",
    )?;
    reject_invalid_row(
        c,
        &format!(
            "SELECT CAST(COUNT(*) AS TEXT) FROM vaults HAVING COUNT(*) > {}",
            MAX_VAULTS
        ),
        "vault count limit",
    )?;
    let user_id_predicate = if multi_user {
        format!("user_id NOT BETWEEN 1 AND {MAX_JS_SAFE_INTEGER}")
    } else {
        "user_id <> 1".to_owned()
    };
    let revision_metadata = format!(
        "SELECT CAST(uid AS TEXT) FROM revisions WHERE
            typeof(uid) <> 'integer' OR uid NOT BETWEEN 1 AND {max_safe} OR
            typeof(vault_id) <> 'text' OR length(vault_id) NOT BETWEEN 1 AND 64 OR
            typeof(path) <> 'text' OR length(path) NOT BETWEEN 1 AND 16384 OR
            (relatedpath IS NOT NULL AND (typeof(relatedpath) <> 'text' OR length(relatedpath) > 16384)) OR
            typeof(extension) <> 'text' OR length(extension) > 256 OR
            typeof(hash) <> 'text' OR length(hash) > 4096 OR
            typeof(ctime) <> 'integer' OR ctime NOT BETWEEN 0 AND {max_safe} OR
            typeof(mtime) <> 'integer' OR mtime NOT BETWEEN 0 AND {max_safe} OR
            typeof(folder) <> 'integer' OR folder NOT IN (0,1) OR
            typeof(deleted) <> 'integer' OR deleted NOT IN (0,1) OR
            typeof(size) <> 'integer' OR size NOT BETWEEN 0 AND {max_safe} OR
            typeof(pieces) <> 'integer' OR pieces < 0 OR
            pieces <> CASE WHEN size=0 THEN 0 ELSE (size + {overhead}) / {piece_size} END OR
            ((folder=1 OR deleted=1) AND (size <> 0 OR pieces <> 0)) OR
            (content IS NOT NULL AND typeof(content) <> 'blob') OR
            typeof(device) <> 'text' OR length(device) NOT BETWEEN 1 AND 256 OR
            typeof(user_id) <> 'integer' OR {user_id_predicate} OR
            typeof(ts) <> 'integer' OR ts NOT BETWEEN 0 AND {max_safe}
         LIMIT 1",
        overhead = REVISION_PIECE_SIZE - 1,
        piece_size = REVISION_PIECE_SIZE,
        max_safe = MAX_JS_SAFE_INTEGER,
    );
    reject_invalid_row(c, &revision_metadata, "revision metadata")?;
    let mut revisions = c.prepare(&format!("SELECT {REVISION_COLUMNS} FROM revisions"))?;
    let revisions = revisions.query_map([], revision_row)?;
    for revision in revisions {
        let notice = serde_json::to_vec(&PushNotice::from(revision?))?;
        if notice.len() > crate::server::MAX_EVENT_BYTES {
            bail!("revision notice exceeds the bounded wire size")
        }
    }

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
        &format!(
            "SELECT name FROM sqlite_sequence
              WHERE name NOT IN ({allowed_sequences}) OR typeof(seq) <> 'integer'
                 OR seq NOT BETWEEN 0 AND {}
              LIMIT 1",
            MAX_JS_SAFE_INTEGER,
            allowed_sequences = if multi_user {
                "'revisions','users'"
            } else {
                "'revisions'"
            },
        ),
        "revision sequence",
    )?;
    reject_invalid_row(
        c,
        "SELECT 'revisions' WHERE
           (SELECT COUNT(*) FROM sqlite_sequence WHERE name='revisions') > 1",
        "revision sequence uniqueness",
    )?;
    if multi_user {
        reject_invalid_row(
            c,
            "SELECT 'users' WHERE
               (SELECT COUNT(*) FROM sqlite_sequence WHERE name='users') <> 1",
            "user sequence uniqueness",
        )?;
        reject_invalid_row(
            c,
            "SELECT 'users' WHERE
               (SELECT seq FROM sqlite_sequence WHERE name='users') <
               COALESCE((SELECT MAX(id) FROM users),0)",
            "user sequence high-water mark",
        )?;
    }
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
            &format!(
                "SELECT CAST(version AS TEXT) FROM schema_migrations
              WHERE typeof(version) <> 'integer' OR
                    typeof(applied_at) <> 'integer' OR applied_at NOT BETWEEN 0 AND {}
              LIMIT 1",
                MAX_JS_SAFE_INTEGER
            ),
            "migration metadata",
        )?;
    }
    if table_exists(c, "sessions")? {
        let session_user_predicate = if multi_user {
            format!(
                "typeof(user_id) <> 'integer' OR user_id NOT BETWEEN 1 AND {} OR",
                MAX_JS_SAFE_INTEGER
            )
        } else {
            String::new()
        };
        reject_invalid_row(
            c,
            &format!(
                "SELECT token_hash FROM sessions
              WHERE {session_user_predicate}
                    typeof(token_hash) <> 'text' OR length(token_hash) <> 64 OR
                    token_hash GLOB '*[^0-9a-f]*' OR
                    typeof(created_at) <> 'integer' OR created_at NOT BETWEEN 0 AND {max_safe} OR
                    typeof(expires_at) <> 'integer' OR expires_at NOT BETWEEN 1 AND {max_safe} OR
                    expires_at <= created_at OR
                    (revoked_at IS NOT NULL AND
                     (typeof(revoked_at) <> 'integer' OR
                      revoked_at NOT BETWEEN created_at AND {max_safe}))
              LIMIT 1",
                max_safe = MAX_JS_SAFE_INTEGER
            ),
            "session token and timestamps",
        )?;
        reject_invalid_row(
            c,
            &format!(
                "SELECT CAST(COUNT(*) AS TEXT) FROM sessions HAVING COUNT(*) > {}",
                MAX_SESSIONS
            ),
            "session count limit",
        )?;
        if multi_user {
            reject_invalid_row(
                c,
                &format!(
                    "SELECT CAST(user_id AS TEXT) FROM sessions
                      WHERE revoked_at IS NULL AND expires_at > {now}
                      GROUP BY user_id HAVING COUNT(*) > {limit} LIMIT 1",
                    now = now_ms(),
                    limit = MAX_SESSIONS_PER_USER,
                ),
                "active session count per user",
            )?;
        }
    }
    if table_exists(c, "retired_vaults")? {
        let retired_owner_predicate = if multi_user {
            format!(
                "typeof(owner_user_id) <> 'integer' OR owner_user_id NOT BETWEEN 1 AND {} OR",
                MAX_JS_SAFE_INTEGER
            )
        } else {
            String::new()
        };
        reject_invalid_row(
            c,
            &format!(
                "SELECT id FROM retired_vaults
                  WHERE {retired_owner_predicate}
                        typeof(id) <> 'text' OR length(id) NOT BETWEEN 1 AND 64 OR
                        typeof(retired_at) <> 'integer' OR
                        retired_at NOT BETWEEN 0 AND {}
                  LIMIT 1",
                MAX_JS_SAFE_INTEGER
            ),
            "retired vault marker fields",
        )?;
        if multi_user {
            reject_invalid_row(
                c,
                &format!(
                    "SELECT CAST(owner_user_id AS TEXT) FROM retired_vaults
                      GROUP BY owner_user_id HAVING COUNT(*) > {} LIMIT 1",
                    MAX_RETIRED_VAULTS_PER_OWNER
                ),
                "retired vault marker count per owner",
            )?;
        }
        reject_invalid_row(
            c,
            &format!(
                "SELECT CAST(COUNT(*) AS TEXT) FROM retired_vaults
                  HAVING COUNT(*) > {}",
                MAX_RETIRED_VAULTS
            ),
            "retired vault marker count",
        )?;
        reject_invalid_row(
            c,
            "SELECT retired.id
               FROM retired_vaults retired
               JOIN vaults active ON active.id=retired.id
              LIMIT 1",
            "active and retired vault identities are disjoint",
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
    let mut removed = false;
    for candidate in std::iter::once(path.to_path_buf()).chain(sqlite_sidecars(path)) {
        match std::fs::remove_file(&candidate) {
            Ok(()) => removed = true,
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
    if first_error.is_none() && removed {
        sync_parent_directory(path)?;
    }
    first_error.map_or(Ok(()), Err)
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)
            .with_context(|| format!("open parent directory for sync: {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync parent directory: {}", parent.display()))?;
    }
    Ok(())
}

fn reject_hardlinked_file(metadata: &std::fs::Metadata, path: &Path, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            bail!(
                "{label} must have exactly one filesystem link: {}",
                path.display()
            )
        }
    }
    Ok(())
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

    #[test]
    fn admin_snapshot_uses_a_literal_query_only_connection_outside_writer_mutex() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin?mode=rw.sqlite");
        let database = Db::open(&path).unwrap();
        let admin = open_admin_connection(&path).unwrap();
        assert_eq!(
            admin
                .query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            admin
                .query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            50
        );
        assert!(admin.execute("CREATE TABLE forbidden(value)", []).is_err());
        let _writer_mutex = database.connection.lock().unwrap();
        assert_eq!(
            database
                .admin_snapshot("127.0.0.1:3003")
                .unwrap()
                .vault_count,
            0
        );
    }
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

    fn create_test_vault(database: &Db, id: &str) {
        database
            .create_vault(&Vault {
                id: id.into(),
                name: "Vault".into(),
                keyhash: Some("key".into()),
                salt: Some("salt".into()),
                host: "localhost:3003".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: None,
            })
            .unwrap();
    }

    fn test_file_revision(vault: &str, path: &str, size: i64) -> NewRevision {
        NewRevision {
            vault_id: vault.into(),
            path: path.into(),
            relatedpath: None,
            extension: "bin".into(),
            hash: format!("hash-{path}"),
            ctime: 1,
            mtime: 2,
            folder: false,
            deleted: false,
            size,
            pieces: (size + REVISION_PIECE_SIZE - 1) / REVISION_PIECE_SIZE,
            device: "test".into(),
            user_id: 1,
        }
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

    fn create_v1_database(path: &Path) {
        create_legacy_database(path);
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                 );
                 INSERT INTO schema_migrations(version,applied_at) VALUES(1,1);",
            )
            .unwrap();
        drop(connection);
        let connection = open_existing_read_only(path, "v1 test database").unwrap();
        assert_eq!(verify_recorded_schema(&connection).unwrap(), 1);
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
    fn runtime_startup_refuses_to_bootstrap_a_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.sqlite");
        let error = match Db::open_existing(&path) {
            Ok(_) => panic!("runtime startup initialized a missing database"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("initialize it offline"));
        assert!(!path.exists());
    }

    #[test]
    fn readiness_fails_fast_while_the_database_connection_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("ready.sqlite")).unwrap();
        let connection = database.connection.lock().unwrap();

        assert!(!database.ready());

        drop(connection);
        assert!(database.ready());
    }

    #[test]
    fn content_chunks_use_bounded_incremental_reads_for_external_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("external-content.sqlite")).unwrap();
        create_test_vault(&database, "vault");
        let content_len = REVISION_PIECE_SIZE as usize * 2 + 17;
        let content = (0..content_len)
            .map(|index| ((index * 31) % 251) as u8)
            .collect::<Vec<_>>();
        let staged = dir.path().join("staged-content");
        std::fs::write(&staged, &content).unwrap();
        let stored = database
            .add_file_revision(
                &test_file_revision("vault", "external", content_len as i64),
                &staged,
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();
        let piece = REVISION_PIECE_SIZE as usize;

        assert_eq!(
            database
                .content_chunk(stored.uid, 0, REVISION_PIECE_SIZE)
                .unwrap(),
            content[..piece]
        );
        assert_eq!(
            database
                .content_chunk(stored.uid, REVISION_PIECE_SIZE, REVISION_PIECE_SIZE)
                .unwrap(),
            content[piece..piece * 2]
        );
        assert_eq!(
            database
                .content_chunk(stored.uid, REVISION_PIECE_SIZE * 2, 17)
                .unwrap(),
            content[piece * 2..]
        );
        assert_eq!(
            database
                .content_chunk(stored.uid, content_len as i64, 0)
                .unwrap(),
            Vec::<u8>::new()
        );

        assert_error_contains(
            database.content_chunk(stored.uid, -1, 1),
            "invalid revision content chunk bounds",
        );
        assert_error_contains(
            database.content_chunk(stored.uid, 0, -1),
            "invalid revision content chunk bounds",
        );
        assert_error_contains(
            database.content_chunk(stored.uid, 0, REVISION_PIECE_SIZE + 1),
            "invalid revision content chunk bounds",
        );
        assert_error_contains(
            database.content_chunk(stored.uid, content_len as i64 - 1, 2),
            "exceeds declared size",
        );
        assert_error_contains(
            database.content_chunk(stored.uid, i64::MAX, 1),
            "bounds overflow",
        );

        database
            .with(|connection| {
                connection.execute(
                    "UPDATE revision_content SET content=zeroblob(?) WHERE uid=?",
                    params![content_len as i64 - 1, stored.uid],
                )?;
                Ok(())
            })
            .unwrap();
        assert_error_contains(
            database.content_chunk(stored.uid, 0, 1),
            "content length changed after validation",
        );

        database
            .with(|connection| {
                connection.execute(
                    "UPDATE revision_content SET content=zeroblob(?) WHERE uid=?",
                    params![content_len as i64, stored.uid],
                )?;
                connection.execute(
                    "UPDATE revisions SET content=zeroblob(?) WHERE uid=?",
                    params![content_len as i64, stored.uid],
                )?;
                Ok(())
            })
            .unwrap();
        assert_error_contains(
            database.content_chunk(stored.uid, 0, 1),
            "storage is missing, duplicated, or not a BLOB",
        );

        database
            .with(|connection| {
                connection.execute(
                    "UPDATE revisions SET content=NULL WHERE uid=?",
                    [stored.uid],
                )?;
                connection.execute("DELETE FROM revision_content WHERE uid=?", [stored.uid])?;
                Ok(())
            })
            .unwrap();
        assert_error_contains(
            database.content_chunk(stored.uid, 0, 1),
            "storage is missing, duplicated, or not a BLOB",
        );
        assert_error_contains(
            database.content_chunk(stored.uid + 1, 0, 1),
            "content metadata not found",
        );
    }

    #[test]
    fn content_chunks_fall_back_to_legacy_inline_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("inline-content.sqlite")).unwrap();
        create_test_vault(&database, "vault");
        let content_len = REVISION_PIECE_SIZE as usize + 23;
        let content = (0..content_len)
            .map(|index| ((index * 17) % 253) as u8)
            .collect::<Vec<_>>();
        let revision = test_file_revision("vault", "inline", content_len as i64);
        let stored = database
            .with(|connection| {
                add_revision(
                    connection,
                    &revision,
                    Some(&content),
                    MAX_JS_SAFE_INTEGER,
                    MAX_JS_SAFE_INTEGER,
                )
            })
            .unwrap();
        let piece = REVISION_PIECE_SIZE as usize;

        assert_eq!(
            database
                .content_chunk(stored.uid, 0, REVISION_PIECE_SIZE)
                .unwrap(),
            content[..piece]
        );
        assert_eq!(
            database
                .content_chunk(stored.uid, REVISION_PIECE_SIZE - 11, 29)
                .unwrap(),
            content[piece - 11..piece + 18]
        );
        assert_eq!(
            database
                .content_chunk(stored.uid, REVISION_PIECE_SIZE, 23)
                .unwrap(),
            content[piece..]
        );

        database
            .with(|connection| {
                connection.execute(
                    "UPDATE revisions SET content=zeroblob(?) WHERE uid=?",
                    params![content_len as i64 - 1, stored.uid],
                )?;
                Ok(())
            })
            .unwrap();
        assert_error_contains(
            database.content_chunk(stored.uid, 0, 1),
            "content length changed after validation",
        );
    }

    #[test]
    fn stored_ciphertext_quota_is_atomic_across_concurrent_file_commits() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("storage-quota.sqlite")).unwrap();
        create_test_vault(&database, "vault");
        let quota = 32;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for name in ["first", "second"] {
            let staged = dir.path().join(format!("{name}.part"));
            std::fs::write(&staged, vec![name.as_bytes()[0]; quota as usize]).unwrap();
            let worker_database = database.clone();
            let worker_barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                worker_barrier.wait();
                worker_database.add_file_revision(
                    &test_file_revision("vault", name, quota),
                    &staged,
                    quota,
                    quota,
                )
            }));
        }

        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { result.as_ref().err().is_some_and(is_storage_quota_exceeded) })
                .count(),
            1
        );
        assert_eq!(database.stored_ciphertext_size().unwrap(), quota);
        assert_eq!(database.vault_size("vault").unwrap(), quota);

        let mut tombstone = test_file_revision("vault", "cleanup", 0);
        tombstone.deleted = true;
        tombstone.hash.clear();
        database
            .add_empty_revision(&tombstone, quota, quota)
            .unwrap();
        assert_eq!(database.stored_ciphertext_size().unwrap(), quota);
    }

    #[test]
    fn owner_storage_quota_is_isolated_and_global_quota_remains_independent() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("owner-storage-quota.sqlite")).unwrap();
        create_test_vault(&database, "owner-one");
        let owner_two = database
            .create_user(
                "owner-two@example.test",
                "Owner two",
                &auth::hash_password("owner-two-password").unwrap(),
            )
            .unwrap();
        database
            .create_vault_for_user(
                owner_two,
                &Vault {
                    id: "owner-two".into(),
                    name: "Owner two vault".into(),
                    keyhash: Some("key".into()),
                    salt: Some("salt".into()),
                    host: "localhost:3003".into(),
                    region: "Blackglass Server".into(),
                    encryption_version: 3,
                    size: 0,
                    created: 1,
                    password: None,
                },
            )
            .unwrap();
        let owner_limit = 16;
        let global_limit = 24;

        for (vault, user_id, byte) in [("owner-one", 1, 0x11), ("owner-two", owner_two, 0x22)] {
            let staged = dir.path().join(format!("{vault}.part"));
            std::fs::write(&staged, vec![byte; owner_limit as usize]).unwrap();
            let mut revision = test_file_revision(vault, "opaque", owner_limit);
            revision.user_id = user_id;
            let result = database.add_file_revision(&revision, &staged, global_limit, owner_limit);
            if user_id == 1 {
                result.unwrap();
            } else {
                assert!(result.as_ref().err().is_some_and(is_storage_quota_exceeded));
            }
        }
        assert_eq!(
            database.stored_ciphertext_size_for_owner(1).unwrap(),
            owner_limit
        );
        assert_eq!(
            database
                .stored_ciphertext_size_for_owner(owner_two)
                .unwrap(),
            0
        );

        let staged = dir.path().join("owner-one-over-limit.part");
        std::fs::write(&staged, [0x44]).unwrap();
        let owner_one_extra = test_file_revision("owner-one", "extra", 1);
        assert!(
            database
                .add_file_revision(&owner_one_extra, &staged, global_limit, owner_limit)
                .as_ref()
                .err()
                .is_some_and(is_storage_quota_exceeded)
        );

        let staged = dir.path().join("owner-two-small.part");
        std::fs::write(&staged, vec![0x33; 8]).unwrap();
        let mut revision = test_file_revision("owner-two", "small", 8);
        revision.user_id = owner_two;
        database
            .add_file_revision(&revision, &staged, global_limit, owner_limit)
            .unwrap();
        assert_eq!(database.stored_ciphertext_size().unwrap(), global_limit);
        assert_eq!(
            database
                .stored_ciphertext_size_for_owner(owner_two)
                .unwrap(),
            8
        );
    }

    #[test]
    fn restore_consumes_quota_and_purge_releases_history_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("restore-quota.sqlite")).unwrap();
        create_test_vault(&database, "vault");
        let size = 16;
        let quota = size * 2;
        let staged = dir.path().join("source.part");
        std::fs::write(&staged, vec![0x5a; size as usize]).unwrap();
        let source = database
            .add_file_revision(
                &test_file_revision("vault", "history", size),
                &staged,
                quota,
                quota,
            )
            .unwrap();
        let restored = database
            .restore("vault", source.uid, "restore-one", quota)
            .unwrap()
            .unwrap();
        assert_eq!(database.stored_ciphertext_size().unwrap(), quota);

        let rejected = database
            .restore("vault", source.uid, "restore-two", quota)
            .unwrap_err();
        assert!(is_storage_quota_exceeded(&rejected));
        assert_eq!(database.current_version("vault").unwrap(), restored.uid);
        assert_eq!(
            database
                .history("vault", "history", None, 10)
                .unwrap()
                .len(),
            2
        );

        database.purge("vault").unwrap();
        assert_eq!(database.stored_ciphertext_size().unwrap(), size);
        database
            .restore("vault", restored.uid, "restore-after-purge", quota)
            .unwrap()
            .unwrap();
        assert_eq!(database.stored_ciphertext_size().unwrap(), quota);
    }

    #[test]
    fn versioned_migration_is_copy_first_validated_and_transactional() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("v1.sqlite");
        let destination = dir.path().join("v2.sqlite");
        create_v1_database(&source);
        let source_before = std::fs::read(&source).unwrap();

        migrate_versioned_database(&source, &destination).unwrap();

        assert_eq!(std::fs::read(&source).unwrap(), source_before);
        verify_database(&destination).unwrap();
        let migrated = Db::open(&destination).unwrap();
        let migrated_vault = migrated.list_vaults().unwrap().pop().unwrap();
        assert_ne!(migrated_vault.id, "legacy-vault");
        let revision = migrated
            .list_changes_page(&migrated_vault.id, 0, i64::MAX, 10)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            migrated.content_chunk(revision.uid, 0, 3).unwrap(),
            [1, 2, 3]
        );

        let rollback = dir.path().join("rollback-v1.sqlite");
        create_v1_database(&rollback);
        let connection = Connection::open(&rollback).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        assert_error_contains(
            apply_migration(
                &connection,
                2,
                "CREATE TABLE sessions(
                    token_hash TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked_at INTEGER
                 );",
            ),
            "unexpected Blackglass schema objects",
        );
        assert!(!table_exists(&connection, "sessions").unwrap());
        assert_eq!(migration_versions(&connection).unwrap(), vec![1]);
        assert_eq!(verify_recorded_schema(&connection).unwrap(), 1);
    }

    #[test]
    fn shipped_v3_migrates_to_v5_without_rotating_identity_or_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("shipped-v3.sqlite");
        let destination = dir.path().join("current-v5.sqlite");
        create_v1_database(&source);
        let connection = Connection::open(&source).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        apply_migration(&connection, 2, MIGRATION_2_SQL).unwrap();
        apply_migration(&connection, 3, MIGRATION_3_SQL).unwrap();
        let session = auth::new_token();
        connection
            .execute(
                "INSERT INTO sessions(token_hash,created_at,expires_at,revoked_at)
                 VALUES(?,1,9999999999999,NULL)",
                [auth::token_hash(&session)],
            )
            .unwrap();
        drop(connection);
        let source_before = std::fs::read(&source).unwrap();

        migrate_versioned_database(&source, &destination).unwrap();

        assert_eq!(std::fs::read(&source).unwrap(), source_before);
        let migrated = Db::open(&destination).unwrap();
        assert_eq!(migrated.list_vaults().unwrap()[0].id, "legacy-vault");
        assert!(migrated.valid_session(&session));
        assert!(!migrated.is_retired_vault("legacy-vault").unwrap());
        migrated
            .with(|connection| {
                assert_eq!(migration_versions(connection)?, vec![1, 2, 3, 4, 5]);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn current_schema_migration_is_rejected_without_creating_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("current.sqlite");
        let destination = dir.path().join("unexpected-copy.sqlite");
        create_current_database(&source);
        assert_error_contains(
            migrate_versioned_database(&source, &destination),
            "already at schema version 5",
        );
        assert!(!destination.exists());
    }

    #[test]
    fn vault_replacement_rolls_back_on_failure_and_removes_old_history_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault-migration.sqlite");
        let database = Db::open(&path).unwrap();
        let source = Vault {
            id: "old-vault".into(),
            name: "Vault".into(),
            keyhash: Some("old-key".into()),
            salt: Some("old-salt".into()),
            host: "old.example".into(),
            region: "Blackglass Server".into(),
            encryption_version: 2,
            size: 0,
            created: 1,
            password: None,
        };
        database.create_vault(&source).unwrap();
        database
            .add_empty_revision(
                &NewRevision {
                    vault_id: source.id.clone(),
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
                },
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();

        let conflicting = Vault {
            id: source.id.clone(),
            encryption_version: 3,
            created: 2,
            ..source.clone()
        };
        assert!(database.migrate_vault(&source.id, &conflicting).is_err());
        assert!(database.find_vault(&source.id).unwrap().is_some());
        assert_eq!(database.current_version(&source.id).unwrap(), 1);
        assert!(!database.is_retired_vault(&source.id).unwrap());

        let replacement = Vault {
            id: "new-vault".into(),
            name: source.name.clone(),
            keyhash: Some("new-key".into()),
            salt: Some("new-salt".into()),
            host: "new.example".into(),
            region: "Blackglass Server".into(),
            encryption_version: 3,
            size: 0,
            created: 3,
            password: None,
        };
        assert!(database.migrate_vault(&source.id, &replacement).unwrap());
        assert!(database.find_vault(&source.id).unwrap().is_none());
        assert!(database.is_retired_vault(&source.id).unwrap());
        assert_eq!(
            database.find_vault(&replacement.id).unwrap().unwrap().size,
            0
        );
        assert!(
            database
                .list_changes_page(&replacement.id, 0, i64::MAX, 10)
                .unwrap()
                .is_empty()
        );
        assert!(database.delete_vault(&replacement.id).unwrap());
        assert!(database.find_vault(&replacement.id).unwrap().is_none());
        assert!(database.is_retired_vault(&replacement.id).unwrap());
        assert!(!database.delete_vault(&replacement.id).unwrap());
    }

    #[test]
    fn data_host_rebind_requires_a_verified_copy_first_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rebind.sqlite");
        let database = Db::open(&path).unwrap();
        database
            .create_vault(&Vault {
                id: "vault".into(),
                name: "Vault".into(),
                keyhash: Some("key".into()),
                salt: Some("salt".into()),
                host: "old.example".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: None,
            })
            .unwrap();
        database.checkpoint().unwrap();
        drop(database);

        let blocked_backup = dir.path().join("blocked.sqlite");
        std::fs::write(&blocked_backup, b"preserve").unwrap();
        assert!(rebind_data_host(&path, "new.example", &blocked_backup).is_err());
        assert_eq!(std::fs::read(&blocked_backup).unwrap(), b"preserve");
        assert_eq!(
            Db::open(&path).unwrap().list_vaults().unwrap()[0].host,
            "old.example"
        );

        let backup = dir.path().join("pre-rebind.sqlite");
        assert_eq!(
            rebind_data_host(&path, "new.example:8443", &backup).unwrap(),
            1
        );
        assert_eq!(
            Db::open(&path).unwrap().list_vaults().unwrap()[0].host,
            "new.example:8443"
        );
        assert_eq!(
            Db::open(&backup).unwrap().list_vaults().unwrap()[0].host,
            "old.example"
        );
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
    fn deleted_history_purge_preserves_live_file_history_and_keeps_tombstone_heads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("purge-deleted.sqlite");
        let backup = dir.path().join("purge-deleted.backup.sqlite");
        let database = Db::open(&path).unwrap();
        database
            .create_vault(&Vault {
                id: "vault".into(),
                name: "Vault".into(),
                keyhash: Some("key".into()),
                salt: Some("salt".into()),
                host: "localhost:3003".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: None,
            })
            .unwrap();
        let revision = |path: &str, hash: &str, deleted: bool| NewRevision {
            vault_id: "vault".into(),
            path: path.into(),
            relatedpath: None,
            extension: "md".into(),
            hash: hash.into(),
            ctime: 1,
            mtime: 2,
            folder: false,
            deleted,
            size: 0,
            pieces: 0,
            device: "test".into(),
            user_id: 1,
        };
        database
            .add_empty_revision(
                &revision("live", "live-1", false),
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();
        database
            .add_empty_revision(
                &revision("live", "live-2", false),
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();
        database
            .add_empty_revision(
                &revision("deleted", "deleted-1", false),
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();
        let tombstone = database
            .add_empty_revision(
                &revision("deleted", "deleted-2", true),
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();
        database.checkpoint().unwrap();
        drop(database);

        assert_eq!(purge_deleted_history(&path, "vault", &backup).unwrap(), 1);
        verify_database(&backup).unwrap();
        let database = Db::open(&path).unwrap();
        assert_eq!(
            database.history("vault", "live", None, 10).unwrap().len(),
            2
        );
        let deleted = database.history("vault", "deleted", None, 10).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].uid, tombstone.uid);
        assert!(deleted[0].deleted);
        assert_eq!(
            database
                .list_deleted_page("vault", false, 0, 10)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn deleted_history_paginates_past_the_old_256_item_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let database = Db::open(&dir.path().join("deleted-pagination.sqlite")).unwrap();
        database
            .create_vault(&Vault {
                id: "vault".into(),
                name: "Vault".into(),
                keyhash: Some("key".into()),
                salt: Some("salt".into()),
                host: "localhost:3003".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: None,
            })
            .unwrap();
        for index in 0..300 {
            for deleted in [false, true] {
                database
                    .add_empty_revision(
                        &NewRevision {
                            vault_id: "vault".into(),
                            path: format!("opaque-{index:03}"),
                            relatedpath: None,
                            extension: "md".into(),
                            hash: if deleted {
                                String::new()
                            } else {
                                format!("hash-{index}")
                            },
                            ctime: 1,
                            mtime: 2,
                            folder: false,
                            deleted,
                            size: 0,
                            pieces: 0,
                            device: "test".into(),
                            user_id: 1,
                        },
                        MAX_JS_SAFE_INTEGER,
                        MAX_JS_SAFE_INTEGER,
                    )
                    .unwrap();
            }
        }

        let mut after = 0;
        let mut deleted = Vec::new();
        loop {
            let page = database
                .list_deleted_page("vault", false, after, 64)
                .unwrap();
            let page_len = page.len();
            if let Some(last) = page.last() {
                after = last.uid;
            }
            deleted.extend(page);
            if page_len < 64 {
                break;
            }
        }
        assert_eq!(deleted.len(), 300);
        assert!(deleted.windows(2).all(|pair| pair[0].uid < pair[1].uid));
    }

    #[test]
    fn restore_rolls_back_when_the_resulting_notice_exceeds_the_event_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("restore-boundary.sqlite");
        let database = Db::open(&path).unwrap();
        database
            .create_vault(&Vault {
                id: "vault".into(),
                name: "Vault".into(),
                keyhash: Some("key".into()),
                salt: Some("salt".into()),
                host: "localhost:3003".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: None,
            })
            .unwrap();
        let source = database
            .add_empty_revision(
                &NewRevision {
                    vault_id: "vault".into(),
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
                },
                MAX_JS_SAFE_INTEGER,
                MAX_JS_SAFE_INTEGER,
            )
            .unwrap();

        assert_error_contains(
            database.restore(
                "vault",
                source.uid,
                &"d".repeat(40_000),
                MAX_JS_SAFE_INTEGER,
            ),
            "restored revision metadata exceeds the bounded event size",
        );
        assert_eq!(database.current_version("vault").unwrap(), source.uid);
        let history = database.history("vault", "opaque", None, 10).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].uid, source.uid);
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
        let backup_active = db.issue_session(60).unwrap();
        assert!(db.valid_session(&backup_active));
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
        let stored = db
            .add_empty_revision(&rev, MAX_JS_SAFE_INTEGER, MAX_JS_SAFE_INTEGER)
            .unwrap();
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
        let restored_vault = copy.list_vaults().unwrap().pop().unwrap();
        assert_ne!(restored_vault.id, "v1");
        assert_eq!(copy.current_version("v1").unwrap(), 0);
        assert_eq!(copy.current_version(&restored_vault.id).unwrap(), 1);
        assert!(copy.is_retired_vault("v1").unwrap());
        assert!(!copy.valid_session(&backup_active));
        assert!(db.valid_session(&backup_active));
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

            let hardlink_database = dir.path().join("hardlink-database.sqlite");
            create_current_database(&hardlink_database);
            let hardlink = dir.path().join("hardlink-alias.sqlite");
            std::fs::hard_link(&hardlink_database, &hardlink).unwrap();
            assert_error_contains(
                verify_database(&hardlink_database),
                "must have exactly one filesystem link",
            );
            assert_error_contains(
                verify_database(&hardlink),
                "must have exactly one filesystem link",
            );
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
        assert_error_contains(verify_database(&empty), "no Blackglass migration metadata");

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

        for (name, mutate, expected) in [
            (
                "check",
                "CHECK (size >= 0)",
                "unsupported schema clause CHECK",
            ),
            ("strict", "STRICT", "unsupported schema clause STRICT"),
        ] {
            let path = dir.path().join(format!("table-option-{name}.sqlite"));
            create_current_database(&path);
            let connection = Connection::open(&path).unwrap();
            let definition: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='table' AND name='vaults'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let changed = if name == "check" {
                format!("{}, {mutate})", definition.strip_suffix(')').unwrap())
            } else {
                format!("{definition} {mutate}")
            };
            connection
                .pragma_update(None, "writable_schema", "ON")
                .unwrap();
            connection
                .execute(
                    "UPDATE sqlite_schema SET sql=? WHERE type='table' AND name='vaults'",
                    [changed],
                )
                .unwrap();
            connection
                .pragma_update(None, "writable_schema", "OFF")
                .unwrap();
            drop(connection);
            assert_error_contains(verify_database(&path), expected);
        }
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
                "vault-name-bound",
                "UPDATE vaults SET name=printf('%0257d',0);",
                "vault field types and ranges",
            ),
            (
                "revision-path-bound",
                "UPDATE revisions SET path=printf('%016385d',0);",
                "revision metadata",
            ),
            (
                "revision-wire-bound",
                "UPDATE revisions SET path=replace(printf('%06000d',0),'0',char(1));",
                "revision notice exceeds the bounded wire size",
            ),
            (
                "vault-count-bound",
                "WITH RECURSIVE numbers(n) AS (
                    SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<100
                 )
                 INSERT INTO vaults(id,name,keyhash,salt,host,region,encryption_version,size,created,password,version,owner_user_id)
                 SELECT printf('extra-%d',n),'extra','key','salt','127.0.0.1:3003','Blackglass Server',3,0,n,NULL,0,1
                 FROM numbers;",
                "vault count limit",
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
                "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,revoked_at)
                 VALUES('short',1,10,9,NULL);",
                "session token and timestamps",
            ),
            (
                "session-revocation",
                "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,revoked_at)
                 VALUES('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',1,10,20,9);",
                "session token and timestamps",
            ),
            (
                "missing-vault-credentials",
                "UPDATE vaults SET keyhash=NULL,salt=NULL,password=NULL;",
                "vault encryption credential shape",
            ),
            (
                "empty-custom-vault-credentials",
                "UPDATE vaults SET keyhash='',salt='salt',password=NULL;",
                "vault encryption credential shape",
            ),
            (
                "malformed-managed-vault-credentials",
                "UPDATE vaults SET keyhash=NULL,salt='abcd',password='abcd';",
                "vault encryption credential shape",
            ),
            (
                "empty-managed-keyhash",
                "UPDATE vaults SET keyhash='',salt=lower(hex(zeroblob(16))),password=lower(hex(zeroblob(32)));",
                "vault encryption credential shape",
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
                "INSERT INTO schema_migrations(version, applied_at) VALUES(6, 6)",
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
            assert_error_contains(result, "schema version 6 is newer");
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
        assert_ne!(vaults[0].id, "legacy-vault");
        let migrated_vault_id = vaults[0].id.clone();
        let through = migrated.current_version(&migrated_vault_id).unwrap();
        let revisions = migrated
            .list_changes_page(&migrated_vault_id, 0, through, 1024)
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
                "INSERT INTO schema_migrations(version, applied_at) VALUES(6, 6)",
                [],
            )
            .unwrap();
        drop(connection);
        let future_destination = dir.path().join("future-destination.sqlite");
        assert_error_contains(
            migrate_legacy_database(&current, &future_destination),
            "schema version 6 is newer",
        );
        assert!(!future_destination.exists());
    }
}
