use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub keyhash: Option<String>,
    pub salt: Option<String>,
    pub host: String,
    pub region: String,
    pub encryption_version: i64,
    pub size: i64,
    pub created: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Revision {
    pub uid: i64,
    pub vault_id: String,
    pub path: String,
    pub relatedpath: Option<String>,
    pub extension: String,
    pub hash: String,
    pub ctime: i64,
    pub mtime: i64,
    pub folder: bool,
    pub deleted: bool,
    pub size: i64,
    pub _pieces: i64,
    pub device: String,
    pub user_id: i64,
    pub ts: i64,
}

#[derive(Clone, Debug)]
pub struct NewRevision {
    pub vault_id: String,
    pub path: String,
    pub relatedpath: Option<String>,
    pub extension: String,
    pub hash: String,
    pub ctime: i64,
    pub mtime: i64,
    pub folder: bool,
    pub deleted: bool,
    pub size: i64,
    pub pieces: i64,
    pub device: String,
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct Signin {
    pub email: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultCreate {
    #[serde(rename = "token")]
    pub _token: Option<String>,
    pub name: Option<String>,
    pub keyhash: Option<String>,
    pub salt: Option<String>,
    pub encryption_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct VaultAccess {
    #[serde(rename = "token")]
    pub _token: Option<String>,
    pub vault_uid: Option<String>,
    pub keyhash: Option<String>,
    pub host: Option<String>,
    pub encryption_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct VaultRename {
    #[serde(rename = "token")]
    pub _token: Option<String>,
    pub vault_uid: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultDelete {
    #[serde(rename = "token")]
    pub _token: Option<String>,
    pub vault_uid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultMigrate {
    #[serde(rename = "token")]
    pub _token: Option<String>,
    pub vault_uid: Option<String>,
    pub keyhash: Option<String>,
    pub salt: Option<String>,
    #[serde(rename = "region")]
    pub _region: Option<String>,
    pub encryption_version: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PushNotice {
    pub op: &'static str,
    pub path: String,
    pub relatedpath: Option<String>,
    pub extension: String,
    pub hash: String,
    pub ctime: i64,
    pub mtime: i64,
    pub folder: bool,
    pub deleted: bool,
    pub size: i64,
    pub uid: i64,
    pub device: String,
    pub user: i64,
    pub ts: i64,
}

impl From<Revision> for PushNotice {
    fn from(r: Revision) -> Self {
        Self {
            op: "push",
            path: r.path,
            relatedpath: r.relatedpath,
            extension: r.extension,
            hash: r.hash,
            ctime: r.ctime,
            mtime: r.mtime,
            folder: r.folder,
            deleted: r.deleted,
            size: r.size,
            uid: r.uid,
            device: r.device,
            user: r.user_id,
            ts: r.ts,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PullInfo {
    pub vault_id: String,
    pub hash: String,
    pub size: i64,
    pub pieces: i64,
    pub folder: bool,
    pub deleted: bool,
    pub has_content: bool,
}
