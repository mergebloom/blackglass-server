use crate::{
    db::{AdminActivity, AdminDatabaseSnapshot, AdminSession, AdminVault},
    server::AppState,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub(crate) const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const MAX_DEVICE_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdminConfig {
    pub bind_host: IpAddr,
    pub port: u16,
    pub token_hash: String,
}

pub(crate) fn parse_admin_config(
    host: Option<&str>,
    port: Option<&str>,
    hash: Option<&str>,
    unsafe_bind: bool,
    control_port: u16,
    data_port: u16,
) -> Result<Option<AdminConfig>> {
    if host.is_none() && port.is_none() && hash.is_none() {
        return Ok(None);
    }
    let (Some(host), Some(port), Some(hash)) = (host, port, hash) else {
        bail!(
            "SELFHOST_ADMIN_BIND_HOST, SELFHOST_ADMIN_PORT, and SELFHOST_ADMIN_TOKEN_HASH must be set together"
        );
    };
    let bind_host: IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("SELFHOST_ADMIN_BIND_HOST must be an IP address"))?;
    if !(bind_host.is_loopback() || unsafe_bind && bind_host.is_unspecified()) {
        bail!(
            "admin listener must bind loopback unless SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND=1 explicitly permits an unspecified container bind"
        );
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("SELFHOST_ADMIN_PORT must be a non-zero port"))?;
    if port == 0 || port == control_port || port == data_port {
        bail!("admin, control, and data ports must be distinct and non-zero");
    }
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("SELFHOST_ADMIN_TOKEN_HASH must be exactly 64 lowercase SHA-256 hex characters");
    }
    Ok(Some(AdminConfig {
        bind_host,
        port,
        token_hash: hash.to_owned(),
    }))
}

pub(crate) fn authorized(value: Option<&str>, expected_hex: &str) -> bool {
    let Some(token) = value
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
    else {
        return false;
    };
    let actual = Sha256::digest(token.as_bytes());
    let Ok(expected) = hex::decode(expected_hex) else {
        return false;
    };
    constant_time_eq(actual.as_slice(), &expected)
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut different = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        different |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    different == 0
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LiveConnection {
    pub id: String,
    pub vault_id: String,
    pub device: String,
    pub connected_at: i64,
    pub last_activity_at: i64,
    pub client_cursor: i64,
    pub state: String,
}
#[derive(Clone, Default)]
pub(crate) struct LiveRegistry {
    inner: Arc<Mutex<HashMap<String, LiveConnection>>>,
    max: usize,
}
impl LiveRegistry {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max,
        }
    }
    pub(crate) fn register(&self, vault: &str, device: &str, cursor: i64) -> Option<LiveGuard> {
        let mut map = self.inner.lock().ok()?;
        if map.len() >= self.max {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        let now = now_ms();
        map.insert(
            id.clone(),
            LiveConnection {
                id: id.clone(),
                vault_id: vault.to_owned(),
                device: sanitize_device(device),
                connected_at: now,
                last_activity_at: now,
                client_cursor: cursor,
                state: "replaying".into(),
            },
        );
        Some(LiveGuard {
            id,
            registry: self.clone(),
        })
    }
    pub(crate) fn snapshot(&self) -> Vec<LiveConnection> {
        let Ok(map) = self.inner.lock() else {
            return vec![];
        };
        let mut out = map.values().cloned().collect::<Vec<_>>();
        out.sort_by_key(|v| v.connected_at);
        out.truncate(self.max);
        out
    }
}
pub(crate) struct LiveGuard {
    id: String,
    registry: LiveRegistry,
}
impl LiveGuard {
    pub(crate) fn activity(&self, cursor: i64, state: &str) {
        if let Ok(mut map) = self.registry.inner.lock()
            && let Some(item) = map.get_mut(&self.id)
        {
            item.client_cursor = cursor;
            item.last_activity_at = now_ms();
            item.state = state.chars().take(32).collect();
        }
    }
}
impl Drop for LiveGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.registry.inner.lock() {
            map.remove(&self.id);
        }
    }
}
fn sanitize_device(value: &str) -> String {
    let clean = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let clean: String = clean
        .chars()
        .take(MAX_DEVICE_BYTES)
        .filter(|c| !c.is_control())
        .collect();
    if clean.is_empty() {
        "Unknown device".into()
    } else {
        clean
    }
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    generated_at: i64,
    overview: Overview,
    limits: Limits,
    vaults: Vec<AdminVault>,
    live_connections: Vec<LiveConnection>,
    recent_activity: Vec<AdminActivity>,
    sessions: Sessions,
    storage: Storage,
    diagnostics: Diagnostics,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Overview {
    healthy: bool,
    version: &'static str,
    source_revision: &'static str,
    schema_version: i64,
    uptime_seconds: u64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Limits {
    per_file_bytes: u64,
    retained_storage_bytes: i64,
    max_sessions: i64,
    max_connections: usize,
    max_uploads: usize,
}
#[derive(Serialize)]
struct Sessions {
    active: i64,
    total: i64,
    items: Vec<AdminSession>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Storage {
    database_file_bytes: Option<u64>,
    logical_bytes: i64,
    retained_bytes: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Diagnostics {
    readiness: bool,
    schema_version: i64,
    staging_file_count: usize,
    oldest_staging_age_seconds: Option<u64>,
    data_host_mismatch: bool,
    admin_bind: String,
    control_bind: String,
    data_bind: String,
    tls_termination: &'static str,
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/admin", get(shell))
        .route("/admin/styles.css", get(styles))
        .route("/admin/app.js", get(script))
        .route("/admin/api/snapshot", get(snapshot))
        .route_layer(middleware::from_fn(security_headers))
        .with_state(state)
}
async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut r = next.run(request).await;
    let h = r.headers_mut();
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}
async fn shell() -> Html<&'static str> {
    Html(ADMIN_HTML)
}
async fn styles() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ADMIN_CSS,
    )
}
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        ADMIN_JS,
    )
}
async fn snapshot(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let Some(admin) = s.config.admin.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !authorized(
        headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok()),
        &admin.token_hash,
    ) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let db = s.db.clone();
    let data = match tokio::task::spawn_blocking(move || db.admin_snapshot()).await {
        Ok(Ok(v)) => v,
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    Json(build_snapshot(&s, data)).into_response()
}
fn build_snapshot(s: &AppState, data: AdminDatabaseSnapshot) -> Snapshot {
    let ready = s.db.ready();
    let staging = staging_facts(&s.config.staging_dir);
    let admin = s
        .config
        .admin
        .as_ref()
        .expect("admin router requires config");
    Snapshot {
        generated_at: now_ms(),
        overview: Overview {
            healthy: ready,
            version: env!("CARGO_PKG_VERSION"),
            source_revision: crate::SOURCE_REVISION,
            schema_version: data.schema_version,
            uptime_seconds: s.started.elapsed().as_secs(),
        },
        limits: Limits {
            per_file_bytes: s.config.per_file_max,
            retained_storage_bytes: s.config.storage_quota_bytes,
            max_sessions: data.max_sessions,
            max_connections: s.config.max_ws_connections,
            max_uploads: s.config.max_concurrent_uploads,
        },
        vaults: data.vaults,
        live_connections: s.live_connections.snapshot(),
        recent_activity: data.activity,
        sessions: Sessions {
            active: data.active_sessions,
            total: data.session_count,
            items: data.sessions,
        },
        storage: Storage {
            database_file_bytes: std::fs::metadata(&s.config.database_path)
                .ok()
                .map(|m| m.len()),
            logical_bytes: data.logical_bytes,
            retained_bytes: data.retained_bytes,
        },
        diagnostics: Diagnostics {
            readiness: ready,
            schema_version: data.schema_version,
            staging_file_count: staging.0,
            oldest_staging_age_seconds: staging.1,
            data_host_mismatch: false,
            admin_bind: format!("{}:{}", admin.bind_host, admin.port),
            control_bind: format!("{}:{}", s.config.bind_host, s.config.control_port),
            data_bind: format!("{}:{}", s.config.bind_host, s.config.data_port),
            tls_termination: "private reverse proxy",
        },
    }
}
fn staging_facts(path: &std::path::Path) -> (usize, Option<u64>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return (0, None);
    };
    let mut count = 0;
    let mut oldest: Option<u64> = None;
    for entry in entries.flatten().take(1024) {
        if entry.path().extension().and_then(|v| v.to_str()) != Some("part") {
            continue;
        }
        count += 1;
        if let Ok(age) = entry.metadata().and_then(|m| m.modified()).and_then(|m| {
            SystemTime::now()
                .duration_since(m)
                .map_err(std::io::Error::other)
        }) {
            oldest = Some(oldest.unwrap_or_default().max(age.as_secs()));
        }
    }
    (count, oldest)
}

pub(crate) const ADMIN_HTML: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Blackglass · Server admin</title><link rel="stylesheet" href="/admin/styles.css"><script defer src="/admin/app.js"></script></head><body><header><strong>Blackglass</strong><span>Server admin</span><span id="refreshed">Not connected</span></header><main><section id="login"><h1>Read-only server view</h1><label>Admin token <input id="token" type="password" autocomplete="off"></label><button id="connect">Connect</button></section><div id="dashboard" hidden><div class="status"><strong id="health">Unknown</strong><span id="version"></span><button id="refresh">Refresh</button><button id="signout">Forget token</button></div><section><h2>Overview</h2><dl id="overview"></dl></section><section><h2>Vaults</h2><div id="vaults" class="rows"></div></section><section><h2>Live connections</h2><div id="connections" class="rows"></div></section><section><h2>Recent activity</h2><div id="activity" class="rows"></div></section><section><h2>Sessions</h2><div id="sessions" class="rows"></div></section><section><h2>Storage &amp; history</h2><dl id="storage"></dl></section><section><h2>Diagnostics</h2><dl id="diagnostics"></dl></section></div></main></body></html>"#;
pub(crate) const ADMIN_CSS: &str = r#":root{color-scheme:light;--ink:#18201d;--muted:#66706b;--line:#d8dedb;--accent:#276b57}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:#f8faf9;font:15px system-ui,sans-serif}header{display:flex;gap:1rem;align-items:baseline;padding:1rem max(1rem,calc((100% - 70rem)/2));border-bottom:1px solid var(--line)}header #refreshed{margin-left:auto;color:var(--muted)}main{max-width:70rem;margin:auto;padding:1rem}section{padding:1rem 0;border-bottom:1px solid var(--line)}h1,h2{font-weight:600}h2{font-size:1rem;text-transform:uppercase;letter-spacing:.06em}button,input{min-height:44px;border:1px solid var(--line);border-radius:3px;padding:.6rem;background:white;color:inherit}button{cursor:pointer}button:focus,input:focus{outline:3px solid #8ec6b4;outline-offset:2px}.status{display:flex;gap:.75rem;align-items:center}.status button:first-of-type{margin-left:auto}.rows>article{display:grid;grid-template-columns:minmax(10rem,1fr) 2fr;gap:.5rem;padding:.7rem 0;border-top:1px solid var(--line)}dl{display:grid;grid-template-columns:minmax(12rem,1fr) 2fr;gap:.5rem}dt{color:var(--muted)}dd{margin:0;font-family:ui-monospace,monospace}@media(max-width:600px){header{flex-wrap:wrap}.status{flex-wrap:wrap}.status button{flex:1}.rows>article,dl{grid-template-columns:1fr}header #refreshed{width:100%;margin:0}}"#;
pub(crate) const ADMIN_JS: &str = r#"'use strict';const $=id=>document.getElementById(id),esc=v=>String(v??'Unavailable'),token=()=>sessionStorage.getItem('blackglass-admin-token');function dl(id,obj){const e=$(id);e.replaceChildren();for(const[k,v]of Object.entries(obj)){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k.replace(/[A-Z]/g,m=>' '+m.toLowerCase());dd.textContent=esc(v);e.append(dt,dd)}}function rows(id,items,empty){const e=$(id);e.replaceChildren();if(!items.length){e.textContent=empty;return}for(const item of items){const a=document.createElement('article'),b=document.createElement('strong'),d=document.createElement('span');b.textContent=esc(item.name||item.device||item.eventType||'Session');d.textContent=Object.entries(item).filter(([k])=>!['name','device','eventType'].includes(k)).map(([k,v])=>`${k}: ${esc(v)}`).join(' · ');a.append(b,d);e.append(a)}}async function load(){const r=await fetch('/admin/api/snapshot',{headers:{Authorization:`Bearer ${token()}`},cache:'no-store'});if(r.status===401){forget();return}if(!r.ok)throw Error('Snapshot unavailable');const x=await r.json();$('login').hidden=true;$('dashboard').hidden=false;$('health').textContent=x.overview.healthy?'Healthy':'Degraded';$('version').textContent=`Version ${x.overview.version}`;$('refreshed').textContent=`Last refreshed ${new Date(x.generatedAt).toLocaleTimeString()}`;dl('overview',{...x.overview,...x.limits});rows('vaults',x.vaults,'No vaults');rows('connections',x.liveConnections,'No active connections');rows('activity',x.recentActivity,'No recent revision activity');rows('sessions',x.sessions.items,'No sessions');dl('storage',x.storage);dl('diagnostics',x.diagnostics)}function forget(){sessionStorage.removeItem('blackglass-admin-token');$('dashboard').hidden=true;$('login').hidden=false;$('token').value=''}$('connect').onclick=()=>{sessionStorage.setItem('blackglass-admin-token',$('token').value);load().catch(e=>$('refreshed').textContent=e.message)};$('refresh').onclick=()=>load();$('signout').onclick=forget;if(token())load().catch(forget);setInterval(()=>{if(token())load().catch(()=>{})},10000);"#;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_is_disabled_or_complete_and_loopback_only() {
        assert_eq!(
            parse_admin_config(None, None, None, false, 3000, 3003).unwrap(),
            None
        );
        let hash = "ab".repeat(32);
        for p in [
            (Some("127.0.0.1"), None, None),
            (None, Some("3100"), None),
            (None, None, Some(hash.as_str())),
        ] {
            assert!(parse_admin_config(p.0, p.1, p.2, false, 3000, 3003).is_err())
        }
        let c = parse_admin_config(
            Some("127.0.0.1"),
            Some("3100"),
            Some(&hash),
            false,
            3000,
            3003,
        )
        .unwrap()
        .unwrap();
        assert!(c.bind_host.is_loopback());
        assert_eq!(c.port, 3100);
        assert!(
            parse_admin_config(
                Some("0.0.0.0"),
                Some("3100"),
                Some(&hash),
                false,
                3000,
                3003
            )
            .is_err()
        );
        assert!(
            parse_admin_config(
                Some("127.0.0.1"),
                Some("3000"),
                Some(&hash),
                false,
                3000,
                3003
            )
            .is_err()
        );
        assert!(
            parse_admin_config(
                Some("127.0.0.1"),
                Some("3100"),
                Some(&"A".repeat(64)),
                false,
                3000,
                3003
            )
            .is_err()
        )
    }
    #[test]
    fn bearer_auth_is_exact_and_hash_based() {
        let t = "independent-admin-token";
        let h = hex::encode(Sha256::digest(t.as_bytes()));
        assert!(authorized(Some(&format!("Bearer {t}")), &h));
        assert!(!authorized(None, &h));
        assert!(!authorized(Some("Bearer ordinary-sync-token"), &h));
        assert!(!authorized(Some(&format!("bearer {t}")), &h))
    }
    #[test]
    fn embedded_assets_are_data_free_responsive_and_secure() {
        for label in [
            "Server admin",
            "Overview",
            "Live connections",
            "Diagnostics",
        ] {
            assert!(ADMIN_HTML.contains(label))
        }
        assert!(!ADMIN_HTML.contains("token_hash"));
        assert!(ADMIN_CSS.contains("@media"));
        assert!(ADMIN_CSS.contains("min-height:44px"));
        for marker in ["sessionStorage", "Authorization", "10000"] {
            assert!(ADMIN_JS.contains(marker))
        }
        assert!(!ADMIN_JS.contains("localStorage"));
        assert!(CSP.contains("default-src 'none'"))
    }
    #[test]
    fn live_registry_is_bounded_sanitized_and_drop_safe() {
        let r = LiveRegistry::new(1);
        {
            let g = r.register("vault", "  Phone\nsecret  ", 7).unwrap();
            assert_eq!(r.snapshot()[0].device, "Phone secret");
            assert!(r.register("other", "Laptop", 0).is_none());
            g.activity(9, "ready");
            assert_eq!(r.snapshot()[0].client_cursor, 9)
        }
        assert!(r.snapshot().is_empty())
    }

    #[test]
    fn projections_distinguish_encryption_modes_without_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&dir.path().join("admin.sqlite")).unwrap();
        for (id, password, keyhash, expected) in [
            ("managed", Some("RECOVERY-SECRET"), None, "managed"),
            ("custom", None, Some("KEYHASH-SECRET"), "custom-password"),
        ] {
            db.create_vault(&crate::model::Vault {
                id: id.into(),
                name: id.into(),
                keyhash: keyhash.map(str::to_owned),
                salt: Some("SALT-SECRET".into()),
                host: "127.0.0.1:3003".into(),
                region: "Blackglass Server".into(),
                encryption_version: 3,
                size: 0,
                created: 1,
                password: password.map(str::to_owned),
            })
            .unwrap();
            assert_eq!(
                db.admin_snapshot()
                    .unwrap()
                    .vaults
                    .iter()
                    .find(|v| v.id == id)
                    .unwrap()
                    .encryption_mode,
                expected
            );
        }
        let encoded = serde_json::to_string(&db.admin_snapshot().unwrap().vaults).unwrap();
        for secret in ["RECOVERY-SECRET", "KEYHASH-SECRET", "SALT-SECRET"] {
            assert!(!encoded.contains(secret));
        }
        assert!(db.admin_snapshot().unwrap().vaults.len() <= 100);
        assert!(db.admin_snapshot().unwrap().activity.len() <= 100);
        assert!(db.admin_snapshot().unwrap().sessions.len() <= 100);
    }
}
