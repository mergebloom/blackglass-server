use crate::{
    db::{AdminActivity, AdminDatabaseSnapshot, AdminSession, AdminUser, AdminVault},
    model::AuthContext,
    server::{
        AppState, DatabaseOperation, authenticate_credentials, db_task, issue_user_session,
        observe_database_error,
    },
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, uri::Authority},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub(crate) const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const MAX_DEVICE_BYTES: usize = 128;
pub(crate) const ADMIN_AUTH_FAILURES_PER_SOURCE: u8 = 8;
const ADMIN_AUTH_FAILURE_WINDOW: Duration = Duration::from_secs(60);
const MAX_ADMIN_AUTH_SOURCES: usize = 8;
const ADMIN_SESSION_COOKIE: &str = "blackglass_admin_session";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AdminConfig {
    pub bind_host: IpAddr,
    pub port: u16,
}

pub(crate) fn parse_admin_config(
    host: Option<&str>,
    port: Option<&str>,
    legacy_hash: Option<&str>,
    control_port: u16,
    data_port: u16,
) -> Result<Option<AdminConfig>> {
    if legacy_hash.is_some() {
        bail!(
            "SELFHOST_ADMIN_TOKEN_HASH is no longer supported; administrators now sign in with their Blackglass account"
        );
    }
    if host.is_none() && port.is_none() {
        return Ok(None);
    }
    let (Some(host), Some(port)) = (host, port) else {
        bail!("SELFHOST_ADMIN_BIND_HOST and SELFHOST_ADMIN_PORT must be set together");
    };
    let bind_host: IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("SELFHOST_ADMIN_BIND_HOST must be an IP address"))?;
    if !bind_host.is_loopback() {
        bail!("SELFHOST_ADMIN_BIND_HOST must be a loopback IP address");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("SELFHOST_ADMIN_PORT must be a non-zero port"))?;
    if port == 0 || port == control_port || port == data_port {
        bail!("admin, control, and data ports must be distinct and non-zero");
    }
    Ok(Some(AdminConfig { bind_host, port }))
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
    pub user_id: i64,
}
struct LiveEntry {
    connection: LiveConnection,
    session_hash: String,
    cancellation: tokio::sync::watch::Sender<bool>,
}
#[derive(Clone, Default)]
pub(crate) struct LiveRegistry {
    inner: Arc<Mutex<HashMap<String, LiveEntry>>>,
    max: usize,
}
impl LiveRegistry {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max,
        }
    }
    pub(crate) fn register(
        &self,
        user_id: i64,
        session_hash: &str,
        vault: &str,
        device: &str,
        cursor: i64,
    ) -> Option<LiveGuard> {
        let mut map = self.inner.lock().ok()?;
        if map.len() >= self.max {
            return None;
        }
        let id = Uuid::new_v4().to_string();
        let now = now_ms();
        let (cancellation, receiver) = tokio::sync::watch::channel(false);
        map.insert(
            id.clone(),
            LiveEntry {
                connection: LiveConnection {
                    id: id.clone(),
                    vault_id: vault.to_owned(),
                    device: sanitize_device(device),
                    connected_at: now,
                    last_activity_at: now,
                    client_cursor: cursor,
                    state: "replaying".into(),
                    user_id,
                },
                session_hash: session_hash.to_owned(),
                cancellation,
            },
        );
        Some(LiveGuard {
            id,
            registry: self.clone(),
            cancellation: receiver,
        })
    }
    pub(crate) fn cancel_session(&self, session_hash: &str) {
        if let Ok(map) = self.inner.lock() {
            for entry in map
                .values()
                .filter(|entry| entry.session_hash == session_hash)
            {
                let _ = entry.cancellation.send(true);
            }
        }
    }
    pub(crate) fn cancel_vault(&self, vault_id: &str) {
        if let Ok(map) = self.inner.lock() {
            for entry in map
                .values()
                .filter(|entry| entry.connection.vault_id == vault_id)
            {
                let _ = entry.cancellation.send(true);
            }
        }
    }
    pub(crate) fn cancel_user_vault(&self, user_id: i64, vault_id: &str) {
        if let Ok(map) = self.inner.lock() {
            for entry in map.values().filter(|entry| {
                entry.connection.user_id == user_id && entry.connection.vault_id == vault_id
            }) {
                let _ = entry.cancellation.send(true);
            }
        }
    }
    pub(crate) fn snapshot(&self) -> Vec<LiveConnection> {
        let Ok(map) = self.inner.lock() else {
            return vec![];
        };
        let mut out = map
            .values()
            .map(|entry| entry.connection.clone())
            .collect::<Vec<_>>();
        out.sort_by_key(|v| v.connected_at);
        out.truncate(self.max);
        out
    }
}
pub(crate) struct LiveGuard {
    id: String,
    registry: LiveRegistry,
    cancellation: tokio::sync::watch::Receiver<bool>,
}
impl LiveGuard {
    pub(crate) fn cancellation(&self) -> tokio::sync::watch::Receiver<bool> {
        self.cancellation.clone()
    }
    pub(crate) fn activity(&self, cursor: i64, state: &str) {
        if let Ok(mut map) = self.registry.inner.lock()
            && let Some(item) = map.get_mut(&self.id)
        {
            let item = &mut item.connection;
            item.client_cursor = cursor;
            item.last_activity_at = now_ms();
            item.state = state.chars().take(32).collect();
        }
    }
    pub(crate) fn protocol_activity(&self, state: &str) {
        if let Ok(mut map) = self.registry.inner.lock()
            && let Some(item) = map.get_mut(&self.id)
        {
            let item = &mut item.connection;
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
    users: Vec<AdminUser>,
    vaults: Vec<AdminVault>,
    live_connections: Vec<LiveConnection>,
    recent_activity: Vec<AdminActivity>,
    sessions: Sessions,
    storage: Storage,
    diagnostics: Diagnostics,
    counts: Counts,
    registration: Registration,
}
#[derive(Serialize)]
struct Registration {
    enabled: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    vaults_total: i64,
    vaults_visible: usize,
    activity_total: i64,
    activity_visible: usize,
    sessions_total: i64,
    sessions_visible: usize,
    users_total: i64,
    users_visible: usize,
    users_active: i64,
    users_disabled: i64,
    memberships_total: i64,
    memberships_active: i64,
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
    retained_storage_bytes_per_owner: i64,
    max_sessions: i64,
    max_connections: usize,
    max_connections_per_user: usize,
    max_uploads: usize,
    max_uploads_per_user: usize,
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
    staging_accessible: bool,
    staging_file_count: Option<usize>,
    oldest_staging_age_seconds: Option<u64>,
    data_host_mismatch: bool,
    admin_bind: String,
    control_bind: String,
    data_bind: String,
    tls_handled_by_server: bool,
    transport_security: &'static str,
}

#[derive(Clone)]
struct AdminRouterState {
    app: AppState,
    auth_failures: AdminAuthFailures,
}

#[derive(Clone, Default)]
struct AdminAuthFailures {
    inner: Arc<Mutex<HashMap<IpAddr, AdminAuthFailureBucket>>>,
}

struct AdminAuthFailureBucket {
    window_started: Instant,
    failures: u8,
}

impl AdminAuthFailures {
    fn register(&self, source: IpAddr) -> Option<u64> {
        self.register_at(source, Instant::now())
    }

    fn register_at(&self, source: IpAddr, now: Instant) -> Option<u64> {
        let Ok(mut entries) = self.inner.lock() else {
            return Some(ADMIN_AUTH_FAILURE_WINDOW.as_secs());
        };
        entries.retain(|_, entry| {
            now.saturating_duration_since(entry.window_started) < ADMIN_AUTH_FAILURE_WINDOW
        });
        if !entries.contains_key(&source) && entries.len() >= MAX_ADMIN_AUTH_SOURCES {
            let oldest = entries
                .iter()
                .min_by_key(|(_, entry)| entry.window_started)
                .map(|(address, _)| *address);
            if let Some(address) = oldest {
                entries.remove(&address);
            }
        }
        let entry = entries.entry(source).or_insert(AdminAuthFailureBucket {
            window_started: now,
            failures: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures <= ADMIN_AUTH_FAILURES_PER_SOURCE {
            return None;
        }
        Some(
            ADMIN_AUTH_FAILURE_WINDOW
                .saturating_sub(now.saturating_duration_since(entry.window_started))
                .as_secs()
                .max(1),
        )
    }

    fn clear(&self, source: IpAddr) {
        if let Ok(mut entries) = self.inner.lock() {
            entries.remove(&source);
        }
    }
}

pub(crate) fn router(state: AppState) -> Router {
    let state = AdminRouterState {
        app: state,
        auth_failures: AdminAuthFailures::default(),
    };
    Router::new()
        .route("/admin", get(shell))
        .route("/admin/styles.css", get(styles))
        .route("/admin/app.js", get(script))
        .route("/admin/logo.png", get(logo))
        .route("/admin/api/login", post(login))
        .route("/admin/api/logout", post(logout))
        .route("/admin/api/session", get(session_status))
        .route("/admin/api/snapshot", get(snapshot))
        .route("/admin/api/registration", post(update_registration))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}
async fn security_headers(
    State(state): State<AdminRouterState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let allowed = state
        .app
        .config
        .admin
        .as_ref()
        .is_some_and(|admin| allowed_authority(request.headers().get(header::HOST), admin));
    let mut r = if allowed {
        next.run(request).await
    } else {
        StatusCode::MISDIRECTED_REQUEST.into_response()
    };
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
fn allowed_authority(value: Option<&HeaderValue>, admin: &AdminConfig) -> bool {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return false;
    };
    let Ok(authority) = value.parse::<Authority>() else {
        return false;
    };
    if authority.port_u16().unwrap_or(80) != admin.port {
        return false;
    }
    let host = authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| authority.host());
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address == admin.bind_host)
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
async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png")], ADMIN_LOGO)
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

async fn login(
    State(state): State<AdminRouterState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<LoginRequest>,
) -> Response {
    let user = match authenticate_credentials(
        &state.app,
        peer.ip(),
        Some(request.email),
        Some(request.password),
    )
    .await
    {
        Ok(user) if user.role == "admin" => user,
        _ => {
            let Some(retry_after) = state.auth_failures.register(peer.ip()) else {
                return StatusCode::UNAUTHORIZED.into_response();
            };
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&retry_after.to_string())
                        .unwrap_or_else(|_| HeaderValue::from_static("60")),
                )],
            )
                .into_response();
        }
    };
    let token = match issue_user_session(&state.app, user.id).await {
        Ok(token) => token,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    state.auth_failures.clear(peer.ip());
    let max_age = state.app.config.session_ttl.as_secs();
    let cookie = format!(
        "{ADMIN_SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age={max_age}"
    );
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"signedIn":true,"name":user.name})),
    )
        .into_response()
}

async fn logout(State(state): State<AdminRouterState>, headers: HeaderMap) -> Response {
    if headers
        .get("x-blackglass-admin")
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = session_token(&headers) {
        let _ = db_task(&state.app, move |db| db.revoke_session(&token)).await;
    }
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            format!("{ADMIN_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0"),
        )],
    )
        .into_response()
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix(&format!("{ADMIN_SESSION_COOKIE}=")))
        .filter(|token| {
            token.len() == 64
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_owned)
}

async fn administrator(
    state: &AdminRouterState,
    headers: &HeaderMap,
) -> Option<(String, AuthContext)> {
    let token = session_token(headers)?;
    let lookup = token.clone();
    let context = db_task(&state.app, move |db| db.auth_context(&lookup))
        .await
        .ok()??;
    (context.role == "admin").then_some((token, context))
}

async fn session_status(State(state): State<AdminRouterState>, headers: HeaderMap) -> Response {
    match administrator(&state, &headers).await {
        Some((_, administrator)) => Json(serde_json::json!({
            "signedIn": true,
            "name": administrator.name,
        }))
        .into_response(),
        None => Json(serde_json::json!({"signedIn":false})).into_response(),
    }
}

async fn snapshot(State(state): State<AdminRouterState>, headers: HeaderMap) -> Response {
    let s = &state.app;
    if s.config.admin.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if administrator(&state, &headers).await.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(_permit) = s.admin_snapshots.clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "30")]).into_response();
    };
    let db = s.db.clone();
    let expected_host = s.config.public_data_host.clone();
    let data = match tokio::task::spawn_blocking(move || db.admin_snapshot(&expected_host)).await {
        Ok(Ok(v)) => v,
        Ok(Err(error)) => {
            observe_database_error(s, DatabaseOperation::AdminSnapshot, &error);
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    Json(build_snapshot(s, data)).into_response()
}

#[derive(Deserialize)]
struct RegistrationUpdate {
    enabled: bool,
}

async fn update_registration(
    State(state): State<AdminRouterState>,
    headers: HeaderMap,
    Json(update): Json<RegistrationUpdate>,
) -> Response {
    if headers
        .get("x-blackglass-admin")
        .and_then(|value| value.to_str().ok())
        != Some("1")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some((_, administrator)) = administrator(&state, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    match db_task(&state.app, move |db| {
        db.set_self_registration_enabled(administrator.user_id, update.enabled)
    })
    .await
    {
        Ok(()) => Json(Registration {
            enabled: update.enabled,
        })
        .into_response(),
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}
fn build_snapshot(s: &AppState, data: AdminDatabaseSnapshot) -> Snapshot {
    let ready = s.db.ready();
    let staging = staging_facts(&s.config.staging_dir);
    let admin = s
        .config
        .admin
        .as_ref()
        .expect("admin router requires config");
    let counts = Counts {
        vaults_total: data.vault_count,
        vaults_visible: data.vaults.len(),
        activity_total: data.activity_count,
        activity_visible: data.activity.len(),
        sessions_total: data.session_count,
        sessions_visible: data.sessions.len(),
        users_total: data.user_count,
        users_visible: data.users.len(),
        users_active: data.active_users,
        users_disabled: data.disabled_users,
        memberships_total: data.membership_count,
        memberships_active: data.active_memberships,
    };
    Snapshot {
        generated_at: now_ms(),
        overview: Overview {
            healthy: ready && staging.accessible,
            version: env!("CARGO_PKG_VERSION"),
            source_revision: crate::SOURCE_REVISION,
            schema_version: data.schema_version,
            uptime_seconds: s.started.elapsed().as_secs(),
        },
        limits: Limits {
            per_file_bytes: s.config.per_file_max,
            retained_storage_bytes: s.config.storage_quota_bytes,
            retained_storage_bytes_per_owner: s.config.storage_quota_bytes_per_owner,
            max_sessions: data.max_sessions,
            max_connections: s.config.max_ws_connections,
            max_connections_per_user: s.config.max_ws_connections_per_user,
            max_uploads: s.config.max_concurrent_uploads,
            max_uploads_per_user: s.config.max_concurrent_uploads_per_user,
        },
        users: data.users,
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
            staging_accessible: staging.accessible,
            staging_file_count: staging.count,
            oldest_staging_age_seconds: staging.oldest_age_seconds,
            data_host_mismatch: data.mismatched_data_hosts > 0,
            admin_bind: format!("{}:{}", admin.bind_host, admin.port),
            control_bind: format!("{}:{}", s.config.bind_host, s.config.control_port),
            data_bind: format!("{}:{}", s.config.bind_host, s.config.data_port),
            tls_handled_by_server: false,
            transport_security: "TLS is expected at the private reverse proxy; not observable by Blackglass",
        },
        counts,
        registration: Registration {
            enabled: data.self_registration_enabled,
        },
    }
}
struct StagingFacts {
    accessible: bool,
    count: Option<usize>,
    oldest_age_seconds: Option<u64>,
}
fn staging_facts(path: &std::path::Path) -> StagingFacts {
    let Ok(entries) = std::fs::read_dir(path) else {
        return StagingFacts {
            accessible: false,
            count: None,
            oldest_age_seconds: None,
        };
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
    StagingFacts {
        accessible: true,
        count: Some(count),
        oldest_age_seconds: oldest,
    }
}

pub(crate) const ADMIN_HTML: &str = include_str!("../admin/index.html");
pub(crate) const ADMIN_CSS: &str = include_str!("../admin/styles.css");
pub(crate) const ADMIN_JS: &str = include_str!("../admin/app.js");
pub(crate) const ADMIN_LOGO: &[u8] = include_bytes!("../../../assets/blackglass-prism.png");
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_is_disabled_or_complete_and_loopback_only() {
        assert_eq!(
            parse_admin_config(None, None, None, 3000, 3003).unwrap(),
            None
        );
        for p in [
            (Some("127.0.0.1"), None, None),
            (None, Some("3100"), None),
            (None, None, Some("legacy-hash")),
        ] {
            assert!(parse_admin_config(p.0, p.1, p.2, 3000, 3003).is_err())
        }
        let c = parse_admin_config(Some("127.0.0.1"), Some("3100"), None, 3000, 3003)
            .unwrap()
            .unwrap();
        assert!(c.bind_host.is_loopback());
        assert_eq!(c.port, 3100);
        assert!(parse_admin_config(Some("0.0.0.0"), Some("3100"), None, 3000, 3003).is_err());
        assert!(parse_admin_config(Some("127.0.0.1"), Some("3000"), None, 3000, 3003).is_err());
        assert!(
            parse_admin_config(
                Some("127.0.0.1"),
                Some("3100"),
                Some("legacy-hash"),
                3000,
                3003
            )
            .is_err()
        )
    }
    #[test]
    fn admin_cookie_parsing_is_exact_and_bounded() {
        let token = "0123456789abcdef".repeat(4);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("theme=dark; {ADMIN_SESSION_COOKIE}={token}")).unwrap(),
        );
        assert_eq!(session_token(&headers), Some(token));
        for value in [
            "blackglass_admin_session=short",
            "BLACKGLASS_ADMIN_SESSION=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "blackglass_admin_session=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        ] {
            headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
            assert_eq!(session_token(&headers), None);
        }
    }
    #[test]
    fn admin_authority_is_exact_loopback_or_localhost() {
        let admin = AdminConfig {
            bind_host: "127.0.0.1".parse().unwrap(),
            port: 3010,
        };
        for value in ["127.0.0.1:3010", "localhost:3010", "LOCALHOST:3010"] {
            assert!(allowed_authority(
                Some(&HeaderValue::from_str(value).unwrap()),
                &admin
            ));
        }
        for value in [
            "attacker.invalid:3010",
            "127.0.0.2:3010",
            "127.0.0.1:3011",
            "127.0.0.1",
        ] {
            assert!(!allowed_authority(
                Some(&HeaderValue::from_str(value).unwrap()),
                &admin
            ));
        }
        assert!(!allowed_authority(None, &admin));

        let ipv6 = AdminConfig {
            bind_host: "::1".parse().unwrap(),
            port: 3010,
        };
        for value in ["[::1]:3010", "localhost:3010"] {
            assert!(allowed_authority(
                Some(&HeaderValue::from_str(value).unwrap()),
                &ipv6
            ));
        }
        for value in ["[::1]:3011", "[::ffff:127.0.0.1]:3010"] {
            assert!(!allowed_authority(
                Some(&HeaderValue::from_str(value).unwrap()),
                &ipv6
            ));
        }
    }
    #[test]
    fn admin_failure_budget_expires_and_is_bounded() {
        let failures = AdminAuthFailures::default();
        let now = Instant::now();
        let source = "127.0.0.1".parse().unwrap();
        for _ in 0..ADMIN_AUTH_FAILURES_PER_SOURCE {
            assert_eq!(failures.register_at(source, now), None);
        }
        assert_eq!(
            failures.register_at(source, now),
            Some(ADMIN_AUTH_FAILURE_WINDOW.as_secs())
        );
        assert_eq!(
            failures.register_at(source, now + ADMIN_AUTH_FAILURE_WINDOW),
            None
        );
        for last in 1..=MAX_ADMIN_AUTH_SOURCES + 1 {
            let source = IpAddr::from([127, 0, 0, last as u8]);
            failures.register_at(source, now);
        }
        assert!(failures.inner.lock().unwrap().len() <= MAX_ADMIN_AUTH_SOURCES);
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
        assert!(ADMIN_CSS.contains("min-height: 48px"));
        assert!(ADMIN_CSS.contains("color-scheme: dark"));
        assert!(ADMIN_HTML.contains("/admin/logo.png"));
        assert_eq!(&ADMIN_LOGO[..8], b"\x89PNG\r\n\x1a\n");
        for marker in [
            "/admin/api/login",
            "/admin/api/logout",
            "/admin/api/session",
            "/admin/api/registration",
            "X-Blackglass-Admin",
            "30000",
            "Request rate limited; retry shortly.",
        ] {
            assert!(ADMIN_JS.contains(marker))
        }
        assert!(!ADMIN_JS.contains("localStorage"));
        assert!(!ADMIN_JS.contains("sessionStorage"));
        assert!(!ADMIN_JS.contains("Authorization"));
        for marker in [
            "aria-busy=\"false\"",
            "tabindex=\"-1\"",
            "autocomplete=\"username\"",
            "autocomplete=\"current-password\"",
            "registration-enabled",
            "new AbortController()",
            "pending.controller.abort()",
            "requestGeneration !== generation",
            "Refreshing dashboard",
            "Refreshing…",
            "$('dashboard-title').focus()",
        ] {
            assert!(
                ADMIN_HTML.contains(marker) || ADMIN_JS.contains(marker),
                "{marker}"
            );
        }
        assert!(CSP.contains("default-src 'none'"));
        assert!(CSP.contains("img-src 'self'"))
    }
    #[test]
    fn live_registry_is_bounded_sanitized_and_drop_safe() {
        let r = LiveRegistry::new(1);
        {
            let g = r
                .register(1, "session-one", "vault", "  Phone\nsecret  ", 7)
                .unwrap();
            let cancellation = g.cancellation();
            assert!(!*cancellation.borrow());
            assert_eq!(r.snapshot()[0].device, "Phone secret");
            assert_eq!(r.snapshot()[0].user_id, 1);
            assert!(r.register(2, "session-two", "other", "Laptop", 0).is_none());
            r.cancel_session("unrelated");
            assert!(!*cancellation.borrow());
            r.cancel_session("session-one");
            assert!(*cancellation.borrow());
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
                db.admin_snapshot("127.0.0.1:3003")
                    .unwrap()
                    .vaults
                    .iter()
                    .find(|v| v.id == id)
                    .unwrap()
                    .encryption_mode,
                expected
            );
        }
        let encoded =
            serde_json::to_string(&db.admin_snapshot("127.0.0.1:3003").unwrap().vaults).unwrap();
        for secret in ["RECOVERY-SECRET", "KEYHASH-SECRET", "SALT-SECRET"] {
            assert!(!encoded.contains(secret));
        }
        assert!(db.admin_snapshot("127.0.0.1:3003").unwrap().vaults.len() <= 100);
        assert!(db.admin_snapshot("127.0.0.1:3003").unwrap().activity.len() <= 100);
        assert!(db.admin_snapshot("127.0.0.1:3003").unwrap().sessions.len() <= 100);
    }
}
