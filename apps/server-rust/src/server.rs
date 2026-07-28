use crate::{
    auth,
    config::Config,
    db::{Db, MAX_JS_SAFE_INTEGER},
    model::*,
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{
        ConnectInfo, DefaultBodyLimit, Request, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    future::Future,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Mutex as AsyncMutex, Semaphore, broadcast, watch},
    time::{MissedTickBehavior, interval, timeout},
};
use tracing::{info, warn};
use uuid::Uuid;

const PIECE_SIZE: i64 = 2 * 1024 * 1024;
const AES_GCM_WIRE_OVERHEAD: u64 = 12 + 16;
const REPLAY_PAGE_SIZE: i64 = 128;
const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(5);
const CONTROL_BODY_DEADLINE: Duration = Duration::from_secs(5);
const GRACEFUL_CONNECTION_DRAIN_DEADLINE: Duration = Duration::from_secs(15);
const SESSION_REVALIDATE_INTERVAL: Duration = Duration::from_secs(5);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNIN_QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNIN_RATE_WINDOW: Duration = Duration::from_secs(60);
const SIGNIN_ATTEMPTS_PER_SOURCE: usize = 6;
const MAX_SIGNIN_WAITERS: usize = 8;
const MAX_UNAUTHENTICATED_WS_PER_SOURCE: usize = 4;
const MAX_SOURCE_LIMIT_ENTRIES: usize = 4096;
pub(crate) const MAX_CONTROL_BODY_READERS: usize = 32;
pub(crate) const MAX_CONTROL_REQUESTS: usize = 16;
pub(crate) const MAX_DB_WORKERS: usize = 2;
pub(crate) const MAX_CONTROL_BODY_BYTES: usize = 64 * 1024;
pub(crate) const EVENT_CAPACITY: usize = 32;
pub(crate) const MAX_EVENT_BYTES: usize = 32 * 1024;
pub(crate) const MAX_LARGE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const DELETED_PAGE_SIZE: i64 = 64;
const STAGING_MARKER: &str = ".blackglass-staging-v1";
const STAGING_MARKER_CONTENT: &str = "blackglass-server staging v1\n";

#[derive(Default)]
pub struct Metrics {
    control: AtomicU64,
    signins: AtomicU64,
    auth_failures: AtomicU64,
    ws_connections: AtomicU64,
    uploads: AtomicU64,
    upload_bytes: AtomicU64,
    downloads: AtomicU64,
    errors: AtomicU64,
    control_rejections: AtomicU64,
}

#[derive(Clone)]
struct Event {
    uid: i64,
    vault: String,
    text: String,
    invalidated: bool,
}
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    events: broadcast::Sender<Event>,
    commit_order: Arc<AsyncMutex<()>>,
    uploads: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    auth_checks: Arc<Semaphore>,
    auth_waiters: Arc<Semaphore>,
    source_limits: Arc<StdMutex<SourceLimits>>,
    control_body_readers: Arc<Semaphore>,
    control_requests: Arc<Semaphore>,
    db_workers: Arc<Semaphore>,
    large_responses: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct SourceLimits {
    entries: HashMap<IpAddr, SourceLimitEntry>,
}

struct SourceLimitEntry {
    signin_attempts: VecDeque<Instant>,
    unauthenticated_websockets: usize,
    last_seen: Instant,
}

impl SourceLimits {
    fn make_room(&mut self, source: IpAddr, now: Instant) {
        self.entries.retain(|_, entry| {
            entry.unauthenticated_websockets > 0
                || now.duration_since(entry.last_seen) <= SIGNIN_RATE_WINDOW
        });
        if !self.entries.contains_key(&source)
            && self.entries.len() >= MAX_SOURCE_LIMIT_ENTRIES
            && let Some(oldest) = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.unauthenticated_websockets == 0)
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(address, _)| *address)
        {
            self.entries.remove(&oldest);
        }
    }

    fn entry(&mut self, source: IpAddr, now: Instant) -> Option<&mut SourceLimitEntry> {
        self.make_room(source, now);
        if !self.entries.contains_key(&source) && self.entries.len() >= MAX_SOURCE_LIMIT_ENTRIES {
            return None;
        }
        Some(
            self.entries
                .entry(source)
                .or_insert_with(|| SourceLimitEntry {
                    signin_attempts: VecDeque::new(),
                    unauthenticated_websockets: 0,
                    last_seen: now,
                }),
        )
    }

    fn admit_signin(&mut self, source: IpAddr, now: Instant) -> bool {
        let Some(entry) = self.entry(source, now) else {
            return false;
        };
        while entry
            .signin_attempts
            .front()
            .is_some_and(|attempt| now.duration_since(*attempt) >= SIGNIN_RATE_WINDOW)
        {
            entry.signin_attempts.pop_front();
        }
        entry.last_seen = now;
        if entry.signin_attempts.len() >= SIGNIN_ATTEMPTS_PER_SOURCE {
            return false;
        }
        entry.signin_attempts.push_back(now);
        true
    }

    fn refund_successful_signin(&mut self, source: IpAddr) {
        if let Some(entry) = self.entries.get_mut(&source) {
            entry.signin_attempts.pop_back();
            entry.last_seen = Instant::now();
        }
    }

    fn admit_websocket(&mut self, source: IpAddr, now: Instant) -> bool {
        let Some(entry) = self.entry(source, now) else {
            return false;
        };
        entry.last_seen = now;
        if entry.unauthenticated_websockets >= MAX_UNAUTHENTICATED_WS_PER_SOURCE {
            return false;
        }
        entry.unauthenticated_websockets += 1;
        true
    }
}

struct SourceConnectionPermit {
    source: IpAddr,
    limits: Arc<StdMutex<SourceLimits>>,
}

impl Drop for SourceConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut limits) = self.limits.lock()
            && let Some(entry) = limits.entries.get_mut(&self.source)
        {
            entry.unauthenticated_websockets = entry.unauthenticated_websockets.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

pub async fn run(config: Config) -> Result<()> {
    let _database_lock = acquire_database_lock(&config.database_path)?;
    let _staging_lock = acquire_path_lock(&config.staging_dir, "staging")?;
    prepare_staging(&config.staging_dir)?;
    let db = Db::open(&config.database_path)?;
    let configured_host = config.public_data_host.clone();
    let mismatched_hosts = db
        .mismatched_data_hosts(&configured_host)
        .context("inspect persisted vault data hosts")?;
    if !mismatched_hosts.is_empty() {
        anyhow::bail!(
            "persisted vault data host(s) {:?} do not match SELFHOST_DATA_HOST={configured_host}; stop the service, run `blackglass-server rebind-data-host {} {configured_host} <backup>`, then restart",
            mismatched_hosts,
            config.database_path.display()
        )
    }
    let (events, _) = broadcast::channel(EVENT_CAPACITY);
    let max_uploads = config.max_concurrent_uploads;
    let max_connections = config.max_ws_connections;
    let (shutdown_tx, shutdown) = watch::channel(false);
    let state = AppState {
        config: Arc::new(config),
        db,
        events,
        commit_order: Arc::new(AsyncMutex::new(())),
        uploads: Arc::new(Semaphore::new(max_uploads)),
        connections: Arc::new(Semaphore::new(max_connections)),
        auth_checks: Arc::new(Semaphore::new(auth::MAX_CONCURRENT_PASSWORD_CHECKS)),
        auth_waiters: Arc::new(Semaphore::new(MAX_SIGNIN_WAITERS)),
        source_limits: Arc::new(StdMutex::new(SourceLimits::default())),
        control_body_readers: Arc::new(Semaphore::new(MAX_CONTROL_BODY_READERS)),
        control_requests: Arc::new(Semaphore::new(MAX_CONTROL_REQUESTS)),
        db_workers: Arc::new(Semaphore::new(MAX_DB_WORKERS)),
        large_responses: Arc::new(Semaphore::new(1)),
        shutdown,
        metrics: Arc::new(Metrics::default()),
    };
    let control = control_router(state.clone());
    let data = data_router(state.clone());
    let control_listener =
        TcpListener::bind((state.config.bind_host, state.config.control_port)).await?;
    let data_listener = TcpListener::bind((state.config.bind_host, state.config.data_port)).await?;
    info!(event="server_started",control=%control_listener.local_addr()?,data=%data_listener.local_addr()?,database=%state.config.database_path.display());
    let mut cstop = state.shutdown.clone();
    let mut dstop = state.shutdown.clone();
    let control_task = tokio::spawn(async move {
        axum::serve(
            control_listener,
            control.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut cstop).await;
        })
        .await
    });
    let data_task = tokio::spawn(async move {
        axum::serve(
            data_listener,
            data.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            wait_for_shutdown(&mut dstop).await;
        })
        .await
    });
    let listener_result =
        supervise_listeners(shutdown_tx, control_task, data_task, shutdown_signal()).await;
    let drain_result = wait_for_connection_drain(&state).await;
    let (checkpoint_result, cleanup_result) = if drain_result.is_ok() {
        (
            db_task(&state, |db| db.checkpoint()).await,
            cleanup_staging(&state.config.staging_dir),
        )
    } else {
        (Ok(()), Ok(()))
    };
    listener_result?;
    drain_result?;
    checkpoint_result?;
    cleanup_result?;
    info!(event = "server_stopped");
    Ok(())
}

fn control_router(state: AppState) -> Router {
    let mut r = Router::new();
    for path in [
        "/user/signin",
        "/user/signout",
        "/user/info",
        "/subscription/list",
        "/vault/regions",
        "/vault/list",
        "/vault/create",
        "/vault/access",
        "/vault/migrate",
        "/vault/rename",
        "/vault/delete",
        "/vault/share/list",
        "/vault/share/invite",
        "/vault/share/remove",
        "/user/signup",
        "/user/forgetpass",
        "/user/resendconfirmation",
        "/subscription/business",
    ] {
        r = r.route(path, post(control).options(preflight));
    }
    r.route_layer(middleware::from_fn_with_state(
        state.clone(),
        control_admission,
    ))
    .route("/health", get(health))
    .route("/ready", get(ready))
    .route("/metrics", get(metrics))
    .with_state(state)
    .layer(DefaultBodyLimit::max(64 * 1024))
}
fn data_router(state: AppState) -> Router {
    Router::new().route("/", get(upgrade)).with_state(state)
}

async fn health(State(s): State<AppState>) -> Response {
    api(
        &s,
        json!({
            "ok": true,
            "service": "blackglass-server",
            "implementation": "rust",
            "version": env!("CARGO_PKG_VERSION"),
            "sourceRevision": crate::SOURCE_REVISION
        }),
        StatusCode::OK,
    )
}
async fn control_admission(State(s): State<AppState>, request: Request, next: Next) -> Response {
    let origin = match permitted_origin(&s, request.headers()) {
        Ok(origin) => origin.map(str::to_owned),
        Err(()) => {
            return api(
                &s,
                json!({"error":"Origin not allowed"}),
                StatusCode::FORBIDDEN,
            );
        }
    };
    let body_permit = match s.control_body_readers.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return control_busy_for_origin(&s, origin.as_deref()),
    };
    let (parts, body) = request.into_parts();
    let body = match timeout(
        CONTROL_BODY_DEADLINE,
        to_bytes(body, MAX_CONTROL_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return api_for_origin(
                &s,
                json!({"error":"Request body too large"}),
                StatusCode::PAYLOAD_TOO_LARGE,
                origin.as_deref(),
            );
        }
        Err(_) => {
            return api_for_origin(
                &s,
                json!({"error":"Request body timed out"}),
                StatusCode::REQUEST_TIMEOUT,
                origin.as_deref(),
            );
        }
    };
    drop(body_permit);
    let permit = match s.control_requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return control_busy_for_origin(&s, origin.as_deref()),
    };
    let request = Request::from_parts(parts, Body::from(body));
    let response = next.run(request).await;
    drop(permit);
    response
}

fn control_busy_for_origin(s: &AppState, origin: Option<&str>) -> Response {
    s.metrics.control_rejections.fetch_add(1, Ordering::Relaxed);
    api_for_origin(
        s,
        json!({"error":"Server busy"}),
        StatusCode::SERVICE_UNAVAILABLE,
        origin,
    )
}

async fn ready(State(s): State<AppState>) -> Response {
    let ok = try_db_task(&s, |db| Ok(db.ready())).await.unwrap_or(false);
    api(
        &s,
        json!({"ok":ok}),
        if ok {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
    )
}
async fn metrics(State(s): State<AppState>) -> Response {
    let m = &s.metrics;
    let body = format!(
        "blackglass_control_requests_total {}\nblackglass_control_rejections_total {}\nblackglass_signins_total {}\nblackglass_auth_failures_total {}\nblackglass_ws_connections_total {}\nblackglass_uploads_total {}\nblackglass_upload_bytes_total {}\nblackglass_downloads_total {}\nblackglass_errors_total {}\nobsidian_sync_control_requests_total {}\nobsidian_sync_signins_total {}\nobsidian_sync_auth_failures_total {}\nobsidian_sync_ws_connections_total {}\nobsidian_sync_uploads_total {}\nobsidian_sync_upload_bytes_total {}\nobsidian_sync_downloads_total {}\nobsidian_sync_errors_total {}\n",
        m.control.load(Ordering::Relaxed),
        m.control_rejections.load(Ordering::Relaxed),
        m.signins.load(Ordering::Relaxed),
        m.auth_failures.load(Ordering::Relaxed),
        m.ws_connections.load(Ordering::Relaxed),
        m.uploads.load(Ordering::Relaxed),
        m.upload_bytes.load(Ordering::Relaxed),
        m.downloads.load(Ordering::Relaxed),
        m.errors.load(Ordering::Relaxed),
        m.control.load(Ordering::Relaxed),
        m.signins.load(Ordering::Relaxed),
        m.auth_failures.load(Ordering::Relaxed),
        m.ws_connections.load(Ordering::Relaxed),
        m.uploads.load(Ordering::Relaxed),
        m.upload_bytes.load(Ordering::Relaxed),
        m.downloads.load(Ordering::Relaxed),
        m.errors.load(Ordering::Relaxed)
    );
    (
        [
            (header::CONTENT_TYPE, "text/plain; version=0.0.4"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}
async fn preflight(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let request_origin = match permitted_origin(&s, &headers) {
        Ok(origin) => origin,
        Err(()) => return StatusCode::FORBIDDEN.into_response(),
    };
    let mut response = api_for_origin(&s, Value::Null, StatusCode::NO_CONTENT, request_origin);
    let h = response.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, GET, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    response
}

async fn control(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    s.metrics.control.fetch_add(1, Ordering::Relaxed);
    let request_origin = match permitted_origin(&s, &headers) {
        Ok(origin) => origin,
        Err(()) => {
            warn!(event="origin_rejected",route=%uri.path());
            return api(
                &s,
                json!({"error":"Origin not allowed"}),
                StatusCode::FORBIDDEN,
            );
        }
    };
    let value: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return api_for_origin(
                &s,
                json!({"error":"Invalid JSON"}),
                StatusCode::BAD_REQUEST,
                request_origin,
            );
        }
    };
    let source = request_source(&s.config, peer, &headers);
    let result = match uri.path() {
        "/user/signin" => signin(&s, source, value).await,
        "/user/signup" | "/user/forgetpass" | "/user/resendconfirmation" => {
            Err("Accounts are managed by the Blackglass Server administrator".into())
        }
        _ => authorized_control(&s, uri.path(), value).await,
    };
    match result {
        Ok(v) => api_for_origin(&s, v, StatusCode::OK, request_origin),
        Err(message) => {
            s.metrics.errors.fetch_add(1, Ordering::Relaxed);
            api_for_origin(&s, json!({"error":message}), StatusCode::OK, request_origin)
        }
    }
}

async fn signin(s: &AppState, source: IpAddr, v: Value) -> std::result::Result<Value, String> {
    let req: Signin =
        serde_json::from_value(v).map_err(|_| "Invalid email or password".to_string())?;
    let admitted = s
        .source_limits
        .lock()
        .map_err(|_| "Try again later".to_string())?
        .admit_signin(source, Instant::now());
    if !admitted {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_rate_limited");
        return Err("Too many sign-in attempts; try again later".into());
    }
    let waiter = match s.auth_waiters.clone().try_acquire_owned() {
        Ok(waiter) => waiter,
        Err(_) => {
            s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            warn!(event = "signin_capacity_reached");
            return Err("Try again later".into());
        }
    };
    let permit = match timeout(SIGNIN_QUEUE_TIMEOUT, s.auth_checks.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        _ => {
            s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            warn!(event = "signin_queue_timed_out");
            return Err("Try again later".into());
        }
    };
    drop(waiter);
    let email_ok = req
        .email
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case(&s.config.email));
    let password = req.password.unwrap_or_default();
    let encoded = s.config.password_hash.clone();
    let password_ok = tokio::task::spawn_blocking(move || {
        let valid = auth::verify_password(&password, &encoded);
        drop(permit);
        valid
    })
    .await
    .map_err(internal)?;
    if !email_ok || !password_ok {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_failed");
        return Err("Invalid email or password".into());
    }
    if let Ok(mut limits) = s.source_limits.lock() {
        limits.refund_successful_signin(source);
    }
    let ttl = s.config.session_ttl.as_secs() as i64;
    let token = db_task(s, move |db| db.issue_session(ttl))
        .await
        .map_err(internal)?;
    s.metrics.signins.fetch_add(1, Ordering::Relaxed);
    info!(event = "signin_succeeded");
    Ok(json!({"email":s.config.email,"name":s.config.display_name,"license":null,"token":token}))
}

async fn authorized_control(
    s: &AppState,
    path: &str,
    v: Value,
) -> std::result::Result<Value, String> {
    let token = v
        .get("token")
        .and_then(Value::as_str)
        .ok_or("Not logged in")?
        .to_owned();
    let validation_token = token.clone();
    if !db_task(s, move |db| Ok(db.valid_session(&validation_token)))
        .await
        .map_err(internal)?
    {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("Not logged in".into());
    }
    match path {
        "/user/signout" => {
            db_task(s, move |db| db.revoke_session(&token))
                .await
                .map_err(internal)?;
            Ok(json!({}))
        }
        "/user/info" => {
            Ok(json!({"email":s.config.email,"name":s.config.display_name,"license":null}))
        }
        "/subscription/list" => Ok(json!({"sync":true,"publish":false})),
        "/subscription/business" => {
            Err("Business subscriptions are unavailable on a self-hosted server".into())
        }
        "/vault/regions" => {
            Ok(json!({"regions":[{"value":"selfhost","name":"Blackglass Server"}]}))
        }
        "/vault/list" => Ok(json!({
            "vaults":db_task(s, |db| db.list_vaults()).await.map_err(internal)?,
            "shared":[],
            "limit":100
        })),
        "/vault/create" => create_vault(s, v).await,
        "/vault/access" => access_vault(s, v).await,
        "/vault/migrate" => migrate_vault(s, v).await,
        "/vault/rename" => rename_vault(s, v).await,
        "/vault/delete" => delete_vault(s, v).await,
        "/vault/share/list" => Ok(json!({"shares":[]})),
        "/vault/share/invite" | "/vault/share/remove" => {
            Err("Sharing is unavailable in single-user mode".into())
        }
        _ => Err("Not found".into()),
    }
}

async fn create_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultCreate =
        serde_json::from_value(v).map_err(|_| "Invalid vault request".to_string())?;
    let name = r
        .name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or("Vault name is required")?
        .to_owned();
    let version = r
        .encryption_version
        .filter(|v| (0..=3).contains(v))
        .ok_or("Unsupported encryption version")?;
    let VaultCredentials {
        keyhash,
        salt,
        password,
    } = vault_credentials(r.keyhash, r.salt)?;
    let vault = Vault {
        id: Uuid::new_v4().to_string(),
        name,
        keyhash,
        salt,
        host: s.config.public_data_host.clone(),
        region: "Blackglass Server".into(),
        encryption_version: version,
        size: 0,
        created: now_ms(),
        password,
    };
    let stored = vault.clone();
    if let Err(error) = db_task(s, move |db| db.create_vault(&stored)).await {
        if error.to_string().contains("vault limit reached") {
            return Err("Vault limit reached".into());
        }
        return Err(internal(error));
    }
    serde_json::to_value(vault).map_err(internal)
}
async fn access_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultAccess =
        serde_json::from_value(v).map_err(|_| "Unable to access vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to access vault")?;
    let lookup_id = id.clone();
    let mut vault = db_task(s, move |db| db.find_vault(&lookup_id))
        .await
        .map_err(internal)?
        .ok_or("Unable to access vault")?;
    if r.host.as_deref() != Some(&vault.host)
        || r.encryption_version != Some(vault.encryption_version)
    {
        return Err("Unable to access vault".into());
    }
    if vault.password.is_some() && vault.keyhash.is_none() {
        let requested = r
            .keyhash
            .as_deref()
            .filter(|keyhash| !keyhash.is_empty() && keyhash.len() <= 4096)
            .ok_or("Unable to access vault")?;
        let bind_id = vault.id.clone();
        let requested = requested.to_owned();
        vault.keyhash = db_task(s, move |db| db.bind_managed_keyhash(&bind_id, &requested))
            .await
            .map_err(internal)?;
    }
    if r.keyhash != vault.keyhash {
        return Err("Unable to access vault".into());
    }
    Ok(json!({}))
}
async fn migrate_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultMigrate =
        serde_json::from_value(v).map_err(|_| "Unable to migrate vault".to_string())?;
    let source_id = r.vault_uid.ok_or("Unable to migrate vault")?;
    if r.encryption_version != Some(3) {
        return Err("Unsupported encryption version".into());
    }
    let VaultCredentials {
        keyhash,
        salt,
        password,
    } = vault_credentials(r.keyhash, r.salt)?;
    let _commit = s.commit_order.lock().await;
    let lookup_id = source_id.clone();
    let source = db_task(s, move |db| db.find_vault(&lookup_id))
        .await
        .map_err(internal)?
        .ok_or("Unable to migrate vault")?;
    if source.encryption_version >= 3 {
        return Err("Vault already uses encryption version 3".into());
    }
    let replacement = Vault {
        id: Uuid::new_v4().to_string(),
        name: source.name,
        keyhash,
        salt,
        host: s.config.public_data_host.clone(),
        region: "Blackglass Server".into(),
        encryption_version: 3,
        size: 0,
        created: now_ms(),
        password,
    };
    let stored = replacement.clone();
    let migrate_source_id = source_id.clone();
    if !db_task(s, move |db| db.migrate_vault(&migrate_source_id, &stored))
        .await
        .map_err(internal)?
    {
        return Err("Unable to migrate vault".into());
    }
    invalidate_vault(s, source_id);
    serde_json::to_value(replacement).map_err(internal)
}
async fn rename_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultRename =
        serde_json::from_value(v).map_err(|_| "Unable to rename vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to rename vault")?;
    let name = r
        .name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or("Unable to rename vault")?
        .to_owned();
    let _commit = s.commit_order.lock().await;
    if !db_task(s, move |db| db.rename_vault(&id, &name))
        .await
        .map_err(internal)?
    {
        return Err("Unable to rename vault".into());
    }
    Ok(json!({}))
}
async fn delete_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultDelete =
        serde_json::from_value(v).map_err(|_| "Unable to delete vault".to_string())?;
    let id = r.vault_uid.unwrap_or_default();
    let _commit = s.commit_order.lock().await;
    let delete_id = id.clone();
    if !db_task(s, move |db| db.delete_vault(&delete_id))
        .await
        .map_err(internal)?
    {
        return Err("Unable to delete vault".into());
    }
    invalidate_vault(s, id);
    Ok(json!({}))
}

struct VaultCredentials {
    keyhash: Option<String>,
    salt: Option<String>,
    password: Option<String>,
}

fn vault_credentials(
    keyhash: Option<String>,
    salt: Option<String>,
) -> std::result::Result<VaultCredentials, String> {
    match (keyhash, salt) {
        (None, None) => {
            let (password, salt) = auth::new_managed_vault_credentials();
            Ok(VaultCredentials {
                keyhash: None,
                salt: Some(salt),
                password: Some(password),
            })
        }
        (Some(keyhash), Some(salt))
            if !keyhash.is_empty()
                && keyhash.len() <= 4096
                && !salt.is_empty()
                && salt.len() <= 4096 =>
        {
            Ok(VaultCredentials {
                keyhash: Some(keyhash),
                salt: Some(salt),
                password: None,
            })
        }
        _ => Err("Invalid encryption credentials".into()),
    }
}

fn invalidate_vault(s: &AppState, vault: String) {
    let _ = s.events.send(Event {
        uid: 0,
        vault,
        text: String::new(),
        invalidated: true,
    });
}

async fn upgrade(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    State(s): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if permitted_origin(&s, &headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let source = request_source(&s.config, peer, &headers);
    let source_permit = {
        let admitted = s
            .source_limits
            .lock()
            .is_ok_and(|mut limits| limits.admit_websocket(source, Instant::now()));
        if !admitted {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        SourceConnectionPermit {
            source,
            limits: s.source_limits.clone(),
        }
    };
    let permit = match s.connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    ws.max_frame_size(PIECE_SIZE as usize)
        .max_message_size(PIECE_SIZE as usize)
        .on_upgrade(move |socket| socket_loop(s, socket, permit, source_permit))
        .into_response()
}

struct Session {
    authenticated: bool,
    token_hash: Option<String>,
    vault: Option<String>,
    device: String,
    pending: Option<Pending>,
}
struct Pending {
    revision: NewRevision,
    path: PathBuf,
    file: tokio::fs::File,
    pieces: i64,
    bytes: i64,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

async fn socket_loop(
    s: AppState,
    socket: WebSocket,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    source_permit: SourceConnectionPermit,
) {
    s.metrics.ws_connections.fetch_add(1, Ordering::Relaxed);
    let (mut tx, mut rx) = socket.split();
    let mut events = s.events.subscribe();
    let mut shutdown = s.shutdown.clone();
    let mut session = Session {
        authenticated: false,
        token_hash: None,
        vault: None,
        device: "Unknown device".into(),
        pending: None,
    };
    let mut source_permit = Some(source_permit);
    let authentication_deadline = tokio::time::sleep(AUTHENTICATION_DEADLINE);
    tokio::pin!(authentication_deadline);
    let mut session_revalidation = interval(SESSION_REVALIDATE_INTERVAL);
    session_revalidation.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(&mut shutdown) => {
                let _ = socket_send(
                    &mut tx,
                    Message::Close(Some(CloseFrame {
                        code: 1001,
                        reason: "Server shutting down".into(),
                    })),
                ).await;
                break
            },
            _ = &mut authentication_deadline, if !session.authenticated => {
                let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                    code: 1008,
                    reason: "Authentication deadline exceeded".into(),
                }))).await;
                break
            },
            _ = session_revalidation.tick(), if session.authenticated => {
                if !session_active(&s, &session).await {
                    let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "Session expired or revoked".into(),
                    }))).await;
                    break
                }
            },
            incoming = rx.next() => match incoming {
                Some(Ok(Message::Close(_))) => break,
                Some(Ok(msg)) => {
                    let result = handle_message(
                        &s,
                        &mut session,
                        &mut events,
                        &mut tx,
                        msg,
                    ).await;
                    if session.authenticated {
                        drop(source_permit.take());
                    }
                    if let Err(error) = result {
                        warn!(event = "websocket_error", error = %error);
                        s.metrics.errors.fetch_add(1, Ordering::Relaxed);
                        break
                    }
                },
                _ => break,
            },
            event = events.recv() => match event {
                Ok(event) if session.vault.as_deref() == Some(&event.vault) && event.invalidated => {
                    let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "Vault deleted or replaced".into(),
                    }))).await;
                    break
                },
                Ok(event) if session.vault.as_deref() == Some(&event.vault) => {
                    if !session_active(&s, &session).await {
                        let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                            code: 1008,
                            reason: "Session expired or revoked".into(),
                        }))).await;
                        break
                    }
                    if socket_send(&mut tx, Message::Text(event.text.into())).await.is_err() {
                        break
                    }
                },
                Ok(_) => {},
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                        code: 1013,
                        reason: "Change stream lagged; reconnect to resume".into(),
                    }))).await;
                    break
                },
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    if let Some(p) = session.pending {
        drop(p.file);
        let _ = tokio::fs::remove_file(p.path).await;
    }
}

async fn handle_message(
    s: &AppState,
    session: &mut Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    msg: Message,
) -> Result<()> {
    match msg {
        Message::Text(text) => {
            if text.len() > 64 * 1024 {
                return close(tx, 1009, "JSON message too large").await;
            }
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) if !session.authenticated => {
                    return close(tx, 1008, "Authentication required").await;
                }
                Err(_) => {
                    send(tx, json!({"res":"err","msg":"Invalid JSON"})).await?;
                    return Ok(());
                }
            };
            let op = v.get("op").and_then(Value::as_str).unwrap_or("");
            if !session.authenticated {
                if op != "init" {
                    return close(tx, 1008, "Authentication required").await;
                }
                return init(s, session, events, tx, v).await;
            }
            if !session_active(s, session).await {
                return close(tx, 1008, "Session expired or revoked").await;
            }
            match op {
                "ping" => send(tx, json!({"op":"pong"})).await?,
                "size" => {
                    let vault = session.vault.clone().unwrap();
                    let (size, vault_size) =
                        db_task(s, move |db| Ok((db.total_size()?, db.vault_size(&vault)?)))
                            .await?;
                    send(tx,json!({"res":"ok","size":size,"limit":1099511627776i64,"vault_size":vault_size})).await?
                }
                "usernames" => send(tx, json!({"1":s.config.display_name})).await?,
                "push" => begin_push(s, session, events, tx, v).await?,
                "pull" => pull(s, session, tx, v).await?,
                "deleted" => deleted(s, session, tx, v).await?,
                "history" => history(s, session, tx, v).await?,
                "restore" => restore(s, session, events, tx, v).await?,
                "purge" => {
                    let vault = session.vault.clone().unwrap();
                    let _commit = s.commit_order.lock().await;
                    db_task(s, move |db| db.purge(&vault)).await?;
                    drop(_commit);
                    send(tx, json!({"res":"ok"})).await?
                }
                _ => send(tx, json!({"err":format!("Unsupported operation: {op}")})).await?,
            }
            Ok(())
        }
        Message::Binary(bytes) => {
            if !session.authenticated || !session_active(s, session).await {
                return close(tx, 1008, "Authentication required").await;
            }
            upload_chunk(s, session, events, tx, &bytes).await
        }
        // The socket loop intercepts peer close frames as normal termination.
        // Keep this arm non-erroring as a defensive fallback.
        Message::Close(_) => Ok(()),
        Message::Ping(v) => {
            if !session.authenticated || !session_active(s, session).await {
                return close(tx, 1008, "Authentication required").await;
            }
            socket_send(tx, Message::Pong(v)).await?;
            Ok(())
        }
        Message::Pong(_) if session.authenticated => Ok(()),
        Message::Pong(_) => close(tx, 1008, "Authentication required").await,
    }
}

async fn init(
    s: &AppState,
    session: &mut Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    if v.get("op").and_then(Value::as_str) != Some("init") {
        send(tx, json!({"res":"err","msg":"Authentication required"})).await?;
        return Ok(());
    }
    let token = v
        .get("token")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_owned();
    let token_hash = auth::token_hash(&token);
    let lookup_id = id.clone();
    let validation_hash = token_hash.clone();
    let token_has_session_shape = token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let keyhash = v.get("keyhash").and_then(Value::as_str).map(str::to_owned);
    let enc = v.get("encryption_version").and_then(Value::as_i64);
    let (vault, valid_session, retired_vault) = db_task(s, move |db| {
        Ok((
            db.find_vault(&lookup_id)?,
            token_has_session_shape && db.valid_session_hash(&validation_hash),
            db.is_retired_vault(&lookup_id)?,
        ))
    })
    .await?;
    let Some(vault) = vault else {
        if valid_session || (token_has_session_shape && retired_vault) {
            send(tx, json!({"res":"err","msg":"Vault not found"})).await?;
            return close(tx, 1008, "Vault not found").await;
        }
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    };
    if !valid_session
        || keyhash.as_deref() != vault.keyhash.as_deref()
        || enc != Some(vault.encryption_version)
    {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    }
    let version = match v.get("version") {
        None => 0,
        Some(value) => match value.as_i64() {
            Some(version) if (0..=MAX_JS_SAFE_INTEGER).contains(&version) => version,
            _ => {
                send(tx, json!({"res":"err","msg":"Invalid Sync version"})).await?;
                return close(tx, 1008, "Invalid Sync version").await;
            }
        },
    };
    session.authenticated = true;
    session.token_hash = Some(token_hash);
    session.vault = Some(vault.id.clone());
    session.device = bounded(
        v.get("device")
            .and_then(Value::as_str)
            .unwrap_or("Unknown device"),
        256,
    )
    .unwrap_or("Unknown device")
    .into();
    let initial = v.get("initial").and_then(Value::as_bool).unwrap_or(false);
    let ready_version = {
        // Establish the replay/live boundary while commits are serialized. Replacing
        // the pre-auth receiver drops already-replayed events; every later commit is
        // then queued exactly once even when sending the replay is slow.
        let _commit = s.commit_order.lock().await;
        let vault_id = vault.id.clone();
        let ready_version = db_task(s, move |db| db.current_version(&vault_id)).await?;
        *events = s.events.subscribe();
        ready_version
    };
    if !initial && version > ready_version {
        send(
            tx,
            json!({"res":"err","msg":"Client Sync version is ahead of the server; reconnect this vault as a fresh client after restore"}),
        )
        .await?;
        return close(tx, 1008, "Client Sync version is ahead of the server").await;
    }
    send(
        tx,
        json!({"res":"ok","userId":1,"perFileMax":s.config.per_file_max}),
    )
    .await?;
    let mut cursor = if initial { 0 } else { version };
    loop {
        if shutting_down(s) {
            return Ok(());
        }
        if !session_active(s, session).await {
            return close(tx, 1008, "Session expired or revoked").await;
        }
        let vault_id = vault.id.clone();
        let page = db_task(s, move |db| {
            if initial {
                db.initial_snapshot_page(&vault_id, cursor, ready_version, REPLAY_PAGE_SIZE)
            } else {
                db.list_changes_page(&vault_id, cursor, ready_version, REPLAY_PAGE_SIZE)
            }
        })
        .await?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        for revision in page {
            if shutting_down(s) {
                return Ok(());
            }
            cursor = revision.uid;
            send(tx, serde_json::to_value(PushNotice::from(revision))?).await?;
        }
        if page_len < REPLAY_PAGE_SIZE as usize {
            break;
        }
    }
    send(tx, json!({"op":"ready","version":ready_version})).await?;
    Ok(())
}

async fn begin_push(
    s: &AppState,
    session: &mut Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    if session.pending.is_some() {
        send(tx, json!({"err":"An upload is already in progress"})).await?;
        return Ok(());
    }
    let size = v.get("size").and_then(Value::as_i64).unwrap_or(0);
    let pieces = v.get("pieces").and_then(Value::as_i64).unwrap_or(0);
    let valid = bounded(v.get("path").and_then(Value::as_str).unwrap_or(""), 16384).is_some()
        && match v.get("relatedpath") {
            None | Some(Value::Null) => true,
            Some(Value::String(value)) => value.len() <= 16384,
            _ => false,
        }
        && v.get("extension")
            .and_then(Value::as_str)
            .is_some_and(|x| x.len() <= 256)
        && v.get("hash")
            .and_then(Value::as_str)
            .is_some_and(|x| x.len() <= 4096)
        && v.get("ctime")
            .and_then(Value::as_i64)
            .is_some_and(js_safe_nonnegative)
        && v.get("mtime")
            .and_then(Value::as_i64)
            .is_some_and(js_safe_nonnegative)
        && v.get("folder").and_then(Value::as_bool).is_some()
        && v.get("deleted").and_then(Value::as_bool).is_some()
        && size >= 0
        && size <= max_ciphertext_size(&s.config)
        && pieces >= 0
        && pieces == (size + PIECE_SIZE - 1) / PIECE_SIZE;
    if !valid {
        send(tx, json!({"err":"Invalid push metadata"})).await?;
        return Ok(());
    }
    let revision = NewRevision {
        vault_id: session.vault.clone().unwrap(),
        path: v["path"].as_str().unwrap().into(),
        relatedpath: v
            .get("relatedpath")
            .and_then(Value::as_str)
            .map(str::to_string),
        extension: v["extension"].as_str().unwrap().into(),
        hash: v["hash"].as_str().unwrap().into(),
        ctime: v["ctime"].as_i64().unwrap(),
        mtime: v["mtime"].as_i64().unwrap(),
        folder: v["folder"].as_bool().unwrap(),
        deleted: v["deleted"].as_bool().unwrap(),
        size,
        pieces,
        device: session.device.clone(),
        user_id: 1,
    };
    if serialized_notice_size(&revision)? > MAX_EVENT_BYTES {
        send(tx, json!({"err":"Push metadata is too large"})).await?;
        return Ok(());
    }
    if revision.folder || revision.deleted || pieces == 0 {
        let notice = {
            let _commit = s.commit_order.lock().await;
            let stored = db_task(s, move |db| db.add_empty_revision(&revision)).await?;
            publish_committed(s, stored)?
        };
        acknowledge_commit(s, session, events, tx, notice).await?;
        return Ok(());
    }
    let permit = match s.uploads.clone().try_acquire_owned() {
        Ok(v) => v,
        Err(_) => {
            send(
                tx,
                json!({"err":"Server upload capacity reached; retry shortly"}),
            )
            .await?;
            return Ok(());
        }
    };
    let path = s
        .config
        .staging_dir
        .join(format!("{}.part", Uuid::new_v4()));
    let file = secure_create(&path).await?;
    session.pending = Some(Pending {
        revision,
        path,
        file,
        pieces: 0,
        bytes: 0,
        _permit: permit,
    });
    send(tx, json!({"res":"next"})).await?;
    Ok(())
}

async fn upload_chunk(
    s: &AppState,
    session: &mut Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    bytes: &Bytes,
) -> Result<()> {
    let Some(p) = session.pending.as_mut() else {
        return close(tx, 1008, "Unexpected binary message").await;
    };
    if bytes.len() > PIECE_SIZE as usize {
        return close(tx, 1009, "Upload piece too large").await;
    }
    p.pieces += 1;
    p.bytes += bytes.len() as i64;
    if p.pieces > p.revision.pieces || p.bytes > p.revision.size {
        return close(tx, 1009, "Upload exceeds declared size").await;
    }
    write_staged_piece(&mut p.file, bytes).await?;
    if p.pieces < p.revision.pieces {
        send(tx, json!({"res":"next"})).await?;
        return Ok(());
    }
    if p.bytes != p.revision.size {
        return close(tx, 1008, "Upload size does not match metadata").await;
    }
    p.file.sync_all().await?;
    let pending = session.pending.take().unwrap();
    drop(pending.file);
    let revision = pending.revision.clone();
    let path = pending.path.clone();
    let commit_result = {
        let _commit = s.commit_order.lock().await;
        db_task(s, move |db| db.add_file_revision(&revision, &path))
            .await
            .and_then(|stored| {
                let stored_size = stored.size;
                Ok((publish_committed(s, stored)?, stored_size))
            })
    };
    if let Err(error) = tokio::fs::remove_file(&pending.path).await {
        warn!(event = "staged_upload_cleanup_failed", error = %error);
        if commit_result.is_ok() {
            return Err(error.into());
        }
    }
    let (notice, stored_size) = commit_result?;
    s.metrics.uploads.fetch_add(1, Ordering::Relaxed);
    s.metrics
        .upload_bytes
        .fetch_add(stored_size as u64, Ordering::Relaxed);
    acknowledge_commit(s, session, events, tx, notice).await
}

async fn write_staged_piece<W>(file: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    file.write_all(bytes).await?;
    // Tokio may acknowledge an async file write after copying the piece into
    // its blocking buffer. Finish that write before requesting another piece
    // so each `next` response preserves the bounded on-disk staging contract.
    file.flush().await
}

async fn pull(
    s: &AppState,
    session: &Session,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    let Some(uid) = v.get("uid").and_then(Value::as_i64) else {
        send(tx, json!({"err":"Revision not found"})).await?;
        return Ok(());
    };
    let Some(info) = db_task(s, move |db| db.pull_info(uid)).await? else {
        send(tx, json!({"err":"Revision not found"})).await?;
        return Ok(());
    };
    if session.vault.as_deref() != Some(&info.vault_id) {
        send(tx, json!({"err":"Revision not found"})).await?;
        return Ok(());
    }
    if info.deleted || info.folder || !info.has_content {
        send(
            tx,
            json!({"res":"ok","size":0,"pieces":0,"deleted":info.deleted,"hash":info.hash}),
        )
        .await?;
        return Ok(());
    }
    send(
        tx,
        json!({"res":"ok","size":info.size,"pieces":info.pieces,"deleted":false,"hash":info.hash}),
    )
    .await?;
    let mut offset = 0;
    while offset < info.size {
        if shutting_down(s) {
            return Ok(());
        }
        if !session_active(s, session).await {
            return close(tx, 1008, "Session expired or revoked").await;
        }
        let len = (info.size - offset).min(PIECE_SIZE);
        let chunk = db_task(s, move |db| db.content_chunk(uid, offset, len)).await?;
        socket_send(tx, Message::Binary(chunk.into())).await?;
        offset += len
    }
    s.metrics.downloads.fetch_add(1, Ordering::Relaxed);
    Ok(())
}
async fn history(
    s: &AppState,
    session: &Session,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    let _response_permit = s
        .large_responses
        .acquire()
        .await
        .context("large-response pool stopped")?;
    let Some(path) = v
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| bounded(p, 16384).is_some())
    else {
        send(tx, json!({"err":"Invalid history path"})).await?;
        return Ok(());
    };
    let vault = session.vault.clone().unwrap();
    let path = path.to_owned();
    let last = v.get("last").and_then(Value::as_i64);
    let all = db_task(s, move |db| db.history(&vault, &path, last, 101)).await?;
    let more = all.len() > 100;
    let items = all
        .into_iter()
        .take(100)
        .map(notice_item)
        .collect::<Vec<_>>();
    if !send_with_limit(
        tx,
        json!({"items":items,"more":more}),
        MAX_LARGE_RESPONSE_BYTES,
    )
    .await?
    {
        send(
            tx,
            json!({"err":"History response exceeds the safe wire limit"}),
        )
        .await?;
    }
    Ok(())
}
async fn deleted(
    s: &AppState,
    session: &Session,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    let _response_permit = s
        .large_responses
        .acquire()
        .await
        .context("large-response pool stopped")?;
    let vault = session.vault.clone().unwrap();
    let suppress = v.get("suppressrenames").and_then(Value::as_bool) == Some(true);
    let _commit = s.commit_order.lock().await;
    let mut response = Vec::with_capacity(64 * 1024);
    response.extend_from_slice(b"{\"items\":[");
    let mut after = 0;
    let mut first = true;
    loop {
        let page_vault = vault.clone();
        let page = db_task(s, move |db| {
            db.list_deleted_page(&page_vault, suppress, after, DELETED_PAGE_SIZE)
        })
        .await?;
        let page_len = page.len();
        for revision in page {
            after = revision.uid;
            let encoded = serde_json::to_vec(&notice_item(revision))?;
            let separator = usize::from(!first);
            if response
                .len()
                .saturating_add(separator)
                .saturating_add(encoded.len())
                .saturating_add(2)
                > MAX_LARGE_RESPONSE_BYTES
            {
                drop(_commit);
                drop(response);
                send(
                    tx,
                    json!({"err":"Deleted response exceeds the safe wire limit; ask the server operator to stop the service, run `blackglass-server purge-deleted <database> <vault-id> <backup>`, and retry"}),
                )
                .await?;
                return Ok(());
            }
            if !first {
                response.push(b',');
            }
            first = false;
            response.extend_from_slice(&encoded);
        }
        if page_len < DELETED_PAGE_SIZE as usize {
            break;
        }
    }
    response.extend_from_slice(b"]}");
    drop(_commit);
    let response = String::from_utf8(response).context("serialize deleted response")?;
    socket_send(tx, Message::Text(response.into())).await?;
    Ok(())
}
async fn restore(
    s: &AppState,
    session: &Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    let Some(uid) = v.get("uid").and_then(Value::as_i64) else {
        send(tx, json!({"err":"Revision not found"})).await?;
        return Ok(());
    };
    let notice = {
        let _commit = s.commit_order.lock().await;
        let vault = session.vault.clone().unwrap();
        let device = session.device.clone();
        match db_task(s, move |db| db.restore(&vault, uid, &device)).await {
            Ok(revision) => revision
                .map(|revision| publish_committed(s, revision))
                .transpose()?,
            Err(error)
                if error
                    .to_string()
                    .contains("restored revision metadata exceeds the bounded event size") =>
            {
                drop(_commit);
                send(tx, json!({"err":"Restore metadata is too large"})).await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    };
    match notice {
        Some(notice) => acknowledge_commit(s, session, events, tx, notice).await?,
        None => send(tx, json!({"err":"Revision not found"})).await?,
    }
    Ok(())
}
fn publish_committed(s: &AppState, r: Revision) -> Result<Event> {
    let uid = r.uid;
    let vault = r.vault_id.clone();
    let notice = serde_json::to_value(PushNotice::from(r))?;
    let text = serde_json::to_string(&notice)?;
    if text.len() > MAX_EVENT_BYTES {
        anyhow::bail!("committed notice exceeds the bounded event size")
    }
    let event = Event {
        uid,
        vault,
        text,
        invalidated: false,
    };
    let _ = s.events.send(event.clone());
    Ok(event)
}

fn serialized_notice_size(revision: &NewRevision) -> Result<usize> {
    Ok(serde_json::to_vec(&json!({
        "op": "push",
        "path": revision.path,
        "relatedpath": revision.relatedpath,
        "extension": revision.extension,
        "hash": revision.hash,
        "ctime": revision.ctime,
        "mtime": revision.mtime,
        "folder": revision.folder,
        "deleted": revision.deleted,
        "size": revision.size,
        "uid": i64::MAX,
        "device": revision.device,
        "user": revision.user_id,
        "ts": i64::MAX,
    }))?
    .len())
}
async fn acknowledge_commit(
    s: &AppState,
    session: &Session,
    events: &mut broadcast::Receiver<Event>,
    tx: &mut SplitSink<WebSocket, Message>,
    committed: Event,
) -> Result<()> {
    if shutting_down(s) {
        return Ok(());
    }
    loop {
        match events.recv().await {
            Ok(event) if event.vault == committed.vault && event.invalidated => {
                return close(tx, 1008, "Vault deleted or replaced").await;
            }
            Ok(event) if event.vault == committed.vault => {
                if shutting_down(s) {
                    return Ok(());
                }
                if !session_active(s, session).await {
                    return close(tx, 1008, "Session expired or revoked").await;
                }
                let uid = event.uid;
                socket_send(tx, Message::Text(event.text.into())).await?;
                if uid == committed.uid {
                    break;
                }
                if uid > committed.uid {
                    return Err(anyhow::anyhow!(
                        "ordered change stream skipped originating commit"
                    ));
                }
            }
            Ok(_) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => {
                return close(tx, 1013, "Change stream lagged; reconnect to resume").await;
            }
            Err(broadcast::error::RecvError::Closed) => {
                return Err(anyhow::anyhow!("change stream closed"));
            }
        }
    }
    if !session_active(s, session).await {
        return close(tx, 1008, "Session expired or revoked").await;
    }
    send(tx, json!({"res":"ok"})).await?;
    Ok(())
}
fn notice_item(r: Revision) -> Value {
    let mut v = serde_json::to_value(PushNotice::from(r)).unwrap_or(Value::Null);
    v.as_object_mut().map(|o| o.remove("op"));
    v
}

async fn send(tx: &mut SplitSink<WebSocket, Message>, v: Value) -> Result<()> {
    if !send_with_limit(tx, v, MAX_LARGE_RESPONSE_BYTES).await? {
        anyhow::bail!("outbound JSON exceeds the safe wire limit")
    }
    Ok(())
}
async fn send_with_limit(
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
    limit: usize,
) -> Result<bool> {
    let text = serde_json::to_string(&v)?;
    drop(v);
    if text.len() > limit {
        return Ok(false);
    }
    socket_send(tx, Message::Text(text.into())).await?;
    Ok(true)
}
async fn socket_send(tx: &mut SplitSink<WebSocket, Message>, message: Message) -> Result<()> {
    timeout(SOCKET_WRITE_TIMEOUT, tx.send(message))
        .await
        .context("websocket write timed out")??;
    Ok(())
}
async fn close(
    tx: &mut SplitSink<WebSocket, Message>,
    code: u16,
    reason: &'static str,
) -> Result<()> {
    socket_send(
        tx,
        Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })),
    )
    .await?;
    Err(anyhow::anyhow!(reason))
}
fn bounded(v: &str, max: usize) -> Option<&str> {
    if !v.is_empty() && v.len() <= max {
        Some(v)
    } else {
        None
    }
}
fn js_safe_nonnegative(value: i64) -> bool {
    (0..=MAX_JS_SAFE_INTEGER).contains(&value)
}
fn max_ciphertext_size(config: &Config) -> i64 {
    config.per_file_max.saturating_add(AES_GCM_WIRE_OVERHEAD) as i64
}
fn internal(e: impl std::fmt::Display) -> String {
    warn!(event="internal_error",error=%e);
    "Internal server error".into()
}
fn api(s: &AppState, value: Value, status: StatusCode) -> Response {
    api_for_origin(s, value, status, None)
}
fn api_for_origin(
    s: &AppState,
    value: Value,
    status: StatusCode,
    request_origin: Option<&str>,
) -> Response {
    let mut h = HeaderMap::new();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let allowed_origin = request_origin
        .or_else(|| s.config.allowed_origins.first().map(String::as_str))
        .unwrap_or("app://obsidian.md");
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(allowed_origin)
            .unwrap_or(HeaderValue::from_static("app://obsidian.md")),
    );
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    (status, h, Json(value)).into_response()
}
fn permitted_origin<'a>(
    s: &AppState,
    h: &'a HeaderMap,
) -> std::result::Result<Option<&'a str>, ()> {
    let value = h.get(header::ORIGIN).ok_or(())?;
    let origin = value.to_str().map_err(|_| ())?;
    if s.config
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        Ok(Some(origin))
    } else {
        Err(())
    }
}

fn request_source(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if config.trusted_proxy != Some(peer.ip()) {
        return peer.ip();
    }
    let Some(forwarded) = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains(','))
        .and_then(|value| value.parse::<IpAddr>().ok())
    else {
        // A trusted proxy must overwrite X-Forwarded-For with exactly one
        // address. Missing, malformed, or ambiguous values collapse to the
        // proxy source, which is safe and deliberately rate-limited.
        return peer.ip();
    };
    forwarded
}

async fn db_task<T, F>(state: &AppState, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Db) -> Result<T> + Send + 'static,
{
    let permit = state
        .db_workers
        .clone()
        .acquire_owned()
        .await
        .context("database worker pool stopped")?;
    spawn_db_task(state, permit, operation).await
}

async fn try_db_task<T, F>(state: &AppState, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Db) -> Result<T> + Send + 'static,
{
    let permit = state
        .db_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("database worker capacity reached"))?;
    spawn_db_task(state, permit, operation).await
}

async fn spawn_db_task<T, F>(
    state: &AppState,
    permit: tokio::sync::OwnedSemaphorePermit,
    operation: F,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Db) -> Result<T> + Send + 'static,
{
    let database = state.db.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(database)
    })
    .await
    .context("database worker stopped")?
}

async fn session_active(s: &AppState, session: &Session) -> bool {
    let Some(token_hash) = session.token_hash.clone() else {
        return false;
    };
    let Some(vault) = session.vault.clone() else {
        return false;
    };
    db_task(s, move |db| {
        Ok(db.valid_session_for_vault(&token_hash, &vault))
    })
    .await
    .unwrap_or(false)
}
fn shutting_down(s: &AppState) -> bool {
    *s.shutdown.borrow()
}
async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub(crate) struct StateLock {
    _file: fs::File,
}

pub(crate) fn acquire_database_lock(database_path: &std::path::Path) -> Result<StateLock> {
    acquire_path_lock(database_path, "database")
}

fn acquire_path_lock(path: &std::path::Path, label: &str) -> Result<StateLock> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(parent)?;
    let canonical_parent = fs::canonicalize(parent)
        .with_context(|| format!("canonicalize {label} parent {}", parent.display()))?;
    let name = path
        .file_name()
        .context("state path must have a final component")?;
    let canonical_path = canonical_parent.join(name);
    let mut lock_name = canonical_path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(&lock_path)
        .with_context(|| format!("open state lock {}", lock_path.display()))?;
    if !file.metadata()?.file_type().is_file() {
        anyhow::bail!("state lock must be a regular file: {}", lock_path.display())
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock only observes the valid, open descriptor retained by StateLock.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                anyhow::bail!(
                    "{label} state is already locked by another Blackglass Server process: {}",
                    lock_path.display()
                )
            }
            return Err(error)
                .with_context(|| format!("lock server state {}", lock_path.display()));
        }
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("exclusive state locking is unavailable on this operating system")
    }
    Ok(StateLock { _file: file })
}

fn prepare_staging(path: &std::path::Path) -> Result<()> {
    let mut created = false;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_staging_directory(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
            let metadata = fs::symlink_metadata(path)?;
            validate_staging_directory(path, &metadata)?;
            created = true;
        }
        Err(error) => return Err(error.into()),
    }

    let marker = path.join(STAGING_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || fs::read_to_string(&marker)? != STAGING_MARKER_CONTENT
            {
                anyhow::bail!("invalid Blackglass staging marker: {}", marker.display())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !created {
                validate_unmarked_staging_contents(path)?;
            }
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&marker)?;
            file.write_all(STAGING_MARKER_CONTENT.as_bytes())?;
            file.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    cleanup_staging(path)
}

fn validate_staging_directory(path: &std::path::Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.file_type().is_dir() {
        anyhow::bail!("staging path must be a real directory: {}", path.display())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "staging directory must not grant group or other permissions: {}",
                path.display()
            )
        }
    }
    Ok(())
}

fn validate_unmarked_staging_contents(path: &std::path::Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !staging_part_name(&entry.file_name()) || !entry.file_type()?.is_file() {
            anyhow::bail!(
                "refusing unrecognized pre-existing staging directory contents: {}",
                path.display()
            )
        }
    }
    Ok(())
}

fn cleanup_staging(path: &std::path::Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if staging_part_name(&entry.file_name()) && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?
        }
    }
    Ok(())
}

fn staging_part_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.strip_suffix(".part")
        .and_then(|value| Uuid::parse_str(value).ok())
        .is_some()
}
async fn secure_create(path: &std::path::Path) -> Result<tokio::fs::File> {
    let mut o = tokio::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        o.mode(0o600);
    }
    Ok(o.open(path).await?)
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn wait_for_connection_drain(state: &AppState) -> Result<()> {
    timeout(GRACEFUL_CONNECTION_DRAIN_DEADLINE, async {
        while state.connections.available_permits() != state.config.max_ws_connections {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .context("WebSocket connections did not drain before the shutdown deadline")
}

type ListenerJoinResult = std::result::Result<std::io::Result<()>, tokio::task::JoinError>;

enum ListenerTrigger {
    Shutdown,
    Control(ListenerJoinResult),
    Data(ListenerJoinResult),
}

async fn supervise_listeners<S>(
    shutdown_tx: watch::Sender<bool>,
    mut control_task: tokio::task::JoinHandle<std::io::Result<()>>,
    mut data_task: tokio::task::JoinHandle<std::io::Result<()>>,
    shutdown_requested: S,
) -> Result<()>
where
    S: Future<Output = ()>,
{
    tokio::pin!(shutdown_requested);
    let trigger = tokio::select! {
        _ = &mut shutdown_requested => ListenerTrigger::Shutdown,
        result = &mut control_task => ListenerTrigger::Control(result),
        result = &mut data_task => ListenerTrigger::Data(result),
    };
    let expected_shutdown = matches!(trigger, ListenerTrigger::Shutdown);
    info!(event = "shutdown_requested", expected = expected_shutdown);
    let _ = shutdown_tx.send(true);

    match trigger {
        ListenerTrigger::Shutdown => {
            let control = listener_result("control", control_task.await);
            let data = listener_result("data", data_task.await);
            control.and(data)
        }
        ListenerTrigger::Control(result) => {
            let control = unexpected_listener_result("control", result);
            let data = listener_result("data", data_task.await);
            control.and(data)
        }
        ListenerTrigger::Data(result) => {
            let data = unexpected_listener_result("data", result);
            let control = listener_result("control", control_task.await);
            data.and(control)
        }
    }
}

fn listener_result(name: &str, result: ListenerJoinResult) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(error).with_context(|| format!("{name} listener failed")),
        Err(error) => Err(anyhow::anyhow!("{name} listener task stopped: {error}")),
    }
}

fn unexpected_listener_result(name: &str, result: ListenerJoinResult) -> Result<()> {
    listener_result(name, result)?;
    anyhow::bail!("{name} listener exited unexpectedly")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FlushBoundaryWriter {
        pending: Vec<u8>,
        visible: Vec<u8>,
        flushes: usize,
    }

    impl tokio::io::AsyncWrite for FlushBoundaryWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.pending.extend_from_slice(bytes);
            std::task::Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let pending = std::mem::take(&mut self.pending);
            self.visible.extend_from_slice(&pending);
            self.flushes += 1;
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn staged_piece_is_flushed_before_the_piece_boundary_returns() {
        let mut writer = FlushBoundaryWriter::default();

        write_staged_piece(&mut writer, b"opaque ciphertext")
            .await
            .unwrap();

        assert_eq!(writer.visible, b"opaque ciphertext");
        assert!(writer.pending.is_empty());
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn forwarded_source_is_used_only_for_one_explicit_trusted_proxy() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::test(directory.path(), 3000, 3003).unwrap();
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "198.51.100.23".parse().unwrap();
        let peer = SocketAddr::new(proxy, 4242);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.23".parse().unwrap());

        assert_eq!(request_source(&config, peer, &headers), proxy);
        config.trusted_proxy = Some(proxy);
        assert_eq!(request_source(&config, peer, &headers), client);

        headers.insert(
            "x-forwarded-for",
            "198.51.100.23, 203.0.113.8".parse().unwrap(),
        );
        assert_eq!(request_source(&config, peer, &headers), proxy);
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(request_source(&config, peer, &headers), proxy);
        let untrusted_peer = SocketAddr::new("10.0.0.9".parse().unwrap(), 4242);
        headers.insert("x-forwarded-for", "198.51.100.23".parse().unwrap());
        assert_eq!(
            request_source(&config, untrusted_peer, &headers),
            untrusted_peer.ip()
        );
    }

    #[test]
    fn source_limits_bound_signins_and_only_unauthenticated_websockets() {
        let source: IpAddr = "198.51.100.23".parse().unwrap();
        let other: IpAddr = "198.51.100.24".parse().unwrap();
        let now = Instant::now();
        let mut limits = SourceLimits::default();
        for _ in 0..SIGNIN_ATTEMPTS_PER_SOURCE {
            assert!(limits.admit_signin(source, now));
        }
        assert!(!limits.admit_signin(source, now));
        assert!(limits.admit_signin(other, now));
        for _ in 0..MAX_UNAUTHENTICATED_WS_PER_SOURCE {
            assert!(limits.admit_websocket(source, now));
        }
        assert!(!limits.admit_websocket(source, now));
        assert!(limits.admit_websocket(other, now));
    }

    #[tokio::test]
    async fn listener_supervisor_propagates_an_unexpected_exit_and_stops_its_sibling() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let control = tokio::spawn(async { Ok(()) });
        let data = tokio::spawn(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
            Ok(())
        });
        let error = timeout(
            Duration::from_secs(1),
            supervise_listeners(shutdown_tx, control, data, std::future::pending()),
        )
        .await
        .expect("supervisor stalled")
        .expect_err("unexpected listener exit was accepted");
        assert!(
            error
                .to_string()
                .contains("control listener exited unexpectedly")
        );
    }

    #[test]
    fn staging_cleanup_only_removes_owned_part_names() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("staging");
        prepare_staging(&staging).unwrap();
        let owned = staging.join(format!("{}.part", Uuid::new_v4()));
        let foreign = staging.join("notes.part");
        fs::write(&owned, b"partial").unwrap();
        fs::write(&foreign, b"keep").unwrap();
        cleanup_staging(&staging).unwrap();
        assert!(!owned.exists());
        assert_eq!(fs::read(&foreign).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_symlinks_and_unmarked_foreign_directories_without_mutation() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = target.join("foreign.part");
        fs::write(&foreign, b"preserve").unwrap();
        let link = directory.path().join("staging-link");
        symlink(&target, &link).unwrap();
        assert!(prepare_staging(&link).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");

        assert!(prepare_staging(&target).is_err());
        assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
        assert!(!target.join(STAGING_MARKER).exists());
    }
}
