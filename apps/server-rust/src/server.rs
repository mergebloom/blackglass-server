use crate::{
    auth,
    config::{AES_GCM_WIRE_OVERHEAD_BYTES, Config, MAX_WS_CONNECTIONS_LIMIT},
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
use sha2::{Digest, Sha256};
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
    time::{
        Instant as TokioInstant, MissedTickBehavior, interval, sleep_until, timeout, timeout_at,
    },
};
use tracing::{info, warn};
use uuid::Uuid;

const PIECE_SIZE: i64 = 2 * 1024 * 1024;
const REPLAY_PAGE_SIZE: i64 = 16;
pub(crate) const MAX_REPLAY_PAGE_BYTES: usize = REPLAY_PAGE_SIZE as usize * MAX_EVENT_BYTES;
pub(crate) const MAX_REPLAY_PAGES_BYTES: usize = MAX_REPLAY_PAGE_BYTES * MAX_WS_CONNECTIONS_LIMIT;
const _: () = assert!(MAX_REPLAY_PAGES_BYTES <= 8 * 1024 * 1024);
const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(5);
const CONTROL_BODY_DEADLINE: Duration = Duration::from_secs(5);
const GRACEFUL_CONNECTION_DRAIN_DEADLINE: Duration = Duration::from_secs(15);
const SESSION_REVALIDATE_INTERVAL: Duration = Duration::from_secs(5);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const SIGNIN_QUEUE_TIMEOUT: Duration = Duration::from_secs(10);
const DB_WORKER_QUEUE_DEADLINE: Duration = Duration::from_secs(5);
const SIGNIN_RATE_WINDOW: Duration = Duration::from_secs(60);
const SIGNIN_ATTEMPTS_PER_SOURCE: usize = 6;
const SHARE_INVITE_WINDOW: Duration = Duration::from_secs(60 * 60);
const MAX_SHARE_INVITE_USER_ENTRIES: usize = 256;
const MAX_SIGNIN_WAITERS: usize = 8;
const MAX_UNAUTHENTICATED_WS_PER_SOURCE: usize = 4;
const MAX_SOURCE_LIMIT_ENTRIES: usize = 4096;
pub(crate) const MAX_CONTROL_BODY_READERS: usize = 32;
pub(crate) const MAX_CONTROL_REQUESTS: usize = 16;
pub(crate) const MAX_DB_WORKERS: usize = 2;
pub(crate) const MAX_CONCURRENT_PULLS: usize = 2;
pub(crate) const BULK_MEMORY_PERMITS: usize = 4;
const ARGON2_MEMORY_PERMITS: u32 = 3;
const _: () = assert!(ARGON2_MEMORY_PERMITS < BULK_MEMORY_PERMITS as u32);
pub(crate) const MAX_CONTROL_BODY_BYTES: usize = 64 * 1024;
pub(crate) const EVENT_CAPACITY: usize = 32;
pub(crate) const MAX_EVENT_BYTES: usize = 32 * 1024;
pub(crate) const MAX_LARGE_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const DELETED_PAGE_SIZE: i64 = 64;
const STAGING_MARKER: &str = ".blackglass-staging-v1";
const STAGING_MARKER_CONTENT: &str = "blackglass-server staging v1\n";
const ADMIN_MANAGED_ACCOUNT_ERROR: &str =
    "Accounts are managed by the Blackglass Server administrator";
const STORAGE_QUOTA_CLIENT_ERROR: &str = "Storage limit reached";
const _: () = assert!(STORAGE_QUOTA_CLIENT_ERROR.len() <= 64);

#[derive(Default)]
pub struct Metrics {
    control: AtomicU64,
    signins: AtomicU64,
    auth_failures: AtomicU64,
    ws_connections: AtomicU64,
    uploads: AtomicU64,
    upload_bytes: AtomicU64,
    upload_timeouts: AtomicU64,
    storage_quota_rejections: AtomicU64,
    downloads: AtomicU64,
    errors: AtomicU64,
    control_rejections: AtomicU64,
    authorization_denials: [AtomicU64; AuthorizationOperation::COUNT],
    database_busy: [AtomicU64; DatabaseOperation::COUNT],
    database_deadlines: [AtomicU64; DatabaseOperation::COUNT],
    share_invites: [AtomicU64; ShareInviteOutcome::COUNT],
}

#[derive(Clone, Copy)]
enum AuthorizationOperation {
    Access,
    Migrate,
    Rename,
    Delete,
    DataInit,
}

#[derive(Clone, Copy)]
enum ShareInviteOutcome {
    Success,
    Unavailable,
    Capacity,
    RateLimited,
}

impl ShareInviteOutcome {
    const COUNT: usize = 4;
    const ALL: [(Self, &'static str); Self::COUNT] = [
        (Self::Success, "success"),
        (Self::Unavailable, "unavailable"),
        (Self::Capacity, "capacity"),
        (Self::RateLimited, "rate_limited"),
    ];
}

impl AuthorizationOperation {
    const COUNT: usize = 5;
    const ALL: [(Self, &'static str); Self::COUNT] = [
        (Self::Access, "access"),
        (Self::Migrate, "migrate"),
        (Self::Rename, "rename"),
        (Self::Delete, "delete"),
        (Self::DataInit, "data_init"),
    ];
}

#[derive(Clone, Copy)]
pub(crate) enum DatabaseOperation {
    Request,
    AdminSnapshot,
}

impl DatabaseOperation {
    const COUNT: usize = 2;
    const ALL: [(Self, &'static str); Self::COUNT] = [
        (Self::Request, "request"),
        (Self::AdminSnapshot, "admin_snapshot"),
    ];
}

impl Metrics {
    fn deny(&self, operation: AuthorizationOperation) {
        self.authorization_denials[operation as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn share_invite(&self, outcome: ShareInviteOutcome) {
        self.share_invites[outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn database_deadline(&self, operation: DatabaseOperation) {
        self.database_deadlines[operation as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn observe_database_error(&self, operation: DatabaseOperation, error: &anyhow::Error) {
        for cause in error.chain() {
            let Some(sqlite) = cause.downcast_ref::<rusqlite::Error>() else {
                continue;
            };
            match sqlite.sqlite_error_code() {
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked) => {
                    self.database_busy[operation as usize].fetch_add(1, Ordering::Relaxed);
                }
                Some(rusqlite::ErrorCode::OperationInterrupted) => {
                    self.database_deadline(operation);
                }
                _ => {}
            }
            break;
        }
    }
}

#[derive(Clone)]
struct Event {
    uid: i64,
    vault: String,
    text: String,
    invalidated: bool,
    invalidated_session_hash: Option<String>,
}
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    events: broadcast::Sender<Event>,
    commit_order: Arc<AsyncMutex<()>>,
    storage_reservations: Arc<StorageReservations>,
    user_concurrency: Arc<UserConcurrency>,
    uploads: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    auth_checks: Arc<Semaphore>,
    auth_waiters: Arc<Semaphore>,
    source_limits: Arc<StdMutex<SourceLimits>>,
    share_invite_limits: Arc<StdMutex<ShareInviteLimits>>,
    control_body_readers: Arc<Semaphore>,
    control_requests: Arc<Semaphore>,
    db_workers: Arc<Semaphore>,
    pulls: Arc<Semaphore>,
    bulk_memory: Arc<Semaphore>,
    large_responses: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
    metrics: Arc<Metrics>,
    pub(crate) live_connections: crate::admin::LiveRegistry,
    pub(crate) admin_snapshots: Arc<Semaphore>,
    pub(crate) started: Instant,
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

struct ShareInviteAttempt {
    source: IpAddr,
    user_id: i64,
    target_digest: [u8; 32],
    at: Instant,
}

struct ShareInviteLimits {
    secret: [u8; 32],
    attempts: VecDeque<ShareInviteAttempt>,
}

impl ShareInviteLimits {
    fn new() -> Self {
        Self {
            secret: rand::random(),
            attempts: VecDeque::new(),
        }
    }

    fn admit(
        &mut self,
        source: IpAddr,
        user_id: i64,
        canonical_target: &str,
        config: &Config,
        now: Instant,
    ) -> bool {
        while self
            .attempts
            .front()
            .is_some_and(|attempt| now.duration_since(attempt.at) >= SHARE_INVITE_WINDOW)
        {
            self.attempts.pop_front();
        }

        let mut digest = Sha256::new();
        digest.update(self.secret);
        digest.update(canonical_target.as_bytes());
        let target_digest: [u8; 32] = digest.finalize().into();
        let source_attempts = self
            .attempts
            .iter()
            .filter(|attempt| attempt.source == source)
            .count();
        let user_attempts = self
            .attempts
            .iter()
            .filter(|attempt| attempt.user_id == user_id)
            .count();
        let known_user = user_attempts > 0;
        let user_entries = self
            .attempts
            .iter()
            .map(|attempt| attempt.user_id)
            .collect::<std::collections::HashSet<_>>()
            .len();
        let distinct_targets = self
            .attempts
            .iter()
            .filter(|attempt| attempt.user_id == user_id)
            .map(|attempt| attempt.target_digest)
            .collect::<std::collections::HashSet<_>>();
        let adds_distinct_target = !distinct_targets.contains(&target_digest);

        if self.attempts.len() >= config.share_invites_global
            || source_attempts >= config.share_invites_per_source
            || user_attempts >= config.share_invites_per_user
            || (adds_distinct_target
                && distinct_targets.len() >= config.share_invite_targets_per_user)
            || (!known_user && user_entries >= MAX_SHARE_INVITE_USER_ENTRIES)
        {
            return false;
        }
        self.attempts.push_back(ShareInviteAttempt {
            source,
            user_id,
            target_digest,
            at: now,
        });
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
    let db = Db::open_existing(&config.database_path)?;
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
        storage_reservations: Arc::new(StorageReservations::default()),
        user_concurrency: Arc::new(UserConcurrency::default()),
        uploads: Arc::new(Semaphore::new(max_uploads)),
        connections: Arc::new(Semaphore::new(max_connections)),
        auth_checks: Arc::new(Semaphore::new(auth::MAX_CONCURRENT_PASSWORD_CHECKS)),
        auth_waiters: Arc::new(Semaphore::new(MAX_SIGNIN_WAITERS)),
        source_limits: Arc::new(StdMutex::new(SourceLimits::default())),
        share_invite_limits: Arc::new(StdMutex::new(ShareInviteLimits::new())),
        control_body_readers: Arc::new(Semaphore::new(MAX_CONTROL_BODY_READERS)),
        control_requests: Arc::new(Semaphore::new(MAX_CONTROL_REQUESTS)),
        db_workers: Arc::new(Semaphore::new(MAX_DB_WORKERS)),
        pulls: Arc::new(Semaphore::new(MAX_CONCURRENT_PULLS)),
        bulk_memory: Arc::new(Semaphore::new(BULK_MEMORY_PERMITS)),
        large_responses: Arc::new(Semaphore::new(1)),
        shutdown,
        metrics: Arc::new(Metrics::default()),
        live_connections: crate::admin::LiveRegistry::new(max_connections),
        admin_snapshots: Arc::new(Semaphore::new(1)),
        started: Instant::now(),
    };
    let control = control_router(state.clone());
    let data = data_router(state.clone());
    let control_listener =
        TcpListener::bind((state.config.bind_host, state.config.control_port)).await?;
    let data_listener = TcpListener::bind((state.config.bind_host, state.config.data_port)).await?;
    let admin_listener = if let Some(admin) = &state.config.admin {
        Some(
            TcpListener::bind((admin.bind_host, admin.port))
                .await
                .context("bind admin listener")?,
        )
    } else {
        None
    };
    info!(event="server_started",control=%control_listener.local_addr()?,data=%data_listener.local_addr()?,admin=?admin_listener.as_ref().and_then(|l|l.local_addr().ok()),database=%state.config.database_path.display());
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
    let admin_task = admin_listener.map(|listener| {
        let router = crate::admin::router(state.clone());
        let mut stop = state.shutdown.clone();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move { wait_for_shutdown(&mut stop).await })
            .await
        })
    });
    let listener_result = supervise_listeners(
        shutdown_tx,
        control_task,
        data_task,
        admin_task,
        shutdown_signal(),
    )
    .await;
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
    let account = crate::account::router();
    let mut r = Router::new();
    for path in [
        "/user/signin",
        "/user/pow-challenge",
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
        "/user/authtoken",
        "/subscription/business",
        "/subscription/sync/signup-mobile",
        "/publish/create",
        "/publish/delete",
        "/publish/list",
        "/publish/share/accept",
        "/publish/share/invite",
        "/publish/share/list",
        "/publish/share/remove",
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
    .merge(account)
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
    let mut body = format!(
        "blackglass_control_requests_total {}\nblackglass_control_rejections_total {}\nblackglass_signins_total {}\nblackglass_auth_failures_total {}\nblackglass_ws_connections_total {}\nblackglass_uploads_total {}\nblackglass_upload_bytes_total {}\nblackglass_upload_timeouts_total {}\nblackglass_storage_quota_bytes {}\nblackglass_storage_quota_rejections_total {}\nblackglass_downloads_total {}\nblackglass_errors_total {}\nobsidian_sync_control_requests_total {}\nobsidian_sync_signins_total {}\nobsidian_sync_auth_failures_total {}\nobsidian_sync_ws_connections_total {}\nobsidian_sync_uploads_total {}\nobsidian_sync_upload_bytes_total {}\nobsidian_sync_downloads_total {}\nobsidian_sync_errors_total {}\n",
        m.control.load(Ordering::Relaxed),
        m.control_rejections.load(Ordering::Relaxed),
        m.signins.load(Ordering::Relaxed),
        m.auth_failures.load(Ordering::Relaxed),
        m.ws_connections.load(Ordering::Relaxed),
        m.uploads.load(Ordering::Relaxed),
        m.upload_bytes.load(Ordering::Relaxed),
        m.upload_timeouts.load(Ordering::Relaxed),
        s.config.storage_quota_bytes,
        m.storage_quota_rejections.load(Ordering::Relaxed),
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
    for (operation, label) in AuthorizationOperation::ALL {
        body.push_str(&format!(
            "blackglass_authorization_denials_total{{operation=\"{label}\",reason=\"not_authorized\"}} {}\n",
            m.authorization_denials[operation as usize].load(Ordering::Relaxed)
        ));
    }
    for (operation, label) in DatabaseOperation::ALL {
        body.push_str(&format!(
            "blackglass_sqlite_busy_total{{operation=\"{label}\"}} {}\nblackglass_sqlite_deadlines_total{{operation=\"{label}\"}} {}\n",
            m.database_busy[operation as usize].load(Ordering::Relaxed),
            m.database_deadlines[operation as usize].load(Ordering::Relaxed)
        ));
    }
    for (outcome, label) in ShareInviteOutcome::ALL {
        body.push_str(&format!(
            "blackglass_share_invites_total{{outcome=\"{label}\"}} {}\n",
            m.share_invites[outcome as usize].load(Ordering::Relaxed)
        ));
    }
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
        "/user/pow-challenge"
        | "/user/signup"
        | "/user/forgetpass"
        | "/user/resendconfirmation" => Err(ADMIN_MANAGED_ACCOUNT_ERROR.into()),
        _ => authorized_control(&s, uri.path(), source, value).await,
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
    let user = authenticate_credentials(s, source, req.email, req.password).await?;
    let token = issue_user_session(s, user.id).await?;
    s.metrics.signins.fetch_add(1, Ordering::Relaxed);
    info!(event = "signin_succeeded");
    Ok(json!({"email":user.email,"name":user.name,"license":null,"token":token}))
}

pub(crate) async fn authenticate_credentials(
    s: &AppState,
    source: IpAddr,
    email: Option<String>,
    password: Option<String>,
) -> std::result::Result<UserCredential, String> {
    let queue_deadline = tokio::time::Instant::now() + SIGNIN_QUEUE_TIMEOUT;
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
    let permit = match timeout_at(queue_deadline, s.auth_checks.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        _ => {
            s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            warn!(event = "signin_queue_timed_out");
            return Err("Try again later".into());
        }
    };
    drop(waiter);
    // Argon2 at the accepted policy maximum owns 64 MiB. Reserve three of four
    // bulk-memory permits so one authenticated Sync lane always remains live.
    // Bound admission so hostile sign-ins cannot hold the fair queue forever.
    let Some(bulk_memory) =
        acquire_password_memory(s.bulk_memory.clone(), s.shutdown.clone(), queue_deadline)
            .await
            .map_err(internal)?
    else {
        drop(permit);
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_memory_capacity_reached");
        return Err("Try again later".into());
    };
    let canonical_email = email
        .as_deref()
        .and_then(|email| auth::canonicalize_email(email).ok())
        .map(|email| email.canonical);
    let candidate = if let Some(canonical_email) = canonical_email {
        db_task(s, move |db| db.signin_candidate(&canonical_email))
            .await
            .map_err(internal)?
    } else {
        None
    };
    let password = password.unwrap_or_default();
    let encoded = candidate
        .as_ref()
        .filter(|user| user.active)
        .map(|user| user.password_hash.clone())
        .unwrap_or_else(|| auth::DUMMY_PASSWORD_HASH.to_owned());
    let password_ok = tokio::task::spawn_blocking(move || {
        let valid = auth::verify_password(&password, &encoded);
        drop((permit, bulk_memory));
        valid
    })
    .await
    .map_err(internal)?;
    let Some(user) = candidate.filter(|user| user.active && password_ok) else {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_failed");
        return Err("Invalid email or password".into());
    };
    if let Ok(mut limits) = s.source_limits.lock() {
        limits.refund_successful_signin(source);
    }
    Ok(user)
}

pub(crate) async fn issue_user_session(
    s: &AppState,
    user_id: i64,
) -> std::result::Result<String, String> {
    let ttl = s.config.session_ttl.as_secs() as i64;
    db_task(s, move |db| db.issue_session_for_user(user_id, ttl))
        .await
        .map_err(internal)
}

pub(crate) enum RegistrationError {
    Invalid(String),
    RateLimited,
    Unavailable,
}

pub(crate) async fn register_account(
    s: &AppState,
    source: IpAddr,
    email: String,
    name: String,
    password: String,
) -> std::result::Result<crate::db::RegistrationResult, RegistrationError> {
    auth::canonicalize_email(&email)
        .map_err(|error| RegistrationError::Invalid(error.to_string()))?;
    auth::normalize_display_name(&name)
        .map_err(|error| RegistrationError::Invalid(error.to_string()))?;
    auth::validate_self_registered_password(&password)
        .map_err(|error| RegistrationError::Invalid(error.to_string()))?;
    let enabled = db_task(s, |db| db.self_registration_enabled())
        .await
        .map_err(registration_internal)?;
    if !enabled {
        return Ok(crate::db::RegistrationResult::Disabled);
    }
    let admitted = s
        .source_limits
        .lock()
        .map_err(|_| RegistrationError::Unavailable)?
        .admit_signin(source, Instant::now());
    if !admitted {
        warn!(event = "registration_rate_limited");
        return Err(RegistrationError::RateLimited);
    }
    let queue_deadline = tokio::time::Instant::now() + SIGNIN_QUEUE_TIMEOUT;
    let waiter = s
        .auth_waiters
        .clone()
        .try_acquire_owned()
        .map_err(|_| RegistrationError::Unavailable)?;
    let permit = timeout_at(queue_deadline, s.auth_checks.clone().acquire_owned())
        .await
        .map_err(|_| RegistrationError::Unavailable)?
        .map_err(|_| RegistrationError::Unavailable)?;
    drop(waiter);
    let Some(bulk_memory) =
        acquire_password_memory(s.bulk_memory.clone(), s.shutdown.clone(), queue_deadline)
            .await
            .map_err(registration_internal)?
    else {
        drop(permit);
        return Err(RegistrationError::Unavailable);
    };
    let password_hash = tokio::task::spawn_blocking(move || {
        let result = auth::hash_password(&password);
        drop((permit, bulk_memory));
        result
    })
    .await
    .map_err(registration_internal)?
    .map_err(registration_internal)?;
    let result = db_task(s, move |db| {
        db.create_self_registered_user(&email, &name, &password_hash)
    })
    .await
    .map_err(registration_internal)?;
    match result {
        crate::db::RegistrationResult::Created(_) => info!(event = "registration_succeeded"),
        crate::db::RegistrationResult::Disabled => info!(event = "registration_disabled"),
        crate::db::RegistrationResult::Unavailable => warn!(event = "registration_unavailable"),
    }
    Ok(result)
}

fn registration_internal(error: impl std::fmt::Display) -> RegistrationError {
    let _ = internal(error);
    RegistrationError::Unavailable
}

async fn authorized_control(
    s: &AppState,
    path: &str,
    source: IpAddr,
    v: Value,
) -> std::result::Result<Value, String> {
    let token = v
        .get("token")
        .and_then(Value::as_str)
        .ok_or("Not logged in")?
        .to_owned();
    let validation_token = token.clone();
    let Some(auth_context) = db_task(s, move |db| db.auth_context(&validation_token))
        .await
        .map_err(internal)?
    else {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("Not logged in".into());
    };
    match path {
        "/user/signout" => {
            let invalidated_session_hash = auth_context.token_hash.clone();
            db_task(s, move |db| db.revoke_session(&token))
                .await
                .map_err(internal)?;
            s.live_connections.cancel_session(&invalidated_session_hash);
            let _ = s.events.send(Event {
                uid: 0,
                vault: String::new(),
                text: String::new(),
                invalidated: false,
                invalidated_session_hash: Some(invalidated_session_hash),
            });
            Ok(json!({}))
        }
        "/user/info" => {
            Ok(json!({"email":auth_context.email,"name":auth_context.name,"license":null}))
        }
        "/subscription/list" => Ok(json!({"sync":true,"publish":false})),
        "/subscription/business" => {
            Err("Business subscriptions are unavailable on a self-hosted server".into())
        }
        "/subscription/sync/signup-mobile" => {
            Err("Mobile Sync signup is unavailable on a self-hosted server".into())
        }
        "/user/authtoken" => Err(ADMIN_MANAGED_ACCOUNT_ERROR.into()),
        "/publish/create"
        | "/publish/delete"
        | "/publish/list"
        | "/publish/share/accept"
        | "/publish/share/invite"
        | "/publish/share/list"
        | "/publish/share/remove" => Err("Publish is unavailable on a self-hosted server".into()),
        "/vault/regions" => {
            Ok(json!({"regions":[{"value":"selfhost","name":"Blackglass Server"}]}))
        }
        "/vault/list" => Ok(json!({
            "vaults":db_task(s, move |db| db.list_vaults_for_user(auth_context.user_id)).await.map_err(internal)?,
            "shared":shared_inventory(s, auth_context.user_id).await?,
            "limit":100
        })),
        "/vault/create" => create_vault(s, auth_context.user_id, auth_context.token_hash, v).await,
        "/vault/access" => access_vault(s, auth_context.user_id, auth_context.token_hash, v).await,
        "/vault/migrate" => {
            migrate_vault(s, auth_context.user_id, auth_context.token_hash, v).await
        }
        "/vault/rename" => rename_vault(s, auth_context.user_id, auth_context.token_hash, v).await,
        "/vault/delete" => delete_vault(s, auth_context.user_id, auth_context.token_hash, v).await,
        "/vault/share/list" => share_list(s, auth_context.user_id, v).await,
        "/vault/share/invite" => {
            share_invite(s, source, auth_context.user_id, auth_context.token_hash, v).await
        }
        "/vault/share/remove" => {
            share_remove(s, auth_context.user_id, auth_context.token_hash, v).await
        }
        _ => Err("Not found".into()),
    }
}

async fn shared_inventory(
    s: &AppState,
    user_id: i64,
) -> std::result::Result<Vec<SharedVault>, String> {
    let mut shared = db_task(s, move |db| db.list_shared_vaults_for_user(user_id))
        .await
        .map_err(internal)?;
    shared.retain(|vault| s.config.sharing_allowed_for_owner(vault.owner_user_id));
    Ok(shared)
}

async fn share_list(s: &AppState, user_id: i64, v: Value) -> std::result::Result<Value, String> {
    if !s.config.sharing_allowed_for_owner(user_id) {
        return Err("Sharing is unavailable".into());
    }
    let request: VaultShareListRequest =
        serde_json::from_value(v).map_err(|_| "Unable to list collaborators".to_string())?;
    let vault_id = request.vault_uid.ok_or("Unable to list collaborators")?;
    let shares = db_task(s, move |db| db.list_shares_for_owner(user_id, &vault_id))
        .await
        .map_err(internal)?
        .ok_or("Unable to list collaborators")?;
    Ok(json!({"shares": shares}))
}

async fn share_invite(
    s: &AppState,
    source: IpAddr,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
    if !s.config.sharing_allowed_for_owner(user_id) {
        return Err("Sharing is unavailable".into());
    }
    let request: VaultShareInviteRequest =
        serde_json::from_value(v).map_err(|_| "Unable to invite collaborator".to_string())?;
    let vault_id = request.vault_uid.ok_or("Unable to invite collaborator")?;
    let email = request.email.ok_or("User unavailable for sharing")?;
    let canonical =
        auth::canonicalize_email(&email).map_err(|_| "User unavailable for sharing".to_string())?;
    let admitted = s
        .share_invite_limits
        .lock()
        .map_err(|_| "Share invitation rate limit reached".to_string())?
        .admit(
            source,
            user_id,
            &canonical.canonical,
            &s.config,
            Instant::now(),
        );
    if !admitted {
        s.metrics.share_invite(ShareInviteOutcome::RateLimited);
        return Err("Share invitation rate limit reached".into());
    }
    let result = db_task(s, move |db| {
        db.invite_collaborator_for_session(user_id, &token_hash, &vault_id, &email)
    })
    .await;
    match result {
        Ok(item) => {
            s.metrics.share_invite(ShareInviteOutcome::Success);
            serde_json::to_value(item).map_err(internal)
        }
        Err(error) => {
            let message = error.to_string();
            if message.contains("sharing user unavailable") {
                s.metrics.share_invite(ShareInviteOutcome::Unavailable);
                Err("User unavailable for sharing".to_string())
            } else if message.contains("collaborator limit reached") {
                s.metrics.share_invite(ShareInviteOutcome::Capacity);
                Err("Collaborator limit reached".to_string())
            } else if message.contains("membership capacity reached")
                || message.contains("membership sequence exhausted")
            {
                s.metrics.share_invite(ShareInviteOutcome::Capacity);
                Err("Sharing capacity reached".to_string())
            } else if message.contains("sharing vault unavailable") {
                Err("Unable to invite collaborator".to_string())
            } else {
                Err(internal(error))
            }
        }
    }
}

async fn share_remove(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
    let request: VaultShareRemoveRequest =
        serde_json::from_value(v).map_err(|_| "Unable to remove collaborator".to_string())?;
    let vault_id = request.vault_uid.ok_or("Unable to remove collaborator")?;
    let owner_lookup = vault_id.clone();
    let owner_user_id = db_task(s, move |db| db.vault_owner_user_id(&owner_lookup))
        .await
        .map_err(internal)?
        .ok_or("Unable to remove collaborator")?;
    if !s.config.sharing_allowed_for_owner(owner_user_id) {
        return Err("Sharing is unavailable".into());
    }
    let share_uid = request
        .share_uid
        .filter(|uid| (1..=MAX_JS_SAFE_INTEGER).contains(uid))
        .ok_or("Unable to remove collaborator")?;
    let removed_vault_id = vault_id.clone();
    let removed = db_task(s, move |db| {
        db.remove_collaborator_for_session(user_id, &token_hash, &vault_id, share_uid)
    })
    .await
    .map_err(internal)?;
    if removed.is_none() {
        return Err("Unable to remove collaborator".into());
    }
    s.live_connections
        .cancel_user_vault(removed.expect("checked above"), &removed_vault_id);
    Ok(json!({}))
}

async fn create_vault(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
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
    if let Err(error) = db_task(s, move |db| {
        db.create_vault_for_session(user_id, &token_hash, &stored)
    })
    .await
    {
        if error.to_string().contains("vault limit reached") {
            return Err("Vault limit reached".into());
        }
        return Err(internal(error));
    }
    serde_json::to_value(vault).map_err(internal)
}
async fn access_vault(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
    let r: VaultAccessRequest =
        serde_json::from_value(v).map_err(|_| "Unable to access vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to access vault")?;
    let lookup_id = id.clone();
    let Some((mut vault, access)) =
        db_task(s, move |db| db.find_authorized_vault(user_id, &lookup_id))
            .await
            .map_err(internal)?
    else {
        s.metrics.deny(AuthorizationOperation::Access);
        return Err("Unable to access vault".into());
    };
    if matches!(access, crate::model::VaultAccess::Collaborator { .. }) {
        let owner_lookup = id.clone();
        let owner_user_id = db_task(s, move |db| db.vault_owner_user_id(&owner_lookup))
            .await
            .map_err(internal)?
            .ok_or("Unable to access vault")?;
        if !s.config.sharing_allowed_for_owner(owner_user_id) {
            return Err("Sharing is unavailable".into());
        }
    }
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
        vault.keyhash = db_task(s, move |db| {
            db.bind_managed_keyhash_for_session(user_id, &token_hash, &bind_id, &requested)
        })
        .await
        .map_err(internal)?;
    }
    if r.keyhash != vault.keyhash {
        return Err("Unable to access vault".into());
    }
    Ok(json!({}))
}
async fn migrate_vault(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
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
    let Some(source) = db_task(s, move |db| db.find_owned_vault(user_id, &lookup_id))
        .await
        .map_err(internal)?
    else {
        s.metrics.deny(AuthorizationOperation::Migrate);
        return Err("Unable to migrate vault".into());
    };
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
    if !db_task(s, move |db| {
        db.migrate_vault_for_session(user_id, &token_hash, &migrate_source_id, &stored)
    })
    .await
    .map_err(internal)?
    {
        s.metrics.deny(AuthorizationOperation::Migrate);
        return Err("Unable to migrate vault".into());
    }
    invalidate_vault(s, source_id);
    serde_json::to_value(replacement).map_err(internal)
}
async fn rename_vault(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
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
    if !db_task(s, move |db| {
        db.rename_vault_for_session(user_id, &token_hash, &id, &name)
    })
    .await
    .map_err(internal)?
    {
        s.metrics.deny(AuthorizationOperation::Rename);
        return Err("Unable to rename vault".into());
    }
    Ok(json!({}))
}
async fn delete_vault(
    s: &AppState,
    user_id: i64,
    token_hash: String,
    v: Value,
) -> std::result::Result<Value, String> {
    let r: VaultDelete =
        serde_json::from_value(v).map_err(|_| "Unable to delete vault".to_string())?;
    let id = r.vault_uid.unwrap_or_default();
    let _commit = s.commit_order.lock().await;
    let delete_id = id.clone();
    if !db_task(s, move |db| {
        db.delete_vault_for_session(user_id, &token_hash, &delete_id)
    })
    .await
    .map_err(internal)?
    {
        s.metrics.deny(AuthorizationOperation::Delete);
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
    s.live_connections.cancel_vault(&vault);
    let _ = s.events.send(Event {
        uid: 0,
        vault,
        text: String::new(),
        invalidated: true,
        invalidated_session_hash: None,
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
    user_id: Option<i64>,
    expires_at: Option<i64>,
    vault: Option<String>,
    vault_owner_user_id: Option<i64>,
    device: String,
    pending: Option<Pending>,
    live: Option<crate::admin::LiveGuard>,
    cancellation: Option<watch::Receiver<bool>>,
    _user_connection_permit: Option<UserConcurrencyPermit>,
}

#[derive(Default)]
struct StorageReservations {
    state: StdMutex<StorageReservationState>,
}

#[derive(Default)]
struct StorageReservationState {
    global_bytes: i64,
    owner_bytes: HashMap<i64, i64>,
}

impl StorageReservations {
    fn reserved(&self) -> i64 {
        self.state.lock().map_or(0, |state| state.global_bytes)
    }

    fn reserved_for_owner(&self, user_id: i64) -> i64 {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.owner_bytes.get(&user_id).copied())
            .unwrap_or(0)
    }

    fn try_reserve(
        self: &Arc<Self>,
        committed_global: i64,
        committed_owner: i64,
        owner_user_id: i64,
        additional: i64,
        global_limit: i64,
        owner_limit: i64,
    ) -> Option<StorageReservation> {
        if committed_global < 0
            || committed_owner < 0
            || additional <= 0
            || global_limit <= 0
            || owner_limit <= 0
        {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        let owner_reserved = state.owner_bytes.get(&owner_user_id).copied().unwrap_or(0);
        if committed_global > global_limit
            || state.global_bytes > global_limit - committed_global
            || additional > global_limit - committed_global - state.global_bytes
            || committed_owner > owner_limit
            || owner_reserved > owner_limit - committed_owner
            || additional > owner_limit - committed_owner - owner_reserved
        {
            return None;
        }
        state.global_bytes += additional;
        *state.owner_bytes.entry(owner_user_id).or_default() += additional;
        Some(StorageReservation {
            owner_user_id,
            bytes: additional,
            reservations: self.clone(),
        })
    }
}

struct StorageReservation {
    owner_user_id: i64,
    bytes: i64,
    reservations: Arc<StorageReservations>,
}

impl Drop for StorageReservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.reservations.state.lock() {
            debug_assert!(state.global_bytes >= self.bytes);
            state.global_bytes = state.global_bytes.saturating_sub(self.bytes);
            if let Some(owner_bytes) = state.owner_bytes.get_mut(&self.owner_user_id) {
                debug_assert!(*owner_bytes >= self.bytes);
                *owner_bytes = owner_bytes.saturating_sub(self.bytes);
                if *owner_bytes == 0 {
                    state.owner_bytes.remove(&self.owner_user_id);
                }
            }
        }
    }
}

#[derive(Default)]
struct UserConcurrency {
    entries: StdMutex<HashMap<i64, UserConcurrencyEntry>>,
}

#[derive(Default)]
struct UserConcurrencyEntry {
    connections: usize,
    uploads: usize,
}

#[derive(Clone, Copy)]
enum UserConcurrencyKind {
    Connection,
    Upload,
}

impl UserConcurrency {
    fn try_acquire(
        self: &Arc<Self>,
        user_id: i64,
        kind: UserConcurrencyKind,
        limit: usize,
    ) -> Option<UserConcurrencyPermit> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.entry(user_id).or_default();
        let count = match kind {
            UserConcurrencyKind::Connection => &mut entry.connections,
            UserConcurrencyKind::Upload => &mut entry.uploads,
        };
        if *count >= limit {
            return None;
        }
        *count += 1;
        Some(UserConcurrencyPermit {
            user_id,
            kind,
            limits: self.clone(),
        })
    }
}

struct UserConcurrencyPermit {
    user_id: i64,
    kind: UserConcurrencyKind,
    limits: Arc<UserConcurrency>,
}

impl Drop for UserConcurrencyPermit {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.limits.entries.lock()
            && let Some(entry) = entries.get_mut(&self.user_id)
        {
            let count = match self.kind {
                UserConcurrencyKind::Connection => &mut entry.connections,
                UserConcurrencyKind::Upload => &mut entry.uploads,
            };
            *count = count.saturating_sub(1);
            if entry.connections == 0 && entry.uploads == 0 {
                entries.remove(&self.user_id);
            }
        }
    }
}

struct Pending {
    revision: NewRevision,
    path: PathBuf,
    file: tokio::fs::File,
    pieces: i64,
    bytes: i64,
    idle_deadline: TokioInstant,
    _storage_reservation: StorageReservation,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _user_upload_permit: UserConcurrencyPermit,
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
        user_id: None,
        expires_at: None,
        vault: None,
        vault_owner_user_id: None,
        device: "Unknown device".into(),
        pending: None,
        live: None,
        cancellation: None,
        _user_connection_permit: None,
    };
    let mut source_permit = Some(source_permit);
    let authentication_deadline = tokio::time::sleep(AUTHENTICATION_DEADLINE);
    tokio::pin!(authentication_deadline);
    let mut session_revalidation = interval(SESSION_REVALIDATE_INTERVAL);
    session_revalidation.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        let cancellation = session.cancellation.clone();
        let pending_upload_deadline = session
            .pending
            .as_ref()
            .map(|pending| pending.idle_deadline);
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
            _ = wait_for_cancellation(cancellation), if session.cancellation.is_some() => {
                let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                    code: 1008,
                    reason: "Authorization revoked".into(),
                }))).await;
                break
            },
            _ = async {
                if let Some(deadline) = pending_upload_deadline {
                    sleep_until(deadline).await;
                }
            }, if pending_upload_deadline.is_some() => {
                s.metrics.upload_timeouts.fetch_add(1, Ordering::Relaxed);
                warn!(event = "upload_idle_timeout");
                discard_pending_upload(&s, &mut session, "idle_timeout").await;
                let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                    code: 1008,
                    reason: "Upload idle timeout exceeded".into(),
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
                Ok(event) if event.invalidated_session_hash.as_deref() == session.token_hash.as_deref() => {
                    let _ = socket_send(&mut tx, Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "Session revoked".into(),
                    }))).await;
                    break
                },
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
                    let delivered_uid = event.uid;
                    if socket_send(&mut tx, Message::Text(event.text.into())).await.is_err() {
                        break
                    }
                    record_delivered_revision(session.live.as_ref(), delivered_uid);
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
    discard_pending_upload(&s, &mut session, "connection_closed").await;
}

fn record_delivered_revision(live: Option<&crate::admin::LiveGuard>, uid: i64) {
    if let Some(live) = live {
        live.activity(uid, "live");
    }
}

async fn discard_pending_upload(s: &AppState, session: &mut Session, reason: &'static str) {
    let Some(pending) = session.pending.take() else {
        return;
    };
    let Pending {
        path,
        file,
        _permit,
        ..
    } = pending;
    drop(file);
    drop(_permit);
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            warn!(event = "staged_upload_cleanup_failed", reason, error = %error);
            s.metrics.errors.fetch_add(1, Ordering::Relaxed);
        }
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
            if let Some(live) = &session.live {
                live.protocol_activity(live_protocol_state(op));
            }
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
                    let (size, vault_size) = db_task(s, move |db| {
                        Ok((
                            db.stored_ciphertext_size_for_vault_owner(&vault)?
                                .context("authorized vault has no owner")?,
                            db.vault_size(&vault)?,
                        ))
                    })
                    .await?;
                    if !session_active(s, session).await {
                        return close(tx, 1008, "Authorization revoked").await;
                    }
                    send(tx,json!({"res":"ok","size":size,"limit":s.config.storage_quota_bytes_per_owner,"vault_size":vault_size})).await?
                }
                "usernames" => {
                    let vault = session.vault.clone().unwrap();
                    let usernames = db_task(s, move |db| db.usernames_for_vault(&vault)).await?;
                    if !session_active(s, session).await {
                        return close(tx, 1008, "Authorization revoked").await;
                    }
                    send(tx, serde_json::to_value(usernames)?).await?
                }
                "push" => begin_push(s, session, events, tx, v).await?,
                "pull" => pull(s, session, tx, v).await?,
                "deleted" => deleted(s, session, tx, v).await?,
                "history" => history(s, session, tx, v).await?,
                "restore" => restore(s, session, events, tx, v).await?,
                "purge" => {
                    let vault = session.vault.clone().unwrap();
                    let user_id = session
                        .user_id
                        .context("authenticated session has no user ID")?;
                    let token_hash = session
                        .token_hash
                        .clone()
                        .context("authenticated session has no token hash")?;
                    let _commit = s.commit_order.lock().await;
                    db_task(s, move |db| {
                        db.purge_for_session(user_id, &token_hash, &vault)
                    })
                    .await?;
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
            if let Some(live) = &session.live {
                live.protocol_activity("uploading");
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

fn live_protocol_state(operation: &str) -> &'static str {
    match operation {
        "ping" => "ping",
        "size" => "size",
        "usernames" => "usernames",
        "push" => "push",
        "pull" => "pull",
        "deleted" => "deleted",
        "history" => "history",
        "restore" => "restore",
        "purge" => "purge",
        _ => "unsupported",
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
    let (auth_context, vault, access, owner_user_id, retired_vault) = db_task(s, move |db| {
        let auth_context = token_has_session_shape
            .then(|| db.auth_context_hash(&validation_hash))
            .transpose()?
            .flatten();
        let Some(auth_context) = auth_context else {
            return Ok((None, None, None, None, false));
        };
        let authorized = db.find_authorized_vault(auth_context.user_id, &lookup_id)?;
        let (vault, access) = match authorized {
            Some((vault, access)) => (Some(vault), Some(access)),
            None => (None, None),
        };
        let owner_user_id = db.vault_owner_user_id(&lookup_id)?;
        let retired = db.is_retired_vault_for_user(auth_context.user_id, &lookup_id)?;
        Ok((Some(auth_context), vault, access, owner_user_id, retired))
    })
    .await?;
    let valid_session = auth_context.is_some();
    let Some(vault) = vault else {
        if valid_session || (token_has_session_shape && retired_vault) {
            if valid_session {
                s.metrics.deny(AuthorizationOperation::DataInit);
            }
            send(tx, json!({"res":"err","msg":"Vault not found"})).await?;
            return close(tx, 1008, "Vault not found").await;
        }
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    };
    if matches!(access, Some(crate::model::VaultAccess::Collaborator { .. }))
        && !owner_user_id.is_some_and(|owner| s.config.sharing_allowed_for_owner(owner))
    {
        send(tx, json!({"res":"err","msg":"Vault not found"})).await?;
        return close(tx, 1008, "Vault not found").await;
    }
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
    let auth_context = auth_context.unwrap();
    let Some(user_connection_permit) = s.user_concurrency.try_acquire(
        auth_context.user_id,
        UserConcurrencyKind::Connection,
        s.config.max_ws_connections_per_user,
    ) else {
        send(
            tx,
            json!({"res":"err","msg":"Account connection capacity reached; retry shortly"}),
        )
        .await?;
        return close(tx, 1013, "Account connection capacity reached").await;
    };
    session.authenticated = true;
    session.token_hash = Some(auth_context.token_hash.clone());
    session.user_id = Some(auth_context.user_id);
    session.expires_at = Some(auth_context.expires_at);
    session._user_connection_permit = Some(user_connection_permit);
    session.vault = Some(vault.id.clone());
    session.vault_owner_user_id = owner_user_id;
    session.device = bounded(
        v.get("device")
            .and_then(Value::as_str)
            .unwrap_or("Unknown device"),
        256,
    )
    .unwrap_or("Unknown device")
    .into();
    session.live = s.live_connections.register(
        auth_context.user_id,
        &auth_context.token_hash,
        &vault.id,
        &session.device,
        version,
    );
    session.cancellation = session.live.as_ref().map(|live| live.cancellation());
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
        json!({"res":"ok","userId":auth_context.user_id,"perFileMax":s.config.per_file_max}),
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
            if !session_active(s, session).await {
                return close(tx, 1008, "Authorization revoked").await;
            }
            cursor = revision.uid;
            // Retain at most a small, explicitly bounded DB page per client,
            // then admit each wire item separately. A trickle reader releases
            // its permit between items and cannot monopolize the bulk pool.
            let Some(_bulk_memory) =
                acquire_bulk_memory(s.bulk_memory.clone(), s.shutdown.clone()).await?
            else {
                return Ok(());
            };
            send(tx, serde_json::to_value(PushNotice::from(revision))?).await?;
        }
        if page_len < REPLAY_PAGE_SIZE as usize {
            break;
        }
    }
    if !session_active(s, session).await {
        return close(tx, 1008, "Authorization revoked").await;
    }
    send(tx, json!({"op":"ready","version":ready_version})).await?;
    if let Some(live) = &session.live {
        live.activity(ready_version, "ready");
    }
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
        user_id: session
            .user_id
            .context("authenticated session has no user ID")?,
    };
    if serialized_notice_size(&revision)? > MAX_EVENT_BYTES {
        send(tx, json!({"err":"Push metadata is too large"})).await?;
        return Ok(());
    }
    if revision.folder || revision.deleted || pieces == 0 {
        let notice = {
            let _commit = s.commit_order.lock().await;
            let storage_quota_bytes = s.config.storage_quota_bytes;
            let owner_storage_quota_bytes = s.config.storage_quota_bytes_per_owner;
            let token_hash = session
                .token_hash
                .clone()
                .context("authenticated session has no token hash")?;
            let stored = match db_task(s, move |db| {
                db.add_empty_revision_for_session(
                    &revision,
                    &token_hash,
                    storage_quota_bytes,
                    owner_storage_quota_bytes,
                )
            })
            .await
            {
                Ok(stored) => stored,
                Err(error) if crate::db::is_storage_quota_exceeded(&error) => {
                    drop(_commit);
                    reject_storage_quota(s, tx).await?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
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
    let user_id = revision.user_id;
    let owner_user_id = session
        .vault_owner_user_id
        .context("authorized vault has no owner")?;
    let Some(user_upload_permit) = s.user_concurrency.try_acquire(
        user_id,
        UserConcurrencyKind::Upload,
        s.config.max_concurrent_uploads_per_user,
    ) else {
        drop(permit);
        send(
            tx,
            json!({"err":"Account upload capacity reached; retry shortly"}),
        )
        .await?;
        return Ok(());
    };
    let storage_reservation = {
        let _commit = s.commit_order.lock().await;
        let (committed_global, committed_owner) = db_task(s, move |db| {
            Ok((
                db.stored_ciphertext_size()?,
                db.stored_ciphertext_size_for_owner(owner_user_id)?,
            ))
        })
        .await?;
        s.storage_reservations.try_reserve(
            committed_global,
            committed_owner,
            owner_user_id,
            revision.size,
            s.config.storage_quota_bytes,
            s.config.storage_quota_bytes_per_owner,
        )
    };
    let Some(storage_reservation) = storage_reservation else {
        drop(permit);
        drop(user_upload_permit);
        reject_storage_quota(s, tx).await?;
        return Ok(());
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
        idle_deadline: TokioInstant::now() + s.config.upload_idle_timeout,
        _storage_reservation: storage_reservation,
        _permit: permit,
        _user_upload_permit: user_upload_permit,
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
    {
        let Some(_bulk_memory) =
            acquire_bulk_memory(s.bulk_memory.clone(), s.shutdown.clone()).await?
        else {
            return Ok(());
        };
        write_staged_piece(&mut p.file, bytes).await?;
    }
    p.idle_deadline = TokioInstant::now() + s.config.upload_idle_timeout;
    if p.pieces < p.revision.pieces {
        send(tx, json!({"res":"next"})).await?;
        return Ok(());
    }
    if p.bytes != p.revision.size {
        return close(tx, 1008, "Upload size does not match metadata").await;
    }
    p.file.sync_all().await?;
    let token_hash = session
        .token_hash
        .clone()
        .context("authenticated session has no token hash")?;
    let pending = session.pending.take().unwrap();
    drop(pending.file);
    let revision = pending.revision.clone();
    let path = pending.path.clone();
    let storage_reservation = pending._storage_reservation;
    let storage_quota_bytes = s.config.storage_quota_bytes;
    let owner_storage_quota_bytes = s.config.storage_quota_bytes_per_owner;
    let commit_result = {
        let _commit = s.commit_order.lock().await;
        let result = db_task(s, move |db| {
            db.add_file_revision_for_session(
                &revision,
                &token_hash,
                &path,
                storage_quota_bytes,
                owner_storage_quota_bytes,
            )
        })
        .await
        .and_then(|stored| {
            let stored_size = stored.size;
            Ok((publish_committed(s, stored)?, stored_size))
        });
        // The database result now reflects this upload. Release its in-flight
        // capacity while the commit-order guard still excludes new admission.
        drop(storage_reservation);
        result
    };
    if let Err(error) = tokio::fs::remove_file(&pending.path).await {
        warn!(event = "staged_upload_cleanup_failed", error = %error);
        if commit_result.is_ok() {
            return Err(error.into());
        }
    }
    let (notice, stored_size) = match commit_result {
        Ok(committed) => committed,
        Err(error) if crate::db::is_storage_quota_exceeded(&error) => {
            close_storage_quota(s, tx).await?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
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
    if !session_active(s, session).await {
        return close(tx, 1008, "Authorization revoked").await;
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
        // A pull frame is 2 MiB and passes through SQLite, WebSocket, and
        // kernel buffers. Admit two frames at a time and release the permit
        // between pieces so slow readers cannot monopolize pull capacity.
        let Some(_pull_permit) = acquire_pull_permit(s.pulls.clone(), s.shutdown.clone()).await?
        else {
            return Ok(());
        };
        let Some(_bulk_memory) =
            acquire_bulk_memory(s.bulk_memory.clone(), s.shutdown.clone()).await?
        else {
            return Ok(());
        };
        if shutting_down(s) {
            return Ok(());
        }
        let len = (info.size - offset).min(PIECE_SIZE);
        let chunk = db_task(s, move |db| db.content_chunk(uid, offset, len)).await?;
        if !session_active(s, session).await {
            return close(tx, 1008, "Authorization revoked").await;
        }
        socket_send(tx, Message::Binary(chunk.into())).await?;
        offset += len
    }
    s.metrics.downloads.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

async fn acquire_password_memory(
    bulk_memory: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown) => Ok(None),
        permit = timeout_at(
            deadline,
            bulk_memory.acquire_many_owned(ARGON2_MEMORY_PERMITS),
        ) => match permit {
            Ok(Ok(permit)) => Ok(Some(permit)),
            Ok(Err(error)) => Err(error).context("bulk-memory pool stopped"),
            Err(_) => Ok(None),
        },
    }
}

async fn acquire_bulk_memory(
    bulk_memory: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown) => Ok(None),
        permit = bulk_memory.acquire_owned() => {
            Ok(Some(permit.context("bulk-memory pool stopped")?))
        },
    }
}

async fn acquire_pull_permit(
    pulls: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    tokio::select! {
        biased;
        _ = wait_for_shutdown(&mut shutdown) => Ok(None),
        permit = pulls.acquire_owned() => Ok(Some(permit.context("pull pool stopped")?)),
    }
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
    let Some(_bulk_memory) = acquire_bulk_memory(s.bulk_memory.clone(), s.shutdown.clone()).await?
    else {
        return Ok(());
    };
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
    if !session_active(s, session).await {
        return close(tx, 1008, "Authorization revoked").await;
    }
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
    let Some(_bulk_memory) = acquire_bulk_memory(s.bulk_memory.clone(), s.shutdown.clone()).await?
    else {
        return Ok(());
    };
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
    if !session_active(s, session).await {
        return close(tx, 1008, "Authorization revoked").await;
    }
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
        let user_id = session
            .user_id
            .context("authenticated session has no user ID")?;
        let token_hash = session
            .token_hash
            .clone()
            .context("authenticated session has no token hash")?;
        let storage_quota_bytes = s.config.storage_quota_bytes;
        let owner_storage_quota_bytes = s.config.storage_quota_bytes_per_owner;
        let reserved_global = s.storage_reservations.reserved();
        let owner_user_id = session
            .vault_owner_user_id
            .context("authorized vault has no owner")?;
        let reserved_owner = s.storage_reservations.reserved_for_owner(owner_user_id);
        let restore_global_quota_bytes = storage_quota_bytes.saturating_sub(reserved_global);
        let restore_owner_quota_bytes = owner_storage_quota_bytes.saturating_sub(reserved_owner);
        match db_task(s, move |db| {
            db.restore_for_session(
                user_id,
                &token_hash,
                &vault,
                uid,
                &device,
                (restore_global_quota_bytes, restore_owner_quota_bytes),
            )
        })
        .await
        {
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
            Err(error) if crate::db::is_storage_quota_exceeded(&error) => {
                drop(_commit);
                reject_storage_quota(s, tx).await?;
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
        invalidated_session_hash: None,
    };
    let _ = s.events.send(event.clone());
    Ok(event)
}

async fn reject_storage_quota(s: &AppState, tx: &mut SplitSink<WebSocket, Message>) -> Result<()> {
    record_storage_quota_rejection(s);
    send(tx, json!({"err":STORAGE_QUOTA_CLIENT_ERROR})).await
}

async fn close_storage_quota(s: &AppState, tx: &mut SplitSink<WebSocket, Message>) -> Result<()> {
    record_storage_quota_rejection(s);
    // Obsidian 1.12.7 checks the metadata response but discards JSON after a
    // binary piece. A close frame is therefore the only fail-safe final-stage
    // signal that cannot be mistaken for a successful upload.
    socket_send(tx, Message::Close(Some(storage_quota_close_frame()))).await?;
    Err(anyhow::anyhow!(STORAGE_QUOTA_CLIENT_ERROR))
}

fn storage_quota_close_frame() -> CloseFrame {
    CloseFrame {
        code: 1008,
        reason: STORAGE_QUOTA_CLIENT_ERROR.into(),
    }
}

fn record_storage_quota_rejection(s: &AppState) {
    s.metrics
        .storage_quota_rejections
        .fetch_add(1, Ordering::Relaxed);
    warn!(
        event = "storage_quota_rejected",
        storage_quota_bytes = s.config.storage_quota_bytes
    );
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
    config
        .per_file_max
        .saturating_add(AES_GCM_WIRE_OVERHEAD_BYTES) as i64
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

pub(crate) fn request_source(config: &Config, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
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

pub(crate) async fn db_task<T, F>(state: &AppState, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Db) -> Result<T> + Send + 'static,
{
    let permit = match timeout(
        DB_WORKER_QUEUE_DEADLINE,
        state.db_workers.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(anyhow::anyhow!("database worker pool stopped")),
        Err(_) => {
            state.metrics.database_deadline(DatabaseOperation::Request);
            return Err(anyhow::anyhow!("database worker deadline exceeded"));
        }
    };
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
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation(database)
    })
    .await
    .context("database worker stopped")?;
    if let Err(error) = &result {
        state
            .metrics
            .observe_database_error(DatabaseOperation::Request, error);
    }
    result
}

pub(crate) fn observe_database_error(
    state: &AppState,
    operation: DatabaseOperation,
    error: &anyhow::Error,
) {
    state.metrics.observe_database_error(operation, error);
}

async fn session_active(s: &AppState, session: &Session) -> bool {
    if session
        .expires_at
        .is_none_or(|expires_at| expires_at <= now_ms())
    {
        return false;
    }
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
async fn wait_for_cancellation(cancellation: Option<watch::Receiver<bool>>) {
    let Some(mut cancellation) = cancellation else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if *cancellation.borrow_and_update() {
            return;
        }
        if cancellation.changed().await.is_err() {
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
    Admin(ListenerJoinResult),
}

async fn supervise_listeners<S>(
    shutdown_tx: watch::Sender<bool>,
    mut control_task: tokio::task::JoinHandle<std::io::Result<()>>,
    mut data_task: tokio::task::JoinHandle<std::io::Result<()>>,
    mut admin_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
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
        result = async { match admin_task.as_mut() { Some(task) => task.await, None => std::future::pending().await } } => ListenerTrigger::Admin(result),
    };
    let expected_shutdown = matches!(trigger, ListenerTrigger::Shutdown);
    info!(event = "shutdown_requested", expected = expected_shutdown);
    let _ = shutdown_tx.send(true);

    match trigger {
        ListenerTrigger::Shutdown => {
            let control = listener_result("control", control_task.await);
            let data = listener_result("data", data_task.await);
            let admin = match admin_task {
                Some(task) => listener_result("admin", task.await),
                None => Ok(()),
            };
            control.and(data).and(admin)
        }
        ListenerTrigger::Control(result) => {
            let control = unexpected_listener_result("control", result);
            let data = listener_result("data", data_task.await);
            let admin = match admin_task {
                Some(task) => listener_result("admin", task.await),
                None => Ok(()),
            };
            control.and(data).and(admin)
        }
        ListenerTrigger::Data(result) => {
            let data = unexpected_listener_result("data", result);
            let control = listener_result("control", control_task.await);
            let admin = match admin_task {
                Some(task) => listener_result("admin", task.await),
                None => Ok(()),
            };
            data.and(control).and(admin)
        }
        ListenerTrigger::Admin(result) => {
            let admin = unexpected_listener_result("admin", result);
            let control = listener_result("control", control_task.await);
            let data = listener_result("data", data_task.await);
            admin.and(control).and(data)
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
    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{Request, StatusCode, header},
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    #[test]
    fn share_invite_limits_are_bounded_keyed_and_uniform() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::test(directory.path(), 3000, 3003).unwrap();
        config.share_invites_per_source = 3;
        config.share_invites_per_user = 3;
        config.share_invite_targets_per_user = 1;
        config.share_invites_global = 3;
        let source: IpAddr = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        let mut limits = ShareInviteLimits::new();

        assert!(limits.admit(source, 1, "first@example.test", &config, now));
        assert!(limits.admit(source, 1, "first@example.test", &config, now));
        assert!(!limits.admit(source, 1, "second@example.test", &config, now));
        assert_eq!(limits.attempts.len(), 2);
        let unkeyed: [u8; 32] = Sha256::digest(b"first@example.test").into();
        assert!(
            limits
                .attempts
                .iter()
                .all(|attempt| attempt.target_digest != unkeyed)
        );

        config.share_invite_targets_per_user = 3;
        assert!(limits.admit(source, 1, "second@example.test", &config, now));
        assert!(!limits.admit(
            "192.0.2.2".parse().unwrap(),
            2,
            "third@example.test",
            &config,
            now
        ));
        assert_eq!(limits.attempts.len(), config.share_invites_global);
    }

    fn admin_test_state(
        directory: &std::path::Path,
        admin_port: u16,
    ) -> (AppState, String, String, watch::Sender<bool>) {
        let mut config = Config::test(directory, 3000, 3003).unwrap();
        prepare_staging(&config.staging_dir).unwrap();
        config.admin = Some(crate::admin::AdminConfig {
            bind_host: "127.0.0.1".parse().unwrap(),
            port: admin_port,
        });
        let max_connections = config.max_ws_connections;
        let max_uploads = config.max_concurrent_uploads;
        let db = Db::open(&config.database_path).unwrap();
        let sync_token = db.issue_session(3600).unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        (
            AppState {
                config: Arc::new(config),
                db,
                events: broadcast::channel(EVENT_CAPACITY).0,
                commit_order: Arc::new(AsyncMutex::new(())),
                storage_reservations: Arc::new(StorageReservations::default()),
                user_concurrency: Arc::new(UserConcurrency::default()),
                uploads: Arc::new(Semaphore::new(max_uploads)),
                connections: Arc::new(Semaphore::new(max_connections)),
                auth_checks: Arc::new(Semaphore::new(auth::MAX_CONCURRENT_PASSWORD_CHECKS)),
                auth_waiters: Arc::new(Semaphore::new(MAX_SIGNIN_WAITERS)),
                source_limits: Arc::new(StdMutex::new(SourceLimits::default())),
                share_invite_limits: Arc::new(StdMutex::new(ShareInviteLimits::new())),
                control_body_readers: Arc::new(Semaphore::new(MAX_CONTROL_BODY_READERS)),
                control_requests: Arc::new(Semaphore::new(MAX_CONTROL_REQUESTS)),
                db_workers: Arc::new(Semaphore::new(MAX_DB_WORKERS)),
                pulls: Arc::new(Semaphore::new(MAX_CONCURRENT_PULLS)),
                bulk_memory: Arc::new(Semaphore::new(BULK_MEMORY_PERMITS)),
                large_responses: Arc::new(Semaphore::new(1)),
                shutdown,
                metrics: Arc::new(Metrics::default()),
                live_connections: crate::admin::LiveRegistry::new(max_connections),
                admin_snapshots: Arc::new(Semaphore::new(1)),
                started: Instant::now(),
            },
            "test-password".to_owned(),
            sync_token,
            shutdown_tx,
        )
    }

    fn admin_request(
        uri: &str,
        host: &str,
        session: Option<&str>,
        source: IpAddr,
    ) -> Request<Body> {
        let mut request = Request::get(uri)
            .header(header::HOST, host)
            .extension(ConnectInfo(SocketAddr::new(source, 49152)));
        if let Some(session) = session {
            request = request.header(
                header::COOKIE,
                format!("blackglass_admin_session={session}"),
            );
        }
        request.body(Body::empty()).unwrap()
    }

    fn admin_post_request(
        uri: &str,
        host: &str,
        session: Option<&str>,
        source: IpAddr,
        body: serde_json::Value,
    ) -> Request<Body> {
        let mut request = Request::post(uri)
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(SocketAddr::new(source, 49152)));
        if let Some(session) = session {
            request = request
                .header(
                    header::COOKIE,
                    format!("blackglass_admin_session={session}"),
                )
                .header("x-blackglass-admin", "1");
        }
        request
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    #[test]
    fn storage_reservations_are_bounded_and_release_on_drop() {
        let reservations = Arc::new(StorageReservations::default());
        let first = reservations.try_reserve(16, 16, 1, 32, 64, 64).unwrap();
        assert_eq!(reservations.reserved(), 32);
        assert_eq!(reservations.reserved_for_owner(1), 32);
        assert!(reservations.try_reserve(16, 16, 1, 17, 64, 64).is_none());
        let second = reservations.try_reserve(16, 16, 2, 16, 64, 64).unwrap();
        assert_eq!(reservations.reserved(), 48);
        assert!(reservations.try_reserve(16, 16, 2, 1, 64, 32).is_none());
        drop(first);
        assert_eq!(reservations.reserved(), 16);
        let third = reservations.try_reserve(16, 16, 1, 32, 64, 64).unwrap();
        assert_eq!(reservations.reserved(), 48);
        drop(second);
        drop(third);
        assert_eq!(reservations.reserved(), 0);
    }

    #[test]
    fn database_metrics_classify_only_fixed_busy_and_deadline_reasons() {
        let metrics = Metrics::default();
        let busy = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("untrusted detail".into()),
        ));
        let interrupted = anyhow::Error::new(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_INTERRUPT),
            None,
        ));
        let unrelated = anyhow::anyhow!("untrusted detail");

        metrics.observe_database_error(DatabaseOperation::Request, &busy);
        metrics.observe_database_error(DatabaseOperation::AdminSnapshot, &interrupted);
        metrics.observe_database_error(DatabaseOperation::Request, &unrelated);

        assert_eq!(
            metrics.database_busy[DatabaseOperation::Request as usize].load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.database_deadlines[DatabaseOperation::AdminSnapshot as usize]
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.database_deadlines[DatabaseOperation::Request as usize].load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn per_user_concurrency_is_isolated_and_releases_on_drop() {
        let limits = Arc::new(UserConcurrency::default());
        let first = limits
            .try_acquire(1, UserConcurrencyKind::Connection, 1)
            .unwrap();
        assert!(
            limits
                .try_acquire(1, UserConcurrencyKind::Connection, 1)
                .is_none()
        );
        let other = limits
            .try_acquire(2, UserConcurrencyKind::Connection, 1)
            .unwrap();
        let upload = limits
            .try_acquire(1, UserConcurrencyKind::Upload, 1)
            .unwrap();
        assert!(
            limits
                .try_acquire(1, UserConcurrencyKind::Upload, 1)
                .is_none()
        );
        drop(first);
        let replacement = limits
            .try_acquire(1, UserConcurrencyKind::Connection, 1)
            .unwrap();
        drop((replacement, other, upload));
        assert!(limits.entries.lock().unwrap().is_empty());
    }

    #[test]
    fn final_storage_quota_rejection_is_a_close_frame_not_json() {
        let frame = storage_quota_close_frame();
        assert_eq!(frame.code, 1008);
        assert_eq!(frame.reason.as_str(), STORAGE_QUOTA_CLIENT_ERROR);
    }

    #[tokio::test]
    async fn admin_http_routes_are_isolated_authenticated_and_hardened() {
        let directory = tempfile::tempdir().unwrap();
        let (state, admin_password, admin_session, _shutdown_tx) =
            admin_test_state(directory.path(), 3010);
        let candidate = state
            .db
            .signin_candidate("owner@example.test")
            .unwrap()
            .unwrap();
        assert_eq!(candidate.role, "admin");
        assert!(auth::verify_password(
            &admin_password,
            &candidate.password_hash
        ));
        let admin = crate::admin::router(state.clone());
        let ordinary_user = state
            .db
            .create_user(
                "member@example.test",
                "Member",
                &auth::hash_password("member-password").unwrap(),
            )
            .unwrap();
        let ordinary_session = state
            .db
            .issue_session_for_user(ordinary_user, 3600)
            .unwrap();

        let shell = admin
            .clone()
            .oneshot(admin_request(
                "/admin",
                "127.0.0.1:3010",
                None,
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .unwrap();
        assert_eq!(shell.status(), StatusCode::OK);
        assert_eq!(
            shell.headers()["content-security-policy"],
            crate::admin::CSP
        );
        assert_eq!(shell.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(shell.headers()["x-content-type-options"], "nosniff");
        assert_eq!(shell.headers()["referrer-policy"], "no-referrer");

        let signed_out = admin
            .clone()
            .oneshot(admin_request(
                "/admin/api/session",
                "127.0.0.1:3010",
                None,
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .unwrap();
        assert_eq!(signed_out.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(signed_out.into_body(), 1024).await.unwrap(),
            Bytes::from_static(br#"{"signedIn":false}"#)
        );

        let logo = admin
            .clone()
            .oneshot(admin_request(
                "/admin/logo.png",
                "127.0.0.1:3010",
                None,
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .unwrap();
        assert_eq!(logo.status(), StatusCode::OK);
        assert_eq!(logo.headers()[header::CONTENT_TYPE], "image/png");
        assert_eq!(logo.headers()[header::CACHE_CONTROL], "no-store");

        for host in ["attacker.invalid:3010", "127.0.0.1:3011"] {
            let response = admin
                .clone()
                .oneshot(admin_request(
                    "/admin",
                    host,
                    None,
                    IpAddr::from([127, 0, 0, 1]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
        let missing_host = admin
            .clone()
            .oneshot(Request::get("/admin").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing_host.status(), StatusCode::MISDIRECTED_REQUEST);

        for session in [None, Some("f".repeat(64)), Some(ordinary_session)] {
            let response = admin
                .clone()
                .oneshot(admin_request(
                    "/admin/api/snapshot",
                    "127.0.0.1:3010",
                    session.as_deref(),
                    IpAddr::from([127, 0, 0, 1]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let authorized = admin
            .clone()
            .oneshot(admin_request(
                "/admin/api/snapshot?fresh=1",
                "127.0.0.1:3010",
                Some(&admin_session),
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        assert_eq!(authorized.headers()[header::CACHE_CONTROL], "no-store");

        let invalid_login = admin
            .clone()
            .oneshot(admin_post_request(
                "/admin/api/login",
                "127.0.0.1:3010",
                None,
                IpAddr::from([127, 0, 0, 1]),
                json!({"email":"owner@example.test","password":"wrong-password"}),
            ))
            .await
            .unwrap();
        assert_eq!(invalid_login.status(), StatusCode::UNAUTHORIZED);

        let valid_login = admin
            .clone()
            .oneshot(admin_post_request(
                "/admin/api/login",
                "127.0.0.1:3010",
                None,
                IpAddr::from([127, 0, 0, 1]),
                json!({"email":"owner@example.test","password":admin_password}),
            ))
            .await
            .unwrap();
        assert_eq!(valid_login.status(), StatusCode::OK);
        let login_cookie = valid_login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(login_cookie.contains("HttpOnly; SameSite=Strict; Path=/admin"));
        let login_session = login_cookie
            .strip_prefix("blackglass_admin_session=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let mut csrf = admin_post_request(
            "/admin/api/registration",
            "127.0.0.1:3010",
            Some(&login_session),
            IpAddr::from([127, 0, 0, 1]),
            json!({"enabled":true}),
        );
        csrf.headers_mut().remove("x-blackglass-admin");
        let csrf = admin.clone().oneshot(csrf).await.unwrap();
        assert_eq!(csrf.status(), StatusCode::FORBIDDEN);
        assert!(!state.db.self_registration_enabled().unwrap());

        let registration = admin
            .clone()
            .oneshot(admin_post_request(
                "/admin/api/registration",
                "127.0.0.1:3010",
                Some(&admin_session),
                IpAddr::from([127, 0, 0, 1]),
                json!({"enabled":true}),
            ))
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::OK);
        assert!(state.db.self_registration_enabled().unwrap());

        let logout = admin
            .clone()
            .oneshot(admin_post_request(
                "/admin/api/logout",
                "127.0.0.1:3010",
                Some(&login_session),
                IpAddr::from([127, 0, 0, 1]),
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::NO_CONTENT);
        assert!(
            logout.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        let revoked = admin
            .clone()
            .oneshot(admin_request(
                "/admin/api/snapshot",
                "127.0.0.1:3010",
                Some(&login_session),
                IpAddr::from([127, 0, 0, 1]),
            ))
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::UNAUTHORIZED);

        for public in [control_router(state.clone()), data_router(state)] {
            let response = public
                .oneshot(Request::get("/admin").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn account_registration_creates_an_ordinary_client_account() {
        let directory = tempfile::tempdir().unwrap();
        let (state, _, _, _shutdown_tx) = admin_test_state(directory.path(), 3010);
        let control = control_router(state.clone());
        let source = IpAddr::from([127, 0, 0, 1]);

        let status = control
            .clone()
            .oneshot(
                Request::get("/account/api/registration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(status.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(status.into_body(), 1024).await.unwrap(),
            Bytes::from_static(br#"{"enabled":false}"#)
        );

        let signup_request = || {
            Request::post("/account/api/signup")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(ConnectInfo(SocketAddr::new(source, 49152)))
                .body(Body::from(
                    r#"{"email":"new@example.test","name":"New user","password":"correct-horse-battery"}"#,
                ))
                .unwrap()
        };
        let disabled = control.clone().oneshot(signup_request()).await.unwrap();
        assert_eq!(disabled.status(), StatusCode::FORBIDDEN);

        state.db.set_self_registration_enabled(1, true).unwrap();
        let created = control.clone().oneshot(signup_request()).await.unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);
        let candidate = state
            .db
            .signin_candidate("new@example.test")
            .unwrap()
            .unwrap();
        assert_eq!(candidate.role, "user");

        let signed_in = control
            .clone()
            .oneshot(
                Request::post("/user/signin")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, "app://obsidian.md")
                    .extension(ConnectInfo(SocketAddr::new(source, 49153)))
                    .body(Body::from(
                        r#"{"email":"new@example.test","password":"correct-horse-battery"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(signed_in.status(), StatusCode::OK);
        let body = to_bytes(signed_in.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["email"], "new@example.test");
        assert_eq!(body["name"], "New user");
        assert_eq!(body["token"].as_str().unwrap().len(), 64);

        let duplicate = control.oneshot(signup_request()).await.unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);
    }

    async fn raw_http_status(address: SocketAddr, request: &str) -> StatusCode {
        use tokio::io::AsyncReadExt;

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let status = std::str::from_utf8(&response)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_ascii_whitespace()
            .nth(1)
            .unwrap();
        StatusCode::from_bytes(status.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn admin_listener_supplies_peer_info_and_rejects_foreign_authorities() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let (state, _, admin_session, _shutdown_tx) =
            admin_test_state(directory.path(), address.port());
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                crate::admin::router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });

        let rejected = raw_http_status(
            address,
            &format!(
                "GET /admin HTTP/1.1\r\nHost: attacker.invalid:{}\r\nConnection: close\r\n\r\n",
                address.port()
            ),
        )
        .await;
        assert_eq!(rejected, StatusCode::MISDIRECTED_REQUEST);

        let rejected_unknown_path = raw_http_status(
            address,
            &format!(
                "GET /unknown HTTP/1.1\r\nHost: attacker.invalid:{}\r\nConnection: close\r\n\r\n",
                address.port()
            ),
        )
        .await;
        assert_eq!(rejected_unknown_path, StatusCode::MISDIRECTED_REQUEST);

        let accepted = raw_http_status(
            address,
            &format!(
                "GET /admin/api/snapshot HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: blackglass_admin_session={admin_session}\r\nConnection: close\r\n\r\n",
                address.port()
            ),
        )
        .await;
        assert_eq!(accepted, StatusCode::OK);

        task.abort();
        let _ = task.await;
    }

    #[test]
    fn live_protocol_state_never_reflects_client_controlled_text() {
        for operation in [
            "ping",
            "size",
            "usernames",
            "push",
            "pull",
            "deleted",
            "history",
            "restore",
            "purge",
        ] {
            assert_eq!(live_protocol_state(operation), operation);
        }
        for operation in ["", "future-client-op", "<script>alert(1)</script>"] {
            assert_eq!(live_protocol_state(operation), "unsupported");
        }
    }

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

    #[tokio::test]
    async fn fixed_pull_queue_exits_promptly_on_shutdown() {
        assert_eq!(MAX_CONCURRENT_PULLS, 2);
        let pulls = Arc::new(Semaphore::new(MAX_CONCURRENT_PULLS));
        let first = pulls.clone().acquire_owned().await.unwrap();
        let second = pulls.clone().acquire_owned().await.unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let waiting = tokio::spawn(acquire_pull_permit(pulls, shutdown));
        tokio::task::yield_now().await;

        shutdown_tx.send(true).unwrap();
        let admitted = timeout(Duration::from_millis(250), waiting)
            .await
            .expect("queued pull ignored shutdown")
            .expect("queued pull task panicked")
            .expect("queued pull admission failed");
        assert!(admitted.is_none());

        drop((first, second));
    }

    #[tokio::test]
    async fn password_memory_reservation_keeps_one_sync_lane_live() {
        assert_eq!(BULK_MEMORY_PERMITS, 4);
        assert_eq!(ARGON2_MEMORY_PERMITS, 3);
        let bulk_memory = Arc::new(Semaphore::new(BULK_MEMORY_PERMITS));
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let password = acquire_password_memory(
            bulk_memory.clone(),
            shutdown,
            tokio::time::Instant::now() + Duration::from_millis(250),
        )
        .await
        .unwrap()
        .expect("password memory admission timed out");

        assert_eq!(bulk_memory.available_permits(), 1);
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let sync = timeout(
            Duration::from_millis(250),
            acquire_bulk_memory(bulk_memory.clone(), shutdown),
        )
        .await
        .expect("password verification froze authenticated Sync")
        .unwrap()
        .expect("bulk-memory pool stopped");
        assert_eq!(bulk_memory.available_permits(), 0);

        drop(sync);
        assert_eq!(bulk_memory.available_permits(), 1);
        drop(password);
        assert_eq!(bulk_memory.available_permits(), BULK_MEMORY_PERMITS);
    }

    #[test]
    fn replay_page_has_an_explicit_memory_bound() {
        assert_eq!(REPLAY_PAGE_SIZE, 16);
        assert_eq!(MAX_REPLAY_PAGE_BYTES, 512 * 1024);
        assert_eq!(MAX_REPLAY_PAGES_BYTES, 8 * 1024 * 1024);
    }

    #[tokio::test]
    async fn queued_password_memory_reservation_is_fair_to_sync_work() {
        let bulk_memory = Arc::new(Semaphore::new(BULK_MEMORY_PERMITS));
        let first_active_sync = bulk_memory
            .clone()
            .acquire_many_owned(ARGON2_MEMORY_PERMITS)
            .await
            .unwrap();
        let second_active_sync = bulk_memory.clone().acquire_owned().await.unwrap();
        let (_shutdown_tx, shutdown) = watch::channel(false);
        let waiting_password = tokio::spawn(acquire_password_memory(
            bulk_memory.clone(),
            shutdown,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;

        let (_shutdown_tx, shutdown) = watch::channel(false);
        let waiting_sync = tokio::spawn(acquire_bulk_memory(bulk_memory.clone(), shutdown));
        tokio::task::yield_now().await;
        assert!(!waiting_sync.is_finished());

        drop(first_active_sync);
        let password = timeout(Duration::from_millis(250), waiting_password)
            .await
            .expect("queued password reservation was bypassed")
            .expect("queued password task panicked")
            .expect("password memory admission failed")
            .expect("password memory admission timed out");
        tokio::task::yield_now().await;
        assert!(!waiting_sync.is_finished());

        drop(second_active_sync);
        let sync = timeout(Duration::from_millis(250), waiting_sync)
            .await
            .expect("reserved Sync lane was not admitted")
            .expect("queued Sync task panicked")
            .expect("bulk-memory admission failed")
            .expect("bulk-memory pool stopped");

        drop((password, sync));
    }

    #[tokio::test]
    async fn queued_password_memory_reservation_exits_promptly_on_shutdown() {
        let bulk_memory = Arc::new(Semaphore::new(BULK_MEMORY_PERMITS));
        let active = bulk_memory
            .clone()
            .acquire_many_owned(BULK_MEMORY_PERMITS as u32)
            .await
            .unwrap();
        let (shutdown_tx, shutdown) = watch::channel(false);
        let waiting = tokio::spawn(acquire_password_memory(
            bulk_memory,
            shutdown,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;

        shutdown_tx.send(true).unwrap();
        let admitted = timeout(Duration::from_millis(250), waiting)
            .await
            .expect("queued password reservation ignored shutdown")
            .expect("queued password task panicked")
            .expect("password memory admission failed");
        assert!(admitted.is_none());

        drop(active);
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
            supervise_listeners(shutdown_tx, control, data, None, std::future::pending()),
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
    fn delivered_live_revision_advances_registry_cursor_and_activity() {
        let registry = crate::admin::LiveRegistry::new(1);
        let guard = registry
            .register(1, "session", "vault", "device", 3)
            .unwrap();
        let before = registry.snapshot()[0].last_activity_at;
        std::thread::sleep(Duration::from_millis(2));
        record_delivered_revision(Some(&guard), 41);
        let delivered = &registry.snapshot()[0];
        assert_eq!(delivered.client_cursor, 41);
        assert!(delivered.last_activity_at > before);
        assert_eq!(delivered.state, "live");
    }

    #[tokio::test]
    async fn listener_supervisor_awaits_admin_after_control_exit() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut admin_shutdown = shutdown_rx.clone();
        let admin_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = admin_finished.clone();
        let control = tokio::spawn(async { Ok(()) });
        let data = tokio::spawn(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
            Ok(())
        });
        let admin = tokio::spawn(async move {
            wait_for_shutdown(&mut admin_shutdown).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            finished.store(true, Ordering::SeqCst);
            Ok(())
        });
        let _ = supervise_listeners(
            shutdown_tx,
            control,
            data,
            Some(admin),
            std::future::pending(),
        )
        .await;
        assert!(admin_finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn listener_supervisor_awaits_admin_after_data_exit() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut admin_shutdown = shutdown_rx.clone();
        let admin_finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finished = admin_finished.clone();
        let control = tokio::spawn(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
            Ok(())
        });
        let data = tokio::spawn(async { Ok(()) });
        let admin = tokio::spawn(async move {
            wait_for_shutdown(&mut admin_shutdown).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            finished.store(true, Ordering::SeqCst);
            Ok(())
        });
        let _ = supervise_listeners(
            shutdown_tx,
            control,
            data,
            Some(admin),
            std::future::pending(),
        )
        .await;
        assert!(admin_finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn listener_supervisor_propagates_an_unexpected_admin_exit() {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut other_shutdown = shutdown_rx.clone();
        let control = tokio::spawn(async move {
            wait_for_shutdown(&mut shutdown_rx).await;
            Ok(())
        });
        let data = tokio::spawn(async move {
            wait_for_shutdown(&mut other_shutdown).await;
            Ok(())
        });
        let admin = tokio::spawn(async { Ok(()) });
        let error = timeout(
            Duration::from_secs(1),
            supervise_listeners(
                shutdown_tx,
                control,
                data,
                Some(admin),
                std::future::pending(),
            ),
        )
        .await
        .expect("supervisor stalled")
        .expect_err("unexpected admin exit was accepted");
        assert!(
            error
                .to_string()
                .contains("admin listener exited unexpectedly")
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
