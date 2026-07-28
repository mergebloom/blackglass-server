use crate::{auth, config::Config, db::Db, model::*};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{
        DefaultBodyLimit, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Semaphore, broadcast},
};
use tracing::{info, warn};
use uuid::Uuid;

const PIECE_SIZE: i64 = 2 * 1024 * 1024;

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
}
#[derive(Default)]
struct LoginLimiter(Mutex<VecDeque<Instant>>);
impl LoginLimiter {
    fn accept(&self) -> bool {
        let Ok(mut attempts) = self.0.lock() else {
            return false;
        };
        let cutoff = Instant::now() - Duration::from_secs(60);
        while attempts.front().is_some_and(|t| *t < cutoff) {
            attempts.pop_front();
        }
        if attempts.len() >= 10 {
            return false;
        }
        attempts.push_back(Instant::now());
        true
    }
}
#[derive(Clone)]
struct Event {
    vault: String,
    origin: Uuid,
    text: String,
}
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Db,
    events: broadcast::Sender<Event>,
    uploads: Arc<Semaphore>,
    metrics: Arc<Metrics>,
    login_limiter: Arc<LoginLimiter>,
}

pub async fn run(config: Config) -> Result<()> {
    prepare_staging(&config.staging_dir)?;
    let db = Db::open(&config.database_path)?;
    let (events, _) = broadcast::channel(1024);
    let max_uploads = config.max_concurrent_uploads;
    let state = AppState {
        config: Arc::new(config),
        db,
        events,
        uploads: Arc::new(Semaphore::new(max_uploads)),
        metrics: Arc::new(Metrics::default()),
        login_limiter: Arc::new(LoginLimiter::default()),
    };
    let control = control_router(state.clone());
    let data = data_router(state.clone());
    let control_listener =
        TcpListener::bind((state.config.bind_host, state.config.control_port)).await?;
    let data_listener = TcpListener::bind((state.config.bind_host, state.config.data_port)).await?;
    info!(event="server_started",control=%control_listener.local_addr()?,data=%data_listener.local_addr()?,database=%state.config.database_path.display());
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut cstop = shutdown_tx.subscribe();
    let mut dstop = shutdown_tx.subscribe();
    let control_task = tokio::spawn(async move {
        axum::serve(control_listener, control)
            .with_graceful_shutdown(async move {
                let _ = cstop.recv().await;
            })
            .await
    });
    let data_task = tokio::spawn(async move {
        axum::serve(data_listener, data)
            .with_graceful_shutdown(async move {
                let _ = dstop.recv().await;
            })
            .await
    });
    shutdown_signal().await;
    info!(event = "shutdown_requested");
    let _ = shutdown_tx.send(());
    control_task.await??;
    data_task.await??;
    state.db.checkpoint()?;
    cleanup_staging(&state.config.staging_dir)?;
    info!(event = "server_stopped");
    Ok(())
}

fn control_router(state: AppState) -> Router {
    let mut r = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics));
    for path in [
        "/user/signin",
        "/user/signout",
        "/user/info",
        "/subscription/list",
        "/vault/regions",
        "/vault/list",
        "/vault/create",
        "/vault/access",
        "/vault/rename",
        "/vault/delete",
        "/vault/share/list",
        "/vault/share/invite",
        "/vault/share/remove",
    ] {
        r = r.route(path, post(control).options(preflight));
    }
    r.with_state(state).layer(DefaultBodyLimit::max(64 * 1024))
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
            "version": env!("CARGO_PKG_VERSION")
        }),
        StatusCode::OK,
    )
}
async fn ready(State(s): State<AppState>) -> Response {
    let ok = s.db.ready();
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
        "blackglass_control_requests_total {}\nblackglass_signins_total {}\nblackglass_auth_failures_total {}\nblackglass_ws_connections_total {}\nblackglass_uploads_total {}\nblackglass_upload_bytes_total {}\nblackglass_downloads_total {}\nblackglass_errors_total {}\nobsidian_sync_control_requests_total {}\nobsidian_sync_signins_total {}\nobsidian_sync_auth_failures_total {}\nobsidian_sync_ws_connections_total {}\nobsidian_sync_uploads_total {}\nobsidian_sync_upload_bytes_total {}\nobsidian_sync_downloads_total {}\nobsidian_sync_errors_total {}\n",
        m.control.load(Ordering::Relaxed),
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

async fn control(State(s): State<AppState>, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
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
    let result = if uri.path() == "/user/signin" {
        signin(&s, value).await
    } else {
        authorized_control(&s, uri.path(), value)
    };
    match result {
        Ok(v) => api_for_origin(&s, v, StatusCode::OK, request_origin),
        Err(message) => {
            s.metrics.errors.fetch_add(1, Ordering::Relaxed);
            api_for_origin(&s, json!({"error":message}), StatusCode::OK, request_origin)
        }
    }
}

async fn signin(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    if !s.login_limiter.accept() {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_rate_limited");
        return Err("Try again later".into());
    }
    let req: Signin =
        serde_json::from_value(v).map_err(|_| "Invalid email or password".to_string())?;
    let email_ok = req
        .email
        .as_deref()
        .is_some_and(|e| e.eq_ignore_ascii_case(&s.config.email));
    let password = req.password.unwrap_or_default();
    let encoded = s.config.password_hash.clone();
    let password_ok =
        tokio::task::spawn_blocking(move || auth::verify_password(&password, &encoded))
            .await
            .map_err(internal)?;
    let valid = email_ok && password_ok;
    if !valid {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        warn!(event = "signin_failed");
        return Err("Invalid email or password".into());
    }
    let token =
        s.db.issue_session(s.config.session_ttl.as_secs() as i64)
            .map_err(internal)?;
    s.metrics.signins.fetch_add(1, Ordering::Relaxed);
    info!(event = "signin_succeeded");
    Ok(
        json!({"email":s.config.email,"name":s.config.display_name,"license":"selfhosted-sync","token":token}),
    )
}

fn authorized_control(s: &AppState, path: &str, v: Value) -> std::result::Result<Value, String> {
    let token = v
        .get("token")
        .and_then(Value::as_str)
        .ok_or("Not logged in")?;
    if !s.db.valid_session(token) {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("Not logged in".into());
    }
    match path {
        "/user/signout" => {
            s.db.revoke_session(token).map_err(internal)?;
            Ok(json!({}))
        }
        "/user/info" => Ok(
            json!({"email":s.config.email,"name":s.config.display_name,"license":"selfhosted-sync"}),
        ),
        "/subscription/list" => Ok(json!({"sync":true,"publish":false})),
        "/vault/regions" => {
            Ok(json!({"regions":[{"value":"selfhost","name":"Blackglass Server"}]}))
        }
        "/vault/list" => {
            Ok(json!({"vaults":s.db.list_vaults().map_err(internal)?,"shared":[],"limit":100}))
        }
        "/vault/create" => create_vault(s, v),
        "/vault/access" => access_vault(s, v),
        "/vault/rename" => rename_vault(s, v),
        "/vault/delete" => delete_vault(s, v),
        "/vault/share/list" => Ok(json!({"shares":[]})),
        "/vault/share/invite" | "/vault/share/remove" => {
            Err("Sharing is unavailable in single-user mode".into())
        }
        _ => Err("Not found".into()),
    }
}

fn create_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultCreate =
        serde_json::from_value(v).map_err(|_| "Invalid vault request".to_string())?;
    let name = r
        .name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or("Vault name is required")?;
    let version = r
        .encryption_version
        .filter(|v| (0..=3).contains(v))
        .ok_or("Unsupported encryption version")?;
    let keyhash = r
        .keyhash
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or("End-to-end encryption is required")?;
    let salt = r
        .salt
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or("End-to-end encryption is required")?;
    let vault = Vault {
        id: Uuid::new_v4().to_string(),
        name: name.into(),
        keyhash: Some(keyhash),
        salt: Some(salt),
        host: s.config.public_data_host.clone(),
        region: "Blackglass Server".into(),
        encryption_version: version,
        size: 0,
        created: now_ms(),
    };
    s.db.create_vault(&vault).map_err(internal)?;
    serde_json::to_value(vault).map_err(internal)
}
fn access_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultAccess =
        serde_json::from_value(v).map_err(|_| "Unable to access vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to access vault")?;
    let vault =
        s.db.find_vault(&id)
            .map_err(internal)?
            .ok_or("Unable to access vault")?;
    if r.host.as_deref() != Some(&vault.host)
        || r.keyhash != vault.keyhash
        || r.encryption_version != Some(vault.encryption_version)
    {
        return Err("Unable to access vault".into());
    }
    Ok(json!({}))
}
fn rename_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultRename =
        serde_json::from_value(v).map_err(|_| "Unable to rename vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to rename vault")?;
    let name = r
        .name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .ok_or("Unable to rename vault")?;
    if !s.db.rename_vault(&id, name).map_err(internal)? {
        return Err("Unable to rename vault".into());
    }
    Ok(json!({}))
}
fn delete_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultDelete =
        serde_json::from_value(v).map_err(|_| "Unable to delete vault".to_string())?;
    if !s
        .db
        .delete_vault(r.vault_uid.as_deref().unwrap_or(""))
        .map_err(internal)?
    {
        return Err("Unable to delete vault".into());
    }
    Ok(json!({}))
}

async fn upgrade(State(s): State<AppState>, headers: HeaderMap, ws: WebSocketUpgrade) -> Response {
    if permitted_origin(&s, &headers).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.max_frame_size(PIECE_SIZE as usize)
        .max_message_size(PIECE_SIZE as usize)
        .on_upgrade(move |socket| socket_loop(s, socket))
        .into_response()
}

struct Session {
    authenticated: bool,
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

async fn socket_loop(s: AppState, socket: WebSocket) {
    s.metrics.ws_connections.fetch_add(1, Ordering::Relaxed);
    let id = Uuid::new_v4();
    let (mut tx, mut rx) = socket.split();
    let mut events = s.events.subscribe();
    let mut session = Session {
        authenticated: false,
        vault: None,
        device: "Unknown device".into(),
        pending: None,
    };
    loop {
        tokio::select! {
            incoming=rx.next()=>match incoming{
                Some(Ok(Message::Close(_)))=>break,
                Some(Ok(msg))=>{if let Err(e)=handle_message(&s,id,&mut session,&mut tx,msg).await{warn!(event="websocket_error",error=%e);s.metrics.errors.fetch_add(1,Ordering::Relaxed);break}},
                _=>break
            },
            event=events.recv()=>match event{Ok(event)=>{if event.origin!=id&&session.vault.as_deref()==Some(&event.vault)&&tx.send(Message::Text(event.text.into())).await.is_err(){break}},Err(broadcast::error::RecvError::Lagged(_))=>{let _=tx.send(Message::Close(Some(CloseFrame{code:1013,reason:"Change stream lagged; reconnect to resume".into()}))).await;break},Err(broadcast::error::RecvError::Closed)=>break}
        }
    }
    if let Some(p) = session.pending {
        drop(p.file);
        let _ = tokio::fs::remove_file(p.path).await;
    }
}

async fn handle_message(
    s: &AppState,
    id: Uuid,
    session: &mut Session,
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
                Err(_) => {
                    send(tx, json!({"res":"err","msg":"Invalid JSON"})).await?;
                    return Ok(());
                }
            };
            let op = v.get("op").and_then(Value::as_str).unwrap_or("");
            if op == "ping" {
                send(tx, json!({"op":"pong"})).await?;
                return Ok(());
            }
            if !session.authenticated {
                return init(s, session, tx, v).await;
            }
            match op{"size"=>send(tx,json!({"res":"ok","size":s.db.total_size()?,"limit":1099511627776i64,"vault_size":s.db.vault_size(session.vault.as_deref().unwrap())?})).await?,"usernames"=>send(tx,json!({"1":s.config.display_name})).await?,"push"=>begin_push(s,id,session,tx,v).await?,"pull"=>pull(s,session,tx,v).await?,"deleted"=>{let items=s.db.list_deleted(session.vault.as_deref().unwrap(),v.get("suppressrenames").and_then(Value::as_bool)==Some(true))?.into_iter().map(notice_item).collect::<Vec<_>>();send(tx,json!({"items":items})).await?},"history"=>history(s,session,tx,v).await?,"restore"=>restore(s,id,session,tx,v).await?,"purge"=>{s.db.purge(session.vault.as_deref().unwrap())?;send(tx,json!({"res":"ok"})).await?},_=>send(tx,json!({"err":format!("Unsupported operation: {op}")})).await?}
            Ok(())
        }
        Message::Binary(bytes) => upload_chunk(s, id, session, tx, &bytes).await,
        // The socket loop intercepts peer close frames as normal termination.
        // Keep this arm non-erroring as a defensive fallback.
        Message::Close(_) => Ok(()),
        Message::Ping(v) => {
            tx.send(Message::Pong(v)).await?;
            Ok(())
        }
        Message::Pong(_) => Ok(()),
    }
}

async fn init(
    s: &AppState,
    session: &mut Session,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    if v.get("op").and_then(Value::as_str) != Some("init") {
        send(tx, json!({"res":"err","msg":"Authentication required"})).await?;
        return Ok(());
    }
    let token = v.get("token").and_then(Value::as_str).unwrap_or("");
    let id = v.get("id").and_then(Value::as_str).unwrap_or("");
    let Some(vault) = s.db.find_vault(id)? else {
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    };
    let keyhash = v.get("keyhash").and_then(Value::as_str);
    let enc = v.get("encryption_version").and_then(Value::as_i64);
    if !s.db.valid_session(token)
        || keyhash != vault.keyhash.as_deref()
        || enc != Some(vault.encryption_version)
    {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    }
    session.authenticated = true;
    session.vault = Some(vault.id.clone());
    session.device = bounded(
        v.get("device")
            .and_then(Value::as_str)
            .unwrap_or("Unknown device"),
        256,
    )
    .unwrap_or("Unknown device")
    .into();
    send(
        tx,
        json!({"res":"ok","userId":1,"perFileMax":s.config.per_file_max}),
    )
    .await?;
    let version = v.get("version").and_then(Value::as_i64).unwrap_or(0).max(0);
    let initial = v.get("initial").and_then(Value::as_bool).unwrap_or(false);
    let revisions = if initial {
        s.db.initial_snapshot(&vault.id)?
    } else {
        s.db.list_changes(&vault.id, version)?
    };
    for r in revisions {
        send(tx, serde_json::to_value(PushNotice::from(r))?).await?
    }
    send(
        tx,
        json!({"op":"ready","version":s.db.current_version(&vault.id)?}),
    )
    .await?;
    Ok(())
}

async fn begin_push(
    s: &AppState,
    id: Uuid,
    session: &mut Session,
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
        && v.get("extension")
            .and_then(Value::as_str)
            .is_some_and(|x| x.len() <= 256)
        && v.get("hash")
            .and_then(Value::as_str)
            .is_some_and(|x| x.len() <= 4096)
        && v.get("ctime").and_then(Value::as_i64).is_some()
        && v.get("mtime").and_then(Value::as_i64).is_some()
        && v.get("folder").and_then(Value::as_bool).is_some()
        && v.get("deleted").and_then(Value::as_bool).is_some()
        && size >= 0
        && size <= s.config.per_file_max as i64
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
            .filter(|x| x.len() <= 16384)
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
    if revision.folder || revision.deleted || pieces == 0 {
        let stored = s.db.add_empty_revision(&revision)?;
        commit_notice(s, id, tx, stored).await?;
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
    id: Uuid,
    session: &mut Session,
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
    p.file.write_all(bytes).await?;
    // Tokio files may buffer writes on the blocking pool. Flush before acknowledging
    // the piece so staging is observable and disconnect cleanup cannot race a write.
    p.file.flush().await?;
    if p.pieces < p.revision.pieces {
        send(tx, json!({"res":"next"})).await?;
        return Ok(());
    }
    if p.bytes != p.revision.size {
        return close(tx, 1008, "Upload size does not match metadata").await;
    }
    p.file.flush().await?;
    p.file.sync_all().await?;
    let pending = session.pending.take().unwrap();
    drop(pending.file);
    let db = s.db.clone();
    let revision = pending.revision.clone();
    let path = pending.path.clone();
    let stored =
        tokio::task::spawn_blocking(move || db.add_file_revision(&revision, &path)).await??;
    let _ = tokio::fs::remove_file(&pending.path).await;
    s.metrics.uploads.fetch_add(1, Ordering::Relaxed);
    s.metrics
        .upload_bytes
        .fetch_add(stored.size as u64, Ordering::Relaxed);
    commit_notice(s, id, tx, stored).await
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
    let Some(info) = s.db.pull_info(uid)? else {
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
        let len = (info.size - offset).min(PIECE_SIZE);
        let chunk = s.db.content_chunk(uid, offset, len)?;
        tx.send(Message::Binary(chunk.into())).await?;
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
    let Some(path) = v
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| bounded(p, 16384).is_some())
    else {
        send(tx, json!({"err":"Invalid history path"})).await?;
        return Ok(());
    };
    let all = s.db.history(
        session.vault.as_deref().unwrap(),
        path,
        v.get("last").and_then(Value::as_i64),
        101,
    )?;
    let more = all.len() > 100;
    let items = all
        .into_iter()
        .take(100)
        .map(notice_item)
        .collect::<Vec<_>>();
    send(tx, json!({"items":items,"more":more})).await?;
    Ok(())
}
async fn restore(
    s: &AppState,
    id: Uuid,
    session: &Session,
    tx: &mut SplitSink<WebSocket, Message>,
    v: Value,
) -> Result<()> {
    let Some(uid) = v.get("uid").and_then(Value::as_i64) else {
        send(tx, json!({"err":"Revision not found"})).await?;
        return Ok(());
    };
    match s
        .db
        .restore(session.vault.as_deref().unwrap(), uid, &session.device)?
    {
        Some(r) => commit_notice(s, id, tx, r).await?,
        None => send(tx, json!({"err":"Revision not found"})).await?,
    }
    Ok(())
}
async fn commit_notice(
    s: &AppState,
    id: Uuid,
    tx: &mut SplitSink<WebSocket, Message>,
    r: Revision,
) -> Result<()> {
    let notice = serde_json::to_value(PushNotice::from(r.clone()))?;
    let text = serde_json::to_string(&notice)?;
    send(tx, notice).await?;
    let _ = s.events.send(Event {
        vault: r.vault_id,
        origin: id,
        text,
    });
    send(tx, json!({"res":"ok"})).await?;
    Ok(())
}
fn notice_item(r: Revision) -> Value {
    let mut v = serde_json::to_value(PushNotice::from(r)).unwrap_or(Value::Null);
    v.as_object_mut().map(|o| o.remove("op"));
    v
}

async fn send(tx: &mut SplitSink<WebSocket, Message>, v: Value) -> Result<()> {
    tx.send(Message::Text(serde_json::to_string(&v)?.into()))
        .await
        .context("send websocket message")
}
async fn close(
    tx: &mut SplitSink<WebSocket, Message>,
    code: u16,
    reason: &'static str,
) -> Result<()> {
    tx.send(Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    })))
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
    let Some(value) = h.get(header::ORIGIN) else {
        return Ok(None);
    };
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
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn prepare_staging(path: &std::path::Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    cleanup_staging(path)
}
fn cleanup_staging(path: &std::path::Path) -> Result<()> {
    for e in fs::read_dir(path)? {
        let p = e?.path();
        if p.extension().and_then(|x| x.to_str()) == Some("part") {
            fs::remove_file(p)?
        }
    }
    Ok(())
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
