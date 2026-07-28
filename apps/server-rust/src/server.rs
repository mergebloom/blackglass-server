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
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
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
const MAX_CONCURRENT_AUTH_CHECKS: usize = 4;
const AUTHENTICATION_DEADLINE: Duration = Duration::from_secs(5);
const SESSION_REVALIDATE_INTERVAL: Duration = Duration::from_secs(5);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

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
#[derive(Clone)]
struct Event {
    uid: i64,
    vault: String,
    text: String,
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
    shutdown: watch::Receiver<bool>,
    metrics: Arc<Metrics>,
}

pub async fn run(config: Config) -> Result<()> {
    prepare_staging(&config.staging_dir)?;
    let db = Db::open(&config.database_path)?;
    let (events, _) = broadcast::channel(1024);
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
        auth_checks: Arc::new(Semaphore::new(MAX_CONCURRENT_AUTH_CHECKS)),
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
        axum::serve(control_listener, control)
            .with_graceful_shutdown(async move {
                wait_for_shutdown(&mut cstop).await;
            })
            .await
    });
    let data_task = tokio::spawn(async move {
        axum::serve(data_listener, data)
            .with_graceful_shutdown(async move {
                wait_for_shutdown(&mut dstop).await;
            })
            .await
    });
    shutdown_signal().await;
    info!(event = "shutdown_requested");
    let _ = shutdown_tx.send(true);
    control_task.await??;
    data_task.await??;
    db_task(&state.db, |db| db.checkpoint()).await?;
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
    let ok = db_task(&s.db, |db| Ok(db.ready())).await.unwrap_or(false);
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
        authorized_control(&s, uri.path(), value).await
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
    let req: Signin =
        serde_json::from_value(v).map_err(|_| "Invalid email or password".to_string())?;
    let permit = match s.auth_checks.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
            warn!(event = "signin_capacity_reached");
            return Err("Try again later".into());
        }
    };
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
    let ttl = s.config.session_ttl.as_secs() as i64;
    let token = db_task(&s.db, move |db| db.issue_session(ttl))
        .await
        .map_err(internal)?;
    s.metrics.signins.fetch_add(1, Ordering::Relaxed);
    info!(event = "signin_succeeded");
    Ok(
        json!({"email":s.config.email,"name":s.config.display_name,"license":"selfhosted-sync","token":token}),
    )
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
    if !db_task(&s.db, move |db| Ok(db.valid_session(&validation_token)))
        .await
        .map_err(internal)?
    {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        return Err("Not logged in".into());
    }
    match path {
        "/user/signout" => {
            db_task(&s.db, move |db| db.revoke_session(&token))
                .await
                .map_err(internal)?;
            Ok(json!({}))
        }
        "/user/info" => Ok(
            json!({"email":s.config.email,"name":s.config.display_name,"license":"selfhosted-sync"}),
        ),
        "/subscription/list" => Ok(json!({"sync":true,"publish":false})),
        "/vault/regions" => {
            Ok(json!({"regions":[{"value":"selfhost","name":"Blackglass Server"}]}))
        }
        "/vault/list" => Ok(json!({
            "vaults":db_task(&s.db, |db| db.list_vaults()).await.map_err(internal)?,
            "shared":[],
            "limit":100
        })),
        "/vault/create" => create_vault(s, v).await,
        "/vault/access" => access_vault(s, v).await,
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
    let (keyhash, salt, password) = match (r.keyhash, r.salt) {
        (None, None) => {
            let (password, salt) = auth::new_managed_vault_credentials();
            (None, Some(salt), Some(password))
        }
        (Some(keyhash), Some(salt))
            if !keyhash.is_empty()
                && keyhash.len() <= 4096
                && !salt.is_empty()
                && salt.len() <= 4096 =>
        {
            (Some(keyhash), Some(salt), None)
        }
        _ => return Err("Invalid encryption credentials".into()),
    };
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
    db_task(&s.db, move |db| db.create_vault(&stored))
        .await
        .map_err(internal)?;
    serde_json::to_value(vault).map_err(internal)
}
async fn access_vault(s: &AppState, v: Value) -> std::result::Result<Value, String> {
    let r: VaultAccess =
        serde_json::from_value(v).map_err(|_| "Unable to access vault".to_string())?;
    let id = r.vault_uid.ok_or("Unable to access vault")?;
    let lookup_id = id.clone();
    let mut vault = db_task(&s.db, move |db| db.find_vault(&lookup_id))
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
        vault.keyhash = db_task(&s.db, move |db| {
            db.bind_managed_keyhash(&bind_id, &requested)
        })
        .await
        .map_err(internal)?;
    }
    if r.keyhash != vault.keyhash {
        return Err("Unable to access vault".into());
    }
    Ok(json!({}))
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
    if !db_task(&s.db, move |db| db.rename_vault(&id, &name))
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
    if !db_task(&s.db, move |db| db.delete_vault(&id))
        .await
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
    let permit = match s.connections.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    ws.max_frame_size(PIECE_SIZE as usize)
        .max_message_size(PIECE_SIZE as usize)
        .on_upgrade(move |socket| socket_loop(s, socket, permit))
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
                    if let Err(error) = handle_message(
                        &s,
                        &mut session,
                        &mut events,
                        &mut tx,
                        msg,
                    ).await {
                        warn!(event = "websocket_error", error = %error);
                        s.metrics.errors.fetch_add(1, Ordering::Relaxed);
                        break
                    }
                },
                _ => break,
            },
            event = events.recv() => match event {
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
                    let (size, vault_size) = db_task(&s.db, move |db| {
                        Ok((db.total_size()?, db.vault_size(&vault)?))
                    })
                    .await?;
                    send(tx,json!({"res":"ok","size":size,"limit":1099511627776i64,"vault_size":vault_size})).await?
                }
                "usernames" => send(tx, json!({"1":s.config.display_name})).await?,
                "push" => begin_push(s, session, events, tx, v).await?,
                "pull" => pull(s, session, tx, v).await?,
                "deleted" => {
                    let vault = session.vault.clone().unwrap();
                    let suppress = v.get("suppressrenames").and_then(Value::as_bool) == Some(true);
                    let items = db_task(&s.db, move |db| db.list_deleted(&vault, suppress))
                        .await?
                        .into_iter()
                        .map(notice_item)
                        .collect::<Vec<_>>();
                    send(tx, json!({"items":items})).await?
                }
                "history" => history(s, session, tx, v).await?,
                "restore" => restore(s, session, events, tx, v).await?,
                "purge" => {
                    let vault = session.vault.clone().unwrap();
                    let _commit = s.commit_order.lock().await;
                    db_task(&s.db, move |db| db.purge(&vault)).await?;
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
    let (vault, valid_session) = db_task(&s.db, move |db| {
        Ok((
            db.find_vault(&lookup_id)?,
            token.len() == 64 && db.valid_session_hash(&validation_hash),
        ))
    })
    .await?;
    let Some(vault) = vault else {
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    };
    let keyhash = v.get("keyhash").and_then(Value::as_str).map(str::to_owned);
    let enc = v.get("encryption_version").and_then(Value::as_i64);
    if !valid_session
        || keyhash.as_deref() != vault.keyhash.as_deref()
        || enc != Some(vault.encryption_version)
    {
        s.metrics.auth_failures.fetch_add(1, Ordering::Relaxed);
        send(tx, json!({"res":"err","msg":"Unable to authenticate"})).await?;
        return Ok(());
    }
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
    send(
        tx,
        json!({"res":"ok","userId":1,"perFileMax":s.config.per_file_max}),
    )
    .await?;
    let version = v.get("version").and_then(Value::as_i64).unwrap_or(0).max(0);
    let initial = v.get("initial").and_then(Value::as_bool).unwrap_or(false);
    let ready_version = {
        // Establish the replay/live boundary while commits are serialized. Replacing
        // the pre-auth receiver drops already-replayed events; every later commit is
        // then queued exactly once even when sending the replay is slow.
        let _commit = s.commit_order.lock().await;
        let vault_id = vault.id.clone();
        let ready_version = db_task(&s.db, move |db| db.current_version(&vault_id)).await?;
        *events = s.events.subscribe();
        ready_version
    };
    let mut cursor = if initial { 0 } else { version };
    loop {
        if shutting_down(s) {
            return Ok(());
        }
        if !session_active(s, session).await {
            return close(tx, 1008, "Session expired or revoked").await;
        }
        let vault_id = vault.id.clone();
        let page = db_task(&s.db, move |db| {
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
        let notice = {
            let _commit = s.commit_order.lock().await;
            let stored = db_task(&s.db, move |db| db.add_empty_revision(&revision)).await?;
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
    p.file.write_all(bytes).await?;
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
    let (notice, stored_size) = {
        let _commit = s.commit_order.lock().await;
        let stored =
            tokio::task::spawn_blocking(move || db.add_file_revision(&revision, &path)).await??;
        let stored_size = stored.size;
        (publish_committed(s, stored)?, stored_size)
    };
    let _ = tokio::fs::remove_file(&pending.path).await;
    s.metrics.uploads.fetch_add(1, Ordering::Relaxed);
    s.metrics
        .upload_bytes
        .fetch_add(stored_size as u64, Ordering::Relaxed);
    acknowledge_commit(s, session, events, tx, notice).await
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
    let Some(info) = db_task(&s.db, move |db| db.pull_info(uid)).await? else {
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
        let chunk = db_task(&s.db, move |db| db.content_chunk(uid, offset, len)).await?;
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
    let all = db_task(&s.db, move |db| db.history(&vault, &path, last, 101)).await?;
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
        db_task(&s.db, move |db| db.restore(&vault, uid, &device))
            .await?
            .map(|revision| publish_committed(s, revision))
            .transpose()?
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
    let event = Event { uid, vault, text };
    let _ = s.events.send(event.clone());
    Ok(event)
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
    socket_send(tx, Message::Text(serde_json::to_string(&v)?.into())).await
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

async fn db_task<T, F>(database: &Db, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(Db) -> Result<T> + Send + 'static,
{
    let database = database.clone();
    tokio::task::spawn_blocking(move || operation(database))
        .await
        .context("database worker stopped")?
}

async fn session_active(s: &AppState, session: &Session) -> bool {
    let Some(token_hash) = session.token_hash.clone() else {
        return false;
    };
    db_task(&s.db, move |db| Ok(db.valid_session_hash(&token_hash)))
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
