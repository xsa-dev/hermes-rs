//! HTTP route handlers for Hermes WebUI / Hermex API compatibility.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::error;

use super::models::*;
use super::stream::{
    agent_event_to_unsequenced_frames, ActiveStream, AgentRunner, MAX_CONCURRENT_RUNNING_STREAMS,
};
use crate::client::Message;

lazy_static::lazy_static! {
    static ref SESSION_ID_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_-]{1,64}$").unwrap();
}

pub const MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10MB

#[derive(Clone)]
pub struct WebUiState {
    pub session_dir: PathBuf,
    pub session_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
    pub active_streams: Arc<RwLock<HashMap<String, Arc<ActiveStream>>>>,
    pub auth_password: Option<String>,
    pub auth_token: Arc<RwLock<Option<String>>>,
    pub runtime_config: Arc<RwLock<crate::config::AppConfig>>,
    pub workspace_root: PathBuf,
    pub agent_runner: Arc<dyn AgentRunner>,
}

impl WebUiState {
    pub fn new(
        runtime_config: Arc<RwLock<crate::config::AppConfig>>,
        auth_password_raw: String,
        workspace_root: PathBuf,
    ) -> Self {
        let auth_password = if auth_password_raw.trim().is_empty() {
            None
        } else {
            Some(auth_password_raw.trim().to_string())
        };

        let session_dir = crate::platform::kerux_home().join("sessions");
        let runner = Arc::new(super::stream::LiveAgentRunner::new(runtime_config.clone()));

        Self {
            session_dir,
            session_locks: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            auth_password,
            auth_token: Arc::new(RwLock::new(None)),
            runtime_config,
            workspace_root,
            agent_runner: runner,
        }
    }

    pub fn with_runner_and_dir(
        runtime_config: Arc<RwLock<crate::config::AppConfig>>,
        auth_password: Option<String>,
        workspace_root: PathBuf,
        session_dir: PathBuf,
        runner: Arc<dyn AgentRunner>,
    ) -> Self {
        Self {
            session_dir,
            session_locks: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            auth_password,
            auth_token: Arc::new(RwLock::new(None)),
            runtime_config,
            workspace_root,
            agent_runner: runner,
        }
    }

    pub async fn get_session_lock(&self, session_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.session_locks.write().await;
        locks
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

pub fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// === Route Handlers ===

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

pub async fn auth_status_handler(
    State(state): State<WebUiState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let is_auth = if state.auth_password.is_none() {
        true
    } else {
        verify_auth_headers(&state, &headers).await
    };

    Json(AuthStatusResponse {
        authenticated: is_auth,
        profile: "default".to_string(),
        version: "0.4.0".to_string(),
    })
}

pub async fn login_handler(
    State(state): State<WebUiState>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let expected = match &state.auth_password {
        Some(p) => p,
        None => {
            let token = {
                let mut tok = state.auth_token.write().await;
                if tok.is_none() {
                    *tok = Some(generate_random_token());
                }
                tok.clone().unwrap()
            };
            let mut res = (
                StatusCode::OK,
                Json(LoginResponse {
                    status: "ok".to_string(),
                    token: token.clone(),
                }),
            )
                .into_response();
            let cookie = format!("hermes_auth={token}; HttpOnly; SameSite=Lax; Path=/");
            if let Ok(val) = cookie.parse() {
                res.headers_mut().insert(header::SET_COOKIE, val);
            }
            return res;
        }
    };

    let provided = req.password.unwrap_or_default();
    if constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        let token = {
            let mut tok = state.auth_token.write().await;
            let t = generate_random_token();
            *tok = Some(t.clone());
            t
        };

        let mut res = (
            StatusCode::OK,
            Json(LoginResponse {
                status: "ok".to_string(),
                token: token.clone(),
            }),
        )
            .into_response();
        let cookie = format!("hermes_auth={token}; HttpOnly; SameSite=Lax; Path=/");
        if let Ok(val) = cookie.parse() {
            res.headers_mut().insert(header::SET_COOKIE, val);
        }
        res
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid password".to_string(),
            }),
        )
            .into_response()
    }
}

pub async fn list_sessions_handler(State(state): State<WebUiState>) -> Response {
    if !state.session_dir.exists() {
        let _ = std::fs::create_dir_all(&state.session_dir);
    }

    let mut summaries = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.session_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(detail) = serde_json::from_str::<SessionDetailResponse>(&data) {
                        summaries.push(SessionSummary {
                            id: detail.id,
                            title: detail.title,
                            created_at: detail.created_at,
                            updated_at: detail.updated_at,
                            message_count: detail.messages.len(),
                        });
                    }
                }
            }
        }
    }

    summaries.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
    Json(SessionsListResponse {
        sessions: summaries,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct SessionQuery {
    pub session_id: String,
}

pub async fn get_session_handler(
    State(state): State<WebUiState>,
    Query(query): Query<SessionQuery>,
) -> Response {
    if !SESSION_ID_REGEX.is_match(&query.session_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session_id format".to_string(),
            }),
        )
            .into_response();
    }

    let lock = state.get_session_lock(&query.session_id).await;
    let _guard = lock.lock().await;

    let path = state.session_dir.join(format!("{}.json", query.session_id));
    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str::<SessionDetailResponse>(&data) {
            Ok(detail) => Json(detail).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("Failed to parse session file: {e}"),
                }),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to read session file: {e}"),
            }),
        )
            .into_response(),
    }
}

pub async fn new_session_handler(
    State(state): State<WebUiState>,
    Json(req): Json<NewSessionRequest>,
) -> Response {
    let id = format!("sess_{}", &generate_random_token()[..12]);
    let title = req.title.unwrap_or_else(|| "New Session".to_string());
    let now = now_epoch_secs();

    let detail = SessionDetailResponse {
        id: id.clone(),
        title: title.clone(),
        created_at: now,
        updated_at: now,
        messages: Vec::new(),
    };

    let lock = state.get_session_lock(&id).await;
    let _guard = lock.lock().await;

    let path = state.session_dir.join(format!("{id}.json"));
    if crate::persist::write_json(&path, &detail).is_ok() {
        return (StatusCode::OK, Json(NewSessionResponse { id, title })).into_response();
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "Failed to persist new session".to_string(),
        }),
    )
        .into_response()
}

pub async fn rename_session_handler(
    State(state): State<WebUiState>,
    Json(req): Json<RenameSessionRequest>,
) -> Response {
    if !SESSION_ID_REGEX.is_match(&req.session_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session_id format".to_string(),
            }),
        )
            .into_response();
    }

    let lock = state.get_session_lock(&req.session_id).await;
    let _guard = lock.lock().await;

    let path = state.session_dir.join(format!("{}.json", req.session_id));
    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(mut detail) = serde_json::from_str::<SessionDetailResponse>(&data) {
            detail.title = req.title;
            detail.updated_at = now_epoch_secs();
            if crate::persist::write_json(&path, &detail).is_ok() {
                return Json(StandardStatusResponse {
                    status: "ok".to_string(),
                })
                .into_response();
            }
        }
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "Failed to update session".to_string(),
        }),
    )
        .into_response()
}

pub async fn delete_session_handler(
    State(state): State<WebUiState>,
    Json(req): Json<DeleteSessionRequest>,
) -> Response {
    if !SESSION_ID_REGEX.is_match(&req.session_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session_id format".to_string(),
            }),
        )
            .into_response();
    }

    let lock = state.get_session_lock(&req.session_id).await;
    let _guard = lock.lock().await;

    let path = state.session_dir.join(format!("{}.json", req.session_id));
    if !path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Session not found".to_string(),
            }),
        )
            .into_response();
    }

    let _ = std::fs::remove_file(path);

    Json(StandardStatusResponse {
        status: "ok".to_string(),
    })
    .into_response()
}

pub async fn chat_start_handler(
    State(state): State<WebUiState>,
    Json(req): Json<ChatStartRequest>,
) -> Response {
    if !SESSION_ID_REGEX.is_match(&req.session_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid session_id format".to_string(),
            }),
        )
            .into_response();
    }

    let (steer_tx, steer_rx) = mpsc::channel(16);
    let (event_tx, mut event_rx) = mpsc::channel(64);

    // Atomic reservation of active stream slot under write lock
    let (stream_id, active_stream) = {
        let mut streams = state.active_streams.write().await;
        let running_count = streams
            .values()
            .filter(|s| s.is_running.load(Ordering::Relaxed))
            .count();
        if running_count >= MAX_CONCURRENT_RUNNING_STREAMS {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Active stream limit reached".to_string(),
                }),
            )
                .into_response();
        }

        let stream_id = format!("stream_{}", &generate_random_token()[..16]);
        let active_stream = Arc::new(ActiveStream::new(
            stream_id.clone(),
            req.session_id.clone(),
            steer_tx,
        ));
        streams.insert(stream_id.clone(), active_stream.clone());
        (stream_id, active_stream)
    };

    // Persist user message immediately under session lock
    let history = {
        let lock = state.get_session_lock(&req.session_id).await;
        let _guard = lock.lock().await;

        let path = state.session_dir.join(format!("{}.json", req.session_id));
        let mut detail = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|d| serde_json::from_str::<SessionDetailResponse>(&d).ok())
                .unwrap_or_else(|| SessionDetailResponse {
                    id: req.session_id.clone(),
                    title: "Session".to_string(),
                    created_at: now_epoch_secs(),
                    updated_at: now_epoch_secs(),
                    messages: Vec::new(),
                })
        } else {
            SessionDetailResponse {
                id: req.session_id.clone(),
                title: "Session".to_string(),
                created_at: now_epoch_secs(),
                updated_at: now_epoch_secs(),
                messages: Vec::new(),
            }
        };

        detail.messages.push(SessionMessageDto {
            role: "user".to_string(),
            content: req.message.clone(),
            timestamp: now_epoch_secs(),
        });
        detail.updated_at = now_epoch_secs();

        let _ = crate::persist::write_json(&path, &detail);

        detail
            .messages
            .iter()
            .map(|m| match m.role.as_str() {
                "user" => Message::user(&m.content),
                "system" => Message::system(&m.content),
                _ => Message::assistant(&m.content),
            })
            .collect::<Vec<_>>()
    };

    let runner = state.agent_runner.clone();
    let session_id_clone = req.session_id.clone();
    let user_msg = req.message.clone();
    let model_req = req.model.clone();
    let stream_clone = active_stream.clone();
    let state_clone = state.clone();

    tokio::spawn(async move {
        let stream_event_clone = stream_clone.clone();
        let event_pump = tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                for (evt, data) in agent_event_to_unsequenced_frames(&event) {
                    stream_event_clone.buffer_raw_frame(evt, data).await;
                }
            }
        });

        let outcome = runner
            .run_turn(
                &session_id_clone,
                &user_msg,
                model_req.as_deref(),
                history,
                event_tx,
                stream_clone.cancel_flag.clone(),
                steer_rx,
            )
            .await;

        let _ = event_pump.await;

        match outcome {
            Ok(content) => {
                let lock = state_clone.get_session_lock(&session_id_clone).await;
                let _guard = lock.lock().await;
                let path = state_clone
                    .session_dir
                    .join(format!("{session_id_clone}.json"));
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(mut detail) = serde_json::from_str::<SessionDetailResponse>(&data) {
                        detail.messages.push(SessionMessageDto {
                            role: "assistant".to_string(),
                            content,
                            timestamp: now_epoch_secs(),
                        });
                        detail.updated_at = now_epoch_secs();
                        let _ = crate::persist::write_json(&path, &detail);
                    }
                }
            }
            Err(e) => {
                error!("Agent turn failed: {e}");
                stream_clone
                    .buffer_raw_frame(
                        "error".to_string(),
                        serde_json::json!({ "error": e.to_string() }).to_string(),
                    )
                    .await;
            }
        }

        stream_clone.mark_completed().await;
    });

    (
        StatusCode::OK,
        Json(ChatStartResponse {
            stream_id,
            session_id: req.session_id,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct StreamQuery {
    pub stream_id: String,
}

pub async fn chat_stream_handler(
    State(state): State<WebUiState>,
    Query(query): Query<StreamQuery>,
) -> Response {
    let stream_opt = {
        let streams = state.active_streams.read().await;
        streams.get(&query.stream_id).cloned()
    };

    let stream = match stream_opt {
        Some(s) => {
            if s.is_expired().await {
                return (
                    StatusCode::NOT_FOUND,
                    Json(ErrorResponse {
                        error: "Stream not found or expired".to_string(),
                    }),
                )
                    .into_response();
            }
            s
        }
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Stream not found or expired".to_string(),
                }),
            )
                .into_response();
        }
    };

    let stream_events = async_stream::stream! {
        let mut last_seen_seq = 0;
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(5));
        heartbeat_interval.reset();

        loop {
            let frames = {
                let buf = stream.buffered_events.read().await;
                buf.iter()
                    .filter(|f| f.seq > last_seen_seq)
                    .cloned()
                    .collect::<Vec<_>>()
            };

            for frame in frames {
                if frame.seq > last_seen_seq {
                    last_seen_seq = frame.seq;
                }
                yield Ok::<Event, Infallible>(Event::default().event(frame.event).data(frame.data));
            }

            let is_running = stream.is_running.load(Ordering::Relaxed);
            if !is_running {
                let final_frames = {
                    let buf = stream.buffered_events.read().await;
                    buf.iter()
                        .filter(|f| f.seq > last_seen_seq)
                        .cloned()
                        .collect::<Vec<_>>()
                };
                for frame in final_frames {
                    if frame.seq > last_seen_seq {
                        last_seen_seq = frame.seq;
                    }
                    yield Ok::<Event, Infallible>(Event::default().event(frame.event).data(frame.data));
                }

                yield Ok::<Event, Infallible>(Event::default().event("streamEnd").data("{}"));
                break;
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                _ = heartbeat_interval.tick() => {
                    yield Ok::<Event, Infallible>(Event::default().event("heartbeat").data("{}"));
                }
            }
        }
    };

    Sse::new(stream_events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(5)))
        .into_response()
}

pub async fn chat_cancel_handler(
    State(state): State<WebUiState>,
    Json(req): Json<ChatCancelRequest>,
) -> Response {
    let streams = state.active_streams.read().await;
    if let Some(stream) = streams.get(&req.stream_id) {
        stream.cancel_flag.store(true, Ordering::SeqCst);
        stream
            .buffer_raw_frame("cancelled".to_string(), "{}".to_string())
            .await;
        stream.mark_completed().await;
        return Json(StandardStatusResponse {
            status: "cancelled".to_string(),
        })
        .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Stream not found".to_string(),
        }),
    )
        .into_response()
}

pub async fn chat_steer_handler(
    State(state): State<WebUiState>,
    Json(req): Json<ChatSteerRequest>,
) -> Response {
    let streams = state.active_streams.read().await;
    if let Some(stream) = streams.get(&req.stream_id) {
        if stream.is_running.load(Ordering::Relaxed)
            && stream.steer_tx.send(req.message).await.is_ok()
        {
            return Json(StandardStatusResponse {
                status: "ok".to_string(),
            })
            .into_response();
        }
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Stream is not active".to_string(),
            }),
        )
            .into_response();
    }

    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "Stream not found".to_string(),
        }),
    )
        .into_response()
}

pub async fn workspaces_handler(State(state): State<WebUiState>) -> impl IntoResponse {
    Json(WorkspacesResponse {
        workspaces: vec![WorkspaceItem {
            path: state.workspace_root.to_string_lossy().to_string(),
            name: "workspace".to_string(),
            active: true,
        }],
    })
}

#[derive(Deserialize)]
pub struct PathQuery {
    pub path: Option<String>,
}

pub async fn list_directory_handler(
    State(state): State<WebUiState>,
    Query(query): Query<PathQuery>,
) -> Response {
    let sub = query.path.unwrap_or_default();
    let target = state.workspace_root.join(sub);

    let canonical = match dunce_canonicalize(&target) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Directory not found".to_string(),
                }),
            )
                .into_response()
        }
    };

    let ws_canonical = match dunce_canonicalize(&state.workspace_root) {
        Ok(c) => c,
        Err(_) => state.workspace_root.clone(),
    };

    if canonical.strip_prefix(&ws_canonical).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied: Path escapes workspace root".to_string(),
            }),
        )
            .into_response();
    }

    let mut items = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&canonical) {
        for entry in entries.flatten() {
            let p = entry.path();
            let is_dir = p.is_dir();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let name = entry.file_name().to_string_lossy().to_string();
            let rel_path = p
                .strip_prefix(&ws_canonical)
                .unwrap_or(&p)
                .to_string_lossy()
                .to_string();
            items.push(DirectoryEntryDto {
                name,
                path: rel_path,
                is_dir,
                size,
            });
        }
    }

    items.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    Json(DirectoryListResponse { items }).into_response()
}

pub async fn read_file_handler(
    State(state): State<WebUiState>,
    Query(query): Query<PathQuery>,
) -> Response {
    let sub = match query.path {
        Some(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Missing path parameter".to_string(),
                }),
            )
                .into_response()
        }
    };

    let target = state.workspace_root.join(&sub);
    let canonical = match dunce_canonicalize(&target) {
        Ok(c) => c,
        Err(_) => {
            if sub.contains("..") {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ErrorResponse {
                        error: "Access denied: Path escapes workspace root".to_string(),
                    }),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "File not found".to_string(),
                }),
            )
                .into_response();
        }
    };

    let ws_canonical = match dunce_canonicalize(&state.workspace_root) {
        Ok(c) => c,
        Err(_) => state.workspace_root.clone(),
    };

    if canonical.strip_prefix(&ws_canonical).is_err() {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Access denied: Path escapes workspace root".to_string(),
            }),
        )
            .into_response();
    }

    if let Ok(meta) = std::fs::metadata(&canonical) {
        if meta.len() > MAX_FILE_SIZE_BYTES {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorResponse {
                    error: "File size exceeds 10MB limit".to_string(),
                }),
            )
                .into_response();
        }
    }

    match std::fs::read_to_string(&canonical) {
        Ok(content) => Json(FileContentResponse { path: sub, content }).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("Failed to read file: {e}"),
            }),
        )
            .into_response(),
    }
}

pub async fn models_handler(State(state): State<WebUiState>) -> impl IntoResponse {
    let cfg = state.runtime_config.read().await;
    let main_model = cfg.agent.model.clone();
    let provider = cfg.client.provider.clone();

    let mut models = vec![ModelItem {
        id: main_model.clone(),
        name: main_model.clone(),
        provider,
    }];

    for fb in &cfg.client.fallback {
        if let Some(ref m) = fb.model {
            models.push(ModelItem {
                id: m.clone(),
                name: m.clone(),
                provider: fb.provider.clone(),
            });
        }
    }

    Json(ModelsResponse {
        models,
        default: main_model,
    })
}

pub async fn default_model_handler(State(state): State<WebUiState>) -> impl IntoResponse {
    let cfg = state.runtime_config.read().await;
    Json(DefaultModelResponse {
        model: cfg.agent.model.clone(),
    })
}

pub async fn settings_handler(State(state): State<WebUiState>) -> impl IntoResponse {
    Json(SettingsResponse {
        version: "0.4.0".to_string(),
        webui: WebUiSettingsDto {
            auth_enabled: state.auth_password.is_some(),
        },
    })
}

// Helpers
fn dunce_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path)
}

pub async fn verify_auth_headers(state: &WebUiState, headers: &HeaderMap) -> bool {
    let current_token = state.auth_token.read().await.clone();
    let Some(valid_token) = current_token else {
        return false;
    };

    if let Some(auth_header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    {
        if let Some(bearer) = auth_header.strip_prefix("Bearer ") {
            if constant_time_eq(bearer.trim().as_bytes(), valid_token.as_bytes()) {
                return true;
            }
        }
    }

    if let Some(cookie_header) = headers.get(header::COOKIE).and_then(|h| h.to_str().ok()) {
        for cookie in cookie_header.split(';') {
            let cookie = cookie.trim();
            if let Some(val) = cookie.strip_prefix("hermes_auth=") {
                if constant_time_eq(val.trim().as_bytes(), valid_token.as_bytes()) {
                    return true;
                }
            }
        }
    }

    false
}
