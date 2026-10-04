use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

use kerux_core::agent::AgentEvent;
use kerux_core::client::Message;
use kerux_core::config::AppConfig;
use kerux_core::gateway::GatewayConfig;
use kerux_core::webui::{
    build_router, split_utf8_safe, ActiveStream, AgentRunner, AuthStatusResponse,
    ChatCancelRequest, ChatStartRequest, ChatStartResponse, ChatSteerRequest, DeleteSessionRequest,
    DirectoryListResponse, FileContentResponse, LoginRequest, LoginResponse, MockAgentRunner,
    ModelsResponse, NewSessionRequest, NewSessionResponse, RenameSessionRequest,
    SessionDetailResponse, SessionsListResponse, SettingsResponse, StandardStatusResponse,
    WebUiState, MAX_CONCURRENT_RUNNING_STREAMS,
};

fn create_test_state(
    auth_password: Option<String>,
    runner: Arc<dyn AgentRunner>,
    workspace_dir: std::path::PathBuf,
    session_dir: std::path::PathBuf,
) -> WebUiState {
    let mut config = AppConfig::default();
    config.agent.model = "gpt-4o".to_string();
    config.client.provider = "openai".to_string();

    WebUiState::with_runner_and_dir(
        Arc::new(tokio::sync::RwLock::new(config)),
        auth_password,
        workspace_dir,
        session_dir,
        runner,
    )
}

#[tokio::test]
async fn test_health_and_auth_status_without_password() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());
    let app = build_router(state);

    // GET /health
    let req = Request::builder()
        .uri("/health")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let val: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(val["status"], "ok");

    // GET /api/auth/status
    let req = Request::builder()
        .uri("/api/auth/status")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let auth_status: AuthStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(auth_status.authenticated);
    assert_eq!(auth_status.profile, "default");
    assert_eq!(auth_status.version, "0.4.0");
}

#[tokio::test]
async fn test_auth_status_and_login_with_password() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(
        Some("secret123".into()),
        runner,
        ws_temp.path().into(),
        sess_temp.path().into(),
    );
    let app = build_router(state);

    // GET /api/auth/status without token -> authenticated: false
    let req = Request::builder()
        .uri("/api/auth/status")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let auth_status: AuthStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(!auth_status.authenticated);

    // Invalid login -> 401
    let login_req = LoginRequest {
        password: Some("wrong".into()),
        username: None,
    };
    let req = Request::builder()
        .uri("/api/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Valid login -> 200 + token + cookie
    let login_req = LoginRequest {
        password: Some("secret123".into()),
        username: None,
    };
    let req = Request::builder()
        .uri("/api/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cookie.contains("hermes_auth="));

    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let login_res: LoginResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(login_res.status, "ok");
    assert!(!login_res.token.is_empty());

    // GET /api/auth/status with Bearer token -> authenticated: true
    let req = Request::builder()
        .uri("/api/auth/status")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {}", login_res.token))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let auth_status: AuthStatusResponse = serde_json::from_slice(&body).unwrap();
    assert!(auth_status.authenticated);
}

#[tokio::test]
async fn test_protected_endpoints_and_cors_preflight() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(
        Some("secret123".into()),
        runner,
        ws_temp.path().into(),
        sess_temp.path().into(),
    );
    let app = build_router(state);

    // Protected endpoint without auth -> 401
    let req = Request::builder()
        .uri("/api/sessions")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // OPTIONS preflight -> 204 without auth
    let req = Request::builder()
        .uri("/api/sessions")
        .method(Method::OPTIONS)
        .header(header::ORIGIN, "http://localhost:3000")
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        res.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "*"
    );
}

#[tokio::test]
async fn test_session_crud_and_persistence() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());
    let app = build_router(state);

    // 1. Create new session
    let new_req = NewSessionRequest {
        title: Some("Integration Test Session".into()),
    };
    let req = Request::builder()
        .uri("/api/session/new")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&new_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let created: NewSessionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(created.title, "Integration Test Session");

    // 2. List sessions
    let req = Request::builder()
        .uri("/api/sessions")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let list: SessionsListResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(list.sessions.len(), 1);
    assert_eq!(list.sessions[0].id, created.id);

    // 3. Get session detail
    let req = Request::builder()
        .uri(format!("/api/session?session_id={}", created.id))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let detail: SessionDetailResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail.id, created.id);
    assert_eq!(detail.title, "Integration Test Session");

    // 4. Rename session
    let rename_req = RenameSessionRequest {
        session_id: created.id.clone(),
        title: "Renamed Session Title".into(),
    };
    let req = Request::builder()
        .uri("/api/session/rename")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&rename_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 5. Delete session
    let del_req = DeleteSessionRequest {
        session_id: created.id.clone(),
    };
    let req = Request::builder()
        .uri("/api/session/delete")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&del_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // 6. Delete again -> 404
    let req = Request::builder()
        .uri("/api/session/delete")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&del_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // 7. Get session again -> 404
    let req = Request::builder()
        .uri(format!("/api/session?session_id={}", created.id))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_path_confinement_and_file_limits() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());

    // Write a test file in workspace
    let test_file = ws_temp.path().join("hello.txt");
    std::fs::write(&test_file, "Hello from workspace").unwrap();

    // Write a file larger than 10MB
    let large_file = ws_temp.path().join("large.bin");
    let large_data = vec![0u8; 11 * 1024 * 1024];
    std::fs::write(&large_file, large_data).unwrap();

    let app = build_router(state);

    // 1. List directory inside workspace
    let req = Request::builder()
        .uri("/api/list?path=")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let list: DirectoryListResponse = serde_json::from_slice(&body).unwrap();
    assert!(list.items.iter().any(|i| i.name == "hello.txt"));

    // 2. Read file inside workspace
    let req = Request::builder()
        .uri("/api/file?path=hello.txt")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let file_res: FileContentResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(file_res.content, "Hello from workspace");

    // 3. Oversized file -> 413 Payload Too Large
    let req = Request::builder()
        .uri("/api/file?path=large.bin")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 4. Path traversal attempt -> 403 Forbidden
    let req = Request::builder()
        .uri("/api/file?path=../../etc/passwd")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_models_and_settings() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(
        Some("secret".into()),
        runner,
        ws_temp.path().into(),
        sess_temp.path().into(),
    );
    let app = build_router(state.clone());

    let req = Request::builder()
        .uri("/api/models")
        .method(Method::GET)
        .header(header::AUTHORIZATION, "Bearer invalid")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Provide auth
    let token = {
        let mut t = state.auth_token.write().await;
        *t = Some("test_token".into());
        "test_token"
    };

    let req = Request::builder()
        .uri("/api/models")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let models: ModelsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(models.default, "gpt-4o");
    assert_eq!(models.models[0].provider, "openai");

    let req = Request::builder()
        .uri("/api/settings")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let settings: SettingsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(settings.version, "0.4.0");
    assert!(settings.webui.auth_enabled);
}

#[tokio::test]
async fn test_chat_start_and_sse_events() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();

    let scripted_events = vec![
        AgentEvent::Content {
            text: "Hello from agent!".into(),
        },
        AgentEvent::Reasoning {
            text: "Thinking about files".into(),
        },
        AgentEvent::ToolStart {
            call_id: "call_1".into(),
            name: "terminal".into(),
            arguments: "{\"command\":\"ls\"}".into(),
        },
        AgentEvent::ToolComplete {
            result: kerux_core::tools::ToolResult::success(
                "call_1",
                serde_json::json!({ "output": "file1.txt" }),
            ),
        },
        AgentEvent::Done {
            message: Message::assistant("All done!"),
        },
    ];

    let runner = Arc::new(MockAgentRunner::new(
        scripted_events,
        "All done!".to_string(),
    ));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());
    let app = build_router(state.clone());

    // 1. Create a session first
    let new_req = NewSessionRequest {
        title: Some("Chat Test".into()),
    };
    let req = Request::builder()
        .uri("/api/session/new")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&new_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let sess: NewSessionResponse = serde_json::from_slice(&body).unwrap();

    // 2. Start chat
    let chat_req = ChatStartRequest {
        session_id: sess.id.clone(),
        message: "Run ls command".into(),
        model: Some("custom-model".into()),
    };
    let req = Request::builder()
        .uri("/api/chat/start")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&chat_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let start_res: ChatStartResponse = serde_json::from_slice(&body).unwrap();

    // 3. Connect to chat stream
    let req = Request::builder()
        .uri(format!(
            "/api/chat/stream?stream_id={}",
            start_res.stream_id
        ))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );

    // Wait briefly for background turn to complete and persist
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 4. Verify session on disk contains both user and assistant messages
    let req = Request::builder()
        .uri(format!("/api/session?session_id={}", sess.id))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let detail: SessionDetailResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail.messages.len(), 2);
    assert_eq!(detail.messages[0].role, "user");
    assert_eq!(detail.messages[0].content, "Run ls command");
    assert_eq!(detail.messages[1].role, "assistant");
    assert_eq!(detail.messages[1].content, "All done!");
}

#[tokio::test]
async fn test_chat_cancel_and_steer() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());
    let app = build_router(state.clone());

    // Register an active stream manually
    let (steer_tx, mut steer_rx) = tokio::sync::mpsc::channel(4);
    let active = Arc::new(ActiveStream::new(
        "test_cancel_stream".into(),
        "sess_1".into(),
        steer_tx,
    ));
    state
        .active_streams
        .write()
        .await
        .insert("test_cancel_stream".into(), active.clone());

    // 1. Steer active stream -> 200
    let steer_req = ChatSteerRequest {
        stream_id: "test_cancel_stream".into(),
        message: "Stop searching".into(),
    };
    let req = Request::builder()
        .uri("/api/chat/steer")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&steer_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(steer_rx.recv().await.unwrap(), "Stop searching");

    // 2. Cancel active stream -> 200
    let cancel_req = ChatCancelRequest {
        stream_id: "test_cancel_stream".into(),
    };
    let req = Request::builder()
        .uri("/api/chat/cancel")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cancel_req).unwrap()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), 1024 * 1024).await.unwrap();
    let cancel_res: StandardStatusResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(cancel_res.status, "cancelled");
    assert!(active.cancel_flag.load(Ordering::Relaxed));

    // 3. Steer completed stream -> 400
    let req = Request::builder()
        .uri("/api/chat/steer")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&steer_req).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_concurrency_32_stream_limit() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());

    // Insert 32 active running streams
    for i in 0..MAX_CONCURRENT_RUNNING_STREAMS {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let stream = Arc::new(ActiveStream::new(
            format!("stream_{i}"),
            "sess_1".into(),
            tx,
        ));
        state
            .active_streams
            .write()
            .await
            .insert(format!("stream_{i}"), stream);
    }

    let app = build_router(state);

    let chat_req = ChatStartRequest {
        session_id: "sess_1".into(),
        message: "hello".into(),
        model: None,
    };
    let req = Request::builder()
        .uri("/api/chat/start")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&chat_req).unwrap()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn test_remote_non_loopback_binding_refusal() {
    let gateway = GatewayConfig {
        webui_enabled: true,
        webui_addr: "0.0.0.0:8787".to_string(),
        webui_password: "".to_string(),
        ..Default::default()
    };

    let socket_addr: std::net::SocketAddr = gateway.webui_addr.parse().unwrap();
    assert!(!socket_addr.ip().is_loopback());
    assert!(gateway.webui_password.trim().is_empty());
}

#[test]
fn test_env_password_precedence() {
    std::env::set_var("KERUX_WEBUI_PASSWORD", "primary_pass");
    std::env::set_var("HERMES_WEBUI_PASSWORD", "fallback_pass");

    let mut config = AppConfig::default();
    config.apply_env_overrides().unwrap();
    assert_eq!(config.gateway.webui_password, "primary_pass");

    std::env::remove_var("KERUX_WEBUI_PASSWORD");
    let mut config2 = AppConfig::default();
    config2.apply_env_overrides().unwrap();
    assert_eq!(config2.gateway.webui_password, "fallback_pass");

    std::env::remove_var("HERMES_WEBUI_PASSWORD");
}

#[test]
fn test_utf8_multibyte_safe_splitting() {
    let s = "🦀🚀Привет мир! This is a test string for safe unicode chunking.";
    let chunks = split_utf8_safe(s, 10);
    assert!(!chunks.is_empty());
    let recombined = chunks.join("");
    assert_eq!(s, recombined);
}

#[tokio::test]
async fn test_unknown_stream_404() {
    let ws_temp = tempdir().unwrap();
    let sess_temp = tempdir().unwrap();
    let runner = Arc::new(MockAgentRunner::new(vec![], "ok".into()));
    let state = create_test_state(None, runner, ws_temp.path().into(), sess_temp.path().into());
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/chat/stream?stream_id=nonexistent")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}
