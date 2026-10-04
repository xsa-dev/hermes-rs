//! SSE stream converter, replay buffer, and AgentRunner abstraction.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

use crate::agent::AgentEvent;
use crate::client::Message;
use crate::error::Result;

pub const MAX_EVENTS_PER_STREAM: usize = 100;
pub const MAX_CHUNK_SIZE_BYTES: usize = 64 * 1024;
pub const STREAM_REPLAY_TTL: Duration = Duration::from_secs(300); // 5 minutes
pub const MAX_CONCURRENT_RUNNING_STREAMS: usize = 32;

/// A wire frame representing an SSE event name, payload, and monotonic sequence ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseWireFrame {
    pub seq: usize,
    pub event: String,
    pub data: String,
}

/// Pluggable AgentRunner trait allowing live agent execution or mock offline runners.
#[async_trait::async_trait]
pub trait AgentRunner: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn run_turn(
        &self,
        session_id: &str,
        user_message: &str,
        model: Option<&str>,
        history: Vec<Message>,
        event_tx: mpsc::Sender<AgentEvent>,
        cancel: Arc<AtomicBool>,
        steer_rx: mpsc::Receiver<String>,
    ) -> Result<String>;
}

/// Default LiveAgentRunner that connects to configured LLM providers and executes tools.
pub struct LiveAgentRunner {
    config: Arc<RwLock<crate::config::AppConfig>>,
}

impl LiveAgentRunner {
    pub fn new(config: Arc<RwLock<crate::config::AppConfig>>) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl AgentRunner for LiveAgentRunner {
    async fn run_turn(
        &self,
        _session_id: &str,
        user_message: &str,
        model_override: Option<&str>,
        history: Vec<Message>,
        event_tx: mpsc::Sender<AgentEvent>,
        cancel: Arc<AtomicBool>,
        mut steer_rx: mpsc::Receiver<String>,
    ) -> Result<String> {
        let mut cfg = self.config.read().await.clone();
        if let Some(m) = model_override {
            cfg.agent.model = m.to_string();
        }

        let provider = crate::client::build_provider_client(&cfg.client)?;
        let tools =
            crate::tools::ToolRegistry::new(Duration::from_secs(cfg.agent.tool_timeout_secs));

        let agent_config = crate::agent::AgentConfig::from(&cfg.agent);
        let agent = crate::agent::KeruxAgent::with_provider_events(
            agent_config,
            provider,
            tools,
            event_tx.clone(),
        );

        // Populate history
        for msg in history {
            agent.add_message(msg).await;
        }

        // Spawn background task to observe steering messages
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            while let Some(_steer_msg) = steer_rx.recv().await {
                if cancel_clone.load(Ordering::Relaxed) {
                    break;
                }
            }
        });

        let response = agent
            .run_with_cancel(user_message.to_string(), cancel)
            .await?;
        Ok(response.content)
    }
}

/// Deterministic mock agent runner for offline unit and integration tests.
pub struct MockAgentRunner {
    scripted_events: Vec<AgentEvent>,
    scripted_response: String,
}

impl MockAgentRunner {
    pub fn new(scripted_events: Vec<AgentEvent>, scripted_response: String) -> Self {
        Self {
            scripted_events,
            scripted_response,
        }
    }
}

#[async_trait::async_trait]
impl AgentRunner for MockAgentRunner {
    async fn run_turn(
        &self,
        _session_id: &str,
        _user_message: &str,
        _model: Option<&str>,
        _history: Vec<Message>,
        event_tx: mpsc::Sender<AgentEvent>,
        cancel: Arc<AtomicBool>,
        mut steer_rx: mpsc::Receiver<String>,
    ) -> Result<String> {
        for event in &self.scripted_events {
            if cancel.load(Ordering::Relaxed) {
                return Err(crate::error::Error::Cancelled);
            }
            let _ = event_tx.send(event.clone()).await;
            tokio::task::yield_now().await;
        }

        while let Ok(_steer) = steer_rx.try_recv() {}

        if cancel.load(Ordering::Relaxed) {
            return Err(crate::error::Error::Cancelled);
        }

        Ok(self.scripted_response.clone())
    }
}

/// Represents an active or recently completed stream.
pub struct ActiveStream {
    pub stream_id: String,
    pub session_id: String,
    pub cancel_flag: Arc<AtomicBool>,
    pub steer_tx: mpsc::Sender<String>,
    pub is_running: Arc<AtomicBool>,
    pub created_at: Instant,
    pub completed_at: Arc<RwLock<Option<Instant>>>,
    pub next_seq: Arc<AtomicUsize>,
    pub buffered_events: Arc<RwLock<Vec<SseWireFrame>>>,
}

impl ActiveStream {
    pub fn new(stream_id: String, session_id: String, steer_tx: mpsc::Sender<String>) -> Self {
        Self {
            stream_id,
            session_id,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            steer_tx,
            is_running: Arc::new(AtomicBool::new(true)),
            created_at: Instant::now(),
            completed_at: Arc::new(RwLock::new(None)),
            next_seq: Arc::new(AtomicUsize::new(1)),
            buffered_events: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn buffer_raw_frame(&self, event: String, data: String) {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let frame = SseWireFrame { seq, event, data };
        let mut buffer = self.buffered_events.write().await;
        if buffer.len() >= MAX_EVENTS_PER_STREAM {
            buffer.remove(0);
        }
        buffer.push(frame);
    }

    pub async fn mark_completed(&self) {
        self.is_running.store(false, Ordering::SeqCst);
        let mut comp = self.completed_at.write().await;
        if comp.is_none() {
            *comp = Some(Instant::now());
        }
    }

    pub async fn is_expired(&self) -> bool {
        if self.is_running.load(Ordering::Relaxed) {
            return false;
        }
        let comp = self.completed_at.read().await;
        if let Some(t) = *comp {
            t.elapsed() > STREAM_REPLAY_TTL
        } else {
            false
        }
    }
}

/// Splits text safely along UTF-8 char boundaries without corrupting multi-byte codepoints.
pub fn split_utf8_safe(text: &str, max_bytes: usize) -> Vec<String> {
    if text.len() <= max_bytes {
        return vec![text.to_string()];
    }

    let mut result = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let target_end = (start + max_bytes).min(text.len());
        let mut end = target_end;
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            end = target_end + 1;
            while end < text.len() && !text.is_char_boundary(end) {
                end += 1;
            }
        }
        result.push(text[start..end].to_string());
        start = end;
    }
    result
}

pub fn agent_event_to_unsequenced_frames(event: &AgentEvent) -> Vec<(String, String)> {
    match event {
        AgentEvent::Content { text } => split_utf8_safe(text, MAX_CHUNK_SIZE_BYTES)
            .into_iter()
            .map(|chunk| {
                (
                    "token".to_string(),
                    serde_json::json!({ "content": chunk }).to_string(),
                )
            })
            .collect(),
        AgentEvent::Reasoning { text } => {
            vec![(
                "reasoning".to_string(),
                serde_json::json!({ "content": text }).to_string(),
            )]
        }
        AgentEvent::Thinking { content } => {
            vec![(
                "reasoning".to_string(),
                serde_json::json!({ "content": content }).to_string(),
            )]
        }
        AgentEvent::ToolStart {
            call_id,
            name,
            arguments,
        } => {
            let args_val: serde_json::Value =
                serde_json::from_str(arguments).unwrap_or_else(|_| serde_json::json!(arguments));
            vec![(
                "toolStarted".to_string(),
                serde_json::json!({
                    "id": call_id,
                    "name": name,
                    "arguments": args_val,
                })
                .to_string(),
            )]
        }
        AgentEvent::ToolComplete { result } => {
            vec![(
                "toolCompleted".to_string(),
                serde_json::json!({
                    "id": result.tool_call_id,
                    "success": result.success,
                    "content": result.content,
                })
                .to_string(),
            )]
        }
        AgentEvent::ToolError { name, error } => {
            vec![(
                "toolCompleted".to_string(),
                serde_json::json!({
                    "id": name,
                    "success": false,
                    "error": error,
                })
                .to_string(),
            )]
        }
        AgentEvent::Telemetry { telemetry } => {
            vec![(
                "metering".to_string(),
                serde_json::json!({
                    "prompt_tokens": telemetry.prompt_tokens,
                    "completion_tokens": telemetry.completion_tokens,
                    "total_tokens": telemetry.total_tokens,
                })
                .to_string(),
            )]
        }
        AgentEvent::Error { error } => {
            vec![(
                "error".to_string(),
                serde_json::json!({ "error": error }).to_string(),
            )]
        }
        AgentEvent::Done { message } => {
            vec![(
                "done".to_string(),
                serde_json::json!({ "message": message.content }).to_string(),
            )]
        }
        _ => Vec::new(),
    }
}
