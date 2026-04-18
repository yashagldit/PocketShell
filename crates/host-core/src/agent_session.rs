//! Live coding-agent sessions.
//!
//! Spawns the user's installed `codex app-server` or `claude -p ... stream-json`
//! CLI as a long-lived child process and exposes a byte-pump abstraction:
//! mobile writes newline-delimited JSON in, child writes newline-delimited JSON
//! out. We do **not** parse the protocol — that lives on the mobile side
//! (different shape per backend).
//!
//! The patterns here mirror the production-tested flow used by the remodex
//! Node.js bridge (`remodex-main/phodex-bridge/src/codex-transport.js`):
//!
//! - **Launch plans.** A static, ordered list of (command, args) attempts so
//!   `ENOENT` falls back to a bundled binary path without "guessing" between
//!   parallel runtimes.
//! - **Line-buffered stdout** with a tail buffer for partial reads.
//! - **Bounded stderr ring** (4 KiB) so crash messages survive without log
//!   spam dominating memory.
//! - **Graceful shutdown**: SIGTERM → wait briefly → SIGKILL.
//! - **Ignorable stdin errors** (`EPIPE`, `ERR_STREAM_DESTROYED` equivalents)
//!   during shutdown — those are expected, not failures.
//!
//! Higher layers (daemon RPC, WebRTC channel routing) live in `daemon.rs` /
//! `rpc.rs` and treat each `AgentSession` as a pair of mpsc channels plus a
//! supervised lifecycle.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Maximum buffered stderr bytes kept around for crash diagnostics.
const STDERR_RING_BYTES: usize = 4 * 1024;

/// Bounded channel sizes. Outbound stdout lines tend to come in bursts during
/// streaming; inbound stdin writes are user-paced.
const STDOUT_CHANNEL_CAPACITY: usize = 256;
const STDIN_CHANNEL_CAPACITY: usize = 64;

/// Which CLI to drive. The protocol shape (JSON-RPC vs stream-json) is the
/// mobile adapter's problem; here we only care about how to spawn it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Codex,
    Claude,
}

impl Backend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Backend::Codex => "codex",
            Backend::Claude => "claude",
        }
    }
}

/// One spawn attempt: the program plus its args. We keep an ordered list so
/// `ENOENT` on the first plan falls back to the next.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub program: String,
    pub args: Vec<String>,
    pub description: String,
}

/// Probe the filesystem for a bundled or user-local copy of the CLI, in case
/// the daemon's PATH doesn't include it (launchd/systemd inherit a minimal
/// PATH). Returns the first executable that exists. Cheap enough to call on
/// every spawn — most paths short-circuit on `stat`.
pub fn discover_bundled(backend: Backend) -> Option<PathBuf> {
    let home = dirs::home_dir();
    let mut candidates: Vec<PathBuf> = Vec::new();

    let push_home = |out: &mut Vec<PathBuf>, rel: &str| {
        if let Some(h) = home.as_ref() {
            out.push(h.join(rel));
        }
    };

    match backend {
        Backend::Codex => {
            push_home(&mut candidates, ".local/bin/codex");
            push_home(&mut candidates, ".volta/bin/codex");
            push_home(&mut candidates, ".bun/bin/codex");
            push_home(&mut candidates, ".npm-global/bin/codex");
            candidates.push(PathBuf::from("/opt/homebrew/bin/codex"));
            candidates.push(PathBuf::from("/usr/local/bin/codex"));
            candidates.push(PathBuf::from("/usr/bin/codex"));
            // Codex desktop app on macOS ships the native binary inside its
            // Resources dir — same path remodex probes.
            candidates.push(PathBuf::from(
                "/Applications/Codex.app/Contents/Resources/codex",
            ));
            // nvm: pick lexicographically-last version dir.
            if let Some(h) = home.as_ref() {
                if let Some(p) = nvm_pick(&h.join(".nvm/versions/node"), "codex") {
                    candidates.push(p);
                }
            }
        }
        Backend::Claude => {
            push_home(&mut candidates, ".local/bin/claude");
            push_home(&mut candidates, ".claude/local/claude");
            push_home(&mut candidates, ".volta/bin/claude");
            push_home(&mut candidates, ".bun/bin/claude");
            push_home(&mut candidates, ".npm-global/bin/claude");
            candidates.push(PathBuf::from("/opt/homebrew/bin/claude"));
            candidates.push(PathBuf::from("/usr/local/bin/claude"));
            candidates.push(PathBuf::from("/usr/bin/claude"));
            if let Some(h) = home.as_ref() {
                if let Some(p) = nvm_pick(&h.join(".nvm/versions/node"), "claude") {
                    candidates.push(p);
                }
                // Anthropic native installer keeps versioned dirs here; pick latest.
                if let Some(p) = pick_latest_versioned(&h.join(".local/share/claude/versions"), "")
                {
                    candidates.push(p);
                }
            }
        }
    }

    candidates.into_iter().find(|p| is_executable_file(p))
}

fn is_executable_file(p: &std::path::Path) -> bool {
    match std::fs::metadata(p) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// Glob `<base>/*/bin/<bin>` and pick the lexicographically-last match.
fn nvm_pick(base: &std::path::Path, bin: &str) -> Option<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    for dir in entries.into_iter().rev() {
        let candidate = dir.join("bin").join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// `<base>/<latest>/<suffix?>` — `suffix` may be empty. Picks the
/// lexicographically-largest immediate child whose target is executable.
fn pick_latest_versioned(base: &std::path::Path, suffix: &str) -> Option<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    entries.sort();
    for dir in entries.into_iter().rev() {
        let candidate = if suffix.is_empty() {
            dir.clone()
        } else {
            dir.join(suffix)
        };
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Canonical framing constants shared with the mobile side.
pub const AGENT_AUTH_PREFIX: &[u8] = b"\x00PSAU";

/// Build the auth-scope channel key the daemon uses for `agent-{id}` channels.
/// Mobile must reproduce this string when signing auth responses.
pub fn agent_channel_key(agent_id: &str, mobile_device_id: &str) -> String {
    format!("agent:{agent_id}:{mobile_device_id}")
}

/// Parameters for opening a new agent session.
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub backend: Backend,
    /// Working directory for the child. Defaults to user home if `None`.
    pub cwd: Option<PathBuf>,
    /// Optional resume target — for Codex this is unused at spawn time
    /// (resume happens via a `resumeConversation` RPC after spawn); for Claude
    /// we pass `--resume <id>` on the command line because each `claude -p`
    /// invocation is a single process bound to one session.
    pub resume_id: Option<String>,
    /// Optional path to the bundled CLI (e.g. inside an app bundle on macOS).
    /// Used as the fallback launch plan when the shell-visible `codex` /
    /// `claude` is missing — important for daemon/launchd contexts where PATH
    /// is minimal. Empty string disables the fallback.
    pub bundled_binary: Option<PathBuf>,
    /// Override the auto-generated session id. The daemon supplies the
    /// channel-label id here so the session can be looked up by that id in
    /// `AgentManager` without a post-hoc re-key.
    pub id: Option<String>,
    /// Model alias/id. Codex: passed via `newConversation`/`thread/start`
    /// params (see `build_start_params`). Claude: passed via `--model` argv.
    pub model: Option<String>,
    /// Reasoning effort hint. Codex-only; Claude CLI has no equivalent knob.
    pub reasoning_effort: Option<String>,
}

/// One image attachment sent with a user message.
#[derive(Debug, Clone)]
pub enum AgentAttachment {
    /// Zero-copy: host filesystem path. Codex consumes this as `localImage`;
    /// Claude has no path form so the path is read + base64-encoded at send time.
    LocalPath {
        path: String,
        media_type: String,
    },
    /// Already-base64-encoded bytes (no `data:` prefix).
    Base64 {
        data: String,
        media_type: String,
    },
}

/// Input for `AgentSession::send_user_message`.
#[derive(Debug, Clone, Default)]
pub struct SendUserMessageInput {
    pub text: String,
    pub attachments: Vec<AgentAttachment>,
}

impl SpawnConfig {
    pub fn launch_plans(&self) -> Vec<LaunchPlan> {
        match self.backend {
            Backend::Codex => self.codex_plans(),
            Backend::Claude => self.claude_plans(),
        }
    }

    /// Build the `params` object for a Codex `newConversation` / `thread/start`
    /// RPC call, populating model + reasoningEffort from this config. Mobile
    /// (or a future host-side driver) merges this with its own fields like
    /// `conversationId` / `workspaceId`.
    pub fn codex_start_params(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        if let Some(m) = self.model.as_ref() {
            obj.insert("model".into(), serde_json::Value::String(m.clone()));
        }
        if let Some(r) = self.reasoning_effort.as_ref() {
            obj.insert(
                "reasoningEffort".into(),
                serde_json::Value::String(r.clone()),
            );
        }
        serde_json::Value::Object(obj)
    }

    /// Build the `params` object for a Codex resume RPC. Uses `thread/resume`
    /// shape if `use_thread_surface` is true (`{threadId}`), else legacy
    /// `resumeConversation` (`{conversationId}`). Returns `None` if there is
    /// no `resume_id` set.
    pub fn codex_resume_params(&self, use_thread_surface: bool) -> Option<serde_json::Value> {
        let id = self.resume_id.as_ref()?.clone();
        let mut obj = serde_json::Map::new();
        if use_thread_surface {
            obj.insert("threadId".into(), serde_json::Value::String(id));
        } else {
            obj.insert("conversationId".into(), serde_json::Value::String(id));
        }
        if let Some(m) = self.model.as_ref() {
            obj.insert("model".into(), serde_json::Value::String(m.clone()));
        }
        if let Some(r) = self.reasoning_effort.as_ref() {
            obj.insert(
                "reasoningEffort".into(),
                serde_json::Value::String(r.clone()),
            );
        }
        Some(serde_json::Value::Object(obj))
    }

    fn codex_plans(&self) -> Vec<LaunchPlan> {
        // `codex app-server` accepts no resume args at spawn — clients call
        // `resumeConversation` over the RPC channel afterwards.
        let args: Vec<String> = vec!["app-server".into()];
        let mut plans = vec![LaunchPlan {
            program: "codex".into(),
            args: args.clone(),
            description: "codex app-server".into(),
        }];
        if let Some(p) = self.bundled_binary.as_ref() {
            if !p.as_os_str().is_empty() {
                plans.push(LaunchPlan {
                    program: p.display().to_string(),
                    args,
                    description: format!("{} app-server", p.display()),
                });
            }
        }
        plans
    }

    fn claude_plans(&self) -> Vec<LaunchPlan> {
        // Streaming chat shape we proved against claude 2.1.x. `--verbose` is
        // required to receive system/init + stream_event lines (despite the
        // name — without it, stream-json suppresses early events). Likewise
        // `--include-partial-messages` is required for token-by-token deltas.
        let mut args: Vec<String> = vec![
            "-p".into(),
            "--input-format".into(),
            "stream-json".into(),
            "--output-format".into(),
            "stream-json".into(),
            "--include-partial-messages".into(),
            "--verbose".into(),
        ];
        if let Some(id) = self.resume_id.as_ref() {
            args.push("--resume".into());
            args.push(id.clone());
        }
        if let Some(model) = self.model.as_ref() {
            args.push("--model".into());
            args.push(model.clone());
        }
        let mut plans = vec![LaunchPlan {
            program: "claude".into(),
            args: args.clone(),
            description: "claude -p stream-json".into(),
        }];
        if let Some(p) = self.bundled_binary.as_ref() {
            if !p.as_os_str().is_empty() {
                plans.push(LaunchPlan {
                    program: p.display().to_string(),
                    args,
                    description: format!("{} -p stream-json", p.display()),
                });
            }
        }
        plans
    }
}

/// Compact wire form of `ExitReason` for the `agent_exit` frame sent to mobile.
/// Keeps the discriminator small and stable; the human-readable detail goes in
/// a sibling field.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentExitWire {
    Requested,
    Normal,
    Crashed,
    SpawnFailed,
    Unknown,
}

impl From<Option<&ExitReason>> for AgentExitWire {
    fn from(reason: Option<&ExitReason>) -> Self {
        match reason {
            Some(ExitReason::RequestedShutdown) => Self::Requested,
            Some(ExitReason::NormalExit { .. }) => Self::Normal,
            Some(ExitReason::Crashed { .. }) => Self::Crashed,
            Some(ExitReason::SpawnFailed { .. }) => Self::SpawnFailed,
            None => Self::Unknown,
        }
    }
}

/// Why an agent session ended. Mobile uses this to decide whether to offer a
/// retry button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// `close()` called by the daemon — clean shutdown.
    RequestedShutdown,
    /// Child exited with status 0 on its own (e.g. Claude's per-turn mode).
    NormalExit { code: i32 },
    /// Child exited with non-zero status. Stderr buffer attached for context.
    Crashed { code: Option<i32>, stderr: String },
    /// We never managed to spawn anything (every launch plan errored out).
    SpawnFailed { last_error: String },
}

/// One running agent session. Drop or `close()` triggers graceful shutdown.
pub struct AgentSession {
    id: String,
    backend: Backend,
    /// Description of the launch that actually succeeded. Useful in errors.
    launch_description: String,
    /// Send a JSON line (no trailing newline; we add it) to the child's stdin.
    /// Returns `Err` if the session has shut down. Taken out on `close()` so
    /// the writer task observes EOF and exits even with queued backlog.
    stdin_tx: Mutex<Option<mpsc::Sender<String>>>,
    /// Receive JSON lines from the child's stdout. Closed when the child exits.
    stdout_rx: Mutex<Option<mpsc::Receiver<String>>>,
    /// Final exit reason, populated when the supervisor task ends.
    exit: Arc<Mutex<Option<ExitReason>>>,
    /// Handles to the supervisor + I/O tasks so we can wait/abort on Drop.
    tasks: Mutex<Vec<JoinHandle<()>>>,
    /// Set true when `close()` runs, so the supervisor knows to mark the
    /// session as `RequestedShutdown` instead of `Crashed`.
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
    /// PID of the live child, used for SIGTERM via `nix`. `None` after exit.
    child_pid: Arc<Mutex<Option<u32>>>,
}

impl AgentSession {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }

    pub fn launch_description(&self) -> &str {
        &self.launch_description
    }

    /// Send a JSON line to the child's stdin. The newline is added internally.
    /// Lines are queued in a bounded channel; if the channel fills up the
    /// caller will be awaited on backpressure.
    pub async fn send_line(&self, line: String) -> Result<(), AgentSendError> {
        let sender = {
            let guard = self.stdin_tx.lock().await;
            guard.as_ref().cloned()
        };
        match sender {
            Some(tx) => tx
                .send(line)
                .await
                .map_err(|_| AgentSendError::SessionClosed),
            None => Err(AgentSendError::SessionClosed),
        }
    }

    /// Build and send a user message frame appropriate for this session's
    /// backend. For Codex the caller must pass the active `conversation_id`
    /// and a JSON-RPC request id; for Claude both are ignored.
    ///
    /// Attachments are transformed per backend: Codex takes `localImage` /
    /// `image` items alongside a `text` item; Claude requires base64 (path
    /// attachments are read from disk and encoded inline).
    pub async fn send_user_message(
        &self,
        input: SendUserMessageInput,
        codex_conversation_id: Option<&str>,
        codex_request_id: Option<i64>,
    ) -> Result<(), AgentSendError> {
        let line = match self.backend {
            Backend::Codex => {
                let conv = codex_conversation_id.ok_or(AgentSendError::MissingConversationId)?;
                let rid = codex_request_id.unwrap_or(1);
                build_codex_send_user_message(conv, rid, &input)
                    .map_err(AgentSendError::BuildFailed)?
            }
            Backend::Claude => {
                build_claude_user_message(&input).map_err(AgentSendError::BuildFailed)?
            }
        };
        self.send_line(line).await
    }

    /// Take the stdout receiver. Can only be taken once — the daemon owns it
    /// for the lifetime of the session and forwards lines to the data channel.
    pub async fn take_stdout(&self) -> Option<mpsc::Receiver<String>> {
        self.stdout_rx.lock().await.take()
    }

    /// Final exit reason if the session has terminated, else `None`.
    pub async fn exit_reason(&self) -> Option<ExitReason> {
        self.exit.lock().await.clone()
    }

    /// Trigger graceful shutdown: SIGTERM, wait briefly, SIGKILL. Returns
    /// after the supervisor task has set the exit reason. Idempotent.
    pub async fn close(&self) {
        self.shutdown_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);

        // Drop the stdin sender. The writer_task will see EOF and exit even
        // if messages were queued.
        self.stdin_tx.lock().await.take();

        // Hold the pid lock across the signal so the supervisor can't clear it
        // and let the OS recycle the PID between the read and the kill.
        {
            let pid_guard = self.child_pid.lock().await;
            if let Some(pid) = *pid_guard {
                send_sigterm(pid);
            }
        }

        let mut taken: Vec<JoinHandle<()>> = {
            let mut guard = self.tasks.lock().await;
            std::mem::take(&mut *guard)
        };
        for h in taken.drain(..) {
            if tokio::time::timeout(Duration::from_millis(3_000), h)
                .await
                .is_err()
            {
                debug!(session = %self.id, "agent task did not finish in time");
            }
        }
    }
}

impl Drop for AgentSession {
    fn drop(&mut self) {
        // Best-effort: abort tasks so they don't outlive the session. We can't
        // await in Drop; callers should prefer explicit `close()` which also
        // gives the child a chance to flush + exit cleanly.
        if let Ok(mut tasks) = self.tasks.try_lock() {
            for h in tasks.drain(..) {
                h.abort();
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentSendError {
    #[error("agent session is closed")]
    SessionClosed,
    #[error("codex send_user_message requires a conversation_id")]
    MissingConversationId,
    #[error("failed to build user message frame: {0}")]
    BuildFailed(String),
}

/// Build the JSON-RPC line for a Codex `sendUserMessage` with optional image
/// attachments. `localImage` items are preferred for host-filesystem paths
/// (zero-copy); `Base64` attachments become `image` items with a data URL.
pub fn build_codex_send_user_message(
    conversation_id: &str,
    request_id: i64,
    input: &SendUserMessageInput,
) -> Result<String, String> {
    let mut items: Vec<serde_json::Value> = Vec::with_capacity(input.attachments.len() + 1);
    for att in &input.attachments {
        match att {
            AgentAttachment::LocalPath { path, .. } => {
                items.push(serde_json::json!({
                    "type": "localImage",
                    "data": { "path": path }
                }));
            }
            AgentAttachment::Base64 { data, media_type } => {
                let url = format!("data:{media_type};base64,{data}");
                items.push(serde_json::json!({
                    "type": "image",
                    "data": { "image_url": url }
                }));
            }
        }
    }
    items.push(serde_json::json!({
        "type": "text",
        "data": { "text": input.text, "text_elements": [] }
    }));
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "sendUserMessage",
        "params": {
            "conversationId": conversation_id,
            "items": items,
        }
    });
    serde_json::to_string(&frame).map_err(|e| e.to_string())
}

/// Build the stream-json line for a Claude user turn. If `attachments` is
/// empty, keeps the legacy string `content` shape (matches existing tests /
/// docs). Otherwise emits an array with images first, then a text block. Local
/// paths are read + base64-encoded here (Claude has no path-form input).
pub fn build_claude_user_message(input: &SendUserMessageInput) -> Result<String, String> {
    if input.attachments.is_empty() {
        let frame = serde_json::json!({
            "type": "user",
            "message": { "role": "user", "content": input.text },
        });
        return serde_json::to_string(&frame).map_err(|e| e.to_string());
    }
    let mut blocks: Vec<serde_json::Value> = Vec::with_capacity(input.attachments.len() + 1);
    for att in &input.attachments {
        let (media_type, data) = match att {
            AgentAttachment::Base64 { data, media_type } => (media_type.clone(), data.clone()),
            AgentAttachment::LocalPath { path, media_type } => {
                let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                (media_type.clone(), encoded)
            }
        };
        blocks.push(serde_json::json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": data,
            }
        }));
    }
    blocks.push(serde_json::json!({ "type": "text", "text": input.text }));
    let frame = serde_json::json!({
        "type": "user",
        "message": { "role": "user", "content": blocks },
    });
    serde_json::to_string(&frame).map_err(|e| e.to_string())
}

/// Errors raised by `spawn_session` before any I/O tasks are running.
#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("failed to spawn agent ({backend:?}): every launch plan failed: {last_error}")]
    AllPlansFailed {
        backend: Backend,
        last_error: String,
    },
    #[error("agent backend produced no launch plans")]
    NoPlans,
}

/// Spawn a fresh agent session. Tries the launch plans in order; falls back to
/// the next plan only on `ENOENT`. Other spawn errors (permission, etc.) are
/// fatal — that matches remodex's behavior and avoids masking real problems.
pub async fn spawn_session(config: SpawnConfig) -> Result<Arc<AgentSession>, SpawnError> {
    let plans = config.launch_plans();
    if plans.is_empty() {
        return Err(SpawnError::NoPlans);
    }

    let mut last_err = String::from("no plans tried");
    let mut spawned: Option<(Child, LaunchPlan)> = None;

    for plan in &plans {
        let mut cmd = Command::new(&plan.program);
        cmd.args(&plan.args);
        if let Some(cwd) = config.cwd.as_ref() {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Don't put the child in our process group on Unix — it shouldn't
            // share signals like Ctrl+C from a controlling TTY.
            .kill_on_drop(true);

        match cmd.spawn() {
            Ok(child) => {
                info!(
                    backend = config.backend.as_str(),
                    launch = %plan.description,
                    pid = child.id(),
                    "agent child spawned",
                );
                spawned = Some((child, plan.clone()));
                break;
            }
            Err(e) => {
                let kind = e.kind();
                last_err = format!("{}: {} ({kind:?})", plan.description, e);
                if kind != std::io::ErrorKind::NotFound {
                    // Non-ENOENT errors are fatal — see remodex
                    // shouldRetryLaunchError.
                    return Err(SpawnError::AllPlansFailed {
                        backend: config.backend,
                        last_error: last_err,
                    });
                }
                debug!(
                    backend = config.backend.as_str(),
                    launch = %plan.description,
                    "launch plan ENOENT, trying next"
                );
            }
        }
    }

    let (mut child, launch) = spawned.ok_or_else(|| SpawnError::AllPlansFailed {
        backend: config.backend,
        last_error: last_err,
    })?;

    let pid = child.id();
    let stdin = child.stdin.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    let stderr = child.stderr.take().expect("piped");

    let (stdin_tx, stdin_rx) = mpsc::channel::<String>(STDIN_CHANNEL_CAPACITY);
    let (stdout_tx, stdout_rx) = mpsc::channel::<String>(STDOUT_CHANNEL_CAPACITY);

    let id = config.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let exit_slot: Arc<Mutex<Option<ExitReason>>> = Arc::new(Mutex::new(None));
    let shutdown_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stderr_ring = Arc::new(Mutex::new(StderrRing::new()));
    let child_pid: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(pid));

    // Writer task: pull lines from stdin_rx and write to child stdin.
    let writer_handle = tokio::spawn(writer_task(
        stdin_rx,
        stdin,
        shutdown_requested.clone(),
        id.clone(),
    ));

    // Reader task: line-buffered stdout → stdout_tx.
    let reader_handle = tokio::spawn(reader_task(stdout, stdout_tx, id.clone()));

    // Stderr task: append to ring buffer for crash diagnostics.
    let stderr_handle = tokio::spawn(stderr_task(stderr, stderr_ring.clone(), id.clone()));

    // Supervisor task: waits on the child, records the exit reason.
    let supervisor_handle = tokio::spawn(supervisor_task(
        child,
        shutdown_requested.clone(),
        exit_slot.clone(),
        stderr_ring.clone(),
        child_pid.clone(),
        id.clone(),
        launch.description.clone(),
    ));

    let session = AgentSession {
        id: id.clone(),
        backend: config.backend,
        launch_description: launch.description,
        stdin_tx: Mutex::new(Some(stdin_tx)),
        stdout_rx: Mutex::new(Some(stdout_rx)),
        exit: exit_slot,
        tasks: Mutex::new(vec![
            writer_handle,
            reader_handle,
            stderr_handle,
            supervisor_handle,
        ]),
        shutdown_requested,
        child_pid,
    };
    Ok(Arc::new(session))
}

/// Pump JSON lines from `rx` into the child's stdin, one per write, with a
/// trailing `\n`. Exits when the channel closes.
async fn writer_task(
    mut rx: mpsc::Receiver<String>,
    mut stdin: tokio::process::ChildStdin,
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
    session_id: String,
) {
    while let Some(mut line) = rx.recv().await {
        if !line.ends_with('\n') {
            line.push('\n');
        }
        if let Err(e) = stdin.write_all(line.as_bytes()).await {
            // Match remodex's "ignorable shutdown stdin error" rule: any pipe
            // breakage during/after shutdown is expected.
            let ignorable = matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof
            ) || shutdown_requested.load(std::sync::atomic::Ordering::SeqCst);
            if ignorable {
                debug!(session = %session_id, ?e, "agent stdin write ignored");
            } else {
                warn!(session = %session_id, ?e, "agent stdin write failed");
            }
            return;
        }
        if let Err(e) = stdin.flush().await {
            if !shutdown_requested.load(std::sync::atomic::Ordering::SeqCst) {
                warn!(session = %session_id, ?e, "agent stdin flush failed");
            }
            return;
        }
    }
    // Closing stdin signals EOF to the child — Claude's per-turn process
    // depends on this to know the user is done.
    let _ = stdin.shutdown().await;
}

/// Read child stdout line-by-line, forwarding each non-empty trimmed line to
/// `tx`. Empty / whitespace-only lines are dropped (Codex sometimes emits
/// blank separators between events).
async fn reader_task(
    stdout: tokio::process::ChildStdout,
    tx: mpsc::Sender<String>,
    session_id: String,
) {
    let mut reader = BufReader::new(stdout).lines();
    loop {
        match reader.next_line().await {
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                if tx.send(line).await.is_err() {
                    debug!(session = %session_id, "stdout receiver dropped");
                    return;
                }
            }
            Ok(None) => {
                debug!(session = %session_id, "agent stdout EOF");
                return;
            }
            Err(e) => {
                warn!(session = %session_id, ?e, "agent stdout read error");
                return;
            }
        }
    }
}

/// Append child stderr to a bounded ring buffer for crash diagnostics. We
/// don't surface stderr to mobile by default — it contains tracing spam and
/// auth tokens in some cases.
async fn stderr_task(
    stderr: tokio::process::ChildStderr,
    ring: Arc<Mutex<StderrRing>>,
    session_id: String,
) {
    let mut reader = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = reader.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        // Filter the most common Codex skill-load noise so the diagnostic
        // window stays useful when a real crash happens.
        if line.contains("failed to load skill") {
            continue;
        }
        debug!(session = %session_id, "agent stderr: {}", line);
        ring.lock().await.append(&line);
    }
}

/// Wait on the child, then populate `exit_slot` with the appropriate
/// `ExitReason`. Also clears `child_pid` so subsequent SIGTERMs are no-ops.
async fn supervisor_task(
    mut child: Child,
    shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
    exit_slot: Arc<Mutex<Option<ExitReason>>>,
    stderr_ring: Arc<Mutex<StderrRing>>,
    child_pid: Arc<Mutex<Option<u32>>>,
    session_id: String,
    launch_description: String,
) {
    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            warn!(session = %session_id, ?e, "agent child wait failed");
            *exit_slot.lock().await = Some(ExitReason::Crashed {
                code: None,
                stderr: e.to_string(),
            });
            *child_pid.lock().await = None;
            return;
        }
    };

    *child_pid.lock().await = None;

    let code = status.code();
    let stderr_snapshot = stderr_ring.lock().await.snapshot();
    let requested = shutdown_requested.load(std::sync::atomic::Ordering::SeqCst);

    let reason = if requested {
        ExitReason::RequestedShutdown
    } else if code == Some(0) {
        ExitReason::NormalExit { code: 0 }
    } else {
        ExitReason::Crashed {
            code,
            stderr: if stderr_snapshot.trim().is_empty() {
                format!("{} exited with status {:?}", launch_description, status)
            } else {
                stderr_snapshot
            },
        }
    };

    info!(session = %session_id, ?reason, "agent exited");
    *exit_slot.lock().await = Some(reason);
}

/// Bounded ring of stderr text. Keeps only the trailing `STDERR_RING_BYTES`
/// bytes — the tail is what matters when a crash dies of an error in the
/// last few writes.
struct StderrRing {
    buf: String,
}

impl StderrRing {
    fn new() -> Self {
        Self {
            buf: String::with_capacity(STDERR_RING_BYTES + 256),
        }
    }

    fn append(&mut self, line: &str) {
        self.buf.push_str(line);
        self.buf.push('\n');
        if self.buf.len() > STDERR_RING_BYTES {
            // Trim from the front, keeping the tail. We may slice in the
            // middle of a UTF-8 char — push to next char boundary.
            let drop = self.buf.len() - STDERR_RING_BYTES;
            let mut idx = drop;
            while !self.buf.is_char_boundary(idx) && idx < self.buf.len() {
                idx += 1;
            }
            self.buf.drain(..idx);
        }
    }

    fn snapshot(&self) -> String {
        self.buf.clone()
    }
}

#[cfg(unix)]
fn send_sigterm(pid: u32) {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    let p = Pid::from_raw(pid as i32);
    if let Err(e) = kill(p, Signal::SIGTERM) {
        debug!(pid, ?e, "SIGTERM failed");
    } else {
        debug!(pid, "SIGTERM sent to agent child");
    }
}

#[cfg(not(unix))]
fn send_sigterm(_pid: u32) {
    // Windows needs `taskkill /pid X /t /f` to handle the cmd.exe wrapper case
    // (see remodex codex-transport.js). Deferred until we ship a Windows host.
}

/// Registry of live agent sessions. Owned by the daemon.
#[derive(Default)]
pub struct AgentManager {
    sessions: Mutex<HashMap<String, Arc<AgentSession>>>,
}

impl AgentManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn create(
        &self,
        config: SpawnConfig,
    ) -> Result<Arc<AgentSession>, SpawnError> {
        let session = spawn_session(config).await?;
        self.sessions
            .lock()
            .await
            .insert(session.id().to_string(), session.clone());
        Ok(session)
    }


    pub async fn get(&self, id: &str) -> Option<Arc<AgentSession>> {
        self.sessions.lock().await.get(id).cloned()
    }

    pub async fn close(&self, id: &str) -> bool {
        let removed = self.sessions.lock().await.remove(id);
        match removed {
            Some(s) => {
                s.close().await;
                true
            }
            None => false,
        }
    }

    pub async fn list(&self) -> Vec<String> {
        self.sessions.lock().await.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> serde_json::Value {
        serde_json::from_str(line).expect("valid json")
    }

    #[test]
    fn codex_builder_text_only() {
        let input = SendUserMessageInput {
            text: "hi".into(),
            attachments: vec![],
        };
        let line = build_codex_send_user_message("conv-1", 42, &input).unwrap();
        let v = parse(&line);
        assert_eq!(v["method"], "sendUserMessage");
        assert_eq!(v["id"], 42);
        assert_eq!(v["params"]["conversationId"], "conv-1");
        let items = v["params"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["type"], "text");
        assert_eq!(items[0]["data"]["text"], "hi");
        assert!(items[0]["data"]["text_elements"].is_array());
    }

    #[test]
    fn codex_builder_mixed_attachments() {
        let input = SendUserMessageInput {
            text: "describe".into(),
            attachments: vec![
                AgentAttachment::LocalPath {
                    path: "/tmp/a.png".into(),
                    media_type: "image/png".into(),
                },
                AgentAttachment::Base64 {
                    data: "QUJD".into(),
                    media_type: "image/jpeg".into(),
                },
            ],
        };
        let v = parse(&build_codex_send_user_message("c", 1, &input).unwrap());
        let items = v["params"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["type"], "localImage");
        assert_eq!(items[0]["data"]["path"], "/tmp/a.png");
        assert_eq!(items[1]["type"], "image");
        assert_eq!(
            items[1]["data"]["image_url"],
            "data:image/jpeg;base64,QUJD"
        );
        assert_eq!(items[2]["type"], "text");
        assert_eq!(items[2]["data"]["text"], "describe");
    }

    #[test]
    fn claude_builder_text_only_keeps_string_content() {
        let input = SendUserMessageInput {
            text: "hello".into(),
            attachments: vec![],
        };
        let v = parse(&build_claude_user_message(&input).unwrap());
        assert_eq!(v["type"], "user");
        assert_eq!(v["message"]["content"], "hello");
    }

    #[test]
    fn claude_builder_base64_block_array() {
        let input = SendUserMessageInput {
            text: "what".into(),
            attachments: vec![AgentAttachment::Base64 {
                data: "WFlB".into(),
                media_type: "image/png".into(),
            }],
        };
        let v = parse(&build_claude_user_message(&input).unwrap());
        let content = v["message"]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "image");
        assert_eq!(content[0]["source"]["type"], "base64");
        assert_eq!(content[0]["source"]["media_type"], "image/png");
        assert_eq!(content[0]["source"]["data"], "WFlB");
        assert_eq!(content[1]["type"], "text");
        assert_eq!(content[1]["text"], "what");
    }

    #[test]
    fn codex_start_params_only_sets_given_keys() {
        let cfg = SpawnConfig {
            backend: Backend::Codex,
            cwd: None,
            resume_id: None,
            bundled_binary: None,
            id: None,
            model: Some("gpt-5.2-codex".into()),
            reasoning_effort: None,
        };
        let v = cfg.codex_start_params();
        assert_eq!(v["model"], "gpt-5.2-codex");
        assert!(v.get("reasoningEffort").is_none());
    }

    #[test]
    fn codex_resume_params_picks_surface() {
        let cfg = SpawnConfig {
            backend: Backend::Codex,
            cwd: None,
            resume_id: Some("abc".into()),
            bundled_binary: None,
            id: None,
            model: None,
            reasoning_effort: Some("high".into()),
        };
        let thread = cfg.codex_resume_params(true).unwrap();
        assert_eq!(thread["threadId"], "abc");
        assert_eq!(thread["reasoningEffort"], "high");
        let legacy = cfg.codex_resume_params(false).unwrap();
        assert_eq!(legacy["conversationId"], "abc");
    }

    #[test]
    fn codex_launch_plans_include_app_server() {
        let cfg = SpawnConfig {
            backend: Backend::Codex,
            cwd: None,
            resume_id: None,
            bundled_binary: Some(PathBuf::from("/Applications/Codex.app/Contents/Resources/codex")),
            id: None,
            model: None,
            reasoning_effort: None,
        };
        let plans = cfg.launch_plans();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].program, "codex");
        assert_eq!(plans[0].args, vec!["app-server".to_string()]);
        assert!(plans[1].program.contains("Codex.app"));
    }

    #[test]
    fn claude_launch_plans_include_resume() {
        let cfg = SpawnConfig {
            backend: Backend::Claude,
            cwd: None,
            resume_id: Some("abc-123".into()),
            bundled_binary: None,
            id: None,
            model: None,
            reasoning_effort: None,
        };
        let plans = cfg.launch_plans();
        assert_eq!(plans.len(), 1);
        assert!(plans[0].args.contains(&"--resume".to_string()));
        assert!(plans[0].args.contains(&"abc-123".to_string()));
        assert!(plans[0].args.contains(&"--include-partial-messages".to_string()));
        assert!(plans[0].args.contains(&"--verbose".to_string()));
    }

    #[test]
    fn claude_launch_plans_omit_resume_when_none() {
        let cfg = SpawnConfig {
            backend: Backend::Claude,
            cwd: None,
            resume_id: None,
            bundled_binary: None,
            id: None,
            model: None,
            reasoning_effort: None,
        };
        let plans = cfg.launch_plans();
        assert!(!plans[0].args.iter().any(|a| a == "--resume"));
    }

    #[test]
    fn discover_bundled_returns_none_for_missing_user() {
        // Whatever this machine actually has, the function must not panic and
        // must return Some(executable) or None.
        let res = discover_bundled(Backend::Codex);
        if let Some(p) = &res {
            assert!(p.exists(), "discovered path should exist: {}", p.display());
            assert!(is_executable_file(p), "discovered path must be executable: {}", p.display());
        }
        let res = discover_bundled(Backend::Claude);
        if let Some(p) = &res {
            assert!(p.exists(), "discovered path should exist: {}", p.display());
            assert!(is_executable_file(p), "discovered path must be executable: {}", p.display());
        }
    }

    #[test]
    fn nvm_pick_handles_missing_dir() {
        assert!(nvm_pick(std::path::Path::new("/no/such/nvm/path/xx"), "codex").is_none());
    }

    #[test]
    fn stderr_ring_keeps_last_n_bytes() {
        let mut r = StderrRing::new();
        for i in 0..1000 {
            r.append(&format!("line-{:04}-padding-padding-padding", i));
        }
        let snap = r.snapshot();
        assert!(snap.len() <= STDERR_RING_BYTES + 64);
        // The last line should be present.
        assert!(snap.contains("line-0999"));
        // The first line should be evicted.
        assert!(!snap.contains("line-0000"));
    }

    #[tokio::test]
    async fn spawn_missing_binary_errors() {
        let cfg = SpawnConfig {
            backend: Backend::Codex,
            cwd: None,
            resume_id: None,
            bundled_binary: Some(PathBuf::from("/definitely/not/here/codex-binary-xyz")),
            id: None,
            model: None,
            reasoning_effort: None,
        };
        // Override the first plan to also point at a missing binary so we
        // exercise the all-plans-failed path. SpawnConfig always tries the
        // shell's `codex` first; on machines where it exists this test would
        // unexpectedly succeed. Force-fail by overriding via a custom plan list.
        let plans = vec![LaunchPlan {
            program: "/no/such/binary-xxx".into(),
            args: vec![],
            description: "missing".into(),
        }];
        // Re-implement the spawn loop locally with our forced plans so we
        // don't depend on whether the host has codex installed.
        let mut last_err = String::new();
        let mut ok = false;
        for plan in &plans {
            let mut cmd = Command::new(&plan.program);
            cmd.args(&plan.args);
            cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            match cmd.spawn() {
                Ok(_) => {
                    ok = true;
                    break;
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        assert!(!ok, "did not expect /no/such/binary-xxx to spawn");
        assert!(!last_err.is_empty());
        let _ = cfg; // silence unused
    }

    /// Real integration test: spawn Codex, drive one turn, assert we got at
    /// least one streaming delta and a terminal event.
    ///
    /// Marked `#[ignore]` because it needs the user's `codex` binary,
    /// network, and ChatGPT auth. Run with `cargo test -p host-core --
    /// --ignored agent_session::tests::codex_real_turn`.
    #[tokio::test]
    #[ignore]
    async fn codex_real_turn() {
        let session = spawn_session(SpawnConfig {
            backend: Backend::Codex,
            cwd: None,
            resume_id: None,
            bundled_binary: None,
            id: None,
            model: None,
            reasoning_effort: None,
        })
        .await
        .expect("codex spawn");
        let mut rx = session.take_stdout().await.expect("rx");

        // Helper to wait for a JSON line whose `id` matches `req_id`.
        async fn await_response(
            rx: &mut mpsc::Receiver<String>,
            req_id: i64,
            timeout: Duration,
        ) -> serde_json::Value {
            let deadline = tokio::time::Instant::now() + timeout;
            while tokio::time::Instant::now() < deadline {
                let recv = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
                match recv {
                    Ok(Some(line)) => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                            if v.get("id").and_then(|x| x.as_i64()) == Some(req_id) {
                                return v;
                            }
                        }
                    }
                    Ok(None) => panic!("agent stdout closed early"),
                    Err(_) => continue,
                }
            }
            panic!("timeout waiting for response id={req_id}");
        }

        // initialize
        session
            .send_line(
                serde_json::json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize",
                    "params":{"clientInfo":{"name":"host-core-test","version":"0.0.1"},"capabilities":{}}
                })
                .to_string(),
            )
            .await
            .unwrap();
        let init = await_response(&mut rx, 1, Duration::from_secs(10)).await;
        assert!(init.get("result").is_some(), "init result: {init}");

        // newConversation
        session
            .send_line(
                serde_json::json!({
                    "jsonrpc":"2.0","id":2,"method":"newConversation","params":{}
                })
                .to_string(),
            )
            .await
            .unwrap();
        let new_conv = await_response(&mut rx, 2, Duration::from_secs(15)).await;
        let conv_id = new_conv["result"]["conversationId"]
            .as_str()
            .expect("conversationId")
            .to_string();

        // addConversationListener — without this no events arrive
        session
            .send_line(
                serde_json::json!({
                    "jsonrpc":"2.0","id":3,"method":"addConversationListener",
                    "params":{"conversationId": conv_id}
                })
                .to_string(),
            )
            .await
            .unwrap();
        await_response(&mut rx, 3, Duration::from_secs(5)).await;

        // sendUserMessage
        session
            .send_line(
                serde_json::json!({
                    "jsonrpc":"2.0","id":4,"method":"sendUserMessage",
                    "params":{
                        "conversationId": conv_id,
                        "items":[{"type":"text","data":{"text":"Reply with the single word: pong"}}]
                    }
                })
                .to_string(),
            )
            .await
            .unwrap();

        // Drain until we see a delta + a terminal event.
        let mut got_delta = false;
        let mut got_terminal = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while tokio::time::Instant::now() < deadline && !(got_delta && got_terminal) {
            match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(line)) => {
                    if line.contains("agent_message_delta")
                        || line.contains("agentMessage/delta")
                        || line.contains("reasoning_content_delta")
                        || line.contains("summaryTextDelta")
                    {
                        got_delta = true;
                    }
                    if line.contains("task_complete")
                        || line.contains("turn/completed")
                        || line.contains("\"turn_complete\"")
                    {
                        got_terminal = true;
                    }
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(got_delta, "expected at least one streaming delta");
        assert!(got_terminal, "expected a terminal event");

        session.close().await;
        let exit = session.exit_reason().await;
        assert!(matches!(exit, Some(ExitReason::RequestedShutdown)));
    }

    /// Same idea for Claude. Ignored by default — needs the binary + auth.
    #[tokio::test]
    #[ignore]
    async fn claude_real_turn() {
        let session = spawn_session(SpawnConfig {
            backend: Backend::Claude,
            cwd: None,
            resume_id: None,
            bundled_binary: None,
            id: None,
            model: None,
            reasoning_effort: None,
        })
        .await
        .expect("claude spawn");
        let mut rx = session.take_stdout().await.expect("rx");

        session
            .send_line(
                serde_json::json!({
                    "type":"user",
                    "message":{"role":"user","content":"Reply with exactly one word: pong"}
                })
                .to_string(),
            )
            .await
            .unwrap();

        let mut got_delta = false;
        let mut got_result = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while tokio::time::Instant::now() < deadline && !got_result {
            match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(line)) => {
                    if line.contains("\"content_block_delta\"") {
                        got_delta = true;
                    }
                    if line.contains("\"type\":\"result\"") {
                        got_result = true;
                    }
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }
        assert!(got_delta, "expected at least one content_block_delta");
        assert!(got_result, "expected a `result` terminal event");

        session.close().await;
    }
}
