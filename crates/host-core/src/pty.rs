use crate::error::{HostError, Result};
use crate::terminal::TerminalMirror;
use crate::terminal_marks::{
    AttentionKind, AttentionTracker, PendingAttention, DEFAULT_QUIET_PERIOD,
};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{ProcessesToUpdate, System};

const MAX_SCROLLBACK_BYTES: usize = 512 * 1024;
const REMOTE_TERMINAL_ENV: &str = "POCKETSHELL_REMOTE_TERMINAL";

/// Dummy child process for PTY relay sessions (the real process is owned by `pocketshell rc`).
#[derive(Debug)]
struct DummyChild;

impl portable_pty::ChildKiller for DummyChild {
    fn kill(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        Box::new(DummyChild)
    }
}

impl portable_pty::Child for DummyChild {
    fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
        Ok(None)
    }
    fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
        Ok(portable_pty::ExitStatus::with_exit_code(0))
    }
    fn process_id(&self) -> Option<u32> {
        None
    }
    // On Windows the `Child` trait additionally requires exposing the
    // underlying OS process handle. `DummyChild` owns no real process (the
    // actual one lives in the `pocketshell rc` relay), so there is no handle —
    // mirrors `process_id` returning `None`.
    #[cfg(windows)]
    fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        None
    }
}

pub struct SessionOutputChunk {
    pub session_id: String,
    /// Absolute start offset of `bytes` in the session's output stream — equal
    /// to the mirror's `bytes_fed` just before these bytes were folded in.
    /// Lets the client dedup the snapshot→live seam (drop frames whose end is
    /// ≤ the snapshot `base_offset`).
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// A debounce-elapsed attention event surfaced to the daemon, tagged with
/// the session it came from.
#[derive(Debug, Clone)]
pub struct SessionAttentionEvent {
    pub session_id: String,
    pub kind: AttentionKind,
    pub command_duration: Option<Duration>,
    pub attention_context: AttentionContext,
    pub foreground_process: Option<String>,
}

impl SessionAttentionEvent {
    fn from_pending(session_id: String, p: PendingAttention, process: ForegroundProcess) -> Self {
        Self {
            session_id,
            kind: p.kind,
            command_duration: p.command_duration,
            attention_context: process.attention_context,
            foreground_process: process.name,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionContext {
    AgentTui,
    Tui,
    Shell,
    Unknown,
}

impl AttentionContext {
    pub fn wire_str(self) -> &'static str {
        match self {
            Self::AgentTui => "agent_tui",
            Self::Tui => "tui",
            Self::Shell => "shell",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct ForegroundProcess {
    name: Option<String>,
    attention_context: AttentionContext,
}

fn normalize_process_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.trim().trim_end_matches(".exe").to_ascii_lowercase()
}

fn classify_process_name(name: &str) -> AttentionContext {
    let normalized = normalize_process_name(name);
    match normalized.as_str() {
        "claude" | "codex" | "gemini" | "aider" | "opencode" => AttentionContext::AgentTui,
        "vim" | "nvim" | "vi" | "emacs" | "nano" | "less" | "more" | "man" | "top" | "htop"
        | "btop" | "btm" | "lazygit" | "tig" | "ssh" => AttentionContext::Tui,
        "sh" | "bash" | "zsh" | "fish" | "nu" | "pwsh" | "powershell" | "cmd" => {
            AttentionContext::Shell
        }
        _ => AttentionContext::Unknown,
    }
}

fn detect_foreground_process(root_pid: Option<u32>) -> ForegroundProcess {
    let Some(root_pid) = root_pid else {
        return ForegroundProcess {
            name: None,
            attention_context: AttentionContext::Unknown,
        };
    };

    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let root = sysinfo::Pid::from_u32(root_pid);
    let mut descendants: Vec<(u32, String, AttentionContext)> = Vec::new();

    for process in system.processes().values() {
        let mut current = process.parent();
        let mut is_descendant = false;
        while let Some(parent) = current {
            if parent == root {
                is_descendant = true;
                break;
            }
            current = system.process(parent).and_then(|p| p.parent());
        }
        if is_descendant {
            let name = process.name().to_string_lossy().to_string();
            let context = classify_process_name(&name);
            descendants.push((process.pid().as_u32(), name, context));
        }
    }

    if let Some((_, name, context)) = descendants
        .iter()
        .find(|(_, _, context)| *context == AttentionContext::AgentTui)
    {
        return ForegroundProcess {
            name: Some(name.clone()),
            attention_context: *context,
        };
    }

    if let Some((_, name, context)) = descendants
        .iter()
        .find(|(_, _, context)| *context == AttentionContext::Tui)
    {
        return ForegroundProcess {
            name: Some(name.clone()),
            attention_context: *context,
        };
    }

    if let Some((_, name, context)) = descendants.iter().max_by_key(|(pid, _, _)| *pid) {
        return ForegroundProcess {
            name: Some(name.clone()),
            attention_context: *context,
        };
    }

    let root_process = system.process(root);
    let name = root_process.map(|p| p.name().to_string_lossy().to_string());
    let attention_context = name
        .as_deref()
        .map(classify_process_name)
        .unwrap_or(AttentionContext::Unknown);
    ForegroundProcess {
        name,
        attention_context,
    }
}

struct PtySession {
    input_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u16, u16)>,
    output_rx: mpsc::Receiver<(u64, Vec<u8>)>,
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    root_pid: Option<u32>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    /// Whether this session remains resumable after viewers detach.
    persistent: bool,
    /// Legacy tmux session name when persistence is delegated to tmux.
    tmux_session_name: Option<String>,
    /// OSC 133 + BEL detector with 10 s debounce. Updated by the read
    /// thread on every chunk; drained by the daemon each output tick.
    attention: Arc<Mutex<AttentionTracker>>,
    /// Passive headless terminal emulator fed every PTY byte by the read
    /// thread. Source of the canonical screen snapshot used for resume.
    mirror: Arc<Mutex<TerminalMirror>>,
}

pub struct SessionManager {
    sessions: HashMap<String, PtySession>,
    limit: usize,
    /// Windows Job Object that kills every spawned PTY child if the daemon dies
    /// for any reason — prevents orphaned, CPU-spinning `conhost.exe` backends.
    /// `None` if the job couldn't be created (the daemon still runs, unguarded).
    /// No-op on non-Windows targets. Held for the lifetime of the manager (i.e.
    /// the daemon process) so the kill-on-close guarantee stays armed.
    ///
    /// Read only on Windows (the assign-on-spawn block); construct-only
    /// elsewhere, so the dead-code allow is scoped to non-Windows targets —
    /// keeping it unconditional would mask a genuine unused field on Windows.
    #[cfg_attr(not(windows), allow(dead_code))]
    job: Option<crate::job_object::JobObjectGuard>,
}

impl SessionManager {
    pub fn new(limit: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            limit,
            job: crate::job_object::JobObjectGuard::new(),
        }
    }

    /// Check if a session is currently active (has I/O threads running).
    pub fn is_active(&self, session_id: &str) -> bool {
        self.sessions.contains_key(session_id)
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn create_session(
        &mut self,
        session_id: String,
        shell: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.create_session_with_command(session_id, shell, &[], cols, rows, true, None)
    }

    /// Reconnect to an existing native persistent session.
    pub fn reconnect_session(&mut self, session_id: String, cols: u16, rows: u16) -> Result<()> {
        let _ = (cols, rows);
        if self.sessions.contains_key(&session_id) {
            return Ok(());
        }
        Err(HostError::Pty(format!(
            "session {session_id} is not active; native PocketShell sessions cannot be restored after a daemon restart"
        )))
    }

    /// Capture PocketShell-managed scrollback for replay.
    pub fn capture_scrollback(&self, session_id: &str) -> Result<Vec<u8>> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;
        let scrollback = session
            .scrollback
            .lock()
            .map_err(|_| HostError::Pty(format!("scrollback lock poisoned: {session_id}")))?;
        Ok(scrollback.iter().copied().collect())
    }

    /// Capture a canonical screen snapshot from the session's terminal mirror.
    ///
    /// This is the resume payload for the rewrite: it reflects the *current
    /// rendered screen* (including alt-screen TUIs), independent of how many
    /// bytes a reconnecting client missed. Not yet wired into the daemon's
    /// resume path — see `docs/terminal-rewrite-design.md` (Phase 2).
    pub fn capture_snapshot(&self, session_id: &str) -> Result<crate::terminal::Snapshot> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;
        let mirror = session
            .mirror
            .lock()
            .map_err(|_| HostError::Pty(format!("mirror lock poisoned: {session_id}")))?;
        Ok(mirror.snapshot())
    }

    /// Check if a session is persistent.
    pub fn is_persistent(&self, session_id: &str) -> bool {
        self.sessions
            .get(session_id)
            .map_or(false, |s| s.persistent)
    }

    /// Get the legacy tmux session name for a session, when applicable.
    pub fn tmux_session_name(&self, session_id: &str) -> Option<String> {
        self.sessions
            .get(session_id)
            .and_then(|s| s.tmux_session_name.clone())
    }

    /// Validate a tmux/screen session name — reject shell metacharacters.
    fn validate_session_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 256 {
            return Err(HostError::Pty("invalid session name length".to_string()));
        }
        // Allow alphanumeric, hyphen, underscore, dot, colon (tmux target separator),
        // forward slash (screen socket paths), plus, at, comma.
        // Reject shell metacharacters: ; | & $ ` ' " \ ( ) { } < > ! ? * ~ # space newline etc.
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || "-_.:/@+,".contains(c))
        {
            return Err(HostError::Pty(
                "session name contains invalid characters".to_string(),
            ));
        }
        Ok(())
    }

    /// Create a session that attaches to an existing tmux/screen session.
    pub fn create_attached_session(
        &mut self,
        session_id: String,
        session_type: &str,
        target_name: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        if session_type == "tmux" || session_type == "screen" {
            Self::validate_session_name(target_name)?;
        }
        match session_type {
            "tmux" => self.create_session_with_command(
                session_id,
                "tmux",
                &["attach-session", "-t", target_name],
                cols,
                rows,
                false,
                None,
            ),
            "screen" => self.create_session_with_command(
                session_id,
                "screen",
                &["-x", target_name],
                cols,
                rows,
                false,
                None,
            ),
            // "pocketshell" type — rejoin an existing PocketShell-managed session by ID
            "pocketshell" => self.reconnect_session(target_name.to_string(), cols, rows),
            // "shell" type from `pocketshell rc` — attach to existing PTY device
            "shell" => self.create_pty_relay_session(session_id, target_name),
            _ => Err(HostError::Pty(format!(
                "unsupported session type: {session_type}"
            ))),
        }
    }

    /// Create a session that starts a new named tmux/screen session.
    pub fn create_named_session(
        &mut self,
        session_id: String,
        session_type: &str,
        target_name: &str,
        shell: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        if session_type == "tmux" || session_type == "screen" {
            Self::validate_session_name(target_name)?;
        }
        match session_type {
            "tmux" => self.create_session_with_command(
                session_id,
                "tmux",
                &["new-session", "-s", target_name],
                cols,
                rows,
                false,
                None,
            ),
            "screen" => self.create_session_with_command(
                session_id,
                "screen",
                &["-S", target_name],
                cols,
                rows,
                false,
                None,
            ),
            _ => self.create_session(session_id, shell, cols, rows),
        }
    }

    /// Relay I/O to/from an existing PTY device (used by `pocketshell rc` exposed sessions).
    ///
    /// Unix-only: it opens a real `/dev/pts/*` device and verifies it with
    /// `isatty(3)`. Relaying an externally-owned terminal has no portable
    /// equivalent on Windows (ConPTY pseudoconsoles aren't filesystem device
    /// nodes), so on non-Unix hosts this returns an error. Fresh sessions
    /// spawned by the daemon itself still work everywhere via `portable-pty`.
    #[cfg(unix)]
    pub fn create_pty_relay_session(&mut self, session_id: String, pty_path: &str) -> Result<()> {
        use std::fs::OpenOptions;

        if self.sessions.len() >= self.limit {
            return Err(HostError::Pty(format!(
                "session limit reached ({})",
                self.limit
            )));
        }
        if self.sessions.contains_key(&session_id) {
            return Err(HostError::Pty(format!(
                "session already exists: {session_id}"
            )));
        }
        if pty_path.is_empty() {
            return Err(HostError::Pty(
                "no PTY path for exposed session".to_string(),
            ));
        }

        // Canonicalize and validate the PTY path before opening
        let canonical = std::fs::canonicalize(pty_path)
            .map_err(|e| HostError::Pty(format!("cannot resolve PTY path {pty_path}: {e}")))?;
        let canonical_str = canonical
            .to_str()
            .ok_or_else(|| HostError::Pty("PTY path is not valid UTF-8".to_string()))?;

        // Enforce /dev/ prefix — only real device nodes
        if !canonical_str.starts_with("/dev/") {
            return Err(HostError::Pty(format!(
                "PTY path must be under /dev/, got: {canonical_str}"
            )));
        }

        let pty_read = OpenOptions::new()
            .read(true)
            .open(canonical_str)
            .map_err(|e| HostError::Pty(format!("open PTY {canonical_str} for read: {e}")))?;

        // Verify it's actually a TTY device
        if !nix::unistd::isatty(&pty_read).unwrap_or(false) {
            return Err(HostError::Pty(format!(
                "path is not a TTY device: {canonical_str}"
            )));
        }

        let mut pty_write = OpenOptions::new()
            .write(true)
            .open(canonical_str)
            .map_err(|e| HostError::Pty(format!("open PTY {canonical_str} for write: {e}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let scrollback = Arc::new(Mutex::new(VecDeque::new()));
        let attention = Arc::new(Mutex::new(AttentionTracker::new(
            DEFAULT_QUIET_PERIOD,
            session_id.clone(),
        )));
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, _resize_rx) = mpsc::channel::<(u16, u16)>();
        let (output_tx, output_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(1024);
        // Passive mirror for snapshot-based resume. Relay sessions attach to an
        // externally-owned PTY of unknown size; default to 80×24 and let the
        // client's first resize correct it.
        let mirror = Arc::new(Mutex::new(TerminalMirror::new(80, 24)));

        // Writer thread — sends mobile input to the host's PTY
        {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match input_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(data) => {
                            let _ = pty_write.write_all(&data);
                            let _ = pty_write.flush();
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
        }

        spawn_pty_reader_thread(
            pty_read,
            Arc::clone(&stop),
            Arc::clone(&scrollback),
            Arc::clone(&attention),
            Arc::clone(&mirror),
            output_tx,
            input_tx.clone(),
        );

        // Use a dummy child — the PTY is owned by the rc process, not us
        let dummy_child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>> =
            Arc::new(Mutex::new(Box::new(DummyChild)));

        self.sessions.insert(
            session_id,
            PtySession {
                input_tx,
                resize_tx,
                output_rx,
                stop,
                child: dummy_child,
                root_pid: None,
                scrollback,
                persistent: false,
                tmux_session_name: None,
                attention,
                mirror,
            },
        );

        Ok(())
    }

    /// Non-Unix stub: relaying an existing PTY device isn't supported.
    #[cfg(not(unix))]
    pub fn create_pty_relay_session(&mut self, _session_id: String, _pty_path: &str) -> Result<()> {
        Err(HostError::Pty(
            "PTY relay (`pocketshell rc` exposed sessions) is not supported on this platform"
                .to_string(),
        ))
    }

    fn create_session_with_command(
        &mut self,
        session_id: String,
        program: &str,
        args: &[&str],
        cols: u16,
        rows: u16,
        persistent: bool,
        tmux_session_name: Option<String>,
    ) -> Result<()> {
        if self.sessions.len() >= self.limit {
            return Err(HostError::Pty(format!(
                "session limit reached ({})",
                self.limit
            )));
        }
        if self.sessions.contains_key(&session_id) {
            return Err(HostError::Pty(format!(
                "session already exists: {session_id}"
            )));
        }

        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| HostError::Pty(format!("openpty failed: {e}")))?;

        let mut cmd = CommandBuilder::new(program);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env(REMOTE_TERMINAL_ENV, "1");

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| HostError::Pty(format!("spawn shell failed: {e}")))?;
        let root_pid = child.process_id();

        // Assign the freshly spawned child to the kill-on-close job object so
        // an ungraceful daemon death can't leave an orphaned, spinning conhost
        // behind. Best-effort and Windows-only; a no-op elsewhere.
        #[cfg(windows)]
        if let Some(job) = &self.job {
            if let Some(h) = child.as_raw_handle() {
                job.assign(h);
            }
        }

        let child = Arc::new(Mutex::new(child));
        let scrollback = Arc::new(Mutex::new(VecDeque::new()));
        let reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| HostError::Pty(format!("clone reader failed: {e}")))?;
        let mut writer = pair.master.take_writer().map_err(|e| {
            HostError::Pty(format!(
                "failed to take PTY writer for session {session_id}: {e}"
            ))
        })?;

        let master = Arc::new(Mutex::new(pair.master));
        let stop = Arc::new(AtomicBool::new(false));
        let attention = Arc::new(Mutex::new(AttentionTracker::new(
            DEFAULT_QUIET_PERIOD,
            session_id.clone(),
        )));

        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>();
        let (output_tx, output_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(1024);
        // Passive mirror fed every PTY byte (see terminal::TerminalMirror) so we
        // can serve a canonical screen snapshot on resume.
        let mirror = Arc::new(Mutex::new(TerminalMirror::new(cols, rows)));

        {
            let stop = Arc::clone(&stop);
            let master = Arc::clone(&master);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match input_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(data) => {
                            let _ = writer.write_all(&data);
                            let _ = writer.flush();
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }

                    // Drain any pending resizes (apply the latest one)
                    let mut last_resize = None;
                    while let Ok(size) = resize_rx.try_recv() {
                        last_resize = Some(size);
                    }
                    if let Some((next_cols, next_rows)) = last_resize {
                        if let Ok(m) = master.lock() {
                            let _ = m.resize(PtySize {
                                rows: next_rows,
                                cols: next_cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                    }
                }
            });
        }

        spawn_pty_reader_thread(
            reader,
            Arc::clone(&stop),
            Arc::clone(&scrollback),
            Arc::clone(&attention),
            Arc::clone(&mirror),
            output_tx,
            input_tx.clone(),
        );

        // Windows/ConPTY only: kick the pseudoconsole so it flushes the initial
        // prompt frame into the read pipe instead of staying blank until a
        // manual reconnect. No-op elsewhere.
        #[cfg(windows)]
        nudge_conpty_initial_frame(Arc::clone(&master), Arc::clone(&stop), cols, rows);

        self.sessions.insert(
            session_id,
            PtySession {
                input_tx,
                resize_tx,
                output_rx,
                stop,
                child,
                root_pid,
                scrollback,
                persistent,
                tmux_session_name,
                attention,
                mirror,
            },
        );

        Ok(())
    }

    pub fn write_input(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;
        // Mark this session as user-engaged so the attention detector knows
        // subsequent output bursts are tied to a real user action. Without
        // this, agent chatter (recap banners, idle spinners) wouldn't be
        // distinguishable from real "your command is done" silence.
        if let Ok(mut tracker) = session.attention.lock() {
            tracker.note_user_input(&bytes, Instant::now());
        }
        session
            .input_tx
            .send(bytes)
            .map_err(|e| HostError::Pty(format!("send input failed: {e}")))
    }

    pub fn resize(&self, session_id: &str, cols: u16, rows: u16) -> Result<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;
        // Keep the snapshot mirror's dimensions in lock-step with the PTY so a
        // resume taken after a resize reflows at the correct width.
        if let Ok(mut mir) = session.mirror.lock() {
            mir.resize(cols, rows);
        }
        session
            .resize_tx
            .send((cols, rows))
            .map_err(|e| HostError::Pty(format!("resize failed: {e}")))
    }

    pub fn drain_output(&self) -> Vec<SessionOutputChunk> {
        let mut out = Vec::new();
        for (session_id, session) in &self.sessions {
            while let Ok((offset, bytes)) = session.output_rx.try_recv() {
                out.push(SessionOutputChunk {
                    session_id: session_id.clone(),
                    offset,
                    bytes,
                });
            }
        }
        out
    }

    /// Pull any debounce-elapsed attention events across all sessions.
    ///
    /// Returns at most one event per session per call (the next pending one
    /// in queue), matching how `AttentionDebouncer` holds a single pending
    /// event at a time. Called from the daemon's output tick.
    pub fn drain_attention(&self, now: Instant) -> Vec<SessionAttentionEvent> {
        let mut out = Vec::new();
        for (session_id, session) in &self.sessions {
            if let Ok(mut tracker) = session.attention.lock() {
                if let Some(pending) = tracker.take_ready(now) {
                    let process = detect_foreground_process(session.root_pid);
                    out.push(SessionAttentionEvent::from_pending(
                        session_id.clone(),
                        pending,
                        process,
                    ));
                }
            }
        }
        out
    }

    /// Reap sessions whose underlying child process has exited.
    pub fn reap_exited_sessions(&mut self) -> Vec<String> {
        let mut ended = Vec::new();
        let ids: Vec<String> = self.sessions.keys().cloned().collect();

        for session_id in ids {
            let exited = self
                .sessions
                .get(&session_id)
                .and_then(|session| {
                    session
                        .child
                        .lock()
                        .ok()
                        .and_then(|mut child| child.try_wait().ok().flatten())
                })
                .is_some();

            if !exited {
                continue;
            }

            if self.close_session(&session_id).is_ok() {
                ended.push(session_id);
            }
        }

        ended
    }

    /// Detach a persistent session without stopping the PTY or clearing scrollback.
    /// For non-persistent sessions, this falls through to close_session.
    pub fn detach_session(&mut self, session_id: &str) -> Result<bool> {
        let is_persistent = self
            .sessions
            .get(session_id)
            .map_or(false, |s| s.persistent);
        if !is_persistent {
            self.close_session(session_id)?;
            return Ok(false);
        }

        if !self.sessions.contains_key(session_id) {
            return Err(HostError::Pty(format!("unknown session: {session_id}")));
        }

        Ok(true)
    }

    /// Detach all sessions. Persistent sessions keep their PTYs alive.
    /// Returns list of session IDs that were detached and remain resumable.
    pub fn detach_all(&mut self) -> Vec<String> {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        let mut detached = Vec::new();
        for id in ids {
            match self.detach_session(&id) {
                Ok(true) => detached.push(id),
                _ => {}
            }
        }
        detached
    }

    pub fn close_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;

        session.stop.store(true, Ordering::Relaxed);
        if let Ok(mut child) = session.child.lock() {
            let _ = child.kill();
            // Only wait on real processes — DummyChild has no process_id
            if child.process_id().is_some() {
                let _ = child.wait();
            }
        }

        // If persistent, also kill the tmux server session
        if let Some(ref tmux_name) = session.tmux_session_name {
            let _ = std::process::Command::new("tmux")
                .args(["kill-session", "-t", tmux_name])
                .status();
        }

        Ok(())
    }

    pub fn close_sessions_for_device(&mut self, _device_id: &str) {
        // In v1, device ownership is tracked by daemon state; revoke closes all active sessions.
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            let _ = self.close_session(&id);
        }
    }

    pub fn close_all(&mut self) {
        let ids: Vec<String> = self.sessions.keys().cloned().collect();
        for id in ids {
            let _ = self.close_session(&id);
        }
    }
}

fn append_scrollback(scrollback: &mut VecDeque<u8>, chunk: &[u8]) {
    scrollback.extend(chunk.iter().copied());
    if scrollback.len() > MAX_SCROLLBACK_BYTES {
        let overflow = scrollback.len() - MAX_SCROLLBACK_BYTES;
        drop(scrollback.drain(..overflow));
    }
}

/// Force a freshly-created Windows ConPTY to emit its initial frame (the shell
/// prompt). A new pseudoconsole frequently won't flush its first frame until it
/// receives a resize it actually honors, and a resize landing too close to the
/// client attach is dropped (microsoft/terminal#10400). portable-pty also
/// doesn't set `PSEUDOCONSOLE_RESIZE_QUIRK`, so a size change forces a full
/// buffer repaint. We nudge the size (a transient +1-row wiggle) shortly after
/// spawn so the prompt lands in the read pipe → the mirror + live stream,
/// instead of the terminal staying blank until a manual reconnect. Only invoked
/// on Windows (Unix PTYs emit immediately); the body is platform-agnostic so it
/// type-checks on every target.
#[cfg_attr(not(windows), allow(dead_code))]
fn nudge_conpty_initial_frame(
    master: Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>,
    stop: Arc<AtomicBool>,
    cols: u16,
    rows: u16,
) {
    if cols == 0 || rows == 0 {
        return;
    }
    thread::spawn(move || {
        let resize_to = |r: u16| {
            if let Ok(m) = master.lock() {
                let _ = m.resize(PtySize {
                    rows: r,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                });
            }
        };
        // Wait past the attach window (and give the shell time to print its
        // prompt into ConPTY's buffer), then wiggle the row count to force a
        // repaint, then restore. The client's own resize settles the final size.
        thread::sleep(Duration::from_millis(500));
        if stop.load(Ordering::Relaxed) {
            return;
        }
        resize_to(rows.saturating_add(1));
        thread::sleep(Duration::from_millis(60));
        if stop.load(Ordering::Relaxed) {
            return;
        }
        resize_to(rows);
        tracing::info!("conpty: applied initial-frame nudge for fresh session");
    });
}

/// Read PTY output in a dedicated thread: append to scrollback, feed the
/// attention parser, feed the headless terminal mirror, and forward to the
/// daemon's output channel. Used by both native and relay session paths.
///
/// `output_tx` is a bounded `SyncSender`; when the daemon falls behind, `send`
/// blocks here, which stalls the read loop and propagates backpressure to the
/// PTY (the child blocks on write) rather than dropping output.
fn spawn_pty_reader_thread<R: Read + Send + 'static>(
    mut reader: R,
    stop: Arc<AtomicBool>,
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    attention: Arc<Mutex<AttentionTracker>>,
    mirror: Arc<Mutex<TerminalMirror>>,
    output_tx: mpsc::SyncSender<(u64, Vec<u8>)>,
    // Back-channel to the PTY's input writer. The mirror answers device queries
    // (e.g. PowerShell's `\x1b[6n` cursor-position request) and those replies are
    // written here so query-driven shells unblock and render their prompt.
    reply_tx: mpsc::Sender<Vec<u8>>,
) {
    thread::spawn(move || {
        let mut buf = vec![0_u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];
                    if let Ok(mut stored) = scrollback.lock() {
                        append_scrollback(&mut stored, chunk);
                    }
                    if let Ok(mut tracker) = attention.lock() {
                        tracker.on_bytes(chunk, Instant::now());
                    }
                    // Read the chunk's absolute start offset under the SAME lock
                    // that folds it into the mirror, so it matches a snapshot cut
                    // at this instant: base_offset == bytes_fed BEFORE this feed.
                    // Capture and feed cannot interleave within one chunk, so live
                    // offsets are strictly contiguous with the snapshot boundary.
                    let (offset, replies) = if let Ok(mut mir) = mirror.lock() {
                        let off = mir.bytes_fed();
                        mir.feed(chunk);
                        // Drain under the same lock so a reply can't be split across
                        // two feeds: the emulator generated it from exactly the bytes
                        // just fed.
                        (off, mir.take_replies())
                    } else {
                        // Mirror lock poisoned (alacritty panicked): emit a sentinel
                        // so the client treats this frame as untagged / always-apply
                        // rather than mis-deduping against a wrong offset.
                        (u64::MAX, Vec::new())
                    };
                    // Write any device-query replies (cursor-position report, device
                    // attributes, …) back to the PTY — Windows only. PowerShell/
                    // PSReadLine blocks on its `\x1b[6n` query before drawing the
                    // prompt, and the pure-viewer mobile can't reliably answer
                    // (deduped on resume / suppressed during snapshot apply), so the
                    // host must. On macOS/Linux the shell doesn't gate its prompt on
                    // the reply AND the mobile xterm.js already answers, so writing
                    // here too would double the report and leak stray input — keep the
                    // existing (client-answers) behavior there. `take_replies` is still
                    // drained above on every platform so the buffer can't grow.
                    #[cfg(windows)]
                    if !replies.is_empty() {
                        let _ = reply_tx.send(replies);
                    }
                    #[cfg(not(windows))]
                    let _ = (&reply_tx, replies);
                    let _ = output_tx.send((offset, chunk.to_vec()));
                }
                Err(_) => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{append_scrollback, SessionManager, MAX_SCROLLBACK_BYTES};
    use std::collections::VecDeque;

    #[test]
    fn scrollback_trims_oldest_bytes() {
        let mut scrollback: VecDeque<u8> = VecDeque::from(vec![b'a'; MAX_SCROLLBACK_BYTES - 2]);
        append_scrollback(&mut scrollback, b"bcdef");

        assert_eq!(scrollback.len(), MAX_SCROLLBACK_BYTES);
        let v: Vec<u8> = scrollback.iter().copied().collect();
        assert_eq!(&v[..4], b"aaaa");
        assert_eq!(&v[v.len() - 4..], b"cdef");
    }

    #[test]
    fn scrollback_appends_below_limit_without_trim() {
        let mut scrollback: VecDeque<u8> = VecDeque::new();
        append_scrollback(&mut scrollback, b"hello");
        append_scrollback(&mut scrollback, b" world");
        assert_eq!(scrollback.len(), 11);
        let v: Vec<u8> = scrollback.iter().copied().collect();
        assert_eq!(&v, b"hello world");
    }

    #[test]
    fn validate_session_name_accepts_allowed_chars() {
        assert!(SessionManager::validate_session_name("abc").is_ok());
        assert!(SessionManager::validate_session_name("My-Session_1.2:tab/left+x@host,y").is_ok());
        assert!(SessionManager::validate_session_name("UPPERCASE123").is_ok());
    }

    #[test]
    fn validate_session_name_rejects_empty() {
        assert!(SessionManager::validate_session_name("").is_err());
    }

    #[test]
    fn validate_session_name_rejects_too_long() {
        let long = "a".repeat(257);
        assert!(SessionManager::validate_session_name(&long).is_err());
    }

    #[test]
    fn validate_session_name_rejects_shell_metacharacters() {
        for bad in &[
            "evil;rm", "a|b", "a&b", "$(x)", "`x`", "a b", "a'b", "a\"b", "a\\b", "a(b", "a>b",
            "a<b", "a!b", "a?b", "a*b", "a~b", "a#b", "a\nb",
        ] {
            assert!(
                SessionManager::validate_session_name(bad).is_err(),
                "expected {:?} to be rejected",
                bad
            );
        }
    }

    #[test]
    fn new_manager_is_empty() {
        let m = SessionManager::new(4);
        assert_eq!(m.active_count(), 0);
        assert!(!m.is_active("anything"));
        assert!(!m.is_persistent("anything"));
        assert!(m.tmux_session_name("anything").is_none());
    }

    #[test]
    fn reconnect_session_unknown_errors() {
        let mut m = SessionManager::new(4);
        let err = m.reconnect_session("no-such".into(), 80, 24);
        assert!(err.is_err());
        let msg = format!("{:?}", err.unwrap_err());
        assert!(msg.contains("no-such"));
    }

    #[test]
    fn close_session_unknown_errors() {
        let mut m = SessionManager::new(4);
        assert!(m.close_session("nope").is_err());
    }

    #[test]
    fn write_input_unknown_errors() {
        let m = SessionManager::new(4);
        assert!(m.write_input("nope", vec![1, 2, 3]).is_err());
    }

    #[test]
    fn resize_unknown_errors() {
        let m = SessionManager::new(4);
        assert!(m.resize("nope", 80, 24).is_err());
    }

    #[test]
    fn capture_scrollback_unknown_errors() {
        let m = SessionManager::new(4);
        assert!(m.capture_scrollback("nope").is_err());
    }

    #[test]
    fn create_attached_session_unsupported_type_errors() {
        let mut m = SessionManager::new(4);
        let err = m
            .create_attached_session("s1".into(), "weird", "target", 80, 24)
            .unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("unsupported session type"));
        assert_eq!(m.active_count(), 0);
    }

    #[test]
    fn create_attached_tmux_validates_name() {
        let mut m = SessionManager::new(4);
        // Shell metacharacter must be rejected BEFORE any tmux spawn attempt.
        let err = m
            .create_attached_session("s1".into(), "tmux", "evil;rm", 80, 24)
            .unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("invalid characters"));
        assert_eq!(m.active_count(), 0);
    }

    #[test]
    fn create_attached_pocketshell_missing_errors() {
        // "pocketshell" type dispatches to reconnect_session which fails for
        // unknown ids — gives us coverage of the branch without spawning a PTY.
        let mut m = SessionManager::new(4);
        let err = m
            .create_attached_session("s1".into(), "pocketshell", "missing-id", 80, 24)
            .unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("missing-id"));
    }

    #[test]
    fn create_pty_relay_empty_path_errors() {
        let mut m = SessionManager::new(4);
        assert!(m.create_pty_relay_session("s1".into(), "").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_pty_relay_nonexistent_path_errors() {
        let mut m = SessionManager::new(4);
        let err = m
            .create_pty_relay_session("s1".into(), "/dev/definitely-not-a-real-pty-xyz-9999")
            .unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("cannot resolve PTY path") || msg.contains("PTY path"));
    }

    #[test]
    fn detach_nonexistent_session_errors() {
        let mut m = SessionManager::new(4);
        assert!(m.detach_session("no-such").is_err());
    }

    #[test]
    fn detach_all_on_empty_returns_empty() {
        let mut m = SessionManager::new(4);
        let detached = m.detach_all();
        assert!(detached.is_empty());
    }

    #[test]
    fn reap_exited_on_empty_returns_empty() {
        let mut m = SessionManager::new(4);
        assert!(m.reap_exited_sessions().is_empty());
    }

    #[test]
    fn close_all_on_empty_is_noop() {
        let mut m = SessionManager::new(4);
        m.close_all();
        assert_eq!(m.active_count(), 0);
    }

    #[test]
    fn drain_output_on_empty_returns_empty() {
        let m = SessionManager::new(4);
        assert!(m.drain_output().is_empty());
    }
}
