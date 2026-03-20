use crate::error::{HostError, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

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
}

pub struct SessionOutputChunk {
    pub session_id: String,
    pub bytes: Vec<u8>,
}

struct PtySession {
    input_tx: mpsc::Sender<Vec<u8>>,
    resize_tx: mpsc::Sender<(u16, u16)>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    stop: Arc<AtomicBool>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    /// Whether this session is backed by a persistent tmux session.
    persistent: bool,
    /// The tmux session name (e.g. "ps-{session_id}") if persistent.
    tmux_session_name: Option<String>,
}

pub struct SessionManager {
    sessions: HashMap<String, PtySession>,
    limit: usize,
    has_tmux: bool,
}

impl SessionManager {
    pub fn new(limit: usize, has_tmux: bool) -> Self {
        Self {
            sessions: HashMap::new(),
            limit,
            has_tmux,
        }
    }

    pub fn has_tmux(&self) -> bool {
        self.has_tmux
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
        if self.has_tmux {
            self.create_tmux_backed_session(session_id, shell, cols, rows)
        } else {
            self.create_session_with_command(session_id, shell, &[], cols, rows, false, None)
        }
    }

    /// Create a persistent session backed by a tmux server session.
    /// The tmux session survives disconnects; we attach a PTY to it for I/O.
    fn create_tmux_backed_session(
        &mut self,
        session_id: String,
        shell: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let tmux_name = format!("ps-{session_id}");

        // Create a detached tmux session
        let status = std::process::Command::new("tmux")
            .args(["new-session", "-d", "-s", &tmux_name, "-x", &cols.to_string(), "-y", &rows.to_string(), shell])
            .status()
            .map_err(|e| HostError::Pty(format!("tmux new-session failed: {e}")))?;

        if !status.success() {
            return Err(HostError::Pty(format!("tmux new-session exited with {status}")));
        }

        // Now attach to it via the existing tmux attach path
        let tmux_name_clone = tmux_name.clone();
        self.create_session_with_command(
            session_id,
            "tmux",
            &["attach-session", "-t", &tmux_name],
            cols,
            rows,
            true,
            Some(tmux_name_clone),
        )
    }

    /// Reconnect to an existing persistent tmux session.
    pub fn reconnect_session(
        &mut self,
        session_id: String,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let tmux_name = format!("ps-{session_id}");

        // Check tmux session still exists
        let status = std::process::Command::new("tmux")
            .args(["has-session", "-t", &tmux_name])
            .status()
            .map_err(|e| HostError::Pty(format!("tmux has-session failed: {e}")))?;

        if !status.success() {
            return Err(HostError::Pty(format!("tmux session {tmux_name} no longer exists")));
        }

        // Attach to it
        let tmux_name_clone = tmux_name.clone();
        self.create_session_with_command(
            session_id,
            "tmux",
            &["attach-session", "-t", &tmux_name],
            cols,
            rows,
            true,
            Some(tmux_name_clone),
        )
    }

    /// Capture scrollback from a persistent tmux session for replay.
    pub fn capture_scrollback(session_id: &str) -> Result<Vec<u8>> {
        let tmux_name = format!("ps-{session_id}");
        let output = std::process::Command::new("tmux")
            .args(["capture-pane", "-t", &tmux_name, "-p", "-S", "-1000"])
            .output()
            .map_err(|e| HostError::Pty(format!("tmux capture-pane failed: {e}")))?;

        if !output.status.success() {
            return Err(HostError::Pty(format!("tmux capture-pane exited with {}", output.status)));
        }

        Ok(output.stdout)
    }

    /// Check if a session is persistent (tmux-backed).
    pub fn is_persistent(&self, session_id: &str) -> bool {
        self.sessions.get(session_id).map_or(false, |s| s.persistent)
    }

    /// Get the tmux session name for a session.
    pub fn tmux_session_name(&self, session_id: &str) -> Option<String> {
        self.sessions.get(session_id).and_then(|s| s.tmux_session_name.clone())
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
            // "pocketshell" type — reconnect to a ps-{name} persistent tmux session
            "pocketshell" => {
                let tmux_name = format!("ps-{target_name}");
                let tmux_name_clone = tmux_name.clone();
                self.create_session_with_command(
                    session_id,
                    "tmux",
                    &["attach-session", "-t", &tmux_name],
                    cols,
                    rows,
                    true,
                    Some(tmux_name_clone),
                )
            }
            // "shell" type from `pocketshell rc` — attach to existing PTY device
            "shell" => self.create_pty_relay_session(session_id, target_name),
            _ => Err(HostError::Pty(format!("unsupported session type: {session_type}"))),
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
    pub fn create_pty_relay_session(
        &mut self,
        session_id: String,
        pty_path: &str,
    ) -> Result<()> {
        use std::fs::OpenOptions;

        if self.sessions.len() >= self.limit {
            return Err(HostError::Pty(format!("session limit reached ({})", self.limit)));
        }
        if self.sessions.contains_key(&session_id) {
            return Err(HostError::Pty(format!("session already exists: {session_id}")));
        }
        if pty_path.is_empty() {
            return Err(HostError::Pty("no PTY path for exposed session".to_string()));
        }

        let pty_read = OpenOptions::new()
            .read(true)
            .open(pty_path)
            .map_err(|e| HostError::Pty(format!("open PTY {pty_path} for read: {e}")))?;
        let mut pty_write = OpenOptions::new()
            .write(true)
            .open(pty_path)
            .map_err(|e| HostError::Pty(format!("open PTY {pty_path} for write: {e}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, _resize_rx) = mpsc::channel::<(u16, u16)>();
        let (output_tx, output_rx) = mpsc::sync_channel::<Vec<u8>>(1024);

        // Writer thread — sends mobile input to the host's PTY
        {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(data) = input_rx.try_recv() {
                        let _ = pty_write.write_all(&data);
                        let _ = pty_write.flush();
                    }
                    thread::sleep(Duration::from_millis(8));
                }
            });
        }

        // Reader thread — reads host PTY output and sends to mobile
        {
            let stop = Arc::clone(&stop);
            let mut reader = pty_read;
            thread::spawn(move || {
                let mut buf = vec![0_u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = output_tx.send(buf[..n].to_vec());
                        }
                        Err(_) => break,
                    }
                }
            });
        }

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
                persistent: false,
                tmux_session_name: None,
            },
        );

        Ok(())
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
            return Err(HostError::Pty(format!("session already exists: {session_id}")));
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

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| HostError::Pty(format!("spawn shell failed: {e}")))?;

        let child = Arc::new(Mutex::new(child));
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| HostError::Pty(format!("clone reader failed: {e}")))?;
        let mut writer = pair.master.take_writer().map_err(|e| {
            HostError::Pty(format!("failed to take PTY writer for session {session_id}: {e}"))
        })?;

        let master = Arc::new(Mutex::new(pair.master));
        let stop = Arc::new(AtomicBool::new(false));

        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>();
        let (resize_tx, resize_rx) = mpsc::channel::<(u16, u16)>();
        let (output_tx, output_rx) = mpsc::sync_channel::<Vec<u8>>(1024);

        {
            let stop = Arc::clone(&stop);
            let master = Arc::clone(&master);
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(data) = input_rx.try_recv() {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }

                    if let Ok((next_cols, next_rows)) = resize_rx.try_recv() {
                        if let Ok(m) = master.lock() {
                            let _ = m.resize(PtySize {
                                rows: next_rows,
                                cols: next_cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            });
                        }
                    }

                    thread::sleep(Duration::from_millis(8));
                }
            });
        }

        {
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let mut buf = vec![0_u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let _ = output_tx.send(buf[..n].to_vec());
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        self.sessions.insert(
            session_id,
            PtySession {
                input_tx,
                resize_tx,
                output_rx,
                stop,
                child,
                persistent,
                tmux_session_name,
            },
        );

        Ok(())
    }

    pub fn write_input(&self, session_id: &str, bytes: Vec<u8>) -> Result<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;
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
        session
            .resize_tx
            .send((cols, rows))
            .map_err(|e| HostError::Pty(format!("resize failed: {e}")))
    }

    pub fn drain_output(&self) -> Vec<SessionOutputChunk> {
        let mut out = Vec::new();
        for (session_id, session) in &self.sessions {
            while let Ok(bytes) = session.output_rx.try_recv() {
                out.push(SessionOutputChunk {
                    session_id: session_id.clone(),
                    bytes,
                });
            }
        }
        out
    }

    /// Detach a persistent session: stop I/O threads but keep the tmux session alive.
    /// For non-persistent sessions, this falls through to close_session.
    pub fn detach_session(&mut self, session_id: &str) -> Result<bool> {
        let is_persistent = self.sessions.get(session_id).map_or(false, |s| s.persistent);
        if !is_persistent {
            self.close_session(session_id)?;
            return Ok(false);
        }

        let session = self
            .sessions
            .remove(session_id)
            .ok_or_else(|| HostError::Pty(format!("unknown session: {session_id}")))?;

        // Stop I/O threads — the tmux server session keeps running independently
        session.stop.store(true, Ordering::Relaxed);
        // Kill the `tmux attach` child process (not the tmux server session)
        if let Ok(mut child) = session.child.lock() {
            let _ = child.kill();
            if child.process_id().is_some() {
                let _ = child.wait();
            }
        }

        Ok(true) // persistent — tmux session still alive
    }

    /// Detach all sessions. Persistent sessions keep their tmux alive.
    /// Returns list of session IDs that were detached (persistent, still alive).
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
