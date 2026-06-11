//! [`TerminalMirror`] — a passive headless terminal emulator.
//!
//! Wraps `alacritty_terminal`'s `Term` + the `vte` ANSI `Processor`. The daemon
//! feeds it every byte the PTY produces (via [`TerminalMirror::feed`]); it parses
//! those bytes into the authoritative screen + scrollback grid. On resume the
//! daemon asks it for a [`Snapshot`](super::Snapshot) of the current screen.
//!
//! The emulator **answers device queries authoritatively**. Its `EventListener`
//! ([`QueryResponder`]) captures any `PtyWrite` the emulation bounces back —
//! cursor-position reports (CPR, answering `\x1b[6n`), device-attributes (DA),
//! status reports — into a buffer the daemon drains via [`TerminalMirror::take_replies`]
//! and writes to the real PTY. This is load-bearing on Windows: PowerShell /
//! PSReadLine emits `\x1b[6n` and **blocks on the reply before drawing its
//! prompt**. The mobile xterm.js is a pure viewer and cannot reliably answer
//! (the query byte is deduped away on resume and suppressed during snapshot
//! apply), so without the host answering the terminal stays blank. (bash/zsh on
//! a Unix host don't gate the prompt on this, which is why it was Windows-only.)
//! The mirror still never writes anything *unsolicited* to the PTY — it only
//! emits the exact reply a real terminal would for a query the app itself sent.

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::Processor;
use std::sync::{Arc, Mutex};

use super::snapshot::{Snapshot, SNAPSHOT_BYTE_BUDGET};

/// `EventListener` that captures the emulator's outbound PTY writes (replies the
/// emulation generates for device-status / cursor-position / device-attributes
/// queries) into a shared buffer, so the daemon can feed them back to the real
/// PTY. See the module docs for why this is essential on Windows.
#[derive(Clone, Default)]
struct QueryResponder {
    pending: Arc<Mutex<Vec<u8>>>,
}

impl EventListener for QueryResponder {
    fn send_event(&self, event: Event) {
        // Only `PtyWrite` carries bytes destined for the application; every other
        // event (title changes, bells, clipboard, color requests, …) is screen
        // state we don't bounce back. A poisoned lock just drops the reply — the
        // shell falls back to its query timeout, same as before this existed.
        if let Event::PtyWrite(text) = event {
            if let Ok(mut buf) = self.pending.lock() {
                buf.extend_from_slice(text.as_bytes());
            }
        }
    }
}

/// Default scrollback retained by the mirror, in lines. Generous on purpose:
/// the whole point is "come back later and see everything Claude did". The grid
/// stores rendered lines (not raw bytes), so this is bounded, predictable memory
/// (~a few hundred bytes/line worst case).
pub const DEFAULT_SCROLLBACK_LINES: usize = 10_000;

/// Viewport dimensions handed to `alacritty_terminal`.
///
/// `total_lines == screen_lines` here because the scrollback capacity is
/// configured separately via [`Config::scrolling_history`]; the `Dimensions`
/// value passed to `Term::new`/`Term::resize` only describes the visible area.
#[derive(Clone, Copy)]
struct MirrorSize {
    cols: usize,
    lines: usize,
}

impl Dimensions for MirrorSize {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// A headless terminal emulator mirroring one PTY's output stream.
pub struct TerminalMirror {
    term: Term<QueryResponder>,
    parser: Processor,
    cols: usize,
    lines: usize,
    /// Absolute count of bytes fed through the emulator since creation. Doubles
    /// as the live output stream offset: a snapshot taken now has
    /// `base_offset == bytes_fed`, and live frames produced after carry offsets
    /// ≥ that value, making the snapshot→live seam dedupable on the client.
    bytes_fed: u64,
    /// Shared with the `Term`'s [`QueryResponder`]; accumulates query replies the
    /// emulator produced during `feed`, drained by [`Self::take_replies`].
    replies: Arc<Mutex<Vec<u8>>>,
}

impl TerminalMirror {
    /// Create a mirror sized to the PTY's initial dimensions.
    pub fn new(cols: u16, rows: u16) -> Self {
        Self::with_scrollback(cols, rows, DEFAULT_SCROLLBACK_LINES)
    }

    /// Create a mirror with an explicit scrollback line budget.
    pub fn with_scrollback(cols: u16, rows: u16, scrollback_lines: usize) -> Self {
        // alacritty enforces a minimum grid size; clamp defensively so a stray
        // 0×0 resize from the client can never panic the emulator.
        let cols = (cols as usize).max(2);
        let lines = (rows as usize).max(1);

        let config = Config {
            scrolling_history: scrollback_lines,
            ..Config::default()
        };
        let replies = Arc::new(Mutex::new(Vec::new()));
        let responder = QueryResponder {
            pending: Arc::clone(&replies),
        };
        let term = Term::new(config, &MirrorSize { cols, lines }, responder);

        Self {
            term,
            parser: Processor::new(),
            cols,
            lines,
            bytes_fed: 0,
            replies,
        }
    }

    /// Feed a chunk of raw PTY output through the emulator. This is the single
    /// place PTY bytes mutate mirror state; call it for every chunk, in order.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
        self.bytes_fed += bytes.len() as u64;
    }

    /// Absolute count of bytes fed so far — the current live stream offset.
    pub fn bytes_fed(&self) -> u64 {
        self.bytes_fed
    }

    /// Drain any query replies the emulator produced while parsing fed bytes
    /// (cursor-position reports, device attributes, status reports). The caller
    /// MUST write these back to the PTY so query-driven shells — notably
    /// PowerShell/PSReadLine, which blocks on the `\x1b[6n` cursor-position
    /// reply before drawing its prompt — unblock instead of hanging blank.
    /// Returns empty when the app sent no query (the common case).
    pub fn take_replies(&self) -> Vec<u8> {
        self.replies
            .lock()
            .map(|mut b| std::mem::take(&mut *b))
            .unwrap_or_default()
    }

    /// Resize the emulated screen. No-op when dimensions are unchanged.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = (cols as usize).max(2);
        let lines = (rows as usize).max(1);
        if cols == self.cols && lines == self.lines {
            return;
        }
        self.cols = cols;
        self.lines = lines;
        self.term.resize(MirrorSize { cols, lines });
    }

    /// Capture the current visible screen as a restorable [`Snapshot`].
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::capture(&self.term, self.bytes_fed, SNAPSHOT_BYTE_BUDGET)
    }

    /// Visible screen width in columns.
    pub fn cols(&self) -> u16 {
        self.cols as u16
    }

    /// Visible screen height in rows.
    pub fn rows(&self) -> u16 {
        self.lines as u16
    }

    /// Whether the alternate screen buffer is currently active (vim, less, a
    /// full-screen TUI). Useful telemetry; the snapshot already encodes it.
    pub fn is_alt_screen(&self) -> bool {
        self.term.mode().contains(TermMode::ALT_SCREEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_and_dimensions() {
        let mut m = TerminalMirror::new(80, 24);
        assert_eq!(m.cols(), 80);
        assert_eq!(m.rows(), 24);
        m.feed(b"hello world");
        assert!(!m.is_alt_screen());
    }

    #[test]
    fn answers_cursor_position_query() {
        let mut m = TerminalMirror::new(80, 24);
        // PowerShell/PSReadLine sends a DSR cursor-position request and blocks on
        // the reply. The mirror must answer it (a real terminal would).
        m.feed(b"\x1b[6n");
        let reply = m.take_replies();
        assert!(!reply.is_empty(), "mirror must answer \\x1b[6n");
        assert_eq!(reply[0], 0x1b, "CPR reply starts with ESC");
        assert!(
            reply.ends_with(b"R"),
            "CPR reply ends with R, got {:?}",
            reply.escape_ascii().to_string()
        );
        // Replies are drained, not re-emitted.
        assert!(m.take_replies().is_empty());
    }

    #[test]
    fn no_reply_without_query() {
        let mut m = TerminalMirror::new(80, 24);
        m.feed(b"just some plain prompt text $ ");
        assert!(
            m.take_replies().is_empty(),
            "ordinary output must not generate PTY writes"
        );
    }

    #[test]
    fn alt_screen_detected() {
        let mut m = TerminalMirror::new(80, 24);
        m.feed(b"\x1b[?1049h");
        assert!(m.is_alt_screen());
        m.feed(b"\x1b[?1049l");
        assert!(!m.is_alt_screen());
    }

    #[test]
    fn resize_clamps_degenerate_dimensions() {
        let mut m = TerminalMirror::new(80, 24);
        // Must not panic on a 0×0 resize; clamps to the enforced minimum.
        m.resize(0, 0);
        assert_eq!(m.cols(), 2);
        assert_eq!(m.rows(), 1);
        m.resize(120, 40);
        assert_eq!(m.cols(), 120);
        assert_eq!(m.rows(), 40);
    }
}
