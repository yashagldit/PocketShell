//! [`TerminalMirror`] — a passive headless terminal emulator.
//!
//! Wraps `alacritty_terminal`'s `Term` + the `vte` ANSI `Processor`. The daemon
//! feeds it every byte the PTY produces (via [`TerminalMirror::feed`]); it parses
//! those bytes into the authoritative screen + scrollback grid. On resume the
//! daemon asks it for a [`Snapshot`](super::Snapshot) of the current screen.
//!
//! It is intentionally output-only: the emulator's `EventListener` is a
//! [`VoidListener`], so any `PtyWrite` the emulation would normally bounce back
//! to the application is **dropped**. The mobile xterm.js is the real terminal
//! and answers those queries itself — letting the mirror reply too would inject
//! duplicate bytes into the PTY's input.

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::Processor;

use super::Snapshot;

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
    term: Term<VoidListener>,
    parser: Processor,
    cols: usize,
    lines: usize,
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
        let term = Term::new(config, &MirrorSize { cols, lines }, VoidListener);

        Self {
            term,
            parser: Processor::new(),
            cols,
            lines,
        }
    }

    /// Feed a chunk of raw PTY output through the emulator. This is the single
    /// place PTY bytes mutate mirror state; call it for every chunk, in order.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.parser.advance(&mut self.term, bytes);
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
        Snapshot::capture(&self.term)
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
