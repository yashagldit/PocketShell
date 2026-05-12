//! Streaming detector for terminal "attention" signals on a PTY output stream.
//!
//! Two signals are surfaced, both opt-in for the user/shell:
//!
//! * **OSC 133** shell-integration marks (`ESC ] 133 ; <kind> [ ; <args> ] <ST>`),
//!   the same marks used by VS Code, iTerm2, WezTerm, and Kitty. When a shell
//!   is configured to emit them, every command is bracketed and we get a
//!   reliable "command finished" event plus exit code.
//! * **Bare BEL** (`\x07`) outside any escape sequence. A CLI or script can
//!   call `printf '\a'` to ask the user to look at the terminal.
//!
//! The parser is a small byte-oriented state machine — it observes the stream
//! and returns events, it does not rewrite or strip bytes (xterm.js on the
//! mobile side still needs OSC 133 too).
//!
//! ## Why not a full ANSI parser?
//!
//! We only need to disambiguate three contexts:
//!
//! 1. Normal output: any `\x07` is a bell.
//! 2. Inside `ESC ]` (OSC string): bytes accumulate into a buffer until BEL or
//!    `ESC \` terminates the string. BEL here is **not** an attention signal.
//! 3. Inside `ESC` (waiting for next byte): if we see `\`, we end an OSC.
//!    Any other byte returns us to normal output.
//!
//! That's it. Other CSI/escape sequences pass through transparently because
//! `\x07` cannot appear inside them — CSI parameter and intermediate bytes
//! are restricted to `0x20..0x3F` plus a final byte in `0x40..0x7E`.

use std::time::{Duration, Instant};

/// Maximum bytes we'll buffer inside a single OSC sequence before giving up
/// and treating the stream as malformed. Real OSC 133 payloads are tiny
/// (`A`, `C`, `D;0`, `D;130`, etc.); 1 KiB is a very generous ceiling that
/// also caps memory use against an adversarial stream of unterminated OSCs.
const OSC_BUFFER_LIMIT: usize = 1024;

/// What a single `feed` call observed.
#[derive(Debug, Default)]
pub struct FeedResult {
    /// Signals detected during this call, in stream order.
    pub signals: Vec<AttentionSignal>,
    /// True iff at least one passthrough output byte appeared in this chunk
    /// after the final signal (or if the chunk was pure passthrough with no
    /// signals). Callers use this to drive `AttentionDebouncer::on_output`.
    pub trailing_passthrough: bool,
}

/// A signal extracted from the PTY byte stream worth surfacing to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttentionSignal {
    /// `ESC ] 133 ; A ST` — shell drew a fresh prompt. We treat this as
    /// "previous command completed" only if a `CommandStart` was seen earlier
    /// in this session; tracking that is the caller's job.
    PromptDrawn,
    /// `ESC ] 133 ; C ST` — a command began executing.
    CommandStart,
    /// `ESC ] 133 ; D [ ; <exit> ] ST` — a command finished. `exit` is
    /// `Some(code)` when the shell reported one.
    CommandDone { exit_code: Option<i32> },
    /// Bare `\x07` in normal output — explicit attention request.
    Bell,
}

/// State machine consuming PTY output bytes and yielding attention signals.
#[derive(Debug)]
pub struct MarkParser {
    state: ParseState,
    /// Holds the body of the current OSC string (everything after `ESC ]`,
    /// excluding the terminator). Reused across OSCs to avoid reallocation.
    osc_buf: Vec<u8>,
    /// True when `osc_buf` overflowed `OSC_BUFFER_LIMIT` for the current OSC;
    /// further bytes are dropped until the terminator arrives.
    osc_overflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Normal stream — accept bytes verbatim; `\x1b` enters Esc, `\x07` is a bell.
    Normal,
    /// Just saw `\x1b` in Normal — next byte decides what kind of escape.
    Esc,
    /// Inside `ESC ] ...` (OSC body) — accumulate until BEL or `ESC \`.
    Osc,
    /// Inside `ESC ] ...` and just saw `\x1b` — if next byte is `\`, OSC ends.
    OscEsc,
}

impl Default for MarkParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkParser {
    pub fn new() -> Self {
        Self {
            state: ParseState::Normal,
            osc_buf: Vec::with_capacity(32),
            osc_overflow: false,
        }
    }

    /// Feed a chunk of bytes and report any detected signals plus whether
    /// "passthrough" output bytes (normal terminal content, not part of any
    /// escape sequence) appeared after the *last* signal in this chunk.
    ///
    /// The `trailing_passthrough` flag is what lets the caller decide
    /// whether to call `AttentionDebouncer::on_output` to cancel a pending
    /// bell or push a `CommandDone` quiet window forward.
    ///
    /// Bytes are not consumed or rewritten — the same chunk should be
    /// forwarded to consumers (WebRTC, scrollback) unmodified.
    pub fn feed(&mut self, bytes: &[u8]) -> FeedResult {
        let mut result = FeedResult {
            signals: Vec::new(),
            trailing_passthrough: false,
        };
        for &b in bytes {
            let signals_before = result.signals.len();
            let was_passthrough = self.step(b, &mut result.signals);
            if result.signals.len() > signals_before {
                // A new signal resets the "trailing" window — anything that
                // came before it doesn't count anymore.
                result.trailing_passthrough = false;
            } else if was_passthrough {
                result.trailing_passthrough = true;
            }
        }
        result
    }

    /// Process one byte. Returns `true` iff the byte was a "passthrough"
    /// byte — normal terminal output, not part of any escape sequence and
    /// not a bare BEL. Bytes inside `ESC ] ... ST` and the framing bytes of
    /// escapes themselves are NOT passthrough.
    fn step(&mut self, b: u8, out: &mut Vec<AttentionSignal>) -> bool {
        match self.state {
            ParseState::Normal => match b {
                0x1b => {
                    self.state = ParseState::Esc;
                    false
                }
                0x07 => {
                    out.push(AttentionSignal::Bell);
                    false
                }
                _ => true,
            },
            ParseState::Esc => {
                match b {
                    b']' => {
                        self.state = ParseState::Osc;
                        self.osc_buf.clear();
                        self.osc_overflow = false;
                    }
                    // ESC followed by ESC: stay in Esc, waiting for a new dispatch.
                    0x1b => {}
                    _ => self.state = ParseState::Normal,
                }
                false
            }
            ParseState::Osc => {
                match b {
                    // BEL inside an OSC is the (xterm/legacy) terminator —
                    // NOT an attention bell.
                    0x07 => self.finish_osc(out),
                    0x1b => self.state = ParseState::OscEsc,
                    _ if self.osc_overflow => {}
                    _ if self.osc_buf.len() >= OSC_BUFFER_LIMIT => {
                        self.osc_overflow = true;
                    }
                    _ => self.osc_buf.push(b),
                }
                false
            }
            ParseState::OscEsc => {
                match b {
                    b'\\' => {
                        // ESC \\ is the canonical ST (String Terminator).
                        self.finish_osc(out);
                    }
                    _ => {
                        // ESC inside OSC followed by something else — most
                        // forgiving interpretation is to treat as still in
                        // OSC and keep accumulating. Real shells don't do this.
                        self.state = ParseState::Osc;
                    }
                }
                false
            }
        }
    }

    fn finish_osc(&mut self, out: &mut Vec<AttentionSignal>) {
        if !self.osc_overflow {
            if let Some(sig) = parse_osc_133(&self.osc_buf) {
                out.push(sig);
            }
        }
        self.osc_buf.clear();
        self.osc_overflow = false;
        self.state = ParseState::Normal;
    }

}

/// Parse the body of an OSC string (the bytes between `ESC ]` and the
/// terminator) and return a 133-flavored signal if it matches.
///
/// Accepted forms:
/// * `133;A` → `PromptDrawn`
/// * `133;C` (optionally with trailing `;...` parameters we ignore) → `CommandStart`
/// * `133;D` → `CommandDone { exit_code: None }`
/// * `133;D;<n>` → `CommandDone { exit_code: Some(n) }` when `<n>` parses
///
/// Anything else (other OSC numbers like `0` for title, `8` for hyperlinks,
/// `52` for clipboard, etc.) returns `None`.
fn parse_osc_133(body: &[u8]) -> Option<AttentionSignal> {
    let s = std::str::from_utf8(body).ok()?;
    let mut parts = s.split(';');
    if parts.next()? != "133" {
        return None;
    }
    let kind = parts.next()?;
    match kind {
        "A" => Some(AttentionSignal::PromptDrawn),
        "B" => None, // command-line start — not interesting
        "C" => Some(AttentionSignal::CommandStart),
        "D" => {
            let exit_code = parts
                .next()
                .and_then(|n| n.trim().parse::<i32>().ok());
            Some(AttentionSignal::CommandDone { exit_code })
        }
        _ => None,
    }
}

// ─── Debounce tracker ────────────────────────────────────────────────────────

/// Per-session debounce state: when a signal arrives we don't notify
/// immediately — we wait `quiet_period` of true silence (no new output, no
/// new signals) before firing. New output during the window cancels the
/// pending notification entirely; a new signal during the window resets the
/// timer and replaces the pending event with the latest one (e.g., a follow-up
/// `CommandDone` supersedes an earlier `PromptDrawn`).
#[derive(Debug)]
pub struct AttentionDebouncer {
    quiet_period: Duration,
    pending: Option<PendingAttention>,
    /// When the in-flight command started, for duration in the payload.
    /// `Some` ⇔ a `CommandStart` was seen and not yet matched by a finish;
    /// also serves as the "command in flight" predicate.
    command_started_at: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct PendingAttention {
    pub kind: AttentionKind,
    /// Earliest moment at which this event can fire.
    pub fire_at: Instant,
    /// Command duration, only set when `kind = CommandDone`.
    pub command_duration: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttentionKind {
    CommandDone { exit_code: Option<i32> },
    Bell,
}

impl AttentionKind {
    /// Stable wire-format string used in the daemon → backend WS payload.
    /// Single source of truth for the literals consumed by Python and the
    /// mobile client.
    pub fn wire_str(&self) -> &'static str {
        match self {
            Self::CommandDone { .. } => "command_done",
            Self::Bell => "bell",
        }
    }
}

impl AttentionDebouncer {
    pub fn new(quiet_period: Duration) -> Self {
        Self {
            quiet_period,
            pending: None,
            command_started_at: None,
        }
    }

    /// Feed a detected signal at time `now`. Callers harvest ready events
    /// via `take_ready`.
    pub fn on_signal(&mut self, sig: AttentionSignal, now: Instant) {
        match sig {
            AttentionSignal::CommandStart => {
                self.command_started_at = Some(now);
                // User started new work — cancel any pending notification.
                self.pending = None;
            }
            AttentionSignal::PromptDrawn => {
                // A bare prompt redraw with no command in flight is noise
                // (empty enter, shell reprint, etc.) — only count it as a
                // completion when a `CommandStart` preceded it.
                if self.command_started_at.is_some() {
                    self.arm(AttentionKind::CommandDone { exit_code: None }, now);
                }
            }
            AttentionSignal::CommandDone { exit_code } => {
                self.arm(AttentionKind::CommandDone { exit_code }, now);
            }
            AttentionSignal::Bell => {
                self.arm(AttentionKind::Bell, now);
            }
        }
    }

    fn arm(&mut self, kind: AttentionKind, now: Instant) {
        let command_duration = match &kind {
            AttentionKind::CommandDone { .. } => self
                .command_started_at
                .map(|s| now.saturating_duration_since(s)),
            _ => None,
        };
        self.pending = Some(PendingAttention {
            kind,
            fire_at: now + self.quiet_period,
            command_duration,
        });
        self.command_started_at = None;
    }

    /// Notify the tracker that fresh PTY output bytes were observed. New
    /// output during the quiet window cancels a pending Bell (the bell was
    /// presumably part of a noisy stream, not an idle attention request) and
    /// pushes a pending CommandDone's fire time forward — we want true
    /// silence after the prompt before claiming the user should look.
    pub fn on_output(&mut self, now: Instant) {
        if let Some(p) = self.pending.as_mut() {
            match p.kind {
                AttentionKind::Bell => {
                    // Bell is a one-shot intent; if more output follows
                    // before the quiet window closes, the program clearly
                    // isn't idle. Drop it.
                    self.pending = None;
                }
                AttentionKind::CommandDone { .. } => {
                    // Push the fire time out — wait for genuine silence.
                    p.fire_at = now + self.quiet_period;
                }
            }
        }
    }

    /// Return the pending event if its quiet window has elapsed.
    pub fn take_ready(&mut self, now: Instant) -> Option<PendingAttention> {
        let ready = match &self.pending {
            Some(p) => now >= p.fire_at,
            None => false,
        };
        if ready { self.pending.take() } else { None }
    }

    #[cfg(test)]
    pub fn pending(&self) -> Option<&PendingAttention> {
        self.pending.as_ref()
    }
}

// ─── Combined tracker (parser + debouncer) ──────────────────────────────────

/// Per-session combination of the byte-stream parser and the debounce timer.
///
/// Lives behind a single `Mutex` shared between the PTY read thread (which
/// calls [`AttentionTracker::on_bytes`] for every chunk) and the daemon loop
/// (which calls [`AttentionTracker::take_ready`] each tick). Holding both in
/// one lock keeps the two state machines consistent without any inter-thread
/// channel between them.
#[derive(Debug)]
pub struct AttentionTracker {
    parser: MarkParser,
    debouncer: AttentionDebouncer,
}

/// Default quiet period before a detected signal fires a notification.
/// 10 s of silence is short enough that the user gets a timely ping after
/// a long-running command (npm build, claude code finishing a turn) and long
/// enough to ride out brief "spinner" gaps between status updates.
pub const DEFAULT_QUIET_PERIOD: Duration = Duration::from_secs(10);

impl AttentionTracker {
    pub fn new(quiet_period: Duration) -> Self {
        Self {
            parser: MarkParser::new(),
            debouncer: AttentionDebouncer::new(quiet_period),
        }
    }

    /// Read-thread hook: feed a chunk of PTY output bytes.
    ///
    /// Bytes are not retained; only the resulting signals and the
    /// "trailing-passthrough" flag are pushed into the debouncer.
    pub fn on_bytes(&mut self, bytes: &[u8], now: Instant) {
        let result = self.parser.feed(bytes);
        for sig in result.signals {
            self.debouncer.on_signal(sig, now);
        }
        if result.trailing_passthrough {
            self.debouncer.on_output(now);
        }
    }

    /// Daemon-tick hook: pull a debounce-elapsed event if one is ready.
    pub fn take_ready(&mut self, now: Instant) -> Option<PendingAttention> {
        self.debouncer.take_ready(now)
    }
}

#[cfg(test)]
mod tracker_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn tracker_fires_command_done_after_quiet_period() {
        let mut t = AttentionTracker::new(Duration::from_secs(10));
        let t0 = Instant::now();
        // Simulate: command starts, runs for 2s producing output, finishes
        // with prompt mark + bare prompt.
        t.on_bytes(b"\x1b]133;C\x07running...\n", t0);
        t.on_bytes(b"more output\n", t0 + Duration::from_secs(1));
        t.on_bytes(b"\x1b]133;D;0\x07$ ", t0 + Duration::from_secs(2));
        // The trailing "$ " is passthrough → fire_at = (t0+2s) + 10s
        assert!(t.take_ready(t0 + Duration::from_secs(11)).is_none());
        let ev = t.take_ready(t0 + Duration::from_secs(13)).unwrap();
        assert_eq!(
            ev.kind,
            AttentionKind::CommandDone { exit_code: Some(0) }
        );
        assert_eq!(ev.command_duration, Some(Duration::from_secs(2)));
    }

    #[test]
    fn tracker_bell_in_busy_stream_does_not_fire() {
        // Tool prints a bell in the middle of streaming output — should NOT
        // fire because more output keeps flowing.
        let mut t = AttentionTracker::new(Duration::from_secs(10));
        let t0 = Instant::now();
        t.on_bytes(b"streaming \x07 work \n", t0);
        t.on_bytes(b"still working\n", t0 + Duration::from_secs(1));
        t.on_bytes(b"and more\n", t0 + Duration::from_secs(2));
        assert!(t.take_ready(t0 + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn tracker_isolated_bell_then_silence_fires() {
        let mut t = AttentionTracker::new(Duration::from_secs(10));
        let t0 = Instant::now();
        t.on_bytes(b"please respond\x07", t0);
        // No further output.
        assert!(t.take_ready(t0 + Duration::from_secs(5)).is_none());
        let ev = t.take_ready(t0 + Duration::from_secs(11)).unwrap();
        assert_eq!(ev.kind, AttentionKind::Bell);
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(bytes: &[u8]) -> Vec<AttentionSignal> {
        MarkParser::new().feed(bytes).signals
    }

    #[test]
    fn osc_133_a_with_bel_terminator() {
        assert_eq!(
            signals(b"\x1b]133;A\x07"),
            vec![AttentionSignal::PromptDrawn]
        );
    }

    #[test]
    fn osc_133_a_with_st_terminator() {
        assert_eq!(
            signals(b"\x1b]133;A\x1b\\"),
            vec![AttentionSignal::PromptDrawn]
        );
    }

    #[test]
    fn osc_133_command_start_then_done_with_exit() {
        assert_eq!(
            signals(b"\x1b]133;C\x07hello\n\x1b]133;D;0\x07"),
            vec![
                AttentionSignal::CommandStart,
                AttentionSignal::CommandDone { exit_code: Some(0) },
            ]
        );
    }

    #[test]
    fn osc_133_done_no_exit_code() {
        assert_eq!(
            signals(b"\x1b]133;D\x07"),
            vec![AttentionSignal::CommandDone { exit_code: None }]
        );
    }

    #[test]
    fn osc_133_done_with_nonzero_exit() {
        assert_eq!(
            signals(b"\x1b]133;D;130\x1b\\"),
            vec![AttentionSignal::CommandDone {
                exit_code: Some(130)
            }]
        );
    }

    #[test]
    fn osc_133_b_is_ignored() {
        // command-line begin — not interesting on its own
        assert_eq!(signals(b"\x1b]133;B\x07"), vec![]);
    }

    #[test]
    fn other_osc_codes_are_ignored() {
        // OSC 0 (title), OSC 8 (hyperlink), OSC 52 (clipboard) — all noise
        // for our purposes; they must not be misclassified as bells either.
        assert_eq!(signals(b"\x1b]0;my title\x07"), vec![]);
        assert_eq!(
            signals(b"\x1b]8;;https://example.com\x07link\x1b]8;;\x07"),
            vec![]
        );
    }

    #[test]
    fn bare_bel_emits_bell() {
        assert_eq!(signals(b"hello\x07world"), vec![AttentionSignal::Bell]);
    }

    #[test]
    fn bel_inside_osc_is_terminator_not_bell() {
        // The BEL terminating the OSC must NOT count as a bell.
        assert_eq!(
            signals(b"\x1b]133;A\x07"),
            vec![AttentionSignal::PromptDrawn]
        );
        // A real bell *after* the OSC, however, still fires.
        assert_eq!(
            signals(b"\x1b]133;A\x07ding\x07"),
            vec![AttentionSignal::PromptDrawn, AttentionSignal::Bell]
        );
    }

    #[test]
    fn sequence_split_across_feed_calls() {
        // Bytes arrive in arbitrary chunk boundaries — the parser must
        // remember its state across `feed` calls.
        let mut p = MarkParser::new();
        assert!(p.feed(b"\x1b]13").signals.is_empty());
        assert!(p.feed(b"3;D;1").signals.is_empty());
        let r = p.feed(b"7\x07");
        assert_eq!(
            r.signals,
            vec![AttentionSignal::CommandDone { exit_code: Some(17) }]
        );
        assert!(!r.trailing_passthrough);
    }

    #[test]
    fn trailing_passthrough_after_signal_is_reported() {
        // "doing\x07more" → bell, then passthrough → trailing=true
        let r = MarkParser::new().feed(b"doing\x07more");
        assert_eq!(r.signals, vec![AttentionSignal::Bell]);
        assert!(r.trailing_passthrough);
    }

    #[test]
    fn trailing_passthrough_before_signal_is_not_reported() {
        // "doing\x07" → text then bell at end → trailing=false
        let r = MarkParser::new().feed(b"doing\x07");
        assert_eq!(r.signals, vec![AttentionSignal::Bell]);
        assert!(!r.trailing_passthrough);
    }

    #[test]
    fn pure_passthrough_reports_trailing() {
        let r = MarkParser::new().feed(b"hello world\n");
        assert!(r.signals.is_empty());
        assert!(r.trailing_passthrough);
    }

    #[test]
    fn osc_only_chunk_has_no_trailing_passthrough() {
        // The OSC framing bytes (ESC, ], 1, 3, 3, ;, D, ;, 0, BEL) are all
        // sequence bytes, not passthrough.
        let r = MarkParser::new().feed(b"\x1b]133;D;0\x07");
        assert_eq!(
            r.signals,
            vec![AttentionSignal::CommandDone { exit_code: Some(0) }]
        );
        assert!(!r.trailing_passthrough);
    }

    #[test]
    fn passthrough_after_osc_is_reported() {
        // Typical "command done + prompt redraw" shape:
        // <CommandDone OSC><prompt text "$ "><PromptDrawn OSC>
        // Trailing passthrough should be false because the last byte is
        // part of the PromptDrawn OSC, not passthrough.
        let r = MarkParser::new().feed(b"\x1b]133;D;0\x07$ \x1b]133;A\x07");
        assert_eq!(
            r.signals,
            vec![
                AttentionSignal::CommandDone { exit_code: Some(0) },
                AttentionSignal::PromptDrawn,
            ]
        );
        assert!(!r.trailing_passthrough);
        // But if a stray byte follows the PromptDrawn, trailing should flip.
        let r2 = MarkParser::new().feed(b"\x1b]133;D;0\x07\x1b]133;A\x07$ ");
        assert!(r2.trailing_passthrough);
    }

    #[test]
    fn malformed_long_osc_does_not_explode() {
        // 4 KiB of garbage inside an unterminated OSC — must be capped and
        // discarded without panic, and the next clean sequence should still
        // parse.
        let mut bytes = Vec::with_capacity(4096 + 64);
        bytes.extend_from_slice(b"\x1b]");
        bytes.extend(std::iter::repeat(b'x').take(4096));
        bytes.extend_from_slice(b"\x07"); // terminate the junk OSC
        bytes.extend_from_slice(b"\x1b]133;D;0\x07"); // clean follow-up
        assert_eq!(
            signals(&bytes),
            vec![AttentionSignal::CommandDone { exit_code: Some(0) }]
        );
    }

    #[test]
    fn esc_then_non_osc_returns_to_normal() {
        // `ESC c` is a full reset — we don't decode it, just don't get stuck.
        // A bell after the escape sequence should still fire.
        assert_eq!(signals(b"\x1bc\x07"), vec![AttentionSignal::Bell]);
    }

    #[test]
    fn unparseable_exit_code_yields_none() {
        // Some shells (rare) emit `D;` with no number; some put junk there.
        assert_eq!(
            signals(b"\x1b]133;D;abc\x07"),
            vec![AttentionSignal::CommandDone { exit_code: None }]
        );
    }

    // ─── Debouncer ──────────────────────────────────────────────────────────

    #[test]
    fn debouncer_fires_after_quiet_period() {
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::CommandStart, t0);
        d.on_signal(
            AttentionSignal::CommandDone { exit_code: Some(0) },
            t0 + Duration::from_secs(1),
        );
        // Not yet ready
        assert!(d.take_ready(t0 + Duration::from_secs(5)).is_none());
        // Now ready (1s start + 10s quiet)
        let ev = d.take_ready(t0 + Duration::from_secs(12)).unwrap();
        assert_eq!(
            ev.kind,
            AttentionKind::CommandDone { exit_code: Some(0) }
        );
        assert_eq!(ev.command_duration, Some(Duration::from_secs(1)));
        // Drained
        assert!(d.take_ready(t0 + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn debouncer_output_pushes_command_done_fire_forward() {
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::CommandDone { exit_code: Some(0) }, t0);
        // Output 5s later resets the quiet window
        d.on_output(t0 + Duration::from_secs(5));
        assert!(d.take_ready(t0 + Duration::from_secs(11)).is_none());
        // Now wait 10s past the latest output
        assert!(d.take_ready(t0 + Duration::from_secs(16)).is_some());
    }

    #[test]
    fn debouncer_output_cancels_pending_bell() {
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::Bell, t0);
        d.on_output(t0 + Duration::from_secs(1));
        // Bell is dropped — program isn't idle
        assert!(d.take_ready(t0 + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn prompt_drawn_without_command_start_is_noise() {
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::PromptDrawn, t0);
        assert!(d.pending().is_none());
        assert!(d.take_ready(t0 + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn prompt_drawn_after_command_start_counts_as_done() {
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::CommandStart, t0);
        d.on_signal(
            AttentionSignal::PromptDrawn,
            t0 + Duration::from_secs(2),
        );
        let ev = d.take_ready(t0 + Duration::from_secs(20)).unwrap();
        assert_eq!(ev.kind, AttentionKind::CommandDone { exit_code: None });
        assert_eq!(ev.command_duration, Some(Duration::from_secs(2)));
    }

    #[test]
    fn new_command_start_cancels_pending() {
        // If a CommandDone is pending and the user starts a new command,
        // they're clearly engaged — drop the pending notification.
        let mut d = AttentionDebouncer::new(Duration::from_secs(10));
        let t0 = Instant::now();
        d.on_signal(AttentionSignal::CommandDone { exit_code: Some(0) }, t0);
        d.on_signal(
            AttentionSignal::CommandStart,
            t0 + Duration::from_secs(1),
        );
        assert!(d.take_ready(t0 + Duration::from_secs(30)).is_none());
    }
}
