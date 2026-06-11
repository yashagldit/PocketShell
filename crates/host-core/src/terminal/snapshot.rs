//! Screen snapshot serializer.
//!
//! Walks the emulator's grid (recent scrollback + visible viewport) and emits a
//! standard escape-code byte stream that, written into a freshly-`reset()`
//! xterm.js of the same size, reproduces the screen. This is the canonical-state
//! resume payload — it replaces blind raw-byte replay entirely.
//!
//! The algorithm is a port of xterm.js's own `SerializeAddon`
//! (`addons/addon-serialize/src/SerializeAddon.ts`), the reference for
//! "grid → restorable escape stream":
//!
//! * iterate rows (scrollback first, then viewport), then columns;
//! * emit an SGR sequence only when a cell's style differs from the last
//!   (each emission is reset-prefixed `0;…` so it is self-contained);
//! * map fg/bg across named / 256-indexed / 24-bit RGB;
//! * skip wide-char spacer cells (the second column of a CJK glyph);
//! * omit the line break after a row that soft-wrapped (`WRAPLINE`) so xterm
//!   re-wraps it identically;
//! * trim trailing blank rows;
//! * finish with an absolute cursor position + cursor visibility.
//!
//! Deep history beyond [`SNAPSHOT_BYTE_BUDGET`] is fetched on demand as the
//! user scrolls (Phase 2 `scrollback_request`); the snapshot carries the screen
//! plus as much recent scrollback as fits that budget, so resume is instant
//! *and* shows what just happened. The alternate screen buffer has no
//! scrollback, so an alt-screen snapshot is the visible screen only.

use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, NamedColor};

/// Wire-format version of the snapshot payload. Bump when the serialization
/// shape changes so the mobile client can refuse / adapt.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Byte budget for the serialized snapshot payload.
///
/// The snapshot is delivered over the signaling relay, which rejects messages
/// larger than ~300 KB (`app/websocket/manager.py`). base64 of this budget
/// (~245 KB) plus the JSON envelope stays comfortably under that. The serializer
/// folds in as much *recent* scrollback as fits: the visible screen is always
/// included, then older history is trimmed until the payload fits. Deeper
/// history beyond this comes from on-demand `scrollback_request`.
pub const SNAPSHOT_BYTE_BUDGET: usize = 180 * 1024;

/// A restorable snapshot of the current screen (+ recent scrollback).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub version: u32,
    pub cols: u16,
    pub rows: u16,
    /// Whether the alternate screen buffer was active when captured.
    pub alt_screen: bool,
    /// Absolute byte offset in the session's output stream at the instant this
    /// snapshot was cut (== bytes fed to the mirror). The client applies the
    /// snapshot, sets its `lastAppliedOffset` to this, and ignores any live
    /// frame whose bytes fall at or before it — making the snapshot→live seam
    /// gap- and overlap-free once live frames are offset-tagged.
    pub base_offset: u64,
    /// Escape-code stream to write into a freshly-reset terminal of `cols`×`rows`.
    pub data: Vec<u8>,
}

impl Snapshot {
    /// Capture the screen of `term` plus as much recent scrollback as fits
    /// within `byte_budget`, tagged with the stream offset `base_offset`.
    ///
    /// Starts from the full retained history and trims the oldest lines until
    /// the serialized payload fits the budget. The visible screen is always
    /// included regardless of how much scrollback survives, so this converges
    /// (worst case: screen only).
    pub fn capture<T>(term: &Term<T>, base_offset: u64, byte_budget: usize) -> Snapshot {
        let mut lines = term.history_size();
        let mut data = serialize(term, lines);
        let mut attempts = 0;
        while data.len() > byte_budget && lines > 0 && attempts < 6 {
            // Shrink proportionally toward the budget (×0.9 for margin), always
            // making progress so we can't loop on a pathological line.
            let scaled =
                (lines as u128 * byte_budget as u128 / (data.len().max(1) as u128)) as usize;
            lines = (scaled * 9 / 10).min(lines.saturating_sub(1));
            data = serialize(term, lines);
            attempts += 1;
        }
        Snapshot {
            version: SNAPSHOT_VERSION,
            cols: term.columns() as u16,
            rows: term.screen_lines() as u16,
            alt_screen: term.mode().contains(TermMode::ALT_SCREEN),
            base_offset,
            data,
        }
    }
}

/// Serialize recent scrollback + the visible viewport of `term` into a
/// restorable escape stream.
fn serialize<T>(term: &Term<T>, scrollback_lines: usize) -> Vec<u8> {
    let grid = term.grid();
    let cols = term.columns();
    let rows = term.screen_lines() as i32;
    let alt = term.mode().contains(TermMode::ALT_SCREEN);

    let mut out: Vec<u8> = Vec::with_capacity((rows as usize) * cols);

    // Switch the client into the alternate buffer first if that's where the
    // content lives, so the restore lands in the correct screen.
    if alt {
        out.extend_from_slice(b"\x1b[?1049h");
    }
    // Home the cursor and start from a known (default) pen.
    out.extend_from_slice(b"\x1b[H\x1b[0m");
    let mut cur_sgr = String::from("0");

    // Alacritty addresses scrollback with negative line indices. The alternate
    // screen has no scrollback, so only fold history in for the primary buffer.
    let history = if alt {
        0
    } else {
        scrollback_lines.min(grid.history_size())
    };
    let top: i32 = -(history as i32);

    if let Some(last_row) = last_content_row(term, cols, top, rows) {
        let mut r = top;
        while r <= last_row {
            let line = Line(r);
            let wrapped = cols > 0
                && grid[Point::new(line, Column(cols - 1))]
                    .flags
                    .contains(Flags::WRAPLINE);
            // A wrapped row always occupies the full width; otherwise stop at
            // the last significant cell so we don't paint trailing blanks.
            let line_len = if wrapped {
                cols
            } else {
                row_len(term, line, cols)
            };

            let mut c = 0;
            while c < line_len {
                let cell = &grid[Point::new(line, Column(c))];
                // Skip the trailing/leading placeholder of a wide glyph; the
                // wide char itself occupies both columns in the client.
                if cell
                    .flags
                    .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
                {
                    c += 1;
                    continue;
                }

                let sgr = sgr_for_cell(cell);
                if sgr != cur_sgr {
                    out.extend_from_slice(b"\x1b[");
                    out.extend_from_slice(sgr.as_bytes());
                    out.push(b'm');
                    cur_sgr = sgr;
                }

                let ch = if cell.c == '\0' { ' ' } else { cell.c };
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                c += 1;
            }

            // Soft-wrapped rows flow into the next line in the client (xterm
            // autowrap), so we must NOT inject a line break for them.
            if r != last_row && !wrapped {
                out.extend_from_slice(b"\r\n");
            }
            r += 1;
        }
    }

    // Restore the cursor with an absolute move (viewport coordinates, 1-based)
    // so any drift from emitting the content above is irrelevant.
    let cursor = grid.cursor.point;
    let cur_row = cursor.line.0.max(0) as usize + 1;
    let cur_col = cursor.column.0 + 1;
    out.extend_from_slice(format!("\x1b[{cur_row};{cur_col}H").as_bytes());

    if !term.mode().contains(TermMode::SHOW_CURSOR) {
        out.extend_from_slice(b"\x1b[?25l");
    }

    out
}

/// The last row index that holds anything worth restoring, scanning from the
/// viewport bottom up to `top` (which may be negative, into scrollback), or
/// `None` when the whole range is blank.
fn last_content_row<T>(term: &Term<T>, cols: usize, top: i32, rows: i32) -> Option<i32> {
    let grid = term.grid();
    let mut r = rows - 1;
    while r >= top {
        let line = Line(r);
        // A soft-wrapped row is content even if its cells look blank.
        if cols > 0
            && grid[Point::new(line, Column(cols - 1))]
                .flags
                .contains(Flags::WRAPLINE)
        {
            return Some(r);
        }
        if row_len(term, line, cols) > 0 {
            return Some(r);
        }
        r -= 1;
    }
    None
}

/// Number of leading columns in `line` that carry restorable content: the index
/// past the last cell with a visible glyph or a non-default background.
fn row_len<T>(term: &Term<T>, line: Line, cols: usize) -> usize {
    let grid = term.grid();
    let mut len = 0;
    for c in 0..cols {
        let cell = &grid[Point::new(line, Column(c))];
        let blank_glyph = cell.c == ' ' || cell.c == '\0';
        if !blank_glyph || !is_default_bg(cell.bg) {
            len = c + 1;
        }
    }
    len
}

fn is_default_bg(bg: Color) -> bool {
    matches!(bg, Color::Named(NamedColor::Background))
}

/// Build the SGR parameter string for a cell, always reset-prefixed (`"0"` for a
/// default cell, e.g. `"0;1;38;2;255;0;0"` for bold + red-RGB foreground). Each
/// emission therefore fully specifies the pen, independent of prior state.
fn sgr_for_cell(cell: &Cell) -> String {
    let mut s = String::from("0");
    let f = cell.flags;

    if f.contains(Flags::BOLD) {
        s.push_str(";1");
    }
    if f.contains(Flags::DIM) {
        s.push_str(";2");
    }
    if f.contains(Flags::ITALIC) {
        s.push_str(";3");
    }
    if f.intersects(Flags::ALL_UNDERLINES) {
        s.push_str(";4");
    }
    if f.contains(Flags::INVERSE) {
        s.push_str(";7");
    }
    if f.contains(Flags::HIDDEN) {
        s.push_str(";8");
    }
    if f.contains(Flags::STRIKEOUT) {
        s.push_str(";9");
    }

    push_color(&mut s, cell.fg, true);
    push_color(&mut s, cell.bg, false);
    s
}

/// Append the SGR code(s) for one color to `s`. Default fg/bg add nothing (the
/// leading reset already restores them).
fn push_color(s: &mut String, color: Color, foreground: bool) {
    match color {
        Color::Named(named) => {
            if let Some(code) = named_sgr(named, foreground) {
                s.push(';');
                push_u16(s, code);
            }
        }
        Color::Indexed(idx) => {
            s.push_str(if foreground { ";38;5;" } else { ";48;5;" });
            push_u16(s, idx as u16);
        }
        Color::Spec(rgb) => {
            s.push_str(if foreground { ";38;2;" } else { ";48;2;" });
            push_u16(s, rgb.r as u16);
            s.push(';');
            push_u16(s, rgb.g as u16);
            s.push(';');
            push_u16(s, rgb.b as u16);
        }
    }
}

/// Map an alacritty `NamedColor` to its base ANSI SGR code, or `None` for the
/// default fg/bg (and other non-paintable slots), which the reset covers.
fn named_sgr(named: NamedColor, foreground: bool) -> Option<u16> {
    let n = named as usize;
    let (normal_base, bright_base) = if foreground { (30, 90) } else { (40, 100) };
    if n <= 7 {
        // Black..White
        Some((normal_base + n) as u16)
    } else if n <= 15 {
        // BrightBlack..BrightWhite
        Some((bright_base + (n - 8)) as u16)
    } else if (259..=266).contains(&n) {
        // DimBlack..DimWhite — render as the base color (the DIM flag, if set
        // on the cell, supplies the dim attribute separately).
        Some((normal_base + (n - 259)) as u16)
    } else {
        // Foreground (256), Background (257), Cursor (258), BrightForeground,
        // DimForeground — leave to the terminal default.
        None
    }
}

fn push_u16(s: &mut String, v: u16) {
    use std::fmt::Write;
    let _ = write!(s, "{v}");
}

#[cfg(test)]
mod tests {
    use crate::terminal::TerminalMirror;

    /// Feed `bytes` into a fresh mirror and return the serialized snapshot data
    /// as a UTF-8 string (escape codes included) for substring assertions.
    fn snap(cols: u16, rows: u16, bytes: &[u8]) -> String {
        let mut m = TerminalMirror::new(cols, rows);
        m.feed(bytes);
        String::from_utf8(m.snapshot().data).expect("snapshot is valid utf-8")
    }

    #[test]
    fn plain_text_is_present_with_home_and_cursor() {
        let s = snap(80, 24, b"hello");
        assert!(
            s.starts_with("\x1b[H\x1b[0m"),
            "starts homed + reset: {s:?}"
        );
        assert!(s.contains("hello"), "contains text: {s:?}");
        assert!(s.ends_with("\x1b[1;6H"), "cursor restored: {s:?}");
    }

    #[test]
    fn trailing_blank_cells_and_rows_are_trimmed() {
        let s = snap(80, 24, b"hi");
        assert!(!s.contains("hi   "), "trailing spaces trimmed: {s:?}");
        assert_eq!(s.matches("\r\n").count(), 0, "no trailing rows: {s:?}");
    }

    #[test]
    fn newline_produces_crlf_between_rows() {
        let s = snap(80, 24, b"a\r\nb");
        assert!(s.contains("a\r\nb"), "two rows joined by crlf: {s:?}");
        assert!(s.ends_with("\x1b[2;2H"), "cursor on row 2 col 2: {s:?}");
    }

    #[test]
    fn bold_red_foreground_emits_sgr() {
        let s = snap(80, 24, b"\x1b[1;31mhi");
        assert!(s.contains("\x1b[0;1;31mhi"), "bold-red sgr: {s:?}");
    }

    #[test]
    fn truecolor_foreground_roundtrips() {
        let s = snap(80, 24, b"\x1b[38;2;10;20;30mX");
        assert!(s.contains("\x1b[0;38;2;10;20;30mX"), "rgb fg: {s:?}");
    }

    #[test]
    fn indexed_256_background_roundtrips() {
        let s = snap(80, 24, b"\x1b[48;5;200mY");
        assert!(s.contains("\x1b[0;48;5;200mY"), "indexed bg: {s:?}");
    }

    #[test]
    fn style_reset_between_styled_and_plain() {
        let s = snap(80, 24, b"\x1b[1mA\x1b[0mB");
        assert!(s.contains("\x1b[0;1mA"), "bold A: {s:?}");
        assert!(s.contains("\x1b[0mB"), "reset before B: {s:?}");
    }

    #[test]
    fn alt_screen_prefixes_restore() {
        let s = snap(80, 24, b"\x1b[?1049hfullscreen");
        assert!(
            s.starts_with("\x1b[?1049h"),
            "enters alt buffer first: {s:?}"
        );
        assert!(s.contains("fullscreen"), "alt content present: {s:?}");
    }

    #[test]
    fn hidden_cursor_is_restored_hidden() {
        let s = snap(80, 24, b"\x1b[?25lmenu");
        assert!(
            s.contains("\x1b[?25l"),
            "cursor hidden flag restored: {s:?}"
        );
    }

    #[test]
    fn absolute_cursor_position_is_restored() {
        let s = snap(80, 24, b"\x1b[5;3H");
        assert!(s.ends_with("\x1b[5;3H"), "cursor at 5;3: {s:?}");
    }

    #[test]
    fn soft_wrapped_line_has_no_internal_crlf() {
        let line = "z".repeat(15);
        let mut m = TerminalMirror::new(10, 6);
        m.feed(line.as_bytes());
        let s = String::from_utf8(m.snapshot().data).unwrap();
        assert!(s.contains(&"z".repeat(15)), "all glyphs present: {s:?}");
        assert_eq!(s.matches("\r\n").count(), 0, "no crlf at soft wrap: {s:?}");
    }

    #[test]
    fn wide_char_spacer_is_skipped() {
        let s = snap(80, 24, "你好".as_bytes());
        assert!(s.contains("你好"), "cjk glyphs present once: {s:?}");
        assert!(!s.contains("你 好"), "no spacer artifacts: {s:?}");
    }

    #[test]
    fn blank_screen_emits_only_home_reset_and_cursor() {
        let s = snap(80, 24, b"");
        assert_eq!(s, "\x1b[H\x1b[0m\x1b[1;1H", "minimal payload: {s:?}");
    }

    #[test]
    fn scrollback_is_folded_into_snapshot() {
        // 5-row terminal; feed 12 lines. Lines that scrolled off the top must
        // still appear in the snapshot (folded-in recent scrollback), along
        // with the lines currently on screen.
        let mut m = TerminalMirror::new(40, 5);
        for i in 0..12 {
            m.feed(format!("line{i}\r\n").as_bytes());
        }
        let s = String::from_utf8(m.snapshot().data).unwrap();
        assert!(s.contains("line0"), "scrolled-off line present: {s:?}");
        assert!(s.contains("line11"), "on-screen line present: {s:?}");
    }

    #[test]
    fn base_offset_tracks_bytes_fed() {
        let mut m = TerminalMirror::new(80, 24);
        m.feed(b"hello");
        m.feed(b" world");
        assert_eq!(
            m.snapshot().base_offset,
            11,
            "base_offset == total bytes fed"
        );
    }

    #[test]
    fn snapshot_stays_within_byte_budget_and_keeps_recent() {
        // Feed far more styled history than the budget can hold. The snapshot
        // must stay within budget yet still contain the most recent lines (the
        // oldest scrollback is what gets trimmed).
        let mut m = TerminalMirror::new(80, 10);
        for i in 0..5000 {
            m.feed(format!("line{i}: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n").as_bytes());
        }
        let snap = m.snapshot();
        assert!(
            snap.data.len() <= super::SNAPSHOT_BYTE_BUDGET,
            "snapshot {} exceeds budget {}",
            snap.data.len(),
            super::SNAPSHOT_BYTE_BUDGET
        );
        let s = String::from_utf8(snap.data).unwrap();
        assert!(s.contains("line4999"), "keeps the most recent line");
    }
}
