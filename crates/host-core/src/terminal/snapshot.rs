//! Screen snapshot serializer.
//!
//! Walks the emulator's visible grid and emits a standard escape-code byte
//! stream that, written into a freshly-`reset()` xterm.js of the same size,
//! reproduces the current screen. This is the canonical-state resume payload —
//! it replaces blind raw-byte replay entirely.
//!
//! The algorithm is a port of xterm.js's own `SerializeAddon`
//! (`addons/addon-serialize/src/SerializeAddon.ts`), which is the reference for
//! "grid → restorable escape stream":
//!
//! * iterate rows, then columns;
//! * emit an SGR sequence only when a cell's style differs from the last
//!   (each emission is reset-prefixed `0;…` so it is self-contained);
//! * map fg/bg across named / 256-indexed / 24-bit RGB;
//! * skip wide-char spacer cells (the second column of a CJK glyph);
//! * omit the line break after a row that soft-wrapped (`WRAPLINE`) so xterm
//!   re-wraps it identically;
//! * trim trailing blank rows;
//! * finish with an absolute cursor position + cursor visibility.
//!
//! Scrollback history is intentionally *not* part of this payload — it is large
//! and is fetched on demand as the user scrolls. The snapshot is the current
//! screen only: small, instant, and always correct (including alt-screen TUIs).

use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, NamedColor};

/// Wire-format version of the snapshot payload. Bump when the serialization
/// shape changes so the mobile client can refuse / adapt.
pub const SNAPSHOT_VERSION: u32 = 1;

/// A restorable snapshot of the current visible screen.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub version: u32,
    pub cols: u16,
    pub rows: u16,
    /// Whether the alternate screen buffer was active when captured.
    pub alt_screen: bool,
    /// Escape-code stream to write into a freshly-reset terminal of `cols`×`rows`.
    pub data: Vec<u8>,
}

impl Snapshot {
    /// Capture the visible screen of `term`.
    pub fn capture<T>(term: &Term<T>) -> Snapshot {
        Snapshot {
            version: SNAPSHOT_VERSION,
            cols: term.columns() as u16,
            rows: term.screen_lines() as u16,
            alt_screen: term.mode().contains(TermMode::ALT_SCREEN),
            data: serialize_visible(term),
        }
    }
}

/// Serialize the visible viewport of `term` into a restorable escape stream.
fn serialize_visible<T>(term: &Term<T>) -> Vec<u8> {
    let grid = term.grid();
    let cols = term.columns();
    let rows = term.screen_lines();
    let alt = term.mode().contains(TermMode::ALT_SCREEN);

    let mut out: Vec<u8> = Vec::with_capacity(rows * cols);

    // Switch the client into the alternate buffer first if that's where the
    // content lives, so the restore lands in the correct screen.
    if alt {
        out.extend_from_slice(b"\x1b[?1049h");
    }
    // Home the cursor and start from a known (default) pen.
    out.extend_from_slice(b"\x1b[H\x1b[0m");
    let mut cur_sgr = String::from("0");

    let last_row = last_content_row(term, cols, rows);

    if let Some(last_row) = last_row {
        for r in 0..=last_row {
            let line = Line(r as i32);
            let wrapped = cols > 0
                && grid[Point::new(line, Column(cols - 1))]
                    .flags
                    .contains(Flags::WRAPLINE);
            // A wrapped row always occupies the full width; otherwise stop at
            // the last significant cell so we don't paint trailing blanks.
            let line_len = if wrapped {
                cols
            } else {
                row_len(term, r, cols)
            };

            let mut c = 0;
            while c < line_len {
                let cell = &grid[Point::new(line, Column(c))];
                // Skip the trailing/leading placeholder of a wide glyph; the
                // wide char itself (previous/next cell) carries the codepoint
                // and occupies both columns in the client.
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
        }
    }

    // Restore the cursor with an absolute move so any drift from emitting the
    // content above (autowrap, trimming) is irrelevant. Coordinates are 1-based.
    let cursor = grid.cursor.point;
    let cur_row = cursor.line.0.max(0) as usize + 1;
    let cur_col = cursor.column.0 + 1;
    out.extend_from_slice(format!("\x1b[{cur_row};{cur_col}H").as_bytes());

    if !term.mode().contains(TermMode::SHOW_CURSOR) {
        out.extend_from_slice(b"\x1b[?25l");
    }

    out
}

/// The last row index (0-based) that holds anything worth restoring, or `None`
/// when the whole screen is blank. Trailing empty rows below this are dropped.
fn last_content_row<T>(term: &Term<T>, cols: usize, rows: usize) -> Option<usize> {
    let grid = term.grid();
    for r in (0..rows).rev() {
        let line = Line(r as i32);
        // A soft-wrapped row is content even if its cells look blank.
        if cols > 0
            && grid[Point::new(line, Column(cols - 1))]
                .flags
                .contains(Flags::WRAPLINE)
        {
            return Some(r);
        }
        if row_len(term, r, cols) > 0 {
            return Some(r);
        }
    }
    None
}

/// Number of leading columns in row `r` that carry restorable content: the
/// index past the last cell with a visible glyph or a non-default background.
fn row_len<T>(term: &Term<T>, r: usize, cols: usize) -> usize {
    let grid = term.grid();
    let line = Line(r as i32);
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
        assert!(s.starts_with("\x1b[H\x1b[0m"), "starts homed + reset: {s:?}");
        assert!(s.contains("hello"), "contains text: {s:?}");
        // Cursor ends one past "hello" → row 1, col 6.
        assert!(s.ends_with("\x1b[1;6H"), "cursor restored: {s:?}");
    }

    #[test]
    fn trailing_blank_cells_and_rows_are_trimmed() {
        let s = snap(80, 24, b"hi");
        // No long run of spaces padding the 80-col row.
        assert!(!s.contains("hi   "), "trailing spaces trimmed: {s:?}");
        // Only one logical line emitted (no CRLF for blank rows below).
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
        // Reset-prefixed, bold (1), red fg (31), before the glyphs.
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
        // Styled "A" then default "B": the serializer must drop back to "0".
        let s = snap(80, 24, b"\x1b[1mA\x1b[0mB");
        assert!(s.contains("\x1b[0;1mA"), "bold A: {s:?}");
        assert!(s.contains("\x1b[0mB"), "reset before B: {s:?}");
    }

    #[test]
    fn alt_screen_prefixes_restore() {
        let s = snap(80, 24, b"\x1b[?1049hfullscreen");
        assert!(s.starts_with("\x1b[?1049h"), "enters alt buffer first: {s:?}");
        assert!(s.contains("fullscreen"), "alt content present: {s:?}");
    }

    #[test]
    fn hidden_cursor_is_restored_hidden() {
        let s = snap(80, 24, b"\x1b[?25lmenu");
        assert!(s.contains("\x1b[?25l"), "cursor hidden flag restored: {s:?}");
    }

    #[test]
    fn absolute_cursor_position_is_restored() {
        // Move cursor to row 5, col 3 then capture.
        let s = snap(80, 24, b"\x1b[5;3H");
        assert!(s.ends_with("\x1b[5;3H"), "cursor at 5;3: {s:?}");
    }

    #[test]
    fn soft_wrapped_line_has_no_internal_crlf() {
        // Write more columns than the width to force a soft wrap.
        let line = "z".repeat(15);
        let mut m = TerminalMirror::new(10, 6);
        m.feed(line.as_bytes());
        let s = String::from_utf8(m.snapshot().data).unwrap();
        // 15 z's across a 10-wide screen wrap to a second row, but as ONE
        // logical line — no CRLF injected at the wrap boundary.
        assert!(s.contains(&"z".repeat(15)), "all glyphs present: {s:?}");
        assert_eq!(s.matches("\r\n").count(), 0, "no crlf at soft wrap: {s:?}");
    }

    #[test]
    fn wide_char_spacer_is_skipped() {
        // A CJK glyph occupies two columns: the glyph cell + a spacer cell.
        // The serializer must emit the glyph once and skip the spacer.
        let s = snap(80, 24, "你好".as_bytes());
        assert!(s.contains("你好"), "cjk glyphs present once: {s:?}");
        // No stray spaces between the two wide glyphs from the spacer cells.
        assert!(!s.contains("你 好"), "no spacer artifacts: {s:?}");
    }

    #[test]
    fn blank_screen_emits_only_home_reset_and_cursor() {
        let s = snap(80, 24, b"");
        assert_eq!(s, "\x1b[H\x1b[0m\x1b[1;1H", "minimal payload: {s:?}");
    }
}
