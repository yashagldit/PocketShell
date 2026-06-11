//! Host-authoritative terminal engine.
//!
//! This module hosts a **passive, headless terminal emulator** ([`TerminalMirror`])
//! that is fed a copy of every byte a PTY emits. It maintains the authoritative
//! screen + scrollback grid (via `alacritty_terminal`) so the daemon can hand a
//! reconnecting mobile client a *correct* screen snapshot — regardless of how long
//! the client was gone or how many bytes it missed.
//!
//! This is the foundation of the Termius-grade resume rewrite: resume comes from
//! canonical emulator state ([`Snapshot`]), never from blind raw-byte replay. See
//! `docs/terminal-rewrite-design.md` for the full design.
//!
//! The mirror is **passive**: it never writes back to the PTY. Query responses
//! (cursor-position reports, device attributes, …) are produced by the real
//! terminal — xterm.js on the mobile side — whose replies travel back over the
//! input channel. The mirror exists only to be snapshotted.

mod mirror;
mod snapshot;

pub use mirror::TerminalMirror;
pub use snapshot::Snapshot;
