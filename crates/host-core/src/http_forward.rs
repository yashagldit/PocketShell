//! HTTP forwarding from mobile to a local dev server on this host.
//!
//! When the user runs `npm run dev` (or similar) and runs `pocketshell expose
//! <port>` to allowlist the port, the mobile app's WebView can render the
//! site through this module. The mobile WebView's URL-scheme handler turns
//! every HTTP request into a sequence of frames over the `http-{hostId}`
//! WebRTC data channel; this module parses those frames, performs the
//! upstream fetch via [`reqwest`] against `127.0.0.1:<port>`, and streams the
//! response back as more frames.
//!
//! ## Why a custom frame protocol?
//!
//! - Multiplexing: a single data channel carries many concurrent HTTP
//!   requests (a SPA loads dozens of subresources in parallel). Each frame
//!   is tagged with a u32 request id so the mobile side can route the
//!   responses back to the right pending fetch.
//! - SCTP message limits: webrtc-rs caps a single send at ~64 KB. Response
//!   bodies are chunked into `RESP_BODY_CHUNK_BYTES` frames so a large
//!   bundle.js doesn't blow up the channel.
//! - Streaming: response chunks are forwarded as they arrive, so SSE and
//!   Vite's hot-update endpoints behave reasonably and first-paint isn't
//!   held up waiting for a full body.
//!
//! ## Security gate
//!
//! Every `ReqHead` is checked against [`ExposedPortsStore::is_allowed`]
//! before opening a local socket. The paired user already has sudo via the
//! terminal channel, but the allowlist still buys "a stolen phone cannot
//! probe random local services without the operator typing a command into
//! a TTY first" — see `TODO-dev-server-forward.md` for the full threat
//! model.

use crate::error::{HostError, Result};
use crate::exposed_ports::ExposedPortsStore;
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

// =====================================================================
// Frame codec
// =====================================================================

/// Sentinel bytes prefixed to every frame. The mobile side uses the same
/// convention on its other channels (terminal `\x00PSAU` auth, files
/// `\x00PSFT` etc.) so an accidental non-frame write logs as obviously
/// malformed instead of being silently misinterpreted.
pub const FRAME_MAGIC: [u8; 5] = [0x00, b'P', b'S', b'H', b'F'];

/// Largest response-body chunk we'll cram into a single SCTP message.
/// webrtc-rs caps individual sends at ~64 KB; 60 KB leaves headroom for the
/// frame header and matches the terminal channel's cap.
pub const RESP_BODY_CHUNK_BYTES: usize = 60 * 1024;

/// Soft upper bound on a request body the forwarder will accept before
/// rejecting with [`ErrorCode::BodyTooLarge`]. Generous enough for typical
/// form posts, JSON payloads, and small file uploads; not generous enough
/// to OOM the daemon if mobile decides to ship a 4 GB blob.
pub const REQ_BODY_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Upper bound on a single response body the forwarder will stream back
/// before aborting with [`ErrorCode::BodyTooLarge`]. Mirrors the mobile
/// hook's `RESPONSE_BODY_MAX_BYTES` (32 MB): without a host-side cap a dev
/// server returning a 200 MB asset would be streamed all the way to the
/// phone only to be rejected there, wasting the WebRTC channel (shared with
/// the terminal) on bytes that get thrown away.
pub const RESP_BODY_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Maximum number of forwards a single channel may have in flight at once.
/// A SPA fires dozens of subresource requests in parallel, so this is set
/// well above a typical first-paint fan-out — its job is to shed a runaway
/// (a fetch loop, an abusive page) before it spawns unbounded tasks and
/// starves the terminal/file channels multiplexed onto the same peer.
pub const MAX_CONCURRENT_REQUESTS: usize = 64;

/// How long we'll wait for the upstream dev server to send headers. Dev
/// servers cold-start slowly (Vite first-request, Next.js compile-on-demand)
/// but 30 s is plenty in practice.
///
/// Applied to the request *head* only (connect + headers), NOT the whole
/// response. A total-request deadline would kill every long-lived stream
/// (`text/event-stream`, chunked progress endpoints) at the 30 s mark even
/// while it is actively delivering bytes.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle timeout between body chunks for non-streaming responses. A regular
/// response whose body stalls this long is effectively dead — fail it so the
/// mobile fetch settles instead of holding a forward slot forever. Streaming
/// content types ([`is_event_stream_headers`]) are exempt: SSE servers may
/// legitimately stay silent for minutes between events, and the client
/// cancels them explicitly (ReqCancel / channel close) when done.
pub const BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Wire-format v2: opcodes 0x2x/0x3x add WebSocket tunneling on the same
/// channel and id-space as HTTP forwards (a v1 peer rejects them as
/// UnknownOpcode, which the sender surfaces as "WS not supported by this
/// host — update the agent").
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    RequestHead = 0x01,
    RequestBody = 0x02,
    RequestEnd = 0x03,
    RequestCancel = 0x04,
    ResponseHead = 0x11,
    ResponseBody = 0x12,
    ResponseEnd = 0x13,
    ResponseError = 0x14,
    /// Client → host: open a WebSocket to `ws://localhost:{port}{path}`.
    /// Payload identical to RequestHead (method is carried but ignored).
    WsOpen = 0x21,
    /// Both directions: one fragment of a WebSocket message.
    /// Payload: flags u8 (bit0 = text, bit1 = fin), then raw bytes.
    WsData = 0x22,
    /// Both directions: close the WebSocket. Payload: u16 close code +
    /// long-string reason. After sending/receiving this the id is dead.
    WsClose = 0x23,
    /// Host → client: upstream WebSocket handshake succeeded. Payload:
    /// headers (e.g. the server-selected `Sec-WebSocket-Protocol`).
    /// Handshake failures come back as a plain ResponseError instead.
    WsOpenOk = 0x31,
}

impl Opcode {
    fn from_u8(b: u8) -> std::result::Result<Self, CodecError> {
        Ok(match b {
            0x01 => Self::RequestHead,
            0x02 => Self::RequestBody,
            0x03 => Self::RequestEnd,
            0x04 => Self::RequestCancel,
            0x11 => Self::ResponseHead,
            0x12 => Self::ResponseBody,
            0x13 => Self::ResponseEnd,
            0x14 => Self::ResponseError,
            0x21 => Self::WsOpen,
            0x22 => Self::WsData,
            0x23 => Self::WsClose,
            0x31 => Self::WsOpenOk,
            other => return Err(CodecError::UnknownOpcode(other)),
        })
    }
}

/// `WsData` flag bits.
pub const WS_FLAG_TEXT: u8 = 0b0000_0001;
pub const WS_FLAG_FIN: u8 = 0b0000_0010;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    PortNotExposed = 1,
    UpstreamFailed = 2,
    MalformedFrame = 3,
    UpstreamTimeout = 4,
    BodyTooLarge = 5,
    InternalError = 6,
    /// The channel already has [`MAX_CONCURRENT_REQUESTS`] forwards in
    /// flight; this one is shed rather than queued so a misbehaving page
    /// can't starve the terminal/file channels that share the WebRTC peer.
    TooManyRequests = 7,
}

impl ErrorCode {
    fn from_u8(b: u8) -> Self {
        match b {
            1 => Self::PortNotExposed,
            2 => Self::UpstreamFailed,
            3 => Self::MalformedFrame,
            4 => Self::UpstreamTimeout,
            5 => Self::BodyTooLarge,
            7 => Self::TooManyRequests,
            _ => Self::InternalError,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub port: u16,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub enum Frame {
    ReqHead {
        id: u32,
        head: RequestHead,
    },
    ReqBody {
        id: u32,
        data: Bytes,
    },
    ReqEnd {
        id: u32,
    },
    ReqCancel {
        id: u32,
    },
    RespHead {
        id: u32,
        head: ResponseHead,
    },
    RespBody {
        id: u32,
        data: Bytes,
    },
    RespEnd {
        id: u32,
    },
    RespError {
        id: u32,
        code: ErrorCode,
        message: String,
    },
    WsOpen {
        id: u32,
        head: RequestHead,
    },
    WsData {
        id: u32,
        /// True for a text-message fragment, false for binary.
        text: bool,
        /// True on the final fragment of a message. Messages that fit in
        /// one frame carry `fin = true` immediately.
        fin: bool,
        data: Bytes,
    },
    WsClose {
        id: u32,
        code: u16,
        reason: String,
    },
    WsOpenOk {
        id: u32,
        headers: Vec<(String, String)>,
    },
}

impl Frame {
    pub fn id(&self) -> u32 {
        match self {
            Frame::ReqHead { id, .. }
            | Frame::ReqBody { id, .. }
            | Frame::ReqEnd { id }
            | Frame::ReqCancel { id }
            | Frame::RespHead { id, .. }
            | Frame::RespBody { id, .. }
            | Frame::RespEnd { id }
            | Frame::RespError { id, .. }
            | Frame::WsOpen { id, .. }
            | Frame::WsData { id, .. }
            | Frame::WsClose { id, .. }
            | Frame::WsOpenOk { id, .. } => *id,
        }
    }

    pub fn opcode(&self) -> Opcode {
        match self {
            Frame::ReqHead { .. } => Opcode::RequestHead,
            Frame::ReqBody { .. } => Opcode::RequestBody,
            Frame::ReqEnd { .. } => Opcode::RequestEnd,
            Frame::ReqCancel { .. } => Opcode::RequestCancel,
            Frame::RespHead { .. } => Opcode::ResponseHead,
            Frame::RespBody { .. } => Opcode::ResponseBody,
            Frame::RespEnd { .. } => Opcode::ResponseEnd,
            Frame::RespError { .. } => Opcode::ResponseError,
            Frame::WsOpen { .. } => Opcode::WsOpen,
            Frame::WsData { .. } => Opcode::WsData,
            Frame::WsClose { .. } => Opcode::WsClose,
            Frame::WsOpenOk { .. } => Opcode::WsOpenOk,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("frame shorter than header ({0} bytes)")]
    TooShort(usize),
    #[error("missing or wrong magic prefix")]
    BadMagic,
    #[error("unknown opcode {0:#04x}")]
    UnknownOpcode(u8),
    #[error("malformed payload: {0}")]
    BadPayload(&'static str),
    #[error("invalid utf-8 in {field}")]
    BadUtf8 { field: &'static str },
}

/// Encode a frame to bytes. Format:
///
/// ```text
/// [0..5]   FRAME_MAGIC                    \x00PSHF
/// [5]      opcode                         1 byte
/// [6..10]  request_id                     u32 big-endian
/// [10..]   opcode-specific payload
/// ```
pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(frame.opcode() as u8);
    out.extend_from_slice(&frame.id().to_be_bytes());

    match frame {
        Frame::ReqHead { head, .. } => {
            out.extend_from_slice(&head.port.to_be_bytes());
            encode_short_string(&mut out, &head.method); // method_len: u8
            encode_long_string(&mut out, &head.path); // path_len: u16
            encode_headers(&mut out, &head.headers);
        }
        Frame::ReqBody { data, .. } | Frame::RespBody { data, .. } => {
            out.extend_from_slice(data);
        }
        Frame::ReqEnd { .. } | Frame::ReqCancel { .. } | Frame::RespEnd { .. } => {}
        Frame::RespHead { head, .. } => {
            out.extend_from_slice(&head.status.to_be_bytes());
            encode_headers(&mut out, &head.headers);
        }
        Frame::RespError { code, message, .. } => {
            out.push(*code as u8);
            let bytes = message.as_bytes();
            let len = bytes.len().min(u16::MAX as usize) as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&bytes[..len as usize]);
        }
        Frame::WsOpen { head, .. } => {
            out.extend_from_slice(&head.port.to_be_bytes());
            encode_short_string(&mut out, &head.method);
            encode_long_string(&mut out, &head.path);
            encode_headers(&mut out, &head.headers);
        }
        Frame::WsData {
            text, fin, data, ..
        } => {
            let mut flags = 0u8;
            if *text {
                flags |= WS_FLAG_TEXT;
            }
            if *fin {
                flags |= WS_FLAG_FIN;
            }
            out.push(flags);
            out.extend_from_slice(data);
        }
        Frame::WsClose { code, reason, .. } => {
            out.extend_from_slice(&code.to_be_bytes());
            encode_long_string(&mut out, reason);
        }
        Frame::WsOpenOk { headers, .. } => {
            encode_headers(&mut out, headers);
        }
    }
    out
}

/// Decode a single frame from `buf`. Returns the frame and the number of
/// trailing bytes that were ignored (in case the channel ever batches
/// frames in one SCTP message — the current protocol is one-frame-per-send
/// so callers can assert `extra == 0`).
pub fn decode(buf: &[u8]) -> std::result::Result<Frame, CodecError> {
    if buf.len() < FRAME_MAGIC.len() + 1 + 4 {
        return Err(CodecError::TooShort(buf.len()));
    }
    if &buf[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(CodecError::BadMagic);
    }
    let op = Opcode::from_u8(buf[FRAME_MAGIC.len()])?;
    let id = u32::from_be_bytes([
        buf[FRAME_MAGIC.len() + 1],
        buf[FRAME_MAGIC.len() + 2],
        buf[FRAME_MAGIC.len() + 3],
        buf[FRAME_MAGIC.len() + 4],
    ]);
    let payload = &buf[FRAME_MAGIC.len() + 5..];

    Ok(match op {
        Opcode::RequestHead => {
            let mut cur = Cursor::new(payload);
            let port = cur.read_u16()?;
            let method = cur.read_short_string("method")?;
            let path = cur.read_long_string("path")?;
            let headers = cur.read_headers()?;
            Frame::ReqHead {
                id,
                head: RequestHead {
                    port,
                    method,
                    path,
                    headers,
                },
            }
        }
        Opcode::RequestBody => Frame::ReqBody {
            id,
            data: Bytes::copy_from_slice(payload),
        },
        Opcode::RequestEnd => Frame::ReqEnd { id },
        Opcode::RequestCancel => Frame::ReqCancel { id },
        Opcode::ResponseHead => {
            let mut cur = Cursor::new(payload);
            let status = cur.read_u16()?;
            let headers = cur.read_headers()?;
            Frame::RespHead {
                id,
                head: ResponseHead { status, headers },
            }
        }
        Opcode::ResponseBody => Frame::RespBody {
            id,
            data: Bytes::copy_from_slice(payload),
        },
        Opcode::ResponseEnd => Frame::RespEnd { id },
        Opcode::ResponseError => {
            let mut cur = Cursor::new(payload);
            let code = ErrorCode::from_u8(cur.read_u8()?);
            let message = cur.read_long_string("error.message")?;
            Frame::RespError { id, code, message }
        }
        Opcode::WsOpen => {
            let mut cur = Cursor::new(payload);
            let port = cur.read_u16()?;
            let method = cur.read_short_string("method")?;
            let path = cur.read_long_string("path")?;
            let headers = cur.read_headers()?;
            Frame::WsOpen {
                id,
                head: RequestHead {
                    port,
                    method,
                    path,
                    headers,
                },
            }
        }
        Opcode::WsData => {
            let mut cur = Cursor::new(payload);
            let flags = cur.read_u8()?;
            Frame::WsData {
                id,
                text: flags & WS_FLAG_TEXT != 0,
                fin: flags & WS_FLAG_FIN != 0,
                data: Bytes::copy_from_slice(cur.rest()),
            }
        }
        Opcode::WsClose => {
            let mut cur = Cursor::new(payload);
            let code = cur.read_u16()?;
            let reason = cur.read_long_string("close.reason")?;
            Frame::WsClose { id, code, reason }
        }
        Opcode::WsOpenOk => {
            let mut cur = Cursor::new(payload);
            let headers = cur.read_headers()?;
            Frame::WsOpenOk { id, headers }
        }
    })
}

/// Find the largest valid byte length ≤ `cap` that lands on a UTF-8 char
/// boundary. Slicing at a non-boundary would produce invalid UTF-8 that
/// the peer's decoder rejects with `BadUtf8`, dropping the whole frame.
fn truncate_to_char_boundary(s: &str, cap: usize) -> usize {
    if s.len() <= cap {
        return s.len();
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn encode_short_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = truncate_to_char_boundary(s, u8::MAX as usize);
    out.push(len as u8);
    out.extend_from_slice(&bytes[..len]);
}

fn encode_long_string(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = truncate_to_char_boundary(s, u16::MAX as usize);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&bytes[..len]);
}

fn encode_headers(out: &mut Vec<u8>, headers: &[(String, String)]) {
    let count = headers.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&count.to_be_bytes());
    for (name, value) in headers.iter().take(count as usize) {
        encode_short_string(out, name);
        encode_long_string(out, value);
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], CodecError> {
        if self.pos + n > self.buf.len() {
            return Err(CodecError::BadPayload("ran past end"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> std::result::Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> std::result::Result<u16, CodecError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn read_short_string(
        &mut self,
        field: &'static str,
    ) -> std::result::Result<String, CodecError> {
        let len = self.read_u8()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::BadUtf8 { field })
    }

    fn read_long_string(&mut self, field: &'static str) -> std::result::Result<String, CodecError> {
        let len = self.read_u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::BadUtf8 { field })
    }

    fn read_headers(&mut self) -> std::result::Result<Vec<(String, String)>, CodecError> {
        let n = self.read_u16()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let name = self.read_short_string("header.name")?;
            let value = self.read_long_string("header.value")?;
            out.push((name, value));
        }
        Ok(out)
    }

    /// Everything after the cursor — the raw tail of a WsData payload.
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

// =====================================================================
// Forwarder runtime
// =====================================================================

/// Per-channel state. The daemon maintains one `HttpForwardSession` per
/// open `http-{hostId}` data channel and routes incoming frames to it.
///
/// State is:
///   - `pending` — partial requests being assembled (head received, body
///     chunks still arriving). Cleared on `ReqEnd` (promoted to a
///     [`ReadyRequest`]) or `ReqCancel`.
///   - `in_flight` — cancel handles for requests that have been promoted
///     to a spawned `forward_request` task. A `ReqCancel` arriving after
///     promotion signals the task via the oneshot so the upstream
///     fetch / body stream can be aborted mid-flight.
pub struct HttpForwardSession {
    pending: HashMap<u32, PendingRequest>,
    in_flight: HashMap<u32, tokio::sync::oneshot::Sender<()>>,
    /// Live WebSocket tunnels: id → sender feeding the relay task's
    /// client-event loop. Entries are pruned when the relay drops its
    /// receiver (upstream closed / relay errored) or on `WsClose`.
    ws_streams: HashMap<u32, tokio::sync::mpsc::Sender<WsClientEvent>>,
}

/// Maximum simultaneous WebSocket tunnels per channel. HMR needs exactly
/// one; a couple more covers SSE-over-WS fallbacks and app-level sockets.
/// Above this we shed with `TooManyRequests` — same rationale as the HTTP
/// concurrency cap (protect the shared peer, refuse rather than queue).
pub const MAX_CONCURRENT_WS: usize = 8;

/// Per-message reassembly cap for client→host WebSocket messages. A page
/// shipping more than this in ONE message through a dev tunnel is broken;
/// refusing bounds daemon memory against a hostile page.
pub const WS_MSG_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Events the daemon routes from inbound frames into a WS relay task.
#[derive(Debug)]
pub enum WsClientEvent {
    Data { text: bool, fin: bool, data: Bytes },
    Close { code: u16, reason: String },
}

struct PendingRequest {
    head: RequestHead,
    body: Vec<u8>,
    /// Set to true once a `BodyTooLarge` error has been reported for this
    /// request id. Subsequent body chunks are silently dropped so we don't
    /// emit a flood of error frames.
    aborted: bool,
}

impl Default for HttpForwardSession {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpForwardSession {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            in_flight: HashMap::new(),
            ws_streams: HashMap::new(),
        }
    }

    /// Process one inbound frame. Returns up to one frame (or a stream
    /// kick-off) that should be sent on the channel. Heavy work (the actual
    /// HTTP fetch) is spawned via [`HttpForwardSession::take_ready_request`]
    /// — keep this method synchronous so the daemon's event loop never
    /// blocks on a slow upstream.
    pub fn ingest(&mut self, frame: Frame) -> Ingest {
        self.reap_completed_in_flight();
        match frame {
            Frame::ReqHead { id, head } => {
                if !head.method.is_ascii() || head.method.is_empty() {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::MalformedFrame,
                        message: "method must be non-empty ASCII".into(),
                    });
                }
                if head.path.is_empty() || !head.path.starts_with('/') {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::MalformedFrame,
                        message: "path must be absolute".into(),
                    });
                }
                self.pending.insert(
                    id,
                    PendingRequest {
                        head,
                        body: Vec::new(),
                        aborted: false,
                    },
                );
                Ingest::Nothing
            }
            Frame::ReqBody { id, data } => {
                let Some(entry) = self.pending.get_mut(&id) else {
                    return Ingest::Nothing; // body arrived after we dropped the request
                };
                if entry.aborted {
                    return Ingest::Nothing;
                }
                if entry.body.len().saturating_add(data.len()) > REQ_BODY_MAX_BYTES {
                    entry.aborted = true;
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::BodyTooLarge,
                        message: format!("request body exceeded {} bytes", REQ_BODY_MAX_BYTES),
                    });
                }
                entry.body.extend_from_slice(&data);
                Ingest::Nothing
            }
            Frame::ReqEnd { id } => {
                let Some(entry) = self.pending.remove(&id) else {
                    return Ingest::Nothing;
                };
                if entry.aborted {
                    return Ingest::Nothing; // error already sent on the overflow
                }
                // Shed load past the concurrency cap. `reap_completed_in_flight`
                // ran at the top of `ingest`, so `in_flight` only counts
                // forwards whose spawned task hasn't dropped its cancel
                // receiver yet. Refuse rather than queue: a queued request
                // would still hold buffered body bytes and the mobile WebView
                // surfaces the error as a failed subresource, which is the
                // honest outcome when a page tries to open more sockets than
                // we're willing to multiplex onto the shared peer.
                if self.in_flight.len() >= MAX_CONCURRENT_REQUESTS {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::TooManyRequests,
                        message: format!(
                            "too many concurrent forwards (cap {MAX_CONCURRENT_REQUESTS}); retry shortly"
                        ),
                    });
                }
                // Create a oneshot cancellation channel for this request.
                // The Sender stays in `in_flight` so a later `ReqCancel`
                // can signal the spawned forward task; the Receiver is
                // handed off in the ReadyRequest. We deliberately don't
                // wire a "task completed → remove from in_flight" signal
                // back here — that would require Arc<Mutex<Session>>;
                // instead the leaked cancel_tx just becomes a no-op send
                // when the task has already finished. Memory bounded by
                // total request count over the channel's lifetime, all
                // freed in `shutdown()`.
                let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
                self.in_flight.insert(id, cancel_tx);
                Ingest::ReadyRequest(ReadyRequest {
                    id,
                    head: entry.head,
                    body: Bytes::from(entry.body),
                    cancel: cancel_rx,
                })
            }
            Frame::ReqCancel { id } => {
                // Pre-promotion cancel: drop the buffer, nothing else
                // needed.
                if self.pending.remove(&id).is_some() {
                    return Ingest::Nothing;
                }
                // Post-promotion cancel: signal the spawned task and
                // surface an error frame so mobile's pending fetch
                // promise rejects (instead of waiting until the
                // upstream-timeout). `oneshot::Sender::send` returns
                // Err if the receiver was already dropped (task done) —
                // in that case skip the error frame, the task will
                // resolve naturally.
                if let Some(cancel_tx) = self.in_flight.remove(&id) {
                    if cancel_tx.send(()).is_ok() {
                        return Ingest::SendBack(Frame::RespError {
                            id,
                            code: ErrorCode::InternalError,
                            message: "request cancelled by client".into(),
                        });
                    }
                }
                Ingest::Nothing
            }
            Frame::WsOpen { id, head } => {
                if head.path.is_empty() || !head.path.starts_with('/') {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::MalformedFrame,
                        message: "path must be absolute".into(),
                    });
                }
                self.reap_closed_ws();
                if self.ws_streams.len() >= MAX_CONCURRENT_WS {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::TooManyRequests,
                        message: format!(
                            "too many concurrent websockets (cap {MAX_CONCURRENT_WS})"
                        ),
                    });
                }
                if self.ws_streams.contains_key(&id) {
                    return Ingest::SendBack(Frame::RespError {
                        id,
                        code: ErrorCode::MalformedFrame,
                        message: "websocket id already in use".into(),
                    });
                }
                // 64 events of headroom: enough for a client bursting sends
                // during the upstream connect, small enough that a stalled
                // relay applies backpressure (we drop, see WsData below)
                // instead of buffering unboundedly.
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                self.ws_streams.insert(id, tx);
                Ingest::WsOpen(WsOpenRequest {
                    id,
                    head,
                    client_rx: rx,
                })
            }
            Frame::WsData {
                id,
                text,
                fin,
                data,
            } => {
                if let Some(tx) = self.ws_streams.get(&id) {
                    // try_send, not send: this runs on the daemon's event
                    // loop and must never block on a slow relay. A full
                    // buffer means the upstream socket has stalled — drop
                    // the fragment (the page's WS sees a lossy tunnel and
                    // its own keepalive recovers) rather than wedge every
                    // other channel sharing the loop.
                    if let Err(e) = tx.try_send(WsClientEvent::Data { text, fin, data }) {
                        tracing::warn!("ws-forward id={}: dropping client frame: {}", id, e);
                    }
                }
                Ingest::Nothing
            }
            Frame::WsClose { id, code, reason } => {
                if let Some(tx) = self.ws_streams.remove(&id) {
                    let _ = tx.try_send(WsClientEvent::Close { code, reason });
                }
                Ingest::Nothing
            }
            // Server only receives request-side frames. Response-side
            // frames showing up here means a protocol bug on the peer; just
            // drop them.
            Frame::RespHead { .. }
            | Frame::RespBody { .. }
            | Frame::RespEnd { .. }
            | Frame::RespError { .. }
            | Frame::WsOpenOk { .. } => Ingest::Nothing,
        }
    }

    /// Drop all in-flight requests — called when the data channel closes.
    /// Sends cancel signals to every spawned forward task so they exit
    /// promptly instead of running to UPSTREAM_TIMEOUT against a closed
    /// channel. WS relays notice their client-event sender dropping and
    /// close the upstream socket.
    pub fn shutdown(&mut self) {
        self.pending.clear();
        for (_, cancel_tx) in self.in_flight.drain() {
            let _ = cancel_tx.send(());
        }
        self.ws_streams.clear();
    }

    fn reap_completed_in_flight(&mut self) {
        self.in_flight.retain(|_, cancel_tx| !cancel_tx.is_closed());
    }

    /// Prune WS entries whose relay task has ended (receiver dropped) so
    /// dead tunnels don't count against MAX_CONCURRENT_WS forever.
    fn reap_closed_ws(&mut self) {
        self.ws_streams.retain(|_, tx| !tx.is_closed());
    }

    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }
}

/// Output of [`HttpForwardSession::ingest`]. The daemon will either:
/// - do nothing (frame buffered or invalid),
/// - send a single response frame back (early error), or
/// - kick off an upstream fetch task whose response frames get streamed
///   back via the channel.
#[derive(Debug)]
pub enum Ingest {
    Nothing,
    SendBack(Frame),
    ReadyRequest(ReadyRequest),
    /// A WsOpen was admitted — the daemon spawns
    /// [`crate::ws_forward::forward_ws`] with this and pumps its frames
    /// back onto the channel, exactly like an HTTP ReadyRequest.
    WsOpen(WsOpenRequest),
}

/// An admitted WebSocket-open, handed to the relay task. `client_rx`
/// receives the mobile side's outbound messages / close, routed by the
/// daemon from subsequent WsData/WsClose frames with the same id.
pub struct WsOpenRequest {
    pub id: u32,
    pub head: RequestHead,
    pub client_rx: tokio::sync::mpsc::Receiver<WsClientEvent>,
}

impl std::fmt::Debug for WsOpenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsOpenRequest")
            .field("id", &self.id)
            .field("head", &self.head)
            .finish()
    }
}

pub struct ReadyRequest {
    pub id: u32,
    pub head: RequestHead,
    pub body: Bytes,
    /// Cancellation receiver. The spawned forward task selects against
    /// this; when it fires (sender called in `ingest(ReqCancel)` or in
    /// `shutdown()`), the in-flight reqwest / body stream is aborted.
    pub cancel: tokio::sync::oneshot::Receiver<()>,
}

impl std::fmt::Debug for ReadyRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadyRequest")
            .field("id", &self.id)
            .field("head", &self.head)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Outcome of [`forward_request`]. The caller (daemon) wraps these as
/// `Frame`s and writes them to the WebRTC channel.
pub struct ForwardOutcome {
    pub head: Frame,
    /// Streamed body chunks followed by a `RespEnd`. Cancel by dropping
    /// the receiver.
    pub body: tokio::sync::mpsc::Receiver<Frame>,
}

/// Reject `req` because no allowlist entry exists for its target port.
/// Returned as a single error frame — no upstream connection is opened.
pub fn build_port_not_exposed(id: u32, port: u16) -> Frame {
    Frame::RespError {
        id,
        code: ErrorCode::PortNotExposed,
        message: format!(
            "port {} is not exposed. Run `pocketshell expose {}` on this host.",
            port, port
        ),
    }
}

/// Perform the upstream fetch and stream response frames into a channel.
/// Designed to be `tokio::spawn`'d.
///
/// Allowlist gate: rejects with [`ErrorCode::PortNotExposed`] before any
/// socket is opened. Re-checks per request (not per session) so a runtime
/// `pocketshell unexpose 3000` takes effect immediately for new requests.
pub async fn forward_request(req: ReadyRequest) -> ForwardOutcome {
    let (tx, rx) = tokio::sync::mpsc::channel::<Frame>(32);

    // Allowlist gate — fail closed.
    let allowed = match ExposedPortsStore::is_allowed(req.head.port) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("exposed_ports read failed: {} — denying request", e);
            false
        }
    };
    if !allowed {
        tracing::info!(
            port = req.head.port,
            method = %req.head.method,
            path = %log_path(&req.head.path),
            "http-forward denied: port not in allowlist"
        );
        // Send a single error frame; no head. We send via `head` field so
        // the daemon writes it in the order: error (alone). The body
        // receiver immediately closes.
        let outcome = ForwardOutcome {
            head: build_port_not_exposed(req.id, req.head.port),
            body: rx,
        };
        drop(tx);
        return outcome;
    }

    // Build the upstream request. Pass through `Host:` as `localhost:<port>`
    // so Vite/Webpack's DNS-rebinding guard doesn't reject the request.
    //
    // Use `localhost` (not `127.0.0.1`) so the OS resolver returns whatever
    // family the host's `getaddrinfo` says first. Node 17+ defaults
    // `dns.lookup` to `verbatim` order, and macOS returns `::1` first — so
    // Vite et al. bound to `localhost` end up listening on `[::1]:<port>`
    // only, with no IPv4 socket. Hardcoding `127.0.0.1` here would
    // refuse-connect against any such dev server.
    //
    // Note: reqwest's default `hyper-util` connector iterates resolved
    // addresses sequentially (no Happy Eyeballs by default). For most
    // dev setups `/etc/hosts` returns the single working family first;
    // if a host has both `127.0.0.1` and `::1` in `/etc/hosts` but no
    // IPv6 connectivity, the first connect will block until kernel
    // timeout. Revisit with a Happy-Eyeballs resolver if that comes up.
    let url = format!("http://localhost:{}{}", req.head.port, req.head.path);
    let mut builder = reqwest::Client::builder()
        // NO total-request `.timeout(...)` here: it would cover the entire
        // body read and abort long-lived streams (SSE) mid-flight. The head
        // is deadlined with `tokio::time::timeout(UPSTREAM_TIMEOUT, send)`
        // below, and non-streaming bodies get a per-chunk idle timeout.
        .connect_timeout(UPSTREAM_TIMEOUT)
        // No keepalive — dev servers come and go.
        .pool_max_idle_per_host(0)
        // Don't follow redirects: forward whatever the dev server returns
        // so the WebView sees its real status (3xx for SPA routing fallbacks
        // would otherwise be silently chased).
        .redirect(reqwest::redirect::Policy::none())
        .build();

    let client = match builder.as_mut() {
        Ok(c) => c.clone(),
        Err(e) => {
            // Return the error AS the head frame, not into the body
            // channel. The daemon writes `head` first; if we put the
            // error in `body` and head as RespEnd, mobile sees a
            // protocol-violating "ended without head" and the real
            // failure is dropped as an orphan.
            drop(tx);
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::InternalError,
                    message: format!("reqwest client build failed: {e}"),
                },
                body: rx,
            };
        }
    };

    let method = match reqwest::Method::from_bytes(req.head.method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::MalformedFrame,
                    message: format!("invalid HTTP method `{}`", req.head.method),
                },
                body: rx,
            };
        }
    };

    let mut rb = client.request(method, &url);
    let synthetic_host = format!("localhost:{}", req.head.port);
    let mut saw_host = false;
    for (name, value) in &req.head.headers {
        // Strip hop-by-hop headers that reqwest will manage itself.
        if header_is_hop_by_hop(name) {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            saw_host = true;
            rb = rb.header(name, &synthetic_host);
        } else {
            rb = rb.header(name, value);
        }
    }
    if !saw_host {
        rb = rb.header("Host", &synthetic_host);
    }
    if !req.body.is_empty() {
        rb = rb.body(req.body);
    }

    // Race the upstream send against the cancellation oneshot. If the
    // mobile peer fires ReqCancel before the dev-server responds (e.g.
    // user navigates away during a slow Vite compile), we abort here
    // instead of waiting out UPSTREAM_TIMEOUT. The head deadline lives
    // here (not on the reqwest client) so the body phase is free of any
    // total-request timeout — see UPSTREAM_TIMEOUT's doc.
    let mut cancel = req.cancel;
    let send_fut = tokio::time::timeout(UPSTREAM_TIMEOUT, rb.send());
    tokio::pin!(send_fut);
    let send_outcome = tokio::select! {
        biased; // prefer cancel so a racing cancel-before-send-poll is honored
        _ = &mut cancel => {
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::InternalError,
                    message: "request cancelled before upstream response".into(),
                },
                body: rx,
            };
        }
        result = &mut send_fut => result,
    };
    let resp = match send_outcome {
        Ok(Ok(r)) => r,
        Err(_) => {
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::UpstreamTimeout,
                    message: format!(
                        "upstream did not answer within {}s",
                        UPSTREAM_TIMEOUT.as_secs()
                    ),
                },
                body: rx,
            };
        }
        Ok(Err(e)) if e.is_timeout() => {
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::UpstreamTimeout,
                    message: format!("upstream timed out: {e}"),
                },
                body: rx,
            };
        }
        Ok(Err(e)) => {
            return ForwardOutcome {
                head: Frame::RespError {
                    id: req.id,
                    code: ErrorCode::UpstreamFailed,
                    message: format!("upstream connect failed: {e}"),
                },
                body: rx,
            };
        }
    };

    let status = resp.status().as_u16();
    tracing::info!(
        port = req.head.port,
        method = %req.head.method,
        path = %log_path(&req.head.path),
        status,
        "http-forward completed"
    );
    let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
    for (name, value) in resp.headers() {
        // HTTP header values are ISO-8859-1 (RFC 7230 §3.2.4), not
        // UTF-8 — `value.to_str()` rejects any byte ≥ 0x80, which
        // silently drops legitimate cookie / authorization values
        // containing high-bit bytes. Use a lossy conversion so the
        // header at least round-trips. Any replacement character
        // surfacing in the mobile-side WebView is a much better
        // failure mode than the cookie vanishing without a trace.
        let v = match value.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => {
                tracing::warn!(
                    "http-forward: header {} has non-UTF8 bytes; converting lossily",
                    name.as_str()
                );
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            }
        };
        headers.push((name.as_str().to_string(), v));
    }

    // Spawn the body-streaming task. Caller polls `body` for chunks; we
    // close the channel after sending `RespEnd` (or an error mid-stream).
    // The cancellation oneshot is selected against each `resp.chunk()` so
    // a mid-stream ReqCancel aborts the upstream read immediately rather
    // than draining whatever bytes were already in flight.
    //
    // Streaming responses (SSE) are exempt from the per-chunk idle timeout:
    // an event stream sitting quiet for minutes is normal, and its lifetime
    // is bounded by the client cancel / channel close instead.
    let id = req.id;
    let streaming = is_event_stream_headers(&headers);
    tokio::spawn(async move {
        let mut resp = resp;
        let mut cancel = cancel;
        let mut sent_bytes: usize = 0;
        loop {
            let chunk_fut = resp.chunk();
            tokio::pin!(chunk_fut);
            let chunk_outcome = tokio::select! {
                biased;
                _ = &mut cancel => {
                    let _ = tx
                        .send(Frame::RespError {
                            id,
                            code: ErrorCode::InternalError,
                            message: "stream cancelled by client".into(),
                        })
                        .await;
                    return;
                }
                result = async {
                    if streaming {
                        // No idle deadline — wait as long as the upstream
                        // keeps the stream open.
                        Ok(chunk_fut.as_mut().await)
                    } else {
                        tokio::time::timeout(BODY_IDLE_TIMEOUT, chunk_fut.as_mut()).await
                    }
                } => match result {
                    Ok(r) => r,
                    Err(_) => {
                        let _ = tx
                            .send(Frame::RespError {
                                id,
                                code: ErrorCode::UpstreamTimeout,
                                message: format!(
                                    "response body stalled for {}s",
                                    BODY_IDLE_TIMEOUT.as_secs()
                                ),
                            })
                            .await;
                        return;
                    }
                },
            };
            match chunk_outcome {
                Ok(Some(chunk)) => {
                    // Abort once the cumulative body crosses the cap. The
                    // mobile hook enforces the same 32 MB limit, so without
                    // this we'd stream tens of MB the phone is just going to
                    // discard — wasted bytes on a channel the terminal shares.
                    if sent_bytes.saturating_add(chunk.len()) > RESP_BODY_MAX_BYTES {
                        let _ = tx
                            .send(Frame::RespError {
                                id,
                                code: ErrorCode::BodyTooLarge,
                                message: format!(
                                    "response body exceeded {RESP_BODY_MAX_BYTES} bytes"
                                ),
                            })
                            .await;
                        return;
                    }
                    sent_bytes += chunk.len();
                    // Split into RESP_BODY_CHUNK_BYTES pieces to stay
                    // under the SCTP message ceiling.
                    for slice in chunk.chunks(RESP_BODY_CHUNK_BYTES) {
                        if tx
                            .send(Frame::RespBody {
                                id,
                                data: Bytes::copy_from_slice(slice),
                            })
                            .await
                            .is_err()
                        {
                            // Receiver dropped (channel closed); stop.
                            return;
                        }
                    }
                }
                Ok(None) => {
                    let _ = tx.send(Frame::RespEnd { id }).await;
                    return;
                }
                Err(e) => {
                    let _ = tx
                        .send(Frame::RespError {
                            id,
                            code: ErrorCode::UpstreamFailed,
                            message: format!("upstream stream errored: {e}"),
                        })
                        .await;
                    return;
                }
            }
        }
    });

    ForwardOutcome {
        head: Frame::RespHead {
            id: req.id,
            head: ResponseHead { status, headers },
        },
        body: rx,
    }
}

/// Render a forwarded request's path for operator logs without leaking
/// sensitive query string content (OAuth `code=`, session tokens, etc.)
/// and without unbounded growth from long deep links. Strips everything
/// from the first `?` and truncates the result at 128 bytes.
fn log_path(path: &str) -> String {
    let stripped = path.split('?').next().unwrap_or("");
    if stripped.len() <= 128 {
        stripped.to_string()
    } else {
        format!("{}…", &stripped[..128])
    }
}

/// True when the response headers declare a `text/event-stream` body — the
/// content type that legitimately never ends and may go silent for minutes
/// between events. Drives the idle-timeout exemption in the body pump and
/// lets future callers branch on "this will stream forever".
pub fn is_event_stream_headers(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value.to_ascii_lowercase().contains("text/event-stream")
    })
}

fn header_is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            // `Content-Length` is set by reqwest based on the body we attach.
            | "content-length"
    )
}

// `HostError::Io` impl lets `?` work cleanly inside callers that bubble
// codec errors through the host-core error type when needed. The codec
// itself uses its own `CodecError` enum so the test surface is precise.
impl From<CodecError> for HostError {
    fn from(e: CodecError) -> Self {
        HostError::Config(format!("http_forward codec: {e}"))
    }
}

#[allow(unused)]
fn _force_result_type() -> Result<()> {
    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_req_head() -> RequestHead {
        RequestHead {
            port: 3000,
            method: "GET".into(),
            path: "/index.html".into(),
            headers: vec![
                ("Accept".into(), "text/html".into()),
                ("User-Agent".into(), "pocketshell-mobile/1.0".into()),
            ],
        }
    }

    #[test]
    fn log_path_strips_query_and_truncates() {
        // No query: pass through.
        assert_eq!(log_path("/api/users"), "/api/users");
        // Query stripped — tokens never reach the log file.
        assert_eq!(
            log_path("/oauth/callback?code=secret_token_abc&state=xyz"),
            "/oauth/callback"
        );
        // Long path truncated with ellipsis so 128-char cap holds.
        let long = format!("/{}", "a".repeat(200));
        let out = log_path(&long);
        assert!(out.ends_with('…'));
        assert!(out.chars().count() <= 129);
        // Empty input is fine.
        assert_eq!(log_path(""), "");
        assert_eq!(log_path("?key=val"), "");
    }

    #[test]
    fn roundtrip_req_head() {
        let f = Frame::ReqHead {
            id: 42,
            head: sample_req_head(),
        };
        let bytes = encode(&f);
        let back = decode(&bytes).unwrap();
        match back {
            Frame::ReqHead { id, head } => {
                assert_eq!(id, 42);
                assert_eq!(head, sample_req_head());
            }
            _ => panic!("wrong variant: {:?}", back),
        }
    }

    #[test]
    fn roundtrip_req_body() {
        let payload = Bytes::from_static(b"some=value&other=42");
        let f = Frame::ReqBody {
            id: 7,
            data: payload.clone(),
        };
        let back = decode(&encode(&f)).unwrap();
        match back {
            Frame::ReqBody { id, data } => {
                assert_eq!(id, 7);
                assert_eq!(data, payload);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_req_end_and_cancel() {
        for f in [Frame::ReqEnd { id: 1 }, Frame::ReqCancel { id: 2 }] {
            let bytes = encode(&f);
            let back = decode(&bytes).unwrap();
            assert_eq!(back.id(), f.id());
            assert_eq!(back.opcode(), f.opcode());
        }
    }

    #[test]
    fn roundtrip_resp_head() {
        let f = Frame::RespHead {
            id: 99,
            head: ResponseHead {
                status: 200,
                headers: vec![
                    ("Content-Type".into(), "text/html; charset=utf-8".into()),
                    ("X-Powered-By".into(), "Vite".into()),
                ],
            },
        };
        let back = decode(&encode(&f)).unwrap();
        match back {
            Frame::RespHead { id, head } => {
                assert_eq!(id, 99);
                assert_eq!(head.status, 200);
                assert_eq!(head.headers.len(), 2);
                assert_eq!(head.headers[0].0, "Content-Type");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_resp_body_and_end() {
        let body = Bytes::from_static(b"<!doctype html><html></html>");
        let f1 = Frame::RespBody {
            id: 1,
            data: body.clone(),
        };
        let f2 = Frame::RespEnd { id: 1 };
        let b1 = decode(&encode(&f1)).unwrap();
        let b2 = decode(&encode(&f2)).unwrap();
        match b1 {
            Frame::RespBody { id, data } => {
                assert_eq!(id, 1);
                assert_eq!(data, body);
            }
            _ => panic!(),
        }
        assert_eq!(b2.id(), 1);
        assert_eq!(b2.opcode(), Opcode::ResponseEnd);
    }

    #[test]
    fn roundtrip_resp_error() {
        let f = Frame::RespError {
            id: 5,
            code: ErrorCode::PortNotExposed,
            message: "port 3000 is not exposed.".into(),
        };
        let back = decode(&encode(&f)).unwrap();
        match back {
            Frame::RespError { id, code, message } => {
                assert_eq!(id, 5);
                assert_eq!(code, ErrorCode::PortNotExposed);
                assert!(message.contains("3000"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut buf = encode(&Frame::ReqEnd { id: 1 });
        buf[0] = 0xff;
        let err = decode(&buf).unwrap_err();
        assert!(matches!(err, CodecError::BadMagic));
    }

    #[test]
    fn decode_rejects_short_buf() {
        let err = decode(&[0, 1, 2]).unwrap_err();
        assert!(matches!(err, CodecError::TooShort(3)));
    }

    #[test]
    fn decode_rejects_unknown_opcode() {
        let mut buf = encode(&Frame::ReqEnd { id: 1 });
        buf[FRAME_MAGIC.len()] = 0xfe;
        let err = decode(&buf).unwrap_err();
        assert!(matches!(err, CodecError::UnknownOpcode(0xfe)));
    }

    #[test]
    fn decode_rejects_truncated_string_payload() {
        // Manually construct a malformed ReqHead: claims a 100-byte method
        // but only ships 3. Decoder must refuse rather than read OOB.
        let mut buf = Vec::new();
        buf.extend_from_slice(&FRAME_MAGIC);
        buf.push(Opcode::RequestHead as u8);
        buf.extend_from_slice(&1u32.to_be_bytes()); // id
        buf.extend_from_slice(&3000u16.to_be_bytes()); // port
        buf.push(100); // method_len lie
        buf.extend_from_slice(b"GET"); // only 3 bytes
        let err = decode(&buf).unwrap_err();
        assert!(matches!(err, CodecError::BadPayload(_)));
    }

    #[test]
    fn session_buffers_body_chunks_until_end() {
        let mut s = HttpForwardSession::new();
        let ingest = s.ingest(Frame::ReqHead {
            id: 1,
            head: sample_req_head(),
        });
        assert!(matches!(ingest, Ingest::Nothing));
        assert_eq!(s.pending_count(), 1);

        let _ = s.ingest(Frame::ReqBody {
            id: 1,
            data: Bytes::from_static(b"hello"),
        });
        let _ = s.ingest(Frame::ReqBody {
            id: 1,
            data: Bytes::from_static(b" world"),
        });
        let out = s.ingest(Frame::ReqEnd { id: 1 });
        match out {
            Ingest::ReadyRequest(r) => {
                assert_eq!(r.id, 1);
                assert_eq!(&r.body[..], b"hello world");
            }
            _ => panic!("expected ReadyRequest, got {:?}", out),
        }
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn session_rejects_malformed_method() {
        let mut s = HttpForwardSession::new();
        let head = RequestHead {
            method: "".into(),
            ..sample_req_head()
        };
        let out = s.ingest(Frame::ReqHead { id: 1, head });
        match out {
            Ingest::SendBack(Frame::RespError { code, .. }) => {
                assert_eq!(code, ErrorCode::MalformedFrame);
            }
            _ => panic!("expected MalformedFrame error"),
        }
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn session_rejects_relative_path() {
        let mut s = HttpForwardSession::new();
        let head = RequestHead {
            path: "index.html".into(), // missing leading /
            ..sample_req_head()
        };
        let out = s.ingest(Frame::ReqHead { id: 1, head });
        assert!(matches!(out, Ingest::SendBack(Frame::RespError { .. })));
    }

    #[test]
    fn session_body_overflow_emits_error_and_drops_further_chunks() {
        let mut s = HttpForwardSession::new();
        let _ = s.ingest(Frame::ReqHead {
            id: 1,
            head: RequestHead {
                method: "POST".into(),
                path: "/upload".into(),
                ..sample_req_head()
            },
        });
        let huge = vec![0u8; REQ_BODY_MAX_BYTES + 1];
        let out = s.ingest(Frame::ReqBody {
            id: 1,
            data: Bytes::from(huge),
        });
        match out {
            Ingest::SendBack(Frame::RespError { code, .. }) => {
                assert_eq!(code, ErrorCode::BodyTooLarge);
            }
            _ => panic!("expected BodyTooLarge"),
        }

        // Subsequent body chunks for the aborted request are silently
        // dropped — no flood of duplicate error frames.
        let after = s.ingest(Frame::ReqBody {
            id: 1,
            data: Bytes::from_static(b"more"),
        });
        assert!(matches!(after, Ingest::Nothing));

        // ReqEnd after abort is a no-op (no ReadyRequest emitted).
        let end = s.ingest(Frame::ReqEnd { id: 1 });
        assert!(matches!(end, Ingest::Nothing));
    }

    #[test]
    fn session_sheds_load_past_concurrency_cap() {
        let mut s = HttpForwardSession::new();
        // Promote MAX_CONCURRENT_REQUESTS requests and hold their cancel
        // receivers so `reap_completed_in_flight` can't prune them — this
        // simulates that many forwards genuinely in flight.
        let mut held = Vec::new();
        for id in 0..MAX_CONCURRENT_REQUESTS as u32 {
            let _ = s.ingest(Frame::ReqHead {
                id,
                head: sample_req_head(),
            });
            match s.ingest(Frame::ReqEnd { id }) {
                Ingest::ReadyRequest(r) => held.push(r.cancel),
                other => panic!("expected ReadyRequest for id {id}, got {other:?}"),
            }
        }
        assert_eq!(s.in_flight_count(), MAX_CONCURRENT_REQUESTS);

        // The next request must be shed with TooManyRequests, not promoted.
        let over = MAX_CONCURRENT_REQUESTS as u32;
        let _ = s.ingest(Frame::ReqHead {
            id: over,
            head: sample_req_head(),
        });
        match s.ingest(Frame::ReqEnd { id: over }) {
            Ingest::SendBack(Frame::RespError { id, code, .. }) => {
                assert_eq!(id, over);
                assert_eq!(code, ErrorCode::TooManyRequests);
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }
        assert_eq!(
            s.in_flight_count(),
            MAX_CONCURRENT_REQUESTS,
            "shed request must not be counted as in flight"
        );

        // Once an in-flight task finishes (its cancel receiver drops), the
        // slot frees and a new request is admitted again.
        held.pop();
        let _ = s.ingest(Frame::ReqHead {
            id: over + 1,
            head: sample_req_head(),
        });
        assert!(matches!(
            s.ingest(Frame::ReqEnd { id: over + 1 }),
            Ingest::ReadyRequest(_)
        ));
    }

    #[test]
    fn error_code_roundtrips_too_many_requests() {
        let f = Frame::RespError {
            id: 3,
            code: ErrorCode::TooManyRequests,
            message: "slow down".into(),
        };
        match decode(&encode(&f)).unwrap() {
            Frame::RespError { code, .. } => assert_eq!(code, ErrorCode::TooManyRequests),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn session_cancel_drops_pending() {
        let mut s = HttpForwardSession::new();
        let _ = s.ingest(Frame::ReqHead {
            id: 1,
            head: sample_req_head(),
        });
        assert_eq!(s.pending_count(), 1);
        let _ = s.ingest(Frame::ReqCancel { id: 1 });
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn session_cancel_after_promotion_signals_inflight_and_emits_error() {
        let mut s = HttpForwardSession::new();
        let _ = s.ingest(Frame::ReqHead {
            id: 1,
            head: sample_req_head(),
        });
        // Promote to in_flight by sending ReqEnd.
        let ready = match s.ingest(Frame::ReqEnd { id: 1 }) {
            Ingest::ReadyRequest(r) => r,
            other => panic!("expected ReadyRequest, got {other:?}"),
        };
        // Hold the cancel receiver — we'll observe it firing.
        let mut cancel_rx = ready.cancel;

        let out = s.ingest(Frame::ReqCancel { id: 1 });
        // Must emit a RespError frame so mobile's pending fetch
        // rejects (instead of hanging on the WebView's load).
        match out {
            Ingest::SendBack(Frame::RespError {
                id,
                code,
                message: _,
            }) => {
                assert_eq!(id, 1);
                assert_eq!(code, ErrorCode::InternalError);
            }
            other => panic!("expected SendBack(RespError), got {other:?}"),
        }
        // The oneshot receiver must have fired so the forward task
        // observes the cancel.
        assert!(matches!(cancel_rx.try_recv(), Ok(())));
    }

    #[test]
    fn session_reaps_completed_inflight_on_next_frame() {
        let mut s = HttpForwardSession::new();
        let _ = s.ingest(Frame::ReqHead {
            id: 1,
            head: sample_req_head(),
        });
        let ready = match s.ingest(Frame::ReqEnd { id: 1 }) {
            Ingest::ReadyRequest(r) => r,
            other => panic!("expected ReadyRequest, got {other:?}"),
        };
        assert_eq!(s.in_flight_count(), 1);

        // Simulate the spawned forward task completing and dropping its
        // cancellation receiver. The next inbound frame should prune the
        // now-useless Sender instead of retaining one entry per request for
        // the whole channel lifetime.
        drop(ready);
        let _ = s.ingest(Frame::ReqCancel { id: 999 });
        assert_eq!(s.in_flight_count(), 0);
    }

    #[test]
    fn session_shutdown_signals_all_in_flight() {
        let mut s = HttpForwardSession::new();
        let _ = s.ingest(Frame::ReqHead {
            id: 1,
            head: sample_req_head(),
        });
        let _ = s.ingest(Frame::ReqHead {
            id: 2,
            head: sample_req_head(),
        });
        let r1 = match s.ingest(Frame::ReqEnd { id: 1 }) {
            Ingest::ReadyRequest(r) => r,
            _ => panic!(),
        };
        let r2 = match s.ingest(Frame::ReqEnd { id: 2 }) {
            Ingest::ReadyRequest(r) => r,
            _ => panic!(),
        };
        let mut c1 = r1.cancel;
        let mut c2 = r2.cancel;

        s.shutdown();
        // Both spawned-task cancels must fire so the forward loops
        // exit promptly on channel close.
        assert!(matches!(c1.try_recv(), Ok(())));
        assert!(matches!(c2.try_recv(), Ok(())));
    }

    #[test]
    fn session_drops_orphan_body_silently() {
        let mut s = HttpForwardSession::new();
        // No ReqHead first — body for unknown id should not panic or emit.
        let out = s.ingest(Frame::ReqBody {
            id: 99,
            data: Bytes::from_static(b"x"),
        });
        assert!(matches!(out, Ingest::Nothing));
        assert_eq!(s.pending_count(), 0);
    }

    #[test]
    fn roundtrip_ws_open() {
        let f = Frame::WsOpen {
            id: 11,
            head: RequestHead {
                port: 5173,
                method: "GET".into(),
                path: "/hmr?token=x".into(),
                headers: vec![("Sec-WebSocket-Protocol".into(), "vite-hmr".into())],
            },
        };
        match decode(&encode(&f)).unwrap() {
            Frame::WsOpen { id, head } => {
                assert_eq!(id, 11);
                assert_eq!(head.port, 5173);
                assert_eq!(head.path, "/hmr?token=x");
                assert_eq!(head.headers[0].1, "vite-hmr");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_ws_data_flag_combinations() {
        for (text, fin) in [(false, false), (true, false), (false, true), (true, true)] {
            let f = Frame::WsData {
                id: 3,
                text,
                fin,
                data: Bytes::from_static(b"{\"type\":\"update\"}"),
            };
            match decode(&encode(&f)).unwrap() {
                Frame::WsData {
                    id,
                    text: t,
                    fin: fi,
                    data,
                } => {
                    assert_eq!(id, 3);
                    assert_eq!(t, text);
                    assert_eq!(fi, fin);
                    assert_eq!(&data[..], b"{\"type\":\"update\"}");
                }
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    #[test]
    fn roundtrip_ws_data_empty_payload() {
        // Empty text messages are legal WS heartbeats; the codec must not
        // confuse "no bytes after flags" with a truncated frame.
        let f = Frame::WsData {
            id: 4,
            text: true,
            fin: true,
            data: Bytes::new(),
        };
        match decode(&encode(&f)).unwrap() {
            Frame::WsData { data, fin, .. } => {
                assert!(data.is_empty());
                assert!(fin);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn roundtrip_ws_close_and_open_ok() {
        let f = Frame::WsClose {
            id: 8,
            code: 1001,
            reason: "going away".into(),
        };
        match decode(&encode(&f)).unwrap() {
            Frame::WsClose { id, code, reason } => {
                assert_eq!((id, code), (8, 1001));
                assert_eq!(reason, "going away");
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let f = Frame::WsOpenOk {
            id: 8,
            headers: vec![("Sec-WebSocket-Protocol".into(), "vite-hmr".into())],
        };
        match decode(&encode(&f)).unwrap() {
            Frame::WsOpenOk { id, headers } => {
                assert_eq!(id, 8);
                assert_eq!(headers[0].0, "Sec-WebSocket-Protocol");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn session_ws_open_registers_stream_and_routes_data() {
        let mut s = HttpForwardSession::new();
        let ready = s.ingest(Frame::WsOpen {
            id: 1,
            head: sample_req_head(),
        });
        let mut client_rx = match ready {
            Ingest::WsOpen(r) => {
                assert_eq!(r.id, 1);
                r.client_rx
            }
            other => panic!("expected WsOpen, got {other:?}"),
        };

        // WsData for the id reaches the relay's receiver.
        let _ = s.ingest(Frame::WsData {
            id: 1,
            text: true,
            fin: true,
            data: Bytes::from_static(b"ping"),
        });
        match client_rx.try_recv().unwrap() {
            WsClientEvent::Data { text, fin, data } => {
                assert!(text && fin);
                assert_eq!(&data[..], b"ping");
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // WsClose routes a Close event and frees the slot.
        let _ = s.ingest(Frame::WsClose {
            id: 1,
            code: 1000,
            reason: "bye".into(),
        });
        match client_rx.try_recv().unwrap() {
            WsClientEvent::Close { code, .. } => assert_eq!(code, 1000),
            other => panic!("expected Close, got {other:?}"),
        }
        // Subsequent data for the closed id is silently dropped.
        let _ = s.ingest(Frame::WsData {
            id: 1,
            text: false,
            fin: true,
            data: Bytes::from_static(b"late"),
        });
        assert!(client_rx.try_recv().is_err());
    }

    #[test]
    fn session_ws_open_sheds_past_cap_and_recovers_on_drop() {
        let mut s = HttpForwardSession::new();
        let mut held = Vec::new();
        for id in 0..MAX_CONCURRENT_WS as u32 {
            match s.ingest(Frame::WsOpen {
                id,
                head: sample_req_head(),
            }) {
                Ingest::WsOpen(r) => held.push(r.client_rx),
                other => panic!("expected WsOpen for id {id}, got {other:?}"),
            }
        }

        let over = MAX_CONCURRENT_WS as u32;
        match s.ingest(Frame::WsOpen {
            id: over,
            head: sample_req_head(),
        }) {
            Ingest::SendBack(Frame::RespError { code, .. }) => {
                assert_eq!(code, ErrorCode::TooManyRequests);
            }
            other => panic!("expected TooManyRequests, got {other:?}"),
        }

        // A relay ending (receiver dropped) frees its slot on the next open.
        held.pop();
        assert!(matches!(
            s.ingest(Frame::WsOpen {
                id: over + 1,
                head: sample_req_head(),
            }),
            Ingest::WsOpen(_)
        ));
    }

    #[test]
    fn session_ws_duplicate_id_rejected() {
        let mut s = HttpForwardSession::new();
        let _first = match s.ingest(Frame::WsOpen {
            id: 7,
            head: sample_req_head(),
        }) {
            Ingest::WsOpen(r) => r,
            other => panic!("expected WsOpen, got {other:?}"),
        };
        match s.ingest(Frame::WsOpen {
            id: 7,
            head: sample_req_head(),
        }) {
            Ingest::SendBack(Frame::RespError { code, .. }) => {
                assert_eq!(code, ErrorCode::MalformedFrame);
            }
            other => panic!("expected MalformedFrame, got {other:?}"),
        }
    }

    #[test]
    fn session_shutdown_drops_ws_senders() {
        let mut s = HttpForwardSession::new();
        let mut rx = match s.ingest(Frame::WsOpen {
            id: 1,
            head: sample_req_head(),
        }) {
            Ingest::WsOpen(r) => r.client_rx,
            other => panic!("expected WsOpen, got {other:?}"),
        };
        s.shutdown();
        // Sender dropped → relay's recv() returns None → it closes upstream.
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn build_port_not_exposed_frame() {
        let f = build_port_not_exposed(7, 3000);
        match f {
            Frame::RespError {
                id, code, message, ..
            } => {
                assert_eq!(id, 7);
                assert_eq!(code, ErrorCode::PortNotExposed);
                assert!(message.contains("3000"));
                assert!(message.contains("pocketshell expose"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn header_is_hop_by_hop_classification() {
        assert!(header_is_hop_by_hop("Connection"));
        assert!(header_is_hop_by_hop("transfer-encoding"));
        assert!(header_is_hop_by_hop("Content-Length"));
        assert!(!header_is_hop_by_hop("Accept"));
        assert!(!header_is_hop_by_hop("User-Agent"));
    }

    #[test]
    fn encode_respects_short_string_length_cap() {
        // method up to 255 bytes; longer methods are truncated cleanly
        // (decoder won't see a length mismatch).
        let head = RequestHead {
            method: "X".repeat(300),
            ..sample_req_head()
        };
        let bytes = encode(&Frame::ReqHead { id: 1, head });
        let back = decode(&bytes).unwrap();
        match back {
            Frame::ReqHead { head, .. } => assert_eq!(head.method.len(), 255),
            _ => panic!(),
        }
    }

    #[test]
    fn encode_truncates_multibyte_at_char_boundary() {
        // Without the char-boundary fix, slicing at byte 255 in
        // `"🚀".repeat(100)` (400 bytes of 4-byte codepoints) would land
        // mid-codepoint and produce a frame the decoder rejects with
        // BadUtf8. With the fix we land on a boundary ≤ 255.
        let head = RequestHead {
            method: "🚀".repeat(100),
            ..sample_req_head()
        };
        let bytes = encode(&Frame::ReqHead { id: 1, head });
        let back = decode(&bytes).expect("must decode without BadUtf8");
        match back {
            Frame::ReqHead { head, .. } => {
                // Every char should be the full 🚀 codepoint.
                assert!(head.method.chars().all(|c| c == '🚀'));
                assert!(head.method.len() <= 255);
            }
            _ => panic!(),
        }
    }

    /// Verifies the security gate: `forward_request` must refuse any port
    /// that isn't in the allowlist *before* opening a socket. We test by
    /// pointing at a port that almost certainly has no listener — even if
    /// it did, the test would still pass because the deny is supposed to
    /// happen before the upstream connect.
    #[tokio::test]
    async fn forward_request_denies_when_port_not_exposed() {
        let _g = crate::test_support::HOME_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", tmp.path()) };
        std::fs::create_dir_all(tmp.path().join(".pocketshell")).unwrap();

        let (_tx, cancel) = tokio::sync::oneshot::channel();
        let req = ReadyRequest {
            id: 7,
            head: RequestHead {
                port: 65500,
                method: "GET".into(),
                path: "/".into(),
                headers: vec![],
            },
            body: Bytes::new(),
            cancel,
        };
        let outcome = forward_request(req).await;

        // Restore HOME before assertions so a panic doesn't leak env state.
        unsafe {
            match prev_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }

        match outcome.head {
            Frame::RespError {
                id, code, message, ..
            } => {
                assert_eq!(id, 7);
                assert_eq!(code, ErrorCode::PortNotExposed);
                assert!(message.contains("65500"));
            }
            other => panic!("expected RespError(PortNotExposed), got {other:?}"),
        }
        // The body receiver must immediately close — no streamed chunks
        // since no upstream connection was opened.
        let mut body = outcome.body;
        assert!(body.recv().await.is_none());
    }
}
