//! Discovery of locally-listening TCP ports for the `ports/list_dev` control
//! RPC. Lets the mobile app present "here are the dev servers running on your
//! host" with a tap-to-expose affordance, instead of making the user guess a
//! port and switch to a terminal blind.
//!
//! ## Read-only by design
//!
//! This module never exposes a port. Exposing a port for forwarding still
//! requires `pocketshell expose <port>` in a TTY (or the daemon TUI) — that
//! is the deliberate trust boundary from `TODO-dev-server-forward.md`: a
//! stolen phone cannot make a local service reachable without the operator
//! typing a command. *Listing* what is already listening is safe: the paired
//! device has shell access, so it could run `ss`/`lsof` over the terminal
//! channel anyway. We surface the same information more conveniently and tag
//! each port with `is_exposed` so the UI knows whether forwarding will work.
//!
//! ## Platform strategy
//!
//! - **Linux** — parse `/proc/net/tcp` + `/proc/net/tcp6` for sockets in the
//!   LISTEN state, then best-effort map the socket inode → owning pid by
//!   walking `/proc/<pid>/fd`. pid/name resolution is best-effort: a non-root
//!   daemon can only read its own user's `/proc` entries, so other users'
//!   ports come back with `pid: null`. That is fine — the port and probe are
//!   the load-bearing signals.
//! - **macOS** — shell out to `lsof -nP -iTCP -sTCP:LISTEN` and parse it.
//! - **Windows** - shell out to `netstat -ano -p tcp` and parse it, then
//!   best-effort map the owning pid to a process name via `sysinfo`.
//!
//! Either way we keep only ports reachable over `localhost` (loopback or
//! wildcard binds), because the forwarder always dials `localhost:<port>`.

use crate::exposed_ports::ExposedPortsStore;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

/// How long the framework-classification probe waits for an HTTP response on
/// a single port. Short, because a port that does not speak HTTP (postgres,
/// redis, ssh) will simply never answer and we want to give up quickly.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Cap on how many ports we probe in one scan, and how many probes run at
/// once. Most hosts listen on a handful of ports; the cap bounds the
/// pathological "hundreds of listeners" case so the RPC stays responsive.
const PROBE_MAX_PORTS: usize = 128;
const PROBE_CONCURRENCY: usize = 32;

/// Largest body prefix we read while sniffing for framework markers.
const PROBE_BODY_SNIFF_BYTES: usize = 8 * 1024;

/// A TCP socket in the LISTEN state on a loopback or wildcard address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListeningPort {
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// A discovered port enriched with allowlist status and (optionally) the
/// result of an HTTP probe. Serialized straight into the RPC response.
#[derive(Debug, Clone, Serialize)]
pub struct DevPort {
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_name: Option<String>,
    /// Whether `pocketshell expose <port>` has been run for this port.
    pub is_exposed: bool,
    /// True when the probe got any HTTP response. False when probing was
    /// disabled or the port did not answer as HTTP within [`PROBE_TIMEOUT`].
    pub is_http: bool,
    /// Best-effort framework classification: `vite`, `next`, `nuxt`,
    /// `webpack`, `angular`, `cra`, `remix`, `astro`, `svelte`, `express`,
    /// `rails`, `django`, `flask`, `php`, or `http` (generic). `None` when
    /// not probed or not HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_kind: Option<String>,
    /// `Server:` response header captured during the probe (truncated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_header: Option<String>,
    /// HTTP status the probe observed. `None` when not probed / not HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_status: Option<u16>,
}

/// Scan listening ports, mark allowlist status, and (when `probe`) classify
/// each as an HTTP dev server. Returns ports sorted ascending. Never errors —
/// platform failures degrade to an empty / partial list and are logged.
pub async fn list_dev_ports(probe: bool) -> Vec<DevPort> {
    let listening = list_listening_ports();

    // Dedupe by port: a server bound to both IPv4 and IPv6 shows up twice,
    // and we only forward by port number anyway. Keep the first pid/name we
    // saw for the port.
    let mut by_port: BTreeMap<u16, ListeningPort> = BTreeMap::new();
    for lp in listening {
        by_port.entry(lp.port).or_insert(lp);
    }

    let exposed: HashSet<u16> = match ExposedPortsStore::list() {
        Ok(list) => list.into_iter().map(|p| p.port).collect(),
        Err(e) => {
            tracing::warn!("dev_ports: reading exposed allowlist failed: {e}");
            HashSet::new()
        }
    };

    let ports: Vec<ListeningPort> = by_port.into_values().collect();

    if !probe {
        return ports
            .into_iter()
            .map(|lp| DevPort {
                port: lp.port,
                pid: lp.pid,
                process_name: lp.process_name,
                is_exposed: exposed.contains(&lp.port),
                is_http: false,
                server_kind: None,
                server_header: None,
                probe_status: None,
            })
            .collect();
    }

    // Probe concurrently with a fan-out cap so a host with many listeners
    // doesn't open hundreds of sockets at once or stall the RPC.
    use futures_util::stream::{self, StreamExt};
    let to_probe: Vec<ListeningPort> = ports.into_iter().take(PROBE_MAX_PORTS).collect();
    let mut results: Vec<DevPort> = stream::iter(to_probe)
        .map(|lp| {
            let is_exposed = exposed.contains(&lp.port);
            async move {
                let probe = probe_port(lp.port).await;
                DevPort {
                    port: lp.port,
                    pid: lp.pid,
                    process_name: lp.process_name,
                    is_exposed,
                    is_http: probe.is_some(),
                    server_kind: probe.as_ref().and_then(|p| p.kind.clone()),
                    server_header: probe.as_ref().and_then(|p| p.server_header.clone()),
                    probe_status: probe.as_ref().map(|p| p.status),
                }
            }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await;

    results.sort_by_key(|d| d.port);
    results
}

/// Platform-dispatching listener enumeration.
pub fn list_listening_ports() -> Vec<ListeningPort> {
    #[cfg(target_os = "linux")]
    {
        list_listening_ports_linux()
    }
    #[cfg(target_os = "macos")]
    {
        list_listening_ports_macos()
    }
    #[cfg(target_os = "windows")]
    {
        list_listening_ports_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

// =====================================================================
// Linux: /proc/net/tcp{,6}
// =====================================================================

#[cfg(target_os = "linux")]
fn list_listening_ports_linux() -> Vec<ListeningPort> {
    let mut inode_ports: Vec<(u16, u64)> = Vec::new();
    for (path, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        match std::fs::read_to_string(path) {
            Ok(content) => inode_ports.extend(parse_proc_net_tcp(&content, v6)),
            Err(e) => tracing::debug!("dev_ports: reading {path} failed: {e}"),
        }
    }
    if inode_ports.is_empty() {
        return Vec::new();
    }

    let wanted: HashSet<u64> = inode_ports.iter().map(|(_, ino)| *ino).collect();
    let inode_to_pid = map_socket_inodes_to_pids(&wanted);

    inode_ports
        .into_iter()
        .map(|(port, inode)| {
            let pid = inode_to_pid.get(&inode).copied();
            let process_name = pid.and_then(read_proc_comm);
            ListeningPort {
                port,
                pid,
                process_name,
            }
        })
        .collect()
}

/// Parse `/proc/net/tcp` (or `..._tcp6` when `v6`) and return `(port, inode)`
/// for every socket in the LISTEN state bound to a loopback or wildcard
/// address. Pure over the file content so it can be unit-tested.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_net_tcp(content: &str, v6: bool) -> Vec<(u16, u64)> {
    const ST_LISTEN: &str = "0A";
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl(0) local(1) rem(2) st(3) tx_rx(4) tr(5) retr(6) uid(7) to(8) inode(9)
        if f.len() < 10 {
            continue;
        }
        if f[3] != ST_LISTEN {
            continue;
        }
        let Some((addr_hex, port_hex)) = f[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        if !addr_is_local(addr_hex, v6) {
            continue;
        }
        let Ok(inode) = f[9].parse::<u64>() else {
            continue;
        };
        out.push((port, inode));
    }
    out
}

/// True when the hex local address from `/proc/net/tcp{,6}` is a loopback or
/// wildcard bind — the only ones reachable as `localhost` from the forwarder.
#[cfg(any(target_os = "linux", test))]
fn addr_is_local(addr_hex: &str, v6: bool) -> bool {
    if v6 {
        let upper = addr_hex.to_ascii_uppercase();
        // Wildcard `::` is all zeros; loopback `::1` has this fixed kernel
        // representation (four little-endian 32-bit words).
        upper == "00000000000000000000000000000000" || upper == "00000000000000000000000001000000"
    } else {
        // The kernel prints the v4 address as a little-endian u32, so the
        // first octet of the dotted address is the low byte.
        match u32::from_str_radix(addr_hex, 16) {
            Ok(0) => true,              // 0.0.0.0 wildcard
            Ok(n) => (n & 0xff) == 127, // 127.0.0.0/8 loopback
            Err(_) => false,
        }
    }
}

/// Walk `/proc/<pid>/fd` looking for symlinks of the form `socket:[<inode>]`
/// whose inode is in `wanted`. Returns a map inode → pid. Best-effort: stops
/// once every wanted inode is found, and silently skips processes we can't
/// read (permission, races with process exit).
#[cfg(target_os = "linux")]
fn map_socket_inodes_to_pids(wanted: &HashSet<u64>) -> std::collections::HashMap<u64, u32> {
    use std::collections::HashMap;
    let mut found: HashMap<u64, u32> = HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in proc_dir.flatten() {
        if found.len() == wanted.len() {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue; // non-pid entry like /proc/self, /proc/net
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else {
            continue; // not ours / vanished
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            if let Some(inode) = parse_socket_inode(target) {
                if wanted.contains(&inode) {
                    found.entry(inode).or_insert(pid);
                }
            }
        }
    }
    found
}

/// Extract `12345` from a `socket:[12345]` fd symlink target.
#[cfg(any(target_os = "linux", test))]
fn parse_socket_inode(link: &str) -> Option<u64> {
    let inner = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}

#[cfg(target_os = "linux")]
fn read_proc_comm(pid: u32) -> Option<String> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = raw.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

// =====================================================================
// macOS: lsof
// =====================================================================

#[cfg(target_os = "macos")]
fn list_listening_ports_macos() -> Vec<ListeningPort> {
    let mut command = std::process::Command::new("lsof");
    crate::platform::hide_command_window(&mut command);
    let output = command.args(["-nP", "-iTCP", "-sTCP:LISTEN"]).output();
    match output {
        Ok(out) if out.status.success() => parse_lsof_output(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => {
            tracing::debug!(
                "dev_ports: lsof exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            Vec::new()
        }
        Err(e) => {
            tracing::debug!("dev_ports: lsof not available: {e}");
            Vec::new()
        }
    }
}

/// Parse the default (whitespace-columns) `lsof` listing. Columns:
/// `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME`. We keep rows whose
/// NAME binds a loopback or wildcard address and pull the trailing `:PORT`.
/// Pure over the text so it can be unit-tested without a Mac.
#[cfg(any(target_os = "macos", test))]
fn parse_lsof_output(text: &str) -> Vec<ListeningPort> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 9 {
            continue;
        }
        let command = f[0];
        let pid: Option<u32> = f[1].parse().ok();
        // lsof renders the NAME column as `127.0.0.1:3000` / `*:3000` /
        // `[::1]:3000`, optionally followed by a parenthesized state token
        // like `(LISTEN)`. Scan from the end past any `(...)` annotations to
        // find the address:port token.
        let Some(name) = f.iter().rev().find(|t| !t.starts_with('(')).copied() else {
            continue;
        };
        let Some((addr, port_str)) = name.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        if port == 0 || !lsof_addr_is_local(addr) {
            continue;
        }
        out.push(ListeningPort {
            port,
            pid,
            process_name: Some(command.to_string()),
        });
    }
    out
}

#[cfg(any(target_os = "macos", test))]
fn lsof_addr_is_local(addr: &str) -> bool {
    matches!(addr, "*" | "0.0.0.0" | "127.0.0.1" | "[::1]" | "[::]") || addr.starts_with("127.")
}

// =====================================================================
// Windows: netstat
// =====================================================================

#[cfg(target_os = "windows")]
fn list_listening_ports_windows() -> Vec<ListeningPort> {
    let mut command = std::process::Command::new("netstat");
    crate::platform::hide_command_window(&mut command);
    let output = command.args(["-ano", "-p", "tcp"]).output();
    let mut ports = match output {
        Ok(out) if out.status.success() => {
            parse_windows_netstat_output(&String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => {
            tracing::debug!(
                "dev_ports: netstat exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            Vec::new()
        }
        Err(e) => {
            tracing::debug!("dev_ports: netstat not available: {e}");
            Vec::new()
        }
    };
    attach_windows_process_names(&mut ports);
    ports
}

/// Parse Windows `netstat -ano -p tcp` output. Expected rows look like:
/// `TCP 127.0.0.1:3000 0.0.0.0:0 LISTENING 1234`
/// or `TCP [::1]:5173 [::]:0 LISTENING 5678`.
#[cfg(any(target_os = "windows", test))]
fn parse_windows_netstat_output(text: &str) -> Vec<ListeningPort> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 || !f[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        let Some(state) = f.get(f.len().saturating_sub(2)) else {
            continue;
        };
        if !state.eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        let Some((addr, port)) = parse_windows_local_endpoint(f[1]) else {
            continue;
        };
        if port == 0 || !windows_addr_is_local(addr) {
            continue;
        }
        let pid = f.last().and_then(|s| s.parse::<u32>().ok());
        out.push(ListeningPort {
            port,
            pid,
            process_name: None,
        });
    }
    out
}

#[cfg(any(target_os = "windows", test))]
fn parse_windows_local_endpoint(endpoint: &str) -> Option<(&str, u16)> {
    if endpoint.starts_with('[') {
        let end = endpoint.find("]:")?;
        let addr = &endpoint[..=end];
        let port = endpoint[end + 2..].parse::<u16>().ok()?;
        return Some((addr, port));
    }
    let (addr, port_str) = endpoint.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    Some((addr, port))
}

#[cfg(any(target_os = "windows", test))]
fn windows_addr_is_local(addr: &str) -> bool {
    matches!(
        addr,
        "*" | "0.0.0.0" | "127.0.0.1" | "[::]" | "[::1]" | "::" | "::1"
    ) || addr.starts_with("127.")
}

#[cfg(target_os = "windows")]
fn attach_windows_process_names(ports: &mut [ListeningPort]) {
    if ports.iter().all(|p| p.pid.is_none()) {
        return;
    }
    let system = sysinfo::System::new_all();
    for port in ports {
        let Some(pid) = port.pid else { continue };
        let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) else {
            continue;
        };
        let name = process.name().to_string_lossy();
        if !name.is_empty() {
            port.process_name = Some(name.to_string());
        }
    }
}

// =====================================================================
// HTTP probe + framework classification
// =====================================================================

struct ProbeResult {
    status: u16,
    server_header: Option<String>,
    kind: Option<String>,
}

/// Probe `http://localhost:<port>/` with a short timeout and classify the
/// response. Returns `None` if the port does not answer as HTTP in time.
async fn probe_port(port: u16) -> Option<ProbeResult> {
    let client = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let url = format!("http://localhost:{port}/");
    let resp = client
        .get(&url)
        .header("Host", format!("localhost:{port}"))
        // Identify ourselves so a curious operator sees what hit their server.
        .header("User-Agent", "pocketshell-portscan/1.0")
        .send()
        .await
        .ok()?;

    let status = resp.status().as_u16();
    let server_header = resp
        .headers()
        .get(reqwest::header::SERVER)
        .and_then(|v| v.to_str().ok())
        .map(|s| truncate(s, 120));
    let powered_by = resp
        .headers()
        .get("x-powered-by")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read a bounded body prefix to sniff for framework markers, then drop
    // the rest — we never need the whole page.
    let mut body = Vec::new();
    let mut resp = resp;
    while body.len() < PROBE_BODY_SNIFF_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = (PROBE_BODY_SNIFF_BYTES - body.len()).min(chunk.len());
                body.extend_from_slice(&chunk[..take]);
                if body.len() >= PROBE_BODY_SNIFF_BYTES {
                    break;
                }
            }
            _ => break,
        }
    }
    let body_snippet = String::from_utf8_lossy(&body);

    let kind = classify_kind(
        server_header.as_deref(),
        powered_by.as_deref(),
        &body_snippet,
    );
    Some(ProbeResult {
        status,
        server_header,
        kind,
    })
}

/// Best-effort framework classification from a `Server` header, an
/// `X-Powered-By` header, and a prefix of the response body. Heuristic and
/// intentionally conservative — falls back to the generic `http` rather than
/// guessing. Pure so it can be unit-tested.
fn classify_kind(
    server_header: Option<&str>,
    powered_by: Option<&str>,
    body: &str,
) -> Option<String> {
    let server = server_header.unwrap_or("").to_ascii_lowercase();
    let powered = powered_by.unwrap_or("").to_ascii_lowercase();

    // Server / X-Powered-By headers are the strongest signals.
    if server.contains("werkzeug") {
        return Some("flask".into());
    }
    if server.contains("wsgiserver") || server.contains("django") {
        return Some("django".into());
    }
    if server.contains("webpack") {
        return Some("webpack".into());
    }
    if powered.contains("next") || server.contains("next") {
        return Some("next".into());
    }
    if powered.contains("express") {
        return Some("express".into());
    }
    if powered.contains("php") || server.contains("php") {
        return Some("php".into());
    }
    if server.contains("puma") || server.contains("webrick") || server.contains("rails") {
        return Some("rails".into());
    }

    // Body markers. Order matters — check the most specific first.
    if body.contains("/@vite/client") || body.contains("/@react-refresh") {
        return Some("vite".into());
    }
    if body.contains("/_next/") || body.contains("__NEXT_DATA__") {
        return Some("next".into());
    }
    if body.contains("__NUXT__") || body.contains("/_nuxt/") {
        return Some("nuxt".into());
    }
    if body.contains("__remixContext") || body.contains("/build/_shared/") {
        return Some("remix".into());
    }
    if body.contains("astro-island") || body.contains("/@astrojs/") {
        return Some("astro".into());
    }
    if body.contains("/_app/immutable/") || body.contains("__sveltekit") {
        return Some("svelte".into());
    }
    if body.contains("ng-version") {
        return Some("angular".into());
    }
    if body.contains("/sockjs-node/") || body.contains("webpackHotUpdate") {
        return Some("webpack".into());
    }
    // CRA serves a webpack bundle; detect the default index shell.
    if body.contains("/static/js/bundle.js") || body.contains("data-reactroot") {
        return Some("cra".into());
    }

    // Any HTTP response at all is still useful to show as a generic server.
    Some("http".into())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_net_tcp_v4_listen_loopback() {
        // sl local rem st ... uid timeout inode ...
        // 0100007F:1F90 → 127.0.0.1:8080, st 0A (LISTEN), inode 23456.
        let sample = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   2: 0100007F:C350 7F000001:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 20 0 0 10 0
";
        let got = parse_proc_net_tcp(sample, false);
        // Row 0 (8080 listen) and row 1 (53 listen) kept; row 2 is ESTABLISHED (st 01) — dropped.
        assert_eq!(got, vec![(8080, 23456), (53, 11111)]);
    }

    #[test]
    fn parse_proc_net_tcp_v4_wildcard_kept_external_dropped() {
        let sample = "\
  sl  local_address rem_address   st ...
   0: 00000000:1F90 00000000:0000 0A 0 0 0 1000 0 200 1
   1: 0101A8C0:1F90 00000000:0000 0A 0 0 0 1000 0 201 1
";
        // 00000000 = 0.0.0.0 wildcard (kept). 0101A8C0 = 192.168.1.1 (external, dropped).
        let got = parse_proc_net_tcp(sample, false);
        assert_eq!(got, vec![(8080, 200)]);
    }

    #[test]
    fn parse_proc_net_tcp6_loopback_and_wildcard() {
        let sample = "\
  sl  local_address                         remote_address                        st ... inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 0 0 0 1000 0 300 1
   1: 00000000000000000000000000000000:147B 00000000000000000000000000000000:0000 0A 0 0 0 1000 0 301 1
";
        // ::1:8080 (inode 300) and :::5243 (inode 301) both kept.
        let got = parse_proc_net_tcp(sample, true);
        assert_eq!(got, vec![(8080, 300), (5243, 301)]);
    }

    #[test]
    fn parse_proc_skips_port_zero_and_malformed() {
        let sample = "\
header
   0: 0100007F:0000 00000000:0000 0A 0 0 0 1000 0 400 1
   1: garbage
   2: 0100007F:1F90 00000000:0000 0A 0 0 0 1000 0 notanum 1
";
        assert!(parse_proc_net_tcp(sample, false).is_empty());
    }

    #[test]
    fn addr_is_local_v4_classification() {
        assert!(addr_is_local("0100007F", false)); // 127.0.0.1
        assert!(addr_is_local("0200007F", false)); // 127.0.0.2
        assert!(addr_is_local("00000000", false)); // 0.0.0.0
        assert!(!addr_is_local("0101A8C0", false)); // 192.168.1.1
        assert!(!addr_is_local("08080808", false)); // 8.8.8.8
    }

    #[test]
    fn parse_socket_inode_extracts_number() {
        assert_eq!(parse_socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(parse_socket_inode("pipe:[999]"), None);
        assert_eq!(parse_socket_inode("/dev/null"), None);
        assert_eq!(parse_socket_inode("socket:[abc]"), None);
    }

    #[test]
    fn parse_lsof_keeps_local_listeners() {
        let sample = "\
COMMAND   PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node    12345 yash   23u  IPv4 0x1234567890abcd      0t0  TCP 127.0.0.1:3000 (LISTEN)
node    12345 yash   25u  IPv6 0xfedcba0987654       0t0  TCP [::1]:5173 (LISTEN)
ssh      6789 yash    3u  IPv4 0x000000000000000      0t0  TCP 192.168.1.5:22 (LISTEN)
postgres 4321 yash    5u  IPv4 0x111111111111111      0t0  TCP *:5432 (LISTEN)
";
        let got = parse_lsof_output(sample);
        let ports: Vec<u16> = got.iter().map(|p| p.port).collect();
        // 3000 (loopback), 5173 (::1), 5432 (wildcard) kept; 22 on LAN IP dropped.
        assert_eq!(ports, vec![3000, 5173, 5432]);
        assert_eq!(got[0].process_name.as_deref(), Some("node"));
        assert_eq!(got[0].pid, Some(12345));
    }

    #[test]
    fn lsof_addr_classification() {
        assert!(lsof_addr_is_local("*"));
        assert!(lsof_addr_is_local("127.0.0.1"));
        assert!(lsof_addr_is_local("[::1]"));
        assert!(lsof_addr_is_local("0.0.0.0"));
        assert!(!lsof_addr_is_local("192.168.1.5"));
        assert!(!lsof_addr_is_local("10.0.0.1"));
    }

    #[test]
    fn parse_windows_netstat_keeps_local_listeners() {
        let sample = "\
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:3000         0.0.0.0:0              LISTENING       12345
  TCP    [::1]:5173             [::]:0                 LISTENING       23456
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       34567
  TCP    [::]:9229              [::]:0                 LISTENING       45678
  TCP    192.168.1.5:22         0.0.0.0:0              LISTENING       56789
  TCP    127.0.0.1:5000         127.0.0.1:6000         ESTABLISHED     67890
";
        let got = parse_windows_netstat_output(sample);
        let ports: Vec<u16> = got.iter().map(|p| p.port).collect();
        assert_eq!(ports, vec![3000, 5173, 8080, 9229]);
        assert_eq!(got[0].pid, Some(12345));
        assert_eq!(got[1].pid, Some(23456));
    }

    #[test]
    fn parse_windows_netstat_skips_port_zero_and_malformed() {
        let sample = "\
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:0            0.0.0.0:0              LISTENING       12345
  TCP    [::1:notaport          [::]:0                 LISTENING       23456
  UDP    127.0.0.1:3000         *:*                                    34567
";
        assert!(parse_windows_netstat_output(sample).is_empty());
    }

    #[test]
    fn windows_endpoint_parses_ipv4_and_ipv6() {
        assert_eq!(
            parse_windows_local_endpoint("127.0.0.1:3000"),
            Some(("127.0.0.1", 3000))
        );
        assert_eq!(
            parse_windows_local_endpoint("[::1]:5173"),
            Some(("[::1]", 5173))
        );
        assert_eq!(
            parse_windows_local_endpoint("[fe80::1%13]:8080"),
            Some(("[fe80::1%13]", 8080))
        );
        assert_eq!(parse_windows_local_endpoint("127.0.0.1:notaport"), None);
    }

    #[test]
    fn windows_addr_classification() {
        assert!(windows_addr_is_local("*"));
        assert!(windows_addr_is_local("0.0.0.0"));
        assert!(windows_addr_is_local("127.0.0.1"));
        assert!(windows_addr_is_local("127.0.0.2"));
        assert!(windows_addr_is_local("[::]"));
        assert!(windows_addr_is_local("[::1]"));
        assert!(!windows_addr_is_local("192.168.1.5"));
        assert!(!windows_addr_is_local("[fe80::1%13]"));
    }

    #[test]
    fn classify_vite_from_body() {
        assert_eq!(
            classify_kind(None, None, "<script src=\"/@vite/client\"></script>").as_deref(),
            Some("vite")
        );
    }

    #[test]
    fn classify_next_from_powered_by() {
        assert_eq!(
            classify_kind(None, Some("Next.js"), "<html></html>").as_deref(),
            Some("next")
        );
        assert_eq!(
            classify_kind(
                None,
                None,
                "<div id=\"__next\">x</div><script src=\"/_next/static/x.js\">"
            )
            .as_deref(),
            Some("next")
        );
    }

    #[test]
    fn classify_django_and_flask_from_server_header() {
        assert_eq!(
            classify_kind(Some("WSGIServer/0.2 CPython/3.11"), None, "").as_deref(),
            Some("django")
        );
        assert_eq!(
            classify_kind(Some("Werkzeug/2.3.7 Python/3.11"), None, "").as_deref(),
            Some("flask")
        );
    }

    #[test]
    fn classify_generic_http_fallback() {
        assert_eq!(
            classify_kind(Some("nginx"), None, "<html>hi</html>").as_deref(),
            Some("http")
        );
    }

    #[test]
    fn truncate_respects_char_boundary() {
        let s = "🚀🚀🚀🚀"; // 16 bytes
        let t = truncate(s, 5); // would split a 4-byte codepoint at 5
        assert!(t.chars().all(|c| c == '🚀'));
        assert!(t.len() <= 5);
    }
}
