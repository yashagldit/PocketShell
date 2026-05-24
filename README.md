# PocketShell

> A real terminal in your pocket. End-to-end encrypted. WebRTC peer-to-peer.

PocketShell turns your phone into a real PTY for the machines you care about — your dev box, a homelab Pi, a fleet of edge servers. Type into your phone, the bytes flow over an encrypted WebRTC data channel directly to your machine. The cloud signals; it does not see your shell.

This repository is the **open-source host agent** that runs on the machine you want to reach. The mobile apps (iOS / Android) and the backend control plane that brokers pairing and signaling are closed-source.

```
┌──────────┐                         ┌──────────────┐                          ┌──────────┐
│  mobile  │ ──── auth · signal ──── │   backend    │ ──── auth · signal ──── │   host   │
│ (closed) │                         │   (closed)   │                          │ (this 👋)│
└────┬─────┘                         └──────────────┘                          └────┬─────┘
     │                                                                              │
     └──── WebRTC datachannel (DTLS) · ED25519-pinned SDP transcript ──── PTY ───┘
                       (your terminal traffic; never touches our servers)
```

The control plane refuses, throttles, or routes connections. Once a mobile↔host session is up, the backend cannot read or forge the terminal/files/agent bytes — they travel over a WebRTC data channel protected by DTLS (the WebRTC stack's standard transport encryption), and the DTLS peer-cert fingerprint is bound into a signed SDP transcript verified against the device's long-term ED25519 pairing key, so a backend that swaps SDPs to MitM is detected before any byte traverses the channel. A second E2E layer (ChaCha20-Poly1305 with X25519-derived session keys) wraps sensitive *signaling* messages that pass through the backend WS. Compromise of our backend does not compromise your shell.

> Host↔host direct file transfer (a Pro feature) is anchored to the mobile device as introducer: the phone signs an attestation binding both hosts' long-term public keys to the transfer, and each host verifies it against the mobile pubkey pinned at pairing — so the backend can relay SDP but cannot substitute a peer's identity. See [Security model](#security-model).

---

## What's in this repo

```
crates/
  host-core/      # library: api client, websocket, pty, crypto, stats, audit, files
  host-agent/     # the `pocketshell` CLI — login, pair, daemon, devices, stats
packaging/
  debian/         # debian package + systemd --user unit
  homebrew/       # homebrew formula
  macos/          # launchd plist
mobile/src/locales/   # 12-language UI translation files (community-maintained)
mobile/src/i18n/      # i18n loader
LICENSE           # Apache-2.0
NOTICE            # required attribution per Apache-2.0 §4(d)
```

The `mobile/src/locales/` tree is here because translations benefit from being public — the rest of the mobile app source isn't in this repo.

---

## Install

Pre-built binaries — pick either:

```bash
# install script
brew install cosign  # one-time, for Sigstore signature verification
curl -fsSL https://pocketshell.app/install.sh | bash

# npm
npm i -g pocketshell
```

**Install script** detects your OS and arch, fetches the matching
tarball from the latest [GitHub
Release](https://github.com/yashagldit/PocketShell/releases), verifies
its SHA-256 checksum **and the Sigstore cosign keyless signature**
(pinned to this repo's release workflow identity), then installs to
`~/.local/bin/pocketshell` (or `/usr/local/bin/pocketshell` if run as
root). Without cosign installed the script refuses to proceed — the
SHA-256 alone is same-origin integrity, not authenticity, so a
compromised release publisher could serve a matching checksum for a
malicious binary. Set `POCKETSHELL_SKIP_COSIGN=1` only if you've
verified the artifact out of band.

Read the script first if you'd rather not pipe to bash blindly — it's
served from the static site and intentionally short.

**npm** ships the binary inside platform-specific packages
(`@pocketshell/darwin-arm64`, `@pocketshell/linux-x64-gnu`, etc.)
selected by npm's `os` / `cpu` / `libc` filters. The packages are
published from this repo's release workflow via [npm Trusted
Publishing](https://docs.npmjs.com/trusted-publishers/) (OIDC, no
long-lived tokens), with build provenance attached automatically.

From source (Rust 1.78+):

```bash
git clone https://github.com/yashagldit/PocketShell.git
cd PocketShell
cargo install --path crates/host-agent --root ~/.local
export PATH="$HOME/.local/bin:$PATH"
```

Verify:

```bash
pocketshell --version
```

## Pair and run

```bash
# 1. open the PocketShell app, tap "Pair host" — you get a 9-character code
pocketshell pair 7H2-9K4-PXM

# 2. start the daemon (runs as your user, not root)
pocketshell daemon start

# 3. status & logs
pocketshell daemon status
journalctl --user -fu pocketshell-host-agent      # linux
log stream --predicate 'process == "pocketshell"' # macOS
```

The daemon connects out to the signaling backend over WSS and waits for a peer offer. When your phone wants a session, the backend signals; the data channel is end-to-end encrypted between phone and host.

---

## How it works

Two planes, deliberately separated. The **control plane** (HTTPS + WebSocket to the backend) carries auth, pairing, presence, SDP offers / answers, and ICE candidates; sensitive signaling messages (file metadata) get an additional ChaCha20-Poly1305 envelope with X25519-derived keys so the backend WS sees only ciphertext. The **data plane** (WebRTC peer connection) carries every byte of your shell — PTY I/O, file chunks, stats samples, agent stdio — directly between phone and host, encrypted by DTLS at the WebRTC layer with the peer cert fingerprint bound into the ED25519-signed SDP.

```mermaid
flowchart TB
    subgraph Mobile["📱  Mobile app  (closed source)"]
        direction TB
        M_auth["Email OTP → JWT<br/>(15 min access · 30 day refresh)"]
        M_key["ED25519 device key<br/>Expo SecureStore"]
        M_ui["Terminal · Files · Stats<br/>Agent chat · Alerts · Workspaces"]
        M_ws["Signaling WS client<br/>/ws/mobile"]
        M_rtc["WebRTC peer<br/>(react-native-webrtc)"]
    end

    subgraph Backend["☁️  Backend control plane  (closed source)"]
        direction TB
        B_api["FastAPI · /api/v1/*<br/>auth · devices · pairing · sessions<br/>presence · turn · alerts · workspaces"]
        B_ws["ConnectionManager<br/>/ws/mobile  ·  /ws/host<br/>signaling relay only"]
        B_pg[("PostgreSQL<br/>users · hosts · sessions<br/>trusted_devices · audit_log")]
        B_redis[("Redis<br/>presence · live stats<br/>rate-limit · pub/sub relay")]
        B_turn["TURN server<br/>(rotating HMAC creds)"]
    end

    subgraph Host["🖥️  Host agent  (this repo)"]
        direction TB
        H_cli["pocketshell CLI<br/>pair · daemon · devices · stats"]
        H_key["ED25519 host key<br/>OS keychain"]
        H_ws["transport.rs<br/>WS client → /ws/host"]
        H_rtc["webrtc_manager.rs<br/>peer-per-mobile-device"]
        H_pty["pty.rs · discovery.rs<br/>tmux / screen / shell"]
        H_stats["stats.rs · files.rs<br/>agent_session.rs · alerts.rs"]
    end

    M_auth -. "HTTPS · JWT" .-> B_api
    M_ws  -. "WSS · signaling<br/>session_offer / answer<br/>ice_candidate · stats_offer<br/>files_offer · agent_offer" .-> B_ws
    H_cli -. "HTTPS · pair / refresh" .-> B_api
    H_ws  -. "WSS · signaling<br/>session_ack · session_event<br/>alert · host_summary<br/>stats_snapshot" .-> B_ws

    B_api --- B_pg
    B_ws  --- B_redis
    B_api --- B_turn

    M_rtc <==>|"WebRTC data channels — E2E encrypted, never touches backend<br/><br/><b>terminal</b> (PTY bytes) · <b>stats</b> (JSON ~1 Hz)<br/><b>files</b> (framed JSON + chunks) · <b>agent-{id}</b> (Claude / Codex stdio)<br/><br/>P2P direct  ·  TURN relay only when NAT blocks P2P"| H_rtc

    B_turn -. "TURN relay path<br/>(opaque to backend)" .-> M_rtc
    B_turn -. "TURN relay path" .-> H_rtc

    classDef mobile  fill:#1e3a5f,stroke:#4a90e2,color:#fff
    classDef backend fill:#3a2f5c,stroke:#9b6dd1,color:#fff
    classDef host    fill:#2d4a3e,stroke:#5cb88c,color:#fff
    class M_auth,M_key,M_ui,M_ws,M_rtc mobile
    class B_api,B_ws,B_pg,B_redis,B_turn backend
    class H_cli,H_key,H_ws,H_rtc,H_pty,H_stats host
```

### Session establishment (the happy path)

```mermaid
sequenceDiagram
    autonumber
    participant M as 📱 Mobile
    participant B as ☁️ Backend
    participant H as 🖥️ Host daemon

    Note over M,H: Both sides are already authed and connected to /ws/mobile and /ws/host.

    M->>B: POST /api/v1/sessions  (host_id, purpose=terminal)
    B-->>M: 201 · session_id  (state = REQUESTED)
    M->>B: WS  session_offer  (SDP, signed)
    B->>H: relay  session_offer
    H->>H: verify ED25519 sig over SDP · spawn PTY
    H-->>B: WS  session_ack { accepted: true }
    B-->>M: relay  session_ack  → state = APPROVED
    H->>B: WS  session_answer  (SDP)
    B->>M: relay  session_answer
    M-->>H: WS  ice_candidate (× N, both directions, via backend)
    H-->>M: WS  ice_candidate (× N)

    rect rgba(92, 184, 140, 0.15)
      Note over M,H: ── WebRTC data channel established ──
      M-->>H: terminal · keystrokes (DTLS over WebRTC datachannel)
      H-->>M: terminal · PTY output
      H-->>M: stats · JSON snapshots ~1 Hz
      M-->>H: files · list / read / write
      Note right of B: Backend sees zero bytes of this traffic.
    end

    Note over M,H: On host disconnect, state becomes DETACHED. PTY survives — mobile can rejoin.
```

### What flows where

| Plane | Carrier | Payload |
|---|---|---|
| Auth | HTTPS `/api/v1/auth/*` | OTP, JWT issue / refresh, host pair / re-auth |
| Signaling | WSS `/ws/mobile`, `/ws/host` | `session_offer` · `session_answer` · `ice_candidate` · `session_event` · `stats_offer` · `files_offer` · `agent_offer` · `alert` · `host_summary` · `available_sessions` |
| Presence + lightweight metrics | WSS `/ws/host` | `heartbeat` (host_id, active_sessions, app_version) · `host_summary` (cpu%, ram%) · `stats_snapshot` and `stats_minute_batch` (cpu/mem/disk/load/battery/net IO/temps — **no processes, no command lines, no logged-in users**) |
| Metrics history (Pro) | HTTPS `/api/v1/presence/hosts/{id}/stats/history*` | minute / 30-min / hourly / daily aggregates served from PostgreSQL — used by the history charts even when no live session is active |
| **Terminal I/O** | **WebRTC `terminal` channel** | **PTY bytes — never touches backend** |
| **Live stats (rich)** | **WebRTC `stats` channel** | **Top-50 processes · per-core CPU · logged-in users · network connections · OS info · hostname — never touches backend** |
| **File ops** | **WebRTC `files` channel** | **Framed JSON + base64 chunks (sentinel `\x00PSFC`)** |
| **Agent chat** | **WebRTC `agent-{id}` channel** | **Claude / Codex stdio, JSON framed** |

The backend is a switchboard — it can refuse a connection, throttle it, or route it through TURN, but once the data channel is up it sees ciphertext at best and nothing at all on direct P2P.

**What the backend persists.** To deliver the Pro history-chart feature, the backend stores minute-bucket aggregates of numerical metrics (cpu/mem/disk/uptime/load/battery/net IO/disk IO/max temp + collected-at) per host, rolled up into 30-min/hourly/daily over time. It does **not** persist processes, command lines, hostnames, logged-in users, or network connection lists — those flow only over WebRTC and are dropped from Redis after ~35 minutes. Account deletion removes all of the above; see `app/services/account_deletion_service.py`.

---

## Security model

| Layer | Primitive |
|---|---|
| Identity | ED25519 long-term host & device keys |
| Handshake | X25519 ephemeral · ED25519-signed SDP transcript binds DTLS cert fingerprint to the device pairing key |
| Data plane | WebRTC DTLS (transport encryption — AES-GCM by default, ciphersuite negotiated) |
| Signaling envelope | ChaCha20-Poly1305 AEAD · per-direction keys (wraps sensitive file/control payloads that pass through the backend WS) |
| KDF | HKDF-SHA256, domain-separated |
| Transport | WebRTC P2P · TURN fallback (rotating credentials) |
| Storage | OS keychain — Apple Keychain · Linux secret-service · Windows DPAPI · 0o600 file fallback for headless Linux |

Long-lived secrets (host private key, refresh token) live in the OS keychain via `crates/host-core/src/secret_store.rs`. Short-lived access tokens sit in `state.json` (mode `0o600`).

### Host↔host transfer trust model

The destination host verifies the source's SDP signature against a public key carried inside a *mobile-signed introducer attestation*, not a backend-relayed field. At transfer-initiation time the mobile app signs `(transfer_id, src_host_id, src_host_pubkey, dst_host_id, dst_host_pubkey, expires_at, nonce)` with its long-term device key; both hosts verify that signature against the mobile pubkey they pinned at pairing. The attestation is short-lived (≤ 5 min), bound to a single `transfer_id`, and both hosts additionally check that their own `host_id`+`public_key` match the attested values. Backend can relay SDP but cannot substitute a peer's identity. See `crates/host-core/src/signaling_crypto.rs` (`verify_host_transfer_attestation`) and `crates/host-core/src/daemon.rs` (`extract_and_verify_mobile_attestation`).

### Known gaps

- **No per-session approval prompt (by design)** — once a mobile device is trusted, every session offer is accepted immediately. The stolen-and-unlocked-phone case is handled by layered controls instead: app open is gated by device biometric, every paired device shows up in the in-app device list and can be revoked remotely from any other paired device, and sensitive ops are written to the local audit log on the host. Adding a per-session prompt would train users to tap "approve" reflexively and degrade the UX for the common case, so it isn't on the roadmap.

Found something? Email `support@pocketshell.app`. Public issues are fine for non-sensitive bugs.

---

## Building & testing

```bash
cargo build -p host-agent                # debug build
cargo build -p host-agent --release      # release
cargo test  -p host-core                 # core library tests
cargo test  -p host-agent                # CLI tests
RUST_LOG=debug cargo run -p host-agent -- daemon run    # run with verbose logs
```

Targets supported today: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`. Windows is not yet supported (PRs welcome).

---

## Translations

The mobile app currently ships in **12 languages**: English, German, Spanish, French, Hindi, Italian, Japanese, Korean, Portuguese (BR), Russian, Simplified Chinese, Traditional Chinese.

Files live under `mobile/src/locales/<lang>/*.json`. To add or improve a language, edit the JSON files and open a PR — no app build required. The strings are loaded by `mobile/src/i18n/index.ts`.

If you want a new language added, open an issue and we'll seed the directory.

---

## Contributing

PRs are welcome. A few notes:

- **Source of truth.** This repo is mirrored from a private monorepo. We accept patches here and apply them upstream. Force-pushes happen on every release — keep your fork rebased rather than merged.
- **Scope.** Issues for the mobile app or the backend get redirected; this repo is the host agent and the locales.
- **Style.** Match the surrounding code. `cargo fmt` and `cargo clippy --all-targets -- -D warnings` should pass.
- **Commits.** Conventional commits preferred (`feat:`, `fix:`, `refactor:`).

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project shall be licensed as Apache-2.0,
without any additional terms or conditions, per §5 of the License. See
also [NOTICE](./NOTICE).

---

**Links** · [pocketshell.app](https://pocketshell.app) · [Privacy](https://pocketshell.app/privacy) · [Terms](https://pocketshell.app/terms) · [Support](https://pocketshell.app/support)
