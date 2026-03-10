# PocketShell Backend Server

FastAPI control-plane backend for PocketShell mobile-host terminal access.

## Features Implemented
- Email OTP auth with JWT access/refresh tokens and refresh-token rotation.
- Mobile device + host registration and update APIs.
- Pairing code generation/validation and host linking.
- Trusted-device approval/revocation per host.
- Session orchestration with state transitions and signaling triggers.
- Authenticated host/mobile WebSocket signaling channels.
- TURN temporary credential endpoint (`/webrtc/turn-credentials`).
- Redis-backed presence tracking.
- Audit log persistence for security-sensitive events.
- Rate limiting for OTP, pairing, and session creation.
- Structured logging, request IDs, and health checks.
- Alembic migration for all v1 schema tables and indexes.

## Quickstart
1. Create virtualenv and install deps:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```
2. Copy env config:
```bash
cp .env.example .env
```
3. Run migration:
```bash
alembic upgrade head
```
4. Start server:
```bash
uvicorn app.main:app --reload
```

API base path: `/api/v1`

## Notes
- OTP delivery and APNs are integration hooks; transport provider wiring is intentionally left as an implementation adapter.
- Backend does not proxy terminal data-plane traffic.
