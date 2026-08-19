# AGENTS.md — Development Guide for RVG Gateway

This file gives AI coding agents (Claude Code, Codex, OpenCode, Hermes, etc.) the context needed to work on this repo without breaking it.

## Project Overview

RVG Gateway is a **multi-protocol proxy management panel** built with Python + FastAPI, deployable on Railway. It implements server-side (terminator) support for:

- **VLESS** — WebSocket transport, XHTTP variants
- **VMess** — WebSocket transport (AEAD 2022 + legacy MD5-chain)
- **Trojan** — WebSocket transport, XHTTP variants
- **Shadowsocks** — AEAD stream cipher, WebSocket transport, XHTTP variants
- **MTProto** — Telegram proxy (via mtg binary)

All protocol implementations are **pure Python** (no Go/Node dependencies) and are wire-compatible with v2ray/xray clients.

## Architecture

```
main.py            → FastAPI app, all HTTP routes, panel auth, link CRUD, share-link generation
pages.py           → Single-page panel UI (HTML + JS + CSS inline, 4.6K lines)
protocol/
  vless/           → VLESS protocol dir
  vmess/           → VMess protocol dir (vmess.py = crypto core, websocket.py = WS tunnel)
  trojan/          → Trojan protocol dir
  shadowsocks/     → Shadowsocks protocol dir
  mtproto/         → MTProto (Telegram) proxy dir
central.py         → Central service integration (bottoken, etc.)
updater.py         → Self-update logic
botgeneratedomin.py → Railway domain automation bot
bottokentcpproxy.py → MTProto public proxy automation
```

## Key Conventions

1. **Language**: Python 3.11+, uses `asyncio`, `FastAPI`, `cryptography`.
2. **Comments/UI strings**: Persian (Farsi) comments are used in code, matching the original RVG style. Keep user-facing strings in Persian.
3. **Pure Python**: No compiled deps beyond `cryptography`. Do NOT introduce Go/Node/other runtime deps.
4. **Wire compatibility**: Protocol implementations MUST stay wire-compatible with v2ray-core/xray clients. Reference Go sources are cached at `/data/workspace/vmess-ref/`.
5. **Share links**: `main.py:generate_share_link()` generates all protocol share links. VMess uses `vmess://<base64>#remark` format.
6. **State persistence**: `main.py:save_state()` writes `rvg_state.json` atomically (temp + replace).
7. **Auth**: PBKDF2-SHA256 password hashing (`pbkdf2$iterations$salt$hash`), session cookie `rvg_session`, rate-limited login.

## Protocol Implementation Pattern

Each protocol directory follows:
```
protocol/<name>/
  <name>.py        → crypto core, header parsing, share-link generation
  websocket.py     → WebSocket tunnel endpoint (relay_ws_to_tcp / relay_tcp_to_ws)
  xhttp*.py        → XHTTP transport variants (where applicable)
```

The shared quota system (`_QuotaGate`) lives in `protocol/trojan/trojan.py` and `protocol/vless/vless.py` — each protocol's websocket tunnel instantiates it for per-connection traffic counting.

## Testing

```bash
# Unit tests (crypto, auth, links, sessions, rate limiting, CORS)
cd /data/workspace/RVG
.venv/bin/python -m pytest test_rvg.py -v

# Manual integration check (needs running server):
#   uvicorn main:app --port 8001
# then run /tmp/test_vmess_integration.py
```

Run `pytest` before committing. The test suite must stay green — protocol changes that break wire-format tests are blocking.

## Verification Checklist

- [ ] `pytest test_rvg.py` passes (40 tests)
- [ ] `python -c "import main"` succeeds
- [ ] No secrets/API keys committed
- [ ] All Persian comment style preserved

## Anti-Patterns to Avoid

- ❌ Adding new compiled/runtime deps beyond `cryptography`
- ❌ Breaking VMess/VLESS Wire format (test vectors would catch)
- ❌ Storing plaintext passwords (use PBKDF2 via `hash_password`)
- ❌ Direct `write_text` on state file (must be atomic temp+replace)
- ❌ Trusting `X-Forwarded-For` without `_sanitize_ip()` validation

## Environment Variables

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | 8000 | HTTP port |
| `ADMIN_PASSWORD` | `123456` | Panel admin password |
| `SECRET_KEY` | random | Session signing secret (persist across restarts!) |
| `DATA_DIR` | `/data` | State file directory |
| `COOKIE_SECURE` | `1` | Force Secure flag on session cookie |