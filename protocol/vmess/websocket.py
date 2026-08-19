# websocket.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess — اندپوینت WebSocket (/vmess-ws)
# پارس هدر AEAD، رمزگشایی بدنه و relay در vmess.py (هسته‌ی مشترک) قرار دارند.
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import socket
import secrets
import time
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from protocol import _validate_target

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    save_state,
    log_activity,
    schedule_save,
)
from protocol.vmess.vmess import (
    _ws_client_ip,
    RELAY_BUF,
    SOCK_BUF,
    WRITE_HIGH_WATER,
    cmd_key_from_uuid,
    all_user_uuids,
    open_vmess_aead_header,
    parse_request_header,
    VmessCipher,
    VmessStreamDecoder,
    VmessStreamEncoder,
    seal_response_header_aead,
    derive_response_keys,
    UserValidator,
    SEC_NONE,
    SEC_LEGACY,
    CMD_TCP,
    CMD_UDP,
    CMD_MUX,
    OPT_CHUNK_STREAM,
    OPT_CHUNK_MASKING,
    OPT_GLOBAL_PADDING,
    OPT_AUTHENTICATED_LENGTH,
    PROTOCOL_VERSION,
)

# ── UserValidator 配音 گلودار ──
# کاربران از LINKS به‌صورت پویا sync می‌شوند (هر اتصال یک بار).
# بیرون از تابع تعریف شده تا state بین اتصال‌ها حفظ شود (anti-replay).

_validator: UserValidator | None = None
_validator_lock = asyncio.Lock()


def _get_validator() -> UserValidator:
    global _validator
    if _validator is None:
        _validator = UserValidator(for_links_cb=_async_links_cb)
    return _validator


async def _async_links_cb(uuids):
    """callback که validator برای بررسی وجود/مجاز بودن کاربر صدا می‌زند."""
    async with LINKS_LOCK:
        return {u: LINKS.get(u) for u in uuids}


async def _sync_validator_from_links():
    """ساخت {(uuid: cmdKey)} از همه‌ی linkهای vmess — هر بار که کلاینت وصل می‌شه."""
    async with _validator_lock:
        async with LINKS_LOCK:
            pairs = {}
            for uid, link in LINKS.items():
                proto = link.get("protocol", "")
                if not proto or not proto.startswith("vmess"):
                    continue
                if not is_link_allowed(link):
                    continue
                alter = int(link.get("vmess_alter_id", 0) or 0)
                for uuid_str, cmd_key in all_user_uuids(uid, alter):
                    pairs[uuid_str] = cmd_key
        _get_validator().sync_users(pairs)


# ── راه‌اندازی سوکت ──

def _tune_socket(writer: asyncio.StreamWriter):
    try:
        sock = writer.transport.get_extra_info("socket")
        if sock is None:
            return
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF)
    except OSError as e:
        logger.warning(f"VMess _tune_socket failed: {e}")


# ── QuotaGate (مشابه VLESS/Trojan) ──

QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 2 * 1024 * 1024
QUOTA_START_BATCH = 128 * 1024
QUOTA_CHECK_INTERVAL = 0.25


async def _check_and_use(uid: str, n: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        if not is_link_allowed(link):
            return False
        link["used_bytes"] += n
        stats["total_bytes"] += n
        from main import hourly_traffic, now_ir
        hourly_traffic[now_ir().strftime("%H:00")] += n
    return True


class _QuotaGate:
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst = flush / elapsed
                self.rate_ewma = inst if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            try:
                self.ok = await _check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"VMess QuotaGate.add failed uuid={self.uuid[:8]}: {exc}")
                self.ok = False
        return self.ok

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            try:
                self.ok = self.ok and await _check_and_use(self.uuid, flush)
            except Exception as exc:
                logger.error(f"VMess QuotaGate.flush failed uuid={self.uuid[:8]}: {exc}")
                self.ok = False
        return self.ok


# ── relay توابع ──

async def _relay_ws_to_tcp(ws: WebSocket, writer: asyncio.StreamWriter,
                           decoder: VmessStreamDecoder, conn_id: str, uuid: str):
    gate = _QuotaGate(uuid)
    conn = connections.get(conn_id)
    try:
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data:
                continue
            decoder.feed(data)
            try:
                for payload in decoder.try_decrypt_chunks():
                    if not payload:
                        continue
                    if not await gate.add(len(payload)):
                        await ws.close(code=1008, reason="quota/disabled/unknown")
                        return
                    stats["total_requests"] += 1
                    if conn is not None:
                        conn["bytes"] += len(payload)
                    writer.write(payload)
            except ValueError:
                await ws.close(code=1008, reason="bad vmess frame")
                return
            if writer.transport.get_write_buffer_size() > WRITE_HIGH_WATER:
                await writer.drain()
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        await gate.flush()
        try:
            writer.write_eof()
        except Exception:
            pass


async def _relay_tcp_to_ws(ws: WebSocket, reader: asyncio.StreamReader,
                           encoder: VmessStreamEncoder, conn_id: str, uuid: str):
    gate = _QuotaGate(uuid)
    conn = connections.get(conn_id)
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                await ws.close(code=1008, reason="quota/disabled/unknown")
                break
            if conn is not None:
                conn["bytes"] += len(data)
            frame = encoder.encode_chunk(data)
            await ws.send_bytes(frame)
    except Exception:
        pass
    finally:
        await gate.flush()


# ── هندشیک: باز کردن هدر، سازگاری AEAD/legacy ──

async def _vmess_handshake(first_chunk: bytes):
    """
    باز کردن هدر درخواست VMess.
    خروجی: (RequestHeader, leftover_body, nconsumed) یا (None, None, error_msg)
    """
    if len(first_chunk) < 16:
        return None, None, "header too short"

    await _sync_validator_from_links()
    validator = _get_validator()

    auth_id = first_chunk[:16]
    uuid = validator.match_auth_id(auth_id)
    if uuid is None:
        return None, None, "no matching user (authID)"

    # پیدا کردن cmdKey برای این uuid (validator نگه ‌دارد)
    cmd_key = None
    for ck, u in validator._users.items():
        if u == uuid:
            cmd_key = ck
            break
    if cmd_key is None:
        return None, None, "cmdKey not found"

    # باز کردن هدر AEAD
    # open_vmess_aead_header expects data AFTER auth_id (len_enc + conn_nonce + payload)
    header_data = first_chunk[16:]
    plaintext, consumed = open_vmess_aead_header(cmd_key, auth_id, header_data)
    if plaintext is None:
        return None, None, "AEAD header decrypt failed"

    header = parse_request_header(plaintext)
    header.uuid = uuid
    header.is_aead = True
    leftover = first_chunk[16 + consumed:]  # بعد از authID + consumed
    return header, leftover, None


# ── endpoint اصلی ──

async def vmess_ws_tunnel(ws: WebSocket):
    await ws.accept()
    ip = _ws_client_ip(ws)
    conn_id = secrets.token_urlsafe(6)
    writer = None

    try:
        # جمع کردن هندشیک (ممکن است در چند فریم WS بیاید)
        loop = asyncio.get_event_loop()
        deadline = loop.time() + 15.0
        buf = bytearray()
        header = None
        leftover = None
        err = None
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                await ws.close(code=1008, reason="handshake timeout")
                return
            msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
            if msg["type"] == "websocket.disconnect":
                return
            chunk = msg.get("bytes") or (msg.get("text") or "").encode()
            if chunk:
                buf += chunk
                if len(buf) > 64 * 1024:
                    await ws.close(code=1008, reason="handshake too large")
                    return
                header, leftover, err = await _vmess_handshake(bytes(buf))
                if header is not None:
                    break
                # اگر کافی بایت وصل شده و باز کردن شکست خورد → رد
                if len(buf) >= 60 and err:
                    logger.warning(f"🚫 VMess-WS rejected [{conn_id}] ip={ip}: {err}")
                    await ws.close(code=1008, reason="not authorized")
                    return

        if header is None:
            logger.warning(f"🚫 VMess-WS rejected [{conn_id}] ip={ip}: {err}")
            await ws.close(code=1008, reason="not authorized")
            return

        async with LINKS_LOCK:
            link = LINKS.get(header.uuid)
        if not is_link_allowed(link):
            await ws.close(code=1008, reason="not authorized")
            return

        # فقط TCP را relay می‌کنیم (MUX/UDP فعلاً پشتیبانی نمی‌شود)
        if header.command not in (CMD_TCP,):
            await ws.close(code=1008, reason="unsupported command")
            return

        connections[conn_id] = {
            "uuid": header.uuid,
            "ip": ip,
            "transport": "vmess-ws",
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
        }
        logger.info(f"✅ VMess-WS [{conn_id}] uuid={header.uuid[:8]}… ip={ip} → "
                     f"{header.address}:{header.port} sec={header.security} opt={header.option:#x}")
        log_activity("connection", f"اتصال VMess از {ip} (کانفیگ {link.get('label','?')})", "info")

        if _validate_target(header.address, header.port) is None:
            logger.warning(f"❌ VMess-WS [{conn_id}] SSRF-blocked dial -> {header.address}:{header.port}")
            await ws.close(code=1008, reason="invalid destination")
            return

        # باز کردن اتصال TCP به مقصد
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(header.address, header.port),
            timeout=10.0
        )
        _tune_socket(writer)

        # رمز بدنه‌ی درخواست
        req_cipher = VmessCipher(header.security, header.body_key, header.body_iv)
        chunk_stream = bool(header.option & OPT_CHUNK_STREAM)
        chunk_masking = bool(header.option & OPT_CHUNK_MASKING)
        global_padding = bool(header.option & OPT_GLOBAL_PADDING)
        auth_len = bool(header.option & OPT_AUTHENTICATED_LENGTH)
        # v2ray client.go: GlobalPadding و AuthenticatedLength بدون ChunkMasking
        # ترکیب نامعتبرند (padding روی ShakeSizeParser می‌سازد). ردشان کنیم تا
        # encoder/decoder با حالت‌های غیرقانونی مواجه نشوند.
        if global_padding and not chunk_masking:
            logger.warning(f"❌ VMess-WS [{conn_id}] illegal option (padding without masking)")
            await ws.close(code=1008, reason="invalid option")
            return
        if auth_len and not chunk_masking:
            logger.warning(f"❌ VMess-WS [{conn_id}] illegal option (auth_len without masking)")
            await ws.close(code=1008, reason="invalid option")
            return
        decoder = VmessStreamDecoder(
            req_cipher, chunk_stream, chunk_masking, global_padding, auth_len, header.command
        )

        # رمز بدنه‌ی پاسخ
        resp_key, resp_iv = derive_response_keys(header.body_key, header.body_iv, header.is_aead)
        resp_cipher = VmessCipher(header.security, resp_key, resp_iv)
        encoder = VmessStreamEncoder(
            resp_cipher, chunk_stream, chunk_masking, global_padding, auth_len
        )

        # ارسال هدر پاسخ
        resp_header_bytes = bytes([header.response_header, 0x00])  # header + option
        if header.is_aead:
            resp_hdr = seal_response_header_aead(resp_key, resp_iv, resp_header_bytes)
        else:
            # legacy: AES-CFB مستقیم روی هدر
            from protocol.vmess.vmess import _AESCFB
            legacy = _AESCFB(resp_key, resp_iv)
            resp_hdr = legacy.encrypt(resp_header_bytes)
        await ws.send_bytes(resp_hdr)

        # اگر leftover در هندشیک بود قبل به مقصد بفرست
        if leftover:
            # leftover باید وارد decoder بشه نه مستقیم — رمز بدنه است
            decoder.feed(leftover)
            try:
                for payload in decoder.try_decrypt_chunks():
                    if payload:
                        writer.write(payload)
                        stats["total_requests"] += 1
                        connections[conn_id]["bytes"] += len(payload)
                await writer.drain()
            except ValueError:
                await ws.close(code=1008, reason="bad leftover frame")
                return

        done, pending = await asyncio.wait(
            {
                asyncio.create_task(_relay_ws_to_tcp(ws, writer, decoder, conn_id, header.uuid)),
                asyncio.create_task(_relay_tcp_to_ws(ws, reader, encoder, conn_id, header.uuid)),
            },
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass

        asyncio.create_task(schedule_save())

    except WebSocketDisconnect:
        pass
    except asyncio.TimeoutError:
        stats["total_errors"] += 1
        error_logs.append({"error": "vmess connection timeout", "time": datetime.now().isoformat()})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"VMess-WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 VMess-WS closed [{conn_id}] total={len(connections)}")
