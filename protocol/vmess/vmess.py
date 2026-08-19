# vmess.py
# ══════════════════════════════════════════════════════════════════════════════
# VMess — پیاده‌سازی سمت سرور (v2ray/xray compatible)
# پورت پایتونی وفادار از v2fly/v2ray-core:
#   proxy/vmess/account.go, common/protocol/id.go, proxy/vmess/encoding/{auth,server}.go,
#   proxy/vmess/aead/{kdf,authid,encrypt}.go, common/crypto/{auth,chunk,io}.go
#
# پشتیبانی:
#   - VMess AEAD (پیش‌فرض v2ray ≥4.22 / xray) — احراز هویت authID
#   - AlterID (برای سازگاری با کلاینت‌های قدیمی‌تر که aid>0 می‌فرستند)
#   - رمز بدنه: auto → AES-128-GCM | chacha20-poly1305 | none | legacy(AES-CFB)
#   - قاب‌بندی chunked: plain یا Shake128-masked (OPT_CHUNK_MASKING)
#   - پاسخ: هدر AEAD + AES-CFB بدنه (مطابق server.go)
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import hashlib
import hmac
import os
import secrets
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from fastapi import WebSocket

# ── ثابت‌های پروتکل ──────────────────────────────────────────────────────────
PROTOCOL_VERSION = 1
CMD_TCP = 1
CMD_UDP = 2
CMD_MUX = 3

ADDR_IPV4 = 1
ADDR_DOMAIN = 2
ADDR_IPV6 = 3

SEC_AUTO = 0
SEC_NONE = 1
SEC_AES128_GCM = 3
SEC_CHACHA20_POLY1305 = 4
SEC_LEGACY = 5

OPT_CHUNK_STREAM = 0x01
OPT_CHUNK_MASKING = 0x04
OPT_GLOBAL_PADDING = 0x08
OPT_AUTHENTICATED_LENGTH = 0x10

# Saltهای KDF (proxy/vmess/aead/consts.go)
KDF_SALT_AEAD_KDF = "VMess AEAD KDF"
KDF_SALT_AUTHID_ENC_KEY = "AES Auth ID Encryption"
KDF_SALT_RESP_HDR_LEN_KEY = "AEAD Resp Header Len Key"
KDF_SALT_RESP_HDR_LEN_IV = "AEAD Resp Header Len IV"
KDF_SALT_RESP_HDR_PAY_KEY = "AEAD Resp Header Key"
KDF_SALT_RESP_HDR_PAY_IV = "AEAD Resp Header IV"
KDF_SALT_HDR_PAY_AEAD_KEY = "VMess Header AEAD Key"
KDF_SALT_HDR_PAY_AEAD_IV = "VMess Header AEAD Nonce"
KDF_SALT_HDR_LEN_AEAD_KEY = "VMess Header AEAD Key_Length"
KDF_SALT_HDR_LEN_AEAD_IV = "VMess Header AEAD Nonce_Length"

UUID_CMD_KEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
UUID_NEXT_ID_SALT = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81"
UUID_NEXT_ID_FALLBACK_SALT = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2"

RESPONSE_HEADER_V0 = 0x00
CHUNK_MAX = 16384
MAX_HEADER_LEN = 4096
REPLAY_WINDOW = 120.0

RELAY_BUF = 1024 * 1024
SOCK_BUF = 4 * 1024 * 1024
WRITE_HIGH_WATER = 512 * 1024


# ══════════════════════════════════════════════════════════════════════════════
# UUID / ID
# ══════════════════════════════════════════════════════════════════════════════

def uuid_bytes(uuid_str_: str) -> bytes:
    u = uuid_str_.replace("-", "").strip().lower()
    if len(u) != 32:
        raise ValueError(f"invalid uuid: {uuid_str_!r}")
    try:
        return bytes.fromhex(u)
    except ValueError:
        raise ValueError(f"invalid uuid: {uuid_str_!r}")


def cmd_key_from_uuid(uuid_str_: str) -> bytes:
    """cmdKey = MD5(uuid_bytes || salt) — common/protocol/id.go NewID."""
    return hashlib.md5(uuid_bytes(uuid_str_) + UUID_CMD_KEY_SALT).digest()


def next_id(uuid_b: bytes) -> bytes:
    """AlterID بعدی (common/protocol/id.go nextID)."""
    md5h = hashlib.md5()
    md5h.update(uuid_b)
    md5h.update(UUID_NEXT_ID_SALT)
    newid = md5h.digest()
    while newid == uuid_b:
        md5h.update(UUID_NEXT_ID_FALLBACK_SALT)
        newid = md5h.digest()
    return newid


def all_user_uuids(uuid_str_: str, alter_id: int = 0) -> list:
    """خروجی: [(uuid_str, cmd_key_bytes), ...] — شامل AlterIDها."""
    out = [(uuid_str_, cmd_key_from_uuid(uuid_str_))]
    prev = uuid_bytes(uuid_str_)
    for _ in range(max(0, int(alter_id or 0))):
        prev = next_id(prev)
        out.append((uuid_str(prev), cmd_key_from_uuid(uuid_str(prev))))
    return out


def uuid_str(b: bytes) -> str:
    if len(b) != 16:
        raise ValueError("uuid bytes must be 16")
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ══════════════════════════════════════════════════════════════════════════════
# KDF — زنجیره HMAC-SHA256 (proxy/vmess/aead/kdf.go)
# ══════════════════════════════════════════════════════════════════════════════

def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def kdf(key: bytes, *path) -> bytes:
    result = _hmac_sha256(KDF_SALT_AEAD_KDF.encode(), key)
    for p in path:
        if isinstance(p, str):
            p = p.encode()
        result = _hmac_sha256(result, p)
    return result


def kdf16(key: bytes, *path) -> bytes:
    return kdf(key, *path)[:16]


# ══════════════════════════════════════════════════════════════════════════════
# AuthID (proxy/vmess/aead/authid.go) — AES-ECB تک‌بلاکی
# ══════════════════════════════════════════════════════════════════════════════

def create_auth_id(cmd_key: bytes, ts: int) -> bytes:
    body = struct.pack(">Q", ts) + os.urandom(4)
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return _aes_ecb_encrypt(kdf16(cmd_key, KDF_SALT_AUTHID_ENC_KEY), body + struct.pack(">I", crc))


def _aes_ecb_encrypt(key16: bytes, plain16: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key16), modes.ECB()).encryptor()
    return c.update(plain16) + c.finalize()


def _aes_ecb_decrypt(key16: bytes, cipher16: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    c = Cipher(algorithms.AES(key16), modes.ECB()).decryptor()
    return c.update(cipher16) + c.finalize()


def decode_auth_id(cmd_key: bytes, auth_id: bytes) -> Tuple[int, int]:
    """برمی‌گرداند (timestamp, crc)."""
    plain = _aes_ecb_decrypt(kdf16(cmd_key, KDF_SALT_AUTHID_ENC_KEY), auth_id)
    ts = struct.unpack(">Q", plain[:8])[0]
    crc = struct.unpack(">I", plain[12:16])[0]
    return ts, crc


# ══════════════════════════════════════════════════════════════════════════════
# AEAD هدر (proxy/vmess/aead/encrypt.go)
# ══════════════════════════════════════════════════════════════════════════════

def _gcm_encrypt(key: bytes, nonce: bytes, plain: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce, plain, aad)


def _gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


def seal_vmess_aead_header(cmd_key: bytes, data: bytes) -> bytes:
    auth_id = create_auth_id(cmd_key, int(time.time()))
    conn_nonce = os.urandom(8)

    len_key = kdf16(cmd_key, KDF_SALT_HDR_LEN_AEAD_KEY, auth_id, conn_nonce)
    len_nonce = kdf(cmd_key, KDF_SALT_HDR_LEN_AEAD_IV, auth_id, conn_nonce)[:12]
    len_enc = _gcm_encrypt(len_key, len_nonce, struct.pack(">H", len(data)), auth_id)

    pay_key = kdf16(cmd_key, KDF_SALT_HDR_PAY_AEAD_KEY, auth_id, conn_nonce)
    pay_nonce = kdf(cmd_key, KDF_SALT_HDR_PAY_AEAD_IV, auth_id, conn_nonce)[:12]
    pay_enc = _gcm_encrypt(pay_key, pay_nonce, data, auth_id)

    return auth_id + len_enc + conn_nonce + pay_enc


def open_vmess_aead_header(cmd_key: bytes, auth_id: bytes, data: bytes) -> Tuple[Optional[bytes], int]:
    """بازکردن هدر AEAD. → (plaintext | None, bytes_consumed).
    auth_id is passed separately (already consumed by caller).
    data = len_enc(18) + conn_nonce(8) + payload_aead(len+16)"""
    if len(data) < 18 + 8:
        return None, 0
    pos = 0
    len_enc = data[pos:pos + 18]; pos += 18
    conn_nonce = data[pos:pos + 8]; pos += 8

    len_key = kdf16(cmd_key, KDF_SALT_HDR_LEN_AEAD_KEY, auth_id, conn_nonce)
    len_nonce = kdf(cmd_key, KDF_SALT_HDR_LEN_AEAD_IV, auth_id, conn_nonce)[:12]
    try:
        len_plain = _gcm_decrypt(len_key, len_nonce, len_enc, auth_id)
    except Exception:
        return None, pos
    length = struct.unpack(">H", len_plain)[0]
    if length > MAX_HEADER_LEN:
        return None, pos

    pay_enc = data[pos:pos + length + 16]
    if len(pay_enc) < length + 16:
        return None, pos + len(pay_enc)
    pay_key = kdf16(cmd_key, KDF_SALT_HDR_PAY_AEAD_KEY, auth_id, conn_nonce)
    pay_nonce = kdf(cmd_key, KDF_SALT_HDR_PAY_AEAD_IV, auth_id, conn_nonce)[:12]
    try:
        payload = _gcm_decrypt(pay_key, pay_nonce, pay_enc, auth_id)
    except Exception:
        return None, pos + len(pay_enc)
    return payload, pos + len(pay_enc)


# ══════════════════════════════════════════════════════════════════════════════
# Shake128 size parser (proxy/vmess/encoding/auth.go) — جریان‌بند برای هر
# 2 بایت: یک mask 2 بایتی. کل خروجی SHAKE128 یک جریان بیت است.
# ══════════════════════════════════════════════════════════════════════════════

class ShakeSizeParser:
    def __init__(self, seed: bytes):
        self._buf = hashlib.shake_128(seed).digest(1024)
        self._pos = 0

    def _next(self) -> bytes:
        if self._pos + 2 > len(self._buf):
            self._buf = hashlib.shake_128(self._buf).digest(1024)
            self._pos = 0
        out = self._buf[self._pos:self._pos + 2]
        self._pos += 2
        return out

    def decode(self, two_bytes: bytes) -> int:
        return struct.unpack(">H", _xor(two_bytes, self._next()))[0]

    def encode(self, size: int) -> bytes:
        return _xor(struct.pack(">H", size), self._next())

    def next_padding_len(self) -> int:
        return struct.unpack(">H", self._next())[0] % 64

    def max_padding_len(self) -> int:
        return 64


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ══════════════════════════════════════════════════════════════════════════════
# Chunk nonce — از client.go GenerateChunkNonce:
#   nonce = base nonce با 2 بایت اول = شمارنده‌ی قاب (big-endian, از 0)
# ══════════════════════════════════════════════════════════════════════════════

def chunk_nonce_generator(nonce: bytes, size: int):
    base = bytearray(nonce)
    count = 0
    while True:
        base[0] = (count >> 8) & 0xFF
        base[1] = count & 0xFF
        out = bytes(base[:size])
        count += 1
        yield out


# ══════════════════════════════════════════════════════════════════════════════
# هدر درخواست
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RequestHeader:
    version: int = PROTOCOL_VERSION
    body_iv: bytes = b""
    body_key: bytes = b""
    response_header: int = RESPONSE_HEADER_V0
    option: int = 0
    security: int = SEC_AES128_GCM
    command: int = CMD_TCP
    address: str = ""
    port: int = 0
    address_type: int = 0
    uuid: str = ""
    is_aead: bool = True
    legacy_ts: int = 0


def _read_addr_port(data: bytes, pos: int) -> Tuple[str, int, int]:
    atyp = data[pos]; pos += 1
    if atyp == ADDR_IPV4:
        if pos + 4 > len(data):
            raise ValueError("short ipv4")
        address = ".".join(str(b) for b in data[pos:pos + 4]); pos += 4
    elif atyp == ADDR_DOMAIN:
        if pos + 1 > len(data):
            raise ValueError("short domain")
        dlen = data[pos]; pos += 1
        if pos + dlen > len(data):
            raise ValueError("short domain body")
        address = data[pos:pos + dlen].decode("utf-8", errors="ignore"); pos += dlen
    elif atyp == ADDR_IPV6:
        if pos + 16 > len(data):
            raise ValueError("short ipv6")
        ab = data[pos:pos + 16]; pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown atyp: {atyp}")
    if pos + 2 > len(data):
        raise ValueError("short port")
    port = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
    return address, port, pos


def parse_request_header(data: bytes) -> RequestHeader:
    if len(data) < 38:
        raise ValueError("header too short")
    h = RequestHeader()
    pos = 0
    h.version = data[pos]; pos += 1
    if h.version != PROTOCOL_VERSION:
        raise ValueError(f"unsupported vmess version {h.version}")
    h.body_iv = data[pos:pos + 16]; pos += 16
    h.body_key = data[pos:pos + 16]; pos += 16
    h.response_header = data[pos]; pos += 1
    h.option = data[pos]; pos += 1
    p = data[pos]; pos += 1
    padding_len = p >> 4
    h.security = p & 0x0F
    pos += 1  # reserved
    h.command = data[pos]; pos += 1

    if h.command == CMD_TCP:
        h.address, h.port, pos = _read_addr_port(data, pos)
    elif h.command == CMD_UDP:
        h.address, h.port, pos = _read_addr_port(data, pos)
    elif h.command == CMD_MUX:
        h.address = "v1.mux.cool"
        h.port = 0
    else:
        raise ValueError(f"unknown command {h.command}")

    if padding_len > 0:
        pos += padding_len
    if pos + 4 > len(data):
        raise ValueError("missing checksum")
    if _fnv1a32(data[:pos]) != struct.unpack(">I", data[pos:pos + 4])[0]:
        raise ValueError("invalid header checksum")
    return h


def _fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ══════════════════════════════════════════════════════════════════════════════
# رمز بدنه
# ══════════════════════════════════════════════════════════════════════════════

class VmessCipher:
    """رمز بدنه‌ی یک سشن — هم رمزگشایی درخواست هم رمزگذاری پاسخ."""

    def __init__(self, security: int, key: bytes, iv: bytes):
        self.security = security
        self.key = key
        self.iv = iv
        self._nonce_gen = None
        self._aead = None
        self._aes_cfb = None
        if security == SEC_AES128_GCM:
            self._aead = AESGCM(key)
            self._nonce_gen = chunk_nonce_generator(iv, 12)
        elif security == SEC_CHACHA20_POLY1305:
            self._aead = ChaCha20Poly1305(_chacha_key(key))
            self._nonce_gen = chunk_nonce_generator(iv, 12)
        elif security == SEC_LEGACY:
            self._aes_cfb = _AESCFB(key, iv)
        elif security == SEC_NONE:
            pass
        else:
            raise ValueError(f"unsupported security {security}")

    def decrypt_chunk(self, data: bytes) -> bytes:
        if self.security in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
            return self._aead.decrypt(next(self._nonce_gen), data, None)
        if self.security == SEC_LEGACY:
            return self._aes_cfb.decrypt(data)
        return data

    def encrypt_chunk(self, data: bytes) -> bytes:
        if self.security in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
            return self._aead.encrypt(next(self._nonce_gen), data, None)
        if self.security == SEC_LEGACY:
            return self._aes_cfb.encrypt(data)
        return data


def _chacha_key(key16: bytes) -> bytes:
    k = hashlib.md5(key16).digest()
    return k + hashlib.md5(k).digest()


class _AESCFB:
    def __init__(self, key: bytes, iv: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self._enc = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        self._dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()

    def encrypt(self, data: bytes) -> bytes:
        return self._enc.update(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._dec.update(data)


# ══════════════════════════════════════════════════════════════════════════════
# Decoder جریان ورودی (chunked + auth) — مطابق AuthenticationReader
# ══════════════════════════════════════════════════════════════════════════════

class VmessStreamDecoder:
    def __init__(self, cipher: VmessCipher, chunk_stream: bool, chunk_masking: bool,
                 global_padding: bool = False, authenticated_length: bool = False,
                 command: int = CMD_TCP):
        self.cipher = cipher
        self.chunk_stream = chunk_stream
        self.chunk_masking = chunk_masking
        self.global_padding = global_padding
        self.authenticated_length = authenticated_length
        self.command = command
        self._shake = ShakeSizeParser(cipher.iv) if chunk_masking else None
        self._len_aead = None
        self._len_nonce_gen = None
        if authenticated_length and cipher.security in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
            len_key = kdf16(cipher.key, "auth_len")
            if cipher.security == SEC_AES128_GCM:
                self._len_aead = AESGCM(len_key)
            else:
                self._len_aead = ChaCha20Poly1305(_chacha_key(len_key))
            self._len_nonce_gen = chunk_nonce_generator(cipher.iv, 12)
        self._buf = bytearray()
        # v2ray AuthenticationReader.hasSize: اگر سایزِ یک قاب کامل پارس شد ولی
        # بدنه‌اش هنوز نرسید، (size, padding, field_bytes) را نگه می‌داریم تا در
        # فراخوانی بعدی دوباره ماسک/SHAKE/nonce مصرف نشود (جلوگیری از desync).
        self._pending = None

    def feed(self, data: bytes):
        self._buf += data

    def _read_size(self) -> Optional[Tuple[int, int, int]]:
        """(size_with_overhead, padding_len, size_field_bytes) یا None اگر کامل نیست."""
        size_field_bytes = 2
        if self._len_aead is not None:
            size_field_bytes = 18  # 2 بایت سایز + 16 بایت AEAD tag
        if self._pending:
            return self._pending
        if len(self._buf) < size_field_bytes:
            return None
        # v2ray AuthenticationReader.readSize(): padding mask consumed BEFORE
        # size mask (NextPaddingLen() then Decode()). The writer (seal()) also
        # consumes padding-mask first — consume padding BEFORE Decode.
        padding = self._shake.next_padding_len() if self.global_padding else 0
        size_raw = bytes(self._buf[:size_field_bytes])
        try:
            if self._len_aead is not None:
                size_plain = self._len_aead.decrypt(next(self._len_nonce_gen), size_raw, None)
                size = struct.unpack(">H", size_plain)[0] + 16  # AEADChunkSizeParser: +Overhead
            elif self._shake is not None:
                size = self._shake.decode(size_raw)
            else:
                size = struct.unpack(">H", size_raw)[0]
        except Exception:
            raise ValueError("bad frame size")
        return size, padding, size_field_bytes

    def try_decrypt_chunks(self) -> list:
        out = []
        while True:
            res = self._read_size()  # اگر داریم، _pending را برمی‌گرداند
            if res is None:
                break
            size, padding, field_bytes = res
            if self._pending is not None:
                self._pending = None  # یک‌بار مصرف
            if size == 0:
                break  # پایان جریان (سایز صفر) — ChunkStreamReader: nextSize==0
            if self._len_aead is not None and size - padding == 16:
                # AEAD EOF — AuthenticationReader.readInternal: اگر بدنه فقط tag(16)
                # + padding باشد (یعنی payload خالی)، پایان جریان است. چون
                # AEADChunkSizeParser.Decode همیشه ≥16 برمی‌گرداند، این سانتی‌نل
                # با شرط size==0 بالا قابل جذب نیست.
                break
            # v2ray wire: size قبلاً شامل padding است (encrypted_size + padding).
            # total_frame = field + size (پدینگ جدا اضافه نمی‌شود چون قبلاً داخل
            # size هست). limit: مقدار ماکزیممی که فیلد ۲بایتی سایز (بعد از +16
            # برای AEAD parser) می‌تواند دربرگیرد — و پاس‌کردن آن در خواننده‌ی
            # v2ray (Protected key) یعنی هیچ قاب قانونی‌ای بزرگ‌تر از این نیست؛
            # در حالی که 20-32KB از clientهای v2ray دار باید پذیرفته شود.
            if size > 0xFFFF + 16:
                raise ValueError(f"chunk too large: size={size}")
            total_frame = field_bytes + size
            if len(self._buf) < total_frame:
                # فریم کامل نیست — سایزش را نگه می‌داریم تا در فراخوانی بعدی
                # ماسک/SHAKE/nonce دوباره مصرف نشود (معادل hasSize در v2ray).
                # متادیتای _pending را روی خود تسکِ (size, padding, field_bytes)
                # هم که هست می‌گذاریم و break می‌کنیم.
                self._pending = (size, padding, field_bytes)
                break
            encrypted_size = size - padding
            payload = bytes(self._buf[field_bytes:field_bytes + encrypted_size])
            del self._buf[:total_frame]
            if self.chunk_stream:
                plain = self.cipher.decrypt_chunk(payload)
            else:
                plain = payload
            if plain:
                out.append(plain)
        return out

    def remaining(self) -> bytes:
        return bytes(self._buf)


# ══════════════════════════════════════════════════════════════════════════════
# Encoder پاسخ — مطابق AuthenticationWriter/ChunkStreamWriter
# ══════════════════════════════════════════════════════════════════════════════

class VmessStreamEncoder:
    def __init__(self, cipher: VmessCipher, chunk_stream: bool, chunk_masking: bool,
                 global_padding: bool = False, authenticated_length: bool = False):
        self.cipher = cipher
        self.chunk_stream = chunk_stream
        self.chunk_masking = chunk_masking
        self.global_padding = global_padding
        self.authenticated_length = authenticated_length
        self._shake = ShakeSizeParser(cipher.iv) if chunk_masking else None
        self._len_aead = None
        self._len_nonce_gen = None
        if authenticated_length and cipher.security in (SEC_AES128_GCM, SEC_CHACHA20_POLY1305):
            len_key = kdf16(cipher.key, "auth_len")
            if cipher.security == SEC_AES128_GCM:
                self._len_aead = AESGCM(len_key)
            else:
                self._len_aead = ChaCha20Poly1305(_chacha_key(len_key))
            self._len_nonce_gen = chunk_nonce_generator(cipher.iv, 12)

    def encode_chunk(self, data: bytes) -> bytes:
        if not self.chunk_stream:
            return self.cipher.encrypt_chunk(data)
        out = bytearray()
        i = 0
        # v2ray نوشتن‌ها را به قاب‌های ≤buf.Size (~32KiB) می‌شکند (writeStream/
        # ChunkStreamWriter). چند-تایی نکردن باعث سرریز فیلد ۲بایتی سایز برای
        # پاسخ‌های بزرگ (RELAY_BUF=1MB) می‌شد → struct.error و قطع سایلنت
        # کانکشن. در اینجا به CHUNK_MAX (16KiB) می‌شکنیم تا زیر این سقف بمانیم.
        while i < len(data):
            out += self._encode_one(data[i:i + CHUNK_MAX])
            i += CHUNK_MAX
        return bytes(out)

    def _encode_one(self, data: bytes) -> bytes:
        # global_padding و auth_len بدون chunk_masking ترکیب قانونی v2ray نیست
        # (client.go: padding به ShakeSizeParser نیاز دارد)؛ در دست‌shake هم رد
        # می‌شود. اگر به اینجا رسید یعنی فریم نامعتبر — خطا بده نه سایلنت.
        if self.global_padding and self._shake is None:
            raise ValueError("global_padding requires chunk_masking")
        ct = self.cipher.encrypt_chunk(data)
        encrypted_size = len(ct)
        shake = self._shake
        # v2ray ordering: size mask FIRST (Encode), padding mask SECOND (NextPaddingLen).
        # Python must match — compute size field before padding to keep masks aligned.
        if self._len_aead is not None:
            # AEADChunkSizeParser.Encode: stores (size - Overhead), i.e. (payload+padding)
            # v2ray: with auth-len, padding comes from the (required) masking parser
            # BEFORE the AEAD size field (seal(): NextPaddingLen then Encode).
            padding = shake.next_padding_len() if self.global_padding else 0
            size_raw = struct.pack(">H", encrypted_size + padding - 16)
            size_field = self._len_aead.encrypt(next(self._len_nonce_gen), size_raw, None)
        elif shake is not None:
            # v2ray AuthenticationWriter.seal(): NextPaddingLen() FIRST (mask #1),
            # then Encode(encryptedSize+paddingSize) (mask #2). Reader matches:
            # NextPaddingLen then Decode. Padding-mask before size-mask.
            padding = shake.next_padding_len() if self.global_padding else 0
            size_field = shake.encode(encrypted_size + padding)
        else:
            padding = 0
            size_field = struct.pack(">H", encrypted_size)
        frame = size_field + ct
        if padding:
            frame += os.urandom(padding)
        return frame


# ══════════════════════════════════════════════════════════════════════════════
# پاسخ AEAD (server.go EncodeResponseHeader — بخش AEAD)
# ══════════════════════════════════════════════════════════════════════════════

def seal_response_header_aead(response_body_key: bytes, response_body_iv: bytes, header: bytes) -> bytes:
    len_key = kdf16(response_body_key, KDF_SALT_RESP_HDR_LEN_KEY)
    len_iv = kdf(response_body_iv, KDF_SALT_RESP_HDR_LEN_IV)[:12]
    pay_key = kdf16(response_body_key, KDF_SALT_RESP_HDR_PAY_KEY)
    pay_iv = kdf(response_body_iv, KDF_SALT_RESP_HDR_PAY_IV)[:12]
    len_enc = _gcm_encrypt(len_key, len_iv, struct.pack(">H", len(header)))
    pay_enc = _gcm_encrypt(pay_key, pay_iv, header)
    return len_enc + pay_enc


def derive_response_keys(body_key: bytes, body_iv: bytes, is_aead: bool) -> Tuple[bytes, bytes]:
    if is_aead:
        return hashlib.sha256(body_key).digest()[:16], hashlib.sha256(body_iv).digest()[:16]
    return hashlib.md5(body_key).digest(), hashlib.md5(body_iv).digest()


# ══════════════════════════════════════════════════════════════════════════════
# UserValidator — جستجوی uuid بر اساس authID
# ══════════════════════════════════════════════════════════════════════════════

class UserValidator:
    """
    cmdKey → uuid. هر authID فقط یک بار پذیرفته می‌شود (anti-replay).
    for_links_cb: async (list_of_uuids) → {uuid: link_dict} — برای بررسی مجاز بودن.
    """

    def __init__(self, for_links_cb):
        self._users: dict = {}
        self._for_links_cb = for_links_cb
        self._seen_auth_ids: dict = {}
        self._last_cleanup = time.monotonic()

    def sync_users(self, uuid_to_cmdkey: dict):
        """uuid_to_cmdkey: {uuid_str: cmd_key_bytes}. We store {cmd_key_bytes: uuid_str}."""
        self._users.clear()
        for uuid_str_v, cmd_key_v in uuid_to_cmdkey.items():
            self._users[cmd_key_v] = uuid_str_v
        self._cleanup()

    def _cleanup(self):
        now = time.monotonic()
        if now - self._last_cleanup < 30:
            return
        self._last_cleanup = now
        cutoff = now - 600
        self._seen_auth_ids = {k: v for k, v in self._seen_auth_ids.items() if v > cutoff}

    def match_auth_id(self, auth_id: bytes) -> Optional[str]:
        for cmd_key, uuid in self._users.items():
            try:
                ts, crc = decode_auth_id(cmd_key, auth_id)
            except Exception:
                continue
            # CRC is computed on the plaintext inside authID: be64(ts) || rand4 (12 bytes)
            # Verify the CRC matches
            plain = _aes_ecb_decrypt(kdf16(cmd_key, KDF_SALT_AUTHID_ENC_KEY), auth_id)
            expected_crc = zlib.crc32(plain[:12]) & 0xFFFFFFFF
            if crc != expected_crc:
                continue
            if abs(ts - int(time.time())) > REPLAY_WINDOW:
                continue
            if auth_id in self._seen_auth_ids:
                continue
            self._seen_auth_ids[auth_id] = time.monotonic()
            self._cleanup()
            return uuid
        return None


# ══════════════════════════════════════════════════════════════════════════════
# لینک اشتراک‌گذاری vmess://
# ══════════════════════════════════════════════════════════════════════════════

def generate_vmess_link(uuid: str, host: str, port: int, remark: str = "RVG",
                        cipher: str = "auto", alter_id: int = 0,
                        ws_path: str = "/vmess-ws", security: str = "tls",
                        sni: str = None, fingerprint: str = "chrome") -> str:
    """vmess:// استاندارد (JSON base64 v2rayN). cipher = نوع رمز بدنه."""
    if cipher not in ("auto", "aes-128-gcm", "chacha20-poly1305", "none"):
        raise ValueError(f"invalid vmess cipher {cipher}")
    import base64
    import json
    from urllib.parse import quote
    payload = {
        "v": "2",
        "ps": remark,
        "add": host,
        "port": str(port),
        "id": uuid,
        "aid": str(int(alter_id or 0)),
        "scy": cipher,
        "net": "ws",
        "type": "none",
        "host": host,
        "path": ws_path,
        "tls": security,
        "sni": sni or host,
        "fp": fingerprint,
        "alpn": "h2,http/1.1",
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    b64 = base64.b64encode(raw.encode()).decode().rstrip("=")
    return f"vmess://{b64}#{quote(remark, safe='')}"


# ══════════════════════════════════════════════════════════════════════════════
# ابزارهای مشترک
# ══════════════════════════════════════════════════════════════════════════════
from protocol import _sanitize_ip


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")
    if fwd:
        first = fwd.split(",")[0].strip()
        ok = _sanitize_ip(first)
        if ok:
            return ok
    real_ip = ws.headers.get("x-real-ip")
    if real_ip:
        ok = _sanitize_ip(real_ip.strip())
        if ok:
            return ok
    return ws.client.host if ws.client else "نامشخص"
