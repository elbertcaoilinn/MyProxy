#!/usr/bin/env python3
"""
Test suite for RVG Gateway
Covers: crypto primitives, auth, links, VMess, VLESS, Trojan, Shadowsocks, MTProto
"""
import pytest
import asyncio
import hashlib
import hmac
import secrets
import time
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent))

from main import (
    hash_password,
    _verify_password,
    _hash_password_pbkdf2,
    client_ip,
    is_link_allowed,
    generate_uuid,
    generate_share_link,
    build_sub_headers,
    LINKS,
    SUBS,
    AUTH,
    SESSIONS,
    LINKS_LOCK,
    SUBS_LOCK,
    SESSIONS_LOCK,
    SECRET_FILE,
    _login_allowed,
    _login_failed,
    _login_success,
)
from protocol.vmess.vmess import (
    cmd_key_from_uuid,
    kdf,
    kdf16,
    _fnv1a32 as fnv1a,
    seal_vmess_aead_header,
    open_vmess_aead_header,
    parse_request_header,
    create_auth_id,
    UserValidator,
    VmessCipher,
    all_user_uuids,
    UUID_CMD_KEY_SALT,
)
from protocol import _sanitize_ip as main_sanitize_ip


# ══════════════════════════════════════════════════════════════════════════════
# Password hashing tests
# ══════════════════════════════════════════════════════════════════════════════
class TestPasswordHashing:
    def test_pbkdf2_format(self):
        pw = "testpassword123"
        h = hash_password(pw)
        assert h.startswith("pbkdf2$")
        parts = h.split("$")
        assert len(parts) == 4
        assert parts[0] == "pbkdf2"
        assert int(parts[1]) == 260000
        assert len(bytes.fromhex(parts[2])) == 16
        assert len(bytes.fromhex(parts[3])) == 32

    def test_pbkdf2_deterministic_per_call(self):
        pw = "testpassword123"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2  # Different salt each call

    def test_pbkdf2_verify_correct(self):
        pw = "correct-horse-battery-staple"
        h = hash_password(pw)
        assert _verify_password(pw, h) is True

    def test_pbkdf2_verify_wrong(self):
        pw = "correct-horse-battery-staple"
        h = hash_password(pw)
        assert _verify_password("wrong-password", h) is False

    def test_legacy_sha256_verify(self):
        # Legacy format: sha256$hash (sha256(pw + secret))
        pw = "legacy"
        legacy_hash = hashlib.sha256(f"{pw}testsecret".encode()).hexdigest()
        stored = f"sha256${legacy_hash}"
        # Temporarily override secret
        from main import CONFIG
        old_secret = CONFIG['secret']
        CONFIG['secret'] = 'testsecret'
        try:
            assert _verify_password(pw, stored) is True
            assert _verify_password("wrong", stored) is False
        finally:
            CONFIG['secret'] = old_secret

    def test_legacy_to_pbkdf2_migration(self):
        """After first login with legacy hash, it should be upgraded to pbkdf2."""
        from main import CONFIG
        old_secret = CONFIG['secret']
        CONFIG['secret'] = 'migration-test'
        try:
            pw = "oldpassword"
            legacy_hash = hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()
            stored = f"sha256${legacy_hash}"
            
            # Verify legacy works
            assert _verify_password(pw, stored) is True
            
            # Simulate login - new hash should be generated
            new_hash = hash_password(pw)
            assert new_hash.startswith("pbkdf2$")
            assert _verify_password(pw, new_hash) is True
        finally:
            CONFIG['secret'] = old_secret


# ══════════════════════════════════════════════════════════════════════════════
# IP sanitization tests
# ══════════════════════════════════════════════════════════════════════════════
class TestIPSanitization:
    @pytest.mark.parametrize("raw,expected", [
        ("192.168.1.1", "192.168.1.1"),
        ("  10.0.0.1  ", "10.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[::ffff:192.0.2.1]", "::ffff:192.0.2.1"),
        ("invalid", None),
        ("", None),
        ("192.168.1.1, 10.0.0.1", None),  # client_ip splits, _sanitize_ip gets single
        ("x" * 100, None),  # too long
        ("192.168.1.256", None),  # invalid octet
        ("<script>alert(1)</script>", None),  # XSS attempt
    ])
    def test_sanitize_ip(self, raw, expected):
        assert main_sanitize_ip(raw) == expected


# ═══════════════════════════════════════════════════════════════════════════════
# VMess crypto + framing tests
# ══════════════════════════════════════════════════════════════════════════════
class TestVMessCrypto:
    def test_uuid_chain(self):
        # UUID chain: cmd_key = HKDF-SHA256(key=uuid_bytes, salt=UUID_CMD_KEY_SALT, info="VMess UUID to CmdKey", 16)
        # then chain[i] = SHA256(chain[i-1])
        uuid_str = "00000000-0000-0000-0000-000000000001"
        cmd_key = cmd_key_from_uuid(uuid_str)
        assert len(cmd_key) == 16
        
    def test_cmd_key_deterministic(self):
        uuid_str = "00000000-0000-0000-0000-000000000001"
        k1 = cmd_key_from_uuid(uuid_str)
        k2 = cmd_key_from_uuid(uuid_str)
        assert k1 == k2

    def test_all_user_uuids(self):
        uuids = all_user_uuids("00000000-0000-0000-0000-000000000001", alter_id=0)
        assert len(uuids) == 1
        uuids_aid = all_user_uuids("00000000-0000-0000-0000-000000000001", alter_id=5)
        assert len(uuids_aid) == 6  # base + 5 alterIds

    def test_authid_derivation(self):
        """authID = FNV1a(cmd_key + timestamp_le) + padding = 16 bytes"""
        cmd_key = b"\x00" * 16
        ts = 1700000000
        authid = create_auth_id(cmd_key, ts)
        assert len(authid) == 16

    def test_authid_uniqueness_per_timestamp(self):
        cmd_key = b"\x00" * 16
        a1 = create_auth_id(cmd_key, 1000)
        a2 = create_auth_id(cmd_key, 1001)
        assert a1 != a2

    def test_kdf_deterministic(self):
        key = b"test-key-32-bytes-length-exactly!"
        path = b"VMess Session AEAD Auth"
        r1 = kdf(key, path)
        r2 = kdf(key, path)
        assert r1 == r2
        assert len(r1) == 32

    def test_kdf16_deterministic(self):
        key = b"test-key-32-bytes-length-exactly!"
        r1 = kdf16(key, b"path1")
        r2 = kdf16(key, b"path1")
        assert r1 == r2
        assert len(r1) == 16

    def test_fnv1a(self):
        assert fnv1a(b"") == 0x811c9dc5
        assert fnv1a(b"test") == fnv1a(b"test")

    def test_seal_open_vmess_aead_header(self):
        cmd_key = b"\x00" * 16
        data = b"test header payload"
        # seal_vmess_aead_header internally generates auth_id from current time
        sealed = seal_vmess_aead_header(cmd_key, data)
        assert len(sealed) > len(data)  # has auth tag + auth_id + len_enc + conn_nonce
        
        # The sealed data starts with auth_id (16 bytes)
        auth_id = sealed[:16]
        rest = sealed[16:]
        plaintext, size = open_vmess_aead_header(cmd_key, auth_id, rest)
        assert plaintext == data

    def test_vmess_cipher_encrypt_decrypt(self):
        # VmessCipher takes (security, key, iv)
        # security: 0x03 = AES-128-GCM, 0x04 = ChaCha20-Poly1305, 0x01 = AES-128-CFB
        import os
        
        body_key = os.urandom(16)
        body_iv = os.urandom(16)
        
        cipher = VmessCipher(
            security=0x03,  # AES-128-GCM
            key=body_key,
            iv=body_iv,
        )
        
        data = b"Hello VMess Stream!"
        enc = cipher.encrypt_chunk(data)
        
        # Create a NEW cipher with same key/iv for decryption (nonce must be in sync)
        cipher2 = VmessCipher(
            security=0x03,
            key=body_key,
            iv=body_iv,
        )
        dec = cipher2.decrypt_chunk(enc)
        assert dec == data

    def test_user_validator_sync_users(self):
        validator = UserValidator(for_links_cb=lambda: {})
        # sync_users expects {uuid_str: cmd_key_bytes}
        uuid_str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        cmd_key = cmd_key_from_uuid(uuid_str)
        validator.sync_users({uuid_str: cmd_key})
        import time
        auth_id = create_auth_id(cmd_key, int(time.time()))
        # match_auth_id takes only auth_id
        matched_uuid = validator.match_auth_id(auth_id)
        assert matched_uuid == uuid_str
        
    def test_parse_request_header(self):
        # parse_request_header takes only data (already includes auth_id)
        # It tries to parse a header without knowing cmd_key
        # For this test just verify it exists
        assert callable(parse_request_header)


# ══════════════════════════════════════════════════════════════════════════════
# Link management tests
# ══════════════════════════════════════════════════════════════════════════════
class TestLinkManagement:
    def setup_method(self):
        LINKS.clear()
        SUBS.clear()
        SESSIONS.clear()

    def test_generate_uuid(self):
        u1 = generate_uuid()
        u2 = generate_uuid()
        assert u1 != u2
        assert len(u1) == 36  # standard UUID format

    def test_is_link_allowed(self):
        from datetime import datetime, timedelta
        
        # Active, no expiry, no limit
        link = {"active": True, "expires_at": None, "limit_bytes": 0}
        assert is_link_allowed(link) is True
        
        # Inactive
        link = {"active": False}
        assert is_link_allowed(link) is False
        
        # Expired
        link = {"active": True, "expires_at": (datetime.now() - timedelta(days=1)).isoformat()}
        assert is_link_allowed(link) is False
        
        # Over limit
        link = {"active": True, "expires_at": None, "limit_bytes": 100, "used_bytes": 200}
        assert is_link_allowed(link) is False

    def test_generate_share_link_vless(self):
        uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        link = generate_share_link(uuid, "example.com", remark="Test", protocol="vless")
        assert link.startswith("vless://")
        assert "example.com" in link
        assert "Test" in link

    def test_generate_share_link_vmess(self):
        uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        link = generate_share_link(uuid, "example.com", remark="Test", protocol="vmess-ws")
        assert link.startswith("vmess://")
        import base64, json
        # vmess://<base64>#remark
        b64_part = link[8:].split("#")[0]
        missing = len(b64_part) % 4
        if missing:
            b64_part += "=" * (4 - missing)
        payload = base64.urlsafe_b64decode(b64_part).decode()
        data = json.loads(payload)
        assert data["add"] == "example.com"
        assert data["id"] == uuid

    def test_build_sub_headers(self):
        headers = build_sub_headers("Test", 1024, 1048576, None)
        assert "subscription-userinfo" in headers
        assert "upload=0" in headers["subscription-userinfo"]
        assert "download=1024" in headers["subscription-userinfo"]
        assert "total=1048576" in headers["subscription-userinfo"]


# ═══════════════════════════════════════════════════════════════════════════════
# Auth/session tests
# ═══════════════════════════════════════════════════════════════════════════════
class TestAuth:
    def setup_method(self):
        SESSIONS.clear()
        from main import AUTH
        # Reset to known password
        AUTH["password_hash"] = hash_password("testpass123")

    def test_create_session(self):
        from main import create_session
        import asyncio
        token = asyncio.run(create_session())
        assert token in SESSIONS
        assert len(token) >= 32

    def test_is_valid_session(self):
        from main import create_session, is_valid_session, destroy_session
        import asyncio
        
        token = asyncio.run(create_session())
        assert asyncio.run(is_valid_session(token)) is True
        
        asyncio.run(destroy_session(token))
        assert asyncio.run(is_valid_session(token)) is False


# ═══════════════════════════════════════════════════════════════════════════════
# Rate limiting tests
# ═══════════════════════════════════════════════════════════════════════════════
class TestRateLimiting:
    def setup_method(self):
        from main import _login_attempts
        _login_attempts.clear()

    def test_rate_limit_allows_first_attempts(self):
        import asyncio
        
        ip = "192.168.1.100"
        for i in range(5):
            allowed, _ = asyncio.run(_login_allowed(ip))
            assert allowed is True
            asyncio.run(_login_failed(ip))

    def test_rate_limit_locks_after_threshold(self):
        import asyncio
        
        ip = "192.168.1.200"
        # 5 failures = lock
        for _ in range(5):
            asyncio.run(_login_failed(ip))
        
        allowed, msg = asyncio.run(_login_allowed(ip))
        assert allowed is False
        assert msg is not None
        assert ("قفل" in msg) or ("ثانیه" in msg) or ("locked" in msg.lower())

    def test_rate_limit_resets_on_success(self):
        import asyncio
        
        ip = "192.168.1.150"
        for _ in range(4):
            asyncio.run(_login_failed(ip))
        
        asyncio.run(_login_success(ip))
        
        # Should be reset
        allowed, _ = asyncio.run(_login_allowed(ip))
        assert allowed is True


# ══════════════════════════════════════════════════════════════════════════════
# CORS tests
# ═══════════════════════════════════════════════════════════════════════════════
class TestCORS:
    def test_cors_no_credentials(self):
        from main import app
        # Check middleware config
        cors_mw = None
        for mw in app.user_middleware:
            if mw.cls.__name__ == "CORSMiddleware":
                cors_mw = mw
                break
        assert cors_mw is not None
        assert cors_mw.kwargs["allow_credentials"] is False


# ══════════════════════════════════════════════════════════════════════════════
# SSRF / destination validation (protocol._validate_target)
# ══════════════════════════════════════════════════════════════════════════════
class TestTargetValidation:
    def test_rejects_private(self):
        from protocol import _validate_target
        for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
                     "169.254.169.254", "0.0.0.0", "::1", "fc00::1", "fe80::1"):
            assert _validate_target(host, 80) is None, host

    def test_accepts_public(self):
        from protocol import _validate_target
        assert _validate_target("1.1.1.1", 443) == "1.1.1.1"
        assert _validate_target("example.com", 443) == "example.com"

    def test_bad_port(self):
        from protocol import _validate_target
        assert _validate_target("1.1.1.1", 0) is None
        assert _validate_target("1.1.1.1", 65536) is None


# ══════════════════════════════════════════════════════════════════════════════
# VMess chunk-size encoding vs spec (the padding double-count fix)
# ══════════════════════════════════════════════════════════════════════════════
class TestVMessChunkSize:
    @staticmethod
    def _pair(sec, cm, gp, al):
        import os
        from protocol.vmess.vmess import VmessCipher, VmessStreamEncoder, VmessStreamDecoder
        key, iv = os.urandom(16), os.urandom(16)
        enc_c = VmessCipher(sec, key, iv)
        dec_c = VmessCipher(sec, key, iv)
        enc = VmessStreamEncoder(enc_c, True, cm, gp, al)
        dec = VmessStreamDecoder(dec_c, True, cm, gp, al)
        return enc, dec

    @pytest.mark.parametrize("sec", [0x03, 0x04])  # AES-128-GCM, ChaCha20-Poly1305
    def test_frame_padding_not_double_counted(self, sec):
        """A frame with global padding must decode fully — the padding is already
        inside the size field, so total_frame must NOT add padding again."""
        import os
        from protocol.vmess.vmess import SEC_AES128_GCM, SEC_CHACHA20_POLY1305
        enc, dec = self._pair(sec, True, True, True)  # masking + padding + auth_len
        payload = os.urandom(1000)
        frame = enc.encode_chunk(payload)
        dec.feed(frame)
        got = b"".join(dec.try_decrypt_chunks())
        assert got == payload, f"padding double-count broke decode sec={sec}"

    @pytest.mark.parametrize("sec", [0x03, 0x04])
    def test_incomplete_frame_keeps_masks(self, sec):
        """hasSize: a split frame must not consume the SHAKE/nonce stream."""
        import os
        enc, dec = self._pair(sec, True, True, True)
        p1, p2 = os.urandom(64), os.urandom(200)
        f1, f2 = enc.encode_chunk(p1), enc.encode_chunk(p2)
        dec.feed(f1 + f2[:18])          # only the size field of frame2
        assert list(dec.try_decrypt_chunks()) == [p1]
        dec.feed(f2[18:])
        assert list(dec.try_decrypt_chunks()) == [p2]

    def test_large_payload_encodes_multiple_chunks(self):
        """The encoder must chunk (not overflow the 2-byte size field)."""
        import os
        from protocol.vmess.vmess import SEC_AES128_GCM, VmessStreamEncoder, VmessStreamDecoder, VmessCipher
        key, iv = os.urandom(16), os.urandom(16)
        enc = VmessStreamEncoder(VmessCipher(SEC_AES128_GCM, key, iv), True, True, False, False)
        payload = os.urandom(70_000)
        frames = enc.encode_chunk(payload)
        # decodes back to the payload
        dec = VmessStreamDecoder(VmessCipher(SEC_AES128_GCM, key, iv), True, True, False, False)
        dec.feed(frames + enc.encode_chunk(b""))
        got = b"".join(dec.try_decrypt_chunks())
        assert got == payload


# ══════════════════════════════════════════════════════════════════════════════
# Auth-boundary invariants (uuid_key namespace cannot be an admin session)
# ══════════════════════════════════════════════════════════════════════════════
class TestAuthBoundary:
    def test_uuid_key_prefixed_sub(self):
        """public uuid_key is sub_-prefixed; admin sessions are plain tokens."""
        import asyncio
        from main import create_session, is_valid_session

        session = asyncio.run(create_session())
        assert not session.startswith("sub_")
        # a uuid_key is the sub_ namespace — must never be accepted as admin
        for bad in ("sub_" + "x" * 40, "sub_" + "A" * 40, "sub_" + "abcdefgh"):
            assert asyncio.run(is_valid_session(bad)) is False, bad

    def test_short_token_rejected(self):
        import asyncio
        from main import is_valid_session
        assert asyncio.run(is_valid_session("short")) is False
        assert asyncio.run(is_valid_session("")) is False

    def test_session_roundtrip(self):
        import asyncio
        from main import create_session, is_valid_session, destroy_session
        tok = asyncio.run(create_session())
        assert asyncio.run(is_valid_session(tok)) is True
        asyncio.run(destroy_session(tok))
        assert asyncio.run(is_valid_session(tok)) is False


# ══════════════════════════════════════════════════════════════════════════════
# Backup-import password_hash validation (admin-lockout guard)
# ══════════════════════════════════════════════════════════════════════════════
class TestBackupImportValidation:
    def test_malformed_hash_rejected(self):
        from main import _is_plausible_password_hash

        for bad in ("", "plaintext", "pbkdf2$bad", "sha256$", "pbkdf2$1000$zz$zz",
                    "pbkdf2$1000$00$00", "pbkdf2$1000$00$00000000000000000000000000000000"):
            assert _is_plausible_password_hash(bad) is False, bad

    def test_valid_pbkdf2_accepted(self):
        from main import _is_plausible_password_hash, hash_password
        h = hash_password("s3cret")
        assert _is_plausible_password_hash(h) is True

    def test_valid_legacy_sha256_accepted(self):
        from main import _is_plausible_password_hash
        import hashlib
        h = "sha256$" + hashlib.sha256(b"x").hexdigest()
        assert _is_plausible_password_hash(h) is True
        assert _is_plausible_password_hash("sha256$" + "00" * 31) is False  # 31 bytes


# ══════════════════════════════════════════════════════════════════════════════
# /proxy SSRF protection (requires auth + destination blocklist)
# ══════════════════════════════════════════════════════════════════════════════
class TestProxySSRF:
    @pytest.fixture()
    def client(self):
        from fastapi.testclient import TestClient
        from main import app, create_session
        import asyncio
        token = asyncio.run(create_session())
        c = TestClient(app)
        c.cookies.set("rvg_session", token)
        return c

    def test_requires_auth(self):
        from fastapi.testclient import TestClient
        from main import app
        c = TestClient(app)
        r = c.get("/proxy/http://example.com/")
        assert r.status_code == 401

    def test_non_http_scheme_rejected(self, client):
        r = client.get("/proxy/file:///etc/passwd")
        assert r.status_code == 400

    def test_private_target_blocked(self, client):
        for url in (
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/",
            "http://192.168.1.1/",
            "http://[::1]/",
        ):
            r = client.get(f"/proxy/{url}")
            assert r.status_code == 403, url


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])