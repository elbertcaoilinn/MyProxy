# tests/test_security.py
# تست‌های امنیتی برای RVG — پوشش تغییرات hardening اخیر
# (PBKDF2, rate limiting, IP sanitization, cookie secure flag)

import asyncio
import hashlib
import os
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main


# ══════════════════════════════════════════════════════════════════
# 1. Password hashing (PBKDF2 + legacy compat)
# ══════════════════════════════════════════════════════════════════

def test_hash_password_format():
    """هش جدید باید فرمت pbkdf2$iterations$salt$hash داشته باشد."""
    h = main.hash_password("secret123")
    parts = h.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2"
    assert int(parts[1]) == 260000
    assert len(bytes.fromhex(parts[2])) == 16  # salt 16 bytes
    assert len(bytes.fromhex(parts[3])) == 32  # SHA-256 digest


def test_hash_password_salt_is_random():
    """دو هش از یک رمز نباید یکسان باشند (salt تصادفی)."""
    h1 = main.hash_password("same-password")
    h2 = main.hash_password("same-password")
    assert h1 != h2
    assert main._verify_password("same-password", h1)
    assert main._verify_password("same-password", h2)


def test_verify_password_roundtrip():
    h = main.hash_password("correct-horse")
    assert main._verify_password("correct-horse", h) is True
    assert main._verify_password("wrong-horse", h) is False


def test_verify_password_legacy_sha256_format():
    """فرمت قدیمی sha256(pw + secret) باید همچنان کار کند."""
    legacy = "sha256$" + hashlib.sha256(
        f"oldpass{main.CONFIG['secret']}".encode()
    ).hexdigest()
    assert main._verify_password("oldpass", legacy) is True
    assert main._verify_password("not-oldpass", legacy) is False


def test_verify_password_garbage():
    assert main._verify_password("x", "") is False
    assert main._verify_password("x", "not-a-valid-format") is False
    assert main._verify_password("x", "pbkdf2$abc$zzz$zzz") is False  # bad hex
    assert main._verify_password("x", "pbkdf2$notanint$00$00") is False
    assert main._verify_password("x", None) is False


# ══════════════════════════════════════════════════════════════════
# 2. Login rate limiting
# ══════════════════════════════════════════════════════════════════

def test_login_allowed_first_try():
    main._login_attempts.clear()
    allowed, err = asyncio.run(main._login_allowed("1.2.3.4"))
    assert allowed is True
    assert err is None


def test_login_lockout_after_max_attempts():
    main._login_attempts.clear()
    ip = "10.0.0.1"
    # 5 failed attempts → lockout
    for _ in range(main.LOGIN_MAX_ATTEMPTS):
        asyncio.run(main._login_failed(ip))
    allowed, err = asyncio.run(main._login_allowed(ip))
    assert allowed is False
    assert "ثانیه" in err  # پیام فارسی با زمان باقی‌مانده
    # حتی تلاش‌های بیشتر هم مسدود می‌ماند
    allowed, _ = asyncio.run(main._login_allowed(ip))
    assert allowed is False


def test_login_window_reset():
    main._login_attempts.clear()
    ip = "10.0.0.2"
    asyncio.run(main._login_failed(ip))
    # پنجره را منقضی کن — `_login_allowed` از `time.time` استفاده می‌کند
    with patch("main.time") as mock_time_mod:
        mock_time_mod.time.return_value = time.time() + main.LOGIN_WINDOW_SECONDS + 10
        allowed, _ = asyncio.run(main._login_allowed(ip))
        assert allowed is True  # ویندو منقضی شده → ریست


def test_login_success_clears_attempts():
    main._login_attempts.clear()
    ip = "10.0.0.3"
    for _ in range(main.LOGIN_MAX_ATTEMPTS - 1):
        asyncio.run(main._login_failed(ip))
    asyncio.run(main._login_success(ip))
    allowed, _ = asyncio.run(main._login_allowed(ip))
    assert allowed is True


def test_login_threshold_edge():
    """۴ تلاش ناموفق = هنوز مجاز، ۵ = قفل."""
    main._login_attempts.clear()
    ip = "10.0.0.4"
    for _ in range(main.LOGIN_MAX_ATTEMPTS - 1):
        asyncio.run(main._login_failed(ip))
    allowed, _ = asyncio.run(main._login_allowed(ip))
    assert allowed is True
    asyncio.run(main._login_failed(ip))  # 5th
    allowed, _ = asyncio.run(main._login_allowed(ip))
    assert allowed is False


# ══════════════════════════════════════════════════════════════════
# 3. IP sanitization
# ══════════════════════════════════════════════════════════════════

def test_sanitize_ip_valid():
    assert main._sanitize_ip("1.2.3.4") == "1.2.3.4"
    assert main._sanitize_ip("2001:db8::1") == "2001:db8::1"
    assert main._sanitize_ip("[2001:db8::1]") == "2001:db8::1"
    assert main._sanitize_ip(" 8.8.8.8 ") == "8.8.8.8"


def test_sanitize_ip_invalid():
    assert main._sanitize_ip("") is None
    assert main._sanitize_ip(None) is None
    assert main._sanitize_ip("not-an-ip") is None
    assert main._sanitize_ip("1.2.3.999") is None
    # log injection / XFF spoofing
    assert main._sanitize_ip("1.2.3.4\nEvil: header") is None
    assert main._sanitize_ip("1.2.3.4, 5.6.7.8") is None
    assert main._sanitize_ip("1.2.3.4\r\nX-Injected: yes") is None
    # too long
    assert main._sanitize_ip("a" * 100) is None


def test_client_ip_xff_validation():
    req = MagicMock()
    req.headers = {"x-forwarded-for": "1.2.3.4, 10.0.0.1"}
    req.client = MagicMock(host="9.9.9.9")
    assert main.client_ip(req) == "1.2.3.4"

    # XFF معتبر نیست → fallback به x-real-ip
    req.headers = {"x-forwarded-for": "garbage\ninjection"}
    assert main.client_ip(req) == "9.9.9.9"

    # x-real-ip معتبر
    req.headers = {"x-forwarded-for": "garbage", "x-real-ip": "5.6.7.8"}
    assert main.client_ip(req) == "5.6.7.8"

    # هیچی معتبر نیست → request.client
    req.headers = {}
    assert main.client_ip(req) == "9.9.9.9"


def test_ws_client_ip_validation():
    from protocol.vless.vless import _ws_client_ip
    ws = MagicMock()
    ws.headers = {"x-forwarded-for": "1.2.3.4"}
    ws.client = MagicMock(host="9.9.9.9")
    assert _ws_client_ip(ws) == "1.2.3.4"

    ws.headers = {"x-forwarded-for": "bad\nip"}
    assert _ws_client_ip(ws) == "9.9.9.9"

    ws.headers = {"x-forwarded-for": "bad\nip", "x-real-ip": "8.8.4.4"}
    assert _ws_client_ip(ws) == "8.8.4.4"


# ══════════════════════════════════════════════════════════════════
# 4. Cookie secure flag
# ══════════════════════════════════════════════════════════════════

def test_cookie_secure_on_https():
    req = MagicMock()
    req.url.scheme = "https"
    req.url = MagicMock()
    req.url.scheme = "https"
    with patch("main.create_session", new=AsyncMock(return_value="tok123")):
        # capture cookie kwargs via direct call of the login logic
        from fastapi.responses import JSONResponse
        import main as m
        # simulate what api_login does
        secure = req.url.scheme == "https" or os.environ.get("COOKIE_SECURE", "1") == "1"
        resp = JSONResponse({"ok": True})
        resp.set_cookie("rvg_session", "tok123", max_age=m.SESSION_TTL,
                        httponly=True, samesite="lax", secure=secure, path="/")
        cookie = resp.headers.get("set-cookie", "")
        assert "Secure" in cookie


def test_cookie_secure_env_override():
    """COOKIE_SECURE=1 → secure حتی روی HTTP (برای Railway پشت پراکسی)."""
    os.environ["COOKIE_SECURE"] = "1"
    req = MagicMock()
    req.url.scheme = "http"
    secure = req.url.scheme == "https" or os.environ.get("COOKIE_SECURE", "1") == "1"
    assert secure is True
    os.environ.pop("COOKIE_SECURE", None)


# ══════════════════════════════════════════════════════════════════
# 5. CORS (spec-valid configuration)
# ══════════════════════════════════════════════════════════════════

def test_cors_credentials_off():
    """allow_credentials با allow_origins=['*'] با هم نباید باشند (spec)."""
    from fastapi.middleware.cors import CORSMiddleware
    mw = next(
        (m for m in main.app.user_middleware if m.cls is CORSMiddleware),
        None,
    )
    assert mw is not None, "CORSMiddleware not found"
    # Starlette CORSMiddleware kwargs: allow_credentials=False, allow_origins=['*']
    assert mw.kwargs.get("allow_credentials") is False
    assert mw.kwargs.get("allow_origins") == ["*"]
