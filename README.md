<div align="center">

# 🛡️ RVG Gateway

**پنل مدیریت و گیتوی چندپروتکلی، سریع، ماژولار و خودکار**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-Private-red?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 🇮🇷 فارسی / 🇺🇸 English

---

## ✨ درباره‌ی پروژه / About

| 🇮🇷 فارسی | 🇺🇸 English |
|---|---|
| **RVG Gateway** یک سرویس گیتوی async و سبک‌وزنه که روی **FastAPI** ساخته شده و چند پروتکل تونل‌سازی رو به‌صورت هم‌زمان، پشت یک نقطه‌ی ورودی واحد (HTTP/WebSocket) سرو می‌کنه. طراحی پروژه کاملاً ماژولاره؛ هر پروتکل توی پکیج مستقل خودش زندگی می‌کنه و پنل مدیریتی، آپدیت خودکار و ارتباط با سرویس مرکزی هم به‌صورت جدا از هسته پیاده‌سازی شده. | **RVG Gateway** is a lightweight async gateway built on **FastAPI** that serves multiple tunneling protocols simultaneously behind a single entry point (HTTP/WebSocket). The design is fully modular — each protocol lives in its own package, and the admin panel, auto-updater, and central service integration are all decoupled from the core. |

---

## 🚀 قابلیت‌های کلیدی / Key Features

| قابلیت | Feature | توضیح / Description |
|---|---|---|
| 🔀 **چندپروتکلی** | **Multi-protocol** | پشتیبانی هم‌زمان از `VLESS`، `VMess`، `Trojan`، `Shadowsocks` و `MTProto` / Simultaneous support for `VLESS`, `VMess`, `Trojan`, `Shadowsocks`, `MTProto` on one async core |
| 🌐 **انتقال XHTTP/WebSocket** | **XHTTP/WebSocket Transport** | لایه‌ی انتقال سفارشی برای هر پروتکل جهت عبور روان از پروکسی‌ها و CDN / Custom transport layer per protocol for seamless proxy/CDN traversal |
| ⚙️ **پنل مدیریتی داخلی** | **Built-in Admin Panel** | مدیریت کاربران، وضعیت سرویس و تنظیمات از طریق `main.py` / `pages.py` / Manage users, service status, config via `main.py` / `pages.py` |
| ☁️ **اتصال به سرویس مرکزی** | **Central Service Integration** | ثبت خودکار instance، دریافت اعلان‌ها و پیام‌های پشتیبانی از طریق Cloudflare Worker (`central.py`) / Auto instance registration, notifications via Cloudflare Worker |
| 🔄 **آپدیت خودکار** | **Auto-update** | بررسی نسخه و بروزرسانی پنل از روی مانیفست JSON، به همراه تاریخچه‌ی کامل آپدیت‌ها (`updater.py`) / Version check & panel update from JSON manifest with full history |
| 🤖 **اتوماسیون دامنه/پروکسی روی Railway** | **Railway Domain/Proxy Automation** | ساخت و مدیریت خودکار TCP proxy و دامنه از طریق GraphQL API (`bottokentcpproxy.py`, `botgeneratedomin.py`) / Auto TCP proxy & domain provisioning via Railway GraphQL API |
| 🔐 **امنیت پیش‌فرض** | **Security by Default** | ذخیره‌ی امن secret/credentials، هش پسورد، و پیکربندی کامل از طریق متغیرهای محیطی / Secure secret storage, password hashing, full env-based config |

---

## 🏗️ ساختار پروژه / Project Structure

```
RVG/
├── main.py                  # هسته‌ی FastAPI، مسیرها و مدیریت WebSocket / FastAPI core, routes, WebSocket handling
├── pages.py                 # رابط کاربری پنل (HTML/JS تعبیه‌شده) / Admin panel UI (embedded HTML/JS)
├── central.py                # ارتباط با سرویس مرکزی (Cloudflare Worker) / Central service (Cloudflare Worker)
├── updater.py                # سیستم بروزرسانی خودکار + تاریخچه / Auto-updater + history
├── botgeneratedomin.py       # تولید انبوه دامنه روی Railway / Bulk domain generation on Railway
├── bottokentcpproxy.py       # ساخت خودکار TCP Proxy روی Railway / Auto TCP Proxy on Railway
├── requirements.txt
├── railway.json              # Railway deployment config
├── Dockerfile                # Docker image definition
└── protocol/
    ├── vless/                 # پیاده‌سازی کامل VLESS + XHTTP/WebSocket
    ├── vmess/                 # پیاده‌سازی کامل VMess (AEAD + Legacy) + WebSocket
    ├── trojan/                # پیاده‌سازی کامل Trojan + XHTTP/WebSocket
    ├── shadowsocks/           # پیاده‌سازی Shadowsocks + XHTTP/WebSocket
    └── mtproto/               # پیاده‌سازی MTProto
```

---

## 🧰 تکنولوژی‌ها / Tech Stack

- **FastAPI** + **Uvicorn** (`uvloop`, `httptools`) برای کارایی بالا / High-performance async
- **httpx** (با پشتیبانی HTTP/2) برای ارتباطات خارجی / External HTTP/2 calls
- **websockets** برای انتقال real-time / Real-time WebSocket transport
- **cryptography** برای عملیات رمزنگاری پروتکل‌ها / Protocol cryptography
- **aiofiles** برای I/O غیرمسدودکننده روی دیسک / Non-blocking disk I/O

---

## 📦 نصب و اجرا / Installation & Usage

### پیش‌نیازها / Prerequisites
- Python 3.11+
- pip
- (اختیاری) Railway CLI برای دیپلوی / Railway CLI for deployment

---

### روش ۱: اجرا محلی (Development) / Local Development

```bash
# کلون مخزن / Clone repo
git clone https://github.com/sofo0001/RVG.git
cd RVG

# ساخت محیط مجازی / Create venv
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# نصب وابستگی‌ها / Install deps
pip install -r requirements.txt

# تنظیم متغیرهای محیطی / Set env vars
export SECRET_KEY="your-super-secret-key"
export DATA_DIR="./data"
export ADMIN_PASSWORD="123456"  # رمز پیش‌فرض پنل / Default panel password

# اجرای سرور / Run server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

سپس در مرورگر: `http://localhost:8000` — پنل مدیریت در دسترس است.  
Open browser: `http://localhost:8000` — Admin panel available.

---

### روش ۲: دیپلوی روی Railway (Production) / Railway Deployment

RVG برای Railway بهینه‌سازی شده. فایل `railway.json` و `Dockerfile` در ریشه پروژه وجود دارد.  
RVG is optimized for Railway. `railway.json` and `Dockerfile` included.

```bash
# نصب Railway CLI / Install Railway CLI
npm i -g @railway/cli

# لاگین / Login
railway login

# ایجاد پروژه و سرویس / Init project & service
railway init
railway up
```

یا مستقیماً از GitHub / Or via GitHub UI:
1. به [Railway Dashboard](https://railway.app/dashboard) بروید / Go to Dashboard
2. **New Project** → **Deploy from GitHub repo**
3. مخزن `sofo0001/RVG` را انتخاب کنید / Select repo
4. متغیرهای محیطی را در تب **Variables** تنظیم کنید / Set env vars:

| متغیر / Variable | ضروری / Required | توضیح / Description |
|---|---|---|
| `SECRET_KEY` | ✅ بله / Yes | کلید رمزنگاری / Encryption key |
| `ADMIN_PASSWORD` | ❌ خیر / No | رمز پنل (پیش‌فرض: `123456`) / Panel password (default) |
| `DATA_DIR` | ❌ خیر / No | مسیر ذخیره داده‌ها (پیش‌فرض: `/data`) / Data dir (default) |
| `CENTRAL_URL` | ❌ خیر / No | آدرس Cloudflare Worker مرکزی / Central Worker URL |
| `UPDATE_MANIFEST_URL` | ❌ خیر / No | URL مانیفست آپدیت / Update manifest URL |

---

### روش ۳: Docker (Standalone) / Docker

```bash
# بیلد ایمیج / Build image
docker build -t rvg-gateway .

# اجرا / Run
docker run -d \
  --name rvg \
  -p 8000:8000 \
  -e SECRET_KEY="your-secret" \
  -e ADMIN_PASSWORD="123456" \
  -v $(pwd)/data:/data \
  rvg-gateway
```

---

## 🖥️ راهنمای پنل مدیریتی / Admin Panel Guide

### ورود / Login
1. آدرس پنل را باز کنید (مثال: `https://your-domain.up.railway.app` یا `http://localhost:8000`)
2. رمز پیش‌فرض: `123456` (قابل تغییر از `ADMIN_PASSWORD`)

### داشبورد / Dashboard
- **نمای کلی**: تعداد کاربران، ترافیک، اتصالات فعال
- **نمودار ترافیک**: مصرف روزانه/هفتگی

### مدیریت کاربران / User Management
| عملیات / Action | مسیر / Path | توضیح / Description |
|---|---|---|
| افزودن کاربر | دکمه `+` در نوار کناری | انتخاب پروتکل، تنظیم محدودیت، انقضا |
| ویرایش | کلیک روی ردیف کاربر | تغییر رمز، محدودیت، یادداشت |
| حذف | آیکن سطل زباله | حذف کامل کاربر و لینک‌ها |
| کپی لینک اشتراک | آیکن کپی | لینک `vless://`، `vmess://`، `trojan://`، `ss://` |

### پروتکل‌ها و تنظیمات / Protocols & Settings
| پروتکل | مسیر WS | تنظیمات مخصوص / Specific Settings |
|---|---|---|
| **VLESS** | `/vless-ws` | UUID، Flow، Encryption |
| **VMess** | `/vmess-ws` | UUID، AlterID (0=AEAD)، Cipher (auto/aes-128-gcm/chacha20-poly1305/none) |
| **Trojan** | `/trojan-ws` | Password، SNI، Fingerprint |
| **Shadowsocks** | `/ss-ws` | Method، Password، Plugin |
| **MTProto** | `/mtproto` | Secret، Domain Fronting |

### اشتراک / Subscription
- URL اشتراک: `https://your-domain/sub/{uuid}`
- پشتیبانی از: v2rayN, Clash, Shadowrocket, Sing-box, Hiddify, ...

---

## 🔗 پروتکل‌های پشتیبانی‌شده و لینک اشتراک / Supported Protocols & Share Links

| پروتکل / Protocol | مسیر WebSocket / WS Path | نمونه لینک اشتراک / Share Link Example |
|---|---|---|
| **VLESS** | `/vless-ws` | `vless://uuid@host:port?security=tls&type=ws...` |
| **VMess** | `/vmess-ws` | `vmess://base64json...` (AEAD + Legacy) |
| **Trojan** | `/trojan-ws` | `trojan://password@host:port?security=tls&type=ws...` |
| **Shadowsocks** | `/ss-ws` | `ss://method:password@host:port...` |
| **MTProto** | `/mtproto` | `tg://proxy?server=host&port=port&secret=...` |

پنل مدیریت به‌صورت خودکار لینک‌های اشتراک استاندارد (v2rayN / Clash / Shadowrocket / Sing-box / Hiddify compatible) تولید می‌کند.  
Admin panel auto-generates standard share links (v2rayN / Clash / Shadowrocket / Sing-box / Hiddify compatible).

---

## ⚙️ متغیرهای محیطی مهم / Important Environment Variables

| متغیر / Variable | پیش‌فرض / Default | توضیح / Description |
|---|---|---|
| `SECRET_KEY` | — | **اجباری / Required** — کلید امضای نشست و رمزنگاری / Session signing & encryption key |
| `ADMIN_PASSWORD` | `123456` | رمز ورود پنل / Admin panel password |
| `DATA_DIR` | `/data` | دایرکتوری ذخیره پایگاه‌داده و لاگ‌ها / DB & logs directory |
| `CENTRAL_URL` | — | آدرس Cloudflare Worker برای ثبت instance / Central Worker URL |
| `UPDATE_MANIFEST_URL` | — | URL فایل `manifest.json` برای آپدیت خودکار / Auto-update manifest URL |
| `PORT` | `8000` | پورت سرور HTTP / HTTP server port |
| `LOG_LEVEL` | `info` | سطح لاگینگ / Log level (`debug`, `info`, `warning`, `error`) |

---

## 🔐 نکات امنیتی ایران / Iran Censorship Notes

| نکته / Note | 🇮🇷 فارسی | 🇺🇸 English |
|---|---|---|
| **VMess vs VLESS** | **VMess** به دلیل رمزنگاری کامل هدر درخواست (AEAD)، مخفی‌سازی IP و DNS بهتری نسبت به VLESS ارائه می‌دهد و برای عبور از سانسور اینترنت ایران مناسب‌تر است. | **VMess** encrypts the full request header (AEAD), hiding IP/DNS better than VLESS — more suitable for bypassing Iran's DPI. |
| **AlterID = 0** | فعال‌سازی `alter_id = 0` حالت AEAD را روشن می‌کند (پیش‌فرض در RVG). | Setting `alter_id = 0` enables AEAD mode (default in RVG). |
| **TLS + SNI** | برای حداکثر مقاومت در برابر DPI، استفاده از **WebSocket + TLS** (با SNI واقعی) توصیه می‌شود. | For max DPI resistance, use **WebSocket + TLS** with a real SNI. |
| **CDN** | قرار دادن سرور پشت Cloudflare یا CDN معتبر دیگر، امضای TLS را به اشتراک می‌گذارند و شناسایی را سخت می‌کند. | Placing server behind Cloudflare or reputable CDN shares TLS fingerprint, making detection harder. |

---

<div align="center">

_بخشی از پروژه‌های [arvin341az-glitch](https://github.com/arvin341az-glitch)_ — Forked & extended by [sofo0001](https://github.com/sofo0001)

</div>