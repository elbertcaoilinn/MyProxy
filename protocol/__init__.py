# protocol/__init__.py
# توابع مشترک برای همه پروتکل‌ها

import ipaddress


def _sanitize_ip(raw: str) -> str | None:
    """اعتبارسنجی آدرس IP — جلوگیری از log injection و XFF جعلی."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 64:
        return None
    if raw.startswith("[") and raw.endswith("]"):  # IPv6 bracket form
        raw = raw[1:-1]
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        return None


def _is_private_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """آیا IP در محدوده‌های غیرعمومی (SSRF/rebind) قرار دارد.

    عمداً permissive تر از ip.is_private است:
      - 127.0.0.0/8 (loopback — همه‌ی بازه، نه فقط 127.0.0.1)
      - ::1 (IPv6 loopback) و 0:0:0:0:0:ffff:0:0/96 (IPv4-mapped — دور زدن کلاسیک)
      - 10/8، 172.16/12، 192.168/16 (RFC1918)
      - 169.254.0.0/16 (link-local — شامل 169.254.169.254 metadata ابر)
      - fe80::/10 (IPv6 link-local)
      - fc00::/7 (ULA/مشخص) — این‌ها routable نیستند
      - 0.0.0.0/8 و 0::/128 (address zero)
    """
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and ip.sixtofour is not None)
        or (isinstance(ip, ipaddress.IPv6Address) and (ip in ipaddress.ip_network("fc00::/7")))
    )


async def _read_first_chunk(request) -> tuple[bytes, bool]:
    """خواندن اولین chunk درخواست بدون مصرف کامل stream.

    starlette.Rquest.stream() اجازه‌ی فراخوانی مجدد نمی‌دهد؛ این تابع اولین
    message را با receive() خام می‌گیرد تا بعداً بشود stream() را برای ادامه
    صدا زد (برای الگوی «اولین chunk را برای dial بخوان، بقیه را زیر lock فرست»).
    Returns:
        (chunk_bytes, ok) — ok=False یعنی کلاینت قطع شد یا بدنه خالی بود.
    """
    try:
        message = await request._receive()
    except Exception:
        return b"", False
    if message.get("type") == "http.disconnect":
        return b"", False
    return message.get("body", b""), True


def _validate_target(host: str, port: int, *, resolve: bool = True) -> str | None:
    """بررسی مقصد قبل از dial — جلوگیری از SSRF به شبکه داخلی.

    موافق است با (host, port) خام از هدر پروتکل (VLESS/VMess/Trojan/SS).
    host می‌تواند آدرس IP یافت‌شده یا hostname باشد؛ resolve به‌صورت پیش‌فرض
    فعال است تا تمام آدرس‌های یک hostname (شامل DNS-rebinding) چک شوند.

    Returns:
        cleaned host (بازگشت برای log) یا None اگر مقصد مجاز نباشد.
    """
    if not host:
        return None
    host = host.strip()
    if not host or len(host) > 253:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    if not (1 <= port <= 65535):
        return None

    try:
        ips = [ipaddress.ip_address(host)] if resolve is False else []
    except ValueError:
        ips = []

    # hostمستقیم IP است
    if ips:
        for ip in ips:
            if _is_private_address(ip):
                return None
        return host
    else:
        # hostname → حل می‌کنیم و همه آدرس‌ها را چک می‌کنیم
        import socket
        try:
            addrinfo = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except Exception:
            return None
        for entry in addrinfo:
            try:
                ip = ipaddress.ip_address(entry[4][0])
            except ValueError:
                continue
            if _is_private_address(ip):
                return None
        return host