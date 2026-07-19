#!/usr/bin/env python3
"""
banner_grabber.py — HTTP/FTP/TLS/SSH banner collection for FLOCK_scan

Grabs what scanner.py's _http_get() leaves on the floor:
  - HTTP response headers (Server, X-Powered-By, Via, etc.)
  - FTP banner on port 21 (SpeedPourer version detection)
  - TLS certificate details (SANs, issuer, expiry, serial)
  - SSH version string (port 22)

Usage:
    from modules.banner_grabber import grab_all_banners
    banners = grab_all_banners(host, timeout=5)
"""

import socket
import ssl
import re
import json
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


# ── 1. HTTP Response Headers + Body ──────────────────────────────────

def http_banner_grab(host, port=80, timeout=5, use_https=False):
    """
    Full HTTP(S) GET — returns status code, headers dict, cookies, and
    truncated body so we can feed them to telemetry/banner analysis.

    Returns dict or None.
    """
    scheme = "https" if use_https or port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"

    if not HAVE_REQUESTS:
        return _http_banner_socket(host, port, timeout, use_https)

    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            headers={"User-Agent": "FLOCK_scan/3.0"},
            allow_redirects=False,
        )
        return {
            "status": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:5000],
            "cookies": r.cookies.get_dict(),
            "url": url,
        }
    except Exception:
        return None


def _http_banner_socket(host, port, timeout, use_https):
    """Fallback raw-socket HTTP GET for environments without requests."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if use_https or port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        req = (
            f"GET / HTTP/1.0\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: FLOCK_scan/3.0\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.send(req.encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()

        # Split headers / body
        raw = resp.decode(errors="replace")
        if "\r\n\r\n" in raw:
            header_text, body = raw.split("\r\n\r\n", 1)
        elif "\n\n" in raw:
            header_text, body = raw.split("\n\n", 1)
        else:
            header_text = raw
            body = ""

        headers = {}
        status = 0
        for line in header_text.split("\r\n"):
            if line.startswith("HTTP/"):
                try:
                    status = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        return {
            "status": status,
            "headers": headers,
            "body": body[:5000],
            "cookies": {},
            "url": f"{'https' if use_https else 'http'}://{host}:{port}/",
        }
    except Exception:
        return None


def http_extract_interesting(headers):
    """
    From a headers dict, pull out the banner-level intel we care about.
    Returns a flat dict with keys: server, powered_by, aspnet_version,
    cloud_proxy, backend_cookie.
    """
    h = {k.lower(): v for k, v in headers.items()}
    info = {}

    if "server" in h:
        info["server"] = h["server"]
    if "x-powered-by" in h:
        info["powered_by"] = h["x-powered-by"]
    if "x-aspnet-version" in h:
        info["aspnet_version"] = h["x-aspnet-version"]

    # Cloud proxy detection
    via = h.get("via", "")
    if "cloudfront" in via.lower():
        info["cloud_proxy"] = "CloudFront"
    elif "akamai" in via.lower():
        info["cloud_proxy"] = "Akamai"
    elif "cloudflare" in via.lower():
        info["cloud_proxy"] = "CloudFlare"
    elif via:
        info["cloud_proxy"] = via[:64]

    x_cache = h.get("x-cache", "")
    if x_cache and "cloud_proxy" not in info:
        info["cloud_proxy_hint"] = x_cache[:64]

    # CSP / HSTS
    if "strict-transport-security" in h:
        info["hsts"] = "yes"
    if "content-security-policy" in h:
        csp = h["content-security-policy"]
        info["csp_report_uri"] = _extract_csp_report_uri(csp)

    # Backend fingerprint via Set-Cookie
    for cname in h.get("set-cookie", "").split(";"):
        cname = cname.strip().split("=")[0]
        if cname in ("PHPSESSID", "JSESSIONID", "connect.sid",
                     "ASP.NET_SessionId", "PLAY_FLASH", "laravel_session",
                     "symfony", "rack.session"):
            info["backend_cookie"] = cname
            break

    # Cloud headers
    for cloud_key in ("x-amz-request-id", "x-amz-id-2",
                      "x-amz-cf-id", "x-amz-cf-pop",
                      "x-azure-ref",
                      "x-guploader-uploadid",
                      "x-sucuri-id", "x-sucuri-cache",
                      "cf-ray", "cf-cache-status"):
        if cloud_key in h:
            info[cloud_key] = h[cloud_key]

    return info


def _extract_csp_report_uri(csp):
    m = re.search(r'report-uri\s+([^\s;]+)', csp)
    if m:
        return m.group(1)
    m = re.search(r'report-to\s+([^\s;]+)', csp)
    if m:
        return m.group(1)
    return None


# ── 2. FTP Banner Grab ──────────────────────────────────────────────

def ftp_banner_grab(host, port=21, timeout=5):
    """
    Connect to FTP port, grab the welcome banner.
    SpeedPourer cameras advertise themselves here.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="replace").strip()
        s.close()

        result = {
            "port": port,
            "banner": banner,
            "is_speedpourer": "speedpourer" in banner.lower(),
        }

        # Extract version if present
        m = re.search(r'v?(\d+\.\d+[\.\d]*)', banner)
        if m:
            result["version"] = m.group(1)

        return result
    except socket.timeout:
        return None
    except ConnectionRefusedError:
        return None
    except Exception:
        return None


def ftp_anonymous_login(host, port=21, timeout=5):
    """
    Test if FTP allows anonymous login (common on misconfigured SpeedPourer).
    Returns True/False.
    """
    try:
        from ftplib import FTP
        ftp = FTP()
        ftp.connect(host, port, timeout=timeout)
        resp = ftp.login("anonymous", "flock_scan@test.com")
        ftp.quit()
        return "230" in str(resp)
    except Exception:
        return False


# ── 3. TLS Certificate Details ──────────────────────────────────────

def tls_cert_grab(host, port=443, timeout=5):
    """
    Connect and extract the full TLS certificate.
    Returns SANs, issuer, subject, validity window, serial.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                der = ssock.getpeercert(binary_form=True)

        if not cert:
            return None

        # SANs
        sans = []
        for ext_type, val in cert.get("subjectAltName", []):
            if ext_type == "DNS":
                sans.append(val)

        # Subject
        subject = dict(cert.get("subject", []))
        issuer = dict(cert.get("issuer", []))

        # Serial
        serial = cert.get("serialNumber", None)

        # Validity
        nb = cert.get("notBefore", "")
        na = cert.get("notAfter", "")

        # SHA-256 fingerprint
        from hashlib import sha256
        fingerprint = sha256(der).hexdigest()

        return {
            "subject": {k: v for k, v in subject.items()},
            "issuer": {k: v for k, v in issuer.items()},
            "sans": sans,
            "serial_number": serial,
            "not_before": nb,
            "not_after": na,
            "sha256_fingerprint": fingerprint,
            "days_until_expiry": _days_between(datetime.now(), na) if na else None,
        }
    except Exception:
        return None


def _days_between(d1, d2_str):
    """Parse an ASN.1 time string and return days between now and it."""
    try:
        d2 = datetime.strptime(d2_str.replace("Z", ""), "%Y%m%d%H%M%S")
        delta = (d2 - d1).days
        return delta
    except Exception:
        return None


# ── 4. SSH Version String ───────────────────────────────────────────

def ssh_banner_grab(host, port=22, timeout=5):
    """
    Grab SSH protocol version string. Can identify OS / SSH server version.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(256).decode(errors="replace").strip()
        s.close()
        return {
            "port": port,
            "banner": banner,
            "ssh_version": banner.split("-")[-1] if "-" in banner else None,
        }
    except Exception:
        return None


# ── 5. HTTP OPTIONS / TRACE ─────────────────────────────────────────

def http_options_scan(host, port=80, timeout=5, use_https=False):
    """
    Send HTTP OPTIONS to discover allowed methods.
    PUT, DELETE, or PATCH exposed = interesting.
    """
    scheme = "https" if use_https or port == 443 else "http"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)

        if use_https or port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)

        s.connect((host, port))
        req = (
            f"OPTIONS / HTTP/1.0\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: FLOCK_scan/3.0\r\n\r\n"
        )
        s.send(req.encode())
        resp = s.recv(4096).decode(errors="replace")
        s.close()

        allow = None
        for line in resp.split("\r\n"):
            if line.lower().startswith("allow:"):
                allow = line.split(":", 1)[1].strip()
                break

        return {"allow": allow, "methods": allow.split(", ") if allow else []}
    except Exception:
        return None


# ── Orchestrator ─────────────────────────────────────────────────────

def grab_all_banners(host, timeout=5):
    """
    Run all banner checks on a host. Returns a dict with results per service.
    """
    results = {}

    # HTTP/HTTPS
    for port, https in [(80, False), (443, True)]:
        http_res = http_banner_grab(host, port=port, timeout=timeout, use_https=https)
        if http_res:
            results[f"http_{port}"] = {
                "url": http_res["url"],
                "status": http_res["status"],
                "headers": http_res["headers"],
                "interesting": http_extract_interesting(http_res["headers"]),
                "body_preview": http_res["body"][:500],
                "cookies": http_res["cookies"],
            }

        # OPTIONS scan
        opts = http_options_scan(host, port=port, timeout=timeout, use_https=https)
        if opts and opts.get("methods"):
            results[f"options_{port}"] = opts

    # FTP
    ftp = ftp_banner_grab(host, timeout=timeout)
    if ftp:
        results["ftp_21"] = ftp
        anon = ftp_anonymous_login(host, timeout=timeout)
        if anon:
            results["ftp_21"]["anonymous_login"] = True

    # TLS cert (always try 443)
    tls = tls_cert_grab(host, timeout=timeout)
    if tls:
        results["tls_443"] = tls

    # SSH
    ssh = ssh_banner_grab(host, timeout=timeout)
    if ssh:
        results["ssh_22"] = ssh

    return results


# ── CLI test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(json.dumps(grab_all_banners(target), indent=2, default=str))
