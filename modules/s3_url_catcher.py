#!/usr/bin/env python3
"""
s3_url_catcher.py — Extract signed S3 URLs from captured camera traffic.

When cameras send alert webhooks or the admin UI loads images, we can
capture signed S3 URLs from the traffic. These URLs have expiry windows
(typically 7 days for Flock alert images) and give us:

  - LPR capture images (license plates)
  - Camera snapshots
  - Evidence of deployment locations

This module processes captured HTTP payloads (from tap mode, PCAP, or
HTTP response bodies) and extracts:

  - flock-hibiki-inbox.s3.amazonaws.com URLs
  - Generic S3 signed URLs
  - hotspot/flocksafety.com image URLs
  - Metadata: timestamp, device, organization
"""

import re
import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs


# ── S3 and Flock image URL patterns ──

S3_SIGNED_URL = re.compile(
    r'https?://[a-zA-Z0-9.-]*flock-hibiki-inbox[a-zA-Z0-9.-]*\.s3\.amazonaws\.com/[^"\'\s<>]+',
    re.I
)

S3_GENERIC = re.compile(
    r'https?://[a-zA-Z0-9._-]+\.s3\.amazonaws\.com/[^"\'\s<>]+',
    re.I
)

FLOCK_IMAGE_URL = re.compile(
    r'https?://[a-zA-Z0-9._-]*flocksafety\.com/[^"\'\s<>]*\.(?:jpg|jpeg|png|gif|webp)[^"\'\s<>]*',
    re.I
)

FLOCK_DETAILS_URL = re.compile(
    r'https?://hotlist\.flocksafety\.com/[^"\'\s<>]+',
    re.I
)

# S3 URL with X-Amz-Signature = signed
SIGNED_URL_PATTERN = re.compile(
    r'https?://[^"\'\s<>]+\?X-Amz-Signature=[a-f0-9]{64}[^"\'\s<>]*',
    re.I
)

# Image URL from JSON payloads (like webhook bodies)
JSON_IMAGE_URL = re.compile(
    r'"(?:imageUrl|image_url|url|preview|thumbnail)"\s*:\s*"(https?://[^"]+\.(?:jpg|jpeg|png))"',
    re.I
)


def extract_s3_urls(data, source="unknown"):
    """
    Extract all S3/flock image URLs from a text body (HTTP response,
    PCAP payload, etc.).

    Returns list of dicts with url, type, expiry_info, source.
    """
    results = []

    if not data:
        return results

    seen_urls = set()

    # 1. Flock hibiki-inbox S3 (known camera image bucket)
    for m in S3_SIGNED_URL.finditer(data):
        url = m.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        info = {
            "url": url,
            "type": "FLOCK_S3_IMAGE",
            "bucket": "flock-hibiki-inbox",
            "source": source,
            "signed": "X-Amz-Signature" in url,
            "expiry": extract_expiry(url),
        }
        results.append(info)

    # 2. Other S3 buckets
    for m in S3_GENERIC.finditer(data):
        url = m.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        bucket = urlparse(url).hostname.split(".")[0] if urlparse(url).hostname else "unknown"

        info = {
            "url": url,
            "type": "S3_GENERIC",
            "bucket": bucket,
            "source": source,
            "signed": "X-Amz-Signature" in url,
            "expiry": extract_expiry(url),
        }
        results.append(info)

    # 3. Signed URLs (non-S3 but with X-Amz-Signature)
    for m in SIGNED_URL_PATTERN.finditer(data):
        url = m.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        info = {
            "url": url,
            "type": "SIGNED_URL",
            "bucket": urlparse(url).hostname if urlparse(url).hostname else "unknown",
            "source": source,
            "signed": True,
            "expiry": extract_expiry(url),
        }
        results.append(info)

    # 4. Flock hotlist/capture URLs
    for m in FLOCK_IMAGE_URL.finditer(data):
        url = m.group(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        info = {
            "url": url,
            "type": "FLOCK_HOTLIST_IMAGE",
            "source": source,
            "signed": False,
        }
        results.append(info)

    return results


def extract_expiry(url):
    """Extract X-Amz-Expires or Expires parameter from a signed URL."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if "X-Amz-Expires" in params:
            expires_seconds = int(params["X-Amz-Expires"][0])
            return f"{expires_seconds}s ({expires_seconds//3600}h)"

        if "Expires" in params:
            return params["Expires"][0]

        # Check for ISO expiry in URL
        m = re.search(r'imageExpiration["\']\s*:\s*["\']([^"\']+)["\']', url)
        if m:
            return m.group(1)

    except Exception:
        pass
    return None


def extract_from_webhook_payload(body, source="unknown"):
    """
    Parse a Flock webhook JSON payload for image URLs and metadata.
    Returns structured data with device info and S3 URLs.
    """
    results = []
    try:
        payload = json.loads(body) if isinstance(body, str) else body
    except json.JSONDecodeError:
        return results

    if not isinstance(payload, dict):
        return results

    # Extract image URL
    image_url = payload.get("imageUrl")
    if image_url:
        results.append({
            "url": image_url,
            "type": "WEBHOOK_IMAGE",
            "source": source,
            "signed": "X-Amz-Signature" in image_url,
            "expiry": payload.get("imageExpiration"),
            "metadata": {
                "device_name": payload.get("deviceName"),
                "device_id": payload.get("deviceExternalId"),
                "plate": payload.get("ocr", {}).get("label"),
                "state": payload.get("ocr", {}).get("state"),
                "timestamp": payload.get("eventTime"),
                "latitude": payload.get("deviceLat"),
                "longitude": payload.get("deviceLong"),
                "network": payload.get("networkName"),
                "details_url": payload.get("detailsUrl"),
            },
        })

    # Details URL
    details = payload.get("detailsUrl")
    if details:
        results.append({
            "url": details,
            "type": "WEBHOOK_DETAILS",
            "source": source,
            "metadata": {"plate": payload.get("ocr", {}).get("label")},
        })

    return results


def scan_traffic_for_s3(http_responses=None, pcap_payloads=None, output_file=None):
    """
    Scan captured HTTP responses and raw PCAP payloads for S3 URLs.

    http_responses: list of {url, body, headers, source}
    pcap_payloads: list of raw strings from traffic tap

    Returns deduplicated S3 findings.
    """
    all_urls = []
    seen = set()

    if http_responses:
        for resp in http_responses:
            body = resp.get("body", "")
            source = resp.get("source", resp.get("url", "unknown"))

            # Extract from body
            for url_info in extract_s3_urls(body, source=source):
                key = url_info["url"]
                if key not in seen:
                    seen.add(key)
                    all_urls.append(url_info)

            # Try webhook JSON parsing
            for wh_info in extract_from_webhook_payload(body, source=source):
                key = wh_info["url"]
                if key not in seen:
                    seen.add(key)
                    all_urls.append(wh_info)

    if pcap_payloads:
        for payload in pcap_payloads:
            if isinstance(payload, str):
                source_data = "pcap_raw"
                for url_info in extract_s3_urls(payload, source=source_data):
                    key = url_info["url"]
                    if key not in seen:
                        seen.add(key)
                        all_urls.append(url_info)

    # Write to output file
    if output_file and all_urls:
        write_s3_report(all_urls, output_file)

    return all_urls


def write_s3_report(urls, output_path):
    """Write S3 URL findings to a file."""
    timestamp = datetime.now().isoformat()

    with open(output_path, "w") as f:
        f.write("╔══════════════════════════════════════════════════════════════╗\n")
        f.write("║        FLOCK_scan — Captured S3 Image URLs                 ║\n")
        f.write(f"║  Generated: {timestamp}                    ║\n")
        f.write("╚══════════════════════════════════════════════════════════════╝\n\n")

        if not urls:
            f.write("No S3 URLs found.\n")
            return 0

        f.write(f"Total unique URLs: {len(urls)}\n\n")

        # Group by type
        for url_info in urls:
            f.write(f"{'─' * 70}\n")
            f.write(f"  {url_info['type']}\n")
            f.write(f"  URL:  {url_info['url']}\n")
            if url_info.get("expiry"):
                f.write(f"  Exp:  {url_info['expiry']}\n")
            if url_info.get("bucket"):
                f.write(f"  Buck: {url_info['bucket']}\n")
            if url_info.get("source"):
                f.write(f"  From: {url_info['source']}\n")

            meta = url_info.get("metadata")
            if meta:
                plate = meta.get("plate")
                if plate:
                    f.write(f"  Plate: {plate}\n")
                dev = meta.get("device_name")
                if dev:
                    f.write(f"  Cam:   {dev}\n")
                loc = meta.get("latitude")
                if loc:
                    f.write(f"  GPS:   {loc}, {meta.get('longitude')}\n")
                ts = meta.get("timestamp")
                if ts:
                    f.write(f"  Time:  {ts}\n")
            f.write("\n")

        f.write(f"{'═' * 70}\n")
        f.write(f"Total: {len(urls)} S3 URLs captured\n")

    return len(urls)


def format_s3_findings_terminal(urls):
    """Format S3 URL findings for terminal display."""
    lines = []
    if not urls:
        return "  No S3 URLs captured."

    lines.append(f"  \033[93m{len(urls)} S3/image URLs captured:\033[0m")

    for u in urls[:15]:  # Show max 15
        url_short = u["url"][:100]
        expiry = u.get("expiry", "")
        plate = u.get("metadata", {}).get("plate", "")

        icon = "\033[91m[S3_IMG]\033[0m" if u["type"] == "WEBHOOK_IMAGE" else "\033[94m[URL]\033[0m"
        line = f"  {icon} {url_short}"

        if expiry:
            line += f" \033[90m(exp: {expiry})\033[0m"
        if plate:
            line += f" \033[93m[{plate}]\033[0m"

        lines.append(line)

    if len(urls) > 15:
        lines.append(f"  \033[90m... and {len(urls) - 15} more\033[0m")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  CLI TEST
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sample_webhook = json.dumps({
        "deviceLat": 33.045,
        "deviceLong": -80.106,
        "deviceName": "LR#007 College Park Rd @ N Main St NB",
        "deviceExternalId": "949692b4-3110-413e-a93c-52fbc5a9885a",
        "imageUrl": "https://flock-hibiki-inbox.s3.us-east-1.amazonaws.com/policy/ORG/raw/CAPTURE.jpg?X-Amz-Signature=abc123&X-Amz-Expires=604800",
        "imageExpiration": "2025-03-19T14:59:16Z",
        "detailsUrl": "https://hotlist.flocksafety.com/img/tar-TOKEN",
        "ocr": {"label": "ABC123", "state": "south_carolina"},
        "eventTime": "2025-03-12T14:59:05.000Z",
    })

    urls = scan_traffic_for_s3(
        http_responses=[{"body": sample_webhook, "source": "webhook_test"}]
    )
    print(format_s3_findings_terminal(urls))
