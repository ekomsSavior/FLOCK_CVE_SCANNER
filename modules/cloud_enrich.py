#!/usr/bin/env python3
"""
cloud_enrich.py — IP-to-cloud-provider enrichment for FLOCK_scan

Turns hardcoded FLOCK_CLOUD_IPS into dynamic enrichment:
  - WHOIS / ASN lookup via ip-api.com or ipinfo.io (free, no key)
  - Maps IP → { org, asn, country, region, cloud_provider }
  - Cloud provider detection from ASN + org name

Usage:
    from modules.cloud_enrich import enrich_ip, enrich_ip_batch
    info = enrich_ip("52.72.49.79")
    # → {"ip": "...", "org": "Amazon Technologies", "asn": "AS16509",
    #     "country": "US", "region": "Virginia", "cloud": "AWS"}
"""

import json
import re
import socket

# ── Fallback ASN database (no network call) ────────────────────────
# Maps ASN prefixes to known cloud providers.
# Helps when ip-api.com is unavailable.

CLOUD_ASN_MAP = {
    # AWS
    "16509": "AWS", "14618": "AWS", "7224": "AWS",
    "8987": "AWS", "17493": "AWS", "39111": "AWS",
    "31763": "AWS", "38895": "AWS", "7018": "AWS",
    # GCP / Google Cloud
    "15169": "GCP", "36040": "GCP", "36384": "GCP",
    "41264": "GCP", "19448": "GCP", "26910": "GCP",
    # Azure / Microsoft
    "8075": "Azure", "12076": "Azure", "63314": "Azure",
    "13100": "Azure", "31898": "Azure", "13526": "Azure",
    # CloudFlare
    "13335": "CloudFlare", "209242": "CloudFlare",
    "14789": "CloudFlare", "203898": "CloudFlare",
    # DigitalOcean
    "14061": "DigitalOcean", "62567": "DigitalOcean",
    # OVH
    "16276": "OVH", "35540": "OVH",
    # Linode
    "63949": "Linode", "48270": "Linode",
    # Vultr
    "20473": "Vultr", "208722": "Vultr",
    # Hetzner
    "24940": "Hetzner", "213230": "Hetzner",
    # Oracle Cloud
    "31898": "Oracle", "395050": "Oracle",
    # Fastly
    "54113": "Fastly", "201737": "Fastly",
    # Akamai
    "16625": "Akamai", "12222": "Akamai", "21399": "Akamai",
    # Linode
    "63949": "Linode",
    # Scaleway
    "12876": "Scaleway",
    # UpCloud
    "202053": "UpCloud",
}

CLOUD_ORG_KEYWORDS = [
    ("amazon", "AWS"),
    ("aws", "AWS"),
    ("amazon technologies", "AWS"),
    ("amazon data services", "AWS"),
    ("amazon web services", "AWS"),
    ("amazon.com", "AWS"),
    ("elastic load balancing", "AWS"),
    ("google cloud", "GCP"),
    ("google compute", "GCP"),
    ("gcp", "GCP"),
    ("microsoft azure", "Azure"),
    ("azure", "Azure"),
    ("microsoft corporation", "Azure"),
    ("cloudflare", "CloudFlare"),
    ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"),
    ("vultr", "Vultr"),
    ("hetzner", "Hetzner"),
    ("oracle cloud", "Oracle"),
    ("oracle public cloud", "Oracle"),
    ("ovh", "OVH"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("scaleway", "Scaleway"),
    ("upcloud", "UpCloud"),
]


# ── ASN / WHOIS Lookup ──────────────────────────────────────────────

def _reverse_dns(ip, timeout=3):
    """Try to PTR the IP — sometimes reveals cloud hostname directly."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def enrich_ip(ip, timeout=5):
    """
    Look up IP enrichment data from ip-api.com (free, no API key).

    Returns dict with:
        ip, org, asn, country, region, city, cloud, reverse_dns

    Falls back gracefully if the HTTP lookup fails.
    """
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    result = {
        "ip": ip,
        "org": None,
        "asn": None,
        "country": None,
        "region": None,
        "city": None,
        "cloud": None,
        "reverse_dns": None,
    }

    # PTR first (fast, local)
    try:
        rdns = _reverse_dns(ip)
        result["reverse_dns"] = rdns
    except Exception:
        pass

    # ip-api.com — limited to 45 req/min from a single IP (free tier)
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=timeout,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result["org"] = data.get("org")
                result["asn"] = data.get("asn")
                result["country"] = data.get("country")
                result["region"] = data.get("regionName")
                result["city"] = data.get("city")
                result["isp"] = data.get("isp")

                # Determine cloud provider
                org = (result["org"] or "").lower()
                asn = result.get("asn") or ""
                result["cloud"] = _detect_cloud_provider(org, asn)
                return result
    except Exception:
        pass

    # Fallback: cli-based whois
    try:
        import subprocess
        whois_out = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=timeout
        ).stdout.lower()
        for line in whois_out.split("\n"):
            if "orgname:" in line:
                result["org"] = line.split(":", 1)[1].strip()
            if "originas:" in line or "origin:" in line:
                asn = line.split(":", 1)[1].strip().lstrip("AS")
                result["asn"] = f"AS{asn}"
            if "netname:" in line:
                if not result.get("org"):
                    result["org"] = line.split(":", 1)[1].strip()
            if "country:" in line and not result.get("country"):
                result["country"] = line.split(":", 1)[1].strip().upper()

        org = (result.get("org") or "").lower()
        asn = result.get("asn", "").replace("AS", "")
        result["cloud"] = _detect_cloud_provider(org, asn)
    except Exception:
        pass

    return result


def _detect_cloud_provider(org, asn):
    """Match org string + ASN against known cloud providers."""
    # ASN match first
    if asn and asn in CLOUD_ASN_MAP:
        return CLOUD_ASN_MAP[asn]

    # Org keyword match
    for keyword, provider in CLOUD_ORG_KEYWORDS:
        if keyword in org.lower():
            return provider

    # PTR-based: if we have a reverse DNS, check for cloud patterns
    return None


def enrich_ip_batch(ips, timeout=10):
    """
    Batch enrich multiple IPs.
    Handles ip-api.com's 45 req/min rate limit with simple sleep.
    Also uses batch endpoint for efficiency.

    Returns dict of ip -> result.
    """
    import requests
    import time

    # Try batch endpoint first (ip-api.com supports up to 100 IPs)
    try:
        r = requests.post(
            "http://ip-api.com/batch",
            json=ips[:100],  # max 100 per batch
            timeout=timeout,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        if r.status_code == 200:
            batch_data = r.json()
            results = {}
            for item in batch_data:
                ip = item.get("query")
                if not ip:
                    continue
                org = item.get("org", "")
                asn = item.get("asn", "")
                results[ip] = {
                    "ip": ip,
                    "org": org,
                    "asn": asn,
                    "country": item.get("country"),
                    "region": item.get("regionName"),
                    "city": item.get("city"),
                    "isp": item.get("isp"),
                    "cloud": _detect_cloud_provider(
                        (org or "").lower(),
                        (asn or "").replace("AS", "")
                    ),
                    "reverse_dns": _reverse_dns(ip),
                }
            return results
    except Exception:
        pass

    # Fallback: one by one
    results = {}
    for ip in ips:
        results[ip] = enrich_ip(ip, timeout=5)
        time.sleep(1.5)  # rate limit: ~40/min
    return results


# ── CLI test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "52.72.49.79"
    print(json.dumps(enrich_ip(target), indent=2, default=str))
