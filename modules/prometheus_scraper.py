#!/usr/bin/env python3
"""
prometheus_scraper.py — Passive Prometheus discovery from camera traffic.

When cameras are on a network that exposes Prometheus endpoints, we can
scrape metrics without authentication. This module:

  1. Checks for Prometheus on discovered gateway/subnet IPs
  2. Scrapes /api/v1/targets to find ALL monitored endpoints
  3. Extracts device names, job names, health status
  4. Queries key metrics (up, flock_device_info, etc.)

This is 100% passive recon — we're reading what Prometheus already exposes.
"""

import json
import re
import socket
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False


# ── Common Prometheus ports ──
PROMETHEUS_PORTS = [9090, 9091, 9100, 9101]

# ── Flock-specific metrics patterns ──
FLOCK_METRIC_PATTERNS = [
    "flock", "camera", "device", "alpr", "lpr",
    "temperature", "uptime", "disk_", "memory_",
    "cpu_", "network_", "wifi_", "signal",
]

# ── Interesting metric names ──
INTERESTING_METRICS = [
    "up", "flock_device_info", "flock_camera_status",
    "node_uname_info", "node_load1", "node_memory_MemTotal_bytes",
    "node_filesystem_size_bytes", "node_network_receive_bytes_total",
    "node_time_seconds", "process_start_time_seconds",
]


def probe_prometheus(host, port=9090, timeout=5):
    """
    Check if a host is running Prometheus on the given port.
    Probes /api/v1/targets (common open endpoint).

    Returns dict with targets + status, or None if not Prometheus.
    """
    if not HAVE_REQUESTS:
        return None

    try:
        r = requests.get(
            f"http://{host}:{port}/api/v1/targets",
            timeout=timeout,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return _parse_targets(data, host, port)
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass

    # Fallback: try /metrics (older Prometheus)
    try:
        r = requests.get(
            f"http://{host}:{port}/metrics",
            timeout=timeout,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        if r.status_code == 200 and b"prometheus" in r.content[:500].lower():
            return {
                "host": host,
                "port": port,
                "type": "prometheus",
                "metrics_accessible": True,
                "targets_api": False,
                "target_count": None,
                "targets": [],
                "flock_targets": 0,
            }
    except Exception:
        pass

    # Grafana fallback check
    try:
        r = requests.get(
            f"http://{host}:{port}/api/health",
            timeout=timeout,
            headers={"User-Agent": "FLOCK_scan/3.0"},
        )
        if r.status_code == 200 and "grafana" in r.text.lower():
            return {
                "host": host,
                "port": port,
                "type": "grafana",
                "metrics_accessible": True,
                "targets_api": False,
                "target_count": None,
                "targets": [],
                "flock_targets": 0,
            }
    except Exception:
        pass

    return None


def _parse_targets(data, host, port):
    """Parse Prometheus /api/v1/targets response."""
    result = {
        "host": host,
        "port": port,
        "type": "prometheus",
        "metrics_accessible": True,
        "targets_api": True,
        "target_count": 0,
        "targets": [],
        "flock_targets": 0,
    }

    active = data.get("data", {}).get("activeTargets", [])
    dropped = data.get("data", {}).get("droppedTargets", [])
    result["dropped_count"] = len(dropped)

    for target in active:
        labels = target.get("labels", {})
        discovered = target.get("discoveredLabels", {})
        scrape_url = target.get("scrapeUrl", "")
        health = target.get("health", "unknown")

        entry = {
            "job": labels.get("job", ""),
            "instance": labels.get("instance", ""),
            "module": labels.get("module", ""),
            "device": labels.get("device", ""),
            "model": labels.get("model", ""),
            "scrape_url": scrape_url,
            "health": health,
            "last_scrape": target.get("lastScrape", ""),
            "scrape_duration": target.get("lastScrapeDuration", ""),
        }

        # Extract Flock-specific info
        name_parts = " ".join(str(v) for v in entry.values()).lower()
        is_flock = any(p in name_parts for p in FLOCK_METRIC_PATTERNS)
        if is_flock:
            result["flock_targets"] += 1
            entry["flock_device"] = True

        result["targets"].append(entry)

    result["target_count"] = len(active)

    # Try /api/v1/query for key metrics
    result["metrics"] = _scrape_metrics(host, port)

    return result


def _scrape_metrics(host, port, timeout=5):
    """Query specific Prometheus metrics."""
    metrics = {}

    for metric in INTERESTING_METRICS:
        try:
            r = requests.get(
                f"http://{host}:{port}/api/v1/query",
                params={"query": metric},
                timeout=timeout,
                headers={"User-Agent": "FLOCK_scan/3.0"},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == "success":
                    results = data.get("data", {}).get("result", [])
                    if results:
                        metrics[metric] = []
                        for res in results:
                            val = res.get("value", [None, ""])
                            labels = res.get("metric", {})
                            metrics[metric].append({
                                "labels": labels,
                                "value": val[1] if len(val) > 1 else None,
                            })
        except Exception:
            pass

    return metrics if metrics else None


def scan_subnet_for_prometheus(gateway=None, local_ips=None, timeout=3):
    """
    Scan likely addresses for Prometheus instances.
    Scans: gateway, .1, .2, .254, and any known local IPs.

    Returns list of discovered Prometheus instances.
    """
    targets = set()

    if gateway:
        targets.add(gateway)
        # Scan nearby IPs
        try:
            parts = gateway.split(".")
            for last in [1, 2, 254]:
                targets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.{last}")
        except Exception:
            pass

    if local_ips:
        for ip in local_ips:
            targets.add(ip)
            try:
                parts = ip.split(".")
                for last in [1, 254]:
                    targets.add(f"{parts[0]}.{parts[1]}.{parts[2]}.{last}")
            except Exception:
                pass

    discovered = []
    for host in targets:
        for port in PROMETHEUS_PORTS:
            result = probe_prometheus(host, port=port, timeout=timeout)
            if result:
                discovered.append(result)
                break  # Don't re-check same host on other ports

    return discovered


def format_prometheus_findings(findings):
    """Format Prometheus findings for terminal display."""
    lines = []
    if not findings:
        return "  No Prometheus/Grafana instances found."

    for f in findings:
        lines.append(f"\n  \033[96m{f['type'].upper()}\033[0m at {f['host']}:{f['port']}")

        if f.get("target_count") is not None:
            lines.append(f"  Targets: {f['target_count']} ({f.get('flock_targets', 0)} Flock-related)")

        if f.get("targets"):
            # Show Flock-related targets
            flock_targets = [t for t in f["targets"] if t.get("flock_device")]
            if flock_targets:
                lines.append(f"  \033[91mFlock Devices in Prometheus:\033[0m")
                for t in flock_targets[:10]:
                    lines.append(f"    └─ {t['instance']:25} job={t['job']} \033[92m{t['health']}\033[0m")
                    if t.get("model"):
                        lines.append(f"       model={t['model']}")

            # Show key metrics
            if f.get("metrics") and len(flock_targets) > 0:
                lines.append(f"  Metrics:")
                for metric, values in f["metrics"].items():
                    lines.append(f"    {metric}: {len(values)} results")

        if f.get("dropped_count"):
            lines.append(f"  Dropped targets: {f['dropped_count']}")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
#  CLI TEST
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"

    print(f"Probing {target} for Prometheus...")
    result = probe_prometheus(target)
    if result:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("No Prometheus found.")
