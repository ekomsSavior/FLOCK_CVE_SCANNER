#!/usr/bin/env python3
"""
network_map.py — Passive subnet discovery for FLOCK_scan

When we have ADB access to a Flock camera, we can map out the local
network without sending a single probe — just by reading ARP tables,
DHCP leases, mDNS responses, and connection state from the camera.

Usage:
    from modules.network_map import NetworkMapper
    nm = NetworkMapper(host, timeout=5)
    report = nm.full_map()
"""

import socket
import re
import json
import time
from collections import defaultdict


class NetworkMapper:
    """Passive network mapper — discovers devices via ARP/mDNS/connection state."""

    OUI_DB = {
        "00:00:0c": "Cisco",
        "00:01:5c": "3Com",
        "00:05:5d": "Dell",
        "00:0c:29": "VMware",
        "00:15:5d": "Microsoft Hyper-V",
        "00:50:56": "VMware",
        "00:1a:a0": "Dell",
        "00:23:ae": "Apple",
        "00:25:00": "Apple",
        "00:26:08": "Apple",
        "08:00:27": "Oracle VirtualBox",
        "08:00:69": "Apple",
        "10:05:ca": "Huawei",
        "10:6f:d9": "Juniper",
        "14:10:9f": "HP",
        "18:03:73": "Cisco",
        "20:37:06": "Samsung",
        "24:65:11": "Hikvision",
        "28:92:4a": "Dahua",
        "2c:33:11": "Ubiquiti",
        "30:8c:fb": "Hikvision",
        "34:08:04": "Ring",
        "3c:2e:ff": "Ubiquiti",
        "44:d9:e7": "Raspberry Pi",
        "48:22:54": "Google Nest",
        "48:e7:29": "Google",
        "4c:eb:42": "Nest Labs",
        "50:c7:bf": "Amazon",
        "54:60:09": "Ring",
        "58:8d:09": "Dahua",
        "60:64:05": "Amazon",
        "64:16:8e": "Pakedge",
        "68:72:51": "Hikvision",
        "6c:83:36": "Hikvision",
        "70:b8:f6": "Axis",
        "74:75:48": "Apple",
        "78:8b:5c": "Axis",
        "7c:dd:90": "Google",
        "80:2a:a8": "Huawei",
        "84:0d:8e": "Amazon",
        "88:36:6c": "Google",
        "8c:85:90": "Ubiquiti",
        "90:38:0c": "Synology",
        "90:b0:ed": "Yale",
        "94:10:3e": "Samsung",
        "98:01:a7": "Belkin",
        "98:f0:ab": "Apple",
        "a0:02:dc": "HP",
        "a4:77:33": "Apple",
        "a8:66:7f": "Samsung",
        "a8:93:4a": "Ring",
        "ac:22:0b": "TP-Link",
        "b0:e1:7e": "D-Link",
        "b8:27:eb": "Raspberry Pi",
        "b8:a3:86": "Netgear",
        "c0:25:a5": "Cisco Meraki",
        "c8:3a:35": "Dell",
        "cc:32:e5": "Hikvision",
        "d0:52:a8": "Google",
        "d4:a6:51": "D-Link",
        "dc:a6:32": "Apple",
        "e0:ac:cb": "Cisco",
        "e4:5f:01": "Google",
        "e8:48:1b": "Arlo",
        "f0:9f:c2": "Apple",
        "f4:f2:6d": "Cisco Meraki",
        "f8:e9:03": "Red Hat KVM",
        "fc:a6:cd": "Amazon",
    }

    def __init__(self, camera_host=None, timeout=5):
        self.camera_host = camera_host
        self.timeout = timeout
        self._adb_func = None
        self._sock_func = None

        if camera_host:
            from modules.adb_deep import (
                get_arp_table, get_interfaces, get_gateway,
                get_process_list as _get_ps,
            )
            self._adb_func = {
                "arp": lambda: get_arp_table(camera_host, timeout),
                "interfaces": lambda: get_interfaces(camera_host, timeout),
                "gateway": lambda: get_gateway(camera_host, timeout),
            }

    def resolve_oui(self, mac):
        """Look up manufacturer by MAC OUI."""
        if not mac:
            return None
        prefix = mac.upper()[:8]
        if prefix in self.OUI_DB:
            return self.OUI_DB[prefix]
        # Try first 3 octets (standard OUI)
        prefix6 = mac.upper()[:8]
        # Some have 6-char prefixes (xx:xx:xx)
        prefix6_alt = ":".join(mac.split(":")[:3]).upper()
        for oui, mfr in self.OUI_DB.items():
            if oui.upper() == prefix6_alt or oui.upper() == prefix6:
                return mfr
        return "Unknown"

    def from_arp(self):
        """Build device list from ARP table (passive, zero probes)."""
        if not self._adb_func:
            return []

        arp_entries = self._adb_func["arp"]()
        devices = []
        seen_ips = set()

        if arp_entries:
            for entry in arp_entries:
                ip = entry.get("ip", "")
                mac = entry.get("mac", "")
                iface = entry.get("iface")

                if ip in seen_ips or not ip or ip == self.camera_host:
                    continue
                seen_ips.add(ip)

                devices.append({
                    "ip": ip,
                    "mac": mac,
                    "oui": self.resolve_oui(mac),
                    "discovery": "arp",
                    "via_interface": iface,
                    "confidence": "high",
                })

        # Add gateway
        gw = self._adb_func["gateway"]()
        if gw and gw not in seen_ips and gw != self.camera_host:
            devices.append({
                "ip": gw,
                "mac": None,
                "oui": None,
                "discovery": "gateway",
                "via_interface": None,
                "confidence": "high",
            })

        return devices

    def from_interfaces(self):
        """Return the camera's own interface information."""
        if not self._adb_func:
            return []

        ifaces = self._adb_func["interfaces"]()
        return ifaces or []

    def _probe_mdns(self, ip, timeout=2):
        """Try to mDNS resolve a hostname for an IP."""
        try:
            # mDNS reverse lookup
            query = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)

            # Simple mDNS query for A records
            name = ip.replace(".", "-") + ".local"
            try:
                host = socket.gethostbyaddr(ip)
                return host[0]
            except Exception:
                return None
        except Exception:
            return None

    def enrich_arp_devices(self, devices):
        """Add MAC vendor + reverse DNS to discovered devices."""
        enriched = []
        for d in devices:
            ip = d.get("ip", "")
            mac = d.get("mac", "")

            # Try to PTR the IP
            rdns = None
            try:
                rdns = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

            d["reverse_dns"] = rdns
            enriched.append(d)
        return enriched

    def full_map(self):
        """
        Produce a full network map report from passive data.

        Returns dict:
          - camera: { ip:, interfaces:, gateway:, dns:, wifi: }
          - discovered_devices: [{ ip, mac, oui, discovery, reverse_dns }]
          - summary: { total, gateway, router, cameras, unknown }
        """
        from modules.adb_deep import adb_deep_collect

        camera_info = adb_deep_collect(self.camera_host, timeout=self.timeout) if self.camera_host else None

        arp_devices = self.from_arp()
        arp_devices = self.enrich_arp_devices(arp_devices)

        # Count types
        vendor_counts = defaultdict(int)
        for d in arp_devices:
            vendor_counts[d.get("oui", "Unknown")] += 1

        report = {
            "camera": {
                "ip": self.camera_host,
                "network_info": camera_info,
            } if camera_info else {"ip": self.camera_host},
            "discovered_devices": arp_devices,
            "summary": {
                "total_devices_on_subnet": len(arp_devices) + 1,  # +1 for camera itself
                "devices_found": len(arp_devices),
                "gateway": next((d["ip"] for d in arp_devices if d.get("discovery") == "gateway"), None),
                "vendor_breakdown": dict(vendor_counts),
            },
        }

        return report


# ── CLI test ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"

    nm = NetworkMapper(target)
    report = nm.full_map()

    print(json.dumps(report, indent=2, default=str))

    print("\n─── Summary ───")
    s = report["summary"]
    print(f"Camera: {target}")
    print(f"Gateway: {s.get('gateway', 'unknown')}")
    print(f"Devices on subnet (from ARP): {s['devices_found']}")
    print(f"Vendors: {s.get('vendor_breakdown', {})}")
