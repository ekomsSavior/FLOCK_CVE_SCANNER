"""
Unit tests for flock_tap.py — the passive Flock camera traffic monitor.

These lock in the detection/accounting behavior, and in particular guard the
three correctness bugs that were fixed:
  * FRP auth-payload detection must fire on data segments, not only on SYN.
  * on_tcp_connect must not inflate bytes_up (real byte counts come from ip.len).
  * connections to a known Flock cloud IP must be flagged even with no SNI/DNS.

Pure-logic tests run everywhere; packet-level tests are skipped when scapy is
not installed.
"""

import pytest

import flock_tap
from flock_tap import FlockTrafficTap

HAVE_SCAPY = flock_tap.HAVE_SCAPY
requires_scapy = pytest.mark.skipif(not HAVE_SCAPY, reason="scapy not installed")

if HAVE_SCAPY:
    from scapy.all import IP, TCP, Raw


def _rebuild(pkt):
    """Serialize and re-parse so IP.len and offsets are populated like a real capture."""
    return IP(bytes(pkt))


@pytest.fixture
def tap():
    return FlockTrafficTap()


# ── _categorize_sni ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("sni,expected", [
    ("login.flocksafety.com", "auth"),
    ("prod-flock-cd-xxx.edge.tenants.auth0.com", "auth"),
    ("flock-hibiki-inbox.s3.us-east-1.amazonaws.com", "s3_upload"),
    ("api.flocksafety.com", "cloud_api"),
    ("websockets.flocksafety.com", "cloud_api"),
    ("example.com", None),
    ("google.com", None),
])
def test_categorize_sni(tap, sni, expected):
    assert tap._categorize_sni(sni) == expected


# ── on_dns_query ────────────────────────────────────────────────────────────

def test_on_dns_query_flocksafety_counts_cloud_dns(tap):
    tap.on_dns_query("api.flocksafety.com", "10.0.0.5")
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 1


def test_on_dns_query_auth0_counts_cloud_dns(tap):
    # Regression: DNS detection used to match only "flocksafety", ignoring the
    # Flock auth0 tenant that the SNI path already recognized.
    tap.on_dns_query("prod-flock-cd-xxx.edge.tenants.auth0.com", "10.0.0.5")
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 1


def test_on_dns_query_learns_resolved_ips(tap):
    # Regression: resolved IPs for Flock domains are unioned into known_flock_ips
    # so later direct-to-IP connections (no SNI/DNS) can still be correlated.
    tap.on_dns_query("api.flocksafety.com", "10.0.0.5", resolved_ips=["203.0.113.9"])
    assert "203.0.113.9" in tap.known_flock_ips


def test_on_dns_query_ignores_non_flock(tap):
    tap.on_dns_query("example.com", "10.0.0.5", resolved_ips=["203.0.113.9"])
    assert tap.flow_stats["10.0.0.5"]["cloud_dns"] == 0
    assert "203.0.113.9" not in tap.known_flock_ips


# ── on_tcp_connect ──────────────────────────────────────────────────────────

def test_on_tcp_connect_does_not_inflate_bytes(tap):
    # Regression: on_tcp_connect used to add a fixed 64 bytes per packet on top
    # of real ip.len accounting, corrupting bandwidth stats.
    tap.on_tcp_connect("10.0.0.5", "8.8.8.8", 51000, 443)
    assert tap.flow_stats["10.0.0.5"]["bytes_up"] == 0
    assert tap.flow_stats["10.0.0.5"]["connections"] == 1


def test_on_tcp_connect_frp_port_sets_tunnel(tap):
    tap.on_tcp_connect("10.0.0.5", "10.0.0.9", 51000, 7000)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True


def test_on_tcp_connect_non_frp_port_no_tunnel(tap):
    tap.on_tcp_connect("10.0.0.5", "10.0.0.9", 51000, 8080)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is False


# ── on_tls_sni ──────────────────────────────────────────────────────────────

def test_on_tls_sni_categories(tap):
    tap.on_tls_sni("login.flocksafety.com", "10.0.0.5", "1.1.1.1")
    tap.on_tls_sni("flock-hibiki-inbox.s3.us-east-1.amazonaws.com", "10.0.0.5", "1.1.1.1")
    tap.on_tls_sni("api.flocksafety.com", "10.0.0.5", "1.1.1.1")
    fs = tap.flow_stats["10.0.0.5"]
    assert fs["auth_tls"] == 1
    assert fs["s3_uploads"] == 1
    assert fs["cloud_api"] == 1


# ── classify_device ─────────────────────────────────────────────────────────

def test_classify_device_cloud_dns(tap):
    tap.flow_stats["ip"]["cloud_dns"] = 1
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_frp(tap):
    tap.flow_stats["ip"]["frp_tunnel"] = True
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_cloud_api_only(tap):
    # The cloud_api-only branch is what surfaces known-Flock-IP correlation.
    tap.flow_stats["ip"]["cloud_api"] = 1
    assert tap.classify_device("ip") == "CLOUD_CONNECTED"


def test_classify_device_local_station(tap):
    tap.flow_stats["ip"]["connections"] = 3
    assert tap.classify_device("ip") == "LOCAL_STATION"


def test_classify_device_offline(tap):
    assert tap.classify_device("ip") == "OFFLINE_OR_UNMONITORED"


# ── classify_camera (fallback via device data) ──────────────────────────────

def test_classify_camera_no_data(tap):
    assert tap.classify_camera("10.0.0.99") == "NO_DATA"


def test_classify_camera_flock_sni_fallback(tap):
    tap.devices["ip"]["tls_snis"] = [{"sni": "login.flocksafety.com"}]
    assert tap.classify_camera("ip") == "CLOUD_CONNECTED"


def test_classify_camera_local_fallback(tap):
    tap.devices["ip"]["connections"] = [{"dst": "10.0.0.9"}]
    assert tap.classify_camera("ip") == "LOCAL_STATION"


# ── _parse_tcpdump_line ─────────────────────────────────────────────────────

def test_parse_tcpdump_dns(tap):
    line = "13:37:00.000000 IP 10.0.0.5.54321 > 8.8.8.8.53: 12345+ A? api.flocksafety.com. (36)"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "dns"
    assert parsed["src"] == "10.0.0.5"
    assert parsed["query"] == "api.flocksafety.com"


def test_parse_tcpdump_syn(tap):
    line = "13:37:00.000000 IP 10.0.0.5.44444 > 10.0.0.9.7000: Flags [S], seq 1, win 64240, length 0"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "syn"
    assert parsed["dport"] == 7000


def test_parse_tcpdump_other(tap):
    line = "13:37:00.000000 IP 10.0.0.5.44444 > 10.0.0.9.8080: Flags [P.], seq 1:10, length 9"
    parsed = tap._parse_tcpdump_line(line)
    assert parsed["type"] == "other"


def test_parse_tcpdump_garbage(tap):
    assert tap._parse_tcpdump_line("not a tcpdump line") is None


# ── packet-level regression guards (scapy) ──────────────────────────────────

@requires_scapy
def test_byte_accounting_matches_ip_len(tap):
    # bytes_up on the source device must equal the sum of real ip.len values,
    # with no per-packet inflation.
    pkts = [
        _rebuild(IP(src="10.0.0.5", dst="8.8.8.8") / TCP(dport=443, flags="S")),
        _rebuild(IP(src="10.0.0.5", dst="8.8.8.8") / TCP(dport=443, flags="PA") / Raw(b"x" * 100)),
    ]
    expected = sum(int(p[IP].len) for p in pkts)
    for p in pkts:
        tap._handle_packet_scapy(p)
    assert tap.devices["10.0.0.5"]["bytes_up"] == expected


@requires_scapy
def test_frp_payload_detected_on_non_syn(tap):
    # Regression: the FRP auth-payload scan used to be nested in the SYN-only
    # branch, so it never fired (SYN packets carry no payload). A data segment
    # (PSH/ACK) carrying the auth JSON must now be detected.
    pkt = _rebuild(
        IP(src="10.0.0.5", dst="10.0.0.9")
        / TCP(sport=51000, dport=12345, flags="PA")
        / Raw(b'{"proxy_type":"tcp","auth":"token"}')
    )
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True
    types = [t["type"] for t in tap.devices["10.0.0.5"]["frp_tunnels"]]
    assert "frp_auth_payload" in types


@requires_scapy
def test_frp_port_detected_on_syn(tap):
    pkt = _rebuild(IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=7000, flags="S"))
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["frp_tunnel"] is True
    types = [t["type"] for t in tap.devices["10.0.0.5"]["frp_tunnels"]]
    assert "frp_tunnel" in types


@requires_scapy
def test_known_flock_ip_correlation(tap):
    # A camera talking straight to a known Flock cloud IP (no SNI, no DNS of its
    # own) must still be counted as cloud_api.
    flock_ip = flock_tap.FLOCK_CLOUD_IPS[0]
    pkt = _rebuild(IP(src="10.0.0.5", dst=flock_ip) / TCP(sport=51000, dport=443, flags="S"))
    tap._handle_packet_scapy(pkt)
    assert tap.flow_stats["10.0.0.5"]["cloud_api"] >= 1
    assert tap.classify_device("10.0.0.5") == "CLOUD_CONNECTED"
