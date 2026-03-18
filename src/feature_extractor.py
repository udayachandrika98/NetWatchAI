"""
NetWatchAI - Feature Extractor
Extracts network features from raw Scapy packets into a dictionary.

Features extracted per packet:
  - timestamp   : when the packet was captured
  - src_ip      : source IP address
  - dst_ip      : destination IP address
  - protocol    : TCP, UDP, ICMP, or OTHER
  - src_port    : source port (0 if not applicable)
  - dst_port    : destination port (0 if not applicable)
  - packet_size : total packet length in bytes
  - flags       : TCP flags like SYN, ACK, FIN (empty for non-TCP)
"""

from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP


def extract_features(packet) -> dict | None:
    """Extract network features from a single Scapy packet.

    Args:
        packet: A Scapy packet object captured by sniff().

    Returns:
        A dictionary with the extracted features, or None if the
        packet has no IP layer (e.g. ARP, raw Ethernet frames).
    """

    # We only care about IP packets — skip everything else
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]

    # Start with fields available in every IP packet
    features = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": "OTHER",
        "src_port": 0,
        "dst_port": 0,
        "packet_size": len(packet),
        "flags": "",
    }

    # ── TCP packets ──────────────────────────────────
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        features["protocol"] = "TCP"
        features["src_port"] = tcp_layer.sport
        features["dst_port"] = tcp_layer.dport
        # TCP flags: S=SYN, A=ACK, F=FIN, R=RST, P=PSH, etc.
        features["flags"] = str(tcp_layer.flags)

    # ── UDP packets ──────────────────────────────────
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        features["protocol"] = "UDP"
        features["src_port"] = udp_layer.sport
        features["dst_port"] = udp_layer.dport

    # ── ICMP packets (ping, traceroute) ──────────────
    elif packet.haslayer(ICMP):
        features["protocol"] = "ICMP"
        # ICMP has no ports, so src_port and dst_port stay 0

    return features
