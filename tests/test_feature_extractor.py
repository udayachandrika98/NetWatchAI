"""Tests for src/feature_extractor.py — packet feature extraction."""

import pytest
from unittest.mock import MagicMock
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from src.feature_extractor import extract_features


class TestExtractFeatures:

    # ── TCP packets ──────────────────────────────

    def test_tcp_packet_basic(self):
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=12345, dport=443, flags="S")
        result = extract_features(pkt)
        assert result is not None
        assert result["src_ip"] == "1.2.3.4"
        assert result["dst_ip"] == "5.6.7.8"
        assert result["protocol"] == "TCP"
        assert result["src_port"] == 12345
        assert result["dst_port"] == 443
        assert "S" in result["flags"]
        assert result["packet_size"] > 0

    def test_tcp_with_payload(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=80, dport=9000) / b"Hello"
        result = extract_features(pkt)
        assert result["protocol"] == "TCP"
        assert result["packet_size"] > 40  # IP + TCP headers + payload

    def test_tcp_flags_ack(self):
        pkt = IP() / TCP(flags="A")
        result = extract_features(pkt)
        assert "A" in result["flags"]

    def test_tcp_flags_syn_ack(self):
        pkt = IP() / TCP(flags="SA")
        result = extract_features(pkt)
        assert "S" in result["flags"] and "A" in result["flags"]

    # ── UDP packets ──────────────────────────────

    def test_udp_packet(self):
        pkt = IP(src="192.168.1.1", dst="8.8.8.8") / UDP(sport=55000, dport=53)
        result = extract_features(pkt)
        assert result["protocol"] == "UDP"
        assert result["src_port"] == 55000
        assert result["dst_port"] == 53
        assert result["flags"] == ""

    def test_udp_with_payload(self):
        pkt = IP() / UDP(sport=1234, dport=5678) / b"DNS query"
        result = extract_features(pkt)
        assert result["protocol"] == "UDP"
        assert result["packet_size"] > 20

    # ── ICMP packets ─────────────────────────────

    def test_icmp_packet(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        result = extract_features(pkt)
        assert result["protocol"] == "ICMP"
        assert result["src_port"] == 0
        assert result["dst_port"] == 0
        assert result["flags"] == ""

    def test_icmp_large_payload(self):
        pkt = IP() / ICMP() / (b"X" * 2000)
        result = extract_features(pkt)
        assert result["protocol"] == "ICMP"
        assert result["packet_size"] > 2000

    # ── Non-IP packets ───────────────────────────

    def test_non_ip_returns_none(self):
        """ARP and raw Ethernet frames should return None."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = extract_features(pkt)
        assert result is None

    # ── Other IP protocol ────────────────────────

    def test_other_protocol(self):
        """IP packet with no TCP/UDP/ICMP layer → protocol=OTHER."""
        pkt = IP(src="1.1.1.1", dst="2.2.2.2", proto=47)  # GRE
        result = extract_features(pkt)
        assert result["protocol"] == "OTHER"
        assert result["src_port"] == 0
        assert result["dst_port"] == 0

    # ── Field completeness ───────────────────────

    def test_all_fields_present(self):
        pkt = IP() / TCP()
        result = extract_features(pkt)
        expected_keys = {"timestamp", "src_ip", "dst_ip", "protocol",
                         "src_port", "dst_port", "packet_size", "flags"}
        assert set(result.keys()) == expected_keys

    def test_timestamp_format(self):
        pkt = IP() / TCP()
        result = extract_features(pkt)
        # Should be YYYY-MM-DD HH:MM:SS
        from datetime import datetime
        datetime.strptime(result["timestamp"], "%Y-%m-%d %H:%M:%S")
