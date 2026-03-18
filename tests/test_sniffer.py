"""Tests for src/sniffer.py — packet sniffer CSV handling."""

import os
import csv
import pytest

from src.sniffer import PacketSniffer
from src.utils import CSV_COLUMNS


class TestPacketSniffer:

    def test_creates_csv_with_headers(self, tmp_path):
        csv_path = str(tmp_path / "test_packets.csv")
        sniffer = PacketSniffer(output_path=csv_path)
        assert os.path.isfile(csv_path)
        with open(csv_path) as f:
            reader = csv.reader(f)
            headers = next(reader)
            assert headers == CSV_COLUMNS

    def test_does_not_overwrite_existing_csv(self, tmp_path):
        csv_path = str(tmp_path / "test_packets.csv")
        # Create CSV with a data row
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writeheader()
            writer.writerow({
                "timestamp": "2026-01-01 00:00:00",
                "src_ip": "1.1.1.1",
                "dst_ip": "2.2.2.2",
                "protocol": "TCP",
                "src_port": "80",
                "dst_port": "443",
                "packet_size": "100",
                "flags": "S",
            })
        # Initialize sniffer — should NOT overwrite
        sniffer = PacketSniffer(output_path=csv_path)
        with open(csv_path) as f:
            lines = f.readlines()
            assert len(lines) == 2  # header + 1 data row

    def test_initial_packet_count_is_zero(self, tmp_path):
        csv_path = str(tmp_path / "test_packets.csv")
        sniffer = PacketSniffer(output_path=csv_path)
        assert sniffer.packet_count == 0

    def test_process_packet_writes_to_csv(self, tmp_path):
        """Test that _process_packet extracts features and writes to CSV."""
        from scapy.layers.inet import IP, TCP
        csv_path = str(tmp_path / "test_packets.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")
        sniffer._process_packet(pkt)

        assert sniffer.packet_count == 1
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["src_ip"] == "10.0.0.1"
            assert rows[0]["dst_ip"] == "10.0.0.2"
            assert rows[0]["protocol"] == "TCP"

    def test_process_non_ip_packet_skipped(self, tmp_path):
        """Non-IP packets should be silently ignored."""
        from scapy.layers.l2 import Ether
        csv_path = str(tmp_path / "test_packets.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff")
        sniffer._process_packet(pkt)

        assert sniffer.packet_count == 0

    def test_multiple_packets_appended(self, tmp_path):
        from scapy.layers.inet import IP, TCP, UDP
        csv_path = str(tmp_path / "test_packets.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        pkt1 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=443)
        pkt2 = IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=1234)

        sniffer._process_packet(pkt1)
        sniffer._process_packet(pkt2)

        assert sniffer.packet_count == 2
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["protocol"] == "TCP"
            assert rows[1]["protocol"] == "UDP"
