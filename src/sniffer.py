"""
NetWatchAI - Packet Sniffer
Captures live network packets using Scapy and saves extracted features to CSV.

Usage (requires root/sudo on macOS):
    sudo python -m src.sniffer --count 100
    sudo python -m src.sniffer --count 0        # 0 = capture forever
    sudo python -m src.sniffer --iface en0 --count 50
"""

import os
import csv
import argparse
from scapy.all import sniff

from src.feature_extractor import extract_features
from src.utils import PACKETS_CSV, CSV_COLUMNS, ensure_dirs, setup_logger

logger = setup_logger(__name__)


class PacketSniffer:
    """Captures live packets and writes features to a CSV file."""

    def __init__(self, output_path: str = PACKETS_CSV):
        self.output_path = output_path
        self.packet_count = 0
        ensure_dirs()
        self._init_csv()

    def _init_csv(self):
        """Create the CSV file with headers if it doesn't exist."""
        if not os.path.exists(self.output_path):
            with open(self.output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writeheader()
            logger.info(f"Created new CSV file: {self.output_path}")

    def _process_packet(self, packet):
        """Callback function called by Scapy for every captured packet.

        1. Extracts features from the packet.
        2. Appends the features as a new row in the CSV.
        3. Prints a summary to the console.
        """
        features = extract_features(packet)

        # Skip non-IP packets (ARP, raw Ethernet, etc.)
        if features is None:
            return

        # Append the row to CSV
        with open(self.output_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
            writer.writerow(features)

        self.packet_count += 1

        # Print a live summary to the terminal
        logger.info(
            f"[#{self.packet_count}] {features['protocol']} "
            f"{features['src_ip']}:{features['src_port']} → "
            f"{features['dst_ip']}:{features['dst_port']} "
            f"({features['packet_size']} bytes)"
        )

    def start(self, count: int = 50, iface: str = None, bpf_filter: str = None):
        """Start capturing packets.

        Args:
            count:      Number of packets to capture. 0 = unlimited.
            iface:      Network interface (e.g. "en0"). None = all interfaces.
            bpf_filter: BPF filter string (e.g. "tcp port 80").
        """
        logger.info(f"Starting packet capture (count={count}, iface={iface or 'all'})...")
        logger.info(f"Saving to: {self.output_path}")
        logger.info("Press Ctrl+C to stop.\n")

        sniff(
            prn=self._process_packet,        # callback per packet
            count=count if count > 0 else 0,  # 0 = infinite
            iface=iface,
            filter=bpf_filter,
            store=False,                      # don't keep packets in memory
        )

        logger.info(f"\nCapture complete. {self.packet_count} packets saved.")


# ── CLI entry point ──────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatchAI Packet Sniffer")
    parser.add_argument("--count", type=int, default=50, help="Number of packets to capture (0=unlimited)")
    parser.add_argument("--iface", type=str, default=None, help="Network interface (e.g. en0)")
    parser.add_argument("--filter", type=str, default=None, help="BPF filter (e.g. 'tcp port 80')")
    args = parser.parse_args()

    sniffer = PacketSniffer()
    sniffer.start(count=args.count, iface=args.iface, bpf_filter=args.filter)
