"""
NetWatchAI - Live Packet Capture
Captures live network packets and optionally runs anomaly detection in real-time.

Usage (requires sudo on macOS):
    sudo python capture.py
    sudo python capture.py --count 100
    sudo python capture.py --count 50 --detect
    sudo python capture.py --iface en0 --filter "tcp port 80"
"""

import argparse
import csv
import os

from src.sniffer import PacketSniffer
from src.detector import AnomalyDetector
from src.feature_extractor import extract_features
from src.utils import PACKETS_CSV, MODEL_PATH, CSV_COLUMNS, setup_logger, ensure_dirs

logger = setup_logger(__name__)


def main():
    parser = argparse.ArgumentParser(description="NetWatchAI Live Packet Capture")
    parser.add_argument("--count", type=int, default=50, help="Packets to capture (0=unlimited)")
    parser.add_argument("--iface", type=str, default=None, help="Network interface (e.g. en0)")
    parser.add_argument("--filter", type=str, default=None, help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument("--detect", action="store_true", help="Run anomaly detection in real-time")
    args = parser.parse_args()

    print("=" * 50)
    print("  NetWatchAI — Live Packet Capture")
    print("=" * 50)
    print()

    ensure_dirs()

    # If --detect flag is used, load the ML model
    detector = None
    if args.detect:
        if not os.path.exists(MODEL_PATH):
            print("ERROR: No trained model found. Run 'python train.py' first.")
            return
        detector = AnomalyDetector()
        print("Anomaly detection: ENABLED")
    else:
        print("Anomaly detection: DISABLED (use --detect to enable)")

    print(f"Saving packets to: {PACKETS_CSV}")
    print()

    # Start the sniffer
    sniffer = PacketSniffer()

    if detector:
        # Override the sniffer callback to include detection
        def detect_callback(packet):
            # Extract features once, reuse for both CSV write and detection
            features = extract_features(packet)
            if features is None:
                return

            # Write to CSV
            with open(sniffer.output_path, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
                writer.writerow(features)
            sniffer.packet_count += 1
            logger.info(
                f"[#{sniffer.packet_count}] {features['protocol']} "
                f"{features['src_ip']}:{features['src_port']} → "
                f"{features['dst_ip']}:{features['dst_port']} "
                f"({features['packet_size']} bytes)"
            )

            # Run anomaly detection on the same features
            result = detector.predict_single(features)
            if result == -1:
                logger.warning(
                    f"  ⚠ ANOMALY DETECTED: {features['src_ip']} → "
                    f"{features['dst_ip']}:{features['dst_port']} "
                    f"({features['protocol']}, {features['packet_size']} bytes)"
                )

        sniffer._process_packet = detect_callback

    sniffer.start(count=args.count, iface=args.iface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
