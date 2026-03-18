"""Integration tests — end-to-end workflows."""

import os
import csv
import tempfile
import pandas as pd
import pytest

from src.utils import SAMPLE_CSV, CSV_COLUMNS
from src.model import train_model
from src.detector import AnomalyDetector
from src.sniffer import PacketSniffer
from src.feature_extractor import extract_features
from scapy.layers.inet import IP, TCP, UDP, ICMP


class TestEndToEndPipeline:
    """Full pipeline: train → capture → detect."""

    @pytest.fixture(scope="class")
    def model_path(self, tmp_path_factory):
        path = str(tmp_path_factory.mktemp("e2e") / "model.pkl")
        train_model(csv_path=SAMPLE_CSV, save_path=path)
        return path

    def test_train_then_detect_sample(self, model_path):
        detector = AnomalyDetector(model_path=model_path)
        result_df = detector.score_csv(SAMPLE_CSV)
        assert "prediction" in result_df.columns
        assert "status" in result_df.columns
        assert len(result_df) > 0

    def test_capture_then_detect(self, model_path, tmp_path):
        """Simulate capture → detect workflow."""
        csv_path = str(tmp_path / "captured.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        # Simulate capturing packets
        packets = [
            IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="S"),
            IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=55321, dport=53),
            IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
            IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="PA") / (b"A" * 500),
        ]
        for pkt in packets:
            sniffer._process_packet(pkt)

        assert sniffer.packet_count == 4

        # Now detect anomalies on captured data
        detector = AnomalyDetector(model_path=model_path)
        result_df = detector.score_csv(csv_path)
        assert len(result_df) == 4
        assert set(result_df["status"].unique()).issubset({"Normal", "ANOMALY"})

    def test_realtime_detection_per_packet(self, model_path):
        """Simulate real-time per-packet detection (like capture.py --detect)."""
        detector = AnomalyDetector(model_path=model_path)

        normal_pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=49152, dport=443, flags="SA")
        features = extract_features(normal_pkt)
        result = detector.predict_single(features)
        assert result in (1, -1)

    def test_suspicious_packet_detection(self, model_path):
        """Suspicious port traffic should ideally be flagged."""
        detector = AnomalyDetector(model_path=model_path)

        suspicious_pkt = IP(src="10.0.0.99", dst="10.0.0.1") / TCP(
            sport=31337, dport=4444, flags="S"
        ) / (b"X" * 8000)
        features = extract_features(suspicious_pkt)
        result = detector.predict_single(features)
        # We don't assert -1 because the model might not flag it,
        # but it should at least not crash
        assert result in (1, -1)


class TestCSVRoundTrip:
    """Verify that data written by sniffer can be read by detector."""

    def test_csv_columns_match(self, tmp_path):
        csv_path = str(tmp_path / "roundtrip.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=443, flags="A")
        sniffer._process_packet(pkt)

        df = pd.read_csv(csv_path)
        for col in CSV_COLUMNS:
            assert col in df.columns, f"Missing column in CSV: {col}"

    def test_written_csv_has_correct_data_types(self, tmp_path):
        csv_path = str(tmp_path / "dtypes.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
        sniffer._process_packet(pkt)

        df = pd.read_csv(csv_path)
        assert pd.to_numeric(df["src_port"], errors="coerce").notnull().all()
        assert pd.to_numeric(df["dst_port"], errors="coerce").notnull().all()
        assert pd.to_numeric(df["packet_size"], errors="coerce").notnull().all()

    def test_detector_can_score_sniffer_output(self, tmp_path):
        """Full round-trip: sniffer writes → detector reads and scores."""
        model_path = str(tmp_path / "model.pkl")
        train_model(csv_path=SAMPLE_CSV, save_path=model_path)

        csv_path = str(tmp_path / "captured.csv")
        sniffer = PacketSniffer(output_path=csv_path)

        for i in range(10):
            pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(
                sport=49152 + i, dport=443, flags="PA"
            )
            sniffer._process_packet(pkt)

        detector = AnomalyDetector(model_path=model_path)
        result_df = detector.score_csv(csv_path)
        assert len(result_df) == 10
        assert result_df["prediction"].isin([1, -1]).all()
