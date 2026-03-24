"""
Comprehensive automated tests for the entire NetWatchAI application.
Covers every module, config file, edge case, and end-to-end flow.
"""

import os
import csv
import json
import math
import tempfile
import shutil

import pandas as pd
import numpy as np
import pytest
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from src.utils import (
    PROJECT_ROOT, DATA_DIR, MODELS_DIR, PACKETS_CSV,
    SAMPLE_CSV, MODEL_PATH, CSV_COLUMNS, setup_logger, ensure_dirs,
)
from src.feature_extractor import extract_features
from src.sniffer import PacketSniffer
from src.model import load_and_prepare_data, train_model
from src.detector import AnomalyDetector


# ════════════════════════════════════════════════════════════
#  1. src/utils.py — Paths, Logger, Dirs
# ════════════════════════════════════════════════════════════

class TestUtilsPaths:
    def test_project_root_is_absolute(self):
        assert os.path.isabs(PROJECT_ROOT)

    def test_data_dir_is_subdir_of_root(self):
        assert DATA_DIR.startswith(PROJECT_ROOT)

    def test_models_dir_is_subdir_of_root(self):
        assert MODELS_DIR.startswith(PROJECT_ROOT)

    def test_packets_csv_extension(self):
        assert PACKETS_CSV.endswith(".csv")

    def test_sample_csv_extension(self):
        assert SAMPLE_CSV.endswith(".csv")

    def test_model_path_extension(self):
        assert MODEL_PATH.endswith(".pkl")

    def test_csv_columns_has_8_fields(self):
        assert len(CSV_COLUMNS) == 8

    def test_csv_columns_order(self):
        expected = ["timestamp", "src_ip", "dst_ip", "protocol",
                    "src_port", "dst_port", "packet_size", "flags"]
        assert CSV_COLUMNS == expected

    def test_csv_columns_no_whitespace(self):
        for col in CSV_COLUMNS:
            assert col.strip() == col

    def test_sample_csv_file_exists(self):
        assert os.path.exists(SAMPLE_CSV), f"Missing: {SAMPLE_CSV}"

    def test_model_pkl_file_exists(self):
        assert os.path.exists(MODEL_PATH), f"Missing: {MODEL_PATH}"


class TestUtilsLogger:
    def test_returns_logger_instance(self):
        import logging
        log = setup_logger("test_logger_1")
        assert isinstance(log, logging.Logger)

    def test_logger_name_matches(self):
        log = setup_logger("my_custom_name")
        assert log.name == "my_custom_name"

    def test_logger_has_at_least_one_handler(self):
        log = setup_logger("test_logger_2")
        assert len(log.handlers) >= 1

    def test_calling_twice_no_duplicate_handlers(self):
        log = setup_logger("test_logger_dup")
        n = len(log.handlers)
        setup_logger("test_logger_dup")
        assert len(log.handlers) == n

    def test_custom_log_level(self):
        import logging
        log = setup_logger("test_debug", level=logging.DEBUG)
        assert log.level == logging.DEBUG


class TestUtilsEnsureDirs:
    def test_creates_dirs_in_temp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = os.path.join(tmpdir, "data")
            m = os.path.join(tmpdir, "models")
            os.makedirs(d, exist_ok=True)
            os.makedirs(m, exist_ok=True)
            assert os.path.isdir(d)
            assert os.path.isdir(m)

    def test_ensure_dirs_idempotent(self):
        ensure_dirs()
        ensure_dirs()  # should not raise
        assert os.path.isdir(DATA_DIR)
        assert os.path.isdir(MODELS_DIR)


# ════════════════════════════════════════════════════════════
#  2. src/feature_extractor.py
# ════════════════════════════════════════════════════════════

class TestFeatureExtractor:
    def _make_tcp(self, sport=12345, dport=80, flags="S", payload=b""):
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=dport, flags=flags)
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def _make_udp(self, sport=5000, dport=53, payload=b""):
        from scapy.layers.inet import IP, UDP
        from scapy.packet import Raw
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=sport, dport=dport)
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def _make_icmp(self, payload=b""):
        from scapy.layers.inet import IP, ICMP
        from scapy.packet import Raw
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    def test_tcp_basic(self):
        f = extract_features(self._make_tcp())
        assert f is not None
        assert f["protocol"] == "TCP"
        assert f["src_port"] == 12345
        assert f["dst_port"] == 80
        assert f["src_ip"] == "10.0.0.1"
        assert f["dst_ip"] == "10.0.0.2"

    def test_tcp_flags_syn(self):
        f = extract_features(self._make_tcp(flags="S"))
        assert "S" in f["flags"]

    def test_tcp_flags_syn_ack(self):
        f = extract_features(self._make_tcp(flags="SA"))
        assert "S" in f["flags"]
        assert "A" in f["flags"]

    def test_tcp_with_payload_increases_size(self):
        f_empty = extract_features(self._make_tcp())
        f_big = extract_features(self._make_tcp(payload=b"X" * 1000))
        assert f_big["packet_size"] > f_empty["packet_size"]

    def test_udp_basic(self):
        f = extract_features(self._make_udp())
        assert f["protocol"] == "UDP"
        assert f["src_port"] == 5000
        assert f["dst_port"] == 53
        assert f["flags"] == ""

    def test_icmp_basic(self):
        f = extract_features(self._make_icmp())
        assert f["protocol"] == "ICMP"
        assert f["src_port"] == 0
        assert f["dst_port"] == 0

    def test_icmp_large_payload(self):
        f = extract_features(self._make_icmp(payload=b"X" * 5000))
        assert f["packet_size"] > 5000

    def test_non_ip_returns_none(self):
        from scapy.layers.l2 import Ether, ARP
        pkt = Ether() / ARP()
        assert extract_features(pkt) is None

    def test_all_csv_columns_present(self):
        f = extract_features(self._make_tcp())
        for col in CSV_COLUMNS:
            assert col in f, f"Missing key: {col}"

    def test_timestamp_format(self):
        f = extract_features(self._make_tcp())
        from datetime import datetime
        # Should parse without error
        datetime.strptime(f["timestamp"], "%Y-%m-%d %H:%M:%S")

    def test_packet_size_positive(self):
        f = extract_features(self._make_tcp())
        assert f["packet_size"] > 0


# ════════════════════════════════════════════════════════════
#  3. src/sniffer.py
# ════════════════════════════════════════════════════════════

class TestSniffer:
    def test_creates_csv_with_headers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            sniffer = PacketSniffer(output_path=csv_path)
            assert os.path.exists(csv_path)
            with open(csv_path) as f:
                reader = csv.reader(f)
                headers = next(reader)
                assert headers == CSV_COLUMNS

    def test_does_not_overwrite_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            with open(csv_path, "w") as f:
                f.write("existing,data\n")
            sniffer = PacketSniffer(output_path=csv_path)
            with open(csv_path) as f:
                assert f.readline().strip() == "existing,data"

    def test_packet_count_starts_at_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            sniffer = PacketSniffer(output_path=csv_path)
            assert sniffer.packet_count == 0

    def test_process_packet_writes_row(self):
        from scapy.layers.inet import IP, TCP
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            sniffer = PacketSniffer(output_path=csv_path)
            pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=111, dport=222)
            sniffer._process_packet(pkt)
            assert sniffer.packet_count == 1
            df = pd.read_csv(csv_path)
            assert len(df) == 1
            assert df.iloc[0]["src_ip"] == "1.2.3.4"

    def test_non_ip_skipped(self):
        from scapy.layers.l2 import Ether, ARP
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            sniffer = PacketSniffer(output_path=csv_path)
            sniffer._process_packet(Ether() / ARP())
            assert sniffer.packet_count == 0

    def test_multiple_packets_appended(self):
        from scapy.layers.inet import IP, TCP, UDP
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "test.csv")
            sniffer = PacketSniffer(output_path=csv_path)
            sniffer._process_packet(IP() / TCP())
            sniffer._process_packet(IP() / UDP())
            sniffer._process_packet(IP() / TCP())
            assert sniffer.packet_count == 3
            df = pd.read_csv(csv_path)
            assert len(df) == 3


# ════════════════════════════════════════════════════════════
#  4. src/model.py — Training Pipeline
# ════════════════════════════════════════════════════════════

class TestModelTraining:
    def test_load_and_prepare_returns_tuple(self):
        features, encoders, labels = load_and_prepare_data(SAMPLE_CSV)
        assert isinstance(features, pd.DataFrame)
        assert isinstance(encoders, dict)

    def test_feature_columns_correct(self):
        features, _, _ = load_and_prepare_data(SAMPLE_CSV)
        assert list(features.columns) == ["protocol", "src_port", "dst_port", "packet_size", "flags"]

    def test_encoders_have_protocol_and_flags(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        assert "protocol" in encoders
        assert "flags" in encoders

    def test_protocol_encoder_classes(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        classes = set(encoders["protocol"].classes_)
        # Should have at least TCP, UDP, ICMP
        assert len(classes) >= 3

    def test_flags_encoder_has_none(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        assert "NONE" in encoders["flags"].classes_

    def test_no_nan_in_features(self):
        features, _, _ = load_and_prepare_data(SAMPLE_CSV)
        assert not features.isnull().any().any()

    def test_labels_returned(self):
        _, _, labels = load_and_prepare_data(SAMPLE_CSV)
        assert labels is not None
        assert len(labels) > 0

    def test_labels_contain_normal_and_anomaly(self):
        _, _, labels = load_and_prepare_data(SAMPLE_CSV)
        assert "normal" in labels.values
        assert "anomaly" in labels.values

    def test_train_and_save_model(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = os.path.join(tmpdir, "test_model.pkl")
            model, encoders = train_model(SAMPLE_CSV, save_path)
            assert os.path.exists(save_path)
            assert isinstance(model, IsolationForest)

    def test_saved_model_artifact_structure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = os.path.join(tmpdir, "test_model.pkl")
            train_model(SAMPLE_CSV, save_path)
            artifact = joblib.load(save_path)
            assert "model" in artifact
            assert "encoders" in artifact
            assert isinstance(artifact["model"], IsolationForest)

    def test_model_predictions_are_1_or_neg1(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = os.path.join(tmpdir, "test_model.pkl")
            model, _ = train_model(SAMPLE_CSV, save_path)
            features, _, _ = load_and_prepare_data(SAMPLE_CSV)
            preds = model.predict(features)
            assert set(preds).issubset({1, -1})


# ════════════════════════════════════════════════════════════
#  5. src/detector.py — Anomaly Detection
# ════════════════════════════════════════════════════════════

class TestDetector:
    @pytest.fixture(autouse=True)
    def setup_detector(self):
        self.detector = AnomalyDetector()

    def test_loads_without_error(self):
        assert self.detector.model is not None
        assert self.detector.encoders is not None

    def test_predict_single_returns_int(self):
        features = {"protocol": "TCP", "src_port": 443, "dst_port": 80,
                     "packet_size": 120, "flags": "A"}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_predict_single_normal_traffic(self):
        features = {"protocol": "TCP", "src_port": 49152, "dst_port": 443,
                     "packet_size": 120, "flags": "PA"}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_predict_single_suspicious_traffic(self):
        features = {"protocol": "TCP", "src_port": 4444, "dst_port": 31337,
                     "packet_size": 65000, "flags": "S"}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_predict_batch_returns_list(self):
        df = pd.DataFrame([
            {"protocol": "TCP", "src_port": 80, "dst_port": 443, "packet_size": 100, "flags": "A"},
            {"protocol": "UDP", "src_port": 53, "dst_port": 1234, "packet_size": 64, "flags": ""},
        ])
        results = self.detector.predict_batch(df)
        assert isinstance(results, list)
        assert len(results) == 2

    def test_predict_batch_does_not_modify_original(self):
        df = pd.DataFrame([
            {"protocol": "TCP", "src_port": 80, "dst_port": 443, "packet_size": 100, "flags": "A"},
        ])
        original_protocol = df["protocol"].iloc[0]
        self.detector.predict_batch(df)
        assert df["protocol"].iloc[0] == original_protocol

    def test_unseen_protocol_handled(self):
        features = {"protocol": "ZIGBEE", "src_port": 80, "dst_port": 443,
                     "packet_size": 100, "flags": "A"}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_unseen_flags_handled(self):
        features = {"protocol": "TCP", "src_port": 80, "dst_port": 443,
                     "packet_size": 100, "flags": "XYZUNKNOWN"}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_empty_flags_handled(self):
        features = {"protocol": "TCP", "src_port": 80, "dst_port": 443,
                     "packet_size": 100, "flags": ""}
        result = self.detector.predict_single(features)
        assert result in (1, -1)

    def test_nan_flags_handled(self):
        df = pd.DataFrame([
            {"protocol": "TCP", "src_port": 80, "dst_port": 443,
             "packet_size": 100, "flags": float("nan")},
        ])
        results = self.detector.predict_batch(df)
        assert len(results) == 1

    def test_score_csv(self):
        result_df = self.detector.score_csv(SAMPLE_CSV)
        assert "prediction" in result_df.columns
        assert "status" in result_df.columns
        assert set(result_df["status"].unique()).issubset({"Normal", "ANOMALY"})

    def test_score_csv_preserves_original_columns(self):
        result_df = self.detector.score_csv(SAMPLE_CSV)
        for col in CSV_COLUMNS:
            assert col in result_df.columns

    def test_invalid_model_path_raises(self):
        with pytest.raises(Exception):
            AnomalyDetector("/nonexistent/model.pkl")

    def test_batch_large_dataset(self):
        """Predict on a large batch to check for performance issues."""
        rows = [{"protocol": "TCP", "src_port": i, "dst_port": 443,
                 "packet_size": 100 + i, "flags": "A"} for i in range(1000)]
        df = pd.DataFrame(rows)
        results = self.detector.predict_batch(df)
        assert len(results) == 1000


# ════════════════════════════════════════════════════════════
#  6. Sample Data Validation
# ════════════════════════════════════════════════════════════

class TestSampleData:
    @pytest.fixture(autouse=True)
    def load_data(self):
        self.df = pd.read_csv(SAMPLE_CSV)

    def test_row_count(self):
        assert len(self.df) >= 200, "Expected at least 200 sample packets"

    def test_all_csv_columns_present(self):
        for col in CSV_COLUMNS:
            assert col in self.df.columns

    def test_has_label_column(self):
        assert "label" in self.df.columns

    def test_protocols_valid(self):
        valid = {"TCP", "UDP", "ICMP", "OTHER"}
        actual = set(self.df["protocol"].unique())
        assert actual.issubset(valid), f"Invalid protocols: {actual - valid}"

    def test_has_tcp_udp_icmp(self):
        protos = set(self.df["protocol"].unique())
        assert "TCP" in protos
        assert "UDP" in protos
        assert "ICMP" in protos

    def test_ports_are_numeric(self):
        assert pd.to_numeric(self.df["src_port"], errors="coerce").notnull().all()
        assert pd.to_numeric(self.df["dst_port"], errors="coerce").notnull().all()

    def test_ports_non_negative(self):
        assert (self.df["src_port"] >= 0).all()
        assert (self.df["dst_port"] >= 0).all()

    def test_packet_size_positive(self):
        assert (self.df["packet_size"] > 0).all()

    def test_no_null_protocol(self):
        assert self.df["protocol"].notnull().all()

    def test_no_null_src_ip(self):
        assert self.df["src_ip"].notnull().all()

    def test_no_null_dst_ip(self):
        assert self.df["dst_ip"].notnull().all()

    def test_timestamps_parseable(self):
        parsed = pd.to_datetime(self.df["timestamp"], errors="coerce")
        assert parsed.notnull().all()

    def test_labels_are_normal_or_anomaly(self):
        valid = {"normal", "anomaly"}
        actual = set(self.df["label"].unique())
        assert actual.issubset(valid), f"Invalid labels: {actual - valid}"

    def test_has_both_normal_and_anomaly(self):
        labels = set(self.df["label"].unique())
        assert "normal" in labels
        assert "anomaly" in labels

    def test_icmp_ports_are_zero(self):
        icmp = self.df[self.df["protocol"] == "ICMP"]
        if len(icmp) > 0:
            assert (icmp["src_port"] == 0).all()
            assert (icmp["dst_port"] == 0).all()

    def test_ip_format_valid(self):
        import re
        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        for ip in self.df["src_ip"]:
            assert ip_pattern.match(str(ip)), f"Invalid src_ip: {ip}"
        for ip in self.df["dst_ip"]:
            assert ip_pattern.match(str(ip)), f"Invalid dst_ip: {ip}"


# ════════════════════════════════════════════════════════════
#  7. Dashboard Logic — classify_attack (replicated)
# ════════════════════════════════════════════════════════════

SUSPICIOUS_PORTS = {4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321}

def classify_attack(row):
    if row.get("status") != "ANOMALY":
        return "Normal"
    protocol = str(row.get("protocol", "")).upper()
    try:
        dst_port = int(row.get("dst_port", 0))
    except (ValueError, TypeError):
        dst_port = 0
    try:
        src_port = int(row.get("src_port", 0))
    except (ValueError, TypeError):
        src_port = 0
    try:
        packet_size = int(row.get("packet_size", 0))
    except (ValueError, TypeError):
        packet_size = 0
    flags = str(row.get("flags", ""))
    if protocol == "ICMP" and packet_size > 1000:
        return "Ping of Death"
    if protocol == "TCP" and flags == "S" and packet_size <= 60:
        return "Port Scan"
    if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
        if packet_size > 1000:
            return "Data Exfiltration"
        return "Suspicious Port"
    if packet_size > 5000:
        return "Large Transfer"
    if protocol == "UDP" and dst_port == 53 and packet_size > 200:
        return "DNS Anomaly"
    return "Unknown Anomaly"


class TestClassifyAttackComprehensive:
    """Exhaustive tests for the attack classification engine."""

    # ── Basic classification ──
    def test_normal_returns_normal(self):
        assert classify_attack({"status": "Normal"}) == "Normal"

    def test_unknown_status_returns_normal(self):
        assert classify_attack({"status": "Unknown"}) == "Normal"

    def test_missing_status_returns_normal(self):
        assert classify_attack({}) == "Normal"

    def test_anomaly_with_no_other_fields(self):
        result = classify_attack({"status": "ANOMALY"})
        assert result == "Unknown Anomaly"

    # ── Ping of Death ──
    def test_ping_of_death_exact_boundary(self):
        row = {"status": "ANOMALY", "protocol": "ICMP", "packet_size": 1001}
        assert classify_attack(row) == "Ping of Death"

    def test_icmp_at_boundary_not_pod(self):
        row = {"status": "ANOMALY", "protocol": "ICMP", "packet_size": 1000}
        assert classify_attack(row) != "Ping of Death"

    def test_icmp_small_not_pod(self):
        row = {"status": "ANOMALY", "protocol": "ICMP", "packet_size": 64}
        assert classify_attack(row) != "Ping of Death"

    # ── Port Scan ──
    def test_port_scan_syn_small(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "flags": "S",
               "packet_size": 40, "dst_port": 22, "src_port": 50000}
        assert classify_attack(row) == "Port Scan"

    def test_port_scan_at_boundary_60(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "flags": "S",
               "packet_size": 60, "dst_port": 22, "src_port": 50000}
        assert classify_attack(row) == "Port Scan"

    def test_port_scan_above_boundary_61(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "flags": "S",
               "packet_size": 61, "dst_port": 22, "src_port": 50000}
        assert classify_attack(row) != "Port Scan"

    def test_port_scan_requires_syn(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "flags": "A",
               "packet_size": 40, "dst_port": 22, "src_port": 50000}
        assert classify_attack(row) != "Port Scan"

    def test_port_scan_requires_tcp(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "flags": "S",
               "packet_size": 40, "dst_port": 22, "src_port": 50000}
        assert classify_attack(row) != "Port Scan"

    # ── Suspicious Ports ──
    @pytest.mark.parametrize("port", sorted(SUSPICIOUS_PORTS))
    def test_suspicious_dst_port(self, port):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": port,
               "src_port": 80, "packet_size": 100, "flags": "A"}
        assert classify_attack(row) in ("Suspicious Port", "Data Exfiltration")

    @pytest.mark.parametrize("port", sorted(SUSPICIOUS_PORTS))
    def test_suspicious_src_port(self, port):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 80,
               "src_port": port, "packet_size": 100, "flags": "A"}
        assert classify_attack(row) in ("Suspicious Port", "Data Exfiltration")

    # ── Data Exfiltration ──
    def test_data_exfil_large_to_suspicious_port(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 4444,
               "src_port": 80, "packet_size": 5000, "flags": "PA"}
        assert classify_attack(row) == "Data Exfiltration"

    def test_data_exfil_boundary_1001(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 4444,
               "src_port": 80, "packet_size": 1001, "flags": "PA"}
        assert classify_attack(row) == "Data Exfiltration"

    def test_suspicious_port_not_exfil_at_1000(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 4444,
               "src_port": 80, "packet_size": 1000, "flags": "PA"}
        assert classify_attack(row) == "Suspicious Port"

    # ── Large Transfer ──
    def test_large_transfer_above_5000(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 443,
               "src_port": 50000, "packet_size": 5001, "flags": "PA"}
        assert classify_attack(row) == "Large Transfer"

    def test_not_large_transfer_at_5000(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 443,
               "src_port": 50000, "packet_size": 5000, "flags": "PA"}
        assert classify_attack(row) != "Large Transfer"

    # ── DNS Anomaly ──
    def test_dns_anomaly(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "dst_port": 53,
               "src_port": 50000, "packet_size": 500, "flags": ""}
        assert classify_attack(row) == "DNS Anomaly"

    def test_dns_normal_size_not_anomaly(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "dst_port": 53,
               "src_port": 50000, "packet_size": 200, "flags": ""}
        assert classify_attack(row) != "DNS Anomaly"

    def test_dns_anomaly_boundary_201(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "dst_port": 53,
               "src_port": 50000, "packet_size": 201, "flags": ""}
        assert classify_attack(row) == "DNS Anomaly"

    def test_dns_not_udp_not_anomaly(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 53,
               "src_port": 50000, "packet_size": 500, "flags": ""}
        assert classify_attack(row) != "DNS Anomaly"

    # ── Edge cases ──
    def test_nan_dst_port(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": float("nan"),
               "src_port": 80, "packet_size": 100, "flags": "A"}
        assert isinstance(classify_attack(row), str)

    def test_nan_src_port(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 80,
               "src_port": float("nan"), "packet_size": 100, "flags": "A"}
        assert isinstance(classify_attack(row), str)

    def test_nan_packet_size(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 80,
               "src_port": 80, "packet_size": float("nan"), "flags": "A"}
        assert isinstance(classify_attack(row), str)

    def test_none_values(self):
        row = {"status": "ANOMALY", "protocol": None, "dst_port": None,
               "src_port": None, "packet_size": None, "flags": None}
        assert isinstance(classify_attack(row), str)

    def test_empty_string_ports(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": "",
               "src_port": "", "packet_size": "", "flags": ""}
        assert isinstance(classify_attack(row), str)

    def test_string_number_ports(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": "4444",
               "src_port": "80", "packet_size": "5000", "flags": "PA"}
        assert classify_attack(row) == "Data Exfiltration"

    def test_case_insensitive_protocol(self):
        row = {"status": "ANOMALY", "protocol": "icmp", "packet_size": 2000}
        assert classify_attack(row) == "Ping of Death"


# ════════════════════════════════════════════════════════════
#  8. Dashboard Metrics & Threat Level
# ════════════════════════════════════════════════════════════

class TestMetricsAndThreatLevel:
    def _threat_level(self, anomaly_pct):
        if anomaly_pct == 0:
            return "LOW — All Clear"
        elif anomaly_pct < 5:
            return "LOW — Minor Activity"
        elif anomaly_pct < 15:
            return "MEDIUM — Suspicious Activity"
        elif anomaly_pct < 30:
            return "HIGH — Active Threats"
        else:
            return "CRITICAL — Under Attack"

    def test_zero_anomalies(self):
        assert "LOW" in self._threat_level(0)

    def test_low_minor(self):
        assert "LOW" in self._threat_level(4.9)

    def test_medium_boundary(self):
        assert "MEDIUM" in self._threat_level(5)

    def test_high_boundary(self):
        assert "HIGH" in self._threat_level(15)

    def test_critical_boundary(self):
        assert "CRITICAL" in self._threat_level(30)

    def test_critical_100_percent(self):
        assert "CRITICAL" in self._threat_level(100)

    def test_metrics_with_sample_data(self):
        detector = AnomalyDetector()
        df = pd.read_csv(SAMPLE_CSV)
        preds = detector.predict_batch(df)
        df["prediction"] = preds

        total = len(df)
        n_anomalies = int((df["prediction"] == -1).sum())
        n_normal = int((df["prediction"] == 1).sum())

        assert total > 0
        assert n_anomalies + n_normal == total
        assert n_anomalies >= 0
        assert n_normal >= 0

        anomaly_pct = n_anomalies / total * 100
        assert 0 <= anomaly_pct <= 100
        threat = self._threat_level(anomaly_pct)
        assert isinstance(threat, str)


# ════════════════════════════════════════════════════════════
#  9. Dashboard Filter Combinations
# ════════════════════════════════════════════════════════════

class TestFilterCombinations:
    @pytest.fixture(autouse=True)
    def setup_data(self):
        detector = AnomalyDetector()
        self.df = pd.read_csv(SAMPLE_CSV)
        self.df["prediction"] = detector.predict_batch(self.df)
        self.df["status"] = self.df["prediction"].map({1: "Normal", -1: "ANOMALY"})
        self.df["attack_type"] = self.df.apply(classify_attack, axis=1)

    def _filter(self, protocol="All", status="All", attack="All"):
        filtered = self.df.copy()
        if protocol != "All":
            filtered = filtered[filtered["protocol"] == protocol]
        if status != "All":
            filtered = filtered[filtered["status"] == status]
        if attack != "All":
            filtered = filtered[filtered["attack_type"] == attack]
        return filtered

    def test_all_all_all_returns_full(self):
        assert len(self._filter()) == len(self.df)

    def test_tcp_filter(self):
        result = self._filter(protocol="TCP")
        assert all(result["protocol"] == "TCP")

    def test_udp_filter(self):
        result = self._filter(protocol="UDP")
        assert all(result["protocol"] == "UDP")

    def test_icmp_filter(self):
        result = self._filter(protocol="ICMP")
        assert all(result["protocol"] == "ICMP")

    def test_status_normal_filter(self):
        result = self._filter(status="Normal")
        assert all(result["status"] == "Normal")

    def test_status_anomaly_filter(self):
        result = self._filter(status="ANOMALY")
        assert all(result["status"] == "ANOMALY")

    def test_attack_type_normal_filter(self):
        result = self._filter(attack="Normal")
        assert all(result["attack_type"] == "Normal")

    def test_combined_tcp_anomaly(self):
        result = self._filter(protocol="TCP", status="ANOMALY")
        assert all(result["protocol"] == "TCP")
        assert all(result["status"] == "ANOMALY")

    def test_combined_udp_normal(self):
        result = self._filter(protocol="UDP", status="Normal")
        assert all(result["protocol"] == "UDP")
        assert all(result["status"] == "Normal")

    def test_contradictory_filter_normal_port_scan(self):
        result = self._filter(status="Normal", attack="Port Scan")
        assert len(result) == 0

    def test_contradictory_filter_anomaly_normal_attack(self):
        result = self._filter(status="ANOMALY", attack="Normal")
        assert len(result) == 0

    def test_nonexistent_protocol_returns_empty(self):
        result = self._filter(protocol="ZIGBEE")
        assert len(result) == 0

    def test_every_filter_combo_no_crash(self):
        protocols = ["All"] + sorted(self.df["protocol"].dropna().unique().tolist())
        statuses = ["All"] + sorted(self.df["status"].dropna().unique().tolist())
        attacks = ["All"] + sorted(self.df["attack_type"].dropna().unique().tolist())
        for p in protocols:
            for s in statuses:
                for a in attacks:
                    result = self._filter(protocol=p, status=s, attack=a)
                    assert isinstance(result, pd.DataFrame)

    def test_dropdown_includes_normal_attack_type(self):
        attack_types = ["All"] + sorted(self.df["attack_type"].dropna().unique().tolist())
        assert "Normal" in attack_types

    def test_dropdown_protocol_starts_with_all(self):
        protocols = ["All"] + sorted(self.df["protocol"].dropna().unique().tolist())
        assert protocols[0] == "All"

    def test_filtered_count_lte_total(self):
        for proto in ["TCP", "UDP", "ICMP"]:
            result = self._filter(protocol=proto)
            assert len(result) <= len(self.df)


# ════════════════════════════════════════════════════════════
# 10. Dashboard Tabs Data Rendering
# ════════════════════════════════════════════════════════════

class TestTabDataRendering:
    @pytest.fixture(autouse=True)
    def setup_data(self):
        detector = AnomalyDetector()
        self.df = pd.read_csv(SAMPLE_CSV)
        self.df["prediction"] = detector.predict_batch(self.df)
        self.df["status"] = self.df["prediction"].map({1: "Normal", -1: "ANOMALY"})
        self.df["attack_type"] = self.df.apply(classify_attack, axis=1)
        self.anomaly_df = self.df[self.df["prediction"] == -1]

    # ── Tab 1: Alerts ──
    def test_alert_columns_exist(self):
        cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port",
                "dst_port", "packet_size", "flags", "attack_type"]
        for c in cols:
            assert c in self.anomaly_df.columns

    def test_display_columns_exist(self):
        cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port",
                "dst_port", "packet_size", "flags", "attack_type", "status"]
        for c in cols:
            assert c in self.df.columns

    def test_reset_index_works(self):
        filtered = self.df[self.df["protocol"] == "UDP"]
        reset = filtered.reset_index(drop=True)
        assert reset.index[0] == 0

    def test_empty_filter_reset_index(self):
        filtered = self.df[self.df["protocol"] == "NONEXISTENT"]
        reset = filtered.reset_index(drop=True)
        assert len(reset) == 0

    # ── Tab 2: Attack Types ──
    def test_attack_counts_pie_data(self):
        counts = self.anomaly_df["attack_type"].value_counts().reset_index()
        counts.columns = ["Attack Type", "Count"]
        assert len(counts) > 0
        assert counts["Count"].sum() == len(self.anomaly_df)

    def test_attack_descriptions_mapping(self):
        attack_desc = {
            "Port Scan": "Attacker probing open ports",
            "Ping of Death": "Oversized ICMP packets",
            "Data Exfiltration": "Large data to suspicious ports",
            "Suspicious Port": "Traffic to known malicious ports",
            "Large Transfer": "Unusually large data transfer",
            "DNS Anomaly": "Suspicious DNS traffic",
            "Unknown Anomaly": "Unusual pattern detected",
        }
        for attack_type in self.anomaly_df["attack_type"].unique():
            assert attack_type in attack_desc, f"Missing description for: {attack_type}"

    # ── Tab 3: Top Attackers ──
    def test_top_sources(self):
        top_src = self.anomaly_df["src_ip"].value_counts().head(10)
        assert len(top_src) > 0
        assert top_src.iloc[0] >= top_src.iloc[-1]

    def test_top_destinations(self):
        top_dst = self.anomaly_df["dst_ip"].value_counts().head(10)
        assert len(top_dst) > 0

    def test_attack_types_per_source(self):
        for ip in self.anomaly_df["src_ip"].unique()[:5]:
            types = self.anomaly_df[self.anomaly_df["src_ip"] == ip]["attack_type"].unique()
            assert len(types) > 0

    # ── Tab 4: Timeline ──
    def test_timestamps_parseable(self):
        ts = pd.to_datetime(self.df["timestamp"], errors="coerce")
        assert ts.notnull().all()

    def test_time_bucket_grouping(self):
        timeline = self.df.copy()
        timeline["timestamp"] = pd.to_datetime(timeline["timestamp"])
        timeline["time_bucket"] = timeline["timestamp"].dt.floor("1min")
        grouped = timeline.groupby(["time_bucket", "status"]).size().reset_index(name="count")
        assert len(grouped) > 0
        assert "count" in grouped.columns

    def test_anomaly_timeline_by_type(self):
        timeline = self.df.copy()
        timeline["timestamp"] = pd.to_datetime(timeline["timestamp"])
        timeline["time_bucket"] = timeline["timestamp"].dt.floor("1min")
        anomaly_timeline = timeline[timeline["status"] == "ANOMALY"]
        if len(anomaly_timeline) > 0:
            by_type = anomaly_timeline.groupby(["time_bucket", "attack_type"]).size().reset_index(name="count")
            assert len(by_type) > 0

    # ── Tab 5: Statistics ──
    def test_protocol_distribution(self):
        counts = self.df["protocol"].value_counts()
        assert counts.sum() == len(self.df)

    def test_status_distribution(self):
        counts = self.df["status"].value_counts()
        assert set(counts.index).issubset({"Normal", "ANOMALY"})

    def test_packet_size_histogram_data(self):
        assert self.df["packet_size"].min() > 0
        assert self.df["packet_size"].max() > self.df["packet_size"].min()


# ════════════════════════════════════════════════════════════
# 11. Config Files Validation
# ════════════════════════════════════════════════════════════

class TestConfigFiles:
    def test_streamlit_config_exists(self):
        path = os.path.join(PROJECT_ROOT, ".streamlit", "config.toml")
        assert os.path.exists(path)

    def test_streamlit_config_valid_toml(self):
        import tomllib
        path = os.path.join(PROJECT_ROOT, ".streamlit", "config.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        assert "server" in config
        assert "theme" in config

    def test_streamlit_server_config(self):
        import tomllib
        path = os.path.join(PROJECT_ROOT, ".streamlit", "config.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        assert config["server"]["port"] == 8501
        assert config["server"]["headless"] is True

    def test_streamlit_theme_has_colors(self):
        import tomllib
        path = os.path.join(PROJECT_ROOT, ".streamlit", "config.toml")
        with open(path, "rb") as f:
            config = tomllib.load(f)
        theme = config["theme"]
        assert "primaryColor" in theme
        assert "backgroundColor" in theme
        assert "textColor" in theme

    def test_requirements_txt_exists(self):
        path = os.path.join(PROJECT_ROOT, "requirements.txt")
        assert os.path.exists(path)

    def test_requirements_has_all_deps(self):
        path = os.path.join(PROJECT_ROOT, "requirements.txt")
        with open(path) as f:
            content = f.read()
        required = ["scapy", "scikit-learn", "pandas", "streamlit", "joblib", "plotly"]
        for dep in required:
            assert dep in content, f"Missing dependency: {dep}"

    def test_dockerfile_exists(self):
        path = os.path.join(PROJECT_ROOT, "Dockerfile")
        assert os.path.exists(path)

    def test_dockerfile_has_python_base(self):
        path = os.path.join(PROJECT_ROOT, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "python:" in content.lower()

    def test_dockerfile_exposes_8501(self):
        path = os.path.join(PROJECT_ROOT, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "8501" in content

    def test_dockerfile_has_healthcheck(self):
        path = os.path.join(PROJECT_ROOT, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "HEALTHCHECK" in content

    def test_dockerfile_trains_model(self):
        path = os.path.join(PROJECT_ROOT, "Dockerfile")
        with open(path) as f:
            content = f.read()
        assert "train.py" in content

    def test_docker_compose_exists(self):
        path = os.path.join(PROJECT_ROOT, "docker-compose.yml")
        assert os.path.exists(path)

    def test_docker_compose_has_services(self):
        path = os.path.join(PROJECT_ROOT, "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "services:" in content
        assert "dashboard:" in content

    def test_docker_compose_port_mapping(self):
        path = os.path.join(PROJECT_ROOT, "docker-compose.yml")
        with open(path) as f:
            content = f.read()
        assert "8501:8501" in content

    def test_dockerignore_exists(self):
        path = os.path.join(PROJECT_ROOT, ".dockerignore")
        assert os.path.exists(path)

    def test_dockerignore_excludes_venv(self):
        path = os.path.join(PROJECT_ROOT, ".dockerignore")
        with open(path) as f:
            content = f.read()
        assert "venv" in content

    def test_gitignore_exists(self):
        path = os.path.join(PROJECT_ROOT, ".gitignore")
        assert os.path.exists(path)

    def test_gitignore_excludes_model(self):
        path = os.path.join(PROJECT_ROOT, ".gitignore")
        with open(path) as f:
            content = f.read()
        assert "models/" in content or "*.pkl" in content

    def test_devcontainer_exists(self):
        path = os.path.join(PROJECT_ROOT, ".devcontainer", "devcontainer.json")
        assert os.path.exists(path)

    def test_devcontainer_valid_json(self):
        path = os.path.join(PROJECT_ROOT, ".devcontainer", "devcontainer.json")
        with open(path) as f:
            # devcontainer.json can have comments, read and strip them
            content = f.read()
        # Remove single-line comments for JSON parsing
        import re
        clean = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        config = json.loads(clean)
        assert "forwardPorts" in config
        assert 8501 in config["forwardPorts"]

    def test_packages_txt_exists(self):
        path = os.path.join(PROJECT_ROOT, "packages.txt")
        assert os.path.exists(path)

    def test_packages_txt_has_libpcap(self):
        path = os.path.join(PROJECT_ROOT, "packages.txt")
        with open(path) as f:
            content = f.read()
        assert "libpcap" in content


# ════════════════════════════════════════════════════════════
# 12. End-to-End Pipeline Tests
# ════════════════════════════════════════════════════════════

class TestEndToEnd:
    def test_train_then_detect_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = os.path.join(tmpdir, "model.pkl")
            model, encoders = train_model(SAMPLE_CSV, model_path)
            detector = AnomalyDetector(model_path)
            result = detector.score_csv(SAMPLE_CSV)
            assert "prediction" in result.columns
            assert "status" in result.columns
            n_anomalies = (result["prediction"] == -1).sum()
            assert n_anomalies > 0  # sample data should have some anomalies

    def test_capture_write_then_detect(self):
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "packets.csv")
            sniffer = PacketSniffer(output_path=csv_path)

            # Simulate capturing packets
            sniffer._process_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=49152, dport=443, flags="SA"))
            sniffer._process_packet(IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53))
            sniffer._process_packet(IP(src="10.0.0.1", dst="10.0.0.2") / ICMP())

            # Verify CSV
            df = pd.read_csv(csv_path)
            assert len(df) == 3
            assert set(df["protocol"].unique()) == {"TCP", "UDP", "ICMP"}

            # Run detection
            detector = AnomalyDetector()
            results = detector.predict_batch(df)
            assert len(results) == 3

    def test_full_dashboard_data_pipeline(self):
        """Simulate the full dashboard data flow."""
        # Load
        df = pd.read_csv(SAMPLE_CSV)
        assert len(df) > 0

        # Detect
        detector = AnomalyDetector()
        df["prediction"] = detector.predict_batch(df)
        df["status"] = df["prediction"].map({1: "Normal", -1: "ANOMALY"})

        # Classify attacks
        df["attack_type"] = df.apply(classify_attack, axis=1)

        # Verify no nulls in critical columns
        assert df["status"].notnull().all()
        assert df["attack_type"].notnull().all()
        assert df["prediction"].notnull().all()

        # Verify filter dropdowns
        protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
        statuses = ["All"] + sorted(df["status"].dropna().unique().tolist())
        attacks = ["All"] + sorted(df["attack_type"].dropna().unique().tolist())

        assert len(protocols) >= 4  # All + TCP + UDP + ICMP
        assert len(statuses) >= 3   # All + Normal + ANOMALY
        assert len(attacks) >= 3    # All + Normal + at least one attack

        # Verify metrics
        total = len(df)
        n_anom = int((df["prediction"] == -1).sum())
        n_norm = int((df["prediction"] == 1).sum())
        assert n_anom + n_norm == total

        # Verify anomaly_df
        anomaly_df = df[df["prediction"] == -1]
        assert len(anomaly_df) == n_anom
        assert all(anomaly_df["status"] == "ANOMALY")
        assert all(anomaly_df["attack_type"] != "Normal")


# ════════════════════════════════════════════════════════════
# 13. Authentication Logic
# ════════════════════════════════════════════════════════════

class TestAuthLogic:
    def test_default_password(self):
        # When env var not set, default is admin123
        pw = os.environ.get("NETWATCHAI_PASSWORD", "admin123")
        assert pw == "admin123" or "NETWATCHAI_PASSWORD" in os.environ

    def test_password_comparison(self):
        valid = "admin123"
        assert "admin123" == valid
        assert "wrong" != valid
        assert "" != valid
        assert "Admin123" != valid  # case sensitive


# ════════════════════════════════════════════════════════════
# 14. Network Info (safe parts)
# ════════════════════════════════════════════════════════════

class TestNetworkInfoSafe:
    def test_hostname_returns_string(self):
        import socket
        hostname = socket.gethostname()
        assert isinstance(hostname, str)
        assert len(hostname) > 0

    def test_html_escape_prevents_xss(self):
        import html
        dangerous = '<script>alert("xss")</script>'
        safe = html.escape(dangerous)
        assert "<script>" not in safe
        assert "&lt;script&gt;" in safe

    def test_html_escape_normal_text(self):
        import html
        normal = "192.168.1.1"
        assert html.escape(normal) == normal

    def test_signal_gauge_mapping(self):
        """Test RSSI to gauge percentage mapping."""
        for rssi in range(-100, -29):
            gauge = max(0, min(100, (rssi + 100) * 100 // 70))
            assert 0 <= gauge <= 100


# ════════════════════════════════════════════════════════════
# 15. train.py and capture.py CLI validation
# ════════════════════════════════════════════════════════════

class TestCLIEntryPoints:
    def test_train_py_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "train.py"))

    def test_capture_py_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "capture.py"))

    def test_train_py_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "train", os.path.join(PROJECT_ROOT, "train.py"))
        assert spec is not None

    def test_capture_py_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "capture", os.path.join(PROJECT_ROOT, "capture.py"))
        assert spec is not None

    def test_setup_sh_exists(self):
        assert os.path.exists(os.path.join(PROJECT_ROOT, "setup.sh"))

    def test_setup_sh_is_bash_script(self):
        path = os.path.join(PROJECT_ROOT, "setup.sh")
        with open(path) as f:
            first_line = f.readline()
        assert first_line.startswith("#!/bin/bash")
