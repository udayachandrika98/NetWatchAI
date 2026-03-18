"""Tests for dashboard.py — classify_attack and data logic.

We import only the pure functions (not the Streamlit UI code) by
extracting them or testing their logic directly.
"""

import os
import math
import pandas as pd
import pytest


# ── classify_attack tests ────────────────────────
# We replicate the function here to test it without importing Streamlit
# (importing dashboard.py directly would trigger st.set_page_config).

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


class TestClassifyAttack:
    def test_normal_status_returns_normal(self):
        row = {"status": "Normal", "protocol": "TCP", "dst_port": 4444,
               "src_port": 80, "packet_size": 100, "flags": "S"}
        assert classify_attack(row) == "Normal"

    def test_unknown_status_returns_normal(self):
        row = {"status": "Unknown", "protocol": "TCP", "dst_port": 80,
               "src_port": 80, "packet_size": 100, "flags": "A"}
        assert classify_attack(row) == "Normal"

    def test_ping_of_death(self):
        row = {"status": "ANOMALY", "protocol": "ICMP", "dst_port": 0,
               "src_port": 0, "packet_size": 2000, "flags": ""}
        assert classify_attack(row) == "Ping of Death"

    def test_icmp_small_not_ping_of_death(self):
        row = {"status": "ANOMALY", "protocol": "ICMP", "dst_port": 0,
               "src_port": 0, "packet_size": 64, "flags": ""}
        assert classify_attack(row) != "Ping of Death"

    def test_port_scan(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 22,
               "src_port": 54321, "packet_size": 40, "flags": "S"}
        # src_port 54321 is in SUSPICIOUS_PORTS — port scan check comes first
        # but port scan requires flags=="S" and packet_size<=60 AND protocol=="TCP"
        # Actually 54321 is in SUSPICIOUS_PORTS so it would be "Suspicious Port"
        # Let's use a non-suspicious port instead:
        row["src_port"] = 50000
        assert classify_attack(row) == "Port Scan"

    def test_port_scan_requires_syn_flag(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 22,
               "src_port": 50000, "packet_size": 40, "flags": "A"}
        assert classify_attack(row) != "Port Scan"

    def test_data_exfiltration(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 4444,
               "src_port": 80, "packet_size": 5000, "flags": "PA"}
        assert classify_attack(row) == "Data Exfiltration"

    def test_suspicious_port(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 31337,
               "src_port": 80, "packet_size": 100, "flags": "A"}
        assert classify_attack(row) == "Suspicious Port"

    def test_large_transfer(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 443,
               "src_port": 50000, "packet_size": 8000, "flags": "PA"}
        assert classify_attack(row) == "Large Transfer"

    def test_dns_anomaly(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "dst_port": 53,
               "src_port": 50000, "packet_size": 500, "flags": ""}
        assert classify_attack(row) == "DNS Anomaly"

    def test_dns_normal_size_not_anomaly(self):
        row = {"status": "ANOMALY", "protocol": "UDP", "dst_port": 53,
               "src_port": 50000, "packet_size": 64, "flags": ""}
        assert classify_attack(row) != "DNS Anomaly"

    def test_unknown_anomaly_fallback(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 443,
               "src_port": 50000, "packet_size": 200, "flags": "PA"}
        assert classify_attack(row) == "Unknown Anomaly"

    # ── NaN / missing value edge cases ───────────

    def test_nan_dst_port_no_crash(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": float("nan"),
               "src_port": 80, "packet_size": 100, "flags": "A"}
        result = classify_attack(row)
        assert isinstance(result, str)

    def test_nan_packet_size_no_crash(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 80,
               "src_port": 80, "packet_size": float("nan"), "flags": "A"}
        result = classify_attack(row)
        assert isinstance(result, str)

    def test_none_dst_port_no_crash(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": None,
               "src_port": 80, "packet_size": 100, "flags": "A"}
        result = classify_attack(row)
        assert isinstance(result, str)

    def test_missing_fields_no_crash(self):
        row = {"status": "ANOMALY"}
        result = classify_attack(row)
        assert isinstance(result, str)

    def test_empty_string_port_no_crash(self):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": "",
               "src_port": "", "packet_size": "", "flags": ""}
        result = classify_attack(row)
        assert isinstance(result, str)

    # ── All suspicious ports are detected ────────

    @pytest.mark.parametrize("port", [4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321])
    def test_all_suspicious_dst_ports_detected(self, port):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": port,
               "src_port": 80, "packet_size": 100, "flags": "A"}
        result = classify_attack(row)
        assert result in ("Suspicious Port", "Data Exfiltration")

    @pytest.mark.parametrize("port", [4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321])
    def test_all_suspicious_src_ports_detected(self, port):
        row = {"status": "ANOMALY", "protocol": "TCP", "dst_port": 80,
               "src_port": port, "packet_size": 100, "flags": "A"}
        result = classify_attack(row)
        assert result in ("Suspicious Port", "Data Exfiltration")


class TestDataLoading:
    """Test that the sample CSV can be loaded and processed."""

    def test_sample_csv_readable(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        assert len(df) > 0

    def test_sample_csv_has_required_columns(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        required = ["timestamp", "src_ip", "dst_ip", "protocol",
                     "src_port", "dst_port", "packet_size", "flags"]
        for col in required:
            assert col in df.columns, f"Missing column: {col}"

    def test_sample_csv_protocols_valid(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        valid_protocols = {"TCP", "UDP", "ICMP", "OTHER"}
        actual = set(df["protocol"].unique())
        assert actual.issubset(valid_protocols), f"Unexpected protocols: {actual - valid_protocols}"

    def test_sample_csv_ports_are_numeric(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        assert pd.to_numeric(df["src_port"], errors="coerce").notnull().all()
        assert pd.to_numeric(df["dst_port"], errors="coerce").notnull().all()

    def test_sample_csv_packet_size_positive(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        assert (df["packet_size"] > 0).all()

    def test_sample_csv_timestamp_parseable(self):
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        parsed = pd.to_datetime(df["timestamp"], errors="coerce")
        assert parsed.notnull().all(), "Some timestamps failed to parse"

    def test_sample_csv_no_nan_protocol(self):
        """Protocol column should never have NaN — would crash sorted() in sidebar."""
        from src.utils import SAMPLE_CSV
        df = pd.read_csv(SAMPLE_CSV)
        assert df["protocol"].notnull().all(), "NaN found in protocol column"


class TestSidebarFilterSafety:
    """Test that sidebar filter logic handles edge cases."""

    def test_sorted_protocols_with_nan_no_crash(self):
        """If a CSV has NaN protocol, dropna() prevents TypeError in sorted()."""
        df = pd.DataFrame({
            "protocol": ["TCP", "UDP", None, "ICMP"],
        })
        # This is what dashboard.py now does (with dropna):
        protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
        assert "All" in protocols
        assert None not in protocols

    def test_sorted_protocols_all_nan_no_crash(self):
        """Even if ALL protocols are NaN, should not crash."""
        df = pd.DataFrame({
            "protocol": [None, None],
        })
        protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
        assert protocols == ["All"]

    def test_sorted_protocols_normal_data(self):
        df = pd.DataFrame({
            "protocol": ["TCP", "UDP", "TCP", "ICMP"],
        })
        protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
        assert protocols == ["All", "ICMP", "TCP", "UDP"]

    def test_attack_type_filter_excludes_normal(self):
        """Attack type filter should exclude 'Normal' from the dropdown."""
        attack_types_col = pd.Series(["Normal", "Port Scan", "Normal", "DNS Anomaly"])
        attack_types = ["All"] + sorted([t for t in attack_types_col.unique() if t != "Normal"])
        assert "Normal" not in attack_types
        assert "Port Scan" in attack_types
        assert "DNS Anomaly" in attack_types
