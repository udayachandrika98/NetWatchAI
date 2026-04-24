"""Tests for stateful behavioral detectors."""
from datetime import datetime, timedelta

import pandas as pd


def _ts(seconds_offset: float) -> str:
    return (datetime(2026, 1, 1, 12, 0, 0) + timedelta(seconds=seconds_offset)).isoformat()


def _packet(src, dst, dport, *, t=0.0, proto="TCP", flags="S", size=60):
    return {
        "timestamp": _ts(t),
        "src_ip": src, "dst_ip": dst,
        "src_port": 50000, "dst_port": dport,
        "protocol": proto, "flags": flags, "packet_size": size,
    }


# ── Port scan ─────────────────────────────────────────────

def test_port_scan_detected_when_threshold_met():
    from src.behavior import detect_port_scans

    rows = [_packet("1.1.1.1", "10.0.0.5", p, t=i * 0.1) for i, p in enumerate(range(1, 21))]
    df = pd.DataFrame(rows)
    assert detect_port_scans(df, window_seconds=60, min_distinct_ports=15) == {"1.1.1.1"}


def test_port_scan_ignored_below_threshold():
    from src.behavior import detect_port_scans

    rows = [_packet("1.1.1.1", "10.0.0.5", p, t=i * 0.1) for i, p in enumerate(range(1, 6))]
    df = pd.DataFrame(rows)
    assert detect_port_scans(df, window_seconds=60, min_distinct_ports=15) == set()


def test_port_scan_requires_syn_only_packets():
    from src.behavior import detect_port_scans

    # All packets are ACK, not SYN — should not be flagged as port scan.
    rows = [_packet("1.1.1.1", "10.0.0.5", p, t=i * 0.1, flags="A")
            for i, p in enumerate(range(1, 21))]
    df = pd.DataFrame(rows)
    assert detect_port_scans(df, min_distinct_ports=15) == set()


def test_port_scan_repeated_same_port_not_counted():
    from src.behavior import detect_port_scans

    # 30 hits to the SAME port — that's brute force, not a scan.
    rows = [_packet("1.1.1.1", "10.0.0.5", 22, t=i * 0.1) for i in range(30)]
    df = pd.DataFrame(rows)
    assert detect_port_scans(df, min_distinct_ports=15) == set()


def test_port_scan_splits_across_time_windows():
    from src.behavior import detect_port_scans

    # 10 ports at t=0s, 10 more ports at t=70s — different 60s buckets.
    rows = [_packet("1.1.1.1", "10.0.0.5", p, t=0) for p in range(1, 11)]
    rows += [_packet("1.1.1.1", "10.0.0.5", p, t=70) for p in range(11, 21)]
    df = pd.DataFrame(rows)
    # Each bucket has only 10 distinct ports — below threshold 15.
    assert detect_port_scans(df, window_seconds=60, min_distinct_ports=15) == set()


def test_port_scan_multiple_attackers():
    from src.behavior import detect_port_scans

    rows = [_packet("1.1.1.1", "10.0.0.5", p) for p in range(1, 21)]
    rows += [_packet("2.2.2.2", "10.0.0.6", p) for p in range(1, 21)]
    rows += [_packet("3.3.3.3", "10.0.0.7", 22)]  # not scanning
    df = pd.DataFrame(rows)
    result = detect_port_scans(df, min_distinct_ports=15)
    assert result == {"1.1.1.1", "2.2.2.2"}


# ── Brute force ───────────────────────────────────────────

def test_brute_force_detected_same_dst_port():
    from src.behavior import detect_brute_force

    rows = [_packet("1.1.1.1", "10.0.0.5", 22, t=i * 0.1) for i in range(25)]
    df = pd.DataFrame(rows)
    assert detect_brute_force(df, min_hits=20) == {"1.1.1.1"}


def test_brute_force_requires_same_target():
    from src.behavior import detect_brute_force

    # 25 connections but to different (dst_ip, dst_port) pairs → not brute force.
    rows = [_packet("1.1.1.1", f"10.0.0.{i}", 22, t=i * 0.1) for i in range(25)]
    df = pd.DataFrame(rows)
    assert detect_brute_force(df, min_hits=20) == set()


# ── DoS flood ─────────────────────────────────────────────

def test_dos_flood_detected_on_high_volume():
    from src.behavior import detect_dos_flooders

    rows = [_packet("1.1.1.1", "10.0.0.5", 80, t=i * 0.05) for i in range(120)]
    df = pd.DataFrame(rows)
    assert detect_dos_flooders(df, window_seconds=10, min_packets=100) == {"1.1.1.1"}


def test_dos_flood_ignored_below_threshold():
    from src.behavior import detect_dos_flooders

    rows = [_packet("1.1.1.1", "10.0.0.5", 80, t=i * 0.05) for i in range(50)]
    df = pd.DataFrame(rows)
    assert detect_dos_flooders(df, window_seconds=10, min_packets=100) == set()


# ── Empty / degenerate cases ──────────────────────────────

def test_empty_dataframe_returns_empty_set():
    from src.behavior import detect_brute_force, detect_dos_flooders, detect_port_scans

    empty = pd.DataFrame()
    assert detect_port_scans(empty) == set()
    assert detect_brute_force(empty) == set()
    assert detect_dos_flooders(empty) == set()


def test_missing_columns_returns_empty_set():
    from src.behavior import detect_port_scans

    df = pd.DataFrame([{"ts": "x", "data": 1}])
    assert detect_port_scans(df) == set()


def test_works_without_timestamps():
    """If timestamps are missing, everything is treated as one bucket."""
    from src.behavior import detect_port_scans

    rows = [{
        "src_ip": "1.1.1.1", "dst_ip": "10.0.0.5",
        "src_port": 50000, "dst_port": p,
        "protocol": "TCP", "flags": "S", "packet_size": 60,
    } for p in range(1, 21)]
    df = pd.DataFrame(rows)
    assert detect_port_scans(df, min_distinct_ports=15) == {"1.1.1.1"}


# ── Combined API ──────────────────────────────────────────

def test_enrich_runs_all_detectors():
    from src.behavior import enrich

    # One scanner, one brute-forcer, one clean source
    rows = [_packet("1.1.1.1", "10.0.0.5", p) for p in range(1, 21)]  # scanner
    rows += [_packet("2.2.2.2", "10.0.0.6", 22) for _ in range(25)]   # brute
    rows += [_packet("3.3.3.3", "10.0.0.7", 80)]                      # clean
    df = pd.DataFrame(rows)
    result = enrich(df)
    assert "1.1.1.1" in result["Port Scan"]
    assert "2.2.2.2" in result["Brute Force"]
    assert "3.3.3.3" not in result["Port Scan"]
    assert "3.3.3.3" not in result["Brute Force"]
