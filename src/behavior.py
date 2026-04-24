"""Stateful behavioral detectors.

Individual packets are rarely suspicious on their own; patterns across packets
are. These functions look at the whole packet dataframe and return the set of
source IPs exhibiting a given bad pattern, so callers can tag rows accordingly.

All detectors are pure functions — no side effects, no state between calls.
"""
from __future__ import annotations

import pandas as pd

# Reasonable defaults tuned for dashboard use. Smaller thresholds than an
# enterprise IDS because users expect to SEE detections on sample data.
DEFAULT_PORT_SCAN_WINDOW_S = 60
DEFAULT_PORT_SCAN_THRESHOLD = 15

DEFAULT_BRUTE_FORCE_WINDOW_S = 60
DEFAULT_BRUTE_FORCE_THRESHOLD = 20

DEFAULT_DOS_WINDOW_S = 10
DEFAULT_DOS_THRESHOLD = 100


def _with_time_bucket(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    """Add a 'bucket' column with the packet's timestamp floored to window_seconds.
    If timestamps are missing, returns a copy with a constant bucket so callers
    can still group without crashing."""
    work = df.copy()
    if "timestamp" in work.columns:
        # format="ISO8601" handles mixed-precision strings (with and without
        # microseconds) in the same series — pandas 2.x otherwise locks onto
        # the first row's format and coerces the rest to NaT.
        try:
            work["ts"] = pd.to_datetime(work["timestamp"], format="ISO8601", errors="coerce")
        except (ValueError, TypeError):
            work["ts"] = pd.to_datetime(work["timestamp"], errors="coerce")
        work = work.dropna(subset=["ts"])
        if work.empty:
            work["bucket"] = pd.NaT
        else:
            work["bucket"] = work["ts"].dt.floor(f"{window_seconds}s")
    else:
        work["bucket"] = 0
    return work


def detect_port_scans(
    df: pd.DataFrame,
    window_seconds: int = DEFAULT_PORT_SCAN_WINDOW_S,
    min_distinct_ports: int = DEFAULT_PORT_SCAN_THRESHOLD,
) -> set[str]:
    """Return source IPs that hit >= min_distinct_ports unique destination ports
    within any window_seconds window. Looks at TCP SYN-only packets."""
    if df.empty or "src_ip" not in df.columns or "dst_port" not in df.columns:
        return set()

    syn = df
    if "protocol" in df.columns and "flags" in df.columns:
        syn = df[
            (df["protocol"].astype(str).str.upper() == "TCP")
            & (df["flags"].astype(str) == "S")
        ]
    if syn.empty:
        return set()

    work = _with_time_bucket(syn, window_seconds)
    grouped = work.groupby(["src_ip", "bucket"])["dst_port"].nunique()
    return {
        str(src) for (src, _bucket), count in grouped.items()
        if count >= min_distinct_ports
    }


def detect_brute_force(
    df: pd.DataFrame,
    window_seconds: int = DEFAULT_BRUTE_FORCE_WINDOW_S,
    min_hits: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
) -> set[str]:
    """Return source IPs that made >= min_hits connections to the SAME
    (dst_ip, dst_port) within any window_seconds window.
    Catches SSH / RDP / login brute-force and credential stuffing."""
    required = {"src_ip", "dst_ip", "dst_port"}
    if df.empty or not required.issubset(df.columns):
        return set()

    work = _with_time_bucket(df, window_seconds)
    grouped = work.groupby(["src_ip", "dst_ip", "dst_port", "bucket"]).size()
    return {str(key[0]) for key, count in grouped.items() if count >= min_hits}


def detect_dos_flooders(
    df: pd.DataFrame,
    window_seconds: int = DEFAULT_DOS_WINDOW_S,
    min_packets: int = DEFAULT_DOS_THRESHOLD,
) -> set[str]:
    """Return source IPs that sent >= min_packets total packets in any
    window_seconds window. A crude but effective flood / DoS signal."""
    if df.empty or "src_ip" not in df.columns:
        return set()

    work = _with_time_bucket(df, window_seconds)
    grouped = work.groupby(["src_ip", "bucket"]).size()
    return {str(src) for (src, _bucket), count in grouped.items() if count >= min_packets}


def enrich(
    df: pd.DataFrame,
    *,
    port_scan_threshold: int = DEFAULT_PORT_SCAN_THRESHOLD,
    port_scan_window: int = DEFAULT_PORT_SCAN_WINDOW_S,
    brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD,
    brute_force_window: int = DEFAULT_BRUTE_FORCE_WINDOW_S,
    dos_threshold: int = DEFAULT_DOS_THRESHOLD,
    dos_window: int = DEFAULT_DOS_WINDOW_S,
) -> dict[str, set[str]]:
    """Run all behavioral detectors and return {pattern_name: set_of_src_ips}."""
    return {
        "Port Scan": detect_port_scans(df, port_scan_window, port_scan_threshold),
        "Brute Force": detect_brute_force(df, brute_force_window, brute_force_threshold),
        "DoS Flood": detect_dos_flooders(df, dos_window, dos_threshold),
    }
