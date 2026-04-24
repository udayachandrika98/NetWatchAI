"""Tests for threat_intel module — parsing, matching, cache TTL."""
import os
import tempfile
import time

FEODO_SAMPLE = """# abuse.ch Feodo Tracker IP blocklist
# Fields: IP
# Last-modified: 2026-01-01
1.2.3.4
5.6.7.8
# A malformed line
not-an-ip
"""

SPAMHAUS_SAMPLE = """; Spamhaus DROP List
; Copyright (c) 2026
192.0.2.0/24 ; SBL1001
198.51.100.0/24 ; SBL1002
not-a-cidr
"""

TOR_SAMPLE = """# Tor exit nodes
10.0.0.1
10.0.0.2
"""


def _setup_feed_dir(monkeypatch):
    import src.threat_intel as ti
    import src.utils as utils

    tmpdir = tempfile.mkdtemp()
    ioc_dir = os.path.join(tmpdir, "threat_intel")
    os.makedirs(ioc_dir, exist_ok=True)
    monkeypatch.setattr(utils, "DATA_DIR", tmpdir)
    monkeypatch.setattr(ti, "IOC_DIR", ioc_dir)
    monkeypatch.setattr(ti, "META_PATH", os.path.join(ioc_dir, "meta.json"))
    return ioc_dir


def test_parse_ip_list_skips_comments_and_garbage():
    from src.threat_intel import _parse_ip_list

    parsed = _parse_ip_list(FEODO_SAMPLE)
    assert parsed == {"1.2.3.4", "5.6.7.8"}


def test_parse_cidr_list_skips_comments_and_garbage():
    from src.threat_intel import _parse_cidr_list

    parsed = _parse_cidr_list(SPAMHAUS_SAMPLE)
    assert len(parsed) == 2
    assert str(parsed[0]) == "192.0.2.0/24"


def test_load_iocs_returns_empty_when_no_cache(monkeypatch):
    _setup_feed_dir(monkeypatch)
    from src import threat_intel

    iocs = threat_intel.load_iocs()
    assert iocs["feodo_tracker"] == set()
    assert iocs["spamhaus_drop"] == []
    assert iocs["tor_exits"] == set()


def test_check_matches_ip_in_feed(monkeypatch):
    ioc_dir = _setup_feed_dir(monkeypatch)
    from src import threat_intel

    with open(os.path.join(ioc_dir, "feodo_tracker.txt"), "w") as f:
        f.write(FEODO_SAMPLE)

    assert threat_intel.check("1.2.3.4") == ["feodo_tracker"]
    assert threat_intel.check("5.6.7.8") == ["feodo_tracker"]
    assert threat_intel.check("9.9.9.9") == []


def test_check_matches_cidr(monkeypatch):
    ioc_dir = _setup_feed_dir(monkeypatch)
    from src import threat_intel

    with open(os.path.join(ioc_dir, "spamhaus_drop.txt"), "w") as f:
        f.write(SPAMHAUS_SAMPLE)

    # 192.0.2.50 is inside 192.0.2.0/24
    assert "spamhaus_drop" in threat_intel.check("192.0.2.50")
    # 203.0.113.5 is outside both ranges
    assert threat_intel.check("203.0.113.5") == []


def test_check_multiple_feeds_match(monkeypatch):
    ioc_dir = _setup_feed_dir(monkeypatch)
    from src import threat_intel

    # Same IP present in two different feeds.
    with open(os.path.join(ioc_dir, "feodo_tracker.txt"), "w") as f:
        f.write("9.9.9.9\n")
    with open(os.path.join(ioc_dir, "tor_exits.txt"), "w") as f:
        f.write("9.9.9.9\n")

    matches = threat_intel.check("9.9.9.9")
    assert "feodo_tracker" in matches
    assert "tor_exits" in matches


def test_check_handles_invalid_ip_gracefully(monkeypatch):
    _setup_feed_dir(monkeypatch)
    from src import threat_intel

    assert threat_intel.check("not-an-ip") == []
    assert threat_intel.check("") == []
    assert threat_intel.check(None) == []


def test_stats_counts_entries(monkeypatch):
    ioc_dir = _setup_feed_dir(monkeypatch)
    from src import threat_intel

    with open(os.path.join(ioc_dir, "feodo_tracker.txt"), "w") as f:
        f.write(FEODO_SAMPLE)
    with open(os.path.join(ioc_dir, "spamhaus_drop.txt"), "w") as f:
        f.write(SPAMHAUS_SAMPLE)

    s = threat_intel.stats()
    assert s["feodo_tracker"] == 2
    assert s["spamhaus_drop"] == 2
    assert s["tor_exits"] == 0


def test_refresh_if_stale_uses_cache_when_fresh(monkeypatch):
    ioc_dir = _setup_feed_dir(monkeypatch)
    from src import threat_intel

    # Prepare cache + meta indicating "just updated"
    with open(os.path.join(ioc_dir, "feodo_tracker.txt"), "w") as f:
        f.write("1.1.1.1\n")
    with open(os.path.join(ioc_dir, "spamhaus_drop.txt"), "w") as f:
        f.write("")
    with open(os.path.join(ioc_dir, "tor_exits.txt"), "w") as f:
        f.write("")

    import json as _json
    with open(threat_intel.META_PATH, "w") as f:
        _json.dump({
            fid: {"updated_at": time.time(), "url": "x"}
            for fid in threat_intel.FEEDS
        }, f)

    called = {"count": 0}

    def fake_fetch(url):
        called["count"] += 1
        return ""

    monkeypatch.setattr(threat_intel, "_fetch", fake_fetch)
    result = threat_intel.refresh_if_stale(force=False)
    assert called["count"] == 0
    for fid in threat_intel.FEEDS:
        assert result[fid]["status"] == "cached"


def test_refresh_if_stale_downloads_when_forced(monkeypatch):
    _setup_feed_dir(monkeypatch)
    from src import threat_intel

    fetched = {"urls": []}

    def fake_fetch(url):
        fetched["urls"].append(url)
        return "1.1.1.1\n"

    monkeypatch.setattr(threat_intel, "_fetch", fake_fetch)
    result = threat_intel.refresh_if_stale(force=True)
    assert len(fetched["urls"]) == len(threat_intel.FEEDS)
    for fid in threat_intel.FEEDS:
        assert result[fid]["status"] == "refreshed"


def test_refresh_reports_failures(monkeypatch):
    _setup_feed_dir(monkeypatch)
    from src import threat_intel

    def flaky_fetch(url):
        raise OSError("simulated network failure")

    monkeypatch.setattr(threat_intel, "_fetch", flaky_fetch)
    result = threat_intel.refresh_if_stale(force=True)
    for fid in threat_intel.FEEDS:
        assert result[fid]["status"] == "failed"
        assert "error" in result[fid]
