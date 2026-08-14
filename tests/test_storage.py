"""Tests for the SQLite persistence layer."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest


def _utcnow_iso() -> str:
    """ISO timestamp in UTC. Replaces the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


@pytest.fixture(autouse=True)
def _tmp_db(monkeypatch):
    """Redirect DATA_DIR to a tmp path so tests don't touch the real DB."""
    tmpdir = tempfile.mkdtemp()
    import src.storage as storage_mod
    import src.utils as utils_mod

    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(storage_mod, "DB_PATH", os.path.join(tmpdir, "test.db"))
    storage_mod.init_db()
    yield tmpdir


def test_record_and_list_alerts():
    from src import storage

    storage.record_alerts([{
        "ts": _utcnow_iso(),
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": 443,
        "dst_port": 80,
        "packet_size": 128,
        "flags": "S",
        "attack_type": "Port Scan",
        "dedup_key": "x",
    }])
    assert len(storage.list_alerts()) == 1


def test_dedup_key_stable_within_window():
    from src import storage

    k1 = storage.dedup_key("1.1.1.1", "Port Scan", 300)
    k2 = storage.dedup_key("1.1.1.1", "Port Scan", 300)
    assert k1 == k2


def test_alert_exists_detects_duplicate():
    from src import storage

    row = {
        "ts": _utcnow_iso(), "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1",
        "protocol": "TCP", "src_port": 1, "dst_port": 2, "packet_size": 10, "flags": "S",
        "attack_type": "Port Scan", "dedup_key": "k-abc",
    }
    storage.record_alerts([row])
    assert storage.alert_exists("k-abc")
    assert not storage.alert_exists("k-def")


def test_mark_false_positive_hides_alert():
    from src import storage

    storage.record_alerts([{
        "ts": _utcnow_iso(), "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4",
        "protocol": "TCP", "src_port": 1, "dst_port": 2, "packet_size": 10, "flags": "S",
        "attack_type": "Port Scan", "dedup_key": "k-fp",
    }])
    alert_id = storage.list_alerts()[0]["id"]
    storage.mark_false_positive(alert_id)
    assert storage.list_alerts(include_fp=False) == []
    assert len(storage.list_alerts(include_fp=True)) == 1


def test_allowlist_add_and_remove():
    from src import storage

    storage.add_allowlist("5.5.5.5", note="internal scanner")
    assert storage.is_allowlisted("5.5.5.5")
    assert not storage.is_allowlisted("6.6.6.6")
    storage.remove_allowlist("5.5.5.5")
    assert not storage.is_allowlisted("5.5.5.5")


def test_audit_log_append_and_read():
    from src import storage

    storage.log_audit("user", "login", "success")
    storage.log_audit("user", "settings_update", "alerts")
    rows = storage.list_audit()
    assert len(rows) == 2
    assert rows[0]["action"] == "settings_update"  # DESC order


def test_purge_older_than_removes_old_rows():
    from src import storage

    old_ts = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40)).isoformat()
    fresh_ts = _utcnow_iso()
    storage.record_alerts([
        {"ts": old_ts, "src_ip": "7.7.7.7", "dst_ip": "", "protocol": "",
         "src_port": 0, "dst_port": 0, "packet_size": 0, "flags": "",
         "attack_type": "X", "dedup_key": "old"},
        {"ts": fresh_ts, "src_ip": "8.8.8.8", "dst_ip": "", "protocol": "",
         "src_port": 0, "dst_port": 0, "packet_size": 0, "flags": "",
         "attack_type": "X", "dedup_key": "new"},
    ])
    removed = storage.purge_older_than(30)
    assert removed == 1
    remaining = storage.list_alerts(days=365)
    assert len(remaining) == 1
    assert remaining[0]["src_ip"] == "8.8.8.8"
