"""Tests for config and auth modules."""
import os
import tempfile


def test_load_config_writes_defaults(monkeypatch):
    import src.config as cfg_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(cfg_mod, "CONFIG_PATH", os.path.join(tmpdir, "c.json"))

    cfg = cfg_mod.load_config()
    assert "alerts" in cfg
    assert cfg["retention_days"] == 30
    assert os.path.exists(cfg_mod.CONFIG_PATH)


def test_save_and_load_roundtrip(monkeypatch):
    import src.config as cfg_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(cfg_mod, "CONFIG_PATH", os.path.join(tmpdir, "c.json"))

    cfg = cfg_mod.load_config()
    cfg["alerts"]["discord_webhook"] = "https://discord.example/webhook"
    cfg_mod.save_config(cfg)

    reread = cfg_mod.load_config()
    assert reread["alerts"]["discord_webhook"] == "https://discord.example/webhook"
    # Defaults still merged
    assert reread["alerts"]["min_severity"] == "high"


def test_auth_env_override(monkeypatch):
    from src import auth

    monkeypatch.setenv("NETWATCHAI_PASSWORD", "env-password")
    assert auth.is_setup()
    assert auth.verify("env-password")
    assert not auth.verify("wrong")


def test_auth_not_setup_without_file_or_env(monkeypatch):
    import src.auth as auth_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.delenv("NETWATCHAI_PASSWORD", raising=False)
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(auth_mod, "PASSWORD_FILE", os.path.join(tmpdir, ".pw"))
    assert not auth_mod.is_setup()
    assert not auth_mod.verify("anything")


def test_auth_set_and_verify(monkeypatch):
    import src.auth as auth_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.delenv("NETWATCHAI_PASSWORD", raising=False)
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(auth_mod, "PASSWORD_FILE", os.path.join(tmpdir, ".pw"))

    auth_mod.set_password("my-chosen-password")
    assert auth_mod.is_setup()
    assert auth_mod.verify("my-chosen-password")
    assert not auth_mod.verify("wrong")


def test_auth_set_password_rejects_short(monkeypatch):
    import pytest as _pytest

    import src.auth as auth_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(auth_mod, "PASSWORD_FILE", os.path.join(tmpdir, ".pw"))
    with _pytest.raises(ValueError):
        auth_mod.set_password("abc")


def test_auth_reset_clears_password(monkeypatch):
    import src.auth as auth_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    monkeypatch.delenv("NETWATCHAI_PASSWORD", raising=False)
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(auth_mod, "PASSWORD_FILE", os.path.join(tmpdir, ".pw"))

    auth_mod.set_password("initial-password")
    assert auth_mod.is_setup()
    auth_mod.reset()
    assert not auth_mod.is_setup()


def test_auth_legacy_plaintext_migrates(monkeypatch):
    """Old versions wrote plaintext; we migrate on first read."""
    import src.auth as auth_mod
    import src.utils as utils_mod

    tmpdir = tempfile.mkdtemp()
    pw_path = os.path.join(tmpdir, ".pw")
    monkeypatch.delenv("NETWATCHAI_PASSWORD", raising=False)
    monkeypatch.setattr(utils_mod, "DATA_DIR", tmpdir)
    monkeypatch.setattr(auth_mod, "PASSWORD_FILE", pw_path)

    # Simulate an old plaintext file.
    with open(pw_path, "w") as f:
        f.write("legacyPass123")

    assert auth_mod.verify("legacyPass123")
    # After migration, the file should be the hashed format.
    with open(pw_path, "rb") as f:
        assert len(f.read()) == 16 + 32


def test_alerting_severity_from_pct():
    from src import alerting

    assert alerting.severity_from_pct(0) == "low"
    assert alerting.severity_from_pct(4.9) == "low"
    assert alerting.severity_from_pct(10) == "medium"
    assert alerting.severity_from_pct(20) == "high"
    assert alerting.severity_from_pct(50) == "critical"


def test_alerting_dispatch_skips_below_severity():
    from src import alerting

    cfg = {
        "alerts": {
            "discord_webhook": "https://discord.example/webhook",
            "slack_webhook": "", "min_severity": "high",
            "email": {},
        },
    }
    result = alerting.dispatch(cfg, title="t", body="b", severity="low")
    assert result.get("skipped") is True


def test_alerting_dispatch_empty_config_returns_empty():
    from src import alerting

    cfg = {"alerts": {"min_severity": "low"}}
    result = alerting.dispatch(cfg, title="t", body="b", severity="critical")
    assert result == {}
