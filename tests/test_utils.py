"""Tests for src/utils.py — paths, logging, directory creation."""

import os
import tempfile
import shutil
import pytest

from src.utils import (
    PROJECT_ROOT,
    DATA_DIR,
    MODELS_DIR,
    PACKETS_CSV,
    SAMPLE_CSV,
    MODEL_PATH,
    CSV_COLUMNS,
    setup_logger,
    ensure_dirs,
)


# ── Path constants ──────────────────────────────

class TestPaths:
    def test_project_root_exists(self):
        assert os.path.isdir(PROJECT_ROOT)

    def test_data_dir_under_project_root(self):
        assert DATA_DIR == os.path.join(PROJECT_ROOT, "data")

    def test_models_dir_under_project_root(self):
        assert MODELS_DIR == os.path.join(PROJECT_ROOT, "models")

    def test_packets_csv_path(self):
        assert PACKETS_CSV == os.path.join(DATA_DIR, "packets.csv")

    def test_sample_csv_path(self):
        assert SAMPLE_CSV == os.path.join(DATA_DIR, "sample_packets.csv")

    def test_model_path(self):
        assert MODEL_PATH == os.path.join(MODELS_DIR, "model.pkl")

    def test_sample_csv_exists(self):
        """The sample data file must be present for the app to work."""
        assert os.path.isfile(SAMPLE_CSV), f"Missing: {SAMPLE_CSV}"

    def test_csv_columns_complete(self):
        expected = ["timestamp", "src_ip", "dst_ip", "protocol",
                    "src_port", "dst_port", "packet_size", "flags"]
        assert CSV_COLUMNS == expected

    def test_csv_columns_no_duplicates(self):
        assert len(CSV_COLUMNS) == len(set(CSV_COLUMNS))


# ── Logger ──────────────────────────────────────

class TestLogger:
    def test_returns_logger(self):
        log = setup_logger("test_logger_1")
        assert log.name == "test_logger_1"

    def test_has_handler(self):
        log = setup_logger("test_logger_2")
        assert len(log.handlers) >= 1

    def test_no_duplicate_handlers(self):
        """Calling setup_logger twice should not add duplicate handlers."""
        log = setup_logger("test_logger_3")
        n1 = len(log.handlers)
        setup_logger("test_logger_3")
        assert len(log.handlers) == n1

    def test_custom_level(self):
        import logging
        log = setup_logger("test_logger_4", level=logging.DEBUG)
        assert log.level == logging.DEBUG


# ── ensure_dirs ─────────────────────────────────

class TestEnsureDirs:
    def test_creates_data_and_models_dirs(self, monkeypatch, tmp_path):
        """ensure_dirs should create data/ and models/ if missing."""
        fake_data = str(tmp_path / "data")
        fake_models = str(tmp_path / "models")
        monkeypatch.setattr("src.utils.DATA_DIR", fake_data)
        monkeypatch.setattr("src.utils.MODELS_DIR", fake_models)
        ensure_dirs()
        assert os.path.isdir(fake_data)
        assert os.path.isdir(fake_models)

    def test_idempotent(self, monkeypatch, tmp_path):
        """Calling ensure_dirs twice should not raise."""
        fake_data = str(tmp_path / "data")
        fake_models = str(tmp_path / "models")
        monkeypatch.setattr("src.utils.DATA_DIR", fake_data)
        monkeypatch.setattr("src.utils.MODELS_DIR", fake_models)
        ensure_dirs()
        ensure_dirs()  # second call should not error
        assert os.path.isdir(fake_data)


class TestNoUnusedImports:
    def test_utils_no_unused_datetime_import(self):
        """utils.py should not import datetime (it was unused)."""
        import inspect
        import src.utils
        source = inspect.getsource(src.utils)
        assert "from datetime import datetime" not in source
