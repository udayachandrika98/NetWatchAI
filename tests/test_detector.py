"""Tests for src/detector.py — anomaly detection."""

import os
import tempfile
import pandas as pd
import pytest

from src.model import train_model
from src.detector import AnomalyDetector
from src.utils import SAMPLE_CSV, MODEL_PATH


@pytest.fixture(scope="module")
def trained_model_path(tmp_path_factory):
    """Train a model once for all tests in this module."""
    path = str(tmp_path_factory.mktemp("models") / "model.pkl")
    train_model(csv_path=SAMPLE_CSV, save_path=path)
    return path


@pytest.fixture(scope="module")
def detector(trained_model_path):
    return AnomalyDetector(model_path=trained_model_path)


class TestAnomalyDetector:

    def test_loads_without_error(self, trained_model_path):
        det = AnomalyDetector(model_path=trained_model_path)
        assert det.model is not None
        assert det.encoders is not None

    def test_predict_single_normal(self, detector):
        features = {
            "protocol": "TCP",
            "src_port": 443,
            "dst_port": 49152,
            "packet_size": 120,
            "flags": "SA",
        }
        result = detector.predict_single(features)
        assert result in (1, -1)

    def test_predict_single_suspicious(self, detector):
        features = {
            "protocol": "TCP",
            "src_port": 4444,
            "dst_port": 31337,
            "packet_size": 9999,
            "flags": "S",
        }
        result = detector.predict_single(features)
        assert result in (1, -1)

    def test_predict_batch(self, detector):
        df = pd.read_csv(SAMPLE_CSV)
        results = detector.predict_batch(df)
        assert len(results) == len(df)
        assert all(r in (1, -1) for r in results)

    def test_predict_batch_does_not_modify_original(self, detector):
        df = pd.read_csv(SAMPLE_CSV)
        original_cols = list(df.columns)
        detector.predict_batch(df)
        assert list(df.columns) == original_cols

    def test_unseen_protocol_handled(self, detector):
        """Unknown protocols should not crash — mapped to first known class."""
        df = pd.DataFrame([{
            "protocol": "QUIC_UNKNOWN",
            "src_port": 443,
            "dst_port": 50000,
            "packet_size": 200,
            "flags": "NONE",
        }])
        results = detector.predict_batch(df)
        assert len(results) == 1
        assert results[0] in (1, -1)

    def test_unseen_flags_handled(self, detector):
        """Unknown flags should not crash."""
        df = pd.DataFrame([{
            "protocol": "TCP",
            "src_port": 80,
            "dst_port": 12345,
            "packet_size": 100,
            "flags": "XYZUNKNOWN",
        }])
        results = detector.predict_batch(df)
        assert len(results) == 1

    def test_empty_flags_handled(self, detector):
        """Empty string flags should be converted to NONE."""
        df = pd.DataFrame([{
            "protocol": "UDP",
            "src_port": 53,
            "dst_port": 1234,
            "packet_size": 64,
            "flags": "",
        }])
        results = detector.predict_batch(df)
        assert len(results) == 1

    def test_nan_flags_handled(self, detector):
        """NaN flags should be converted to NONE."""
        df = pd.DataFrame([{
            "protocol": "UDP",
            "src_port": 53,
            "dst_port": 1234,
            "packet_size": 64,
            "flags": None,
        }])
        results = detector.predict_batch(df)
        assert len(results) == 1

    def test_score_csv(self, detector):
        result_df = detector.score_csv(SAMPLE_CSV)
        assert "prediction" in result_df.columns
        assert "status" in result_df.columns
        assert set(result_df["status"].unique()).issubset({"Normal", "ANOMALY"})

    def test_invalid_model_path_raises(self):
        with pytest.raises(Exception):
            AnomalyDetector(model_path="/nonexistent/model.pkl")
