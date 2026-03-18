"""Tests for src/model.py — training pipeline."""

import os
import tempfile
import pandas as pd
import pytest

from src.model import load_and_prepare_data, train_model
from src.utils import SAMPLE_CSV


class TestLoadAndPrepareData:
    def test_loads_sample_csv(self):
        features, encoders, labels = load_and_prepare_data(SAMPLE_CSV)
        assert isinstance(features, pd.DataFrame)
        assert len(features) > 0

    def test_feature_columns(self):
        features, _, _ = load_and_prepare_data(SAMPLE_CSV)
        expected_cols = ["protocol", "src_port", "dst_port", "packet_size", "flags"]
        assert list(features.columns) == expected_cols

    def test_encoders_created(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        assert "protocol" in encoders
        assert "flags" in encoders

    def test_protocol_encoder_has_classes(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        classes = list(encoders["protocol"].classes_)
        assert len(classes) > 0

    def test_flags_encoder_has_classes(self):
        _, encoders, _ = load_and_prepare_data(SAMPLE_CSV)
        classes = list(encoders["flags"].classes_)
        assert len(classes) > 0
        assert "NONE" in classes  # empty flags should be encoded as NONE

    def test_no_nan_in_features(self):
        features, _, _ = load_and_prepare_data(SAMPLE_CSV)
        assert features.isnull().sum().sum() == 0

    def test_labels_returned(self):
        """sample_packets.csv has a 'label' column."""
        _, _, labels = load_and_prepare_data(SAMPLE_CSV)
        assert labels is not None
        assert len(labels) > 0

    def test_handles_empty_flags(self):
        """CSV rows with empty flags should be converted to 'NONE'."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("timestamp,src_ip,dst_ip,protocol,src_port,dst_port,packet_size,flags\n")
            f.write("2026-01-01 00:00:00,1.1.1.1,2.2.2.2,TCP,80,443,100,S\n")
            f.write("2026-01-01 00:00:01,1.1.1.1,2.2.2.2,UDP,1234,53,64,\n")
            f.write("2026-01-01 00:00:02,1.1.1.1,2.2.2.2,TCP,80,443,100,A\n")
            tmp_path = f.name
        try:
            features, encoders, _ = load_and_prepare_data(tmp_path)
            assert features.isnull().sum().sum() == 0
        finally:
            os.unlink(tmp_path)


class TestTrainModel:
    def test_train_and_save(self, tmp_path):
        save_path = str(tmp_path / "test_model.pkl")
        model, encoders = train_model(csv_path=SAMPLE_CSV, save_path=save_path)
        assert os.path.isfile(save_path)
        assert model is not None
        assert "protocol" in encoders
        assert "flags" in encoders

    def test_model_predicts(self, tmp_path):
        save_path = str(tmp_path / "test_model.pkl")
        model, encoders = train_model(csv_path=SAMPLE_CSV, save_path=save_path)
        features, _, _ = load_and_prepare_data(SAMPLE_CSV)
        predictions = model.predict(features)
        assert len(predictions) == len(features)
        assert set(predictions).issubset({1, -1})

    def test_saved_artifact_structure(self, tmp_path):
        import joblib
        save_path = str(tmp_path / "test_model.pkl")
        train_model(csv_path=SAMPLE_CSV, save_path=save_path)
        artifact = joblib.load(save_path)
        assert "model" in artifact
        assert "encoders" in artifact
