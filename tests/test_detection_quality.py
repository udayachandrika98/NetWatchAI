"""Detection-quality regression test (the PCAP-replay equivalent).

Trains the Isolation Forest on the committed sample dataset and asserts that
precision / recall / F1 / accuracy do not regress below baseline thresholds.

The dataset is small (227 rows, 20 labeled anomalies) and the model is seeded
(`random_state=42`), so results are deterministic. Any drop below the
thresholds indicates the detector got worse — fail the build, not the runtime.

Baselines measured 2026-05-12 on sample_packets.csv:
  accuracy=0.9251  precision=0.5652  recall=0.6500  f1=0.6047

Thresholds are set ~5 points below to absorb minor environment drift
(sklearn version, BLAS impl). Tighten as the model improves.
"""
import os

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)

from src.detector import AnomalyDetector
from src.model import train_model
from src.utils import SAMPLE_CSV

# Floors — fail the build if metrics drop below these.
MIN_ACCURACY = 0.90
MIN_PRECISION = 0.50
MIN_RECALL = 0.55
MIN_F1 = 0.55


@pytest.fixture(scope="module")
def trained_detector(tmp_path_factory) -> AnomalyDetector:
    """Train inline so the test is self-contained and CI doesn't need a pre-built model."""
    model_path = tmp_path_factory.mktemp("model") / "detection_quality_model.pkl"
    train_model(csv_path=SAMPLE_CSV, save_path=str(model_path))
    return AnomalyDetector(model_path=str(model_path))


@pytest.fixture(scope="module")
def labeled_predictions(trained_detector: AnomalyDetector) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(SAMPLE_CSV)
    assert "label" in df.columns, "sample_packets.csv must carry a 'label' column"
    raw_preds = np.asarray(trained_detector.predict_batch(df))
    # Detector emits 1 (normal) / -1 (anomaly); convert to 0 (normal) / 1 (attack).
    y_pred = np.where(raw_preds == -1, 1, 0)
    y_true = (df["label"] == "anomaly").astype(int).to_numpy()
    return y_true, y_pred


def test_dataset_present():
    """Sample dataset is committed and labeled."""
    assert os.path.exists(SAMPLE_CSV), "data/sample_packets.csv is missing"
    df = pd.read_csv(SAMPLE_CSV)
    assert (df["label"] == "anomaly").sum() >= 10, "need at least 10 labeled anomalies"
    assert (df["label"] == "normal").sum() >= 100, "need at least 100 labeled normal rows"


def test_accuracy_does_not_regress(labeled_predictions):
    y_true, y_pred = labeled_predictions
    acc = accuracy_score(y_true, y_pred)
    assert acc >= MIN_ACCURACY, f"accuracy={acc:.4f} fell below floor {MIN_ACCURACY}"


def test_precision_does_not_regress(labeled_predictions):
    y_true, y_pred = labeled_predictions
    prec = precision_score(y_true, y_pred, zero_division=0)
    assert prec >= MIN_PRECISION, f"precision={prec:.4f} fell below floor {MIN_PRECISION}"


def test_recall_does_not_regress(labeled_predictions):
    y_true, y_pred = labeled_predictions
    rec = recall_score(y_true, y_pred, zero_division=0)
    assert rec >= MIN_RECALL, f"recall={rec:.4f} fell below floor {MIN_RECALL}"


def test_f1_does_not_regress(labeled_predictions):
    y_true, y_pred = labeled_predictions
    f1 = f1_score(y_true, y_pred, zero_division=0)
    assert f1 >= MIN_F1, f"f1={f1:.4f} fell below floor {MIN_F1}"


def test_metrics_are_deterministic(trained_detector):
    """Re-running prediction on the same data yields identical results (seeded model)."""
    df = pd.read_csv(SAMPLE_CSV)
    a = np.asarray(trained_detector.predict_batch(df))
    b = np.asarray(trained_detector.predict_batch(df))
    assert (a == b).all(), "predict_batch is non-deterministic"
