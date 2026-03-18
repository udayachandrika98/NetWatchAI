"""
NetWatchAI - Anomaly Detector
Loads the trained ML model and predicts whether packets are normal or anomalous.

Prediction values:
   1  = normal traffic
  -1  = anomaly (suspicious/malicious)
"""

import pandas as pd
import joblib

from src.utils import MODEL_PATH, setup_logger

logger = setup_logger(__name__)


class AnomalyDetector:
    """Loads a trained Isolation Forest model and scores new packets."""

    def __init__(self, model_path: str = MODEL_PATH):
        """Load the saved model and encoders from disk.

        Args:
            model_path: Path to the .pkl file saved by model.py
        """
        logger.info(f"Loading model from {model_path}")
        artifact = joblib.load(model_path)
        self.model = artifact["model"]
        self.encoders = artifact["encoders"]
        logger.info("Model loaded successfully.")

    def predict_single(self, features: dict) -> int:
        """Predict whether a single packet is normal or anomalous.

        Args:
            features: Dictionary with keys: protocol, src_port, dst_port,
                      packet_size, flags (as returned by feature_extractor).

        Returns:
            1 if normal, -1 if anomaly.
        """
        df = pd.DataFrame([features])
        results = self.predict_batch(df)
        return results[0]

    def predict_batch(self, df: pd.DataFrame) -> list:
        """Predict anomalies for a batch of packets.

        Args:
            df: DataFrame with columns: protocol, src_port, dst_port,
                packet_size, flags.

        Returns:
            List of predictions (1=normal, -1=anomaly).
        """
        # Make a copy so we don't modify the original DataFrame
        df = df.copy()

        # Select only the feature columns the model expects
        feature_cols = ["protocol", "src_port", "dst_port", "packet_size", "flags"]

        # Clean up flags column (same as during training)
        df["flags"] = df["flags"].fillna("NONE").astype(str).str.strip()
        df.loc[df["flags"] == "", "flags"] = "NONE"

        # Encode text columns using the SAME encoders from training
        for col in ["protocol", "flags"]:
            encoder = self.encoders[col]
            # Handle unseen categories: replace with "OTHER" or first known class
            known_classes = set(encoder.classes_)
            df[col] = df[col].apply(
                lambda x: x if x in known_classes else encoder.classes_[0]
            )
            df[col] = encoder.transform(df[col])

        # Run the model prediction
        predictions = self.model.predict(df[feature_cols])
        return predictions.tolist()

    def score_csv(self, csv_path: str) -> pd.DataFrame:
        """Load a CSV file, predict anomalies, and return results.

        Args:
            csv_path: Path to a CSV file with packet data.

        Returns:
            Original DataFrame with an added 'prediction' column.
            prediction: 1=normal, -1=anomaly
        """
        df = pd.read_csv(csv_path)
        predictions = self.predict_batch(df)
        df["prediction"] = predictions
        df["status"] = df["prediction"].map({1: "Normal", -1: "ANOMALY"})

        n_anomalies = (df["prediction"] == -1).sum()
        logger.info(f"Scanned {len(df)} packets → {n_anomalies} anomalies detected")

        return df
