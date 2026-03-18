"""
NetWatchAI - ML Model
Trains an Isolation Forest model on packet data to detect anomalous traffic.

How Isolation Forest works (beginner explanation):
  - It builds many random decision trees.
  - Normal data points need MORE splits to isolate → longer path.
  - Anomalous data points need FEWER splits to isolate → shorter path.
  - Short path = easy to isolate = probably an anomaly.

The model is unsupervised — it doesn't need labeled data to learn.
We use labels in the sample dataset only for evaluation purposes.
"""

import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from src.utils import SAMPLE_CSV, MODEL_PATH, setup_logger, ensure_dirs

logger = setup_logger(__name__)


def load_and_prepare_data(csv_path: str = SAMPLE_CSV) -> tuple:
    """Load CSV and convert features into numbers the ML model can use.

    Args:
        csv_path: Path to the training CSV file.

    Returns:
        A tuple of (feature_dataframe, label_encoders_dict).

    What this function does step by step:
        1. Reads the CSV file into a pandas DataFrame.
        2. Selects only the numeric-compatible columns.
        3. Converts text columns (protocol, flags) into numbers using LabelEncoder.
        4. Returns the prepared DataFrame and the encoders (so we can reuse them later).
    """
    logger.info(f"Loading data from {csv_path}")
    df = pd.read_csv(csv_path)

    # Columns we'll use as input features for the model
    feature_cols = ["protocol", "src_port", "dst_port", "packet_size", "flags"]

    # Fill any missing flag values with "NONE"
    df["flags"] = df["flags"].fillna("NONE").astype(str).str.strip()
    df.loc[df["flags"] == "", "flags"] = "NONE"

    # Encode text columns → numbers
    # Example: TCP=0, UDP=1, ICMP=2  (order depends on data)
    encoders = {}
    for col in ["protocol", "flags"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        encoders[col] = le
        logger.info(f"  Encoded '{col}': {list(le.classes_)}")

    logger.info(f"  Dataset shape: {df[feature_cols].shape}")
    return df[feature_cols], encoders, df.get("label")


def train_model(csv_path: str = SAMPLE_CSV, save_path: str = MODEL_PATH):
    """Train an Isolation Forest model and save it to disk.

    Args:
        csv_path:  Path to the training CSV.
        save_path: Where to save the trained model (.pkl file).

    The saved file contains both the model and the label encoders,
    so the detector can decode new packets the same way.
    """
    ensure_dirs()

    # Step 1: Prepare the data
    features, encoders, labels = load_and_prepare_data(csv_path)

    # Step 2: Create and train the Isolation Forest
    # contamination=0.1 means we expect ~10% of training data to be anomalies
    # random_state=42 makes results reproducible
    logger.info("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100,       # number of trees
        contamination=0.1,      # expected fraction of anomalies
        random_state=42,        # for reproducibility
        n_jobs=-1,              # use all CPU cores
    )
    model.fit(features)
    logger.info("Training complete.")

    # Step 3: Quick evaluation if labels are available
    if labels is not None:
        predictions = model.predict(features)
        # Isolation Forest returns: 1 = normal, -1 = anomaly
        n_total = len(predictions)
        n_anomalies = (predictions == -1).sum()
        logger.info(f"  Detected {n_anomalies}/{n_total} anomalies in training data")

        # Compare with actual labels
        actual_anomalies = (labels == "anomaly").sum()
        logger.info(f"  Actual anomalies in dataset: {actual_anomalies}/{n_total}")

    # Step 4: Save the model + encoders together
    artifact = {
        "model": model,
        "encoders": encoders,
    }
    joblib.dump(artifact, save_path)
    logger.info(f"Model saved to {save_path}")

    return model, encoders
