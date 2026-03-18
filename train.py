"""
NetWatchAI - Train the ML Model
Run this script to train the Isolation Forest model on sample data.

Usage:
    python train.py
    python train.py --data data/sample_packets.csv
"""

import argparse
from src.model import train_model
from src.utils import SAMPLE_CSV


def main():
    parser = argparse.ArgumentParser(description="Train the NetWatchAI anomaly detection model")
    parser.add_argument(
        "--data",
        type=str,
        default=SAMPLE_CSV,
        help="Path to training CSV file (default: data/sample_packets.csv)",
    )
    args = parser.parse_args()

    print("=" * 50)
    print("  NetWatchAI — Model Training")
    print("=" * 50)
    print()

    train_model(csv_path=args.data)

    print()
    print("Done! You can now run the dashboard:")
    print("  streamlit run dashboard.py")
    print()


if __name__ == "__main__":
    main()
