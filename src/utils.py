"""
NetWatchAI - Shared Utilities
Provides common paths, logging setup, and helper functions used across the project.
"""

import os
import logging

# ──────────────────────────────────────────────
# Project Paths
# ──────────────────────────────────────────────

# Root directory of the project (one level up from src/)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Path to the data folder
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# Path to the models folder
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")

# Path where live-captured packets are saved
PACKETS_CSV = os.path.join(DATA_DIR, "packets.csv")

# Path to the sample/training dataset
SAMPLE_CSV = os.path.join(DATA_DIR, "sample_packets.csv")

# Path to the saved ML model
MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")

# CSV column order — every module uses this same list
CSV_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "packet_size",
    "flags",
]

# ──────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────

def setup_logger(name: str, level=logging.INFO) -> logging.Logger:
    """Create a logger with a consistent format.

    Args:
        name:  Logger name (usually __name__ of the calling module).
        level: Logging level (default: INFO).

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def ensure_dirs():
    """Create data/ and models/ directories if they don't exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
