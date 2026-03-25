"""CLI entry points for NetWatchAI."""

import subprocess
import sys
import os


def run_train():
    """Run the training script."""
    train_path = os.path.join(os.path.dirname(__file__), "..", "train.py")
    subprocess.run([sys.executable, train_path] + sys.argv[1:])


def run_capture():
    """Run the packet capture script."""
    capture_path = os.path.join(os.path.dirname(__file__), "..", "capture.py")
    subprocess.run([sys.executable, capture_path] + sys.argv[1:])


def run_dashboard():
    """Launch the Streamlit dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "..", "dashboard.py")
    subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path] + sys.argv[1:])
