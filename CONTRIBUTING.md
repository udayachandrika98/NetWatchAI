# Contributing to NetWatchAI

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python train.py               # Train the model
pytest                        # Run tests (300+ should pass)
streamlit run dashboard.py    # Launch dashboard locally
```

## How to Contribute

### Reporting Bugs

Open an [issue](https://github.com/udayak/NetWatchAI/issues) with:
- What you expected vs what happened
- Steps to reproduce
- Your OS and Python version

### Suggesting Features

Open an issue with the **Feature Request** label describing:
- What problem it solves
- How you'd expect it to work

### Submitting Code

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Run `pytest` and make sure all tests pass
4. Open a Pull Request with a clear description of what you changed and why

## Code Guidelines

- **Python 3.11+** required
- Follow existing code style (no strict linter enforced, just be consistent)
- Add tests for new features in the `tests/` directory
- Keep dashboard changes in `dashboard.py` (single-file Streamlit app)
- Core ML/capture logic lives in `src/`

## Project Layout

| Directory | What goes here |
|-----------|---------------|
| `src/` | Core library: packet capture, feature extraction, ML model, detection |
| `tests/` | All tests (pytest) |
| `data/` | Sample datasets |
| `models/` | Trained model artifacts (auto-generated, not committed) |

## Running Tests

```bash
pytest              # Run all tests
pytest tests/test_model.py -v   # Run specific test file
```

## Questions?

Open an issue or start a discussion. All skill levels welcome.
