# Contributing

PRs welcome. Here's how to get a dev environment running.

## Setup

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install pytest ruff bandit pre-commit
pre-commit install
```

## Running things

```bash
# Tests
pytest tests/ -q -W ignore::DeprecationWarning

# Lint
ruff check src/ tests/ dashboard.py

# Security scan
bandit -r src/ -ll --skip B101

# Dashboard
streamlit run dashboard.py
```

## Submitting changes

1. Open an issue first for anything non-trivial so we can align on approach.
2. Keep PRs focused. One change per PR beats a dozen bundled changes.
3. Add tests for new code paths. The CI bar is ~400 passing tests today.
4. Update the `CHANGELOG.md` under `[Unreleased]`.
5. Make sure `ruff check` and `pytest` pass locally — CI will run both.

## Project layout

```
NetWatchAI/
├── dashboard.py            # Streamlit entry point
├── src/
│   ├── sniffer.py          # Scapy packet capture
│   ├── detector.py         # Model inference
│   ├── model.py            # Training pipeline
│   ├── feature_extractor.py
│   ├── storage.py          # SQLite persistence
│   ├── alerting.py         # Webhook and email dispatch
│   ├── config.py           # User settings
│   ├── auth.py             # Password handling
│   └── utils.py            # Shared paths and helpers
├── tests/                  # pytest suite
├── docs/                   # MkDocs site
└── .github/workflows/ci.yml
```

## Priorities we want help on

- Extending the detection ruleset for new attack types.
- Benchmarking on CIC-IDS2017 and UNSW-NB15.
- Packaging improvements (Helm chart, systemd unit).
- Translations for the dashboard UI.
