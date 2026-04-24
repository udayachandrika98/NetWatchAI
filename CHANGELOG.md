# Changelog

All notable changes to NetWatchAI are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Stateful behavioral detection** (`src/behavior.py`): catches patterns no single packet can reveal — **Port Scan** (15+ distinct destination ports from one source within 60s), **Brute Force** (20+ repeated connections to the same target/port within 60s), **DoS Flood** (100+ packets per source within 10s). Replaces the noisy per-packet port-scan rule.
- **Threat-intel IP reputation** (`src/threat_intel.py`): every source IP is checked against three free feeds (abuse.ch Feodo Tracker, Spamhaus DROP, Tor exit nodes). Matches are auto-flagged as "Known Malicious". Feeds cache locally and refresh once per day. Manual refresh button in **Settings → Threat Intelligence**. No API keys required.
- **Optional login**: authentication is now fully opt-in. A fresh install opens the dashboard directly; set a password via Settings → Login & Security (or the `NETWATCHAI_PASSWORD` env var) to enable the sign-in screen.
- SQLite persistence layer (`src/storage.py`) for alerts, allowlist, feedback, and audit log.
- Alert dispatch to Discord, Slack, and SMTP email (`src/alerting.py`) — all free channels.
- User-editable settings (`src/config.py`): webhook URLs, SMTP credentials, severity threshold, dedup window, retention.
- Secure first-run password handling (`src/auth.py`): random token generated on first boot, override via `NETWATCHAI_PASSWORD`.
- Settings tab in the dashboard: configure alert channels, manage allowlist, set retention, rotate the admin password, view audit log, export alerts as JSON/CSV.
- False-positive feedback buttons on stored alerts; one-click allowlist from a flagged source.
- Executive Overview panel: Security Score (0–100), Threats Detected, Hostile Sources.
- Sign Out button in the sidebar; login form now submits on Enter.
- Audit log records logins, settings changes, false-positive marks, allowlist edits, and password rotations.
- GitHub Actions CI: ruff lint, bandit security scan, pytest on Python 3.11/3.12, multi-arch Docker build (amd64 + arm64).
- Pre-commit hooks: ruff, trailing whitespace, large-file guard, private-key detector, bandit.

### Changed
- Dashboard UI redesigned (dark theme, indigo/violet accent, refined typography) inspired by Linear / Vercel / Stripe dashboards.
- PDF report cover redesigned to match brand.
- Chart palette switched to an accessible indigo-based scheme with dark gridlines.
- Anomalies from allowlisted IPs are now automatically reclassified as Normal before rendering.

### Removed
- Hardcoded fallback password `admin123`.
- Neon glow, shimmer, and pulse animations that distracted from the data.

## [0.1.0] — Initial release

- Live packet capture (Scapy) with real-time anomaly detection (Decision Tree).
- Streamlit dashboard: alerts, attack-type breakdown, top attackers, timeline, statistics, network info, global attack map, PDF report.
- Dockerfile and `docker-compose.yml` for one-command deployment.
- Sample packet dataset bundled for demo mode.
