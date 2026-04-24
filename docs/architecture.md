# Architecture

NetWatchAI is three independent pieces that talk through plain files and a SQLite database.

```
┌─────────────┐   packets.csv   ┌─────────────┐   SQLite    ┌─────────────┐
│  Sniffer    │ ──────────────> │  Detector   │ ──────────> │  Dashboard  │
│  (Scapy)    │                  │  (sklearn) │              │ (Streamlit) │
└─────────────┘                  └─────────────┘              └─────────────┘
      │                                                              │
      │                                                              │
      └──────────── on threat ──────────> Webhook / Email ──────────┘
                                          (Discord, Slack, SMTP)
```

## Components

### `src/sniffer.py`
Captures live packets with Scapy, extracts features (protocol, packet size, ports, TCP
flags), writes to `data/packets.csv`. Runs in its own process; no shared memory with the
dashboard.

### `src/detector.py`
Loads the trained model and runs inference on each row of the CSV. Returns `1` (normal)
or `-1` (anomaly). Inference is ~5ms per packet on a 2020 MacBook.

### `src/model.py`
Training pipeline. Loads `data/sample_packets.csv`, encodes categorical features, trains
the selected model, and pickles it to `models/model.pkl`.

### `dashboard.py`
Streamlit app. Reads `packets.csv`, runs detection, applies the allowlist, deduplicates
alerts, persists new ones to SQLite, dispatches notifications, and renders the UI.

### `src/storage.py`
SQLite persistence: alerts, allowlist, audit log, feedback. Indexed by timestamp, source
IP, and deduplication key.

### `src/alerting.py`
Webhook dispatch (Discord, Slack) and SMTP email. All transports are synchronous with a
5–10 second timeout and fail closed — a broken webhook never blocks the UI.

### `src/auth.py`
First-run password generation, verification, and rotation. Password is stored in
`data/.password` with 0600 permissions or, preferably, read from the `NETWATCHAI_PASSWORD`
environment variable.

### `src/config.py`
JSON-file configuration (webhooks, SMTP credentials, dedup window, retention days). Loaded
fresh on every dashboard render — no restart needed after changing settings.

## Data flow on a single packet

1. Sniffer captures the frame → extracts features → appends to CSV.
2. Dashboard rereads the CSV every 5 seconds (cache TTL).
3. Detector predicts normal/anomaly.
4. If anomaly and source not allowlisted:
   - Build a dedup key (`src_ip|attack_type|5-min-bucket`).
   - If key already exists, drop the alert (deduplicated).
   - Otherwise insert into SQLite and dispatch to configured channels.
5. UI re-renders with the updated metrics and alert list.
