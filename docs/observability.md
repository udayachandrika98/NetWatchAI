# Observability

NetWatchAI ships with a self-contained **Prometheus + Grafana** stack. When you run `docker compose up -d`, you get four services:

| Service | URL | Purpose |
|---|---|---|
| Streamlit dashboard | http://localhost:8501 | Operator UI — triage alerts, manage allowlist, run reports |
| Metrics exporter | http://localhost:9100/metrics | Reads `data/netwatchai.db` per scrape and serves Prometheus-format gauges |
| Prometheus | http://localhost:9090 | Scrapes the exporter every 15s, retains time-series history |
| Grafana | http://localhost:3000 | Long-term dashboards + alerting (default login `admin` / `admin`) |

Streamlit is the **operator UI** (what's happening now, take an action). Grafana is the **monitoring layer** (trends, history, alert rules). They're complementary — keep both running.

## Exported metrics

The exporter ([src/metrics_exporter.py](https://github.com/udayak/NetWatchAI/blob/main/src/metrics_exporter.py)) reads SQLite on each Prometheus scrape and exposes:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `netwatchai_db_up` | gauge | — | 1 if the SQLite alert store is reachable |
| `netwatchai_alerts_total` | gauge | `attack_type` | Total alerts ever recorded, by type (excludes FPs) |
| `netwatchai_alerts_last_24h` | gauge | `attack_type` | Alerts in the last 24h |
| `netwatchai_alerts_open` | gauge | — | Alerts with `status='new'` |
| `netwatchai_alerts_false_positive_total` | gauge | — | Alerts marked as false positive |
| `netwatchai_allowlist_size` | gauge | — | Number of IPs on the allowlist |
| `netwatchai_top_src_ip_alerts_24h` | gauge | `src_ip` | Per-source-IP count over 24h (top 10) |

## Pre-provisioned dashboard

The **NetWatchAI Overview** dashboard auto-loads with eight panels:

- Open alerts, 24h alerts, FP count, allowlist size (stat tiles)
- Attack type donut (24h)
- Top source IPs bargauge (24h)
- Stacked alert rate over time
- Exporter + DB health timeseries

Edit it freely in Grafana — your changes won't be overwritten unless you delete it.

## Pre-provisioned alert rules

Four default rules live in [`grafana/provisioning/alerting/rules.yml`](https://github.com/udayak/NetWatchAI/blob/main/grafana/provisioning/alerting/rules.yml):

| Rule | Threshold | Severity | Pages because |
|---|---|---|---|
| Exporter is down | `up{job="netwatchai"} < 1` for 5m | critical | Metrics pipeline broken |
| DB unreachable | `netwatchai_db_up < 1` for 5m | critical | Alert ingestion likely broken too |
| Open alerts unusually high | `netwatchai_alerts_open > 100` for 15m | warning | Triage backlog growing |
| Alert rate spike | `sum(increase(netwatchai_alerts_total[5m])) > 50` for 10m | warning | Likely attack in progress |

### Wire alerts to a real channel

By default, alerts route to a placeholder email contact. To deliver them somewhere real:

```bash
# Option 1: set the email at compose-up time
ALERT_EMAIL=you@example.com docker compose up -d

# Option 2: edit grafana/provisioning/alerting/contact-points.yml
#   change `type: email` to `slack`, `discord`, `webhook`, `pagerduty`, etc.
#   Grafana supports all of them — see the alerting docs.
```

Then restart Grafana: `docker compose restart grafana`.

## Tuning

- **Scrape interval** — `prometheus/prometheus.yml` (default 15s).
- **Retention** — Prometheus default is 15 days. Add `--storage.tsdb.retention.time=30d` to the prometheus service `command` for longer.
- **Thresholds** — edit `rules.yml`. The defaults assume a single-host homelab; tune up for SMB-scale traffic.

## When you'd add more

The current stack monitors NetWatchAI itself. To correlate with host metrics (CPU, memory, network bandwidth), add `node_exporter` as another scrape target — useful for telling a real attack apart from a noisy neighbor.
