<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/ML-Isolation%20Forest-orange?logo=scikit-learn&logoColor=white" alt="ML">
  <img src="https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit&logoColor=white" alt="Streamlit">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white" alt="Docker">
</p>

<h1 align="center">NetWatchAI</h1>
<p align="center"><b>AI-Powered Network Monitoring & Intrusion Detection System</b></p>
<p align="center">
  Captures live network packets, detects anomalies with machine learning, and shows real-time alerts in a beautiful dashboard.
</p>

---

<!-- Add a screenshot or GIF of your dashboard here -->
<!-- ![Dashboard Screenshot](docs/screenshot.png) -->

## Get Started — Pick Your Way

> On first launch, NetWatchAI generates a random admin password and prints it to the console.
> Override it anytime by setting the `NETWATCHAI_PASSWORD` environment variable, or rotate it
> from **Settings → Session & Security** in the dashboard.

### Option 1: Docker (Recommended)

```bash
docker run -d -p 8501:8501 --name netwatchai udayak/netwatchai:latest
```

Open **http://localhost:8501** — done.

### Option 2: pip install

```bash
pip install netwatchai
netwatchai-train              # Train the model
netwatchai-dashboard          # Launch dashboard
```

### Option 3: pip install from GitHub (latest)

```bash
pip install git+https://github.com/udayak/NetWatchAI.git
netwatchai-train && netwatchai-dashboard
```

### Option 4: One-Line Script

```bash
curl -sSL https://raw.githubusercontent.com/udayak/NetWatchAI/main/setup.sh | bash
```

Auto-installs Docker if needed, pulls the image, and opens the dashboard in your browser.

### Option 5: GitHub Codespaces (Zero Install — Runs in Browser)

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/udayak/NetWatchAI)

Click the button above. A full dev environment opens in your browser with the dashboard running automatically. No install, no setup.

### Option 6: VS Code DevContainer

1. Install [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
2. Open this repo in VS Code
3. Click **"Reopen in Container"** when prompted

Dashboard starts automatically on port 8501.

### Option 7: Run from Source

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python train.py               # Train the ML model
streamlit run dashboard.py    # Launch dashboard
```

### Option 8: Docker Compose

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
docker compose up -d
```

Open **http://localhost:8501**.

Docker Compose also brings up a Prometheus + Grafana observability stack:

| Service | URL | Notes |
|---------|-----|-------|
| Streamlit dashboard | http://localhost:8501 | main app |
| Metrics exporter | http://localhost:9100/metrics | Prometheus format |
| Prometheus | http://localhost:9090 | scrapes the exporter |
| Grafana | http://localhost:3000 | login `admin` / `admin` (override with `GRAFANA_PASSWORD`) |

The **NetWatchAI Overview** dashboard is auto-provisioned in Grafana with panels for open alerts, attack-type breakdown, top source IPs, and alert rate over time.

<details>
<summary><b>Quick comparison — which option should I pick?</b></summary>

| Option | Best For | Needs Install? | Time to Start |
|--------|----------|---------------|---------------|
| Docker | Most users | Docker only | ~30 sec |
| pip install | Python developers | Python 3.11+ | ~1 min |
| pip from GitHub | Latest unreleased code | Python 3.11+ | ~1 min |
| One-line script | First-time users | Nothing (auto-installs) | ~1 min |
| GitHub Codespaces | Try without installing anything | Nothing | ~2 min |
| VS Code DevContainer | Developers with VS Code | VS Code + Docker | ~2 min |
| From source | Contributors / customizers | Python 3.11+ | ~2 min |
| Docker Compose | Multi-service setups | Docker | ~1 min |

</details>

---

## How It Works

```
Network Traffic → Scapy Capture → Feature Extraction → ML Model → Dashboard
```

```
┌─────────────┐    ┌──────────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐
│   Scapy     │───>│   Feature    │───>│    CSV    │───>│ Isolation│───>│ Streamlit │
│   Packet    │    │  Extractor   │    │  Storage  │    │  Forest  │    │ Dashboard │
│   Capture   │    │              │    │           │    │  Model   │    │           │
└─────────────┘    └──────────────┘    └───────────┘    └──────────┘    └───────────┘
```

1. **Capture** — Sniffs live packets from your network using Scapy
2. **Extract** — Pulls 8 features per packet: IPs, ports, protocol, size, TCP flags
3. **Detect** — Isolation Forest ML model flags anomalies (unsupervised — no labeled data needed)
4. **Classify** — Rule-based classification into specific attack types
5. **Display** — Real-time dashboard with alerts, charts, maps, and PDF reports

---

## Dashboard Tabs

| Tab | What You See |
|-----|-------------|
| **Alerts** | Anomaly list with threat level + full packet log with pagination & filters |
| **Attack Types** | Pie chart breakdown + descriptions of each attack type |
| **Top Attackers** | Ranked source/destination IPs with attack counts |
| **Timeline** | Area chart of normal vs anomaly traffic over time |
| **Statistics** | Protocol distribution, packet size histogram, normal vs anomaly bar chart |
| **Network Info** | WiFi SSID, signal strength, local/public IP, gateway, DNS, MAC (cross-platform) |
| **Attack Map** | World map with geolocated attacker IPs (batch GeoIP lookup) |
| **PDF Report** | Download a professional security report with executive summary & recommendations |
| **Settings** | Configure Discord / Slack / email alerts, allowlist, retention, rotate password, view audit log, export data |

**Threat Levels:** GREEN (0-5%) → YELLOW (5-15%) → ORANGE (15-30%) → RED (>30% anomaly rate)

---

## Sign in with GitHub (optional)

NetWatchAI ships with a single-password gate by default. For multi-user / production use, you can layer **GitHub OAuth** on top — the "Sign in with GitHub" button appears on the login screen as soon as the three env vars are present.

1. Go to https://github.com/settings/developers → **New OAuth App**
2. Set the **Authorization callback URL** to `http://localhost:8501/` (or your real domain)
3. Copy the **Client ID** and **Client Secret** into your `.env`:

```bash
GITHUB_OAUTH_CLIENT_ID=...
GITHUB_OAUTH_CLIENT_SECRET=...
GITHUB_OAUTH_REDIRECT_URI=http://localhost:8501/
ALLOWED_GITHUB_USERS=your-github-username   # optional comma-separated allowlist
```

4. `docker compose up -d --build dashboard`

If `ALLOWED_GITHUB_USERS` is blank, any GitHub user can sign in. Set it for a private deployment. The password gate stays available alongside — the two paths are independent.

---

## Configure Alerts (Free Channels)

Open **Settings → Alert Channels** in the dashboard.

- **Discord webhook:** Server Settings → Integrations → Webhooks → New Webhook → copy URL.
- **Slack webhook:** [api.slack.com/messaging/webhooks](https://api.slack.com/messaging/webhooks) — one-click install.
- **Email (free via Gmail SMTP):** host `smtp.gmail.com`, port `587`, your Gmail address, and a 16-char Google App Password. 500 emails/day free.

Set a **minimum severity** so you only get paged for real threats. Use **Send test alert** to verify each channel.

---

## False Positives and Allowlists

Click **False positive** next to any stored alert to suppress it and record the correction.
Click **Allowlist** to immediately stop all future alerts from that source IP.
Manage the allowlist any time under **Settings → Allowlist**.

---

## Detectable Attacks

| Attack | Detection Method |
|--------|-----------------|
| **Port Scan** | TCP SYN-only packets to multiple ports |
| **Ping of Death** | ICMP packets > 1000 bytes |
| **Data Exfiltration** | Large transfers to suspicious ports (4444, 31337) |
| **Suspicious Port** | Traffic on known backdoor ports (1337, 5555, 6666, etc.) |
| **DNS Anomaly** | UDP port 53 with unusual packet size |
| **Large Transfer** | Packets exceeding 5000 bytes |

---

## Why NetWatchAI Over Other Tools?

There are great IDS tools out there. Here's how NetWatchAI compares:

### Feature Comparison

| Feature | NetWatchAI | Snort | Suricata | Zeek | Wazuh | Security Onion |
|---------|-----------|-------|----------|------|-------|----------------|
| ML anomaly detection | **Yes** | No | No | No | No | No |
| Built-in dashboard | **Yes** | No | No | No | Needs Kibana | Needs Kibana |
| PDF reports | **Yes** | No | No | No | No | No |
| GeoIP attack map | **Yes** | No | No | No | Plugin | Plugin |
| pip installable | **Yes** | No | No | No | No | No |
| Docker one-command | **Yes** | Community | Community | Community | Yes | No (ISO) |
| Python-native | **Yes** | C/C++ | C/Rust | C++ | C/Python | Mixed |
| Setup time | **~30 sec** | Hours | Hours | Hours | 30+ min | 1+ hour |
| Cross-platform | **macOS/Linux/Win** | Linux | Linux | Linux | Linux/Win | Linux only |
| Signature/rule-based | No | Yes (30K+ rules) | Yes | Via scripts | Yes | Yes |
| Enterprise scale | Small networks | Enterprise | Enterprise | Enterprise | Enterprise | Enterprise |
| Blocks traffic (IPS) | No | Yes | Yes | No | Via agent | Yes |

### What Each Tool Is Best At

| Tool | Best For | Limitation |
|------|----------|-----------|
| **Snort** | Enterprise rule-based detection | No ML, no dashboard, complex setup |
| **Suricata** | High-speed multi-threaded IDS | Needs ELK stack for UI, no ML |
| **Zeek** | Deep protocol analysis & forensics | Steep learning curve, no alerting UI |
| **Wazuh** | Host-based monitoring + compliance | Not a network packet IDS |
| **Security Onion** | Full SOC platform (Suricata+Zeek+ELK) | Needs dedicated hardware, 16GB+ RAM |
| **NetWatchAI** | **Lightweight ML-based detection + instant dashboard** | Not for high-throughput enterprise networks |

### NetWatchAI's Unique Advantages

**1. ML-first detection (no other production IDS has this)**
Snort and Suricata only catch **known** attacks via signatures. NetWatchAI's Isolation Forest catches **unknown/zero-day** patterns by learning what normal traffic looks like and flagging anything unusual.

**2. Zero-config setup**
```bash
# NetWatchAI — 30 seconds
docker run -d -p 8501:8501 udayak/netwatchai:latest

# Suricata + ELK — you need all of this:
# Install Suricata → Configure YAML → Download rules → Install Elasticsearch
# → Install Kibana → Configure index patterns → Import dashboards
```

**3. All-in-one package**
Others need 4 separate tools: Suricata (detect) + Zeek (analyze) + Elasticsearch (store) + Kibana (view). NetWatchAI does capture + ML detection + dashboard + reports in **one package**.

**4. Python-native = easy to extend**
Security researchers and data scientists can read the code, swap ML models, add features. No C/C++ knowledge required.

### Who Should Use What

| If you need... | Use |
|---------------|-----|
| Quick ML-based monitoring for small network / home lab / learning | **NetWatchAI** |
| Enterprise IDS with 30K+ signature rules | Snort or Suricata |
| Deep protocol forensics and threat hunting | Zeek |
| Host-based monitoring + compliance (PCI-DSS, HIPAA) | Wazuh |
| Full SOC platform with everything bundled | Security Onion |

---

## Live Packet Capture

To capture real network traffic (requires admin/root privileges):

**Local:**
```bash
sudo python capture.py --count 100 --detect
```

**Docker:**
```bash
# Terminal 1: Capture packets
docker run -d --name netwatchai-capture \
  --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v $(pwd)/data:/app/data \
  udayak/netwatchai:latest \
  python capture.py --count 0 --detect

# Terminal 2: View dashboard
docker run -d -p 8501:8501 \
  -v $(pwd)/data:/app/data \
  --name netwatchai udayak/netwatchai:latest
```

**Capture options:**
| Flag | Description | Example |
|------|-------------|---------|
| `--count N` | Number of packets (0 = unlimited) | `--count 500` |
| `--iface` | Network interface | `--iface en0` |
| `--filter` | BPF filter expression | `--filter "tcp port 80"` |
| `--detect` | Run anomaly detection in real-time | `--detect` |

---

## CLI Commands

After `pip install -e .` you get these commands:

```bash
netwatchai-train      # Train the ML model
netwatchai-capture    # Start packet capture
netwatchai-dashboard  # Launch the dashboard
```

---

## Project Structure

```
NetWatchAI/
├── train.py               # Train the ML model
├── capture.py             # Capture live packets
├── dashboard.py           # Streamlit dashboard (main UI)
├── evaluate.py            # Benchmark against NSL-KDD dataset
│
├── src/                   # Core library
│   ├── feature_extractor.py  # Extract features from raw packets
│   ├── sniffer.py            # Packet capture with Scapy
│   ├── model.py              # Isolation Forest training
│   ├── detector.py           # Anomaly detection/prediction
│   ├── utils.py              # Shared paths & helpers
│   └── cli.py                # CLI entry points
│
├── data/
│   └── sample_packets.csv    # Sample training data (228 packets)
├── models/
│   └── model.pkl             # Trained model (auto-generated)
├── tests/                    # 440+ tests with pytest, including
│                             # `test_detection_quality.py` — precision/recall
│                             # regression test that fails the build if model
│                             # quality drops below baseline floors
│
├── Dockerfile                # Container build
├── docker-compose.yml        # Docker Compose setup
├── setup.sh                  # One-line installer script
├── requirements.txt          # Python dependencies
└── pyproject.toml            # Package config
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11+ |
| Packet Capture | [Scapy](https://scapy.net/) |
| Machine Learning | [scikit-learn](https://scikit-learn.org/) (Isolation Forest) |
| Data Processing | [pandas](https://pandas.pydata.org/) |
| Dashboard | [Streamlit](https://streamlit.io/) |
| Charts | [Plotly](https://plotly.com/python/) |
| GeoIP | [ip-api.com](http://ip-api.com/) (free, no key) |
| PDF Reports | [fpdf2](https://py-pdf.github.io/fpdf2/) |
| Deployment | [Docker](https://www.docker.com/) |

---

## Model Performance

Benchmarked on the [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html) dataset (125K training / 22.5K test samples):

| Model | Accuracy | Precision | Recall | F1-Score | Training Time |
|-------|----------|-----------|--------|----------|---------------|
| **Isolation Forest** (used) | 57.6% | 87.3% | 29.8% | 44.5% | 0.38s |
| Random Forest | 77.0% | 96.6% | 61.7% | 75.3% | 3.2s |
| Decision Tree | 79.4% | 96.5% | 66.2% | 78.5% | 0.8s |
| SVM | 78.1% | 97.6% | 63.1% | 76.7% | 45s |

> Isolation Forest is **unsupervised** (no labels needed) with high precision. Run `python evaluate.py` to reproduce.

---

## Configuration

| Setting | How to Change |
|---------|--------------|
| Dashboard password | `NETWATCHAI_PASSWORD=mypass streamlit run dashboard.py` |
| Streamlit theme | Edit `.streamlit/config.toml` |
| Model parameters | Edit `src/model.py` (contamination, n_estimators) |
| Suspicious ports | Edit `SUSPICIOUS_PORTS` in `dashboard.py` |

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Dev setup
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python train.py
pytest                    # Run 300+ tests
streamlit run dashboard.py
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>NetWatchAI</b> — AI-Powered Network Intrusion Detection<br>
  Built by <a href="https://github.com/udayak">Udaya K</a>
</p>
