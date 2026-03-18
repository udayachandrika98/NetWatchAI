# NetWatchAI — AI Network Monitoring & Intrusion Detection System

An AI-powered network monitoring tool that captures live network packets, analyzes traffic using machine learning (Isolation Forest), and displays real-time alerts in a Streamlit dashboard.

---

## Quick Start (Docker — Recommended)

**Only requirement: [Docker](https://docs.docker.com/get-docker/) must be installed.**

```bash
docker run -d -p 8501:8501 --name netwatchai udayak/netwatchai:latest
```

Open **http://localhost:8501** — done.

```bash
# Stop it
docker stop netwatchai

# Start it again
docker start netwatchai

# Remove it completely
docker rm -f netwatchai
```

---

## Alternative: Run from Source

<details>
<summary>Click to expand (for developers who want to modify the code)</summary>

### 1. Clone & install

```bash
git clone https://github.com/udayak/NetWatchAI.git
cd NetWatchAI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Train the model

```bash
python train.py
```

### 3. Launch the dashboard

```bash
streamlit run dashboard.py
```

### 4. Capture live packets (optional, requires sudo)

```bash
sudo python capture.py --count 50 --detect
```

</details>

---

## What It Does

```
┌─────────────┐    ┌──────────────┐    ┌───────────┐    ┌──────────┐    ┌───────────┐
│   Scapy     │───>│   Feature    │───>│    CSV    │───>│ ML Model │───>│ Streamlit │
│   Packet    │    │  Extractor   │    │  Storage  │    │ (sklearn)│    │ Dashboard │
│   Capture   │    │              │    │           │    │          │    │           │
└─────────────┘    └──────────────┘    └───────────┘    └──────────┘    └───────────┘
  sniffer.py      feature_extractor.py  data/*.csv      model.py       dashboard.py
```

1. **Captures** live packets from your network using Scapy
2. **Extracts** features — IPs, ports, protocol, size, TCP flags
3. **Detects anomalies** using an Isolation Forest ML model
4. **Classifies attacks** — Port Scan, Ping of Death, Data Exfiltration, DNS Anomaly, etc.
5. **Displays** real-time dashboard with threat level, alerts, charts, and network info

---

## Dashboard Features

| Tab | What It Shows |
|-----|--------------|
| Alerts | Anomaly list + full packet log with filters |
| Attack Types | Pie chart + descriptions of detected attack types |
| Top Attackers | Ranked source/destination IPs with attack counts |
| Timeline | Packets over time (normal vs anomaly) |
| Statistics | Protocol distribution, packet size histogram |
| Network Info | WiFi SSID, signal strength, IPs, DNS, gateway |

**Threat Levels:** GREEN (0-5%) → YELLOW (5-15%) → ORANGE (15-30%) → RED (>30% anomaly rate)

---

## Detectable Attacks

| Attack | How It's Detected |
|--------|------------------|
| Port Scan | TCP SYN packets to multiple ports |
| Ping of Death | ICMP packets > 1000 bytes |
| Data Exfiltration | Large transfers to suspicious ports (4444, 31337) |
| Suspicious Port | Traffic to known backdoor ports |
| DNS Anomaly | UDP port 53 with unusual size |
| Large Transfer | Packets > 5000 bytes |

---

## Project Structure

```
NetWatchAI/
├── Dockerfile             ← Container build file
├── docker-compose.yml     ← One-command deployment
├── setup.sh               ← Auto-setup script
├── requirements.txt       ← Python dependencies
├── train.py               ← Train the ML model
├── capture.py             ← Capture live packets
├── dashboard.py           ← Streamlit dashboard
├── data/
│   └── sample_packets.csv ← Sample training dataset (228 packets)
├── models/
│   └── model.pkl          ← Trained model (created after training)
└── src/
    ├── utils.py            ← Shared paths, logging helpers
    ├── feature_extractor.py← Extract features from raw packets
    ├── sniffer.py          ← Live packet capture with Scapy
    ├── model.py            ← Train Isolation Forest model
    └── detector.py         ← Load model & predict anomalies
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11 |
| Packet Capture | Scapy |
| Machine Learning | scikit-learn (Isolation Forest) |
| Data Processing | pandas |
| Dashboard | Streamlit |
| Charts | Plotly |
| Deployment | Docker |

---

## Live Packet Capture (Advanced)

To capture real network traffic inside Docker:

```bash
docker run -d \
  --name netwatchai-capture \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v $(pwd)/data:/app/data \
  udayak/netwatchai:latest \
  python capture.py --count 0 --detect
```

Then run the dashboard separately to view results:
```bash
docker run -d -p 8501:8501 -v $(pwd)/data:/app/data --name netwatchai udayak/netwatchai:latest
```

---

## License

This project is for educational purposes.
