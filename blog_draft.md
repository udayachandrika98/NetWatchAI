# How I Built an AI-Powered Network Intrusion Detection System with Python

*A complete guide to building a real-time network security monitoring tool using Machine Learning, Scapy, and Streamlit.*

---

Every 39 seconds, a cyberattack happens somewhere in the world. Most organizations rely on expensive commercial tools to detect these threats. But what if you could build your own AI-powered intrusion detection system from scratch — using just Python?

That's exactly what I did with **NetWatchAI** — a real-time network monitoring tool that captures live packets, detects anomalies using machine learning, and displays everything on a sleek cybersecurity dashboard.

In this article, I'll walk you through how I built it, the architecture decisions I made, and what I learned along the way.

---

## The Problem

Traditional intrusion detection systems (IDS) rely on **signature-based detection** — they match network traffic against a database of known attack patterns. The problem? They can't detect **new, unknown attacks**.

I wanted to build something smarter. An IDS that could learn what "normal" network traffic looks like and automatically flag anything suspicious — without needing a pre-built list of attack signatures.

The answer? **Unsupervised Machine Learning.**

---

## The Architecture

Here's the high-level pipeline I designed:

```
Live Network → Packet Capture → Feature Extraction → ML Model → Dashboard
  (Scapy)       (sniffer.py)   (feature_extractor.py) (detector.py) (Streamlit)
```

The system has four main stages:

1. **Capture** — sniff live packets from the network
2. **Extract** — pull meaningful features from raw packets
3. **Detect** — run each packet through an ML model
4. **Display** — show results on a real-time dashboard

Let me break down each component.

---

## Step 1: Capturing Network Packets with Scapy

The first challenge was getting access to raw network traffic. I used **Scapy**, a powerful Python library for packet manipulation and capture.

```python
from scapy.all import sniff

def start(self, count=50, iface=None, bpf_filter=None):
    sniff(
        count=count,
        iface=iface,
        filter=bpf_filter,
        prn=self._process_packet,
        store=False,
    )
```

Scapy captures packets at the network interface level, giving access to every layer — Ethernet, IP, TCP, UDP, ICMP, and more. It requires root/sudo access since it operates on raw sockets.

**Key decisions:**
- Used BPF (Berkeley Packet Filter) support so users can filter specific traffic (e.g., only TCP port 80)
- Stored captured packets to CSV for persistence and later analysis
- Added a callback-based architecture so detection could happen in real-time

---

## Step 2: Feature Extraction

Raw packets are messy. A single TCP packet has dozens of fields. I needed to extract the features that matter most for anomaly detection:

```python
def extract_features(packet):
    if not packet.haslayer(IP):
        return None

    features = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": get_protocol(packet),
        "src_port": get_src_port(packet),
        "dst_port": get_dst_port(packet),
        "packet_size": len(packet),
        "flags": get_flags(packet),
    }
    return features
```

I focused on these features because they're the strongest indicators of malicious activity:
- **Source/Destination IPs** — who's talking to whom
- **Ports** — certain ports (4444, 31337) are commonly used by backdoors
- **Protocol** — TCP, UDP, or ICMP
- **Packet size** — unusually large packets can indicate data exfiltration
- **TCP flags** — SYN floods and port scans have distinct flag patterns

---

## Step 3: The ML Model — Why Isolation Forest?

This was the most important architectural decision. I chose **Isolation Forest** for several reasons:

1. **Unsupervised** — it doesn't need labeled "attack" data to train. It learns what's normal and flags everything else.
2. **Fast** — it handles real-time prediction without lag.
3. **Effective with high-dimensional data** — network traffic has many features, and Isolation Forest handles this well.

```python
from sklearn.ensemble import IsolationForest

model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42,
)
model.fit(training_data)
```

**How it works:** Isolation Forest builds 100 random decision trees. Normal data points take more splits to isolate, while anomalies — being rare and different — get isolated quickly. Points that are isolated in fewer splits are flagged as anomalies.

The `contamination=0.1` parameter tells the model to expect about 10% of traffic to be anomalous — a reasonable baseline for a monitored network.

### Attack Classification

Beyond just flagging anomalies, I added rule-based classification to identify *what type* of attack was detected:

| Attack Type | Detection Logic |
|------------|----------------|
| Port Scan | TCP SYN packets to multiple ports |
| Ping of Death | ICMP packets > 1000 bytes |
| Data Exfiltration | Large transfers to backdoor ports (4444, 31337) |
| DNS Anomaly | UDP port 53 with unusual payload size |
| Suspicious Port | Traffic to known dangerous ports |
| Large Transfer | Any packet > 5000 bytes |

This hybrid approach — ML for detection, rules for classification — gives the best of both worlds.

---

## Step 4: The Dashboard

A detection system is useless if no one can see the results. I built a real-time Security Operations Center (SOC) dashboard using **Streamlit** and **Plotly**.

*[Add screenshot of dashboard here]*

The dashboard includes six tabs:

- **Alerts** — real-time anomaly log with filtering
- **Attack Types** — pie chart showing distribution of detected threats
- **Top Attackers** — ranked list of most suspicious IPs
- **Timeline** — time-series visualization of normal vs anomalous traffic
- **Statistics** — protocol distribution, packet size histograms
- **Network Info** — current WiFi, IPs, DNS, gateway, signal strength

### Threat Level System

I implemented a color-coded threat level that updates based on the anomaly rate:

- **GREEN** — 0-5% anomalies (all clear)
- **YELLOW** — 5-15% (elevated)
- **ORANGE** — 15-30% (high)
- **RED** — >30% (critical)

The dashboard auto-refreshes every 5 seconds, so it works as a real-time monitoring tool.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.11 |
| Packet Capture | Scapy |
| Machine Learning | scikit-learn (Isolation Forest) |
| Data Processing | Pandas |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Deployment | Docker |

---

## Making It Production-Ready

A few things I did to make this more than a toy project:

- **Docker support** — one command to deploy: `docker run -d -p 8501:8501 netwatchai`
- **Password protection** — the dashboard is locked behind authentication
- **Comprehensive tests** — 302 unit and integration tests covering every module
- **pip installable** — `pip install netwatchai` with CLI commands (`netwatchai-train`, `netwatchai-capture`, `netwatchai-dashboard`)

---

## What I Learned

1. **Unsupervised ML is powerful for security** — you don't need labeled attack data when you can model what "normal" looks like.
2. **Feature engineering matters more than model complexity** — choosing the right packet features was more impactful than tuning the model.
3. **Real-time systems need careful architecture** — the callback-based design was essential for processing packets without blocking.
4. **Visualization sells the project** — the dashboard made this 10x more impressive than just a CLI tool.
5. **Networking fundamentals are essential** — understanding TCP/IP, packet structure, and protocol behavior was critical for building meaningful detection rules.

---

## What's Next

I'm planning to add:
- **GeoIP mapping** — show attacker locations on a world map
- **Email/Slack alerts** — real-time notifications when threats are detected
- **PCAP file upload** — analyze pre-captured traffic without live capture
- **Threat intelligence feeds** — cross-check IPs against known malicious databases

---

## Try It Yourself

NetWatchAI is open source. You can try it in one command:

```bash
pip install netwatchai
netwatchai-train
netwatchai-dashboard
```

Or with Docker:
```bash
docker run -d -p 8501:8501 udayak/netwatchai:latest
```

Check out the full source code on [GitHub](https://github.com/udayak/NetWatchAI).

---

*If you found this interesting, follow me for more posts on cybersecurity, machine learning, and Python development.*

---

#Python #MachineLearning #Cybersecurity #NetworkSecurity #IntrusionDetection #AI #DataScience #Streamlit #OpenSource #Programming
