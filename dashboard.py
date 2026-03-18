"""
NetWatchAI - Streamlit Dashboard
Displays captured packets, anomaly alerts, and network statistics.

Usage:
    streamlit run dashboard.py
"""

import os
import subprocess
import socket
import time
import html as html_module
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from src.detector import AnomalyDetector
from src.utils import PACKETS_CSV, SAMPLE_CSV, MODEL_PATH


# ──────────────────────────────────────────────
# Network Info Helper
# ──────────────────────────────────────────────

def get_network_info():
    """Collect WiFi and network details from the system."""
    info = {}

    # WiFi SSID
    try:
        result = subprocess.run(
            ["networksetup", "-getairportnetwork", "en0"],
            capture_output=True, text=True, timeout=5,
        )
        line = result.stdout.strip()
        info["WiFi Network (SSID)"] = line.split(": ", 1)[1] if ": " in line else "Not connected"
    except Exception:
        info["WiFi Network (SSID)"] = "N/A"

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            info["Local IP"] = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        info["Local IP"] = "N/A"

    # Gateway / Router
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "gateway" in line.lower():
                info["Gateway (Router)"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        info["Gateway (Router)"] = "N/A"

    # DNS Servers
    try:
        result = subprocess.run(
            ["scutil", "--dns"],
            capture_output=True, text=True, timeout=5,
        )
        dns_servers = []
        for line in result.stdout.splitlines():
            if "nameserver" in line.lower():
                server = line.split(":", 1)[1].strip()
                if server not in dns_servers:
                    dns_servers.append(server)
                if len(dns_servers) >= 3:
                    break
        info["DNS Servers"] = ", ".join(dns_servers) if dns_servers else "N/A"
    except Exception:
        info["DNS Servers"] = "N/A"

    # Interface & MAC Address
    try:
        result = subprocess.run(
            ["ifconfig", "en0"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "ether" in line:
                info["MAC Address"] = line.strip().split()[1]
            if "inet " in line and "broadcast" in line:
                parts = line.strip().split()
                mask_idx = parts.index("netmask") if "netmask" in parts else -1
                if mask_idx > 0:
                    info["Subnet Mask"] = parts[mask_idx + 1]
    except Exception:
        pass

    # WiFi Signal Strength (RSSI)
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("agrCtlRSSI"):
                rssi = int(stripped.split(":")[1].strip())
                if rssi > -50:
                    strength = "Excellent"
                elif rssi > -60:
                    strength = "Good"
                elif rssi > -70:
                    strength = "Fair"
                else:
                    strength = "Weak"
                info["Signal Strength"] = f"{rssi} dBm ({strength})"
            if stripped.startswith("lastTxRate"):
                info["Link Speed"] = stripped.split(":")[1].strip() + " Mbps"
            if stripped.startswith("channel"):
                info["Channel"] = stripped.split(":")[1].strip()
    except Exception:
        info["Signal Strength"] = "N/A"

    # Hostname
    info["Hostname"] = socket.gethostname()

    # Public IP
    try:
        import urllib.request
        info["Public IP"] = urllib.request.urlopen("https://api.ipify.org", timeout=3).read().decode()
    except Exception:
        info["Public IP"] = "N/A"

    return info


# ──────────────────────────────────────────────
# Attack Type Classification
# ──────────────────────────────────────────────

SUSPICIOUS_PORTS = {4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321}

def classify_attack(row):
    """Classify an anomaly packet into a specific attack type."""
    if row.get("status") != "ANOMALY":
        return "Normal"

    protocol = str(row.get("protocol", "")).upper()
    try:
        dst_port = int(row.get("dst_port", 0))
    except (ValueError, TypeError):
        dst_port = 0
    try:
        src_port = int(row.get("src_port", 0))
    except (ValueError, TypeError):
        src_port = 0
    try:
        packet_size = int(row.get("packet_size", 0))
    except (ValueError, TypeError):
        packet_size = 0
    flags = str(row.get("flags", ""))

    if protocol == "ICMP" and packet_size > 1000:
        return "Ping of Death"
    if protocol == "TCP" and flags == "S" and packet_size <= 60:
        return "Port Scan"
    if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
        if packet_size > 1000:
            return "Data Exfiltration"
        return "Suspicious Port"
    if packet_size > 5000:
        return "Large Transfer"
    if protocol == "UDP" and dst_port == 53 and packet_size > 200:
        return "DNS Anomaly"
    return "Unknown Anomaly"


# ──────────────────────────────────────────────
# Page Configuration & Custom CSS
# ──────────────────────────────────────────────

st.set_page_config(
    page_title="NetWatchAI — Network Monitor",
    page_icon="🛡️",
    layout="wide",
)

# ──────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────

VALID_PASSWORD = os.environ.get("NETWATCHAI_PASSWORD", "admin123")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("""
    <div style="text-align:center; padding:3rem 0 1rem 0;">
        <div style="font-size:3.5rem; margin-bottom:0.5rem;">🛡️</div>
        <h1 style="color:#4f46e5; margin:0; font-size:2.2rem; font-weight:800;">NetWatchAI</h1>
        <p style="color:#64748b; margin:0.5rem 0 0 0; font-size:1.05rem;">AI-Powered Network Monitoring & Intrusion Detection</p>
    </div>
    """, unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1.2, 1, 1.2])
    with col2:
        st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)
        if st.button("Sign In", use_container_width=True, type="primary"):
            if password == VALID_PASSWORD:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password. Please try again.")
    st.stop()

# Custom CSS for clean, modern look
st.markdown("""
<style>
    /* Header banner */
    .main-header {
        background: linear-gradient(135deg, #4f46e5, #7c3aed, #6366f1);
        padding: 1.5rem 2rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        color: white;
        box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3);
    }
    .main-header h1 { color: #ffffff; margin: 0; font-size: 2rem; font-weight: 800; }
    .main-header p { color: #e0e7ff; margin: 0.3rem 0 0 0; font-size: 1rem; }

    /* Metric cards */
    .metric-card {
        background: #ffffff;
        border-radius: 16px;
        padding: 1.3rem;
        text-align: center;
        border: 1px solid #e2e8f0;
        transition: transform 0.2s, box-shadow 0.2s;
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .metric-card:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
    .metric-card .label { color: #64748b; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
    .metric-card .value { font-size: 2.2rem; font-weight: 800; margin: 0.3rem 0; }
    .metric-card.blue .value { color: #4f46e5; }
    .metric-card.green .value { color: #10b981; }
    .metric-card.red .value { color: #ef4444; }
    .metric-card.orange .value { color: #f59e0b; }

    /* Threat level bar */
    .threat-bar {
        background: #ffffff;
        border-radius: 12px;
        padding: 1rem 1.5rem;
        margin-bottom: 1rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.06);
    }
    .threat-label { font-size: 0.8rem; color: #64748b; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
    .threat-level { font-size: 1.3rem; font-weight: 700; }
    .threat-low { color: #10b981; }
    .threat-medium { color: #f59e0b; }
    .threat-high { color: #f97316; }
    .threat-critical { color: #ef4444; }

    /* Status badges */
    .badge-normal { background: #d1fae5; color: #065f46; padding: 3px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; }
    .badge-anomaly { background: #fee2e2; color: #991b1b; padding: 3px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; }

    /* Sidebar styling */
    [data-testid="stSidebar"] { background: #f1f5f9; }
    [data-testid="stSidebar"] .stMarkdown p { color: #475569; }
    [data-testid="stSidebar"] h2 { color: #4f46e5; font-weight: 700; }

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] {
        background: #ffffff;
        border-radius: 10px;
        padding: 8px 16px;
        color: #64748b;
        border: 1px solid #e2e8f0;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: #eef2ff;
        color: #4f46e5;
        border-color: #4f46e5;
        font-weight: 600;
    }

    /* Network info cards */
    .net-info-card {
        background: #ffffff;
        padding: 0.7rem 1rem;
        border-radius: 10px;
        margin-bottom: 0.5rem;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    }
    .net-info-card .info-label { color: #64748b; font-size: 0.8rem; font-weight: 500; }
    .net-info-card .info-value { color: #4f46e5; font-size: 1.1rem; font-weight: 600; }

    /* Footer */
    .footer {
        text-align: center;
        color: #94a3b8;
        padding: 1.5rem;
        font-size: 0.85rem;
        border-top: 1px solid #e2e8f0;
        margin-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────

st.markdown("""
<div class="main-header">
    <h1>🛡️ NetWatchAI</h1>
    <p>AI-Powered Network Monitoring & Intrusion Detection</p>
</div>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Auto-train model if not present
# ──────────────────────────────────────────────

if not os.path.exists(MODEL_PATH):
    from src.model import train_model
    with st.spinner("Training AI model for the first time..."):
        train_model()

# ──────────────────────────────────────────────
# Load Data
# ──────────────────────────────────────────────

@st.cache_data(ttl=5)
def load_packet_data():
    if os.path.exists(PACKETS_CSV):
        return pd.read_csv(PACKETS_CSV), "Live Capture"
    elif os.path.exists(SAMPLE_CSV):
        return pd.read_csv(SAMPLE_CSV), "Sample Data"
    return None, "No Data"


def run_detection(df):
    if not os.path.exists(MODEL_PATH):
        st.warning("No trained model found. Run `python train.py` first.")
        df["prediction"] = 0
        df["status"] = "Unknown"
        return df
    detector = AnomalyDetector()
    predictions = detector.predict_batch(df)
    df["prediction"] = predictions
    df["status"] = df["prediction"].map({1: "Normal", -1: "ANOMALY"})
    return df


df, data_source = load_packet_data()

if df is None:
    st.error("No packet data found. Run `sudo python capture.py` or ensure `data/sample_packets.csv` exists.")
    st.stop()

df = run_detection(df)
df["attack_type"] = df.apply(classify_attack, axis=1)

# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────

st.sidebar.markdown("## 🔧 Filters")
st.sidebar.markdown(f"**Source:** {data_source}")

protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
selected_protocol = st.sidebar.selectbox("Protocol", protocols)

status_options = ["All"] + sorted(df["status"].dropna().unique().tolist())
selected_status = st.sidebar.selectbox("Status", status_options)

attack_types = ["All"] + sorted(df["attack_type"].dropna().unique().tolist())
selected_attack = st.sidebar.selectbox("Attack Type", attack_types)

filtered_df = df.copy()
if selected_protocol != "All":
    filtered_df = filtered_df[filtered_df["protocol"] == selected_protocol]
if selected_status != "All":
    filtered_df = filtered_df[filtered_df["status"] == selected_status]
if selected_attack != "All":
    filtered_df = filtered_df[filtered_df["attack_type"] == selected_attack]

auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=False)
if auto_refresh:
    time.sleep(5)
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Total:** {len(df)} packets")
st.sidebar.markdown(f"**Filtered:** {len(filtered_df)} packets")

# ──────────────────────────────────────────────
# Metrics + Threat Level
# ──────────────────────────────────────────────

total_packets = len(df)
n_anomalies = int((df["prediction"] == -1).sum())
n_normal = int((df["prediction"] == 1).sum())
anomaly_pct = (n_anomalies / total_packets * 100) if total_packets > 0 else 0

# Determine threat level
if anomaly_pct == 0:
    threat_text, threat_class = "LOW — All Clear", "threat-low"
elif anomaly_pct < 5:
    threat_text, threat_class = "LOW — Minor Activity", "threat-low"
elif anomaly_pct < 15:
    threat_text, threat_class = "MEDIUM — Suspicious Activity", "threat-medium"
elif anomaly_pct < 30:
    threat_text, threat_class = "HIGH — Active Threats", "threat-high"
else:
    threat_text, threat_class = "CRITICAL — Under Attack", "threat-critical"

# Threat level bar
st.markdown(f"""
<div class="threat-bar">
    <span class="threat-label">Threat Level:</span>
    <span class="threat-level {threat_class}"> {threat_text}</span>
</div>
""", unsafe_allow_html=True)

# Metric cards
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""
    <div class="metric-card blue">
        <div class="label">Total Packets</div>
        <div class="value">{total_packets:,}</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""
    <div class="metric-card green">
        <div class="label">Normal</div>
        <div class="value">{n_normal:,}</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""
    <div class="metric-card red">
        <div class="label">Anomalies</div>
        <div class="value">{n_anomalies:,}</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""
    <div class="metric-card orange">
        <div class="label">Anomaly Rate</div>
        <div class="value">{anomaly_pct:.1f}%</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

anomaly_df = df[df["prediction"] == -1]

# ──────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🚨 Alerts",
    "🎯 Attack Types",
    "🏴‍☠️ Top Attackers",
    "📈 Timeline",
    "📊 Statistics",
    "📡 Network Info",
])

# ── Tab 1: Alerts + Packet Log ─────────────────

with tab1:
    if len(anomaly_df) == 0:
        st.success("All traffic looks normal. No anomalies detected.")
    else:
        st.error(f"{len(anomaly_df)} suspicious packet(s) detected!")
        alert_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type"]
        available_cols = [c for c in alert_cols if c in anomaly_df.columns]
        st.dataframe(anomaly_df[available_cols], use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown(f"**Packet Log** — {len(filtered_df)} of {len(df)} packets")

    display_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type", "status"]
    available_display = [c for c in display_cols if c in filtered_df.columns]

    if len(filtered_df) == 0:
        st.info("No packets match the selected filters.")
    else:
        st.dataframe(
            filtered_df[available_display].reset_index(drop=True),
            use_container_width=True,
            hide_index=True,
            height=350,
        )

# ── Tab 2: Attack Types ───────────────────────

with tab2:
    if len(anomaly_df) > 0:
        attack_col1, attack_col2 = st.columns(2)

        with attack_col1:
            attack_counts = anomaly_df["attack_type"].value_counts().reset_index()
            attack_counts.columns = ["Attack Type", "Count"]
            fig_attack = px.pie(
                attack_counts, values="Count", names="Attack Type",
                color_discrete_sequence=["#ef4444", "#f59e0b", "#f97316", "#8b5cf6", "#4f46e5", "#10b981"],
                hole=0.4,
            )
            fig_attack.update_layout(
                margin=dict(t=20, b=20, l=20, r=20),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#a0aec0",
            )
            st.plotly_chart(fig_attack, use_container_width=True)

        with attack_col2:
            attack_desc = {
                "Port Scan": "Attacker probing open ports",
                "Ping of Death": "Oversized ICMP packets",
                "Data Exfiltration": "Large data to suspicious ports",
                "Suspicious Port": "Traffic to known malicious ports",
                "Large Transfer": "Unusually large data transfer",
                "DNS Anomaly": "Suspicious DNS traffic",
                "Unknown Anomaly": "Unusual pattern detected",
            }
            attack_summary = anomaly_df["attack_type"].value_counts().reset_index()
            attack_summary.columns = ["Attack Type", "Count"]
            attack_summary["Description"] = attack_summary["Attack Type"].map(attack_desc).fillna("")
            st.dataframe(attack_summary, use_container_width=True, hide_index=True)
    else:
        st.success("No attacks detected.")

# ── Tab 3: Top Attackers ───────────────────────

with tab3:
    if len(anomaly_df) > 0:
        attacker_col1, attacker_col2 = st.columns(2)

        with attacker_col1:
            top_src = anomaly_df["src_ip"].value_counts().head(10).reset_index()
            top_src.columns = ["Source IP", "Anomaly Count"]
            top_src["Attack Types"] = top_src["Source IP"].apply(
                lambda ip: ", ".join(anomaly_df[anomaly_df["src_ip"] == ip]["attack_type"].unique())
            )
            st.markdown("**Top Suspicious Source IPs**")
            st.dataframe(top_src, use_container_width=True, hide_index=True)

        with attacker_col2:
            top_dst = anomaly_df["dst_ip"].value_counts().head(10).reset_index()
            top_dst.columns = ["Destination IP", "Attack Count"]
            top_dst["Targeted Ports"] = top_dst["Destination IP"].apply(
                lambda ip: ", ".join(
                    str(p) for p in anomaly_df[anomaly_df["dst_ip"] == ip]["dst_port"].unique()[:5]
                )
            )
            st.markdown("**Top Targeted Destinations**")
            st.dataframe(top_dst, use_container_width=True, hide_index=True)

        fig_attackers = px.bar(
            top_src, x="Anomaly Count", y="Source IP",
            orientation="h", color="Anomaly Count", color_continuous_scale="Purples",
        )
        fig_attackers.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            yaxis=dict(autorange="reversed"), showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
        )
        st.plotly_chart(fig_attackers, use_container_width=True)
    else:
        st.success("No attackers detected.")

# ── Tab 4: Timeline ───────────────────────────

with tab4:
    if "timestamp" not in df.columns:
        st.warning("No timestamp column found in packet data. Timeline is unavailable.")
    else:
        timeline_df = df.copy()
        timeline_df["timestamp"] = pd.to_datetime(timeline_df["timestamp"], errors="coerce")
        timeline_df = timeline_df.dropna(subset=["timestamp"])

        if len(timeline_df) == 0:
            st.warning("Could not parse any timestamps. Timeline is unavailable.")
        else:
            timeline_df["time_bucket"] = timeline_df["timestamp"].dt.floor("1min")
            timeline_grouped = timeline_df.groupby(["time_bucket", "status"]).size().reset_index(name="count")

            fig_timeline = px.area(
                timeline_grouped, x="time_bucket", y="count", color="status",
                color_discrete_map={"Normal": "#10b981", "ANOMALY": "#ef4444", "Unknown": "#94a3b8"},
                labels={"time_bucket": "Time", "count": "Packets", "status": "Status"},
            )
            fig_timeline.update_layout(
                margin=dict(t=20, b=20, l=20, r=20),
                xaxis_title="Time", yaxis_title="Packet Count", hovermode="x unified",
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#a0aec0",
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

            anomaly_timeline = timeline_df[timeline_df["status"] == "ANOMALY"]
            if len(anomaly_timeline) > 0:
                anomaly_by_type = anomaly_timeline.groupby(["time_bucket", "attack_type"]).size().reset_index(name="count")
                fig_attack_timeline = px.bar(
                    anomaly_by_type, x="time_bucket", y="count", color="attack_type",
                    color_discrete_sequence=["#ef4444", "#f59e0b", "#f97316", "#8b5cf6", "#4f46e5", "#10b981"],
                    labels={"time_bucket": "Time", "count": "Attacks", "attack_type": "Attack Type"},
                )
                fig_attack_timeline.update_layout(
                    margin=dict(t=20, b=20, l=20, r=20),
                    xaxis_title="Time", yaxis_title="Attack Count",
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font_color="#a0aec0",
                )
                st.markdown("**Attacks Over Time (by type)**")
                st.plotly_chart(fig_attack_timeline, use_container_width=True)

# ── Tab 5: Statistics ──────────────────────────

with tab5:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("**Protocol Distribution**")
        protocol_counts = df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["Protocol", "Count"]
        fig_proto = px.pie(
            protocol_counts, values="Count", names="Protocol",
            color_discrete_sequence=["#4f46e5", "#10b981", "#f59e0b", "#8b5cf6"],
            hole=0.4,
        )
        fig_proto.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
        )
        st.plotly_chart(fig_proto, use_container_width=True)

    with chart_col2:
        st.markdown("**Normal vs Anomaly Traffic**")
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        fig_status = px.bar(
            status_counts, x="Status", y="Count", color="Status",
            color_discrete_map={"Normal": "#10b981", "ANOMALY": "#ef4444", "Unknown": "#94a3b8"},
        )
        fig_status.update_layout(
            margin=dict(t=20, b=20, l=20, r=20), showlegend=False,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
        )
        st.plotly_chart(fig_status, use_container_width=True)

    st.markdown("**Packet Size Distribution**")
    fig_size = px.histogram(
        df, x="packet_size", color="status", nbins=30,
        color_discrete_map={"Normal": "#10b981", "ANOMALY": "#ef4444", "Unknown": "#94a3b8"},
        labels={"packet_size": "Packet Size (bytes)", "status": "Status"},
    )
    fig_size.update_layout(
        margin=dict(t=20, b=20, l=20, r=20),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#a0aec0",
    )
    st.plotly_chart(fig_size, use_container_width=True)

# ── Tab 6: Network Info ────────────────────────

with tab6:
    net_info = get_network_info()

    info_col1, info_col2 = st.columns(2)

    with info_col1:
        st.markdown("**WiFi & Connection**")
        wifi_keys = ["WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel", "Hostname"]
        wifi_data = {k: net_info.get(k, "N/A") for k in wifi_keys}
        for key, val in wifi_data.items():
            safe_val = html_module.escape(str(val))
            st.markdown(f"""
            <div class="net-info-card">
                <span class="info-label">{key}</span><br>
                <span class="info-value">{safe_val}</span>
            </div>""", unsafe_allow_html=True)

    with info_col2:
        st.markdown("**IP & Routing**")
        ip_keys = ["Local IP", "Public IP", "Gateway (Router)", "Subnet Mask", "MAC Address", "DNS Servers"]
        ip_data = {k: net_info.get(k, "N/A") for k in ip_keys}
        for key, val in ip_data.items():
            safe_val = html_module.escape(str(val))
            st.markdown(f"""
            <div class="net-info-card">
                <span class="info-label">{key}</span><br>
                <span class="info-value">{safe_val}</span>
            </div>""", unsafe_allow_html=True)

    # Signal strength gauge
    signal_str = net_info.get("Signal Strength", "")
    if "dBm" in signal_str:
        rssi_val = int(signal_str.split(" ")[0])
        # Map RSSI (-100 to -30) to gauge (0-100)
        gauge_val = max(0, min(100, (rssi_val + 100) * 100 // 70))
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=gauge_val,
            title={"text": "WiFi Signal Quality", "font": {"color": "#475569"}},
            number={"suffix": "%", "font": {"color": "#4f46e5"}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                "bar": {"color": "#4f46e5"},
                "bgcolor": "#f1f5f9",
                "steps": [
                    {"range": [0, 30], "color": "#fee2e2"},
                    {"range": [30, 60], "color": "#fef3c7"},
                    {"range": [60, 100], "color": "#d1fae5"},
                ],
            },
        ))
        fig_gauge.update_layout(
            height=250,
            margin=dict(t=40, b=20, l=40, r=40),
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────

st.markdown(
    '<div class="footer">NetWatchAI — AI Network Monitoring & Intrusion Detection System</div>',
    unsafe_allow_html=True,
)
