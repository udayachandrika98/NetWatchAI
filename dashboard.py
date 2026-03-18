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
    <style>
        .login-container {
            max-width: 420px;
            margin: 6rem auto 0 auto;
            text-align: center;
        }
        .login-logo {
            width: 80px; height: 80px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6, #a78bfa);
            border-radius: 20px;
            display: inline-flex; align-items: center; justify-content: center;
            font-size: 2.2rem;
            box-shadow: 0 8px 30px rgba(99, 102, 241, 0.35);
            margin-bottom: 1.2rem;
        }
        .login-title {
            font-size: 1.8rem; font-weight: 800;
            background: linear-gradient(135deg, #4f46e5, #7c3aed);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            margin: 0;
        }
        .login-subtitle {
            color: #94a3b8; font-size: 0.95rem; margin: 0.4rem 0 2rem 0;
        }
    </style>
    <div class="login-container">
        <div class="login-logo">🛡️</div>
        <h1 class="login-title">NetWatchAI</h1>
        <p class="login-subtitle">AI-Powered Network Monitoring & Intrusion Detection</p>
    </div>
    """, unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1.3, 1, 1.3])
    with col2:
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)
        if st.button("Sign In", use_container_width=True, type="primary"):
            if password == VALID_PASSWORD:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password. Please try again.")
    st.stop()

# ──────────────────────────────────────────────
# Main Dashboard CSS
# ──────────────────────────────────────────────

st.markdown("""
<style>
    /* ── Header banner ── */
    .main-header {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #a855f7 100%);
        padding: 1.8rem 2rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        color: white;
        box-shadow: 0 4px 20px rgba(79, 70, 229, 0.35);
        position: relative;
        overflow: hidden;
    }
    .main-header::before {
        content: '';
        position: absolute;
        top: -50%; right: -20%;
        width: 300px; height: 300px;
        background: rgba(255,255,255,0.05);
        border-radius: 50%;
    }
    .main-header h1 { color: #fff; margin: 0; font-size: 2rem; font-weight: 800; position: relative; }
    .main-header p { color: #e0e7ff; margin: 0.3rem 0 0 0; font-size: 1rem; position: relative; }

    /* ── Metric cards with colored left border ── */
    .metric-card {
        background: #ffffff;
        border-radius: 14px;
        padding: 1.2rem 1.4rem;
        text-align: left;
        border: 1px solid #f1f5f9;
        transition: transform 0.2s, box-shadow 0.2s;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        position: relative;
        overflow: hidden;
    }
    .metric-card::before {
        content: '';
        position: absolute;
        left: 0; top: 0; bottom: 0;
        width: 4px;
        border-radius: 4px 0 0 4px;
    }
    .metric-card:hover { transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0,0,0,0.08); }
    .metric-card .icon { font-size: 1.6rem; margin-bottom: 0.3rem; }
    .metric-card .label { color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
    .metric-card .value { font-size: 2rem; font-weight: 800; margin: 0.2rem 0; }

    .metric-card.blue::before { background: linear-gradient(180deg, #6366f1, #4f46e5); }
    .metric-card.blue .value { color: #4f46e5; }
    .metric-card.blue .icon { color: #6366f1; }

    .metric-card.green::before { background: linear-gradient(180deg, #34d399, #10b981); }
    .metric-card.green .value { color: #059669; }
    .metric-card.green .icon { color: #10b981; }

    .metric-card.red::before { background: linear-gradient(180deg, #f87171, #ef4444); }
    .metric-card.red .value { color: #dc2626; }
    .metric-card.red .icon { color: #ef4444; }

    .metric-card.orange::before { background: linear-gradient(180deg, #fbbf24, #f59e0b); }
    .metric-card.orange .value { color: #d97706; }
    .metric-card.orange .icon { color: #f59e0b; }

    /* ── Threat level bar ── */
    .threat-bar {
        background: #ffffff;
        border-radius: 14px;
        padding: 1rem 1.5rem;
        margin-bottom: 1.2rem;
        border: 1px solid #f1f5f9;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .threat-icon { font-size: 1.5rem; }
    .threat-label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 1.2px; font-weight: 600; }
    .threat-level { font-size: 1.2rem; font-weight: 700; }
    .threat-low { color: #059669; }
    .threat-medium { color: #d97706; }
    .threat-high { color: #ea580c; }
    .threat-critical { color: #dc2626; }

    .threat-dot {
        width: 10px; height: 10px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 6px;
        animation: pulse-dot 2s ease-in-out infinite;
    }
    .dot-low { background: #10b981; box-shadow: 0 0 8px #10b981; }
    .dot-medium { background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }
    .dot-high { background: #f97316; box-shadow: 0 0 8px #f97316; }
    .dot-critical { background: #ef4444; box-shadow: 0 0 8px #ef4444; animation: pulse-dot 0.8s ease-in-out infinite; }

    @keyframes pulse-dot {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(1.3); }
    }

    /* ── Alert cards ── */
    .alert-card {
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: flex-start;
        gap: 0.8rem;
    }
    .alert-danger {
        background: linear-gradient(135deg, #fef2f2, #fee2e2);
        border-left: 4px solid #ef4444;
    }
    .alert-success {
        background: linear-gradient(135deg, #f0fdf4, #dcfce7);
        border-left: 4px solid #10b981;
    }
    .alert-icon { font-size: 1.3rem; margin-top: 2px; }
    .alert-text { flex: 1; }
    .alert-title { font-weight: 700; color: #1e293b; font-size: 0.95rem; }
    .alert-desc { color: #64748b; font-size: 0.85rem; margin-top: 2px; }

    /* ── Section headers ── */
    .section-header {
        display: flex; align-items: center; gap: 0.5rem;
        margin: 0.5rem 0 1rem 0;
    }
    .section-header .section-icon {
        width: 36px; height: 36px;
        border-radius: 10px;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: 1.1rem;
    }
    .section-header .section-title {
        font-size: 1.1rem; font-weight: 700; color: #1e293b; margin: 0;
    }
    .section-header .section-subtitle {
        font-size: 0.8rem; color: #94a3b8; margin: 0;
    }

    /* ── Network info cards ── */
    .net-info-card {
        background: #ffffff;
        padding: 0.8rem 1rem;
        border-radius: 12px;
        margin-bottom: 0.6rem;
        border: 1px solid #f1f5f9;
        box-shadow: 0 1px 4px rgba(0,0,0,0.03);
        display: flex;
        align-items: center;
        gap: 0.8rem;
    }
    .net-icon {
        width: 38px; height: 38px;
        border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.1rem;
        flex-shrink: 0;
    }
    .net-icon-wifi { background: #eef2ff; }
    .net-icon-ip { background: #f0fdf4; }
    .net-info-text { flex: 1; }
    .info-label { color: #94a3b8; font-size: 0.75rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-value { color: #1e293b; font-size: 1rem; font-weight: 600; }

    /* ── Sidebar styling ── */
    [data-testid="stSidebar"] { background: linear-gradient(180deg, #f8fafc, #eef2ff); }
    [data-testid="stSidebar"] .stMarkdown p { color: #475569; }
    [data-testid="stSidebar"] h2 { color: #4f46e5; font-weight: 700; }

    /* ── Tab styling ── */
    .stTabs [data-baseweb="tab-list"] { gap: 6px; }
    .stTabs [data-baseweb="tab"] {
        background: #ffffff;
        border-radius: 10px;
        padding: 8px 16px;
        color: #64748b;
        border: 1px solid #e2e8f0;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #eef2ff, #e0e7ff);
        color: #4f46e5;
        border-color: #818cf8;
        font-weight: 600;
    }

    /* ── Footer ── */
    .footer {
        text-align: center;
        color: #94a3b8;
        padding: 1.5rem;
        font-size: 0.85rem;
        border-top: 1px solid #e2e8f0;
        margin-top: 2rem;
    }
    .footer a { color: #6366f1; text-decoration: none; }
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
    threat_text, threat_class, threat_icon, dot_class = "LOW — All Clear", "threat-low", "✅", "dot-low"
elif anomaly_pct < 5:
    threat_text, threat_class, threat_icon, dot_class = "LOW — Minor Activity", "threat-low", "✅", "dot-low"
elif anomaly_pct < 15:
    threat_text, threat_class, threat_icon, dot_class = "MEDIUM — Suspicious Activity", "threat-medium", "⚠️", "dot-medium"
elif anomaly_pct < 30:
    threat_text, threat_class, threat_icon, dot_class = "HIGH — Active Threats", "threat-high", "🔶", "dot-high"
else:
    threat_text, threat_class, threat_icon, dot_class = "CRITICAL — Under Attack", "threat-critical", "🚨", "dot-critical"

# Threat level bar
st.markdown(f"""
<div class="threat-bar">
    <span class="threat-icon">{threat_icon}</span>
    <div>
        <div class="threat-label">Threat Level</div>
        <div class="threat-level {threat_class}">
            <span class="threat-dot {dot_class}"></span>
            {threat_text}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Metric cards with icons
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""
    <div class="metric-card blue">
        <div class="icon">📊</div>
        <div class="label">Total Packets</div>
        <div class="value">{total_packets:,}</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""
    <div class="metric-card green">
        <div class="icon">✅</div>
        <div class="label">Normal</div>
        <div class="value">{n_normal:,}</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""
    <div class="metric-card red">
        <div class="icon">🚨</div>
        <div class="label">Anomalies</div>
        <div class="value">{n_anomalies:,}</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""
    <div class="metric-card orange">
        <div class="icon">📈</div>
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

# Chart color palette
CHART_COLORS = ["#6366f1", "#8b5cf6", "#a855f7", "#ec4899", "#f43f5e", "#f97316", "#eab308", "#22c55e", "#06b6d4", "#3b82f6"]
NORMAL_COLOR = "#22c55e"
ANOMALY_COLOR = "#ef4444"
UNKNOWN_COLOR = "#cbd5e1"
CHART_FONT_COLOR = "#475569"
CHART_BG = "rgba(0,0,0,0)"

# ── Tab 1: Alerts + Packet Log ─────────────────

with tab1:
    if len(anomaly_df) == 0:
        st.markdown("""
        <div class="alert-card alert-success">
            <div class="alert-icon">✅</div>
            <div class="alert-text">
                <div class="alert-title">All Clear</div>
                <div class="alert-desc">No anomalies detected. All traffic looks normal.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="alert-card alert-danger">
            <div class="alert-icon">🚨</div>
            <div class="alert-text">
                <div class="alert-title">{len(anomaly_df)} Suspicious Packet(s) Detected</div>
                <div class="alert-desc">Review the anomalies below. Immediate attention may be required.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        alert_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type"]
        available_cols = [c for c in alert_cols if c in anomaly_df.columns]
        st.dataframe(anomaly_df[available_cols], use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown(f"""
    <div class="section-header">
        <div class="section-icon" style="background:#eef2ff;">📋</div>
        <div>
            <p class="section-title">Packet Log</p>
            <p class="section-subtitle">{len(filtered_df)} of {len(df)} packets</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

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
            st.markdown("""
            <div class="section-header">
                <div class="section-icon" style="background:#fef2f2;">🎯</div>
                <div><p class="section-title">Attack Distribution</p></div>
            </div>
            """, unsafe_allow_html=True)
            attack_counts = anomaly_df["attack_type"].value_counts().reset_index()
            attack_counts.columns = ["Attack Type", "Count"]
            fig_attack = px.pie(
                attack_counts, values="Count", names="Attack Type",
                color_discrete_sequence=CHART_COLORS,
                hole=0.45,
            )
            fig_attack.update_traces(textinfo="percent+label", textfont_size=12)
            fig_attack.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=CHART_FONT_COLOR,
                legend=dict(font=dict(size=11)),
            )
            st.plotly_chart(fig_attack, use_container_width=True)

        with attack_col2:
            st.markdown("""
            <div class="section-header">
                <div class="section-icon" style="background:#fef3c7;">📝</div>
                <div><p class="section-title">Attack Details</p></div>
            </div>
            """, unsafe_allow_html=True)
            attack_desc = {
                "Port Scan": "Attacker probing open ports on your system",
                "Ping of Death": "Oversized ICMP packets to crash targets",
                "Data Exfiltration": "Sensitive data being sent to external servers",
                "Suspicious Port": "Traffic to known backdoor/malware ports",
                "Large Transfer": "Unusually large data transfer detected",
                "DNS Anomaly": "Suspicious DNS traffic (possible tunneling)",
                "Unknown Anomaly": "Unusual pattern that doesn't match known attacks",
            }
            attack_summary = anomaly_df["attack_type"].value_counts().reset_index()
            attack_summary.columns = ["Attack Type", "Count"]
            attack_summary["Description"] = attack_summary["Attack Type"].map(attack_desc).fillna("")
            st.dataframe(attack_summary, use_container_width=True, hide_index=True)
    else:
        st.markdown("""
        <div class="alert-card alert-success">
            <div class="alert-icon">🎯</div>
            <div class="alert-text">
                <div class="alert-title">No Attacks Detected</div>
                <div class="alert-desc">Your network looks clean. No attack patterns found.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Tab 3: Top Attackers ───────────────────────

with tab3:
    if len(anomaly_df) > 0:
        attacker_col1, attacker_col2 = st.columns(2)

        with attacker_col1:
            st.markdown("""
            <div class="section-header">
                <div class="section-icon" style="background:#fef2f2;">🔴</div>
                <div><p class="section-title">Top Suspicious Sources</p></div>
            </div>
            """, unsafe_allow_html=True)
            top_src = anomaly_df["src_ip"].value_counts().head(10).reset_index()
            top_src.columns = ["Source IP", "Anomaly Count"]
            top_src["Attack Types"] = top_src["Source IP"].apply(
                lambda ip: ", ".join(anomaly_df[anomaly_df["src_ip"] == ip]["attack_type"].unique())
            )
            st.dataframe(top_src, use_container_width=True, hide_index=True)

        with attacker_col2:
            st.markdown("""
            <div class="section-header">
                <div class="section-icon" style="background:#fff7ed;">🎯</div>
                <div><p class="section-title">Top Targeted Destinations</p></div>
            </div>
            """, unsafe_allow_html=True)
            top_dst = anomaly_df["dst_ip"].value_counts().head(10).reset_index()
            top_dst.columns = ["Destination IP", "Attack Count"]
            top_dst["Targeted Ports"] = top_dst["Destination IP"].apply(
                lambda ip: ", ".join(
                    str(p) for p in anomaly_df[anomaly_df["dst_ip"] == ip]["dst_port"].unique()[:5]
                )
            )
            st.dataframe(top_dst, use_container_width=True, hide_index=True)

        fig_attackers = px.bar(
            top_src, x="Anomaly Count", y="Source IP",
            orientation="h", color="Anomaly Count",
            color_continuous_scale=[[0, "#c7d2fe"], [0.5, "#818cf8"], [1, "#4f46e5"]],
        )
        fig_attackers.update_layout(
            margin=dict(t=20, b=20, l=20, r=20),
            yaxis=dict(autorange="reversed"), showlegend=False,
            paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
            font_color=CHART_FONT_COLOR,
        )
        st.plotly_chart(fig_attackers, use_container_width=True)
    else:
        st.markdown("""
        <div class="alert-card alert-success">
            <div class="alert-icon">🏴‍☠️</div>
            <div class="alert-text">
                <div class="alert-title">No Attackers Detected</div>
                <div class="alert-desc">No suspicious source IPs found in the traffic.</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

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
            st.markdown("""
            <div class="section-header">
                <div class="section-icon" style="background:#eef2ff;">📈</div>
                <div><p class="section-title">Traffic Over Time</p></div>
            </div>
            """, unsafe_allow_html=True)

            timeline_df["time_bucket"] = timeline_df["timestamp"].dt.floor("1min")
            timeline_grouped = timeline_df.groupby(["time_bucket", "status"]).size().reset_index(name="count")

            fig_timeline = px.area(
                timeline_grouped, x="time_bucket", y="count", color="status",
                color_discrete_map={"Normal": NORMAL_COLOR, "ANOMALY": ANOMALY_COLOR, "Unknown": UNKNOWN_COLOR},
                labels={"time_bucket": "Time", "count": "Packets", "status": "Status"},
            )
            fig_timeline.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                xaxis_title="Time", yaxis_title="Packet Count", hovermode="x unified",
                paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                font_color=CHART_FONT_COLOR,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

            anomaly_timeline = timeline_df[timeline_df["status"] == "ANOMALY"]
            if len(anomaly_timeline) > 0:
                st.markdown("""
                <div class="section-header">
                    <div class="section-icon" style="background:#fef2f2;">⏱️</div>
                    <div><p class="section-title">Attacks Over Time</p></div>
                </div>
                """, unsafe_allow_html=True)
                anomaly_by_type = anomaly_timeline.groupby(["time_bucket", "attack_type"]).size().reset_index(name="count")
                fig_attack_timeline = px.bar(
                    anomaly_by_type, x="time_bucket", y="count", color="attack_type",
                    color_discrete_sequence=CHART_COLORS,
                    labels={"time_bucket": "Time", "count": "Attacks", "attack_type": "Attack Type"},
                )
                fig_attack_timeline.update_layout(
                    margin=dict(t=10, b=10, l=10, r=10),
                    xaxis_title="Time", yaxis_title="Attack Count",
                    paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
                    font_color=CHART_FONT_COLOR,
                    legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                )
                st.plotly_chart(fig_attack_timeline, use_container_width=True)

# ── Tab 5: Statistics ──────────────────────────

with tab5:
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon" style="background:#eef2ff;">🌐</div>
            <div><p class="section-title">Protocol Distribution</p></div>
        </div>
        """, unsafe_allow_html=True)
        protocol_counts = df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["Protocol", "Count"]
        fig_proto = px.pie(
            protocol_counts, values="Count", names="Protocol",
            color_discrete_sequence=CHART_COLORS,
            hole=0.45,
        )
        fig_proto.update_traces(textinfo="percent+label", textfont_size=12)
        fig_proto.update_layout(
            margin=dict(t=10, b=10, l=10, r=10),
            paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
            font_color=CHART_FONT_COLOR,
        )
        st.plotly_chart(fig_proto, use_container_width=True)

    with chart_col2:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon" style="background:#f0fdf4;">⚖️</div>
            <div><p class="section-title">Normal vs Anomaly</p></div>
        </div>
        """, unsafe_allow_html=True)
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        fig_status = px.bar(
            status_counts, x="Status", y="Count", color="Status",
            color_discrete_map={"Normal": NORMAL_COLOR, "ANOMALY": ANOMALY_COLOR, "Unknown": UNKNOWN_COLOR},
        )
        fig_status.update_layout(
            margin=dict(t=10, b=10, l=10, r=10), showlegend=False,
            paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
            font_color=CHART_FONT_COLOR,
        )
        fig_status.update_traces(marker_line_width=0, opacity=0.9)
        st.plotly_chart(fig_status, use_container_width=True)

    st.markdown("""
    <div class="section-header">
        <div class="section-icon" style="background:#fef3c7;">📦</div>
        <div><p class="section-title">Packet Size Distribution</p></div>
    </div>
    """, unsafe_allow_html=True)
    fig_size = px.histogram(
        df, x="packet_size", color="status", nbins=30,
        color_discrete_map={"Normal": NORMAL_COLOR, "ANOMALY": ANOMALY_COLOR, "Unknown": UNKNOWN_COLOR},
        labels={"packet_size": "Packet Size (bytes)", "status": "Status"},
    )
    fig_size.update_layout(
        margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font_color=CHART_FONT_COLOR,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig_size, use_container_width=True)

# ── Tab 6: Network Info ────────────────────────

WIFI_ICONS = {
    "WiFi Network (SSID)": "📶",
    "Signal Strength": "📡",
    "Link Speed": "⚡",
    "Channel": "📻",
    "Hostname": "💻",
}
IP_ICONS = {
    "Local IP": "🏠",
    "Public IP": "🌐",
    "Gateway (Router)": "🔀",
    "Subnet Mask": "🎭",
    "MAC Address": "🔖",
    "DNS Servers": "📇",
}

with tab6:
    net_info = get_network_info()

    info_col1, info_col2 = st.columns(2)

    with info_col1:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon" style="background:#eef2ff;">📶</div>
            <div><p class="section-title">WiFi & Connection</p></div>
        </div>
        """, unsafe_allow_html=True)
        wifi_keys = ["WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel", "Hostname"]
        for key in wifi_keys:
            val = net_info.get(key, "N/A")
            safe_val = html_module.escape(str(val))
            icon = WIFI_ICONS.get(key, "📌")
            st.markdown(f"""
            <div class="net-info-card">
                <div class="net-icon net-icon-wifi">{icon}</div>
                <div class="net-info-text">
                    <div class="info-label">{key}</div>
                    <div class="info-value">{safe_val}</div>
                </div>
            </div>""", unsafe_allow_html=True)

    with info_col2:
        st.markdown("""
        <div class="section-header">
            <div class="section-icon" style="background:#f0fdf4;">🌐</div>
            <div><p class="section-title">IP & Routing</p></div>
        </div>
        """, unsafe_allow_html=True)
        ip_keys = ["Local IP", "Public IP", "Gateway (Router)", "Subnet Mask", "MAC Address", "DNS Servers"]
        for key in ip_keys:
            val = net_info.get(key, "N/A")
            safe_val = html_module.escape(str(val))
            icon = IP_ICONS.get(key, "📌")
            st.markdown(f"""
            <div class="net-info-card">
                <div class="net-icon net-icon-ip">{icon}</div>
                <div class="net-info-text">
                    <div class="info-label">{key}</div>
                    <div class="info-value">{safe_val}</div>
                </div>
            </div>""", unsafe_allow_html=True)

    # Signal strength gauge
    signal_str = net_info.get("Signal Strength", "")
    if "dBm" in signal_str:
        rssi_val = int(signal_str.split(" ")[0])
        gauge_val = max(0, min(100, (rssi_val + 100) * 100 // 70))
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=gauge_val,
            title={"text": "WiFi Signal Quality", "font": {"color": "#475569", "size": 16}},
            number={"suffix": "%", "font": {"color": "#4f46e5", "size": 36}},
            gauge={
                "axis": {"range": [0, 100], "tickcolor": "#94a3b8"},
                "bar": {"color": "#6366f1", "thickness": 0.75},
                "bgcolor": "#f1f5f9",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 30], "color": "#fee2e2"},
                    {"range": [30, 60], "color": "#fef3c7"},
                    {"range": [60, 100], "color": "#d1fae5"},
                ],
                "threshold": {
                    "line": {"color": "#4f46e5", "width": 3},
                    "thickness": 0.8,
                    "value": gauge_val,
                },
            },
        ))
        fig_gauge.update_layout(
            height=260,
            margin=dict(t=50, b=20, l=40, r=40),
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#475569",
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────

st.markdown(
    '<div class="footer">🛡️ NetWatchAI — AI-Powered Network Monitoring & Intrusion Detection</div>',
    unsafe_allow_html=True,
)
