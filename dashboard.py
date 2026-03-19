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
    try:
        result = subprocess.run(["networksetup", "-getairportnetwork", "en0"], capture_output=True, text=True, timeout=5)
        line = result.stdout.strip()
        info["WiFi Network (SSID)"] = line.split(": ", 1)[1] if ": " in line else "Not connected"
    except Exception:
        info["WiFi Network (SSID)"] = "N/A"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            info["Local IP"] = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        info["Local IP"] = "N/A"
    try:
        result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            if "gateway" in line.lower():
                info["Gateway (Router)"] = line.split(":", 1)[1].strip()
                break
    except Exception:
        info["Gateway (Router)"] = "N/A"
    try:
        result = subprocess.run(["scutil", "--dns"], capture_output=True, text=True, timeout=5)
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
    try:
        result = subprocess.run(["ifconfig", "en0"], capture_output=True, text=True, timeout=5)
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
    try:
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("agrCtlRSSI"):
                rssi = int(stripped.split(":")[1].strip())
                strength = "Excellent" if rssi > -50 else "Good" if rssi > -60 else "Fair" if rssi > -70 else "Weak"
                info["Signal Strength"] = f"{rssi} dBm ({strength})"
            if stripped.startswith("lastTxRate"):
                info["Link Speed"] = stripped.split(":")[1].strip() + " Mbps"
            if stripped.startswith("channel"):
                info["Channel"] = stripped.split(":")[1].strip()
    except Exception:
        info["Signal Strength"] = "N/A"
    info["Hostname"] = socket.gethostname()
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
    if row.get("status") != "ANOMALY":
        return "Normal"
    protocol = str(row.get("protocol", "")).upper()
    try: dst_port = int(row.get("dst_port", 0))
    except (ValueError, TypeError): dst_port = 0
    try: src_port = int(row.get("src_port", 0))
    except (ValueError, TypeError): src_port = 0
    try: packet_size = int(row.get("packet_size", 0))
    except (ValueError, TypeError): packet_size = 0
    flags = str(row.get("flags", ""))
    if protocol == "ICMP" and packet_size > 1000: return "Ping of Death"
    if protocol == "TCP" and flags == "S" and packet_size <= 60: return "Port Scan"
    if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
        return "Data Exfiltration" if packet_size > 1000 else "Suspicious Port"
    if packet_size > 5000: return "Large Transfer"
    if protocol == "UDP" and dst_port == 53 and packet_size > 200: return "DNS Anomaly"
    return "Unknown Anomaly"


# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────

st.set_page_config(page_title="NetWatchAI", page_icon="🛡️", layout="wide")

# ──────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────

VALID_PASSWORD = os.environ.get("NETWATCHAI_PASSWORD", "admin123")

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("""
    <style>
        @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-10px)} }
        .login-wrap { text-align:center; padding:4rem 0 1rem; }
        .login-shield {
            font-size: 4rem;
            animation: float 3s ease-in-out infinite;
            display: inline-block;
        }
        .login-brand {
            font-size: 2.5rem; font-weight: 900;
            background: linear-gradient(90deg, #00e5ff, #7c4dff, #00e5ff);
            background-size: 200% auto;
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            animation: shimmer 3s linear infinite;
            margin: 0.5rem 0 0 0;
        }
        @keyframes shimmer { 0%{background-position:0%} 100%{background-position:200%} }
        .login-sub { color: #64748b; font-size:1rem; margin:0.3rem 0 0; }
        .login-tagline {
            display: inline-block; margin-top: 1.5rem;
            padding: 0.4rem 1.2rem; border-radius: 20px;
            background: rgba(0,229,255,0.08); border: 1px solid rgba(0,229,255,0.2);
            color: #00e5ff; font-size: 0.8rem; font-weight: 500; letter-spacing: 2px;
        }
    </style>
    <div class="login-wrap">
        <div class="login-shield">🛡️</div>
        <h1 class="login-brand">NetWatchAI</h1>
        <p class="login-sub">AI-Powered Network Intrusion Detection</p>
        <div class="login-tagline">SECURE ACCESS REQUIRED</div>
    </div>
    """, unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1.3, 1, 1.3])
    with col2:
        st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)
        password = st.text_input("Password", type="password", placeholder="Enter access code")
        st.markdown("<div style='height:0.3rem'></div>", unsafe_allow_html=True)
        if st.button("Access Dashboard", use_container_width=True, type="primary"):
            if password == VALID_PASSWORD:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Access denied. Invalid credentials.")
    st.stop()

# ──────────────────────────────────────────────
# Main CSS — Cybersecurity Dark Theme
# ──────────────────────────────────────────────

st.markdown("""
<style>
    /* ── Global ── */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');
    * { font-family: 'Inter', sans-serif !important; }

    .stApp {
        background: linear-gradient(160deg, #0a0e1a 0%, #0f172a 40%, #0c1322 100%);
    }

    /* Hide streamlit branding */
    #MainMenu, footer, header { visibility: hidden; }
    .stDeployButton { display: none; }

    /* ── Header ── */
    .cyber-header {
        background: linear-gradient(135deg, rgba(0,229,255,0.1), rgba(124,77,255,0.1));
        border: 1px solid rgba(0,229,255,0.15);
        border-radius: 16px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(10px);
    }
    .cyber-header::before {
        content: '';
        position: absolute; top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, #00e5ff, #7c4dff, #00e5ff, transparent);
        animation: scan 3s linear infinite;
    }
    @keyframes scan { 0%{transform:translateX(-100%)} 100%{transform:translateX(100%)} }
    .cyber-header h1 {
        color: #fff; font-size: 1.8rem; font-weight: 900; margin: 0;
    }
    .cyber-header .header-sub { color: #94a3b8; font-size: 0.9rem; margin: 0.2rem 0 0; }
    .header-badge {
        display: inline-block; margin-top: 0.5rem;
        padding: 0.2rem 0.8rem; border-radius: 4px;
        font-size: 0.7rem; font-weight: 700; letter-spacing: 1.5px;
        text-transform: uppercase;
    }
    .badge-live { background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
    .badge-sample { background: rgba(0,229,255,0.1); color: #67e8f9; border: 1px solid rgba(0,229,255,0.2); }

    /* ── Metric cards ── */
    .mc {
        background: rgba(15,23,42,0.6);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 0.8rem 1rem;
        border-left: 3px solid;
    }
    .mc .mc-label {
        color: #64748b; font-size: 0.65rem; font-weight: 600;
        text-transform: uppercase; letter-spacing: 1.5px;
    }
    .mc .mc-val {
        font-size: 1.8rem; font-weight: 800; margin: 0.1rem 0 0;
        letter-spacing: -0.5px;
    }
    .mc .mc-sub { color: #475569; font-size: 0.7rem; }

    .mc-cyan { border-left-color: #00e5ff; }
    .mc-cyan .mc-val { color: #00e5ff; }

    .mc-green { border-left-color: #34d399; }
    .mc-green .mc-val { color: #34d399; }

    .mc-red { border-left-color: #f87171; }
    .mc-red .mc-val { color: #f87171; }

    .mc-amber { border-left-color: #fbbf24; }
    .mc-amber .mc-val { color: #fbbf24; }

    /* ── Threat bar ── */
    .threat-bar {
        background: rgba(15,23,42,0.6);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 0.8rem 1.5rem;
        margin-bottom: 1.2rem;
        display: flex; align-items: center; gap: 1rem;
    }
    .tb-icon { font-size: 1.6rem; }
    .tb-label { color: #475569; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 1.5px; }
    .tb-status { font-size: 1.1rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
    .pulse {
        width: 10px; height: 10px; border-radius: 50%;
        display: inline-block;
        animation: pulse 2s ease-in-out infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1;box-shadow:0 0 0 0 currentColor} 50%{opacity:0.6;box-shadow:0 0 0 8px transparent} }
    .pulse-g { background:#34d399; color:#34d399; }
    .pulse-y { background:#fbbf24; color:#fbbf24; animation-duration:1.5s; }
    .pulse-o { background:#fb923c; color:#fb923c; animation-duration:1s; }
    .pulse-r { background:#f87171; color:#f87171; animation-duration:0.6s; }
    .st-low { color: #34d399; }
    .st-med { color: #fbbf24; }
    .st-high { color: #fb923c; }
    .st-crit { color: #f87171; }

    /* Anomaly rate bar */
    .rate-bar-bg {
        background: rgba(255,255,255,0.05); border-radius: 6px;
        height: 6px; flex: 1; margin-left: 1rem; overflow: hidden;
    }
    .rate-bar-fill { height: 100%; border-radius: 6px; transition: width 1s ease; }

    /* ── Glass card (reusable) ── */
    .glass {
        background: rgba(15,23,42,0.5);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.6rem;
        transition: border-color 0.3s;
    }
    .glass:hover { border-color: rgba(0,229,255,0.2); }

    /* ── Alert banners ── */
    .alert-banner {
        border-radius: 12px;
        padding: 1rem 1.4rem;
        margin-bottom: 1rem;
        display: flex; align-items: center; gap: 1rem;
    }
    .ab-danger {
        background: linear-gradient(135deg, rgba(248,113,113,0.1), rgba(239,68,68,0.05));
        border: 1px solid rgba(248,113,113,0.25);
    }
    .ab-safe {
        background: linear-gradient(135deg, rgba(52,211,153,0.1), rgba(16,185,129,0.05));
        border: 1px solid rgba(52,211,153,0.25);
    }
    .ab-icon { font-size: 1.4rem; }
    .ab-danger .ab-icon { color: #f87171; }
    .ab-safe .ab-icon { color: #34d399; }
    .ab-title { font-weight: 700; color: #e2e8f0; font-size: 1rem; }
    .ab-desc { color: #94a3b8; font-size: 0.85rem; margin-top: 2px; }

    /* ── Section header ── */
    .sec-h {
        display: flex; align-items: center; gap: 0.6rem;
        margin: 0.8rem 0 1rem 0;
    }
    .sec-dot {
        width: 8px; height: 8px; border-radius: 50%;
    }
    .sec-h h3 { margin: 0; font-size: 1rem; font-weight: 700; color: #e2e8f0; }

    /* ── Network info ── */
    .ni-card {
        background: rgba(15,23,42,0.5);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 0.7rem 1rem;
        margin-bottom: 0.5rem;
        display: flex; align-items: center; gap: 0.8rem;
        transition: all 0.3s;
    }
    .ni-card:hover { border-color: rgba(0,229,255,0.3); transform: translateX(4px); }
    .ni-icon {
        width: 40px; height: 40px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.2rem; flex-shrink: 0;
    }
    .ni-icon-b { background: rgba(0,229,255,0.1); }
    .ni-icon-g { background: rgba(52,211,153,0.1); }
    .ni-lbl { color: #64748b; font-size: 0.7rem; font-weight: 500; text-transform: uppercase; letter-spacing: 0.8px; }
    .ni-val { color: #e2e8f0; font-size: 0.95rem; font-weight: 600; }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0e1a, #111827) !important;
        border-right: 1px solid rgba(255,255,255,0.06);
    }
    [data-testid="stSidebar"] h2 { color: #00e5ff; font-weight: 700; }

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 4px; }
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 8px 8px 0 0;
        padding: 8px 14px;
        color: #64748b;
        border: none;
        font-weight: 500;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(0,229,255,0.08);
        color: #00e5ff;
        border-bottom: 2px solid #00e5ff;
        font-weight: 600;
    }

    /* ── Footer ── */
    .cyber-footer {
        text-align: center; color: #334155;
        padding: 1.5rem; font-size: 0.8rem;
        border-top: 1px solid rgba(255,255,255,0.04);
        margin-top: 2rem;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Auto-train model
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
        st.warning("No trained model found.")
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
    st.error("No packet data found.")
    st.stop()

df = run_detection(df)
df["attack_type"] = df.apply(classify_attack, axis=1)

# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────

badge_cls = "badge-live" if data_source == "Live Capture" else "badge-sample"
badge_txt = "LIVE" if data_source == "Live Capture" else "SAMPLE DATA"
st.markdown(f"""
<div class="cyber-header">
    <h1>🛡️ NetWatchAI</h1>
    <p class="header-sub">AI-Powered Network Monitoring & Intrusion Detection System</p>
    <span class="header-badge {badge_cls}">{badge_txt}</span>
</div>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────

st.sidebar.markdown("## 🔧 Filters")
protocols = ["All"] + sorted(df["protocol"].dropna().unique().tolist())
selected_protocol = st.sidebar.selectbox("Protocol", protocols)
status_options = ["All"] + sorted(df["status"].dropna().unique().tolist())
selected_status = st.sidebar.selectbox("Status", status_options)
attack_types = ["All"] + sorted(df["attack_type"].dropna().unique().tolist())
selected_attack = st.sidebar.selectbox("Attack Type", attack_types)

filtered_df = df.copy()
if selected_protocol != "All": filtered_df = filtered_df[filtered_df["protocol"] == selected_protocol]
if selected_status != "All": filtered_df = filtered_df[filtered_df["status"] == selected_status]
if selected_attack != "All": filtered_df = filtered_df[filtered_df["attack_type"] == selected_attack]

auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=False)
if auto_refresh:
    time.sleep(5)
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(f"📊 **Total:** {len(df)} packets")
st.sidebar.markdown(f"🔍 **Filtered:** {len(filtered_df)} packets")

# ──────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────

total_packets = len(df)
n_anomalies = int((df["prediction"] == -1).sum())
n_normal = int((df["prediction"] == 1).sum())
anomaly_pct = (n_anomalies / total_packets * 100) if total_packets > 0 else 0
normal_pct = (n_normal / total_packets * 100) if total_packets > 0 else 0

# Threat level
if anomaly_pct == 0:
    t_txt, t_cls, t_icon, p_cls, bar_color = "ALL CLEAR", "st-low", "✅", "pulse-g", "#34d399"
elif anomaly_pct < 5:
    t_txt, t_cls, t_icon, p_cls, bar_color = "LOW RISK", "st-low", "✅", "pulse-g", "#34d399"
elif anomaly_pct < 15:
    t_txt, t_cls, t_icon, p_cls, bar_color = "MEDIUM — Suspicious Activity", "st-med", "⚠️", "pulse-y", "#fbbf24"
elif anomaly_pct < 30:
    t_txt, t_cls, t_icon, p_cls, bar_color = "HIGH — Active Threats", "st-high", "🔶", "pulse-o", "#fb923c"
else:
    t_txt, t_cls, t_icon, p_cls, bar_color = "CRITICAL — Under Attack", "st-crit", "🚨", "pulse-r", "#f87171"

st.markdown(f"""
<div class="threat-bar">
    <span class="tb-icon">{t_icon}</span>
    <div style="flex:1;">
        <div class="tb-label">Threat Level</div>
        <div class="tb-status {t_cls}">
            <span class="pulse {p_cls}"></span> {t_txt}
        </div>
    </div>
    <div class="rate-bar-bg">
        <div class="rate-bar-fill" style="width:{min(anomaly_pct*2, 100):.0f}%; background:{bar_color};"></div>
    </div>
    <span style="color:{bar_color}; font-weight:700; font-size:0.9rem; min-width:45px; text-align:right;">{anomaly_pct:.1f}%</span>
</div>
""", unsafe_allow_html=True)

unique_attacks = df[df["prediction"]==-1]["attack_type"].nunique()
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""<div class="mc mc-cyan">
        <div class="mc-label">Total Packets</div>
        <div class="mc-val">{total_packets:,}</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""<div class="mc mc-green">
        <div class="mc-label">Normal</div>
        <div class="mc-val">{n_normal:,}</div>
        <div class="mc-sub">{normal_pct:.1f}%</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""<div class="mc mc-red">
        <div class="mc-label">Anomalies</div>
        <div class="mc-val">{n_anomalies:,}</div>
        <div class="mc-sub">{anomaly_pct:.1f}%</div>
    </div>""", unsafe_allow_html=True)
with col4:
    st.markdown(f"""<div class="mc mc-amber">
        <div class="mc-label">Attack Types</div>
        <div class="mc-val">{unique_attacks}</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

anomaly_df = df[df["prediction"] == -1]

# Chart config
COLORS = ["#00e5ff", "#7c4dff", "#e040fb", "#ff5252", "#ffd740", "#69f0ae", "#40c4ff", "#ea80fc", "#ff6e40", "#b2ff59"]
SAFE = "#34d399"
DANGER = "#f87171"
NEUTRAL = "#475569"
FONT = "#94a3b8"
BG = "rgba(0,0,0,0)"

def chart_layout(fig, **kwargs):
    grid = "rgba(255,255,255,0.04)"
    defaults = dict(
        paper_bgcolor=BG, plot_bgcolor=BG, font_color=FONT,
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=11)),
        xaxis=dict(gridcolor=grid, zerolinecolor=grid),
        yaxis=dict(gridcolor=grid, zerolinecolor=grid),
    )
    # Merge kwargs into defaults (kwargs wins on conflict)
    for key, val in kwargs.items():
        if key in defaults and isinstance(defaults[key], dict) and isinstance(val, dict):
            defaults[key].update(val)
        else:
            defaults[key] = val
    fig.update_layout(**defaults)
    return fig

# ──────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🚨 Alerts", "🎯 Attack Types", "🏴‍☠️ Top Attackers",
    "📈 Timeline", "📊 Statistics", "📡 Network Info",
])

# ── Tab 1: Alerts ──────────────────────────────

with tab1:
    if len(anomaly_df) == 0:
        st.markdown("""<div class="alert-banner ab-safe">
            <div class="ab-icon">✅</div>
            <div><div class="ab-title">All Clear — No Threats Detected</div>
            <div class="ab-desc">All network traffic appears normal. No anomalies found in current data.</div></div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""<div class="alert-banner ab-danger">
            <div class="ab-icon">🚨</div>
            <div><div class="ab-title">{n_anomalies} Threat(s) Detected — Immediate Review Required</div>
            <div class="ab-desc">{unique_attacks} unique attack pattern(s) found across {anomaly_df['src_ip'].nunique()} source IP(s).</div></div>
        </div>""", unsafe_allow_html=True)
        alert_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type"]
        st.dataframe(anomaly_df[[c for c in alert_cols if c in anomaly_df.columns]], use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown(f"""<div class="sec-h"><div class="sec-dot" style="background:#00e5ff; color:#00e5ff;"></div>
        <h3>Packet Log — {len(filtered_df):,} of {len(df):,}</h3></div>""", unsafe_allow_html=True)

    display_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type", "status"]
    avail = [c for c in display_cols if c in filtered_df.columns]
    if len(filtered_df) == 0:
        st.info("No packets match filters.")
    else:
        st.dataframe(filtered_df[avail].reset_index(drop=True), use_container_width=True, hide_index=True, height=400)

# ── Tab 2: Attack Types ───────────────────────

with tab2:
    if len(anomaly_df) > 0:
        c1, c2 = st.columns([1.2, 1])
        with c1:
            st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#e040fb; color:#e040fb;"></div>
                <h3>Attack Distribution</h3></div>""", unsafe_allow_html=True)
            ac = anomaly_df["attack_type"].value_counts().reset_index()
            ac.columns = ["Attack Type", "Count"]
            fig = px.pie(ac, values="Count", names="Attack Type", color_discrete_sequence=COLORS, hole=0.5)
            fig.update_traces(textinfo="percent+label", textfont_size=11, marker=dict(line=dict(color="#0a0e1a", width=2)))
            chart_layout(fig)
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#ffd740; color:#ffd740;"></div>
                <h3>Attack Details</h3></div>""", unsafe_allow_html=True)
            desc = {"Port Scan":"Probing open ports to find vulnerabilities", "Ping of Death":"Oversized ICMP packets to crash systems",
                    "Data Exfiltration":"Stealing data via suspicious ports", "Suspicious Port":"Traffic to known backdoor ports",
                    "Large Transfer":"Abnormally large data transfer", "DNS Anomaly":"DNS tunneling or spoofing attempt",
                    "Unknown Anomaly":"Unclassified suspicious pattern"}
            acs = anomaly_df["attack_type"].value_counts().reset_index()
            acs.columns = ["Attack Type", "Count"]
            acs["Description"] = acs["Attack Type"].map(desc).fillna("")
            st.dataframe(acs, use_container_width=True, hide_index=True)
    else:
        st.markdown("""<div class="alert-banner ab-safe"><div class="ab-icon">🎯</div>
            <div><div class="ab-title">No Attack Patterns Found</div>
            <div class="ab-desc">Your network looks clean.</div></div></div>""", unsafe_allow_html=True)

# ── Tab 3: Top Attackers ───────────────────────

# Threat assessment for each attack type
ATTACK_RISK = {
    "Port Scan": {
        "severity": "HIGH",
        "color": "#fb923c",
        "issue": "Reconnaissance Attack",
        "description": "Attacker is scanning for open ports to find vulnerable services (SSH, RDP, HTTP). This is usually the first step before a targeted attack.",
        "action": "Block this IP on your firewall. Check if any scanned ports are unnecessarily open.",
    },
    "Ping of Death": {
        "severity": "CRITICAL",
        "color": "#f87171",
        "issue": "Denial of Service (DoS)",
        "description": "Sending oversized ICMP packets to crash or freeze your system. This can take down servers and network devices.",
        "action": "Block ICMP from this IP immediately. Enable ICMP rate limiting on your firewall.",
    },
    "Data Exfiltration": {
        "severity": "CRITICAL",
        "color": "#f87171",
        "issue": "Data Theft",
        "description": "Large amounts of data are being sent to suspicious external ports. Sensitive files, credentials, or databases may be stolen.",
        "action": "Isolate the source machine. Check for malware. Audit what data was accessed.",
    },
    "Suspicious Port": {
        "severity": "HIGH",
        "color": "#fb923c",
        "issue": "Backdoor / Malware Communication",
        "description": "Traffic to known malicious ports (4444, 31337, etc.) often used by trojans, reverse shells, and C2 servers.",
        "action": "Scan the source machine for malware. Block these ports on your firewall.",
    },
    "Large Transfer": {
        "severity": "MEDIUM",
        "color": "#fbbf24",
        "issue": "Unusual Data Movement",
        "description": "Abnormally large data transfer detected. Could be data theft, unauthorized backup, or compromised machine uploading data.",
        "action": "Verify if this transfer was authorized. Monitor the destination IP.",
    },
    "DNS Anomaly": {
        "severity": "HIGH",
        "color": "#fb923c",
        "issue": "DNS Tunneling / Spoofing",
        "description": "Suspicious DNS traffic that may be tunneling data through DNS queries or redirecting users to malicious websites.",
        "action": "Check DNS server logs. Consider using encrypted DNS (DoH/DoT). Block suspicious DNS destinations.",
    },
    "Unknown Anomaly": {
        "severity": "MEDIUM",
        "color": "#fbbf24",
        "issue": "Unclassified Threat",
        "description": "AI detected an unusual traffic pattern that doesn't match known attacks. May be a zero-day or novel technique.",
        "action": "Investigate the traffic manually. Capture packets for deeper analysis.",
    },
}

def get_ip_threat_report(ip, adf):
    """Generate a threat report for a specific IP."""
    ip_data = adf[adf["src_ip"] == ip]
    attacks = ip_data["attack_type"].value_counts().to_dict()
    total = len(ip_data)
    ports_targeted = sorted(ip_data["dst_port"].unique().tolist())[:10]
    protocols = ip_data["protocol"].unique().tolist()
    max_size = int(ip_data["packet_size"].max()) if len(ip_data) > 0 else 0

    # Determine overall severity (worst of all attack types)
    severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    worst_severity = "MEDIUM"
    for atk in attacks:
        risk = ATTACK_RISK.get(atk, {})
        if severity_order.get(risk.get("severity", "MEDIUM"), 1) > severity_order.get(worst_severity, 1):
            worst_severity = risk.get("severity", "MEDIUM")

    return {
        "attacks": attacks,
        "total": total,
        "ports": ports_targeted,
        "protocols": protocols,
        "max_size": max_size,
        "severity": worst_severity,
    }

with tab3:
    if len(anomaly_df) > 0:
        # Top tables
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#ff5252; color:#ff5252;"></div>
                <h3>Suspicious Sources</h3></div>""", unsafe_allow_html=True)
            top_src = anomaly_df["src_ip"].value_counts().head(10).reset_index()
            top_src.columns = ["Source IP", "Attacks"]
            top_src["Types"] = top_src["Source IP"].apply(lambda ip: ", ".join(anomaly_df[anomaly_df["src_ip"]==ip]["attack_type"].unique()))
            st.dataframe(top_src, use_container_width=True, hide_index=True)
        with c2:
            st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#ffd740; color:#ffd740;"></div>
                <h3>Targeted Destinations</h3></div>""", unsafe_allow_html=True)
            top_dst = anomaly_df["dst_ip"].value_counts().head(10).reset_index()
            top_dst.columns = ["Destination IP", "Attacks"]
            top_dst["Ports"] = top_dst["Destination IP"].apply(lambda ip: ", ".join(str(p) for p in anomaly_df[anomaly_df["dst_ip"]==ip]["dst_port"].unique()[:5]))
            st.dataframe(top_dst, use_container_width=True, hide_index=True)

        # Bar chart
        fig = px.bar(top_src, x="Attacks", y="Source IP", orientation="h", color="Attacks",
                     color_continuous_scale=[[0,"#1e1b4b"],[0.5,"#7c4dff"],[1,"#e040fb"]])
        chart_layout(fig, yaxis=dict(autorange="reversed", gridcolor="rgba(255,255,255,0.04)"), showlegend=False, coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)

        # Threat Report for each attacker IP
        st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#e040fb; color:#e040fb;"></div>
            <h3>Threat Report — Attacker Details</h3></div>""", unsafe_allow_html=True)

        for _, row in top_src.iterrows():
            ip = row["Source IP"]
            report = get_ip_threat_report(ip, anomaly_df)
            sev = report["severity"]
            sev_colors = {"CRITICAL": "#f87171", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#34d399"}
            sev_color = sev_colors.get(sev, "#fbbf24")

            # Build attack details HTML
            attack_details = ""
            for atk, count in report["attacks"].items():
                risk = ATTACK_RISK.get(atk, {})
                atk_color = risk.get("color", "#fbbf24")
                atk_issue = risk.get("issue", "Unknown")
                atk_desc = risk.get("description", "")
                atk_action = risk.get("action", "")
                attack_details += f"""
                <div style="margin: 0.6rem 0 0.6rem 0; padding: 0.7rem 1rem; background:rgba(255,255,255,0.02);
                            border-radius:10px; border-left: 3px solid {atk_color};">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.3rem;">
                        <span style="color:{atk_color}; font-weight:700; font-size:0.9rem;">{atk} ({count}x)</span>
                        <span style="color:{atk_color}; font-size:0.7rem; font-weight:600;
                                     background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:4px;">{atk_issue}</span>
                    </div>
                    <div style="color:#94a3b8; font-size:0.8rem; line-height:1.4;">{atk_desc}</div>
                    <div style="color:#67e8f9; font-size:0.78rem; margin-top:0.3rem;">
                        <strong>Recommended:</strong> {atk_action}
                    </div>
                </div>"""

            ports_str = ", ".join(str(p) for p in report["ports"]) if report["ports"] else "N/A"
            proto_str = ", ".join(report["protocols"])

            st.markdown(f"""
            <div style="background:rgba(15,23,42,0.6); backdrop-filter:blur(12px);
                        border:1px solid rgba(255,255,255,0.06); border-radius:14px;
                        padding:1.2rem 1.4rem; margin-bottom:1rem;
                        border-top:3px solid {sev_color};">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.8rem;">
                    <div>
                        <span style="color:#e2e8f0; font-size:1.1rem; font-weight:800;">🔴 {ip}</span>
                        <span style="color:#64748b; font-size:0.8rem; margin-left:0.6rem;">{report['total']} anomalous packet(s)</span>
                    </div>
                    <span style="color:{sev_color}; font-size:0.75rem; font-weight:700;
                                 background:rgba(255,255,255,0.05); padding:3px 12px;
                                 border-radius:4px; border:1px solid {sev_color}40;">{sev} RISK</span>
                </div>
                <div style="display:flex; gap:2rem; margin-bottom:0.5rem; color:#64748b; font-size:0.78rem;">
                    <span>Protocols: <strong style="color:#e2e8f0;">{proto_str}</strong></span>
                    <span>Targeted Ports: <strong style="color:#e2e8f0;">{ports_str}</strong></span>
                    <span>Max Packet: <strong style="color:#e2e8f0;">{report['max_size']:,} bytes</strong></span>
                </div>
                {attack_details}
            </div>
            """, unsafe_allow_html=True)

    else:
        st.markdown("""<div class="alert-banner ab-safe"><div class="ab-icon">🏴‍☠️</div>
            <div><div class="ab-title">No Attackers Found</div>
            <div class="ab-desc">No suspicious source IPs detected.</div></div></div>""", unsafe_allow_html=True)

# ── Tab 4: Timeline ───────────────────────────

with tab4:
    if "timestamp" in df.columns:
        tdf = df.copy()
        tdf["timestamp"] = pd.to_datetime(tdf["timestamp"], errors="coerce")
        tdf = tdf.dropna(subset=["timestamp"])
        if len(tdf) > 0:
            st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#00e5ff; color:#00e5ff;"></div>
                <h3>Traffic Over Time</h3></div>""", unsafe_allow_html=True)
            tdf["tb"] = tdf["timestamp"].dt.floor("1min")
            tg = tdf.groupby(["tb", "status"]).size().reset_index(name="count")
            fig = px.area(tg, x="tb", y="count", color="status",
                         color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL},
                         labels={"tb":"Time","count":"Packets","status":"Status"})
            chart_layout(fig, hovermode="x unified")
            st.plotly_chart(fig, use_container_width=True)

            at = tdf[tdf["status"]=="ANOMALY"]
            if len(at) > 0:
                st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#ff5252; color:#ff5252;"></div>
                    <h3>Attacks Over Time</h3></div>""", unsafe_allow_html=True)
                abt = at.groupby(["tb","attack_type"]).size().reset_index(name="count")
                fig = px.bar(abt, x="tb", y="count", color="attack_type", color_discrete_sequence=COLORS,
                             labels={"tb":"Time","count":"Attacks","attack_type":"Type"})
                chart_layout(fig)
                st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Could not parse timestamps.")
    else:
        st.warning("No timestamp column found.")

# ── Tab 5: Statistics ──────────────────────────

with tab5:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#40c4ff; color:#40c4ff;"></div>
            <h3>Protocol Distribution</h3></div>""", unsafe_allow_html=True)
        pc = df["protocol"].value_counts().reset_index()
        pc.columns = ["Protocol", "Count"]
        fig = px.pie(pc, values="Count", names="Protocol", color_discrete_sequence=COLORS, hole=0.5)
        fig.update_traces(textinfo="percent+label", textfont_size=11, marker=dict(line=dict(color="#0a0e1a", width=2)))
        chart_layout(fig)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#69f0ae; color:#69f0ae;"></div>
            <h3>Normal vs Anomaly</h3></div>""", unsafe_allow_html=True)
        sc = df["status"].value_counts().reset_index()
        sc.columns = ["Status", "Count"]
        fig = px.bar(sc, x="Status", y="Count", color="Status",
                     color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL})
        fig.update_traces(marker_line_width=0, opacity=0.9)
        chart_layout(fig, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#ea80fc; color:#ea80fc;"></div>
        <h3>Packet Size Distribution</h3></div>""", unsafe_allow_html=True)
    fig = px.histogram(df, x="packet_size", color="status", nbins=30,
                       color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL},
                       labels={"packet_size":"Packet Size (bytes)","status":"Status"})
    chart_layout(fig)
    st.plotly_chart(fig, use_container_width=True)

# ── Tab 6: Network Info ────────────────────────

WIFI_ICO = {"WiFi Network (SSID)":"📶","Signal Strength":"📡","Link Speed":"⚡","Channel":"📻","Hostname":"💻"}
IP_ICO = {"Local IP":"🏠","Public IP":"🌐","Gateway (Router)":"🔀","Subnet Mask":"🎭","MAC Address":"🔖","DNS Servers":"📇"}

with tab6:
    net_info = get_network_info()
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#00e5ff; color:#00e5ff;"></div>
            <h3>WiFi & Connection</h3></div>""", unsafe_allow_html=True)
        for key in ["WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel", "Hostname"]:
            val = html_module.escape(str(net_info.get(key, "N/A")))
            ico = WIFI_ICO.get(key, "📌")
            st.markdown(f"""<div class="ni-card"><div class="ni-icon ni-icon-b">{ico}</div>
                <div><div class="ni-lbl">{key}</div><div class="ni-val">{val}</div></div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""<div class="sec-h"><div class="sec-dot" style="background:#34d399; color:#34d399;"></div>
            <h3>IP & Routing</h3></div>""", unsafe_allow_html=True)
        for key in ["Local IP", "Public IP", "Gateway (Router)", "Subnet Mask", "MAC Address", "DNS Servers"]:
            val = html_module.escape(str(net_info.get(key, "N/A")))
            ico = IP_ICO.get(key, "📌")
            st.markdown(f"""<div class="ni-card"><div class="ni-icon ni-icon-g">{ico}</div>
                <div><div class="ni-lbl">{key}</div><div class="ni-val">{val}</div></div></div>""", unsafe_allow_html=True)

    signal_str = net_info.get("Signal Strength", "")
    if "dBm" in signal_str:
        rssi_val = int(signal_str.split(" ")[0])
        gauge_val = max(0, min(100, (rssi_val + 100) * 100 // 70))
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=gauge_val,
            title={"text":"WiFi Signal Quality", "font":{"color":"#94a3b8","size":14}},
            number={"suffix":"%", "font":{"color":"#00e5ff","size":40}},
            gauge={"axis":{"range":[0,100],"tickcolor":"#334155"},
                   "bar":{"color":"#00e5ff","thickness":0.7},
                   "bgcolor":"rgba(255,255,255,0.03)", "borderwidth":0,
                   "steps":[{"range":[0,30],"color":"rgba(248,113,113,0.15)"},
                            {"range":[30,60],"color":"rgba(251,191,36,0.1)"},
                            {"range":[60,100],"color":"rgba(52,211,153,0.1)"}]}))
        fig.update_layout(height=250, margin=dict(t=40,b=10,l=30,r=30), paper_bgcolor=BG, font_color="#94a3b8")
        st.plotly_chart(fig, use_container_width=True)

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────

st.markdown('<div class="cyber-footer">🛡️ NetWatchAI — AI-Powered Network Monitoring & Intrusion Detection</div>', unsafe_allow_html=True)
