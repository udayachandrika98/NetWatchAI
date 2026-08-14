"""
NetWatchAI - Streamlit Dashboard
Displays captured packets, anomaly alerts, and network statistics.

Usage:
    streamlit run dashboard.py
"""

import os
import io
import json
import subprocess
import socket
import time
import html as html_module
from datetime import datetime
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from fpdf import FPDF
from src.detector import AnomalyDetector
from src.utils import PACKETS_CSV, SAMPLE_CSV, MODEL_PATH
from src import storage, auth, alerting, config as app_config, threat_intel, behavior, ai_explainer, oauth_github

storage.init_db()


# Threat-intel: refresh once per day on the first dashboard render.
# Cached at the module level so subsequent renders are instant.
@st.cache_resource(ttl=86400, show_spinner=False)
def _load_threat_intel():
    threat_intel.refresh_if_stale(force=False)
    return threat_intel.load_iocs()


# ──────────────────────────────────────────────
# Network Info Helper
# ──────────────────────────────────────────────

import platform

def _run_cmd(cmd, timeout=5):
    """Run a shell command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except Exception:
        return ""

def _get_network_info_darwin(info):
    """macOS-specific network info."""
    out = _run_cmd(["networksetup", "-getairportnetwork", "en0"])
    info["WiFi Network (SSID)"] = out.split(": ", 1)[1] if ": " in out else "Not connected"

    out = _run_cmd(["route", "-n", "get", "default"])
    for line in out.splitlines():
        if "gateway" in line.lower():
            info["Gateway (Router)"] = line.split(":", 1)[1].strip()
            break

    out = _run_cmd(["scutil", "--dns"])
    dns_servers = []
    for line in out.splitlines():
        if "nameserver" in line.lower():
            server = line.split(":", 1)[1].strip()
            if server not in dns_servers:
                dns_servers.append(server)
            if len(dns_servers) >= 3:
                break
    if dns_servers:
        info["DNS Servers"] = ", ".join(dns_servers)

    out = _run_cmd(["ifconfig", "en0"])
    for line in out.splitlines():
        if "ether" in line:
            parts = line.strip().split()
            if len(parts) > 1:
                info["MAC Address"] = parts[1]
        if "inet " in line and "netmask" in line:
            parts = line.strip().split()
            mask_idx = parts.index("netmask") if "netmask" in parts else -1
            if mask_idx > 0:
                info["Subnet Mask"] = parts[mask_idx + 1]

    out = _run_cmd(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("agrCtlRSSI"):
            rssi = int(stripped.split(":")[1].strip())
            strength = "Excellent" if rssi > -50 else "Good" if rssi > -60 else "Fair" if rssi > -70 else "Weak"
            info["Signal Strength"] = f"{rssi} dBm ({strength})"
        if stripped.startswith("lastTxRate"):
            info["Link Speed"] = stripped.split(":")[1].strip() + " Mbps"
        if stripped.startswith("channel"):
            info["Channel"] = stripped.split(":")[1].strip()

def _get_network_info_linux(info):
    """Linux-specific network info."""
    out = _run_cmd(["iwgetid", "-r"])
    info["WiFi Network (SSID)"] = out if out else "Not connected"

    out = _run_cmd(["ip", "route", "show", "default"])
    if "via" in out:
        info["Gateway (Router)"] = out.split("via")[1].strip().split()[0]

    out = _run_cmd(["cat", "/etc/resolv.conf"])
    dns_servers = []
    for line in out.splitlines():
        if line.strip().startswith("nameserver"):
            parts = line.strip().split()
            if len(parts) < 2:
                continue
            server = parts[1]
            if server not in dns_servers:
                dns_servers.append(server)
            if len(dns_servers) >= 3:
                break
    if dns_servers:
        info["DNS Servers"] = ", ".join(dns_servers)

    out = _run_cmd(["ip", "link", "show"])
    import re as _re
    mac_match = _re.search(r"link/ether\s+([\da-f:]+)", out)
    if mac_match:
        info["MAC Address"] = mac_match.group(1)

    out = _run_cmd(["ip", "addr", "show"])
    for line in out.splitlines():
        if "inet " in line and "127.0.0.1" not in line:
            parts = line.strip().split()
            if len(parts) > 1 and "/" in parts[1]:
                cidr_parts = parts[1].split("/")
                if len(cidr_parts) > 1 and cidr_parts[1].isdigit():
                    cidr = int(cidr_parts[1])
                    mask = ".".join(str((0xFFFFFFFF << (32 - cidr) >> i) & 0xFF) for i in [24, 16, 8, 0])
                    info["Subnet Mask"] = mask
            break

    out = _run_cmd(["iwconfig"])
    import re as _re
    rssi_match = _re.search(r"Signal level[=:](-?\d+)", out)
    if rssi_match:
        rssi = int(rssi_match.group(1))
        strength = "Excellent" if rssi > -50 else "Good" if rssi > -60 else "Fair" if rssi > -70 else "Weak"
        info["Signal Strength"] = f"{rssi} dBm ({strength})"
    rate_match = _re.search(r"Bit Rate[=:](\S+)", out)
    if rate_match:
        info["Link Speed"] = rate_match.group(1) + " Mbps"

def _get_network_info_windows(info):
    """Windows-specific network info."""
    out = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSID") and "BSSID" not in stripped:
            info["WiFi Network (SSID)"] = stripped.split(":", 1)[1].strip()
        if "Signal" in stripped:
            info["Signal Strength"] = stripped.split(":", 1)[1].strip()
        if "Radio type" in stripped:
            info["Channel"] = stripped.split(":", 1)[1].strip()
        if "Receive rate" in stripped:
            info["Link Speed"] = stripped.split(":", 1)[1].strip()

    out = _run_cmd(["ipconfig", "/all"])
    for line in out.splitlines():
        stripped = line.strip()
        if "Default Gateway" in stripped and ":" in stripped:
            gw = stripped.split(":", 1)[1].strip()
            if gw:
                info["Gateway (Router)"] = gw
        if "DNS Servers" in stripped:
            dns = stripped.split(":", 1)[1].strip()
            if dns:
                info["DNS Servers"] = dns
        if "Physical Address" in stripped:
            info["MAC Address"] = stripped.split(":", 1)[1].strip()
        if "Subnet Mask" in stripped:
            info["Subnet Mask"] = stripped.split(":", 1)[1].strip()

def get_network_info():
    """Collect WiFi and network details from the system (cross-platform)."""
    info = {}
    # Local IP — works on all platforms
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            info["Local IP"] = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        info["Local IP"] = "N/A"

    # Platform-specific details. Each parser walks shell output that can vary
    # by OS version, locale, VPN state, etc. — swallow parser errors so a
    # malformed line never breaks the Network Info tab.
    system = platform.system()
    try:
        if system == "Darwin":
            _get_network_info_darwin(info)
        elif system == "Linux":
            _get_network_info_linux(info)
        elif system == "Windows":
            _get_network_info_windows(info)
    except Exception:
        pass

    # Defaults for missing keys
    for key in ["WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel",
                 "Gateway (Router)", "DNS Servers", "MAC Address", "Subnet Mask"]:
        info.setdefault(key, "N/A")

    info["Hostname"] = socket.gethostname()

    # Public IP — works on all platforms
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

# Per-attack-type explanations shown in the Alerts tab "Investigate" drill-down.
# Each entry: (why this gets flagged, what an analyst should do about it).
ATTACK_PLAYBOOK = {
    "Port Scan": (
        "The same source IP probed 15+ distinct ports within 60 seconds — "
        "classic reconnaissance pattern before an exploit attempt.",
        "Block the source IP at the firewall. Enable SYN cookies on exposed servers. "
        "Rate-limit incoming SYN packets per source.",
    ),
    "Ping of Death": (
        "An ICMP packet larger than 1000 bytes was observed. Modern stacks survive it, "
        "but oversized ICMP is almost always malicious or misconfigured.",
        "Block oversized ICMP packets at the perimeter. Drop fragmented ICMP. "
        "Restrict ICMP echo requests to trusted ranges.",
    ),
    "Data Exfiltration": (
        "A large packet (>1000 bytes) was sent to or from a known backdoor port "
        "(4444, 31337, etc). Strong indicator of data being smuggled out.",
        "Block outbound traffic to those ports immediately. Inspect the source host "
        "for compromise. Review DLP logs for the affected timeframe.",
    ),
    "Suspicious Port": (
        "Traffic was seen on a port commonly used by malware C2 channels "
        "(Metasploit default 4444, IRC bots, RATs).",
        "Block the port at the firewall. Audit the host for unexpected listeners "
        "with `lsof -i` / `netstat -anp`.",
    ),
    "DNS Anomaly": (
        "A DNS (UDP/53) packet exceeded 200 bytes. DNS queries are normally tiny — "
        "oversized ones suggest DNS tunneling (data smuggled inside DNS records).",
        "Inspect DNS query payloads. Force DNS through a filtering resolver "
        "(Cloudflare 1.1.1.2, Quad9). Alert on TXT-record floods.",
    ),
    "Large Transfer": (
        "A single packet exceeded 5000 bytes — well above normal MTU. "
        "Often signals bulk data movement or a misconfigured client.",
        "Investigate whether the transfer is authorized. Set per-host bandwidth "
        "thresholds. Review file-share access logs for the source.",
    ),
    "Unknown Anomaly": (
        "The ML model flagged this packet as statistically unusual, but it didn't "
        "match a known signature. Could be a novel attack or benign edge case.",
        "Manually review the source IP, destination, and timing. If similar packets "
        "repeat, consider adding a custom rule. If clearly benign, mark as false positive.",
    ),
}

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
    if protocol == "ICMP" and packet_size > 1000: return "Ping of Death"
    # NOTE: Port Scan is handled by the stateful detector in src/behavior.py,
    # not per-packet. A single small TCP SYN is not a scan — 15+ distinct ports
    # within 60 seconds is.
    if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
        return "Data Exfiltration" if packet_size > 1000 else "Suspicious Port"
    if packet_size > 5000: return "Large Transfer"
    if protocol == "UDP" and dst_port == 53 and packet_size > 200: return "DNS Anomaly"
    return "Unknown Anomaly"


# ──────────────────────────────────────────────
# GeoIP Lookup
# ──────────────────────────────────────────────

def _is_private_ip(ip):
    """Check if an IP is private/local."""
    return ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.", "0."))

@st.cache_data(ttl=3600)
def get_geo_data_for_ips(ips):
    """Batch geolocate IPs using ip-api.com batch endpoint (up to 100 per request)."""
    public_ips = [ip for ip in ips if not _is_private_ip(ip)]
    if not public_ips:
        return []

    public_ips = public_ips[:100]  # ip-api.com batch limit
    results = []

    # Use batch endpoint — single request for all IPs (no rate limit issues)
    try:
        resp = requests.post(
            "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,isp,query",
            json=public_ips,
            timeout=10,
        )
        batch_results = resp.json()
        for data in batch_results:
            if data.get("status") == "success":
                data["ip"] = data.pop("query", "")
                results.append(data)
    except Exception:
        # Fallback to individual requests if batch fails
        for ip in public_ips[:20]:
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp",
                    timeout=3,
                )
                data = resp.json()
                if data.get("status") == "success":
                    data["ip"] = ip
                    results.append(data)
                time.sleep(0.15)  # Rate limit: max 45 req/min
            except Exception:
                continue

    return results



# ──────────────────────────────────────────────
# PDF Report Generator
# ──────────────────────────────────────────────

def generate_pdf_report(df, anomaly_df):
    """Generate a professional PDF security report."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Title Page — deep indigo cover
    pdf.add_page()
    pdf.set_fill_color(9, 9, 11)
    pdf.rect(0, 0, 210, 297, 'F')
    # Accent band
    pdf.set_fill_color(99, 102, 241)
    pdf.rect(0, 0, 210, 4, 'F')
    pdf.set_text_color(250, 250, 250)
    pdf.set_font("Helvetica", "B", 40)
    pdf.ln(75)
    pdf.cell(0, 20, "NetWatchAI", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 15)
    pdf.set_text_color(165, 180, 252)
    pdf.cell(0, 10, "Security Threat Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(161, 161, 170)
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, "Network Monitoring and Intrusion Detection", align="C", new_x="LMARGIN", new_y="NEXT")

    # Executive Summary Page
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.rect(0, 0, 210, 297, 'F')
    pdf.set_text_color(29, 29, 31)
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 15, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(210, 210, 215)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    total = len(df)
    n_anom = len(anomaly_df)
    pct = (n_anom / total * 100) if total > 0 else 0

    if pct == 0: level, level_color = "ALL CLEAR", (30, 126, 52)
    elif pct < 5: level, level_color = "LOW RISK", (30, 126, 52)
    elif pct < 15: level, level_color = "MEDIUM", (178, 80, 0)
    elif pct < 30: level, level_color = "HIGH", (178, 80, 0)
    else: level, level_color = "CRITICAL", (194, 59, 34)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*level_color)
    pdf.cell(0, 10, f"Threat Level: {level}", new_x="LMARGIN", new_y="NEXT")

    pdf.set_text_color(29, 29, 31)
    pdf.set_font("Helvetica", "", 11)
    pdf.ln(3)
    def _safe_nunique(col):
        if n_anom == 0 or col not in anomaly_df.columns:
            return 0
        return anomaly_df[col].nunique()

    summary_items = [
        f"Total Packets Analyzed: {total:,}",
        f"Normal Traffic: {total - n_anom:,} ({100-pct:.1f}%)",
        f"Anomalies Detected: {n_anom:,} ({pct:.1f}%)",
        f"Unique Attack Types: {_safe_nunique('attack_type')}",
        f"Unique Source IPs (Attackers): {_safe_nunique('src_ip')}",
        f"Unique Destination IPs (Targets): {_safe_nunique('dst_ip')}",
    ]
    for item in summary_items:
        pdf.cell(0, 7, f"  {item}", new_x="LMARGIN", new_y="NEXT")

    # Attack Breakdown
    if n_anom > 0 and "attack_type" in anomaly_df.columns:
        pdf.ln(8)
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Attack Type Breakdown", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(210, 210, 215)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        attack_counts = anomaly_df["attack_type"].value_counts()
        desc_map = {
            "Port Scan": "Probing open ports to find vulnerabilities",
            "Ping of Death": "Oversized ICMP packets to crash systems",
            "Data Exfiltration": "Stealing data via suspicious ports",
            "Suspicious Port": "Traffic to known backdoor ports",
            "Large Transfer": "Abnormally large data transfer",
            "DNS Anomaly": "DNS tunneling or spoofing attempt",
            "Unknown Anomaly": "Unclassified suspicious pattern",
        }

        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(245, 245, 247)
        pdf.cell(70, 8, "Attack Type", border=1, fill=True)
        pdf.cell(30, 8, "Count", border=1, fill=True, align="C")
        pdf.cell(90, 8, "Description", border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 10)
        for attack, count in attack_counts.items():
            pdf.cell(70, 7, str(attack), border=1)
            pdf.cell(30, 7, str(count), border=1, align="C")
            pdf.cell(90, 7, desc_map.get(str(attack), ""), border=1)
            pdf.ln()

        # Top Attackers
        if "src_ip" in anomaly_df.columns:
            pdf.ln(8)
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 12, "Top Suspicious IPs", new_x="LMARGIN", new_y="NEXT")
            pdf.set_draw_color(210, 210, 215)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(5)

            top_src = anomaly_df["src_ip"].value_counts().head(10)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_fill_color(245, 245, 247)
            pdf.cell(50, 8, "Source IP", border=1, fill=True)
            pdf.cell(30, 8, "Attacks", border=1, fill=True, align="C")
            pdf.cell(110, 8, "Attack Types", border=1, fill=True)
            pdf.ln()

            pdf.set_font("Helvetica", "", 10)
            for ip, cnt in top_src.items():
                if "attack_type" in anomaly_df.columns:
                    types = ", ".join(anomaly_df[anomaly_df["src_ip"] == ip]["attack_type"].unique())
                else:
                    types = ""
                pdf.cell(50, 7, str(ip), border=1)
                pdf.cell(30, 7, str(cnt), border=1, align="C")
                pdf.cell(110, 7, types[:50], border=1)
                pdf.ln()

    # Recommendations
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.cell(0, 15, "Recommendations", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(210, 210, 215)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 11)
    recommendations = []
    if n_anom > 0:
        attack_types = set(anomaly_df["attack_type"].unique()) if "attack_type" in anomaly_df.columns else set()
        if "Port Scan" in attack_types:
            recommendations.append("Port Scan Detected: Configure firewall rules to limit SYN packet rates. Enable SYN cookies on servers.")
        if "Ping of Death" in attack_types:
            recommendations.append("Ping of Death Detected: Block oversized ICMP packets at the network perimeter. Limit ICMP traffic.")
        if "Data Exfiltration" in attack_types:
            recommendations.append("Data Exfiltration Risk: Block outbound traffic to suspicious ports (4444, 31337). Monitor for large outbound transfers.")
        if "DNS Anomaly" in attack_types:
            recommendations.append("DNS Anomaly Detected: Inspect DNS queries for tunneling patterns. Consider DNS filtering solutions.")
        if "Suspicious Port" in attack_types:
            recommendations.append("Suspicious Port Activity: Block known backdoor ports at the firewall. Audit running services.")
        if "Large Transfer" in attack_types:
            recommendations.append("Large Transfer Detected: Investigate unauthorized bulk data movement. Set data transfer thresholds.")
        recommendations.append("General: Review and update firewall rules. Enable network segmentation. Conduct regular security audits.")
    else:
        recommendations.append("No threats detected. Continue monitoring and keep security policies up to date.")
        recommendations.append("Consider running periodic vulnerability scans to proactively identify weaknesses.")

    for i, rec in enumerate(recommendations, 1):
        pdf.multi_cell(0, 7, f"{i}. {rec}")
        pdf.ln(2)

    # Footer on each page
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.set_y(-20)
    pdf.cell(0, 10, "Generated by NetWatchAI. Network Intrusion Detection.", align="C")

    return bytes(pdf.output())


# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────

st.set_page_config(page_title="NetWatchAI", layout="wide", initial_sidebar_state="expanded")

# ──────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Auth is entirely optional. Login screen only appears when the admin has
# explicitly configured a password — either via NETWATCHAI_PASSWORD env var
# (recommended for any public/server deploy) or by setting one in the UI.
# On a fresh local install with no password set, the dashboard opens directly.
# Setting NETWATCHAI_DEMO=1 bypasses auth entirely (used for the public demo).
_demo_mode = os.environ.get("NETWATCHAI_DEMO") == "1"
_auth_enabled = auth.is_setup() and not _demo_mode
_needs_setup = False  # "Create password" screen is opt-in via Settings, not forced on first run.

# Handle GitHub OAuth callback if the URL carries ?code=...&state=...
# Runs before the login form renders so a successful redirect lands directly in the app.
if _auth_enabled and not st.session_state.authenticated and oauth_github.is_configured():
    _qp_code = st.query_params.get("code")
    _qp_state = st.query_params.get("state")
    if _qp_code and _qp_state:
        try:
            user = oauth_github.exchange_code(
                code=_qp_code,
                state=_qp_state,
                expected_state=st.session_state.get("oauth_state", ""),
            )
            st.session_state.authenticated = True
            st.session_state.login_time = datetime.now()
            st.session_state.github_user = user
            storage.log_audit(f"github:{user['login']}", "login", "oauth_success")
            st.query_params.clear()
            st.rerun()
        except Exception as _oauth_err:
            storage.log_audit("user", "login", f"oauth_failed: {_oauth_err}")
            st.error(f"GitHub sign-in failed: {_oauth_err}")
            st.query_params.clear()

if _auth_enabled and not st.session_state.authenticated:
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important; }
        [data-testid="stIconMaterial"],
        [data-testid="stExpanderToggleIcon"],
        .material-icons, .material-icons-outlined,
        .material-symbols-rounded, .material-symbols-outlined,
        [class*="material-symbols"] {
            font-family:
                'Material Symbols Rounded', 'Material Symbols Outlined',
                'Material Icons', 'Material Icons Outlined' !important;
            font-feature-settings: 'liga' !important;
        }
        .stApp {
            background:
                radial-gradient(1200px 600px at 20% -10%, rgba(99,102,241,0.18), transparent 60%),
                radial-gradient(900px 500px at 90% 10%, rgba(139,92,246,0.12), transparent 60%),
                #09090b;
        }
        #MainMenu, footer, header { visibility: hidden; }
        .stDeployButton { display: none; }
        .stApp, .stApp p, .stApp span, .stApp div, .stApp label { color: #e4e4e7; }

        /* Hide Streamlit's default top toolbar/padding so the card is truly centered */
        [data-testid="stToolbar"] { display: none !important; }
        .block-container { padding-top: 2.5rem !important; max-width: 100% !important; }

        .login-card {
            max-width: 380px;
            margin: 4.5rem auto 0;
            padding: 2.25rem 2rem 1.75rem;
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
            box-shadow: 0 20px 60px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.02) inset;
            text-align: center;
        }
        .login-mark {
            width: 52px; height: 52px; margin: 0 auto 1.1rem;
            border-radius: 14px;
            background: linear-gradient(135deg, #6366f1, #8b5cf6);
            display: flex; align-items: center; justify-content: center;
            box-shadow: 0 8px 28px rgba(99,102,241,0.35), inset 0 1px 0 rgba(255,255,255,0.2);
        }
        .login-mark svg { width: 26px; height: 26px; color: #fff; }
        .login-brand {
            font-size: 1.75rem; font-weight: 600;
            color: #fafafa; margin: 0;
            letter-spacing: -0.03em; line-height: 1.15;
        }
        .login-sub {
            color: #a1a1aa; font-size: 0.9rem;
            margin: 0.4rem 0 1.75rem; font-weight: 400;
        }
        .login-foot {
            color: #71717a; font-size: 0.75rem;
            margin: 1rem 0 0; line-height: 1.5;
        }
        [data-testid="stTextInput"] input {
            background: rgba(255,255,255,0.04) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            color: #fafafa !important;
            border-radius: 10px !important;
            padding: 0.65rem 0.85rem !important;
            font-size: 0.95rem !important;
        }
        [data-testid="stTextInput"] input:focus {
            border-color: #6366f1 !important;
            box-shadow: 0 0 0 3px rgba(99,102,241,0.18) !important;
        }
        .stButton > button,
        [data-testid="stFormSubmitButton"] > button {
            background: linear-gradient(180deg, #6366f1, #4f46e5) !important;
            color: #fff !important;
            border: 1px solid rgba(255,255,255,0.08) !important;
            border-radius: 10px !important;
            font-weight: 500 !important;
            padding: 0.6rem 1.1rem !important;
            box-shadow: 0 1px 0 rgba(255,255,255,0.1) inset, 0 4px 14px rgba(99,102,241,0.3);
            width: 100%;
        }
        .stButton > button:hover,
        [data-testid="stFormSubmitButton"] > button:hover {
            background: linear-gradient(180deg, #7c7df7, #5b55ea) !important;
        }
    </style>
    """, unsafe_allow_html=True)

    _left, _center, _right = st.columns([1, 1.2, 1])
    with _center:
        _sub = "Create your admin password" if _needs_setup else "Network Intrusion Detection"
        st.markdown(f"""
        <div class="login-card">
            <div class="login-mark">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <h1 class="login-brand">NetWatchAI</h1>
            <p class="login-sub">{_sub}</p>
        </div>
        """, unsafe_allow_html=True)

        if _needs_setup:
            # First-run: let the user pick their own password.
            st.info(
                "Welcome. Choose a password to protect your NetWatchAI dashboard. "
                "It stays on this machine, hashed with PBKDF2. Minimum 6 characters."
            )
            with st.form("setup_form", clear_on_submit=False, border=False):
                pw1 = st.text_input(
                    "New password", type="password",
                    placeholder="Choose a password (at least 6 characters)",
                    label_visibility="collapsed",
                )
                pw2 = st.text_input(
                    "Confirm password", type="password",
                    placeholder="Type it again to confirm",
                    label_visibility="collapsed",
                )
                submitted = st.form_submit_button(
                    "Create password and continue",
                    use_container_width=True, type="primary",
                )
                if submitted:
                    if pw1 != pw2:
                        st.error("The two passwords don't match.")
                    elif len(pw1) < 6:
                        st.error("Password must be at least 6 characters.")
                    else:
                        auth.set_password(pw1)
                        storage.log_audit("user", "password_set")
                        st.session_state.authenticated = True
                        st.session_state.login_time = datetime.now()
                        st.rerun()
            st.markdown(
                "<p class='login-foot'>Forgot it later? "
                "Rotate the password anytime from <b>Settings &rarr; Session &amp; Security</b>.</p>",
                unsafe_allow_html=True,
            )
        else:
            # Normal sign-in.
            with st.form("login_form", clear_on_submit=False, border=False):
                password = st.text_input(
                    "Password", type="password",
                    placeholder="Enter your password", label_visibility="collapsed",
                )
                submitted = st.form_submit_button(
                    "Sign In", use_container_width=True, type="primary",
                )
                if submitted:
                    if auth.verify(password):
                        st.session_state.authenticated = True
                        st.session_state.login_time = datetime.now()
                        storage.log_audit("user", "login", "success")
                        st.rerun()
                    else:
                        storage.log_audit("user", "login", "failed")
                        st.error("Invalid password.")

            st.markdown(
                "<p style='text-align:center;color:#71717a;font-size:0.8rem;margin:1rem 0 0.5rem;'>or</p>",
                unsafe_allow_html=True,
            )
            if oauth_github.is_configured():
                # Fresh state per render so the CSRF check stays meaningful across visits.
                if "oauth_state" not in st.session_state:
                    st.session_state["oauth_state"] = oauth_github.make_state()
                st.link_button(
                    "Sign in with GitHub",
                    oauth_github.authorize_url(st.session_state["oauth_state"]),
                    use_container_width=True,
                )
            if st.button("Try Demo (no password)", key="try_demo_btn", use_container_width=True):
                st.session_state.authenticated = True
                st.session_state.login_time = datetime.now()
                storage.log_audit("user", "login", "demo")
                st.rerun()

            with st.expander("Forgot password?"):
                st.caption(
                    "Clicking Reset will erase your stored password. "
                    "You'll be shown the 'Create password' screen where you can pick a new one."
                )
                if st.button("Reset my password", key="reset_pw_btn", use_container_width=True):
                    auth.reset()
                    storage.log_audit("user", "password_reset")
                    st.rerun()

            st.markdown(
                "<p class='login-foot'>Secured session &middot; Stored as a PBKDF2 hash</p>",
                unsafe_allow_html=True,
            )
    st.stop()

# ──────────────────────────────────────────────
# Main CSS — Cybersecurity Dark Theme
# ──────────────────────────────────────────────

st.markdown("""
<style>
    /* Global — Linear/Vercel-inspired refined dark theme */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
    * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important; }

    /* Preserve Streamlit's icon fonts — otherwise ligature names like
       "arrow_down" render as literal text instead of the chevron icon. */
    [data-testid="stIconMaterial"],
    [data-testid="stExpanderToggleIcon"],
    .material-icons,
    .material-icons-outlined,
    .material-symbols-rounded,
    .material-symbols-outlined,
    [class*="material-symbols"] {
        font-family:
            'Material Symbols Rounded',
            'Material Symbols Outlined',
            'Material Icons',
            'Material Icons Outlined' !important;
        font-feature-settings: 'liga' !important;
    }

    :root {
        --bg: #09090b;
        --bg-2: #0d0d10;
        --panel: #111114;
        --panel-2: #131318;
        --border: rgba(255,255,255,0.07);
        --border-hi: rgba(255,255,255,0.12);
        --text: #fafafa;
        --text-2: #a1a1aa;
        --text-3: #71717a;
        --accent: #6366f1;
        --accent-2: #8b5cf6;
        --success: #10b981;
        --warning: #f59e0b;
        --danger: #ef4444;
    }

    .stApp {
        background:
            radial-gradient(1400px 700px at 15% -15%, rgba(99,102,241,0.10), transparent 60%),
            radial-gradient(1000px 500px at 95% 0%, rgba(139,92,246,0.07), transparent 60%),
            linear-gradient(180deg, #0a0a0d 0%, #09090b 100%);
        background-attachment: fixed;
    }

    #MainMenu, footer { visibility: hidden; }
    /* Keep header transparent (so the sidebar collapse arrow stays clickable)
       but hide its background and the deploy button. */
    header[data-testid="stHeader"] { background: transparent !important; }
    .stDeployButton { display: none; }

    .stApp, .stApp p, .stApp span, .stApp div, .stApp label { color: var(--text); }
    .stMarkdown p { color: var(--text-2); }
    code, .stMarkdown code { font-family: 'JetBrains Mono', ui-monospace, monospace !important; font-size: 0.85em; background: rgba(255,255,255,0.06); padding: 0.1em 0.35em; border-radius: 4px; }

    /* Header */
    .app-header {
        padding: 1.25rem 1.5rem;
        margin-bottom: 1.5rem;
        border-radius: 16px;
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
        border: 1px solid var(--border);
        position: relative;
        overflow: hidden;
    }
    .app-header::before {
        content: "";
        position: absolute; top: 0; left: 0; right: 0; height: 1px;
        background: linear-gradient(90deg, transparent, rgba(99,102,241,0.7), rgba(139,92,246,0.5), transparent);
    }
    .app-header-row { display: flex; align-items: center; gap: 0.9rem; }
    .brand-mark {
        width: 40px; height: 40px; border-radius: 11px;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        display: flex; align-items: center; justify-content: center;
        box-shadow: 0 4px 16px rgba(99,102,241,0.35), inset 0 1px 0 rgba(255,255,255,0.2);
        flex-shrink: 0;
    }
    .brand-mark svg { width: 20px; height: 20px; color: #fff; }
    .app-header h1 {
        color: var(--text);
        font-size: 1.4rem; font-weight: 600; margin: 0;
        letter-spacing: -0.02em;
    }
    .app-header .header-sub {
        color: var(--text-3);
        font-size: 0.85rem;
        margin: 0.1rem 0 0;
        font-weight: 400;
    }
    .header-badge {
        margin-left: auto;
        padding: 0.3rem 0.75rem;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 500;
        letter-spacing: 0.2px;
        display: inline-flex; align-items: center; gap: 0.45rem;
    }
    .header-badge::before {
        content: ""; width: 6px; height: 6px; border-radius: 50%;
    }
    .badge-live { background: rgba(16,185,129,0.12); color: #34d399; border: 1px solid rgba(16,185,129,0.25); }
    .badge-live::before { background: #10b981; box-shadow: 0 0 8px #10b981; }
    .badge-sample { background: rgba(99,102,241,0.12); color: #a5b4fc; border: 1px solid rgba(99,102,241,0.25); }
    .badge-sample::before { background: #6366f1; }

    /* Metric cards */
    .mc {
        background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005));
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 1.1rem 1.25rem;
        position: relative;
        transition: border-color 0.2s ease, transform 0.2s ease;
        overflow: hidden;
    }
    .mc:hover { border-color: var(--border-hi); transform: translateY(-1px); }
    .mc::before {
        content: ""; position: absolute; left: 0; top: 0; bottom: 0;
        width: 3px;
    }
    .mc-cyan::before { background: linear-gradient(180deg, #6366f1, #8b5cf6); }
    .mc-green::before { background: linear-gradient(180deg, #10b981, #059669); }
    .mc-red::before { background: linear-gradient(180deg, #ef4444, #b91c1c); }
    .mc-amber::before { background: linear-gradient(180deg, #f59e0b, #d97706); }

    .mc .mc-label {
        color: var(--text-3);
        font-size: 0.72rem;
        font-weight: 500;
        letter-spacing: 0.4px;
        text-transform: uppercase;
        margin-bottom: 0.5rem;
    }
    .mc .mc-val {
        font-size: 1.85rem;
        font-weight: 600;
        margin: 0;
        letter-spacing: -0.03em;
        color: var(--text);
    }
    .mc .mc-sub {
        color: var(--text-3);
        font-size: 0.78rem;
        margin-top: 0.35rem;
        font-weight: 400;
    }
    .mc-green .mc-val { background: linear-gradient(180deg, #34d399, #10b981); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .mc-red .mc-val   { background: linear-gradient(180deg, #f87171, #ef4444); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .mc-amber .mc-val { background: linear-gradient(180deg, #fbbf24, #f59e0b); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .mc-cyan .mc-val  { background: linear-gradient(180deg, #a5b4fc, #6366f1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

    /* Threat bar */
    .threat-bar {
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 0.95rem 1.25rem;
        margin-bottom: 1.25rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .tb-label {
        color: var(--text-3);
        font-size: 0.7rem;
        font-weight: 500;
        letter-spacing: 0.4px;
        text-transform: uppercase;
        margin-bottom: 0.2rem;
    }
    .tb-status {
        font-size: 1rem;
        font-weight: 600;
        color: var(--text);
    }
    .st-low { color: #34d399; }
    .st-med { color: #fbbf24; }
    .st-high { color: #fb923c; }
    .st-crit { color: #f87171; }

    .rate-bar-bg {
        background: rgba(255,255,255,0.06);
        border-radius: 999px;
        height: 6px;
        flex: 1;
        margin-left: 1rem;
        overflow: hidden;
    }
    .rate-bar-fill {
        height: 100%;
        border-radius: 999px;
        transition: width 0.5s ease;
    }

    /* Card (reusable) */
    .glass {
        background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005));
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.6rem;
    }

    /* Alert banners */
    .alert-banner {
        border-radius: 12px;
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        display: flex;
        align-items: flex-start;
        gap: 0.85rem;
        border: 1px solid;
    }
    .ab-danger {
        background: linear-gradient(180deg, rgba(239,68,68,0.08), rgba(239,68,68,0.02));
        border-color: rgba(239,68,68,0.25);
    }
    .ab-safe {
        background: linear-gradient(180deg, rgba(16,185,129,0.08), rgba(16,185,129,0.02));
        border-color: rgba(16,185,129,0.25);
    }
    .ab-title {
        font-weight: 600;
        color: var(--text);
        font-size: 0.95rem;
    }
    .ab-desc {
        color: var(--text-2);
        font-size: 0.85rem;
        margin-top: 3px;
    }
    .ab-danger .ab-title { color: #fca5a5; }
    .ab-safe .ab-title { color: #6ee7b7; }

    /* Section header */
    .sec-h { margin: 1.25rem 0 0.85rem 0; }
    .sec-h h3 {
        margin: 0;
        font-size: 0.95rem;
        font-weight: 600;
        color: var(--text);
        letter-spacing: -0.01em;
    }

    /* Network info */
    .ni-card {
        background: linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.005));
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
        transition: border-color 0.15s ease;
    }
    .ni-card:hover { border-color: var(--border-hi); }
    .ni-lbl {
        color: var(--text-3);
        font-size: 0.7rem;
        font-weight: 500;
        letter-spacing: 0.3px;
        text-transform: uppercase;
        margin-bottom: 0.2rem;
    }
    .ni-val {
        color: var(--text);
        font-size: 0.95rem;
        font-weight: 500;
        font-family: 'JetBrains Mono', ui-monospace, monospace !important;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b0b0e 0%, #09090b 100%) !important;
        border-right: 1px solid var(--border);
    }
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] span {
        color: var(--text) !important;
    }
    [data-testid="stSidebar"] hr { border-color: var(--border) !important; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
        border-bottom: 1px solid var(--border);
        background: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        border-radius: 8px 8px 0 0;
        padding: 10px 16px;
        color: var(--text-3);
        border: none;
        font-weight: 500;
        font-size: 0.88rem;
        transition: color 0.15s;
    }
    .stTabs [data-baseweb="tab"]:hover { color: var(--text-2); }
    .stTabs [aria-selected="true"] {
        background: transparent;
        color: var(--text);
        border-bottom: 2px solid var(--accent);
        font-weight: 600;
    }

    /* Buttons */
    .stButton > button,
    [data-testid="stFormSubmitButton"] > button {
        background: linear-gradient(180deg, #6366f1, #4f46e5);
        color: #fff;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        font-weight: 500;
        padding: 0.5rem 1.1rem;
        box-shadow: 0 1px 0 rgba(255,255,255,0.1) inset, 0 4px 14px rgba(99,102,241,0.25);
        transition: all 0.15s ease;
    }
    .stButton > button:hover,
    [data-testid="stFormSubmitButton"] > button:hover {
        background: linear-gradient(180deg, #7c7df7, #5b55ea);
        border-color: rgba(255,255,255,0.15);
        transform: translateY(-1px);
    }
    /* Secondary/outline button (used for Sign Out) */
    .btn-secondary .stButton > button {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
        color: #e4e4e7;
        box-shadow: none;
    }
    .btn-secondary .stButton > button:hover {
        background: rgba(239,68,68,0.08);
        border-color: rgba(239,68,68,0.3);
        color: #fca5a5;
    }

    /* Executive overview panel */
    .exec-grid {
        display: grid;
        grid-template-columns: 1.3fr 1fr 1fr;
        gap: 0.9rem;
        margin-bottom: 1.25rem;
    }
    .exec-card {
        position: relative;
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.008));
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 1.1rem 1.25rem;
        overflow: hidden;
    }
    .exec-card .ec-label {
        color: var(--text-3);
        font-size: 0.7rem;
        font-weight: 500;
        letter-spacing: 0.4px;
        text-transform: uppercase;
    }
    .ec-score-row { display: flex; align-items: baseline; gap: 0.45rem; margin-top: 0.4rem; }
    .ec-score {
        font-size: 2.4rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1;
        background: linear-gradient(180deg, #a5b4fc, #6366f1);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    }
    .ec-score-unit { color: var(--text-3); font-size: 0.85rem; font-weight: 500; }
    .ec-score-status {
        display: inline-flex; align-items: center; gap: 0.4rem;
        padding: 0.2rem 0.6rem; border-radius: 999px;
        font-size: 0.72rem; font-weight: 500;
        margin-top: 0.6rem;
    }
    .ec-status-good { background: rgba(16,185,129,0.12); color: #34d399; border: 1px solid rgba(16,185,129,0.25); }
    .ec-status-warn { background: rgba(245,158,11,0.12); color: #fbbf24; border: 1px solid rgba(245,158,11,0.25); }
    .ec-status-bad  { background: rgba(239,68,68,0.12); color: #f87171; border: 1px solid rgba(239,68,68,0.25); }
    .ec-score-bar {
        margin-top: 0.85rem; height: 6px; border-radius: 999px;
        background: rgba(255,255,255,0.06); overflow: hidden;
    }
    .ec-score-bar-fill {
        height: 100%; border-radius: 999px;
        background: linear-gradient(90deg, #6366f1, #8b5cf6);
    }
    .ec-metric-val { font-size: 1.5rem; font-weight: 600; color: var(--text); margin-top: 0.4rem; letter-spacing: -0.02em; }
    .ec-metric-sub { color: var(--text-3); font-size: 0.78rem; margin-top: 0.25rem; }

    /* User chip in sidebar */
    .user-chip {
        display: flex; align-items: center; gap: 0.65rem;
        padding: 0.7rem 0.85rem;
        background: linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
        border: 1px solid var(--border);
        border-radius: 12px;
        margin-bottom: 1rem;
    }
    .user-avatar {
        width: 34px; height: 34px; border-radius: 50%;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        display: flex; align-items: center; justify-content: center;
        color: #fff; font-weight: 600; font-size: 0.85rem;
        flex-shrink: 0;
    }
    .user-meta { line-height: 1.25; min-width: 0; }
    .user-name { color: var(--text); font-size: 0.88rem; font-weight: 600; }
    .user-role { color: var(--text-3); font-size: 0.72rem; }
    .stDownloadButton > button {
        background: linear-gradient(180deg, #10b981, #059669);
        color: #fff;
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 10px;
        font-weight: 500;
        box-shadow: 0 1px 0 rgba(255,255,255,0.1) inset, 0 4px 14px rgba(16,185,129,0.25);
    }

    /* Inputs */
    .stTextInput input,
    .stSelectbox div[data-baseweb="select"] > div,
    .stNumberInput input {
        background: rgba(255,255,255,0.04) !important;
        border: 1px solid var(--border) !important;
        border-radius: 10px !important;
        color: var(--text) !important;
    }
    .stTextInput input:focus,
    .stNumberInput input:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px rgba(99,102,241,0.2) !important;
    }

    /* Dataframes */
    .stDataFrame {
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
    }
    /* Streamlit's dataframe toolbar can show hover tooltips ("Rearrange columns",
       "Search", etc.) that visually bleed into adjacent widgets. Keep them inside. */
    [data-testid="stDataFrame"] { position: relative; isolation: isolate; }
    [data-testid="stDataFrame"] [data-testid="StyledFullScreenButton"],
    [data-testid="stDataFrame"] [title] { z-index: 1; }
    .stDataFrame [data-testid="stTable"] { background: transparent !important; }

    /* Metrics widget override */
    [data-testid="stMetricValue"] { color: var(--text) !important; font-weight: 600 !important; }
    [data-testid="stMetricLabel"] { color: var(--text-3) !important; }

    /* Info/warning/success boxes */
    .stAlert { border-radius: 12px !important; background: rgba(255,255,255,0.03) !important; border: 1px solid var(--border) !important; }

    /* Checkbox */
    [data-testid="stCheckbox"] label { color: var(--text-2) !important; }

    /* Footer */
    .app-footer {
        text-align: center;
        color: var(--text-3);
        padding: 1.75rem 1rem 1rem;
        font-size: 0.8rem;
        border-top: 1px solid var(--border);
        margin-top: 2.5rem;
        font-weight: 400;
    }
    .app-footer .dot {
        display: inline-block; width: 4px; height: 4px; border-radius: 50%;
        background: var(--accent); margin: 0 0.5rem; vertical-align: middle;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Auto-train model
# ──────────────────────────────────────────────

if not os.path.exists(MODEL_PATH):
    from src.model import train_model
    with st.spinner("Training AI model for the first time..."):
        try:
            train_model()
        except Exception as e:
            st.error(
                f"Model training failed: {e}. "
                "The dashboard will continue with detection disabled until the model is trained successfully."
            )

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


# Short-TTL caches for SQLite reads that re-fire on every Streamlit rerun.
# `st.rerun()` (called from FP/allowlist/explain buttons) invalidates these,
# so user-driven mutations stay consistent.
@st.cache_data(ttl=5)
def _cached_list_alerts(days: int, include_fp: bool):
    return storage.list_alerts(days=days, include_fp=include_fp)


@st.cache_data(ttl=10)
def _cached_list_allowlist():
    return storage.list_allowlist()


@st.cache_data(ttl=10)
def _cached_list_audit(limit: int):
    return storage.list_audit(limit=limit)

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

# Stateful behavioral detection — catches patterns that no single packet can
# reveal: port scans (many distinct ports), brute force (many repeats to same
# target), and DoS floods (high packet volume per source).
_behavior_hits = behavior.enrich(df)
if "src_ip" in df.columns:
    for _pattern, _ips in _behavior_hits.items():
        if not _ips:
            continue
        _hit_mask = df["src_ip"].astype(str).isin(_ips)
        df.loc[_hit_mask, "attack_type"] = _pattern
        df.loc[_hit_mask, "prediction"] = -1
        df.loc[_hit_mask, "status"] = "ANOMALY"

# Apply allowlist: any src_ip on the allowlist is reclassified as Normal.
_allowlisted_ips = {row["ip"] for row in _cached_list_allowlist()}
if _allowlisted_ips and "src_ip" in df.columns:
    _mask = df["src_ip"].isin(_allowlisted_ips)
    df.loc[_mask, "prediction"] = 1
    df.loc[_mask, "status"] = "Normal"
    df.loc[_mask, "attack_type"] = "Normal"

# Threat-intel enrichment: upgrade any source IP that matches a known IOC feed.
_ti_iocs = _load_threat_intel()
if "src_ip" in df.columns:
    _ti_match_map: dict[str, list[str]] = {}
    for _unique_ip in df["src_ip"].dropna().unique():
        _hits = threat_intel.check(str(_unique_ip), _ti_iocs)
        if _hits:
            _ti_match_map[str(_unique_ip)] = _hits
    if _ti_match_map:
        _ti_mask = df["src_ip"].astype(str).isin(_ti_match_map.keys())
        df.loc[_ti_mask, "attack_type"] = "Known Malicious"
        df.loc[_ti_mask, "prediction"] = -1
        df.loc[_ti_mask, "status"] = "ANOMALY"
        df["threat_intel"] = df["src_ip"].astype(str).map(
            lambda ip: ", ".join(_ti_match_map.get(ip, []))
        )
    else:
        df["threat_intel"] = ""
else:
    df["threat_intel"] = ""

# Persist new anomalies (deduped by src_ip+attack_type within dedup window).
_cfg = app_config.load_config()
_dedup_window = int(_cfg.get("dedup", {}).get("window_seconds", 300))
_anoms = df[df["prediction"] == -1]
_new_alerts = []
for _, _row in _anoms.iterrows():
    _src = str(_row.get("src_ip", ""))
    _atk = str(_row.get("attack_type", ""))
    _key = storage.dedup_key(_src, _atk, _dedup_window)
    if storage.alert_exists(_key):
        continue
    _new_alerts.append({
        "ts": str(_row.get("timestamp") or datetime.now().isoformat()),
        "src_ip": _src,
        "dst_ip": str(_row.get("dst_ip", "")),
        "protocol": str(_row.get("protocol", "")),
        "src_port": int(_row.get("src_port") or 0),
        "dst_port": int(_row.get("dst_port") or 0),
        "packet_size": int(_row.get("packet_size") or 0),
        "flags": str(_row.get("flags", "")),
        "attack_type": _atk,
        "dedup_key": _key,
    })

if _new_alerts:
    storage.record_alerts(_new_alerts)
    _severity = alerting.severity_from_pct(
        len(_anoms) / max(len(df), 1) * 100,
    )
    _body = "\n".join(
        f"- {a['src_ip']} → {a['dst_ip']} [{a['attack_type']}]"
        for a in _new_alerts[:10]
    )
    alerting.dispatch(
        _cfg,
        title=f"NetWatchAI: {len(_new_alerts)} new threat(s) ({_severity})",
        body=_body,
        severity=_severity,
    )

# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────

badge_cls = "badge-live" if data_source == "Live Capture" else "badge-sample"
badge_txt = "Live" if data_source == "Live Capture" else "Sample Data"
st.markdown(f"""
<div class="app-header">
    <div class="app-header-row">
        <div class="brand-mark">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div style="flex:1;">
            <h1>NetWatchAI</h1>
            <p class="header-sub">Network Monitoring and Intrusion Detection</p>
        </div>
        <span class="header-badge {badge_cls}">{badge_txt}</span>
    </div>
</div>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────

# User chip + sign-out at the top of the sidebar — only when auth is enabled.
if _auth_enabled:
    login_time = st.session_state.get("login_time")
    session_txt = login_time.strftime("Signed in at %H:%M") if login_time else "Signed in"
    st.sidebar.markdown(f"""
    <div class="user-chip">
        <div class="user-avatar">SA</div>
        <div class="user-meta">
            <div class="user-name">Security Admin</div>
            <div class="user-role">{session_txt}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    with st.sidebar.container():
        st.markdown('<div class="btn-secondary">', unsafe_allow_html=True)
        if st.button("Sign Out", use_container_width=True, key="signout_btn"):
            storage.log_audit("user", "logout")
            st.session_state.authenticated = False
            st.session_state.pop("login_time", None)
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    st.sidebar.markdown("---")
st.sidebar.markdown("## Filters")
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
st.sidebar.markdown(f"**Total:** {len(df)} packets")
st.sidebar.markdown(f"**Filtered:** {len(filtered_df)} packets")

# ──────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────

total_packets = len(df)
n_anomalies = int((df["prediction"] == -1).sum())
n_normal = int((df["prediction"] == 1).sum())
anomaly_pct = (n_anomalies / total_packets * 100) if total_packets > 0 else 0
normal_pct = (n_normal / total_packets * 100) if total_packets > 0 else 0

# Business-facing Security Score — inverse of anomaly rate, dampened
security_score = max(0, min(100, round(100 - (anomaly_pct * 2.5))))
if security_score >= 85:
    sec_status_txt, sec_status_cls = "Healthy", "ec-status-good"
elif security_score >= 60:
    sec_status_txt, sec_status_cls = "Needs Attention", "ec-status-warn"
else:
    sec_status_txt, sec_status_cls = "At Risk", "ec-status-bad"

unique_sources = int(df["src_ip"].nunique()) if "src_ip" in df.columns else 0
anomaly_df_preview = df[df["prediction"] == -1]
unique_attackers = int(anomaly_df_preview["src_ip"].nunique()) if len(anomaly_df_preview) > 0 else 0

st.markdown(f"""
<div class="exec-grid">
    <div class="exec-card">
        <div class="ec-label">Security Score</div>
        <div class="ec-score-row">
            <span class="ec-score">{security_score}</span>
            <span class="ec-score-unit">/ 100</span>
        </div>
        <div class="ec-score-bar"><div class="ec-score-bar-fill" style="width:{security_score}%;"></div></div>
        <span class="ec-score-status {sec_status_cls}">&bull; {sec_status_txt}</span>
    </div>
    <div class="exec-card">
        <div class="ec-label">Threats Detected</div>
        <div class="ec-metric-val">{n_anomalies:,}</div>
        <div class="ec-metric-sub">{anomaly_pct:.1f}% of {total_packets:,} packets analyzed</div>
    </div>
    <div class="exec-card">
        <div class="ec-label">Hostile Sources</div>
        <div class="ec-metric-val">{unique_attackers}</div>
        <div class="ec-metric-sub">of {unique_sources} total sources observed</div>
    </div>
</div>
""", unsafe_allow_html=True)

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"""<div class="mc mc-cyan">
        <div class="mc-label">Total Packets</div>
        <div class="mc-val">{total_packets:,}</div>
        <div class="mc-sub">All captured traffic</div>
    </div>""", unsafe_allow_html=True)
with col2:
    st.markdown(f"""<div class="mc mc-green">
        <div class="mc-label">Normal</div>
        <div class="mc-val">{n_normal:,}</div>
        <div class="mc-sub">{normal_pct:.1f}% safe traffic</div>
    </div>""", unsafe_allow_html=True)
with col3:
    st.markdown(f"""<div class="mc mc-red">
        <div class="mc-label">Anomalies</div>
        <div class="mc-val">{n_anomalies:,}</div>
        <div class="mc-sub">{anomaly_pct:.1f}% suspicious</div>
    </div>""", unsafe_allow_html=True)
with col4:
    unique_attacks = df[df["prediction"]==-1]["attack_type"].nunique()
    st.markdown(f"""<div class="mc mc-amber">
        <div class="mc-label">Attack Types</div>
        <div class="mc-val">{unique_attacks}</div>
        <div class="mc-sub">Unique threat patterns</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

anomaly_df = df[df["prediction"] == -1]

# Chart config — refined palette, dark theme
COLORS = ["#6366f1", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444", "#ec4899", "#14b8a6", "#a78bfa", "#f97316"]
SAFE = "#10b981"
DANGER = "#ef4444"
NEUTRAL = "#71717a"
FONT = "#a1a1aa"
BG = "rgba(0,0,0,0)"
GRID = "rgba(255,255,255,0.06)"

def chart_layout(fig, **kwargs):
    fig.update_layout(
        paper_bgcolor=BG, plot_bgcolor=BG, font_color=FONT,
        margin=dict(t=10, b=10, l=10, r=10),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=11, color=FONT)),
        xaxis=dict(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont=dict(color=FONT)),
        yaxis=dict(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont=dict(color=FONT)),
        **kwargs,
    )
    return fig

# ──────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab_settings = st.tabs([
    "Alerts", "Attack Types", "Top Attackers",
    "Timeline", "Statistics", "Network Info",
    "Attack Map", "PDF Report", "Settings",
])

# ── Tab 1: Alerts ──────────────────────────────

with tab1:
    if len(anomaly_df) == 0:
        st.markdown("""<div class="alert-banner ab-safe">
            <div><div class="ab-title">All Clear: No Threats Detected</div>
            <div class="ab-desc">All network traffic appears normal. No anomalies found in current data.</div></div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""<div class="alert-banner ab-danger">
            <div><div class="ab-title">{n_anomalies} Threat(s) Detected. Immediate Review Required.</div>
            <div class="ab-desc">{unique_attacks} unique attack pattern(s) found across {anomaly_df['src_ip'].nunique()} source IP(s).</div></div>
        </div>""", unsafe_allow_html=True)
        alert_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type"]
        st.dataframe(anomaly_df[[c for c in alert_cols if c in anomaly_df.columns]], use_container_width=True, hide_index=True)

        st.markdown("<div style='height:1.25rem'></div>", unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:0.95rem;font-weight:600;color:#fafafa;margin-bottom:0.5rem;'>"
            "Investigate — why was each threat flagged, and what to do</div>",
            unsafe_allow_html=True,
        )
        attack_counts = anomaly_df["attack_type"].value_counts()
        for atk_type, count in attack_counts.items():
            why, action = ATTACK_PLAYBOOK.get(
                atk_type,
                ("This event was flagged as anomalous by the ML model.",
                 "Manually review the source IP, destination, and timing."),
            )
            sources = anomaly_df[anomaly_df["attack_type"] == atk_type]["src_ip"].unique()
            sources_str = ", ".join(sources[:5]) + (f" and {len(sources) - 5} more" if len(sources) > 5 else "")
            with st.expander(f"{atk_type} — {count} event(s)", expanded=False):
                st.markdown(
                    f"<div style='margin-bottom:0.75rem;'>"
                    f"<span style='color:#a1a1aa;font-size:0.8rem;'>Source IP(s):</span> "
                    f"<span style='font-family:JetBrains Mono,monospace;font-size:0.85rem;color:#fafafa;'>"
                    f"{sources_str}</span></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div style='margin-bottom:0.5rem;'>"
                    f"<span style='color:#a1a1aa;font-size:0.8rem;font-weight:600;'>WHY THIS WAS FLAGGED</span><br>"
                    f"<span style='color:#e4e4e7;font-size:0.9rem;line-height:1.5;'>{why}</span></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"<div>"
                    f"<span style='color:#a1a1aa;font-size:0.8rem;font-weight:600;'>RECOMMENDED ACTION</span><br>"
                    f"<span style='color:#e4e4e7;font-size:0.9rem;line-height:1.5;'>{action}</span></div>",
                    unsafe_allow_html=True,
                )

    # Spacer prevents the dataframe's hover toolbar tooltip ("Rearrange columns",
    # "Search", "Download") from visually overlapping the expander title below.
    st.markdown("<div style='height:1.75rem'></div>", unsafe_allow_html=True)

    # Review persisted alerts: mark as false positive or allowlist.
    with st.expander("Manage alerts (mark false positives, add to allowlist)", expanded=False):
        st.caption(
            "Threats NetWatchAI has saved to its database. "
            "Click 'Explain' for an AI breakdown, 'False positive' to suppress, or 'Allowlist' to trust the source IP."
        )
        days_window = st.selectbox(
            "Look back", options=[7, 30, 90, 365], index=1,
            format_func=lambda d: f"{d} days", key="manage_alerts_days",
        )
        stored = _cached_list_alerts(days=days_window, include_fp=False)
        if not stored:
            st.info(
                "Nothing to review yet. New threats will appear here after they're detected. "
                "If you're running on sample data, any anomalies you see above have already been "
                "saved for the next time you open this panel."
            )
        else:
            st.caption(f"Showing {len(stored)} saved alert(s).")
            ai_ready = ai_explainer.is_configured()
            if not ai_ready:
                st.caption(
                    "_Set `ANTHROPIC_API_KEY` in your environment to enable per-alert AI explanations._"
                )
            for alert in stored[:25]:
                c1, c2, c3, c4, c5 = st.columns([3.4, 1.8, 1.0, 1.2, 1.2])
                with c1:
                    st.markdown(
                        f"<div style='font-size:0.85rem;'>"
                        f"<b>{alert['attack_type']}</b> &middot; "
                        f"<span style='color:#a1a1aa;font-family:JetBrains Mono,monospace;'>"
                        f"{alert['src_ip']} → {alert['dst_ip']}</span></div>"
                        f"<div style='color:#71717a;font-size:0.75rem;'>{alert['ts']}</div>",
                        unsafe_allow_html=True,
                    )
                with c2:
                    st.markdown(
                        f"<span style='color:#a1a1aa;font-size:0.8rem;'>"
                        f"{alert['protocol']} :{alert['dst_port']} &middot; {alert['packet_size']}B"
                        f"</span>",
                        unsafe_allow_html=True,
                    )
                with c3:
                    if st.button("Explain", key=f"ex_{alert['id']}", disabled=not ai_ready,
                                 help="Ask Claude to explain this alert" if ai_ready else "Set ANTHROPIC_API_KEY"):
                        st.session_state[f"explain_open_{alert['id']}"] = True
                with c4:
                    if st.button("False positive", key=f"fp_{alert['id']}"):
                        storage.mark_false_positive(alert["id"])
                        storage.log_audit("user", "mark_fp", f"alert_id={alert['id']}")
                        _cached_list_alerts.clear()
                        _cached_list_audit.clear()
                        st.rerun()
                with c5:
                    if st.button("Allowlist", key=f"al_{alert['id']}"):
                        storage.add_allowlist(alert["src_ip"], note=f"from alert {alert['id']}")
                        storage.log_audit("user", "allowlist_add", alert["src_ip"])
                        _cached_list_allowlist.clear()
                        _cached_list_audit.clear()
                        st.rerun()

                if st.session_state.get(f"explain_open_{alert['id']}"):
                    with st.expander("AI explanation", expanded=True):
                        try:
                            with st.spinner("Asking Claude..."):
                                result = ai_explainer.explain(alert)
                            st.markdown(result["explanation"])
                            st.caption(f"_Model: {result['model']} &middot; {result['source']}_")
                        except Exception as e:
                            st.error(f"Explanation failed: {e}")

    st.markdown("---")
    st.markdown(f"""<div class="sec-h"><h3>Packet Log ({len(filtered_df):,} of {len(df):,})</h3></div>""", unsafe_allow_html=True)

    display_cols = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "packet_size", "flags", "attack_type", "status"]
    avail = [c for c in display_cols if c in filtered_df.columns]
    if len(filtered_df) == 0:
        st.info("No packets match filters.")
    else:
        PAGE_SIZE = 100
        total_pages = max(1, (len(filtered_df) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1, key="packet_log_page")
        start = (page - 1) * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(filtered_df))
        st.caption(f"Showing {start+1}–{end} of {len(filtered_df):,} packets (page {page}/{total_pages})")
        page_df = filtered_df[avail].iloc[start:end].reset_index(drop=True)
        st.dataframe(page_df, use_container_width=True, hide_index=True, height=400)

        # Per-packet AI explainer. Pick a row from the current page and ask Claude to break it down.
        ai_ready = ai_explainer.is_configured()
        pc1, pc2 = st.columns([1, 5])
        with pc1:
            row_pick = st.number_input(
                "Explain row #", min_value=1, max_value=len(page_df),
                value=1, step=1, key=f"packet_explain_row_{page}",
                disabled=not ai_ready,
            )
        with pc2:
            if st.button("Explain packet", key=f"packet_explain_btn_{page}",
                         disabled=not ai_ready,
                         help="Ask Claude what this packet might mean" if ai_ready else "Set ANTHROPIC_API_KEY"):
                st.session_state[f"packet_explain_open_{page}"] = int(row_pick)
        if not ai_ready:
            st.caption("_Set `ANTHROPIC_API_KEY` to enable per-packet AI explanations._")

        opened_row = st.session_state.get(f"packet_explain_open_{page}")
        if opened_row:
            packet = page_df.iloc[opened_row - 1].to_dict()
            packet["ts"] = packet.get("timestamp")
            with st.expander(f"AI explanation — row {opened_row}", expanded=True):
                try:
                    with st.spinner("Asking Claude..."):
                        result = ai_explainer.explain(packet, use_cache=False)
                    st.markdown(result["explanation"])
                    st.caption(f"_Model: {result['model']} &middot; {result['source']}_")
                except Exception as e:
                    st.error(f"Explanation failed: {e}")

# ── Tab 2: Attack Types ───────────────────────

with tab2:
    if len(anomaly_df) > 0:
        c1, c2 = st.columns([1.2, 1])
        with c1:
            st.markdown("""<div class="sec-h"><h3>Attack Distribution</h3></div>""", unsafe_allow_html=True)
            ac = anomaly_df["attack_type"].value_counts().reset_index()
            ac.columns = ["Attack Type", "Count"]
            fig = px.pie(ac, values="Count", names="Attack Type", color_discrete_sequence=COLORS, hole=0.5)
            fig.update_traces(textinfo="percent+label", textfont_size=11, marker=dict(line=dict(color="#09090b", width=2)))
            chart_layout(fig)
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            st.markdown("""<div class="sec-h"><h3>Attack Details</h3></div>""", unsafe_allow_html=True)
            desc = {"Port Scan":"Probing open ports to find vulnerabilities", "Ping of Death":"Oversized ICMP packets to crash systems",
                    "Data Exfiltration":"Stealing data via suspicious ports", "Suspicious Port":"Traffic to known backdoor ports",
                    "Large Transfer":"Abnormally large data transfer", "DNS Anomaly":"DNS tunneling or spoofing attempt",
                    "Unknown Anomaly":"Unclassified suspicious pattern"}
            acs = anomaly_df["attack_type"].value_counts().reset_index()
            acs.columns = ["Attack Type", "Count"]
            acs["Description"] = acs["Attack Type"].map(desc).fillna("")
            st.dataframe(acs, use_container_width=True, hide_index=True)
    else:
        st.markdown("""<div class="alert-banner ab-safe">
            <div><div class="ab-title">No Attack Patterns Found</div>
            <div class="ab-desc">Your network looks clean.</div></div></div>""", unsafe_allow_html=True)

# ── Tab 3: Top Attackers ───────────────────────

with tab3:
    if len(anomaly_df) > 0:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""<div class="sec-h"><h3>Suspicious Sources</h3></div>""", unsafe_allow_html=True)
            top_src = anomaly_df["src_ip"].value_counts().head(10).reset_index()
            top_src.columns = ["Source IP", "Attacks"]
            top_src["Types"] = top_src["Source IP"].apply(lambda ip: ", ".join(anomaly_df[anomaly_df["src_ip"]==ip]["attack_type"].unique()))
            st.dataframe(top_src, use_container_width=True, hide_index=True)
        with c2:
            st.markdown("""<div class="sec-h"><h3>Targeted Destinations</h3></div>""", unsafe_allow_html=True)
            top_dst = anomaly_df["dst_ip"].value_counts().head(10).reset_index()
            top_dst.columns = ["Destination IP", "Attacks"]
            top_dst["Ports"] = top_dst["Destination IP"].apply(lambda ip: ", ".join(str(p) for p in anomaly_df[anomaly_df["dst_ip"]==ip]["dst_port"].unique()[:5]))
            st.dataframe(top_dst, use_container_width=True, hide_index=True)

        fig = px.bar(top_src, x="Attacks", y="Source IP", orientation="h", color="Attacks",
                     color_continuous_scale=[[0,"#1e1b4b"],[0.5,"#6366f1"],[1,"#a78bfa"]])
        chart_layout(fig, showlegend=False, coloraxis_showscale=False)
        fig.update_layout(yaxis=dict(autorange="reversed", gridcolor=GRID))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.markdown("""<div class="alert-banner ab-safe">
            <div><div class="ab-title">No Attackers Found</div>
            <div class="ab-desc">No suspicious source IPs detected.</div></div></div>""", unsafe_allow_html=True)

# ── Tab 4: Timeline ───────────────────────────

with tab4:
    if "timestamp" in df.columns:
        tdf = df.copy()
        tdf["timestamp"] = pd.to_datetime(tdf["timestamp"], errors="coerce")
        tdf = tdf.dropna(subset=["timestamp"])
        if len(tdf) > 0:
            st.markdown("""<div class="sec-h"><h3>Traffic Over Time</h3></div>""", unsafe_allow_html=True)
            tdf["tb"] = tdf["timestamp"].dt.floor("1min")
            tg = tdf.groupby(["tb", "status"]).size().reset_index(name="count")
            fig = px.area(tg, x="tb", y="count", color="status",
                         color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL},
                         labels={"tb":"Time","count":"Packets","status":"Status"})
            chart_layout(fig, hovermode="x unified")
            st.plotly_chart(fig, use_container_width=True)

            at = tdf[tdf["status"]=="ANOMALY"]
            if len(at) > 0:
                st.markdown("""<div class="sec-h"><h3>Attacks Over Time</h3></div>""", unsafe_allow_html=True)
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
        st.markdown("""<div class="sec-h"><h3>Protocol Distribution</h3></div>""", unsafe_allow_html=True)
        pc = df["protocol"].value_counts().reset_index()
        pc.columns = ["Protocol", "Count"]
        fig = px.pie(pc, values="Count", names="Protocol", color_discrete_sequence=COLORS, hole=0.5)
        fig.update_traces(textinfo="percent+label", textfont_size=11, marker=dict(line=dict(color="#09090b", width=2)))
        chart_layout(fig)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.markdown("""<div class="sec-h"><h3>Normal vs Anomaly</h3></div>""", unsafe_allow_html=True)
        sc = df["status"].value_counts().reset_index()
        sc.columns = ["Status", "Count"]
        fig = px.bar(sc, x="Status", y="Count", color="Status",
                     color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL})
        fig.update_traces(marker_line_width=0, opacity=0.9)
        chart_layout(fig, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("""<div class="sec-h"><h3>Packet Size Distribution</h3></div>""", unsafe_allow_html=True)
    fig = px.histogram(df, x="packet_size", color="status", nbins=30,
                       color_discrete_map={"Normal":SAFE, "ANOMALY":DANGER, "Unknown":NEUTRAL},
                       labels={"packet_size":"Packet Size (bytes)","status":"Status"})
    chart_layout(fig)
    st.plotly_chart(fig, use_container_width=True)

# ── Tab 6: Network Info ────────────────────────

with tab6:
    net_info = get_network_info()
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""<div class="sec-h"><h3>WiFi and Connection</h3></div>""", unsafe_allow_html=True)
        for key in ["WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel", "Hostname"]:
            val = html_module.escape(str(net_info.get(key, "N/A")))
            st.markdown(f"""<div class="ni-card">
                <div class="ni-lbl">{key}</div><div class="ni-val">{val}</div></div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""<div class="sec-h"><h3>IP and Routing</h3></div>""", unsafe_allow_html=True)
        for key in ["Local IP", "Public IP", "Gateway (Router)", "Subnet Mask", "MAC Address", "DNS Servers"]:
            val = html_module.escape(str(net_info.get(key, "N/A")))
            st.markdown(f"""<div class="ni-card">
                <div class="ni-lbl">{key}</div><div class="ni-val">{val}</div></div>""", unsafe_allow_html=True)

    signal_str = net_info.get("Signal Strength", "")
    if "dBm" in signal_str:
        rssi_val = int(signal_str.split(" ")[0])
        gauge_val = max(0, min(100, (rssi_val + 100) * 100 // 70))
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=gauge_val,
            title={"text":"WiFi Signal Quality", "font":{"color":"#a1a1aa","size":14}},
            number={"suffix":"%", "font":{"color":"#fafafa","size":36}},
            gauge={"axis":{"range":[0,100],"tickcolor":"rgba(255,255,255,0.15)","tickfont":{"color":"#71717a"}},
                   "bar":{"color":"#6366f1","thickness":0.6},
                   "bgcolor":"rgba(255,255,255,0.04)", "borderwidth":0,
                   "steps":[{"range":[0,30],"color":"rgba(239,68,68,0.15)"},
                            {"range":[30,60],"color":"rgba(245,158,11,0.15)"},
                            {"range":[60,100],"color":"rgba(16,185,129,0.15)"}]}))
        fig.update_layout(height=250, margin=dict(t=40,b=10,l=30,r=30), paper_bgcolor=BG, font_color="#a1a1aa")
        st.plotly_chart(fig, use_container_width=True)

# ── Tab 7: Attack Map ────────────────────────

with tab7:
    st.markdown("""<div class="sec-h"><h3>Global Attack Map</h3></div>""", unsafe_allow_html=True)

    if len(anomaly_df) > 0:
        attacker_ips = anomaly_df["src_ip"].unique().tolist()
        geo_data = get_geo_data_for_ips(attacker_ips)

        if geo_data:
            geo_df = pd.DataFrame(geo_data)
            # Add attack counts
            ip_counts = anomaly_df["src_ip"].value_counts().to_dict()
            geo_df["attacks"] = geo_df["ip"].map(ip_counts).fillna(1).astype(int)
            geo_df["attack_types"] = geo_df["ip"].apply(
                lambda ip: ", ".join(anomaly_df[anomaly_df["src_ip"] == ip]["attack_type"].unique())
            )
            geo_df["label"] = geo_df.apply(
                lambda r: f"{r['ip']} ({r['city']}, {r['country']})<br>Attacks: {r['attacks']}<br>{r['attack_types']}", axis=1
            )

            fig = go.Figure()

            # Attack lines
            for _, row in geo_df.iterrows():
                fig.add_trace(go.Scattergeo(
                    lon=[row["lon"], None],
                    lat=[row["lat"], None],
                    mode="lines",
                    line=dict(width=1, color="rgba(239,68,68,0.35)"),
                    showlegend=False,
                    hoverinfo="skip",
                ))

            # Attacker dots
            fig.add_trace(go.Scattergeo(
                lon=geo_df["lon"],
                lat=geo_df["lat"],
                text=geo_df["label"],
                hoverinfo="text",
                mode="markers",
                marker=dict(
                    size=geo_df["attacks"].clip(upper=30) * 2 + 6,
                    color="#ef4444",
                    opacity=0.85,
                    line=dict(width=1, color="#fca5a5"),
                    sizemode="diameter",
                ),
                name="Attackers",
            ))

            fig.update_geos(
                bgcolor="rgba(0,0,0,0)",
                landcolor="rgba(255,255,255,0.04)",
                oceancolor="rgba(0,0,0,0)",
                lakecolor="rgba(0,0,0,0)",
                coastlinecolor="rgba(99,102,241,0.35)",
                countrycolor="rgba(255,255,255,0.08)",
                showframe=False,
                projection_type="natural earth",
            )
            fig.update_layout(
                height=500,
                paper_bgcolor="rgba(0,0,0,0)",
                geo=dict(bgcolor="rgba(0,0,0,0)"),
                margin=dict(t=10, b=10, l=0, r=0),
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

            # Attacker table with geo info
            st.markdown("""<div class="sec-h"><h3>Attacker Locations</h3></div>""", unsafe_allow_html=True)
            display_geo = geo_df[["ip", "city", "country", "isp", "attacks", "attack_types"]].copy()
            display_geo.columns = ["IP Address", "City", "Country", "ISP", "Attacks", "Attack Types"]
            st.dataframe(display_geo.sort_values("Attacks", ascending=False), use_container_width=True, hide_index=True)
        else:
            st.info("Could not geolocate attacker IPs. They may all be private/local addresses.")
    else:
        st.markdown("""<div class="alert-banner ab-safe">
            <div><div class="ab-title">No Attacks to Map</div>
            <div class="ab-desc">No anomalous traffic detected. The map will populate when threats are found.</div></div></div>""",
            unsafe_allow_html=True)

# ── Tab 8: PDF Report ────────────────────────

with tab8:
    st.markdown("""<div class="sec-h"><h3>Security Threat Report</h3></div>""", unsafe_allow_html=True)

    st.markdown("""<div class="glass">
        <div style="color:#fafafa; font-weight:600; font-size:0.95rem; margin-bottom:0.4rem;">Generate PDF Report</div>
        <div style="color:#a1a1aa; font-size:0.85rem;">
        Download a professional security report with executive summary, attack breakdown,
        top attacker analysis, and actionable recommendations. Share it with your team or management.
        </div></div>""", unsafe_allow_html=True)

    st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

    # Report preview
    total = len(df)
    n_anom = len(anomaly_df)
    pct = (n_anom / total * 100) if total > 0 else 0

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("Total Packets", f"{total:,}")
    with c2:
        st.metric("Anomalies", f"{n_anom:,}")
    with c3:
        st.metric("Anomaly Rate", f"{pct:.1f}%")

    st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)

    report_contents = "**Report will include:**\n"
    report_contents += "- Cover page with branding\n"
    report_contents += "- Executive summary with threat level\n"
    report_contents += "- Attack type breakdown with descriptions\n"
    report_contents += "- Top suspicious IP addresses\n"
    report_contents += "- Actionable security recommendations\n"
    st.markdown(report_contents)

    if st.button("Generate PDF Report", type="primary", use_container_width=True):
        with st.spinner("Generating security report..."):
            pdf_bytes = generate_pdf_report(df, anomaly_df)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            st.download_button(
                label="Download Report",
                data=pdf_bytes,
                file_name=f"NetWatchAI_Report_{timestamp}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        st.success("Report generated successfully! Click 'Download Report' above.")

# ──────────────────────────────────────────────
# Footer
# ──────────────────────────────────────────────

# ── Tab: Settings ─────────────────────────────

with tab_settings:
    cfg = app_config.load_config()

    st.markdown("""<div class="sec-h"><h3>Alert Channels</h3></div>""", unsafe_allow_html=True)
    st.caption("Get pinged when NetWatchAI detects a threat. All channels are optional and free.")

    with st.form("channels_form"):
        col_a, col_b = st.columns(2)
        with col_a:
            discord = st.text_input(
                "Discord webhook URL",
                value=cfg["alerts"].get("discord_webhook", ""),
                placeholder="https://discord.com/api/webhooks/...",
            )
            slack = st.text_input(
                "Slack webhook URL",
                value=cfg["alerts"].get("slack_webhook", ""),
                placeholder="https://hooks.slack.com/services/...",
            )
            severity = st.selectbox(
                "Minimum severity to notify",
                options=["low", "medium", "high", "critical"],
                index=["low", "medium", "high", "critical"].index(
                    cfg["alerts"].get("min_severity", "high")
                ),
            )
        with col_b:
            email_cfg = cfg["alerts"].get("email", {})
            smtp_host = st.text_input("SMTP host", value=email_cfg.get("smtp_host", ""), placeholder="smtp.gmail.com")
            smtp_port = st.number_input("SMTP port", value=int(email_cfg.get("smtp_port", 587)), step=1)
            smtp_user = st.text_input("SMTP username", value=email_cfg.get("username", ""))
            smtp_pass = st.text_input("SMTP password / app token", value=email_cfg.get("password", ""), type="password")
            smtp_to = st.text_input("Send alerts to", value=email_cfg.get("to", ""))

        if st.form_submit_button("Save settings", use_container_width=True):
            cfg["alerts"]["discord_webhook"] = discord.strip()
            cfg["alerts"]["slack_webhook"] = slack.strip()
            cfg["alerts"]["min_severity"] = severity
            cfg["alerts"]["email"] = {
                "smtp_host": smtp_host.strip(),
                "smtp_port": int(smtp_port),
                "username": smtp_user.strip(),
                "password": smtp_pass,
                "to": smtp_to.strip(),
            }
            app_config.save_config(cfg)
            storage.log_audit("user", "settings_update", "alert channels")
            st.success("Settings saved.")

    if st.button("Send test alert", key="test_alert_btn"):
        result = alerting.dispatch(
            cfg,
            title="NetWatchAI: test alert",
            body="This is a test. If you see this, the channel works.",
            severity="critical",
        )
        if result.get("skipped"):
            st.warning("Test skipped: severity below threshold.")
        elif not result:
            st.warning("No channels configured yet.")
        else:
            st.success(f"Dispatched: {result}")

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Allowlist</h3></div>""", unsafe_allow_html=True)
    st.caption("IPs here will never trigger an anomaly. Useful for internal scanners and monitoring tools.")

    allow = _cached_list_allowlist()
    with st.form("allow_form", clear_on_submit=True):
        col_x, col_y, col_z = st.columns([2, 3, 1])
        with col_x:
            new_ip = st.text_input("IP address", placeholder="10.0.0.5")
        with col_y:
            new_note = st.text_input("Note", placeholder="Internal scanner")
        with col_z:
            st.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
            if st.form_submit_button("Add", use_container_width=True):
                if new_ip.strip():
                    storage.add_allowlist(new_ip.strip(), new_note.strip())
                    storage.log_audit("user", "allowlist_add", new_ip.strip())
                    _cached_list_allowlist.clear()
                    _cached_list_audit.clear()
                    st.rerun()

    if allow:
        for item in allow:
            c1, c2, c3 = st.columns([2, 4, 1])
            with c1:
                st.markdown(
                    f"<span style='font-family:JetBrains Mono,monospace;'>{item['ip']}</span>",
                    unsafe_allow_html=True,
                )
            with c2:
                st.markdown(
                    f"<span style='color:#a1a1aa;font-size:0.85rem;'>{item.get('note') or '(no note)'}</span>",
                    unsafe_allow_html=True,
                )
            with c3:
                if st.button("Remove", key=f"rm_{item['ip']}"):
                    storage.remove_allowlist(item["ip"])
                    storage.log_audit("user", "allowlist_remove", item["ip"])
                    _cached_list_allowlist.clear()
                    _cached_list_audit.clear()
                    st.rerun()
    else:
        st.caption("No allowlisted IPs yet.")

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Data Retention</h3></div>""", unsafe_allow_html=True)
    st.caption("How long to keep stored alerts before automatic deletion.")

    col_r1, col_r2 = st.columns([3, 1])
    with col_r1:
        retention = st.slider(
            "Retention window (days)",
            min_value=7, max_value=365,
            value=int(cfg.get("retention_days", 30)),
        )
    with col_r2:
        st.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
        if st.button("Save & purge now", use_container_width=True):
            cfg["retention_days"] = int(retention)
            app_config.save_config(cfg)
            removed = storage.purge_older_than(int(retention))
            storage.log_audit("user", "purge", f"{removed} rows (>{retention}d)")
            st.success(f"Saved. Purged {removed} old alert(s).")

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Login & Security</h3></div>""", unsafe_allow_html=True)

    if _auth_enabled:
        st.caption(
            "Login is currently **enabled**. Anyone visiting the dashboard must enter your password."
        )
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            with st.form("change_pw_form", clear_on_submit=True, border=False):
                new_pw_input = st.text_input(
                    "Change password", type="password",
                    placeholder="New password (at least 6 characters)",
                )
                if st.form_submit_button("Update password", use_container_width=True):
                    try:
                        auth.set_password(new_pw_input)
                        storage.log_audit("user", "password_change")
                        st.success("Password updated.")
                    except ValueError as e:
                        st.error(str(e))
        with col_s2:
            if st.button("Disable login (remove password)", use_container_width=True):
                auth.reset()
                storage.log_audit("user", "auth_disable")
                st.success("Login disabled. Refresh the page — the dashboard will open without prompting.")
    else:
        st.caption(
            "Login is currently **disabled**. The dashboard opens directly to anyone who can reach it. "
            "This is fine for local use. For any public deploy, set a password."
        )
        with st.form("enable_auth_form", clear_on_submit=True, border=False):
            col_ea1, col_ea2 = st.columns([3, 1])
            with col_ea1:
                set_pw_input = st.text_input(
                    "Set a password to enable login",
                    type="password",
                    placeholder="Choose a password (at least 6 characters)",
                    label_visibility="collapsed",
                )
            with col_ea2:
                if st.form_submit_button("Enable login", use_container_width=True):
                    try:
                        auth.set_password(set_pw_input)
                        storage.log_audit("user", "auth_enable")
                        st.success("Login enabled. Refresh the page to sign in.")
                    except ValueError as e:
                        st.error(str(e))

    st.markdown(
        "<div style='color:#a1a1aa;font-size:0.82rem;margin-top:0.75rem;'>"
        "For server / public deploys, set the <code>NETWATCHAI_PASSWORD</code> environment variable. "
        "It overrides any password set in the UI."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Threat Intelligence</h3></div>""", unsafe_allow_html=True)
    st.caption(
        "NetWatchAI checks every source IP against free threat-intel feeds. "
        "Matches are automatically flagged as 'Known Malicious' in the dashboard. "
        "Feeds refresh once a day."
    )

    _ti_stats = threat_intel.stats(_ti_iocs)
    _ti_meta = threat_intel.last_updated()
    for _fid, _feed in threat_intel.FEEDS.items():
        _count = _ti_stats.get(_fid, 0)
        _last = _ti_meta.get(_fid, {}).get("updated_at", 0)
        _last_txt = (
            datetime.fromtimestamp(_last).strftime("%Y-%m-%d %H:%M")
            if _last else "not yet downloaded"
        )
        _dot_color = "#10b981" if _count > 0 else "#71717a"
        st.markdown(
            f"""<div class="ni-card" style="display:flex;justify-content:space-between;align-items:center;">
                <div>
                    <div class="ni-lbl">{_fid.replace('_', ' ').title()}</div>
                    <div style="color:#a1a1aa;font-size:0.82rem;margin-top:0.1rem;">
                        {_feed['description']}
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="color:{_dot_color};font-weight:600;font-size:1rem;">
                        {_count:,} indicators
                    </div>
                    <div style="color:#71717a;font-size:0.72rem;">
                        Last updated: {_last_txt}
                    </div>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

    if st.button("Refresh feeds now", key="ti_refresh_btn"):
        with st.spinner("Downloading threat-intel feeds..."):
            _result = threat_intel.refresh_if_stale(force=True)
            _load_threat_intel.clear()  # bust the streamlit cache
            storage.log_audit("user", "ti_refresh", ", ".join(
                f"{k}={v['status']}" for k, v in _result.items()
            ))
        ok = sum(1 for v in _result.values() if v["status"] == "refreshed")
        failed = sum(1 for v in _result.values() if v["status"] == "failed")
        if failed:
            st.warning(f"{ok} feed(s) refreshed, {failed} failed. Check your internet connection.")
        else:
            st.success(f"{ok} feed(s) refreshed successfully.")

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Audit Log</h3></div>""", unsafe_allow_html=True)
    st.caption(
        "Tamper-evident — every row is SHA-256-chained to the previous one. "
        "Use the verify button to prove the log hasn't been edited."
    )
    av1, av2 = st.columns([1, 3])
    with av1:
        if st.button("Verify chain integrity", key="audit_verify_btn"):
            st.session_state["audit_verify_result"] = storage.verify_audit_chain()
    with av2:
        _v = st.session_state.get("audit_verify_result")
        if _v is None:
            st.caption("_Not yet verified this session._")
        elif _v["ok"]:
            st.success(f"Chain intact ({_v['total']} rows).")
        else:
            st.error(
                f"Tampering detected at row id={_v['first_broken_id']} ({_v.get('reason','?')}). "
                f"Total rows: {_v['total']}."
            )

    audit_rows = _cached_list_audit(limit=50)
    if audit_rows:
        audit_df = pd.DataFrame(audit_rows)[["ts", "actor", "action", "detail"]]
        st.dataframe(audit_df, use_container_width=True, hide_index=True, height=280)
    else:
        st.caption("No audit events recorded yet.")

    st.markdown("---")
    st.markdown("""<div class="sec-h"><h3>Export</h3></div>""", unsafe_allow_html=True)
    col_e1, col_e2 = st.columns(2)
    with col_e1:
        if st.button("Download alerts as JSON", use_container_width=True):
            alerts_json = json.dumps(storage.list_alerts(days=365, include_fp=True), indent=2)
            st.download_button(
                "Save JSON",
                data=alerts_json,
                file_name=f"netwatchai_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )
    with col_e2:
        if st.button("Download alerts as CSV", use_container_width=True):
            alerts_df = pd.DataFrame(storage.list_alerts(days=365, include_fp=True))
            st.download_button(
                "Save CSV",
                data=alerts_df.to_csv(index=False) if not alerts_df.empty else "",
                file_name=f"netwatchai_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

st.markdown('<div class="app-footer">NetWatchAI <span class="dot"></span> Network Monitoring and Intrusion Detection</div>', unsafe_allow_html=True)
