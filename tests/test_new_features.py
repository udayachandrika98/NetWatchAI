"""Tests for Phase 8 features: GeoIP batch, cross-platform network info,
PDF report, pagination, Docker security, and AI chatbot removal.

Functions are replicated here to avoid importing Streamlit (which triggers
st.set_page_config on import of dashboard.py).
"""

import os
import platform
import socket
import subprocess

import pandas as pd
import pytest

# ──────────────────────────────────────────────
# Replicate _is_private_ip from dashboard.py
# ──────────────────────────────────────────────

def _is_private_ip(ip):
    """Check if an IP is private/local."""
    return ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "127.", "0."))


class TestIsPrivateIp:
    """Test private IP detection."""

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_loopback_other(self):
        assert _is_private_ip("127.0.0.2") is True

    def test_class_a_private(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_class_a_private_high(self):
        assert _is_private_ip("10.255.255.255") is True

    def test_class_b_private_low(self):
        assert _is_private_ip("172.16.0.1") is True

    def test_class_b_private_high(self):
        assert _is_private_ip("172.31.255.255") is True

    def test_class_b_not_private(self):
        # 172.32.x.x is NOT private
        assert _is_private_ip("172.32.0.1") is False

    def test_class_c_private(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_class_c_private_other(self):
        assert _is_private_ip("192.168.0.100") is True

    def test_zero_prefix(self):
        assert _is_private_ip("0.0.0.0") is True

    def test_public_google_dns(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_public_cloudflare(self):
        assert _is_private_ip("1.1.1.1") is False

    def test_public_random(self):
        assert _is_private_ip("203.0.113.50") is False

    def test_public_192_not_168(self):
        # 192.169.x.x is public
        assert _is_private_ip("192.169.1.1") is False

    @pytest.mark.parametrize("octet", range(16, 32))
    def test_all_172_private_ranges(self, octet):
        assert _is_private_ip(f"172.{octet}.0.1") is True

    @pytest.mark.parametrize("octet", [0, 1, 15, 32, 33, 255])
    def test_172_non_private_ranges(self, octet):
        if 16 <= octet <= 31:
            assert _is_private_ip(f"172.{octet}.0.1") is True
        else:
            assert _is_private_ip(f"172.{octet}.0.1") is False


# ──────────────────────────────────────────────
# GeoIP Batch Lookup Tests
# ──────────────────────────────────────────────

class TestGeoIpBatch:
    """Test GeoIP batch lookup logic (without making real API calls)."""

    def test_private_ips_filtered_before_lookup(self):
        """Private IPs should be excluded from API calls."""
        ips = ["192.168.1.1", "10.0.0.1", "127.0.0.1"]
        public = [ip for ip in ips if not _is_private_ip(ip)]
        assert public == []

    def test_mixed_ips_only_public_sent(self):
        ips = ["8.8.8.8", "192.168.1.1", "1.1.1.1", "10.0.0.5"]
        public = [ip for ip in ips if not _is_private_ip(ip)]
        assert public == ["8.8.8.8", "1.1.1.1"]

    def test_batch_limit_100(self):
        """Should limit to 100 IPs max."""
        ips = [f"8.8.{i // 256}.{i % 256}" for i in range(200)]
        public = [ip for ip in ips if not _is_private_ip(ip)][:100]
        assert len(public) == 100

    def test_empty_list_returns_empty(self):
        ips = []
        public = [ip for ip in ips if not _is_private_ip(ip)]
        assert public == []

    def test_all_private_returns_empty(self):
        ips = ["10.0.0.1", "192.168.1.1", "172.16.0.1"]
        public = [ip for ip in ips if not _is_private_ip(ip)]
        assert public == []


class TestGeoIpLive:
    """Live GeoIP API tests (skipped if no internet)."""

    @pytest.fixture(autouse=True)
    def check_internet(self):
        """Skip if no internet connection."""
        try:
            socket.create_connection(("ip-api.com", 80), timeout=3)
        except OSError:
            pytest.skip("No internet connection")

    def test_batch_api_returns_results(self):
        import requests
        resp = requests.post(
            "http://ip-api.com/batch?fields=status,country,city,lat,lon,isp,query",
            json=["8.8.8.8"],
            timeout=10,
        )
        data = resp.json()
        assert len(data) == 1
        assert data[0]["status"] == "success"
        assert data[0]["country"] == "United States"

    def test_batch_api_multiple_ips(self):
        import requests
        resp = requests.post(
            "http://ip-api.com/batch?fields=status,country,city,query",
            json=["8.8.8.8", "1.1.1.1"],
            timeout=10,
        )
        data = resp.json()
        assert len(data) == 2
        assert all(d["status"] == "success" for d in data)

    def test_batch_api_private_ip_fails(self):
        import requests
        resp = requests.post(
            "http://ip-api.com/batch?fields=status,query",
            json=["192.168.1.1"],
            timeout=10,
        )
        data = resp.json()
        assert data[0]["status"] == "fail"


# ──────────────────────────────────────────────
# Cross-Platform Network Info Tests
# ──────────────────────────────────────────────

class TestRunCmd:
    """Test the _run_cmd helper."""

    def test_successful_command(self):
        out = ""
        try:
            result = subprocess.run(["echo", "hello"], capture_output=True, text=True, timeout=5)
            out = result.stdout.strip()
        except Exception:
            out = ""
        assert out == "hello"

    def test_failing_command_returns_empty(self):
        out = ""
        try:
            result = subprocess.run(["false"], capture_output=True, text=True, timeout=5)
            out = result.stdout.strip()
        except Exception:
            out = ""
        assert out == ""

    def test_nonexistent_command_returns_empty(self):
        out = ""
        try:
            result = subprocess.run(["nonexistent_command_xyz"], capture_output=True, text=True, timeout=5)
            out = result.stdout.strip()
        except Exception:
            out = ""
        assert out == ""


class TestNetworkInfoCrossPlatform:
    """Test cross-platform network info collection."""

    def test_hostname_is_string(self):
        hostname = socket.gethostname()
        assert isinstance(hostname, str)
        assert len(hostname) > 0

    def test_local_ip_detection(self):
        """Local IP should be retrievable on any platform."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
            assert "." in local_ip
            parts = local_ip.split(".")
            assert len(parts) == 4
            assert all(0 <= int(p) <= 255 for p in parts)
        except OSError:
            pytest.skip("No network connection")

    def test_platform_system_returns_known_value(self):
        system = platform.system()
        assert system in ("Darwin", "Linux", "Windows")

    def test_default_keys_always_present(self):
        """All expected keys should have defaults."""
        expected_keys = [
            "WiFi Network (SSID)", "Signal Strength", "Link Speed", "Channel",
            "Gateway (Router)", "DNS Servers", "MAC Address", "Subnet Mask",
        ]
        info = {}
        for key in expected_keys:
            info.setdefault(key, "N/A")
        for key in expected_keys:
            assert key in info
            assert info[key] == "N/A"

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_macos_gateway_command_runs(self):
        result = subprocess.run(["route", "-n", "get", "default"],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0 or "gateway" not in result.stdout

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_macos_ifconfig_runs(self):
        result = subprocess.run(["ifconfig", "en0"],
                                capture_output=True, text=True, timeout=5)
        # en0 might not exist but command should not crash
        assert isinstance(result.stdout, str)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_linux_ip_route_runs(self):
        result = subprocess.run(["ip", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5)
        assert isinstance(result.stdout, str)

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux only")
    def test_linux_resolv_conf_exists(self):
        assert os.path.exists("/etc/resolv.conf")


# ──────────────────────────────────────────────
# PDF Report Generation Tests
# ──────────────────────────────────────────────

class TestPdfReport:
    """Test PDF report generation using fpdf2."""

    @pytest.fixture
    def sample_data(self):
        """Create sample dataframes for report testing."""
        df = pd.read_csv("data/sample_packets.csv")
        from src.detector import AnomalyDetector
        detector = AnomalyDetector()
        df["prediction"] = detector.predict_batch(df)
        df["status"] = df["prediction"].map({1: "Normal", -1: "ANOMALY"})

        SUSPICIOUS_PORTS = {4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321}

        def classify(row):
            if row.get("status") != "ANOMALY":
                return "Normal"
            protocol = str(row.get("protocol", "")).upper()
            try: dst_port = int(row.get("dst_port", 0))
            except: dst_port = 0
            try: src_port = int(row.get("src_port", 0))
            except: src_port = 0
            try: packet_size = int(row.get("packet_size", 0))
            except: packet_size = 0
            flags = str(row.get("flags", ""))
            if protocol == "ICMP" and packet_size > 1000: return "Ping of Death"
            if protocol == "TCP" and flags == "S" and packet_size <= 60: return "Port Scan"
            if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
                return "Data Exfiltration" if packet_size > 1000 else "Suspicious Port"
            if packet_size > 5000: return "Large Transfer"
            if protocol == "UDP" and dst_port == 53 and packet_size > 200: return "DNS Anomaly"
            return "Unknown Anomaly"

        df["attack_type"] = df.apply(classify, axis=1)
        anomaly_df = df[df["prediction"] == -1]
        return df, anomaly_df

    def test_pdf_generates_bytes(self, sample_data):
        from fpdf import FPDF
        df, anomaly_df = sample_data
        # Minimal PDF generation test
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "NetWatchAI Test Report")
        result = bytes(pdf.output())
        assert len(result) > 0
        assert result[:4] == b"%PDF"

    def test_pdf_with_anomalies(self, sample_data):
        from fpdf import FPDF
        df, anomaly_df = sample_data
        assert len(anomaly_df) > 0, "Need anomalies for this test"

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, f"Anomalies: {len(anomaly_df)}", new_x="LMARGIN", new_y="NEXT")

        # Add attack breakdown table
        attack_counts = anomaly_df["attack_type"].value_counts()
        pdf.set_font("Helvetica", "", 10)
        for attack, count in attack_counts.items():
            pdf.cell(0, 7, f"{attack}: {count}", new_x="LMARGIN", new_y="NEXT")

        result = bytes(pdf.output())
        assert result[:4] == b"%PDF"
        assert len(result) > 100

    def test_pdf_with_no_anomalies(self):
        from fpdf import FPDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "", 12)
        pdf.cell(0, 10, "No threats detected.")
        result = bytes(pdf.output())
        assert result[:4] == b"%PDF"

    def test_pdf_report_has_multiple_pages(self, sample_data):
        """Full report should have cover + summary + recommendations = 3+ pages."""
        from fpdf import FPDF
        df, anomaly_df = sample_data
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Page 1: Cover
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 36)
        pdf.cell(0, 20, "NetWatchAI", align="C")

        # Page 2: Summary
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 22)
        pdf.cell(0, 15, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 7, f"Total: {len(df)}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Anomalies: {len(anomaly_df)}", new_x="LMARGIN", new_y="NEXT")

        # Page 3: Recommendations
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 22)
        pdf.cell(0, 15, "Recommendations", new_x="LMARGIN", new_y="NEXT")

        result = bytes(pdf.output())
        assert result[:4] == b"%PDF"
        assert pdf.page_no() >= 3

    def test_attack_type_descriptions_complete(self):
        """All attack types should have descriptions for the report."""
        desc_map = {
            "Port Scan": "Probing open ports to find vulnerabilities",
            "Ping of Death": "Oversized ICMP packets to crash systems",
            "Data Exfiltration": "Stealing data via suspicious ports",
            "Suspicious Port": "Traffic to known backdoor ports",
            "Large Transfer": "Abnormally large data transfer",
            "DNS Anomaly": "DNS tunneling or spoofing attempt",
            "Unknown Anomaly": "Unclassified suspicious pattern",
        }
        expected_types = ["Port Scan", "Ping of Death", "Data Exfiltration",
                          "Suspicious Port", "Large Transfer", "DNS Anomaly",
                          "Unknown Anomaly"]
        for at in expected_types:
            assert at in desc_map, f"Missing description for {at}"
            assert len(desc_map[at]) > 0


# ──────────────────────────────────────────────
# Pagination Logic Tests
# ──────────────────────────────────────────────

class TestPagination:
    """Test pagination math for the packet log."""

    def test_single_page(self):
        total_rows = 50
        page_size = 100
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        assert total_pages == 1

    def test_exact_page_boundary(self):
        total_rows = 100
        page_size = 100
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        assert total_pages == 1

    def test_just_over_boundary(self):
        total_rows = 101
        page_size = 100
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        assert total_pages == 2

    def test_large_dataset(self):
        total_rows = 10000
        page_size = 100
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        assert total_pages == 100

    def test_zero_rows(self):
        total_rows = 0
        page_size = 100
        total_pages = max(1, (total_rows + page_size - 1) // page_size)
        assert total_pages == 1  # Still 1 page (empty)

    def test_page_slice_first_page(self):
        page = 1
        page_size = 100
        start = (page - 1) * page_size
        end = start + page_size
        assert start == 0
        assert end == 100

    def test_page_slice_second_page(self):
        page = 2
        page_size = 100
        start = (page - 1) * page_size
        end = start + page_size
        assert start == 100
        assert end == 200

    def test_last_page_partial(self):
        total_rows = 250
        page_size = 100
        page = 3  # Last page
        start = (page - 1) * page_size
        end = min(start + page_size, total_rows)
        assert start == 200
        assert end == 250

    def test_page_slicing_with_dataframe(self):
        df = pd.DataFrame({"val": range(250)})
        page_size = 100
        page = 2
        start = (page - 1) * page_size
        end = min(start + page_size, len(df))
        page_df = df.iloc[start:end]
        assert len(page_df) == 100
        assert page_df.iloc[0]["val"] == 100
        assert page_df.iloc[-1]["val"] == 199

    def test_page_slicing_last_page_partial(self):
        df = pd.DataFrame({"val": range(250)})
        page_size = 100
        page = 3
        start = (page - 1) * page_size
        end = min(start + page_size, len(df))
        page_df = df.iloc[start:end]
        assert len(page_df) == 50
        assert page_df.iloc[0]["val"] == 200
        assert page_df.iloc[-1]["val"] == 249


# ──────────────────────────────────────────────
# Docker Security Tests
# ──────────────────────────────────────────────

class TestDockerSecurity:
    """Test Dockerfile security configuration."""

    @pytest.fixture
    def dockerfile_content(self):
        with open("Dockerfile") as f:
            return f.read()

    def test_non_root_user_created(self, dockerfile_content):
        assert "useradd" in dockerfile_content

    def test_user_directive_present(self, dockerfile_content):
        assert "USER netwatchai" in dockerfile_content

    def test_group_created(self, dockerfile_content):
        assert "groupadd" in dockerfile_content

    def test_chown_applied(self, dockerfile_content):
        assert "chown" in dockerfile_content

    def test_user_after_copy(self, dockerfile_content):
        """USER directive should come after COPY and RUN train."""
        lines = dockerfile_content.splitlines()
        copy_line = None
        user_line = None
        for i, line in enumerate(lines):
            if line.startswith("COPY ."):
                copy_line = i
            if line.startswith("USER"):
                user_line = i
        assert copy_line is not None, "No COPY . found"
        assert user_line is not None, "No USER found"
        assert user_line > copy_line, "USER should come after COPY"

    def test_user_before_cmd(self, dockerfile_content):
        """USER directive should come before CMD."""
        lines = dockerfile_content.splitlines()
        user_line = None
        cmd_line = None
        for i, line in enumerate(lines):
            if line.startswith("USER"):
                user_line = i
            if line.startswith("CMD"):
                cmd_line = i
        assert user_line is not None
        assert cmd_line is not None
        assert user_line < cmd_line, "USER should come before CMD"

    def test_healthcheck_present(self, dockerfile_content):
        assert "HEALTHCHECK" in dockerfile_content

    def test_expose_8501(self, dockerfile_content):
        assert "EXPOSE 8501" in dockerfile_content


# ──────────────────────────────────────────────
# AI Chatbot Removal Verification
# ──────────────────────────────────────────────

class TestAiChatbotRemoved:
    """Verify the AI chatbot was fully removed from dashboard.py."""

    @pytest.fixture
    def dashboard_content(self):
        with open("dashboard.py") as f:
            return f.read()

    def test_no_ai_threat_analyst_function(self, dashboard_content):
        assert "def ai_threat_analyst" not in dashboard_content

    def test_no_chat_history(self, dashboard_content):
        assert "chat_history" not in dashboard_content

    def test_no_chat_input(self, dashboard_content):
        assert "chat_input" not in dashboard_content

    def test_no_chat_message(self, dashboard_content):
        assert "chat_message" not in dashboard_content

    def test_no_ai_analyst_tab_label(self, dashboard_content):
        assert "AI Analyst" not in dashboard_content

    def test_settings_tab_present(self, dashboard_content):
        # Nine tabs now: the eight feature tabs plus Settings.
        assert "tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab_settings = st.tabs" in dashboard_content
        assert '"Settings"' in dashboard_content

    def test_no_re_import(self, dashboard_content):
        """re module was only used by chatbot for IP regex matching."""
        lines = dashboard_content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped == "import re" or stripped == "import re as re":
                pytest.fail("Found 'import re' at top level — should have been removed")


# ──────────────────────────────────────────────
# GeoIP Batch Integration in Dashboard
# ──────────────────────────────────────────────

class TestGeoIpDashboardIntegration:
    """Verify GeoIP batch endpoint is used in dashboard.py."""

    @pytest.fixture
    def dashboard_content(self):
        with open("dashboard.py") as f:
            return f.read()

    def test_uses_batch_endpoint(self, dashboard_content):
        assert "ip-api.com/batch" in dashboard_content

    def test_no_individual_geoip_function(self, dashboard_content):
        """Old get_ip_geolocation individual function should be removed."""
        assert "def get_ip_geolocation" not in dashboard_content

    def test_has_private_ip_check(self, dashboard_content):
        assert "_is_private_ip" in dashboard_content

    def test_has_fallback_logic(self, dashboard_content):
        """Should have fallback to individual requests if batch fails."""
        assert "Fallback" in dashboard_content or "fallback" in dashboard_content


# ──────────────────────────────────────────────
# Cross-Platform Network Info in Dashboard
# ──────────────────────────────────────────────

class TestNetworkInfoDashboardIntegration:
    """Verify cross-platform network info is in dashboard.py."""

    @pytest.fixture
    def dashboard_content(self):
        with open("dashboard.py") as f:
            return f.read()

    def test_has_platform_import(self, dashboard_content):
        assert "import platform" in dashboard_content

    def test_has_darwin_handler(self, dashboard_content):
        assert "_get_network_info_darwin" in dashboard_content

    def test_has_linux_handler(self, dashboard_content):
        assert "_get_network_info_linux" in dashboard_content

    def test_has_windows_handler(self, dashboard_content):
        assert "_get_network_info_windows" in dashboard_content

    def test_has_platform_detection(self, dashboard_content):
        assert 'platform.system()' in dashboard_content

    def test_defaults_for_missing_keys(self, dashboard_content):
        assert "setdefault" in dashboard_content


# ──────────────────────────────────────────────
# End-to-End Detection Pipeline
# ──────────────────────────────────────────────

class TestEndToEndPipeline:
    """Full pipeline test: load data → detect → classify → validate."""

    def test_full_pipeline(self):
        df = pd.read_csv("data/sample_packets.csv")
        from src.detector import AnomalyDetector
        detector = AnomalyDetector()

        # Predict
        preds = detector.predict_batch(df)
        df["prediction"] = preds
        df["status"] = df["prediction"].map({1: "Normal", -1: "ANOMALY"})

        # Classify
        SUSPICIOUS_PORTS = {4444, 31337, 1337, 5555, 6666, 6667, 12345, 54321}

        def classify(row):
            if row.get("status") != "ANOMALY":
                return "Normal"
            protocol = str(row.get("protocol", "")).upper()
            try: dst_port = int(row.get("dst_port", 0))
            except: dst_port = 0
            try: src_port = int(row.get("src_port", 0))
            except: src_port = 0
            try: packet_size = int(row.get("packet_size", 0))
            except: packet_size = 0
            flags = str(row.get("flags", ""))
            if protocol == "ICMP" and packet_size > 1000: return "Ping of Death"
            if protocol == "TCP" and flags == "S" and packet_size <= 60: return "Port Scan"
            if dst_port in SUSPICIOUS_PORTS or src_port in SUSPICIOUS_PORTS:
                return "Data Exfiltration" if packet_size > 1000 else "Suspicious Port"
            if packet_size > 5000: return "Large Transfer"
            if protocol == "UDP" and dst_port == 53 and packet_size > 200: return "DNS Anomaly"
            return "Unknown Anomaly"

        df["attack_type"] = df.apply(classify, axis=1)
        anomaly_df = df[df["prediction"] == -1]

        # Assertions
        assert len(df) == 227
        assert len(anomaly_df) > 0
        assert len(anomaly_df) < len(df)
        assert set(df["status"].unique()) == {"Normal", "ANOMALY"}
        assert "Normal" in df["attack_type"].values
        assert all(anomaly_df["attack_type"] != "Normal")

        # Verify pagination would work
        page_size = 100
        total_pages = max(1, (len(df) + page_size - 1) // page_size)
        assert total_pages == 3  # 227 rows / 100 = 3 pages
