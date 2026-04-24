"""Dispatch alerts to Discord, Slack, and email — all free."""
import json
import smtplib
from email.mime.text import MIMEText
from urllib.error import URLError
from urllib.request import Request, urlopen

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _meets_severity(current: str, min_sev: str) -> bool:
    return SEVERITY_RANK.get(current, 0) >= SEVERITY_RANK.get(min_sev, 2)


def severity_from_pct(anomaly_pct: float) -> str:
    if anomaly_pct < 5:
        return "low"
    if anomaly_pct < 15:
        return "medium"
    if anomaly_pct < 30:
        return "high"
    return "critical"


def _post_json(url: str, payload: dict, timeout: int = 5) -> bool:
    try:
        req = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except (URLError, OSError, ValueError):
        return False


def send_discord(webhook_url: str, title: str, description: str) -> bool:
    if not webhook_url:
        return False
    return _post_json(webhook_url, {
        "embeds": [{"title": title, "description": description, "color": 15548997}],
    })


def send_slack(webhook_url: str, title: str, description: str) -> bool:
    if not webhook_url:
        return False
    return _post_json(webhook_url, {"text": f"*{title}*\n{description}"})


def send_email(smtp_host: str, smtp_port: int, username: str, password: str,
               to_email: str, subject: str, body: str) -> bool:
    if not (smtp_host and username and password and to_email):
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = username
    msg["To"] = to_email
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.starttls()
            s.login(username, password)
            s.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError):
        return False


def dispatch(cfg: dict, title: str, body: str, severity: str = "high") -> dict:
    """Send to all configured channels. Returns a per-channel success map."""
    alerts_cfg = cfg.get("alerts", {})
    if not _meets_severity(severity, alerts_cfg.get("min_severity", "high")):
        return {"skipped": True, "reason": "below min_severity"}

    results = {}
    if alerts_cfg.get("discord_webhook"):
        results["discord"] = send_discord(alerts_cfg["discord_webhook"], title, body)
    if alerts_cfg.get("slack_webhook"):
        results["slack"] = send_slack(alerts_cfg["slack_webhook"], title, body)

    email_cfg = alerts_cfg.get("email", {})
    if email_cfg.get("to"):
        results["email"] = send_email(
            email_cfg.get("smtp_host", ""),
            int(email_cfg.get("smtp_port", 587)),
            email_cfg.get("username", ""),
            email_cfg.get("password", ""),
            email_cfg["to"],
            subject=title,
            body=body,
        )
    return results
