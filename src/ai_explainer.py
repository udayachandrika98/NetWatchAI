"""AI-powered per-alert explainer using the Claude API.

Takes an alert row from the storage layer and returns a short, plain-English
explanation of what the alert likely means and what the operator should check.
Results are cached in SQLite keyed by alert_id, so every refresh of the
dashboard does not re-bill the API.
"""
from __future__ import annotations

import os
from typing import Any

from src import storage

MODEL = "claude-opus-4-7"

SYSTEM_PROMPT = """You are NetWatchAI's per-alert security explainer.

For each network alert, write a short markdown response with three sections:

**What this likely is** — one or two sentences in plain English. Skip the jargon.
**Why it was flagged** — point to the specific packet fields that matter (port, flags, size, protocol).
**What to check next** — two or three concrete steps the operator can take in under five minutes.

Constraints:
- Keep the whole response under 180 words.
- Be honest about uncertainty: alerts in an unsupervised IDS often have benign explanations.
- Do not invent threat-intel context that wasn't given to you.
- Do not start with "Here is" or "Based on" — go straight into the analysis."""


def is_configured() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _format_alert(alert: dict[str, Any]) -> str:
    fields = [
        ("Attack type", alert.get("attack_type")),
        ("Source IP", alert.get("src_ip")),
        ("Destination IP", alert.get("dst_ip")),
        ("Protocol", alert.get("protocol")),
        ("Source port", alert.get("src_port")),
        ("Destination port", alert.get("dst_port")),
        ("Packet size", f"{alert.get('packet_size')} bytes" if alert.get("packet_size") else None),
        ("TCP flags", alert.get("flags")),
        ("Detected at", alert.get("ts")),
    ]
    return "\n".join(f"- {k}: {v}" for k, v in fields if v not in (None, ""))


def explain(alert: dict[str, Any], use_cache: bool = True) -> dict[str, str]:
    """Return `{explanation, model, source}` for an alert or packet row.

    Reads from SQLite cache when available (only for rows with a DB `id`);
    otherwise calls Claude and persists the result. Caller should check
    is_configured() before invoking.
    """
    alert_id = alert.get("id")
    if use_cache and isinstance(alert_id, int):
        cached = storage.get_explanation(alert_id)
        if cached:
            return {
                "explanation": cached["explanation"],
                "model": cached["model"] or MODEL,
                "source": "cache",
            }

    import anthropic

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        thinking={"type": "adaptive"},
        output_config={"effort": "medium"},
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[
            {
                "role": "user",
                "content": f"Explain this NetWatchAI alert:\n\n{_format_alert(alert)}",
            }
        ],
    )

    text = next((b.text for b in response.content if b.type == "text"), "").strip()
    if not text:
        text = "_(Claude returned an empty response — try again.)_"

    if isinstance(alert_id, int):
        storage.save_explanation(alert_id, text, response.model)

    return {"explanation": text, "model": response.model, "source": "live"}
