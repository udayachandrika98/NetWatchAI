"""Free threat-intel feeds: download once/day, match source IPs.

Feeds used (all free, no API key):
    - abuse.ch Feodo Tracker (botnet C2)
    - Spamhaus DROP list (hijacked / malicious networks, CIDR)
    - Tor exit nodes (legitimate but often suspicious)
"""
import ipaddress
import json
import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from src.utils import DATA_DIR

IOC_DIR = os.path.join(DATA_DIR, "threat_intel")
META_PATH = os.path.join(IOC_DIR, "meta.json")
REFRESH_SECONDS = 24 * 3600
FETCH_TIMEOUT = 20

FEEDS = {
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "abuse.ch Feodo Tracker — active botnet command-and-control servers",
        "parser": "ip_list",
    },
    "spamhaus_drop": {
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "description": "Spamhaus DROP — hijacked and malicious network ranges",
        "parser": "cidr_list",
    },
    "tor_exits": {
        "url": "https://check.torproject.org/torbulkexitlist",
        "description": "Tor exit nodes — legitimate but frequently suspicious",
        "parser": "ip_list",
    },
}


def _cache_path(feed_id: str) -> str:
    return os.path.join(IOC_DIR, f"{feed_id}.txt")


def _load_meta() -> dict:
    if not os.path.exists(META_PATH):
        return {}
    try:
        with open(META_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_meta(meta: dict) -> None:
    os.makedirs(IOC_DIR, exist_ok=True)
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)


def _fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "NetWatchAI/0.2"})
    with urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read().decode("utf-8", errors="replace")


def refresh_if_stale(force: bool = False) -> dict:
    """Download any feed whose cache is older than REFRESH_SECONDS.

    Returns {feed_id: {"status": "refreshed|cached|failed", ...}}.
    """
    os.makedirs(IOC_DIR, exist_ok=True)
    results: dict = {}
    meta = _load_meta()
    now = time.time()
    for feed_id, feed in FEEDS.items():
        last = meta.get(feed_id, {}).get("updated_at", 0)
        cached = os.path.exists(_cache_path(feed_id))
        if not force and cached and (now - last) < REFRESH_SECONDS:
            results[feed_id] = {"status": "cached", "last_updated": last}
            continue
        try:
            content = _fetch(feed["url"])
            with open(_cache_path(feed_id), "w") as f:
                f.write(content)
            meta[feed_id] = {"updated_at": now, "url": feed["url"]}
            results[feed_id] = {"status": "refreshed", "last_updated": now}
        except (URLError, OSError, TimeoutError) as e:
            results[feed_id] = {"status": "failed", "error": str(e)}
    _save_meta(meta)
    return results


def _parse_ip_list(text: str) -> set[str]:
    ips: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        try:
            ips.add(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    return ips


def _parse_cidr_list(text: str) -> list:
    nets: list = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        cidr = line.split(";")[0].strip()
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return nets


_PARSERS = {"ip_list": _parse_ip_list, "cidr_list": _parse_cidr_list}


def load_iocs() -> dict:
    """Return {feed_id -> parsed IOCs}. Empty collection for any missing cache."""
    iocs: dict = {}
    for feed_id, feed in FEEDS.items():
        path = _cache_path(feed_id)
        empty: object = set() if feed["parser"] == "ip_list" else []
        if not os.path.exists(path):
            iocs[feed_id] = empty
            continue
        try:
            with open(path) as f:
                text = f.read()
            iocs[feed_id] = _PARSERS[feed["parser"]](text)
        except OSError:
            iocs[feed_id] = empty
    return iocs


def check(ip: str, iocs: dict | None = None) -> list[str]:
    """Return the list of feed IDs that match the given IP (empty = clean)."""
    if not ip:
        return []
    if iocs is None:
        iocs = load_iocs()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return []

    matches: list[str] = []
    for feed_id, feed in FEEDS.items():
        data = iocs.get(feed_id)
        if not data:
            continue
        if feed["parser"] == "ip_list":
            if str(ip_obj) in data:
                matches.append(feed_id)
        else:  # cidr_list
            for net in data:
                if ip_obj in net:
                    matches.append(feed_id)
                    break
    return matches


def stats(iocs: dict | None = None) -> dict:
    """{feed_id: count} for UI display."""
    if iocs is None:
        iocs = load_iocs()
    return {fid: len(iocs.get(fid, [])) for fid in FEEDS}


def last_updated() -> dict:
    """{feed_id: {"updated_at": epoch, "url": ...}} from meta cache."""
    return _load_meta()
