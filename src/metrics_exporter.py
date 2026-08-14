"""Prometheus exporter for NetWatchAI.

Reads the SQLite alert store on each scrape and exposes gauges that Grafana
can graph. Run standalone: ``python -m src.metrics_exporter`` (port 9100).
"""
from __future__ import annotations

import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta

from prometheus_client import REGISTRY, start_http_server
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector

from src.storage import DB_PATH

PORT = int(os.environ.get("NETWATCHAI_METRICS_PORT", "9100"))


class NetWatchCollector(Collector):
    # Cache scrape results for SCRAPE_CACHE_SECONDS to absorb high-frequency Prometheus
    # scrapes (or multiple federated scrapes from the same DB) without hammering SQLite.
    SCRAPE_CACHE_SECONDS = 10

    def __init__(self) -> None:
        self._cached_at: float = 0.0
        self._cached_families: list = []

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        if not os.path.exists(DB_PATH):
            return []
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            return list(conn.execute(sql, params))
        finally:
            conn.close()

    def collect(self):
        now = time.monotonic()
        if self._cached_families and (now - self._cached_at) < self.SCRAPE_CACHE_SECONDS:
            yield from self._cached_families
            return
        families = list(self._collect_fresh())
        self._cached_families = families
        self._cached_at = now
        yield from families

    def _collect_fresh(self):
        db_up = GaugeMetricFamily(
            "netwatchai_db_up", "1 if the SQLite alert store is reachable"
        )
        db_up.add_metric([], 1.0 if os.path.exists(DB_PATH) else 0.0)
        yield db_up

        if not os.path.exists(DB_PATH):
            return

        by_type = GaugeMetricFamily(
            "netwatchai_alerts_total",
            "Total alerts recorded, partitioned by attack type",
            labels=["attack_type"],
        )
        for row in self._query(
            "SELECT attack_type, COUNT(*) AS n FROM alerts "
            "WHERE marked_fp = 0 GROUP BY attack_type"
        ):
            by_type.add_metric([row["attack_type"]], row["n"])
        yield by_type

        cutoff = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
        last_24 = GaugeMetricFamily(
            "netwatchai_alerts_last_24h",
            "Alerts in the last 24 hours, partitioned by attack type",
            labels=["attack_type"],
        )
        for row in self._query(
            "SELECT attack_type, COUNT(*) AS n FROM alerts "
            "WHERE ts >= ? AND marked_fp = 0 GROUP BY attack_type",
            (cutoff,),
        ):
            last_24.add_metric([row["attack_type"]], row["n"])
        yield last_24

        open_alerts = GaugeMetricFamily(
            "netwatchai_alerts_open", "Alerts with status='new'"
        )
        rows = self._query(
            "SELECT COUNT(*) AS n FROM alerts WHERE status='new' AND marked_fp = 0"
        )
        open_alerts.add_metric([], rows[0]["n"] if rows else 0)
        yield open_alerts

        fp = GaugeMetricFamily(
            "netwatchai_alerts_false_positive_total",
            "Alerts marked as false positive",
        )
        rows = self._query("SELECT COUNT(*) AS n FROM alerts WHERE marked_fp = 1")
        fp.add_metric([], rows[0]["n"] if rows else 0)
        yield fp

        allowlist = GaugeMetricFamily(
            "netwatchai_allowlist_size", "Number of IPs on the allowlist"
        )
        rows = self._query("SELECT COUNT(*) AS n FROM allowlist")
        allowlist.add_metric([], rows[0]["n"] if rows else 0)
        yield allowlist

        top_src = GaugeMetricFamily(
            "netwatchai_top_src_ip_alerts_24h",
            "Alert count per source IP over the last 24h (top 10)",
            labels=["src_ip"],
        )
        for row in self._query(
            "SELECT src_ip, COUNT(*) AS n FROM alerts "
            "WHERE ts >= ? AND marked_fp = 0 "
            "GROUP BY src_ip ORDER BY n DESC LIMIT 10",
            (cutoff,),
        ):
            top_src.add_metric([row["src_ip"]], row["n"])
        yield top_src


def main() -> None:
    REGISTRY.register(NetWatchCollector())
    start_http_server(PORT)
    print(f"NetWatchAI metrics exporter listening on :{PORT}/metrics")
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
