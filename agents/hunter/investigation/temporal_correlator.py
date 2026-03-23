"""
Temporal Correlator – L1 investigation thread.

Queries ClickHouse triage_scores for related alerts in the investigation
window and derives 4 feature-vector dimensions:
  [temporal_escalation_count, temporal_unique_categories,
   temporal_tactic_diversity, temporal_mean_score]
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

from config import (
    CLICKHOUSE_DATABASE,
    INVESTIGATION_WINDOW_MIN,
)
from models import TemporalResult

log = logging.getLogger(__name__)


async def run(
    payload: Dict[str, Any],
    ch_client: Any,
) -> TemporalResult:
    """
    Async wrapper – runs the blocking ClickHouse queries in a thread pool
    so they don't block the event loop.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query, payload, ch_client)


def _query(payload: Dict[str, Any], ch_client: Any) -> TemporalResult:
    hostname: str = payload.get("hostname", "")
    source_ip: str = payload.get("source_ip", "")
    user_id: str = payload.get("user_id", "")

    result = TemporalResult()

    try:
        # ---------------------------------------------------------------
        # Q1 – Count escalating alerts in the window (higher score
        #       than the triggering alert's adjusted_score)
        # ---------------------------------------------------------------
        trigger_score: float = float(payload.get("adjusted_score", 0.0))
        q1 = f"""
            SELECT count() AS escalation_count
            FROM {CLICKHOUSE_DATABASE}.triage_scores
            WHERE hostname = '{_s(hostname)}'
              AND source_ip = '{_s(source_ip)}'
              AND adjusted_score > {trigger_score:.4f}
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
        """
        rows = ch_client.query(q1).result_rows
        result.escalation_count = int(rows[0][0]) if rows else 0

        # ---------------------------------------------------------------
        # Q2 – Count distinct rule categories in the window
        # ---------------------------------------------------------------
        q2 = f"""
            SELECT
                countDistinct(source_type) AS unique_categories,
                countDistinct(mitre_tactic) AS tactic_diversity,
                avg(adjusted_score) AS mean_score
            FROM {CLICKHOUSE_DATABASE}.triage_scores
            WHERE hostname = '{_s(hostname)}'
              AND (source_ip = '{_s(source_ip)}' OR user_id = '{_s(user_id)}')
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
        """
        rows = ch_client.query(q2).result_rows
        if rows:
            result.unique_categories = int(rows[0][0] or 0)
            result.tactic_diversity = int(rows[0][1] or 0)
            result.mean_score = float(rows[0][2] or 0.0)

        # ---------------------------------------------------------------
        # Q3 – Collect related alert IDs
        # ---------------------------------------------------------------
        q3 = f"""
            SELECT toString(event_id)
            FROM {CLICKHOUSE_DATABASE}.triage_scores
            WHERE hostname = '{_s(hostname)}'
              AND (source_ip = '{_s(source_ip)}' OR user_id = '{_s(user_id)}')
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
            LIMIT 50
        """
        rows = ch_client.query(q3).result_rows
        result.related_alert_ids = [str(r[0]) for r in rows if r[0]]

    except Exception as exc:  # noqa: BLE001
        log.warning("TemporalCorrelator failed for %s/%s: %s", hostname, source_ip, exc)

    return result


def _s(value: str) -> str:
    """Minimal SQL-injection sanitiser."""
    import re
    return re.sub(r"[';\"\\]", "", str(value))
