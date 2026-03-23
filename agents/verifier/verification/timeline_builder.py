"""
Timeline Builder — reconstruct a chronological event timeline for the entity
being investigated.  Queries raw_logs, triage_scores, and
hunter_investigations.

Read-only — no writes to any table.
"""
from __future__ import annotations

import asyncio
import json
import logging
from functools import partial
from typing import Any

from models import TimelineResult
from utils import sanitize_sql

log = logging.getLogger(__name__)


async def build(
    ch: Any,
    payload: dict,
    window_hours: int = 24,
) -> TimelineResult:
    """
    Build a chronological event timeline for the entity.

    Args:
        ch: clickhouse-connect client.
        payload: Hunter verdict dict.
        window_hours: hours to look back from the event.

    Returns:
        TimelineResult with assembled timeline.
    """
    result = TimelineResult()

    hostname = sanitize_sql(payload.get("hostname", ""))
    source_ip = sanitize_sql(payload.get("source_ip", ""))
    event_ts = sanitize_sql(payload.get("started_at", ""))

    if not event_ts or (not hostname and not source_ip):
        return result

    entity_filter = _entity_filter(hostname, source_ip)
    timeline_entries: list = []

    try:
        # --- Raw logs for the entity ------------------------------------
        raw_query = (
            "SELECT event_id, timestamp, source, "
            "       ip_address, level, message "
            "FROM raw_logs "
            f"WHERE ip_address = '{source_ip}' "
            f"  AND timestamp >= parseDateTimeBestEffort('{event_ts}') "
            f"      - INTERVAL {int(window_hours)} HOUR "
            f"  AND timestamp <= parseDateTimeBestEffort('{event_ts}') "
            "      + INTERVAL 1 HOUR "
            "ORDER BY timestamp ASC "
            "LIMIT 200"
        )
        loop = asyncio.get_event_loop()
        raw_rows = await loop.run_in_executor(None, partial(ch.query, raw_query))
        result.raw_events = len(raw_rows.result_rows)
        for row in raw_rows.result_rows:
            timeline_entries.append({
                "source": "raw_logs",
                "event_id": str(row[0]),
                "timestamp": str(row[1]),
                "source_type": str(row[2]),
                "source_ip": str(row[3]),
                "log_level": str(row[4]),
                "message": str(row[5])[:300],
            })

        # --- Triage scores for the entity --------------------------------
        triage_query = (
            "SELECT event_id, timestamp, source_type, combined_score, "
            "       adjusted_score, action, mitre_tactic "
            "FROM triage_scores "
            f"WHERE {entity_filter} "
            f"  AND timestamp >= parseDateTimeBestEffort('{event_ts}') "
            f"      - INTERVAL {int(window_hours)} HOUR "
            "ORDER BY timestamp ASC "
            "LIMIT 100"
        )
        triage_rows = await loop.run_in_executor(None, partial(ch.query, triage_query))
        result.triage_events = len(triage_rows.result_rows)
        for row in triage_rows.result_rows:
            timeline_entries.append({
                "source": "triage_scores",
                "event_id": str(row[0]),
                "timestamp": str(row[1]),
                "source_type": str(row[2]),
                "combined_score": float(row[3]) if row[3] else 0.0,
                "adjusted_score": float(row[4]) if row[4] else 0.0,
                "action": str(row[5]),
                "mitre_tactic": str(row[6]),
            })

        # --- Prior Hunter investigations for the entity ------------------
        hunter_query = (
            "SELECT alert_id, started_at, severity, finding_type, "
            "       summary, confidence, mitre_tactics, mitre_techniques "
            "FROM hunter_investigations "
            f"WHERE {entity_filter} "
            f"  AND started_at >= parseDateTimeBestEffort('{event_ts}') "
            f"      - INTERVAL {int(window_hours)} HOUR "
            "ORDER BY started_at ASC "
            "LIMIT 50"
        )
        hunter_rows = await loop.run_in_executor(None, partial(ch.query, hunter_query))
        result.hunter_events = len(hunter_rows.result_rows)
        for row in hunter_rows.result_rows:
            timeline_entries.append({
                "source": "hunter_investigations",
                "alert_id": str(row[0]),
                "timestamp": str(row[1]),
                "severity": str(row[2]),
                "finding_type": str(row[3]),
                "summary": str(row[4])[:200],
                "confidence": float(row[5]) if row[5] else 0.0,
            })

        # --- Sort by timestamp and assemble ------------------------------
        timeline_entries.sort(key=lambda e: e.get("timestamp", ""))

        result.event_count = (
            result.raw_events + result.triage_events + result.hunter_events
        )
        result.timeline_json = json.dumps(timeline_entries)

        # --- Check sequence coherence ------------------------------------
        result.sequence_coherent = _check_coherence(timeline_entries)

    except Exception as exc:
        log.error("Timeline build failed: %s", exc)

    return result


def _entity_filter(hostname: str, source_ip: str) -> str:
    """Build a WHERE clause fragment matching hostname OR source_ip."""
    parts = []
    if hostname:
        parts.append(f"hostname = '{hostname}'")
    if source_ip:
        parts.append(f"source_ip = '{source_ip}'")
    if not parts:
        return "1 = 0"
    return f"({' OR '.join(parts)})"


def _check_coherence(entries: list) -> bool:
    """
    Verify timestamps are in monotonically non-decreasing order.
    A few out-of-order entries (≤ 5%) is tolerable due to clock skew.
    """
    if len(entries) < 2:
        return True
    timestamps = [e.get("timestamp", "") for e in entries]
    out_of_order = sum(
        1 for i in range(1, len(timestamps))
        if timestamps[i] < timestamps[i - 1]
    )
    return out_of_order <= max(1, len(timestamps) // 20)
