"""
Campaign Detector – L2 investigation thread.

Looks for coordinated multi-host / multi-tactic activity by joining
`triage_scores` with `network_events`.

Fires when:
  - ≥ 3 network events AND ≥ 2 distinct hosts AND ≥ 2 distinct tactics
    are associated to the same source entity in the investigation window.

Feature dims produced (2):
  [campaign_host_count, campaign_tactic_count]
"""
from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from config import CLICKHOUSE_DATABASE, INVESTIGATION_WINDOW_MIN
from models import CampaignResult

log = logging.getLogger(__name__)


async def run(
    payload: Dict[str, Any],
    ch_client: Any,
) -> CampaignResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query, payload, ch_client)


def _query(payload: Dict[str, Any], ch_client: Any) -> CampaignResult:
    source_ip = _s(payload.get("source_ip", ""))
    user_id = _s(payload.get("user_id", ""))

    result = CampaignResult()

    try:
        # -------------------------------------------------------------------
        # Campaign detection: multi-host, multi-tactic activity
        # Query triage_scores directly — the old query joined on
        # network_events which excluded security-event-only entities.
        # -------------------------------------------------------------------
        q = f"""
            SELECT
                countDistinct(hostname) AS host_count,
                countDistinct(mitre_tactic) AS tactic_count
            FROM {CLICKHOUSE_DATABASE}.triage_scores
            WHERE source_ip = '{source_ip}'
              AND adjusted_score >= 0.70
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
        """
        rows = ch_client.query(q).result_rows

        if rows:
            host_count = int(rows[0][0] or 0)
            tactic_count = int(rows[0][1] or 0)
            result.host_count = host_count
            result.tactic_count = tactic_count
            result.is_campaign = host_count >= 2 and tactic_count >= 2

        # -------------------------------------------------------------------
        # Collect related host IDs (for evidence / narrative)
        # -------------------------------------------------------------------
        if result.is_campaign:
            q2 = f"""
                SELECT DISTINCT toString(t.hostname)
                FROM {CLICKHOUSE_DATABASE}.triage_scores t
                WHERE t.source_ip = '{source_ip}'
                  AND t.timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
                LIMIT 20
            """
            rows2 = ch_client.query(q2).result_rows
            result.related_host_ids = [str(r[0]) for r in rows2 if r[0]]
            # Generate a deterministic campaign_id from (source_ip, window)
            result.campaign_id = str(
                uuid.uuid5(uuid.NAMESPACE_DNS, f"{source_ip}_{INVESTIGATION_WINDOW_MIN}")
            )

    except Exception as exc:  # noqa: BLE001
        log.warning("CampaignDetector failed for source_ip=%s: %s", source_ip, exc)

    return result


def _s(value: Any) -> str:
    return re.sub(r"[';\"\\]", "", str(value))
