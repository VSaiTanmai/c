"""
Evidence Integrity — verify Merkle-anchored evidence chain for a Hunter verdict.

Queries the ``evidence_anchors`` table in ClickHouse (populated by the Merkle
Service) to confirm that the underlying log data has not been tampered with.

Read-only — no writes to any table.
"""
from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any

from models import EvidenceResult
from utils import sanitize_sql

log = logging.getLogger(__name__)


async def verify(
    ch: Any,
    payload: dict,
    lookback_hours: int = 2,
) -> EvidenceResult:
    """
    Check whether Merkle evidence anchors cover the event's timestamp.

    Args:
        ch: clickhouse-connect client instance.
        payload: Hunter verdict dict (needs ``started_at``, ``hostname``).
        lookback_hours: how many hours around the event to search.

    Returns:
        EvidenceResult with integrity status.
    """
    result = EvidenceResult()

    event_ts = sanitize_sql(payload.get("started_at", ""))
    if not event_ts:
        log.warning("No started_at in payload — skipping evidence check")
        return result

    try:
        # --- Find Merkle batches overlapping the event timestamp -----------
        query = (
            "SELECT batch_id, merkle_root, event_count, "
            "       time_from, time_to, prev_merkle_root, table_name "
            "FROM evidence_anchors "
            f"WHERE time_from <= parseDateTimeBestEffort('{event_ts}') "
            f"      + INTERVAL {int(lookback_hours)} HOUR "
            f"  AND time_to   >= parseDateTimeBestEffort('{event_ts}') "
            f"      - INTERVAL {int(lookback_hours)} HOUR "
            "ORDER BY time_from DESC "
            "LIMIT 10"
        )
        loop = asyncio.get_event_loop()
        rows = await loop.run_in_executor(None, partial(ch.query, query))

        if not rows.result_rows:
            # No batch found — event may be too recent for anchoring
            result.coverage_gap = True
            log.debug("No Merkle batch covers event at %s", event_ts)
            return result

        result.evidence_verified = True
        result.coverage_gap = False
        result.merkle_batch_ids = [str(r[0]) for r in rows.result_rows]

        # --- Verify chain integrity (prev root links) ---------------------
        tables_seen = {str(r[6]) for r in rows.result_rows}
        for table_name in tables_seen:
            safe_table = sanitize_sql(table_name)
            chain_query = (
                "SELECT batch_id, merkle_root, prev_merkle_root "
                "FROM evidence_anchors "
                f"WHERE table_name = '{safe_table}' "
                "ORDER BY time_from DESC "
                "LIMIT 5"
            )
            chain_rows = await loop.run_in_executor(None, partial(ch.query, chain_query))
            if chain_rows.result_rows and len(chain_rows.result_rows) >= 2:
                for i in range(len(chain_rows.result_rows) - 1):
                    current_prev = str(chain_rows.result_rows[i][2])
                    previous_root = str(chain_rows.result_rows[i + 1][1])
                    if current_prev and current_prev != previous_root:
                        result.chain_intact = False
                        log.warning(
                            "Merkle chain break in table %s: "
                            "batch %s prev_root != batch %s root",
                            safe_table,
                            chain_rows.result_rows[i][0],
                            chain_rows.result_rows[i + 1][0],
                        )
                        break

    except Exception as exc:
        log.error("Evidence integrity check failed: %s", exc)
        result.evidence_verified = False

    return result
