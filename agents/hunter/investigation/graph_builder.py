"""
Graph Builder – L1 investigation thread.

Queries ClickHouse to build an entity-relationship picture around the
alert's primary entities and derives 8 feature-vector dimensions:
  [graph_unique_destinations, graph_unique_src_ips,
   graph_has_ioc_neighbor, graph_hop_count,
   graph_high_risk_neighbors, graph_escalation_count,
   graph_lateral_movement_score, graph_c2_candidate_score]

Noisy-IP cap: hosts with > 50 escalations AND no IOC are excluded to
prevent high-volume scanning hosts from dominating the feature values.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict

from config import CLICKHOUSE_DATABASE, INVESTIGATION_WINDOW_MIN
from models import GraphResult

log = logging.getLogger(__name__)


async def run(
    payload: Dict[str, Any],
    ch_client: Any,
) -> GraphResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query, payload, ch_client)


def _query(payload: Dict[str, Any], ch_client: Any) -> GraphResult:
    hostname = _s(payload.get("hostname", ""))
    source_ip = _s(payload.get("source_ip", ""))
    user_id = _s(payload.get("user_id", ""))

    result = GraphResult()

    try:
        # -------------------------------------------------------------------
        # Q1 – Unique destination IPs reached from this source (noisy-IP cap)
        # -------------------------------------------------------------------
        q1 = f"""
            SELECT countDistinct(dst_ip) AS unique_dests
            FROM {CLICKHOUSE_DATABASE}.network_events
            WHERE toString(src_ip) = '{source_ip}'
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
              AND (
                toString(src_ip) IN (
                    SELECT ioc_value FROM {CLICKHOUSE_DATABASE}.ioc_cache
                    WHERE ioc_type = 'ip'
                )
                OR toString(src_ip) NOT IN (
                    SELECT source_ip
                    FROM {CLICKHOUSE_DATABASE}.triage_scores
                    GROUP BY source_ip
                    HAVING count() > 50
                )
              )
        """
        rows = ch_client.query(q1).result_rows
        result.unique_destinations = int(rows[0][0]) if rows else 0

        # -------------------------------------------------------------------
        # Q2 – Unique source IPs that also touched this hostname
        # -------------------------------------------------------------------
        q2 = f"""
            SELECT countDistinct(src_ip) AS unique_srcs
            FROM {CLICKHOUSE_DATABASE}.network_events
            WHERE hostname = '{hostname}'
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
        """
        rows = ch_client.query(q2).result_rows
        result.unique_src_ips = int(rows[0][0]) if rows else 0

        # -------------------------------------------------------------------
        # Q3 – Does source_ip appear in IOC cache?
        # -------------------------------------------------------------------
        q3 = f"""
            SELECT count() > 0
            FROM {CLICKHOUSE_DATABASE}.ioc_cache
            WHERE ioc_value = '{source_ip}'
              AND ioc_type = 'ip'
        """
        rows = ch_client.query(q3).result_rows
        result.has_ioc_neighbor = bool(rows[0][0]) if rows else False

        # -------------------------------------------------------------------
        # Q4 – Hop count: how many distinct hosts did source_ip visit?
        # -------------------------------------------------------------------
        q4 = f"""
            SELECT countDistinct(hostname) AS hop_count
            FROM {CLICKHOUSE_DATABASE}.network_events
            WHERE toString(src_ip) = '{source_ip}'
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
        """
        rows = ch_client.query(q4).result_rows
        hop_count = int(rows[0][0]) if rows else 0
        result.hop_count = hop_count

        # -------------------------------------------------------------------
        # Q5 – High-risk neighbour count (IOC-listed destinations)
        # -------------------------------------------------------------------
        q5 = f"""
            SELECT count() AS hr_neighbors,
                   countIf(action = 'escalate') AS escalation_count
            FROM {CLICKHOUSE_DATABASE}.triage_scores
            WHERE hostname = '{hostname}'
              AND adjusted_score >= 0.75
              AND timestamp >= now() - INTERVAL {INVESTIGATION_WINDOW_MIN} MINUTE
              AND (
                  ioc_match = 1
                  OR source_ip IN (
                      SELECT ioc_value FROM {CLICKHOUSE_DATABASE}.ioc_cache
                      WHERE ioc_type = 'ip'
                  )
              )
        """
        rows = ch_client.query(q5).result_rows
        if rows:
            result.high_risk_neighbors = int(rows[0][0] or 0)
            result.escalation_count = int(rows[0][1] or 0)

        # -------------------------------------------------------------------
        # Derived scores
        # -------------------------------------------------------------------
        # Lateral movement: multiple hops to internal hosts on privileged ports
        result.lateral_movement_score = min(1.0, hop_count / 10.0)

        # C2 candidate: high destination count + low source diversity
        if result.unique_destinations >= 3 and result.hop_count >= 2:
            result.c2_candidate_score = min(
                1.0,
                (result.unique_destinations / 10.0) * (1 + result.has_ioc_neighbor),
            )
        else:
            result.c2_candidate_score = 0.0

    except Exception as exc:  # noqa: BLE001
        log.warning("GraphBuilder failed for %s/%s: %s", hostname, source_ip, exc)

    return result


def _s(value: Any) -> str:
    return re.sub(r"[';\"\\]", "", str(value))
