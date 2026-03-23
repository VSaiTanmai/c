"""
False-Positive Pattern Analyzer — detect FP patterns by cross-referencing
analyst feedback (``feedback_labels``), prior Verifier verdicts
(``verifier_results``), and LanceDB similarity search
(``attack_embeddings``).

Read-only — no writes to any table or service.
"""
from __future__ import annotations

import asyncio
import logging
from functools import partial
from typing import Any, Optional

import httpx

from models import FPResult
from utils import sanitize_sql

log = logging.getLogger(__name__)


async def analyze(
    ch: Any,
    payload: dict,
    lancedb_url: str = "http://lancedb:8100",
    lancedb_timeout: float = 5.0,
    similarity_threshold: float = 0.3,
) -> FPResult:
    """
    Determine false-positive likelihood for a Hunter verdict.

    Args:
        ch: clickhouse-connect client.
        payload: Hunter verdict dict.
        lancedb_url: LanceDB REST base URL.
        lancedb_timeout: HTTP timeout in seconds.
        similarity_threshold: distance threshold for confirmed-attack matches.

    Returns:
        FPResult with FP analysis.
    """
    result = FPResult()

    hostname = sanitize_sql(payload.get("hostname", ""))
    source_ip = sanitize_sql(payload.get("source_ip", ""))
    if not hostname and not source_ip:
        return result

    entity_filter = _entity_filter(hostname, source_ip)

    try:
        # --- Analyst feedback history -----------------------------------
        feedback_query = (
            "SELECT fl.label, fl.confidence, fl.notes, fl.timestamp "
            "FROM feedback_labels fl "
            "INNER JOIN triage_scores ts ON fl.event_id = ts.event_id "
            f"WHERE ({entity_filter.replace('hostname', 'ts.hostname').replace('source_ip', 'ts.source_ip')}) "
            "  AND fl.timestamp >= now() - INTERVAL 30 DAY "
            "ORDER BY fl.timestamp DESC "
            "LIMIT 20"
        )
        loop = asyncio.get_event_loop()
        fb_rows = await loop.run_in_executor(None, partial(ch.query, feedback_query))

        for row in fb_rows.result_rows:
            label = str(row[0])
            if label == "false_positive":
                result.fp_feedback_count += 1
            elif label == "true_positive":
                result.tp_feedback_count += 1

        # --- Prior Verifier verdicts for entity --------------------------
        verifier_query = (
            "SELECT verdict, confidence, priority, started_at "
            "FROM verifier_results "
            "WHERE alert_id IN ("
            "    SELECT alert_id FROM hunter_investigations "
            f"   WHERE ({entity_filter}) "
            "      AND started_at >= now() - INTERVAL 7 DAY"
            ") "
            "ORDER BY started_at DESC "
            "LIMIT 10"
        )
        vr_rows = await loop.run_in_executor(None, partial(ch.query, verifier_query))
        prior_vr_fp = 0
        prior_vr_tp = 0
        for row in vr_rows.result_rows:
            verdict = str(row[0])
            if verdict == "false_positive":
                prior_vr_fp += 1
            elif verdict == "true_positive":
                prior_vr_tp += 1

        # Weight prior automated verdicts at 50% of human feedback
        result.fp_feedback_count += prior_vr_fp // 2
        result.tp_feedback_count += prior_vr_tp // 2

    except Exception as exc:
        log.error("Feedback query failed: %s", exc)

    # --- LanceDB similarity search (optional) ----------------------------
    result.similar_attack_count = _lancedb_search(
        payload, lancedb_url, lancedb_timeout, similarity_threshold
    )

    # --- Compute FP confidence score ------------------------------------
    total_feedback = result.fp_feedback_count + result.tp_feedback_count
    if total_feedback > 0:
        fp_ratio = result.fp_feedback_count / (total_feedback + 1)
    else:
        fp_ratio = 0.0

    # confirmed attacks in vector DB reduce FP score
    total_search = max(1, result.similar_attack_count + 1)
    similar_attack_ratio = result.similar_attack_count / total_search

    result.fp_confidence = fp_ratio * (1.0 - similar_attack_ratio)
    result.has_fp_history = result.fp_confidence > 0.6

    return result


def _lancedb_search(
    payload: dict,
    lancedb_url: str,
    timeout: float,
    threshold: float,
) -> int:
    """Query LanceDB attack_embeddings for similar confirmed attacks."""
    try:
        mitre = payload.get("mitre_tactics", [])
        tactics_str = " ".join(mitre) if isinstance(mitre, list) else str(mitre)
        query_text = (
            f"{payload.get('hostname', '')} "
            f"{payload.get('source_ip', '')} "
            f"{tactics_str} "
            f"{payload.get('finding_type', '')}"
        ).strip()

        if not query_text:
            return 0

        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{lancedb_url}/search",
                json={"query": query_text, "limit": 10, "table": "attack_embeddings"},
            )
            if resp.status_code != 200:
                log.debug("LanceDB search returned %d", resp.status_code)
                return 0

            data = resp.json()
            results = data.get("results", [])
            close_matches = sum(
                1 for r in results
                if float(r.get("_distance", 999)) < threshold
            )
            return close_matches

    except Exception as exc:
        log.debug("LanceDB search failed (non-critical): %s", exc)
        return 0


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
