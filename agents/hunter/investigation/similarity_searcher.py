"""
Similarity Searcher – L1 investigation thread.

Queries three LanceDB tables via HTTP and derives 7 feature-vector dims:
  [attack_embed_dist, historical_dist, log_embed_matches,
   confirmed_neighbor_count, min_confirmed_dist,
   false_positive_count, label_confidence]

Falls back to safe defaults [1,1,0,0,1,0,0] if the LanceDB service is
unreachable (circuit breaker upstream handles retries).
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Tuple

import httpx

from config import LANCEDB_TIMEOUT_SEC, LANCEDB_URL
from models import SimilarityResult

log = logging.getLogger(__name__)

_FALLBACK = SimilarityResult(
    attack_embed_dist=1.0,
    historical_dist=1.0,
    log_embed_matches=0,
    confirmed_neighbor_count=0,
    min_confirmed_dist=1.0,
    false_positive_count=0,
    label_confidence=0.0,
)

_EMBED_DIM = 384  # sentence-transformer all-MiniLM-L6-v2


def _build_query_text(payload: Dict[str, Any]) -> str:
    parts = [
        str(payload.get("hostname", "")),
        str(payload.get("source_ip", "")),
        str(payload.get("user_id", "")),
        str(payload.get("summary", "")),
    ]
    tactic = str(payload.get("mitre_tactic", ""))
    if tactic:
        parts.append(tactic)
    return " ".join(p for p in parts if p)


async def run(
    payload: Dict[str, Any],
    lancedb_url: str = LANCEDB_URL,
) -> SimilarityResult:
    """Entry point called from L1 gather."""
    try:
        return await _search(payload, lancedb_url)
    except Exception as exc:  # noqa: BLE001
        log.warning("SimilaritySearcher failed, using fallback: %s", exc)
        return _FALLBACK


async def _search(
    payload: Dict[str, Any],
    lancedb_url: str,
) -> SimilarityResult:
    query_text = _build_query_text(payload)
    hostname = str(payload.get("hostname", ""))
    source_ip = str(payload.get("source_ip", ""))

    async with httpx.AsyncClient(timeout=LANCEDB_TIMEOUT_SEC) as client:
        # Run all three searches concurrently
        attack_task = asyncio.create_task(
            _vector_search(
                client,
                lancedb_url,
                "attack_embeddings",
                query_text,
                limit=10,
                filter_expr=None,
            )
        )
        history_task = asyncio.create_task(
            _vector_search(
                client,
                lancedb_url,
                "historical_incidents",
                query_text,
                limit=10,
                filter_expr=None,
            )
        )
        log_task = asyncio.create_task(
            _vector_search(
                client,
                lancedb_url,
                "log_embeddings",
                query_text,
                limit=20,
                filter_expr=f"hostname = '{hostname}'",
            )
        )

        attack_rows, history_rows, log_rows = await asyncio.gather(
            attack_task, history_task, log_task, return_exceptions=True
        )

    result = SimilarityResult()

    # --- attack_embeddings distance + confirmed neighbour count ---
    # attack_embeddings contains ONLY confirmed attacks; every close result
    # is a confirmed-attack neighbor — no label field needed.
    if isinstance(attack_rows, list) and attack_rows:
        distances = [float(r.get("_distance", 1.0)) for r in attack_rows]
        result.attack_embed_dist = min(distances, default=1.0)
        result.confirmed_neighbor_count = sum(1 for d in distances if d < 0.3)
        result.min_confirmed_dist = min(
            (d for d in distances if d < 0.3), default=1.0
        )
        # label_confidence: fraction of attack_embedding neighbors that are
        # very close (< 0.3) out of all < 0.5 results
        close_any = [d for d in distances if d < 0.5]
        close_confirmed = [d for d in distances if d < 0.3]
        result.label_confidence = (
            len(close_confirmed) / len(close_any) if close_any else 0.0
        )
    else:
        result.attack_embed_dist = 1.0

    # --- historical_incidents distance ---
    # historical_incidents has no label; we only use the distance score.
    # false_positive_count is zeroed here — could be populated from
    # feedback_labels in a future sprint.
    if isinstance(history_rows, list) and history_rows:
        hist_distances = [float(r.get("_distance", 1.0)) for r in history_rows]
        result.historical_dist = min(hist_distances, default=1.0)
        result.false_positive_count = 0   # no label field in historical_incidents
    else:
        result.historical_dist = 1.0

    # --- log_embeddings matches ---
    if isinstance(log_rows, list):
        result.log_embed_matches = sum(
            1 for r in log_rows
            if float(r.get("_distance", 1.0)) < 0.4
        )
    else:
        result.log_embed_matches = 0

    return result


async def _vector_search(
    client: httpx.AsyncClient,
    base_url: str,
    table: str,
    query_text: str,
    limit: int,
    filter_expr: Any,
) -> List[Dict[str, Any]]:
    """POST to /tables/{table}/search with a text query."""
    body: Dict[str, Any] = {
        "query_text": query_text,
        "limit": limit,
    }
    if filter_expr:
        body["filter"] = filter_expr

    resp = await client.post(
        f"{base_url}/tables/{table}/search",
        json=body,
    )
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, list) else data.get("results", [])
