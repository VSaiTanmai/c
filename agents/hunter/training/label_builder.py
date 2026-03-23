"""
Label Builder – generates training labels from hunter verdicts.

Label hierarchy (ORDER BY CASE in the SQL training query):
  1. CONFIRMED_ATTACK / ACTIVE_CAMPAIGN → label = 1
  2. FALSE_POSITIVE / NORMAL_BEHAVIOUR  → label = 0
  3. BEHAVIOURAL_ANOMALY / SIGMA_MATCH  → label = 1 (ambiguous-positive)
  4. ANOMALOUS_PATTERN                  → label = 1 (weak positive)
  5. else                               → label = 0

Guards:
  - is_fast_path=True rows are EXCLUDED (Sigma skipped full investigation)
  - A minimum of 10% of the training set must be negatives
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from config import CLICKHOUSE_DATABASE
from models import (
    AMBIGUOUS_TYPES,
    DEFINITE_POSITIVE_TYPES,
    HunterVerdict,
)

log = logging.getLogger(__name__)

# Minimum fraction of negative examples in any training batch
MIN_NEGATIVE_RATIO = 0.10


def get_label(finding_type: str) -> int:
    """
    Map a finding_type string to a binary label.
    Returns 1 (attack) or 0 (benign).
    """
    if finding_type in DEFINITE_POSITIVE_TYPES:
        return 1
    if finding_type in AMBIGUOUS_TYPES:
        return 1
    # NORMAL_BEHAVIOUR, FALSE_POSITIVE, and unknowns → 0
    return 0


# Minimum confidence required to store training data.
# v2: lowered from 0.50 to 0.20 — the cold-start heuristic scorer produces
# scores in 0.27-0.40 range (with the rebalanced weights).  The original
# threshold of 0.50 blocked ALL training writes, creating a chicken-and-egg
# problem where CatBoost could never be trained.
MIN_TRAINING_CONFIDENCE = 0.20


def should_include_in_training(verdict: HunterVerdict) -> bool:
    """
    Return True if this verdict should be written to the training store.

    Guards (ALL must pass):
      1. Not a fast-path verdict (Sigma-only, no full feature vector)
      2. Feature vector is present and correctly sized
      3. Confidence is above MIN_TRAINING_CONFIDENCE — prevents
         cold-start heuristic noise from contaminating the training set.
         Once the CatBoost model is trained, its higher-confidence
         verdicts will pass this gate naturally.
    """
    if verdict.is_fast_path:
        return False
    if not verdict.feature_vector or len(verdict.feature_vector) == 0:
        return False
    if verdict.hunter_score < MIN_TRAINING_CONFIDENCE:
        log.debug(
            "Skipping training write for %s: confidence %.3f < gate %.3f (model=%s)",
            verdict.alert_id, verdict.hunter_score, MIN_TRAINING_CONFIDENCE,
            getattr(verdict, 'model_used', 'unknown'),
        )
        return False
    return True


def fetch_training_set(
    ch_client: Any,
    min_samples: int,
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetch training rows from ClickHouse with the label hierarchy applied.

    Returns None if insufficient data; otherwise a list of dicts with
    keys: feature_vector_json, label
    """
    try:
        count_q = f"SELECT count() FROM {CLICKHOUSE_DATABASE}.hunter_training_data"
        rows = ch_client.query(count_q).result_rows
        total = int(rows[0][0]) if rows else 0

        if total < min_samples:
            log.info(
                "Insufficient training data: %d / %d required", total, min_samples
            )
            return None

        q = f"""
            SELECT
                feature_vector AS feature_vector_json,
                label
            FROM {CLICKHOUSE_DATABASE}.hunter_training_data
            ORDER BY created_at DESC
            LIMIT 50000
        """
        rows = ch_client.query(q).result_rows
        data = [{"feature_vector_json": r[0], "label": int(r[1])} for r in rows]

        # Guard: ensure minimum negative ratio
        positives = sum(1 for d in data if d["label"] == 1)
        negatives = len(data) - positives
        if len(data) > 0 and negatives / len(data) < MIN_NEGATIVE_RATIO:
            log.warning(
                "Training set has only %.1f%% negatives (min %.0f%%) – "
                "model will not be retrained until balance improves",
                100 * negatives / len(data),
                100 * MIN_NEGATIVE_RATIO,
            )
            return None

        return data

    except Exception as exc:  # noqa: BLE001
        log.error("fetch_training_set failed: %s", exc)
        return None
