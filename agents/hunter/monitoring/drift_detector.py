"""
Drift Detector – monitors for feature distribution shift between a
7-day baseline window and the most recent 1-day window.

Three signals are combined:
  1. KL Divergence averaged across all feature dimensions
  2. PSI (Population Stability Index) on 4 sentinel features
  3. Triage-Anchored Divergence – mean score drift between the two windows

Results are written to `hunter_model_health` table.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np  # type: ignore

from config import (
    CLICKHOUSE_DATABASE,
    DRIFT_BASELINE_DAYS,
    DRIFT_CURRENT_DAYS,
    DRIFT_KL_THRESHOLD,
    DRIFT_PSI_THRESHOLD,
)
from models import FEATURE_ORDER, DriftReport

log = logging.getLogger(__name__)

# Indices of 4 sentinel features used for PSI calculation
PSI_FEATURE_INDICES = [
    FEATURE_ORDER.index("adjusted_score"),         # 0
    FEATURE_ORDER.index("sigma_hit_count"),         # 36
    FEATURE_ORDER.index("similarity_attack_embed_dist"),  # 24
    FEATURE_ORDER.index("spc_z_score"),             # 38
]

_NUM_BINS = 10  # PSI bin count


class DriftDetector:
    def __init__(self, ch_client: Any) -> None:
        self._ch = ch_client

    async def check_drift(self) -> DriftReport:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_drift_check)

    def _run_drift_check(self) -> DriftReport:
        report = DriftReport()

        try:
            baseline_vectors = self._fetch_vectors(days=DRIFT_BASELINE_DAYS)
            current_vectors = self._fetch_vectors(days=DRIFT_CURRENT_DAYS)

            if len(baseline_vectors) < 10 or len(current_vectors) < 5:
                log.debug("Insufficient data for drift detection")
                return report

            baseline_arr = np.array(baseline_vectors, dtype=np.float32)
            current_arr = np.array(current_vectors, dtype=np.float32)

            # --- KL divergence per feature, averaged ---
            kl_scores: List[float] = []
            affected: List[str] = []
            for i, name in enumerate(FEATURE_ORDER):
                kl = _kl_divergence(baseline_arr[:, i], current_arr[:, i])
                kl_scores.append(kl)
                if kl > DRIFT_KL_THRESHOLD:
                    affected.append(name)

            report.kl_divergence = float(np.mean(kl_scores))
            report.affected_features = affected

            # --- PSI on sentinel features ---
            psi_values: List[float] = []
            for idx in PSI_FEATURE_INDICES:
                psi = _psi(baseline_arr[:, idx], current_arr[:, idx])
                psi_values.append(psi)
            report.psi = float(np.mean(psi_values))

            # --- Triage-anchored divergence ---
            b_score_idx = FEATURE_ORDER.index("adjusted_score")
            b_mean = float(np.mean(baseline_arr[:, b_score_idx]))
            c_mean = float(np.mean(current_arr[:, b_score_idx]))
            report.triage_anchor_divergence = abs(b_mean - c_mean)

            # --- Overall drift flag ---
            report.drift_detected = (
                report.kl_divergence > DRIFT_KL_THRESHOLD
                or report.psi > DRIFT_PSI_THRESHOLD
                or report.triage_anchor_divergence > 0.1
            )

            # --- Persist to ClickHouse ---
            self._write_health_record(report)

        except Exception as exc:  # noqa: BLE001
            log.error("DriftDetector._run_drift_check failed: %s", exc)

        return report

    def _fetch_vectors(self, days: int) -> List[List[float]]:
        q = f"""
            SELECT feature_vector_json
            FROM {CLICKHOUSE_DATABASE}.hunter_training_data
            WHERE is_fast_path = 0
              AND recorded_at >= now() - INTERVAL {days} DAY
            ORDER BY recorded_at DESC
            LIMIT 5000
        """
        rows = self._ch.query(q).result_rows
        vectors: List[List[float]] = []
        for (fv_json,) in rows:
            try:
                vec = json.loads(fv_json)
                if len(vec) == len(FEATURE_ORDER):
                    vectors.append([float(v) for v in vec])
            except Exception:  # noqa: BLE001
                pass
        return vectors

    def _write_health_record(self, report: DriftReport) -> None:
        now = datetime.now(tz=timezone.utc).isoformat()
        affected_json = json.dumps(report.affected_features)
        try:
            self._ch.command(
                f"""
                INSERT INTO {CLICKHOUSE_DATABASE}.hunter_model_health
                (recorded_at, kl_divergence, psi, triage_anchor_divergence,
                 drift_detected, affected_features_json)
                VALUES (
                    '{now}',
                    {report.kl_divergence:.6f},
                    {report.psi:.6f},
                    {report.triage_anchor_divergence:.6f},
                    {int(report.drift_detected)},
                    '{_s(affected_json)}'
                )
                """
            )
        except Exception as exc:  # noqa: BLE001
            log.error("DriftDetector health write failed: %s", exc)


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def _kl_divergence(p: np.ndarray, q: np.ndarray, bins: int = _NUM_BINS) -> float:
    """Symmetric KL divergence between two 1-D arrays."""
    eps = 1e-8
    lo = min(p.min(), q.min())
    hi = max(p.max(), q.max()) + eps

    p_hist, _ = np.histogram(p, bins=bins, range=(lo, hi), density=True)
    q_hist, _ = np.histogram(q, bins=bins, range=(lo, hi), density=True)

    p_hist = p_hist + eps
    q_hist = q_hist + eps

    kl_pq = float(np.sum(p_hist * np.log(p_hist / q_hist)))
    kl_qp = float(np.sum(q_hist * np.log(q_hist / p_hist)))
    return (kl_pq + kl_qp) / 2.0


def _psi(expected: np.ndarray, actual: np.ndarray, bins: int = _NUM_BINS) -> float:
    """Population Stability Index between expected and actual arrays."""
    eps = 1e-8
    lo = min(expected.min(), actual.min())
    hi = max(expected.max(), actual.max()) + eps

    e_hist, _ = np.histogram(expected, bins=bins, range=(lo, hi))
    a_hist, _ = np.histogram(actual, bins=bins, range=(lo, hi))

    e_frac = e_hist / (e_hist.sum() + eps)
    a_frac = a_hist / (a_hist.sum() + eps)

    e_frac = np.where(e_frac == 0, eps, e_frac)
    a_frac = np.where(a_frac == 0, eps, a_frac)

    return float(np.sum((a_frac - e_frac) * np.log(a_frac / e_frac)))


def _s(value: Any) -> str:
    import re
    return re.sub(r"[';\"\\]", "", str(value))
