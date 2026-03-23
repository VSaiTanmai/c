"""
CLIF Triage Agent v7 — Score Fusion & Routing
================================================
Applies post-model adjustments to the raw ensemble scores:
  1. Kill-chain progression boost  (up to 1.5×)
  2. Cross-host correlation boost  (1.2×)
  3. IOC context-aware boost       (+0.05 to +0.20)
  4. Disagreement escalation       (force to 0.95)

Then routes each scored event to the appropriate topic:
  - adjusted ≥ 0.90  →  ESCALATE (anomaly-alerts + hunter-tasks)
  - adjusted ≥ 0.40  →  MONITOR  (triage-scores, dashboard visible)
  - adjusted < 0.40  →  DISCARD  (triage-scores, audit only)

v7 changes:
  - Vectorized numpy operations (no row-by-row loops)
  - Lower anomalous threshold (0.90 vs 0.95) — confident with better features
  - Kill-chain and cross-host boosts are NEW
  - IOC boost is context-aware (scaled by combined score)
  - Drift monitoring via PSI (Population Stability Index)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

import config

logger = logging.getLogger("clif.triage.fusion")

# ── Action codes (from config) ──────────────────────────────────────────────

LABEL_DISCARD = "discard"
LABEL_MONITOR = "monitor"
LABEL_ESCALATE = "escalate"


# ── Baseline Tracker ────────────────────────────────────────────────────────

class BaselineTracker:
    """
    Tracks running mean/std of scores per entity (host or user)
    to compute z-score deviation from baseline.
    Uses Welford's online algorithm — O(1) per update.
    """

    __slots__ = ("_lock", "_entities", "_max_entities")

    def __init__(self, max_entities: int = 200_000):
        self._lock = threading.Lock()
        self._entities: Dict[str, Tuple[int, float, float, float]] = {}
        # key → (count, mean, M2, last_ts)
        self._max_entities = max_entities

    def update_and_get_z(self, entity: str, score: float, timestamp: float) -> float:
        """Update baseline and return z-score deviation."""
        with self._lock:
            if entity in self._entities:
                count, mean, m2, _ = self._entities[entity]
            else:
                if len(self._entities) >= self._max_entities:
                    return 0.0
                count, mean, m2 = 0, 0.0, 0.0

            count += 1
            delta = score - mean
            mean += delta / count
            delta2 = score - mean
            m2 += delta * delta2
            self._entities[entity] = (count, mean, m2, timestamp)

            if count < 10:
                return 0.0

            variance = m2 / count
            std = max(variance ** 0.5, 1e-6)
            return (score - mean) / std

    def cleanup(self, now: float, max_age_sec: float = 86400.0) -> int:
        cutoff = now - max_age_sec
        with self._lock:
            stale = [k for k, v in self._entities.items() if v[3] < cutoff]
            for k in stale:
                del self._entities[k]
            return len(stale)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {"tracked_entities": len(self._entities)}


# ── Drift Monitor (PSI) ────────────────────────────────────────────────────

class DriftMonitor:
    """
    Population Stability Index (PSI) for score distribution drift.
    Compares current batch distribution against a reference window.
    """

    def __init__(
        self,
        n_bins: int = 10,
        window_size: int = 5000,
        psi_warning: float = 0.1,
        psi_critical: float = 0.25,
    ):
        self._n_bins = n_bins
        self._window_size = window_size
        self._psi_warning = psi_warning
        self._psi_critical = psi_critical
        self._reference: Optional[np.ndarray] = None
        self._current_window: Deque[float] = deque(maxlen=window_size)
        self._batches_seen = 0
        self._lock = threading.Lock()

    def set_reference(self, scores: np.ndarray) -> None:
        """Set reference distribution from training or initial scores."""
        self._reference = self._compute_histogram(scores)

    def add_batch(self, scores: np.ndarray) -> Optional[Dict[str, Any]]:
        """Add scores and periodically compute PSI."""
        with self._lock:
            self._current_window.extend(scores.tolist())
            self._batches_seen += 1

            if self._batches_seen % config.DRIFT_INTERVAL_BATCHES != 0:
                return None
            if self._reference is None:
                self._reference = self._compute_histogram(
                    np.array(list(self._current_window))
                )
                return None

            current_hist = self._compute_histogram(
                np.array(list(self._current_window))
            )
            psi = self._compute_psi(self._reference, current_hist)

            level = "ok"
            if psi >= self._psi_critical:
                level = "critical"
                logger.warning("DRIFT CRITICAL: PSI=%.4f (threshold=%.4f)", psi, self._psi_critical)
            elif psi >= self._psi_warning:
                level = "warning"
                logger.info("DRIFT WARNING: PSI=%.4f (threshold=%.4f)", psi, self._psi_warning)

            return {
                "psi": float(psi),
                "level": level,
                "batches_seen": self._batches_seen,
                "window_size": len(self._current_window),
            }

    def _compute_histogram(self, scores: np.ndarray) -> np.ndarray:
        bins = np.linspace(0, 1, self._n_bins + 1)
        hist, _ = np.histogram(scores, bins=bins)
        # Add small epsilon to avoid division by zero
        hist = hist.astype(np.float64) + 1e-6
        return hist / hist.sum()

    @staticmethod
    def _compute_psi(reference: np.ndarray, current: np.ndarray) -> float:
        return float(np.sum((current - reference) * np.log(current / reference)))


# ── Score Fusion Engine ─────────────────────────────────────────────────────

class ScoreFusion:
    """
    Applies post-model adjustments and routes scored events.

    Process:
      1. Start with combined score = lgbm * 0.85 + ae * 0.15
      2. Apply kill-chain boost (up to 1.5×)
      3. Apply cross-host correlation boost (1.2×)
      4. Apply IOC context-aware boost (+0.05 to +0.20)
      5. Apply disagreement escalation (force to 0.95)
      6. Route to appropriate topic/action

    All operations are vectorized over the batch.
    """

    def __init__(self):
        self._host_baseline = BaselineTracker()
        self._user_baseline = BaselineTracker()
        self._drift_monitor: Optional[DriftMonitor] = None


        if config.DRIFT_ENABLED:
            self._drift_monitor = DriftMonitor(
                n_bins=config.DRIFT_PSI_BINS,
                window_size=config.DRIFT_WINDOW_SIZE,
                psi_warning=config.DRIFT_PSI_WARNING,
                psi_critical=config.DRIFT_PSI_CRITICAL,
            )

        self._total_events = 0
        self._total_escalated = 0
        self._total_monitored = 0
        self._total_discarded = 0

    def fuse_batch(
        self,
        features_list: List[Dict[str, Any]],
        model_scores: Dict[str, np.ndarray],
    ) -> List[Dict[str, Any]]:
        """
        Fuse model scores with contextual adjustments for a batch.

        Args:
            features_list: list of N feature dicts (from FeatureExtractor)
            model_scores: dict with "lgbm_scores", "ae_scores", "combined"

        Returns:
            list of N result dicts, each with:
                "final_score", "label", "lgbm_score", "ae_score",
                "adjustments" (dict of applied boosts), metadata
        """
        n = len(features_list)
        lgbm = model_scores["lgbm_scores"]
        ae = model_scores["ae_scores"]
        combined = model_scores["combined"].copy()

        # Vectorized adjustments
        adjustments_log = [[] for _ in range(n)]

        for i in range(n):
            feat = features_list[i]

            # ── 1. Kill-chain boost ─────────────────────────────────────
            kc_stage = feat.get("kill_chain_stage", 0.0)
            if kc_stage >= 2:
                boost = 1.0 + kc_stage * 0.10  # max 1.5 at stage 5
                combined[i] *= boost
                adjustments_log[i].append(
                    f"kc_boost:{boost:.2f}(stage={int(kc_stage)})"
                )

            # ── 2. Cross-host correlation boost ─────────────────────────
            xhost = feat.get("cross_host_correlation", 0.0)
            if xhost >= 3.0:
                combined[i] *= 1.20
                adjustments_log[i].append(f"xhost_boost:1.20(hosts={xhost:.0f})")

            # ── 3. IOC context-aware boost ──────────────────────────────
            has_ioc = feat.get("has_known_ioc", 0.0)
            if has_ioc > 0.5:
                ioc_boost = config.IOC_BOOST_BASE + config.IOC_BOOST_SCALE * combined[i]
                combined[i] += ioc_boost
                adjustments_log[i].append(f"ioc_boost:{ioc_boost:.3f}")

            # ── 4. Disagreement escalation ──────────────────────────────
            # Only escalate when BOTH models show elevated scores and
            # disagree — prevents false escalation from a single noisy model.
            disagreement = abs(float(lgbm[i]) - float(ae[i]))
            min_score = min(float(lgbm[i]), float(ae[i]))
            max_score = max(float(lgbm[i]), float(ae[i]))
            if (
                disagreement > config.DISAGREEMENT_THRESHOLD
                and max_score > config.DISAGREEMENT_ESCALATION_FLOOR
                and min_score > 0.30  # both models must show some signal
            ):
                # Damped escalation: blend toward 0.95 rather than hard-set
                escalation_target = 0.90 + 0.05 * min(disagreement, 1.0)
                combined[i] = max(combined[i], escalation_target)
                adjustments_log[i].append(
                    f"disagree_escalate(Δ={disagreement:.2f},target={escalation_target:.2f})"
                )

        # Clamp to [0, 1]
        combined = np.clip(combined, 0.0, 1.0)

        # ── Update baselines and compute z-scores ───────────────────────
        now = time.monotonic()
        results = []

        for i in range(n):
            feat = features_list[i]
            score = float(combined[i])
            hostname = feat.get("_hostname", "unknown")
            user = feat.get("_user", "")

            # Update baseline trackers
            host_z = self._host_baseline.update_and_get_z(hostname, score, now)
            user_z = self._user_baseline.update_and_get_z(user, score, now) if user else 0.0

            # Route
            if score >= config.DEFAULT_ANOMALOUS_THRESHOLD:
                label = LABEL_ESCALATE
                self._total_escalated += 1
            elif score >= config.DEFAULT_SUSPICIOUS_THRESHOLD:
                label = LABEL_MONITOR
                self._total_monitored += 1
            else:
                label = LABEL_DISCARD
                self._total_discarded += 1

            self._total_events += 1

            results.append({
                "final_score": score,
                "label": label,
                "lgbm_score": float(lgbm[i]),
                "ae_score": float(ae[i]),
                "host_baseline_z": host_z,
                "user_baseline_z": user_z,
                "adjustments": "; ".join(adjustments_log[i]) if adjustments_log[i] else "none",
                "hostname": hostname,
                "user": user,
                "entity_key": feat.get("_entity_key", ""),
                "source_type": feat.get("_source_type", ""),
                "topic": feat.get("_topic", ""),
                "action_type_name": feat.get("_action_type_name", "info"),
                "template_id": feat.get("_template_id", ""),
                # v7: entity EWMA rates for Hunter consumption
                "entity_event_rate": feat.get("entity_event_rate", 0.0),
                "entity_error_rate": feat.get("entity_error_rate", 0.0),
            })

        # Drift monitoring
        if self._drift_monitor is not None:
            drift_result = self._drift_monitor.add_batch(combined)
            if drift_result and drift_result["level"] != "ok":
                for r in results:
                    r["drift_alert"] = drift_result

        return results

    def get_baseline_z(self, hostname: str, user: str) -> Tuple[float, float]:
        """Get current baseline z-scores for a host and user."""
        host_z = 0.0
        user_z = 0.0
        # We can't query without updating, so return 0 for unknown entities
        return host_z, user_z

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_events": self._total_events,
            "total_escalated": self._total_escalated,
            "total_monitored": self._total_monitored,
            "total_discarded": self._total_discarded,
            "escalation_rate": (
                self._total_escalated / max(self._total_events, 1)
            ),
            "monitoring_rate": (
                self._total_monitored / max(self._total_events, 1)
            ),
            "host_baselines": self._host_baseline.get_stats(),
            "user_baselines": self._user_baseline.get_stats(),
        }

    def cleanup(self) -> None:
        now = time.monotonic()
        h = self._host_baseline.cleanup(now)
        u = self._user_baseline.cleanup(now)
        if h > 0 or u > 0:
            logger.info("Baseline cleanup: removed %d hosts, %d users", h, u)
