"""
CLIF Triage Agent — Drain3 Log Template Miner
================================================
Production wrapper around Drain3 for real-time log template mining.

Responsibilities:
  - Parse unstructured log messages into templates
  - Compute template rarity scores based on frequency distribution
  - Persist state periodically for crash recovery
  - Thread-safe for multi-worker inference

The template_rarity feature is one of the 20 canonical features used by
the ML ensemble. Rare templates (low frequency) get higher rarity scores,
which the model interprets as more anomalous.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Dict, Optional, Tuple

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

import config

logger = logging.getLogger("clif.triage.drain3")


class Drain3Miner:
    """
    Thread-safe Drain3 template miner with rarity scoring.

    Template rarity = 1.0 - log(1 + cluster_size) / log(1 + total_events)
    Rare templates  → rarity close to 1.0 (more suspicious)
    Common templates → rarity close to 0.0 (benign)

    Log-scale ensures meaningful spread even with many small clusters:
      cluster=1,   total=100K → rarity ≈ 0.94 (truly rare)
      cluster=100, total=100K → rarity ≈ 0.60 (moderate)
      cluster=10K, total=100K → rarity ≈ 0.20 (common)
      cluster=50K, total=100K → rarity ≈ 0.06 (very common)

    Warmup: Returns neutral 0.5 until MIN_WARMUP_EVENTS (10 000) events
    have been processed.  During warmup, the template distribution is too
    concentrated to be reliable, so 0.5 forces the model to score using
    only the other 19 features.
    """

    MIN_WARMUP_EVENTS = 10_000

    def __init__(self, state_path: Optional[str] = None, config_path: Optional[str] = None):
        self._lock = threading.Lock()
        self._state_path = state_path or config.DRAIN3_STATE_PATH
        self._config_path = config_path or config.DRAIN3_CONFIG_PATH

        # Load Drain3 configuration
        drain3_config = TemplateMinerConfig()
        if os.path.exists(self._config_path):
            drain3_config.load(self._config_path)
            logger.info("Drain3 config loaded from %s", self._config_path)
        else:
            # Apply defaults from env vars
            drain3_config.drain_depth = config.DRAIN3_DEPTH
            drain3_config.drain_sim_th = config.DRAIN3_SIM_TH
            drain3_config.drain_max_children = config.DRAIN3_MAX_CHILDREN
            drain3_config.drain_max_clusters = config.DRAIN3_MAX_CLUSTERS
            drain3_config.snapshot_interval_minutes = 10
            drain3_config.drain_extra_delimiters = ["_"]
            logger.info("Drain3 config from env (depth=%d, sim_th=%.2f, max_clusters=%d)",
                        config.DRAIN3_DEPTH, config.DRAIN3_SIM_TH, config.DRAIN3_MAX_CLUSTERS)

        # Initialize the template miner
        self._miner = TemplateMiner(config=drain3_config)

        # Load persisted state if available
        if os.path.exists(self._state_path):
            try:
                self._miner.load_state(self._state_path)
                n = len(self._miner.drain.clusters)
                logger.info("Drain3 state restored: %d templates from %s", n, self._state_path)
            except Exception as e:
                logger.warning("Failed to load Drain3 state from %s: %s — starting fresh",
                               self._state_path, e)
        else:
            logger.info("No Drain3 state file found — starting with empty template set")

        # Track total events for rarity calculation
        self._total_events = max(1, sum(
            c.size for c in self._miner.drain.clusters
        ))

        # Background state persistence
        self._persist_interval = 600  # 10 minutes
        self._last_persist = time.monotonic()

    @property
    def template_count(self) -> int:
        """Number of learned templates."""
        return len(self._miner.drain.clusters)

    def mine(self, log_message: str) -> Tuple[str, str, float]:
        """
        Mine a log message and return (template_id, template_str, rarity_score).

        Thread-safe. Updates internal state and computes rarity.

        Args:
            log_message: The preprocessed log message body (headers stripped).

        Returns:
            (template_id, template_string, rarity_score)
            - template_id:     Unique string ID for this template cluster
            - template_string: The generalized template pattern
            - rarity_score:    Float in [0.0, 1.0]. Higher = rarer = more suspicious.
        """
        if not log_message or not log_message.strip():
            return "empty", "<EMPTY>", 0.5

        with self._lock:
            result = self._miner.add_log_message(log_message.strip())
            cluster = result["cluster_id"]
            template = result.get("template_mined", "")

            # Find the cluster to get its size
            cluster_size = 1
            for c in self._miner.drain.clusters:
                if c.cluster_id == cluster:
                    cluster_size = c.size
                    break

            self._total_events += 1

            # ── Warmup guard ─────────────────────────────────────────
            # During warmup the template distribution is too concentrated
            # (few templates, each matching most events → rarity ≈ 0 for
            # everything).  Returning 0.5 (mid-point between benign mean
            # 0.26 and attack mean 0.79 in training) makes the model
            # rely on the other 19 features instead.
            if self._total_events < self.MIN_WARMUP_EVENTS:
                rarity = 0.5
            else:
                # Rarity: log-scaled inverse frequency.
                import math
                log_total = math.log(1.0 + self._total_events)
                if log_total > 0:
                    rarity = 1.0 - math.log(1.0 + cluster_size) / log_total
                else:
                    rarity = 0.5

                # Clamp to [0.0, 1.0]
                rarity = max(0.0, min(1.0, rarity))

            # Periodic state persistence
            now = time.monotonic()
            if now - self._last_persist > self._persist_interval:
                self._persist_state()
                self._last_persist = now

        template_id = f"T{cluster}"
        return template_id, template, rarity

    def get_rarity(self, template_id: str) -> float:
        """
        Get the current rarity score for a known template ID.

        Args:
            template_id: Template ID string (e.g., "T42").

        Returns:
            Rarity score in [0.0, 1.0], or 0.5 if template not found.
        """
        try:
            cluster_num = int(template_id.lstrip("T"))
        except (ValueError, AttributeError):
            return 0.5

        with self._lock:
            for c in self._miner.drain.clusters:
                if c.cluster_id == cluster_num:
                    if self._total_events < self.MIN_WARMUP_EVENTS:
                        return 0.5
                    import math
                    log_total = math.log(1.0 + max(1, self._total_events))
                    if log_total > 0:
                        rarity = 1.0 - math.log(1.0 + c.size) / log_total
                    else:
                        rarity = 0.5
                    return max(0.0, min(1.0, rarity))
        return 0.5

    def _persist_state(self):
        """Save current Drain3 state to disk."""
        try:
            self._miner.save_state(self._state_path)
            logger.debug("Drain3 state persisted to %s (%d templates)",
                         self._state_path, self.template_count)
        except Exception as e:
            logger.error("Failed to persist Drain3 state: %s", e)

    def shutdown(self):
        """Persist state on shutdown."""
        with self._lock:
            self._persist_state()
            logger.info("Drain3 state saved on shutdown (%d templates, %d total events)",
                        self.template_count, self._total_events)

    def get_stats(self) -> Dict:
        """Return operational statistics."""
        with self._lock:
            return {
                "template_count": self.template_count,
                "total_events_mined": self._total_events,
                "state_file": self._state_path,
                "max_clusters": config.DRAIN3_MAX_CLUSTERS,
            }
