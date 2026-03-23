"""
CLIF Triage Agent v7 — EWMA Rate Tracker
============================================
Per-entity exponentially weighted moving average rate tracking.

Replaces the fixed-window ConnectionTracker for rate features.
Tracks event rate, error rate, and action diversity per
(hostname, user) entity at multiple time scales.

Memory: ~200 bytes per entity. 100K entities = 20 MB.
Thread-safe via sharded locks (16 shards by default).
"""

from __future__ import annotations

import math
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import config


class _EntityState:
    """Mutable state for a single tracked entity."""

    __slots__ = (
        "rates", "error_rates", "last_ts",
        "unique_actions", "action_window_start",
        "last_access",
    )

    def __init__(self, n_scales: int, timestamp: float):
        self.rates: List[float] = [0.0] * n_scales
        self.error_rates: List[float] = [0.0] * n_scales
        self.last_ts: float = timestamp
        self.unique_actions: Set[int] = set()
        self.action_window_start: float = timestamp
        self.last_access: float = timestamp


class EWMATracker:
    """
    Per-entity exponentially weighted rate tracker.

    Maintains event rate and error rate at three time scales
    (fast=2s, medium=60s, slow=600s half-life) for each entity.
    Also tracks action diversity in a rolling 300s window.

    Thread-safe via sharded locks to minimize contention with
    concurrent feature extraction workers.
    """

    ACTION_WINDOW_SEC = 300.0  # Rolling window for unique action count

    def __init__(
        self,
        half_lives: Optional[List[float]] = None,
        num_shards: int = 16,
        max_entities: int = 500000,
        cleanup_interval_sec: float = 60.0,
    ):
        if half_lives is None:
            half_lives = [
                config.EWMA_HALF_LIFE_FAST,
                config.EWMA_HALF_LIFE_MEDIUM,
                config.EWMA_HALF_LIFE_SLOW,
            ]

        self._half_lives = half_lives
        self._n_scales = len(half_lives)
        self._decay_constants = [math.log(2) / hl for hl in half_lives]
        self._num_shards = num_shards
        self._max_entities = max_entities
        self._cleanup_interval = cleanup_interval_sec

        # Sharded storage: each shard has its own lock and entity dict
        self._shards: List[Dict] = [
            {
                "lock": threading.Lock(),
                "entities": {},
            }
            for _ in range(num_shards)
        ]
        self._last_cleanup = time.monotonic()
        self._cleanup_lock = threading.Lock()

    def _shard_for(self, entity_key: str) -> int:
        """Deterministic shard assignment."""
        return hash(entity_key) % self._num_shards

    def update(
        self,
        entity_key: str,
        timestamp: float,
        is_error: bool = False,
        action_type: int = 0,
    ) -> Dict[str, float]:
        """
        Record an event for an entity and return current rate features.

        Args:
            entity_key: Unique entity identifier (e.g., "hostname::user").
            timestamp: Event timestamp (monotonic seconds).
            is_error: Whether this event represents an error/warning.
            action_type: Numeric action type (0-11).

        Returns:
            Dict with keys: entity_event_rate, entity_error_rate,
            entity_unique_actions, rate_acceleration.
        """
        shard_idx = self._shard_for(entity_key)
        shard = self._shards[shard_idx]

        with shard["lock"]:
            state = shard["entities"].get(entity_key)
            if state is None:
                state = _EntityState(self._n_scales, timestamp)
                shard["entities"][entity_key] = state

            elapsed = max(timestamp - state.last_ts, 0.001)

            for i, dc in enumerate(self._decay_constants):
                decay = math.exp(-elapsed * dc)
                state.rates[i] = state.rates[i] * decay + 1.0
                if is_error:
                    state.error_rates[i] = state.error_rates[i] * decay + 1.0
                else:
                    state.error_rates[i] = state.error_rates[i] * decay

            state.last_ts = timestamp
            state.last_access = time.monotonic()

            # Track unique actions in rolling window
            if timestamp - state.action_window_start > self.ACTION_WINDOW_SEC:
                state.unique_actions.clear()
                state.action_window_start = timestamp
            state.unique_actions.add(action_type)

            result = {
                "entity_event_rate": state.rates[1],     # medium (60s)
                "entity_error_rate": state.error_rates[1], # medium (60s)
                "entity_unique_actions": float(len(state.unique_actions)),
                "rate_acceleration": (
                    state.rates[0] / max(state.rates[2], 0.01)
                ),
            }

        # Periodic cleanup across all shards (non-blocking attempt)
        now = time.monotonic()
        if now - self._last_cleanup > self._cleanup_interval:
            if self._cleanup_lock.acquire(blocking=False):
                try:
                    self._cleanup_stale(now)
                    self._last_cleanup = now
                finally:
                    self._cleanup_lock.release()

        return result

    def get_rates(self, entity_key: str) -> Dict[str, float]:
        """Get current rates for an entity without recording an event."""
        shard_idx = self._shard_for(entity_key)
        shard = self._shards[shard_idx]

        with shard["lock"]:
            state = shard["entities"].get(entity_key)
            if state is None:
                return {
                    "entity_event_rate": 0.0,
                    "entity_error_rate": 0.0,
                    "entity_unique_actions": 0.0,
                    "rate_acceleration": 0.0,
                }

            return {
                "entity_event_rate": state.rates[1],
                "entity_error_rate": state.error_rates[1],
                "entity_unique_actions": float(len(state.unique_actions)),
                "rate_acceleration": (
                    state.rates[0] / max(state.rates[2], 0.01)
                ),
            }

    def _cleanup_stale(self, now: float) -> None:
        """Remove entities not accessed in 2× the slow half-life."""
        stale_cutoff = now - (self._half_lives[-1] * 2)
        total_removed = 0

        for shard in self._shards:
            with shard["lock"]:
                stale_keys = [
                    k for k, v in shard["entities"].items()
                    if v.last_access < stale_cutoff
                ]
                for k in stale_keys:
                    del shard["entities"][k]
                total_removed += len(stale_keys)

    def get_stats(self) -> Dict[str, int]:
        """Return tracker statistics."""
        total_entities = 0
        for shard in self._shards:
            with shard["lock"]:
                total_entities += len(shard["entities"])

        return {
            "total_entities": total_entities,
            "num_shards": self._num_shards,
            "half_lives": self._half_lives,
        }


class CrossHostCorrelator:
    """
    Tracks recent anomalous events across hosts to detect coordinated attacks.

    Maintains a time-windowed count of hosts showing anomalous behavior.
    When multiple hosts exhibit similar anomalies within the correlation
    window, the cross_host_correlation count increases, boosting scores
    for potential campaign detection.
    """

    def __init__(
        self,
        window_sec: float = 900.0,
        min_score: float = 0.50,
    ):
        self._window_sec = window_sec
        self._min_score = min_score
        self._lock = threading.Lock()
        # List of (timestamp, hostname) for anomalous events
        self._recent_anomalies: List[Tuple[float, str]] = []

    def record(self, timestamp: float, hostname: str, score: float) -> int:
        """
        Record an event and return the count of distinct hosts
        showing anomalies in the correlation window.
        """
        if score < self._min_score:
            return 0

        with self._lock:
            self._recent_anomalies.append((timestamp, hostname))

            # Prune old entries
            cutoff = timestamp - self._window_sec
            self._recent_anomalies = [
                (ts, h) for ts, h in self._recent_anomalies
                if ts >= cutoff
            ]

            # Count distinct hosts
            unique_hosts = set(h for _, h in self._recent_anomalies)
            return len(unique_hosts)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            unique_hosts = set(h for _, h in self._recent_anomalies)
            return {
                "tracked_anomalous_events": len(self._recent_anomalies),
                "unique_anomalous_hosts": len(unique_hosts),
            }
