"""
CLIF Triage Agent v7 — Kill-Chain State Machine
===================================================
Per-host attack stage progression tracking with decay.

Tracks the MITRE-aligned kill-chain position for each host based
on the sequence of suspicious actions observed. Used to:
  1. Provide kill_chain_stage and kill_chain_velocity features
  2. Boost scores for events at advanced attack stages
  3. Pass kill-chain context to Hunter for investigation prioritization

Stages:
  0 = none       — No suspicious activity
  1 = recon      — Enumeration, scanning, failed auth probing
  2 = access     — Initial access (successful auth after failures)
  3 = execution  — Process creation, command execution
  4 = persistence — Config changes, service installation, scheduled tasks
  5 = exfil      — Data access, large transfers, unusual destinations

Memory: ~100 bytes per host. 100K hosts = 10 MB.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple

import config


@dataclass
class _HostState:
    """Mutable kill-chain state for a single host."""

    stage: int = 0
    last_update: float = 0.0
    transitions: List[float] = field(default_factory=list)
    stage_events: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        # Compute velocity from transitions
        velocity = 0.0
        if len(self.transitions) >= 2:
            intervals = [
                self.transitions[i] - self.transitions[i - 1]
                for i in range(1, len(self.transitions))
            ]
            avg_interval = sum(intervals) / len(intervals)
            velocity = 1.0 / max(avg_interval, 1.0)
        return {
            "stage": self.stage,
            "velocity": velocity,
            "transitions": self.transitions[-10:],
            "stage_events": self.stage_events[-10:],
        }


# Map action_type → kill-chain stage (only advances, never retreats)
_STAGE_MAP = {
    0: 0,   # info → none
    1: 1,   # auth_attempt → recon
    2: 2,   # auth_success → access (especially after failures)
    3: 1,   # auth_fail → recon
    4: 3,   # process_create → execution
    5: 0,   # process_terminate → none
    6: 0,   # network_connect → none (normal)
    7: 1,   # network_deny → recon (probing)
    8: 4,   # policy_change → persistence
    9: 3,   # privilege_use → execution
    10: 5,  # data_access → exfil
    11: 4,  # config_change → persistence
}


class KillChainTracker:
    """
    Per-host attack stage progression with decay.

    Thread-safe via sharded locks. Each host independently tracks
    its current kill-chain stage and the velocity of stage transitions.
    """

    NUM_SHARDS = 16

    def __init__(
        self,
        decay_sec: float = 3600.0,
        score_gate: float = 0.30,
    ):
        self._decay_sec = decay_sec
        self._score_gate = score_gate

        self._shards: List[Dict] = [
            {"lock": threading.Lock(), "hosts": {}}
            for _ in range(self.NUM_SHARDS)
        ]

    def _shard_for(self, hostname: str) -> int:
        return hash(hostname) % self.NUM_SHARDS

    def update(
        self,
        hostname: str,
        action_type: int,
        score: float,
        timestamp: float,
        event_id: str = "",
    ) -> Tuple[int, float]:
        """
        Update kill-chain state for a host and return current stage info.

        Only advances the stage if:
          1. The new stage > current stage (forward progression)
          2. The event score > score_gate (event is suspicious)

        Decays to stage 0 after decay_sec of inactivity.

        Args:
            hostname: Host identifier.
            action_type: Numeric action type (0-11).
            score: Combined triage score for this event.
            timestamp: Monotonic timestamp.
            event_id: Event UUID for audit trail.

        Returns:
            Tuple of (current_stage, stage_velocity).
            velocity = transitions per second (0 if no progression).
        """
        shard_idx = self._shard_for(hostname)
        shard = self._shards[shard_idx]

        with shard["lock"]:
            state = shard["hosts"].get(hostname)
            if state is None:
                state = _HostState(last_update=timestamp)
                shard["hosts"][hostname] = state

            # Check decay
            elapsed_since_last = timestamp - state.last_update
            if elapsed_since_last > self._decay_sec:
                state.stage = 0
                state.transitions.clear()
                state.stage_events.clear()

            # Determine new stage from action type
            new_stage = _STAGE_MAP.get(action_type, 0)

            # Only advance if forward AND event is suspicious
            if new_stage > state.stage and score > self._score_gate:
                transition_time = timestamp - state.last_update
                state.transitions.append(transition_time)
                state.stage = new_stage
                state.last_update = timestamp

                # Record stage event for Hunter context
                state.stage_events.append({
                    "stage": new_stage,
                    "event_id": event_id,
                    "timestamp": timestamp,
                })
            elif score > self._score_gate:
                # Suspicious event at same or lower stage — update timestamp
                state.last_update = timestamp

            # Compute velocity (transitions per second)
            velocity = 0.0
            if len(state.transitions) >= 2:
                recent = state.transitions[-5:]
                avg_interval = sum(recent) / len(recent)
                velocity = 1.0 / max(avg_interval, 1.0)

            return state.stage, velocity

    def get_host_state(self, hostname: str) -> Optional[Dict]:
        """Get the full kill-chain state for a host (for Hunter context)."""
        shard_idx = self._shard_for(hostname)
        shard = self._shards[shard_idx]

        with shard["lock"]:
            state = shard["hosts"].get(hostname)
            if state is None:
                return None
            return state.to_dict()

    def get_stats(self) -> Dict[str, int]:
        """Return tracker statistics."""
        total_hosts = 0
        stage_counts = {i: 0 for i in range(6)}

        for shard in self._shards:
            with shard["lock"]:
                for state in shard["hosts"].values():
                    total_hosts += 1
                    stage_counts[state.stage] = stage_counts.get(state.stage, 0) + 1

        return {
            "tracked_hosts": total_hosts,
            "stage_distribution": stage_counts,
        }

    def cleanup_stale(self, now: float) -> int:
        """Remove hosts with no activity for 2× decay period."""
        cutoff = now - (self._decay_sec * 2)
        total_removed = 0

        for shard in self._shards:
            with shard["lock"]:
                stale = [
                    k for k, v in shard["hosts"].items()
                    if v.last_update < cutoff
                ]
                for k in stale:
                    del shard["hosts"][k]
                total_removed += len(stale)

        return total_removed
