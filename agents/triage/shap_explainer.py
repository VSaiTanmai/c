"""
CLIF Triage Agent v7 — Async SHAP Feature Attribution
========================================================
Perturbation-based feature attribution for escalated events.

v7 changes:
  - Async queue: SHAP runs in a background thread, does NOT block
    the main scoring pipeline. Results are delivered asynchronously
    to the output topic.
  - 32-feature vector support
  - Batch perturbation: perturbs all features at once using a
    single (F+1, 32) matrix instead of F sequential calls.
  - Configurable queue depth and batch size
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

import config
from feature_extractor import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger("clif.triage.shap")


class FeatureAttributor:
    """
    Perturbation-based feature attribution for the LightGBM ONNX model.

    For each escalated event, creates a (F+1, 32) perturbation matrix:
      Row 0: original event
      Row i: event with feature i zeroed out

    One batched model call computes all perturbation scores at once.
    """

    def __init__(self, lgbm_model: Any) -> None:
        self._model = lgbm_model

    def explain(self, X_single: np.ndarray) -> Tuple[str, str]:
        """
        Compute feature attributions for a single event.

        Args:
            X_single: shape (1, 32) float32

        Returns:
            (shap_top_features_json, shap_summary_text)
        """
        try:
            # Build perturbation matrix: (33, 32)
            n_feat = X_single.shape[1]
            perturb = np.tile(X_single, (n_feat + 1, 1))  # (33, 32)
            for i in range(n_feat):
                perturb[i + 1, i] = 0.0

            # Single batched model call
            scores = self._model.predict_batch(perturb.astype(np.float32))
            base_score = float(scores[0])

            # Feature contributions
            contributions: List[Tuple[str, float, float]] = []
            for i in range(n_feat):
                delta = base_score - float(scores[i + 1])
                contributions.append((
                    FEATURE_NAMES[i],
                    round(delta, 6),
                    round(float(X_single[0, i]), 4),
                ))

            contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            top_5 = contributions[:5]

            shap_json = json.dumps(
                {name: {"contribution": delta, "value": val} for name, delta, val in top_5},
                default=str,
            )

            parts = []
            for name, delta, val in top_5:
                direction = "+" if delta > 0 else ""
                parts.append(f"{name}={val} ({direction}{delta:.4f})")
            summary = f"Score {base_score:.4f} driven by: {', '.join(parts)}"

            return shap_json, summary

        except Exception as e:
            logger.warning("Feature attribution failed: %s", e)
            return "{}", ""


class AsyncSHAPWorker:
    """
    Background thread that processes SHAP explanation requests.
    Escalated events are enqueued without blocking the main pipeline.
    Results are delivered via a callback function.
    """

    def __init__(
        self,
        lgbm_model: Any,
        result_callback: Callable[[str, str, str], None],
        max_queue_size: int = 1000,
    ):
        """
        Args:
            lgbm_model: LightGBMONNX instance
            result_callback: fn(event_id, shap_json, shap_summary)
            max_queue_size: max pending SHAP requests
        """
        self._attributor = FeatureAttributor(lgbm_model)
        self._callback = result_callback
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._total_processed = 0
        self._total_dropped = 0

    def start(self) -> None:
        """Start the background SHAP worker thread."""
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._worker_loop,
            name="shap-worker",
            daemon=True,
        )
        self._thread.start()
        logger.info("Async SHAP worker started (queue_size=%d)", self._queue.maxsize)

    def stop(self) -> None:
        """Signal the worker to stop and wait for drain."""
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info(
            "Async SHAP worker stopped (processed=%d, dropped=%d)",
            self._total_processed, self._total_dropped,
        )

    def enqueue(self, event_id: str, X_single: np.ndarray) -> bool:
        """
        Enqueue an escalated event for SHAP computation.
        Returns False if the queue is full (non-blocking).
        """
        try:
            self._queue.put_nowait((event_id, X_single))
            return True
        except queue.Full:
            self._total_dropped += 1
            return False

    def _worker_loop(self) -> None:
        """Process SHAP requests until stopped."""
        while not self._stop.is_set():
            try:
                event_id, X_single = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                shap_json, shap_summary = self._attributor.explain(X_single)
                self._callback(event_id, shap_json, shap_summary)
                self._total_processed += 1
            except Exception as e:
                logger.error("SHAP worker error for %s: %s", event_id, e)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "queue_size": self._queue.qsize(),
            "total_processed": self._total_processed,
            "total_dropped": self._total_dropped,
            "alive": self._thread.is_alive() if self._thread else False,
        }
