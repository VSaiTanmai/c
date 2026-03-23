"""
CLIF Triage Agent — SHAP-like Feature Attribution
====================================================
Computes per-feature score contributions for escalated events using
perturbation-based attribution against the LightGBM ONNX model.

For each escalated event, we zero-out each feature individually and
measure the score delta — features that cause the biggest drop when
removed are the most important for that specific prediction.

This runs ONLY for escalated events (action == "escalate") to avoid
adding latency to the 95%+ of events that are discarded/monitored.

Output populates two fields on TriageResult:
    shap_top_features: JSON string of top-5 feature→contribution pairs
    shap_summary:      Human-readable sentence explaining the prediction
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("clif.triage.shap")


class FeatureAttributor:
    """
    Perturbation-based feature attribution for ONNX LightGBM predictions.

    Computes the marginal contribution of each feature by measuring the
    score delta when that feature is replaced with a baseline value (0.0).
    """

    def __init__(self, lgbm_model: Any, feature_names: List[str]) -> None:
        """
        Args:
            lgbm_model: LightGBMONNX instance with a predict_batch method.
            feature_names: Ordered list of feature column names.
        """
        self._model = lgbm_model
        self._feature_names = feature_names
        self._num_features = len(feature_names)

    def explain(self, X_single: np.ndarray) -> Tuple[str, str]:
        """
        Compute feature attributions for a single event.

        Args:
            X_single: shape (1, num_features) float32 array.

        Returns:
            (shap_top_features_json, shap_summary_text)
        """
        try:
            base_score = float(self._model.predict_batch(X_single)[0])

            # Compute per-feature deltas
            contributions: List[Tuple[str, float, float]] = []
            for i in range(self._num_features):
                perturbed = X_single.copy()
                perturbed[0, i] = 0.0
                perturbed_score = float(self._model.predict_batch(perturbed)[0])
                delta = base_score - perturbed_score
                contributions.append(
                    (self._feature_names[i], round(delta, 6), round(float(X_single[0, i]), 4))
                )

            # Sort by absolute contribution (most impactful first)
            contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            top_5 = contributions[:5]

            # Build JSON output
            shap_json = json.dumps(
                {name: {"contribution": delta, "value": val} for name, delta, val in top_5},
                default=str,
            )

            # Build human-readable summary
            parts = []
            for name, delta, val in top_5:
                direction = "+" if delta > 0 else ""
                parts.append(f"{name}={val} ({direction}{delta:.4f})")
            summary = f"Score {base_score:.4f} driven by: {', '.join(parts)}"

            return shap_json, summary

        except Exception as e:
            logger.warning("Feature attribution failed: %s", e)
            return "{}", ""

    def explain_batch_escalated(
        self,
        X: np.ndarray,
        actions: List[str],
    ) -> List[Tuple[str, str]]:
        """
        Compute attributions only for escalated events in a batch.

        Args:
            X: shape (N, num_features) float32 array.
            actions: list of routing decisions, one per event.

        Returns:
            List of (shap_top_features_json, shap_summary_text) per event.
            Non-escalated events get ("", "").
        """
        results = []
        for i in range(len(actions)):
            if actions[i] == "escalate":
                x_single = X[i:i+1].copy()
                results.append(self.explain(x_single))
            else:
                results.append(("", ""))
        return results
