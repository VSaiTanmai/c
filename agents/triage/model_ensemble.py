"""
CLIF Triage Agent v7 — 2-Model Ensemble
==========================================
Loads and runs batched inference on:
  1. LightGBM  (ONNX)  — supervised classifier  (weight 0.85)
  2. Autoencoder (ONNX) — reconstruction anomaly  (weight 0.15)

Both models expect a 32-feature vector in canonical order.

v7 changes vs v6:
  - Removed EIF  (Δ0.03 discrimination, noise)
  - Removed ARF  (constant probs after pickle, throughput bottleneck)
  - Added Autoencoder with per-source-type calibration
  - Single-call batch inference (no row-by-row loop)
  - Feature scaler loaded from JSON (same scaler used in training)
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

import config
from feature_extractor import FEATURE_NAMES, NUM_FEATURES

logger = logging.getLogger("clif.triage.ensemble")


# ── Feature Scaler ──────────────────────────────────────────────────────────

class FeatureScaler:
    """
    Z-score feature normalization with per-feature mean/std.
    The autoencoder was trained on scaled features; LightGBM
    handles unscaled features natively but we normalize for
    consistency.
    """

    def __init__(self, scaler_path: str):
        path = Path(scaler_path)
        if not path.exists():
            logger.warning("Feature scaler not found at %s — using identity", scaler_path)
            self._mean = np.zeros(NUM_FEATURES, dtype=np.float32)
            self._std = np.ones(NUM_FEATURES, dtype=np.float32)
            self._loaded = False
            return

        with open(path, "r") as f:
            data = json.load(f)

        self._mean = np.array(data["mean"], dtype=np.float32)
        self._std = np.array(data["std"], dtype=np.float32)
        # Avoid division by zero
        self._std[self._std < 1e-8] = 1.0
        self._loaded = True

        if len(self._mean) != NUM_FEATURES:
            raise ValueError(
                f"Scaler has {len(self._mean)} features but expected {NUM_FEATURES}"
            )
        logger.info("Feature scaler loaded from %s (%d features)", scaler_path, NUM_FEATURES)

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Scale features: (X - mean) / std. Input shape: (N, 32)."""
        return (X - self._mean) / self._std

    @property
    def is_loaded(self) -> bool:
        return self._loaded


# ── LightGBM ONNX ──────────────────────────────────────────────────────────

class LightGBMONNX:
    """
    LightGBM served via ONNX Runtime for deterministic, batched inference.
    Outputs anomaly probability in [0, 1].
    """

    def __init__(self, model_path: str):
        import onnxruntime as ort

        if not Path(model_path).exists():
            raise FileNotFoundError(f"LightGBM ONNX model not found: {model_path}")

        self._session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
            sess_options=self._session_options(),
        )
        self._input_name = self._session.get_inputs()[0].name
        logger.info(
            "LightGBM ONNX loaded: %s (input=%s)",
            model_path, self._input_name,
        )

    @staticmethod
    def _session_options():
        import onnxruntime as ort

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        return opts

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly probabilities for a batch.

        Args:
            X: shape (N, 32), float32

        Returns:
            scores: shape (N,), float64, probability of class=1 (anomalous)
        """
        if X.dtype != np.float32:
            X = X.astype(np.float32)

        results = self._session.run(None, {self._input_name: X})

        # ONNX LightGBM classifiers output [labels, probabilities_list]
        if len(results) >= 2:
            prob_list = results[1]
            scores = np.array(
                [d.get(1, d.get("1", 0.0)) for d in prob_list],
                dtype=np.float64,
            )
        else:
            scores = np.array(results[0], dtype=np.float64).flatten()

        return np.clip(scores, 0.0, 1.0)


# ── Autoencoder ONNX ────────────────────────────────────────────────────────

class AutoencoderONNX:
    """
    Autoencoder anomaly detector served via ONNX Runtime.

    Architecture (trained):
        32 → 64 → 32 → 16 → 8 → 16 → 32 → 64 → 32

    Anomaly score = reconstruction_error / p99_training_error
    Per-source-type calibration normalizes across log heterogeneity.
    """

    def __init__(self, model_path: str, calibration_path: str):
        import onnxruntime as ort

        if not Path(model_path).exists():
            raise FileNotFoundError(f"Autoencoder ONNX not found: {model_path}")

        self._session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
            sess_options=self._session_options(),
        )
        self._input_name = self._session.get_inputs()[0].name

        # Load per-source-type calibration
        self._calibration = self._load_calibration(calibration_path)

        logger.info(
            "Autoencoder ONNX loaded: %s (calibration types: %d)",
            model_path, len(self._calibration),
        )

    @staticmethod
    def _session_options():
        import onnxruntime as ort

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 1
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        return opts

    @staticmethod
    def _load_calibration(path: str) -> Dict[str, Dict[str, float]]:
        """
        Load per-source-type calibration: {source_type: {p99_error, p50_error}}.
        Falls back to a global default if file not found.
        """
        cal_path = Path(path)
        if not cal_path.exists():
            logger.warning(
                "AE calibration not found at %s — using default p99=0.05", path
            )
            return {"_default": {"p99_error": 0.05, "p50_error": 0.01}}

        with open(cal_path, "r") as f:
            data = json.load(f)

        # Validate structure
        if "_default" not in data:
            data["_default"] = {"p99_error": 0.05, "p50_error": 0.01}

        return data

    def predict_batch(
        self,
        X_scaled: np.ndarray,
        source_types: Optional[List[str]] = None,
    ) -> np.ndarray:
        """
        Predict anomaly scores via reconstruction error.

        Args:
            X_scaled: shape (N, 32), float32 — ALREADY z-scaled
            source_types: list of N source type strings for calibration

        Returns:
            scores: shape (N,), float64 in [0, 1]
        """
        if X_scaled.dtype != np.float32:
            X_scaled = X_scaled.astype(np.float32)

        # Forward pass: input → reconstruction
        results = self._session.run(None, {self._input_name: X_scaled})
        reconstructed = results[0]  # shape (N, 32)

        # MSE per-sample
        mse = np.mean((X_scaled - reconstructed) ** 2, axis=1)  # (N,)

        # Per-source-type calibration
        n = len(mse)
        scores = np.zeros(n, dtype=np.float64)
        default_cal = self._calibration["_default"]

        if source_types and len(source_types) == n:
            for i in range(n):
                cal = self._calibration.get(source_types[i], default_cal)
                p99 = cal.get("p99_error", default_cal["p99_error"])
                if p99 < 1e-10:
                    p99 = default_cal["p99_error"]
                scores[i] = mse[i] / p99
        else:
            p99 = default_cal["p99_error"]
            scores = mse / max(p99, 1e-10)

        return np.clip(scores, 0.0, 1.0)

    def get_reconstruction_errors(self, X_scaled: np.ndarray) -> np.ndarray:
        """Return raw MSE per sample (for calibration and monitoring)."""
        if X_scaled.dtype != np.float32:
            X_scaled = X_scaled.astype(np.float32)
        results = self._session.run(None, {self._input_name: X_scaled})
        reconstructed = results[0]
        return np.mean((X_scaled - reconstructed) ** 2, axis=1)


# ── Model Manifest ──────────────────────────────────────────────────────────

def load_manifest(manifest_path: str) -> Dict[str, Any]:
    """
    Load model manifest with version, feature list, training metadata.
    Used for version tracking and train/serve skew detection.
    """
    path = Path(manifest_path)
    if not path.exists():
        logger.warning("Model manifest not found at %s", manifest_path)
        return {
            "version": "v7-unknown",
            "features": FEATURE_NAMES,
            "num_features": NUM_FEATURES,
        }

    with open(path, "r") as f:
        manifest = json.load(f)

    # Validate feature list matches
    manifest_features = manifest.get("features", [])
    if manifest_features and manifest_features != FEATURE_NAMES:
        logger.error(
            "TRAIN/SERVE SKEW: Manifest features (%d) != extractor features (%d)",
            len(manifest_features), NUM_FEATURES,
        )
        mismatched = [
            (i, mf, ef)
            for i, (mf, ef) in enumerate(zip(manifest_features, FEATURE_NAMES))
            if mf != ef
        ]
        for idx, mf, ef in mismatched[:5]:
            logger.error("  Feature %d: manifest=%s, extractor=%s", idx, mf, ef)

    return manifest


# ── Ensemble Orchestrator ───────────────────────────────────────────────────

class ModelEnsemble:
    """
    2-model ensemble: LightGBM + Autoencoder.

    Provides batch inference with weighted score fusion.
    Score fusion post-processing (kill-chain, cross-host, IOC)
    is handled by the ScoreFusion class.
    """

    def __init__(self):
        self._lgbm: Optional[LightGBMONNX] = None
        self._autoencoder: Optional[AutoencoderONNX] = None
        self._scaler: Optional[FeatureScaler] = None
        self._manifest: Dict[str, Any] = {}
        self._ready = False
        self._load_time_ms = 0.0

    def load(self) -> None:
        """Load all models, scaler, and manifest. Called once at startup."""
        t0 = time.monotonic()

        # Load manifest first (for version validation)
        self._manifest = load_manifest(config.MANIFEST_PATH)
        logger.info("Model manifest: version=%s", self._manifest.get("version", "?"))

        # Feature scaler (required for autoencoder)
        self._scaler = FeatureScaler(config.FEATURE_SCALER_PATH)

        # LightGBM
        self._lgbm = LightGBMONNX(config.MODEL_LGBM_PATH)

        # Autoencoder
        self._autoencoder = AutoencoderONNX(
            config.MODEL_AUTOENCODER_PATH,
            config.MODEL_AE_CALIBRATION_PATH,
        )

        self._load_time_ms = (time.monotonic() - t0) * 1000
        self._ready = True
        logger.info("Ensemble loaded in %.1f ms", self._load_time_ms)

    def predict_batch(
        self,
        X: np.ndarray,
        source_types: Optional[List[str]] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Run both models on a batch of 32-feature vectors.

        Args:
            X: shape (N, 32), float32 — raw (unscaled) feature matrix
            source_types: list of N source type strings for AE calibration

        Returns:
            Dict with:
                "lgbm_scores":  (N,) float64
                "ae_scores":    (N,) float64
                "combined":     (N,) float64 — weighted sum
        """
        if not self._ready:
            raise RuntimeError("ModelEnsemble.load() not called")

        n = X.shape[0]

        # LightGBM: uses raw features (tree models are scale-invariant)
        lgbm_scores = self._lgbm.predict_batch(X)

        # Autoencoder: uses z-scaled features
        X_scaled = self._scaler.transform(X)
        X_scaled[:, config.AE_MASKED_INDICES] = 0.0  # mask stateful features
        ae_scores = self._autoencoder.predict_batch(X_scaled, source_types)

        # Weighted combination
        combined = (
            lgbm_scores * config.LGBM_WEIGHT
            + ae_scores * config.AUTOENCODER_WEIGHT
        )
        combined = np.clip(combined, 0.0, 1.0)

        return {
            "lgbm_scores": lgbm_scores,
            "ae_scores": ae_scores,
            "combined": combined,
        }

    def selftest(self) -> bool:
        """
        Run a self-test with synthetic data to verify model loading.
        Called at startup before accepting Kafka messages.
        """
        try:
            X_test = np.random.randn(10, NUM_FEATURES).astype(np.float32)
            result = self.predict_batch(X_test)

            for key in ("lgbm_scores", "ae_scores", "combined"):
                assert key in result, f"Missing key: {key}"
                assert result[key].shape == (10,), f"Bad shape for {key}"
                assert np.all(np.isfinite(result[key])), f"Non-finite in {key}"

            logger.info(
                "Selftest passed: lgbm=[%.4f,%.4f], ae=[%.4f,%.4f], combined=[%.4f,%.4f]",
                result["lgbm_scores"].min(), result["lgbm_scores"].max(),
                result["ae_scores"].min(), result["ae_scores"].max(),
                result["combined"].min(), result["combined"].max(),
            )
            return True

        except Exception as e:
            logger.error("Selftest FAILED: %s", e, exc_info=True)
            return False

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def manifest(self) -> Dict[str, Any]:
        return self._manifest

    def get_stats(self) -> Dict[str, Any]:
        return {
            "ready": self._ready,
            "load_time_ms": self._load_time_ms,
            "manifest_version": self._manifest.get("version", "unknown"),
            "scaler_loaded": self._scaler.is_loaded if self._scaler else False,
            "feature_count": NUM_FEATURES,
            "lgbm_weight": config.LGBM_WEIGHT,
            "ae_weight": config.AUTOENCODER_WEIGHT,
        }
