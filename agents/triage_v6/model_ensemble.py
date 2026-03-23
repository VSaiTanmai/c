"""
CLIF Triage Agent — 3-Model Ensemble
========================================
Loads and runs inference on:
  1. LightGBM (ONNX)     — supervised classifier, 50 % weight
  2. Extended Isolation Forest (EIF) — unsupervised anomaly detector, 30 % weight
  3. Adaptive Random Forest (River ARF) — online learner, 20 % weight

All three models expect the same 20 canonical features.

CRITICAL — ARF Warm Restart:
  After pickle.load(), River ARF models return CONSTANT probabilities
  (upstream River bug). The pickle file is retained as an offline reference
  but is NEVER loaded for production inference. Instead, production uses
  the *warm restart* approach:
    1. Create a fresh ARFClassifier with identical hyperparameters.
    2. Replay the last 24 h / 50 K events from the ClickHouse
       arf_replay_buffer table (chronological ORDER BY timestamp).
    3. Each replayed row is fed through learn_one() to rebuild
       Hoeffding trees + ADWIN drift/warning detectors.
    4. Cold-start fallback: stream from the offline training CSV.
  After warm restart, predict_proba_one() returns correct, varying values.
"""

from __future__ import annotations

import csv
import json
import logging
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np

import config

logger = logging.getLogger("clif.triage.ensemble")


class LightGBMONNX:
    """
    LightGBM model served via ONNX Runtime for deterministic, high-perf inference.
    Outputs anomaly probability in [0, 1].
    """

    def __init__(self, model_path: str, feature_cols: List[str]):
        import onnxruntime as ort

        if not Path(model_path).exists():
            raise FileNotFoundError(f"LightGBM ONNX model not found: {model_path}")

        self._session = ort.InferenceSession(
            model_path,
            providers=["CPUExecutionProvider"],
            sess_options=self._get_options(),
        )
        self._input_name = self._session.get_inputs()[0].name
        self._feature_cols = feature_cols
        logger.info(
            "LightGBM ONNX loaded: %s (input=%s, features=%d)",
            model_path,
            self._input_name,
            len(feature_cols),
        )

    @staticmethod
    def _get_options():
        import onnxruntime as ort

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 2
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        return opts

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for a batch.

        Args:
            X: shape (N, 20) float32

        Returns:
            scores: shape (N,) float64, probability of being anomalous.
        """
        if X.dtype != np.float32:
            X = X.astype(np.float32)

        # ONNX LightGBM classifiers output [label, probabilities_map]
        results = self._session.run(None, {self._input_name: X})

        # results[1] is a list of dicts like [{0: 0.9, 1: 0.1}]
        if len(results) >= 2:
            prob_list = results[1]
            # Extract probability for the positive class (1 = anomalous)
            scores = np.array(
                [d.get(1, d.get("1", 0.0)) for d in prob_list], dtype=np.float64
            )
        else:
            # Single output — assume it's the score directly
            scores = np.array(results[0], dtype=np.float64).flatten()

        return np.clip(scores, 0.0, 1.0)


class ExtendedIsolationForest:
    """
    Extended Isolation Forest — trained on normal-only data.
    Scores represent isolation-based anomaly measure in [0, 1].
    Higher = more anomalous.

    CALIBRATED NORMALIZATION:
      Uses training-time mean/std of raw path lengths for z-score
      normalization, loaded from eif_calibration.npz. This ensures
      the same event always gets the same score regardless of what
      else is in the batch (fixing the batch-dependent scoring bug).
    """

    def __init__(self, model_path: str, threshold_path: str,
                 calibration_path: Optional[str] = None):
        if not Path(model_path).exists():
            raise FileNotFoundError(f"EIF model not found: {model_path}")

        self._model = joblib.load(model_path)
        self._threshold = float(np.load(threshold_path)) if Path(threshold_path).exists() else 0.4277

        # Load training-calibrated normalization parameters
        self._cal_mean: Optional[float] = None
        self._cal_std: Optional[float] = None
        self._score_flip: bool = False
        cal_path = calibration_path or str(Path(model_path).parent / "eif_calibration.npz")
        if Path(cal_path).exists():
            cal = np.load(cal_path)
            self._cal_mean = float(cal["path_mean"])
            self._cal_std = float(cal["path_std"])
            # score_flip: when EIF discrimination is inverted (normal > malicious),
            # flip the sigmoid so higher scores still mean more anomalous.
            if "score_flip" in cal:
                self._score_flip = bool(int(cal["score_flip"]))
            logger.info(
                "EIF loaded: %s (threshold=%.4f, cal_mean=%.4f, cal_std=%.4f, flip=%s)",
                model_path, self._threshold, self._cal_mean, self._cal_std, self._score_flip,
            )
        else:
            logger.warning(
                "EIF calibration file not found at %s — "
                "falling back to per-batch normalization (LESS STABLE)",
                cal_path,
            )
            logger.info(
                "EIF loaded: %s (threshold=%.4f, NO calibration)",
                model_path, self._threshold,
            )

    def predict_batch(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly scores for a batch.

        Returns:
            scores: shape (N,) float64 in [0, 1].
            Uses path-length normalization with FIXED training statistics:
              z = (raw - training_mean) / training_std
              score = 1 / (1 + exp(z))   (shorter path -> higher score)
        """
        if X.dtype != np.float64:
            X = X.astype(np.float64)

        # Defensive: replace inf/NaN before computing paths
        X = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)

        raw_scores = self._model.compute_paths(X_in=X)

        # Use FIXED training statistics for normalization (not per-batch)
        if self._cal_mean is not None and self._cal_std is not None:
            std_s = self._cal_std
            mean_s = self._cal_mean
        else:
            # Fallback: per-batch (legacy behavior, less stable)
            mean_s = float(np.mean(raw_scores)) if len(raw_scores) > 1 else 0.0
            std_s = float(np.std(raw_scores)) if len(raw_scores) > 1 else 1.0

        if std_s > 1e-8:
            z = (raw_scores - mean_s) / std_s
        else:
            z = raw_scores - mean_s

        # Sigmoid: shorter path -> lower raw -> negative z -> higher score
        scores = 1.0 / (1.0 + np.exp(z))

        # When EIF discrimination is inverted (multi-log heterogeneity causes
        # normal data to score higher than malicious), flip the scores so
        # "higher = more anomalous" invariant is maintained.
        if self._score_flip:
            scores = 1.0 - scores

        return np.clip(scores, 0.0, 1.0)

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def is_calibrated(self) -> bool:
        return self._cal_mean is not None and self._cal_std is not None


class AdaptiveRandomForest:
    """
    River ARF + ADWIN online learner — WARM RESTART implementation.

    The pickle checkpoint is NEVER loaded for production inference because
    River's predict_proba_one returns CONSTANT probabilities after
    deserialization (20 % of the fused score would be fabricated).

    Instead we:
      1. Create a FRESH ARFClassifier with identical hyperparameters.
      2. Replay recent events from ClickHouse arf_replay_buffer (last 24 h,
         up to 50 K rows, chronological ORDER BY timestamp).
      3. Cold-start fallback: stream from the offline training CSV.
      4. After replay, predict_proba_one returns correct, varying values.
    """

    def __init__(self, feature_cols: List[str]):
        from river.forest import ARFClassifier
        from river.drift import ADWIN

        self._feature_cols = feature_cols
        self._ready = False
        self._rows_replayed = 0
        self._samples_learned = 0

        # Create a fresh ARF with the EXACT same hyperparameters as training
        self._model = ARFClassifier(
            n_models=config.ARF_N_MODELS,
            drift_detector=ADWIN(delta=config.ARF_ADWIN_DELTA),
            warning_detector=ADWIN(delta=config.ARF_ADWIN_WARNING_DELTA),
            seed=config.ARF_SEED,
        )
        logger.info(
            "ARF fresh model created: n_models=%d, adwin_delta=%.4f, seed=%d",
            config.ARF_N_MODELS,
            config.ARF_ADWIN_DELTA,
            config.ARF_SEED,
        )

    def warm_restart(
        self,
        ch_client=None,
        csv_fallback_path: Optional[str] = None,
    ) -> int:
        """
        Replay historical events through learn_one() to rebuild the
        Hoeffding trees and ADWIN drift detectors.

        Priority:
          1. ClickHouse arf_replay_buffer (last N hours, max M rows)
          2. Offline training CSV fallback

        Returns:
            Number of rows replayed.
        """
        rows_replayed = 0

        # ─── Try ClickHouse replay buffer first ────────────────────────
        if ch_client is not None:
            try:
                rows_replayed = self._replay_from_clickhouse(ch_client)
            except Exception as e:
                logger.warning(
                    "ClickHouse replay failed (%s) — falling back to CSV", e
                )
                rows_replayed = 0

        # ─── CSV cold-start fallback ───────────────────────────────────
        if rows_replayed == 0 and csv_fallback_path:
            csv_path = Path(csv_fallback_path)
            if csv_path.exists():
                rows_replayed = self._replay_from_csv(csv_path)
            else:
                logger.warning("ARF CSV fallback not found: %s", csv_fallback_path)

        self._rows_replayed = rows_replayed
        self._ready = rows_replayed > 0

        if self._ready:
            # Verify proba produces varying output after warm restart
            self._verify_proba()
            logger.info(
                "ARF warm restart complete: %d rows replayed, model ready",
                rows_replayed,
            )
        else:
            logger.warning(
                "ARF warm restart: 0 rows available — model will cold-start. "
                "Predictions will be 0.5 (uninformed prior) until replay buffer populates."
            )
            # Mark ready even with 0 rows — uninformed prior is better than crash
            self._ready = True

        return rows_replayed

    def _replay_from_clickhouse(self, ch_client) -> int:
        """Replay rows from arf_replay_buffer, chronological order."""
        query = (
            "SELECT {cols}, label FROM clif_logs.arf_replay_buffer "
            "WHERE timestamp >= now() - INTERVAL {hours} HOUR "
            "ORDER BY timestamp ASC "
            "LIMIT {limit}"
        ).format(
            cols=", ".join(self._feature_cols),
            hours=config.ARF_REPLAY_HOURS,
            limit=config.ARF_REPLAY_MAX_ROWS,
        )

        logger.info(
            "ARF replaying from ClickHouse (last %d h, max %d rows)...",
            config.ARF_REPLAY_HOURS,
            config.ARF_REPLAY_MAX_ROWS,
        )

        rows = ch_client.execute(query)
        if not rows:
            logger.info("arf_replay_buffer is empty — no rows to replay")
            return 0

        count = 0
        for row in rows:
            x_dict = {
                self._feature_cols[j]: float(row[j])
                for j in range(len(self._feature_cols))
            }
            y = int(row[-1])  # label column is last
            self._model.learn_one(x_dict, y)
            count += 1

        logger.info("ARF replayed %d rows from ClickHouse", count)
        return count

    def _replay_from_csv(self, csv_path: Path) -> int:
        """Replay rows from offline training CSV (cold-start fallback)."""
        logger.info("ARF cold-start: replaying from CSV %s ...", csv_path)

        count = 0
        max_rows = config.ARF_REPLAY_MAX_ROWS

        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row_dict in reader:
                if count >= max_rows:
                    break

                # Extract label (column name: 'label' or 'is_anomaly')
                label_val = row_dict.pop("label", row_dict.pop("is_anomaly", "0"))
                y = int(float(label_val))

                # Build feature dict using only the canonical columns
                x_dict = {}
                for col in self._feature_cols:
                    raw = row_dict.get(col, "0")
                    try:
                        x_dict[col] = float(raw)
                    except (ValueError, TypeError):
                        x_dict[col] = 0.0

                self._model.learn_one(x_dict, y)
                count += 1

        logger.info("ARF replayed %d rows from CSV", count)
        return count

    def _verify_proba(self) -> None:
        """Verify predict_proba_one returns varying output after warm restart."""
        try:
            d1 = {col: 0.0 for col in self._feature_cols}
            d2 = {col: 100.0 for col in self._feature_cols}
            p1 = self._model.predict_proba_one(d1)
            p2 = self._model.predict_proba_one(d2)

            v1 = p1.get(1, p1.get("1", 0.5))
            v2 = p2.get(1, p2.get("1", 0.5))

            if abs(v1 - v2) < 1e-9:
                logger.error(
                    "ARF PROBA STILL CONSTANT after warm restart! "
                    "p1=%.6f, p2=%.6f — this should not happen with warm restart.",
                    v1, v2,
                )
            else:
                logger.info(
                    "ARF proba verified varying: p(all-zeros)=%.4f, p(all-100s)=%.4f, "
                    "delta=%.6f",
                    v1, v2, abs(v1 - v2),
                )
        except Exception as e:
            logger.warning("ARF proba verification failed: %s", e)

    def learn_one(self, x_dict: Dict[str, float], y: int) -> None:
        """Online learning — called on each scored event for continuous adaptation."""
        self._model.learn_one(x_dict, y)
        self._samples_learned += 1

    @property
    def confidence(self) -> float:
        """
        ARF confidence level (0.0-1.0) based on how many samples it has learned.
        Ramps up from 0 to 1.0 over ARF_CONFIDENCE_RAMP_SAMPLES events.
        Used by ScoreFusion for dynamic weighting — avoids dead-weight
        during cold start when ARF returns near-constant scores.
        """
        total = self._rows_replayed + self._samples_learned
        ramp = config.ARF_CONFIDENCE_RAMP_SAMPLES
        return min(1.0, total / ramp) if ramp > 0 else 1.0

    def predict_batch(
        self, X: np.ndarray, feature_names: List[str]
    ) -> np.ndarray:
        """
        Predict anomaly scores for a batch.

        Args:
            X: shape (N, 20) float32
            feature_names: list of feature column names

        Returns:
            scores: shape (N,) float64 in [0, 1].
        """
        scores = np.zeros(X.shape[0], dtype=np.float64)

        for i in range(X.shape[0]):
            row_dict = {
                feature_names[j]: float(X[i, j]) for j in range(len(feature_names))
            }

            proba = self._model.predict_proba_one(row_dict)
            if proba:
                scores[i] = proba.get(1, proba.get("1", 0.5))
            else:
                # Model has not seen enough data yet — uninformed prior
                scores[i] = 0.5

        return np.clip(scores, 0.0, 1.0)

    @property
    def is_ready(self) -> bool:
        return self._ready

    @property
    def rows_replayed(self) -> int:
        return self._rows_replayed


class ModelEnsemble:
    """
    Orchestrates loading and inference across all three models.
    Thread-safe: each model is read-only after initialization
    (ARF continues online learning via learn_one but is GIL-safe).
    """

    def __init__(self):
        self._feature_cols: List[str] = []
        self._manifest: Dict[str, Any] = {}
        self._lgbm: Optional[LightGBMONNX] = None
        self._eif: Optional[ExtendedIsolationForest] = None
        self._arf: Optional[AdaptiveRandomForest] = None
        self._loaded = False

    def load(self, ch_client=None) -> None:
        """
        Load all models and metadata files.

        Args:
            ch_client: ClickHouse client for ARF warm restart replay buffer.
                       If None, ARF falls back to CSV cold-start.
        """
        start = time.monotonic()

        # ─── Load feature column order (AUTHORITATIVE SOURCE) ──────────
        feature_cols_path = Path(config.FEATURE_COLS_PATH)
        if feature_cols_path.exists():
            with open(feature_cols_path, "rb") as f:
                self._feature_cols = pickle.load(f)
            logger.info(
                "Feature columns loaded from %s: %d columns",
                config.FEATURE_COLS_PATH,
                len(self._feature_cols),
            )
        else:
            # feature_cols.pkl is the SINGLE authoritative source of column order.
            # Without it, we cannot guarantee model input alignment.
            logger.critical(
                "CRITICAL: feature_cols.pkl not found at %s! "
                "This file is the single authoritative source of feature column order. "
                "Falling back to hardcoded FEATURE_NAMES — verify this matches training.",
                config.FEATURE_COLS_PATH,
            )
            from feature_extractor import FEATURE_NAMES
            self._feature_cols = list(FEATURE_NAMES)

        # Cross-validate feature columns against the canonical list
        from feature_extractor import FEATURE_NAMES
        if self._feature_cols != list(FEATURE_NAMES):
            logger.warning(
                "feature_cols.pkl order differs from FEATURE_NAMES! "
                "feature_cols.pkl: %s vs FEATURE_NAMES: %s — "
                "INPUT COLUMNS WILL FOLLOW feature_cols.pkl (authoritative).",
                self._feature_cols,
                list(FEATURE_NAMES),
            )

        # ─── Load manifest ─────────────────────────────────────────────
        manifest_path = Path(config.MANIFEST_PATH)
        if manifest_path.exists():
            with open(manifest_path) as f:
                self._manifest = json.load(f)
            logger.info("Manifest loaded: %s", self._manifest.get("version", "unknown"))

        # ─── Load LightGBM ONNX ───────────────────────────────────────
        self._lgbm = LightGBMONNX(config.MODEL_LGBM_PATH, self._feature_cols)

        # ─── Load EIF ──────────────────────────────────────────────────
        self._eif = ExtendedIsolationForest(
            config.MODEL_EIF_PATH,
            config.MODEL_EIF_THRESHOLD_PATH,
            calibration_path=config.MODEL_EIF_CALIBRATION_PATH,
        )

        # ─── ARF warm restart (NOT pickle.load) ───────────────────────
        self._arf = AdaptiveRandomForest(self._feature_cols)
        if config.ARF_WARM_RESTART:
            replay_count = self._arf.warm_restart(
                ch_client=ch_client,
                csv_fallback_path=config.ARF_STREAM_CSV_PATH,
            )
            logger.info("ARF warm restart: %d events replayed", replay_count)
        else:
            logger.warning(
                "ARF_WARM_RESTART=false — ARF will use uninformed prior (0.5). "
                "This means 20%% of the fused score is a constant!"
            )
            self._arf._ready = True

        elapsed = time.monotonic() - start
        self._loaded = True
        logger.info("All 3 models loaded in %.2f seconds", elapsed)

    def predict_batch(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Run all three models on a batch.

        Args:
            X: shape (N, 20) float32 in feature_cols order.

        Returns:
            Dict with keys 'lgbm', 'eif', 'arf', each shape (N,) float64.
            Also includes 'arf_confidence' (0.0-1.0) indicating ARF reliability.
        """
        if not self._loaded:
            raise RuntimeError("Models not loaded. Call load() first.")

        # Defensive: sanitize input — replace inf/NaN before inference
        X_clean = np.nan_to_num(X, nan=0.0, posinf=1e9, neginf=-1e9)
        if X_clean.dtype != np.float32:
            X_clean = X_clean.astype(np.float32)

        lgbm_scores = self._lgbm.predict_batch(X_clean)
        eif_scores = self._eif.predict_batch(X_clean)
        arf_scores = self._arf.predict_batch(X_clean, self._feature_cols)

        return {
            "lgbm": lgbm_scores,
            "eif": eif_scores,
            "arf": arf_scores,
            "arf_confidence": self._arf.confidence,
        }

    @property
    def arf(self) -> Optional[AdaptiveRandomForest]:
        """Expose ARF for online learning in the pipeline."""
        return self._arf

    @property
    def feature_cols(self) -> List[str]:
        return self._feature_cols

    @property
    def manifest(self) -> Dict[str, Any]:
        return self._manifest

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_stats(self) -> Dict[str, Any]:
        return {
            "loaded": self._loaded,
            "manifest": self._manifest,
            "feature_cols_count": len(self._feature_cols),
            "feature_cols": self._feature_cols,
            "lgbm_loaded": self._lgbm is not None,
            "eif_loaded": self._eif is not None,
            "eif_threshold": self._eif.threshold if self._eif else None,
            "eif_calibrated": self._eif.is_calibrated if self._eif else False,
            "arf_loaded": self._arf is not None,
            "arf_ready": self._arf.is_ready if self._arf else False,
            "arf_rows_replayed": self._arf.rows_replayed if self._arf else 0,
            "arf_confidence": self._arf.confidence if self._arf else 0.0,
            "arf_samples_learned": self._arf._samples_learned if self._arf else 0,
            "arf_warm_restart": config.ARF_WARM_RESTART,
        }
