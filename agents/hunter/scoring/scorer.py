"""
Scorer – auto-switching scorer.

Uses the heuristic linear scorer until MIN_TRAINING_SAMPLES training
examples exist in ClickHouse, then switches to CatBoost.

Hot-reload: the CatBoost model is reloaded every MODEL_RELOAD_INTERVAL_SEC
so newly trained weights take effect without a service restart.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import (
    CATBOOST_MODEL_PATH,
    CLICKHOUSE_DATABASE,
    MIN_TRAINING_SAMPLES,
    RETRAIN_INTERVAL_SEC,
)
from models import FEATURE_ORDER, MLResult
from scoring import heuristic_scorer

log = logging.getLogger(__name__)

MODEL_RELOAD_INTERVAL_SEC = 300   # check for updated model every 5 min


class Scorer:
    """
    Wraps heuristic_scorer and optionally CatBoost.
    Thread-safe for async contexts: model reference is replaced atomically.
    """

    def __init__(self, ch_client: Any) -> None:
        self._ch = ch_client
        self._catboost_model: Optional[Any] = None
        self._use_ml: bool = False
        self._model_mtime: float = 0.0

    # ------------------------------------------------------------------
    # Background hot-reload loop
    # ------------------------------------------------------------------

    async def start_model_reload_loop(self) -> None:
        while True:
            await asyncio.sleep(MODEL_RELOAD_INTERVAL_SEC)
            try:
                await self._try_load_model()
            except Exception as exc:  # noqa: BLE001
                log.warning("Model reload failed: %s", exc)

    async def _try_load_model(self) -> None:
        """Load (or reload) CatBoost model if the file has changed."""
        path = CATBOOST_MODEL_PATH
        if not path.exists():
            self._use_ml = False
            return

        mtime = path.stat().st_mtime
        if mtime == self._model_mtime:
            return  # unchanged

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._load_model_sync, path)

    def _load_model_sync(self, path: Path) -> None:
        try:
            from catboost import CatBoostClassifier  # type: ignore

            model = CatBoostClassifier()
            model.load_model(str(path))
            self._catboost_model = model
            self._model_mtime = path.stat().st_mtime
            self._use_ml = True
            log.info("CatBoost model loaded from %s", path)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to load CatBoost model: %s", exc)
            self._use_ml = False

    # ------------------------------------------------------------------
    # Training sample count check
    # ------------------------------------------------------------------

    def _has_enough_training_data(self) -> bool:
        """Quick COUNT(*) to decide whether CatBoost is viable."""
        try:
            q = f"SELECT count() FROM {CLICKHOUSE_DATABASE}.hunter_training_data"
            rows = self._ch.query(q).result_rows
            return int(rows[0][0]) >= MIN_TRAINING_SAMPLES if rows else False
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Public scoring API
    # ------------------------------------------------------------------

    async def score(self, feature_vector: List[float]) -> MLResult:
        """
        Return an MLResult with:
          - score  : 0.0–1.0
          - model_used : "heuristic" or "catboost"
        """
        if self._use_ml and self._catboost_model is not None:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, self._catboost_score, feature_vector
            )

        # Try to trigger one-time switch to CatBoost
        if not self._use_ml and CATBOOST_MODEL_PATH.exists():
            await self._try_load_model()
            if self._use_ml and self._catboost_model is not None:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self._catboost_score, feature_vector
                )

        return MLResult(
            score=heuristic_scorer.score(feature_vector),
            model_used="heuristic",
        )

    def _catboost_score(self, feature_vector: List[float]) -> MLResult:
        import numpy as np  # type: ignore

        arr = np.array([feature_vector], dtype=np.float32)
        proba = self._catboost_model.predict_proba(arr)[0]
        # proba[1] = probability of class 1 (attack)
        attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        try:
            importances = self._catboost_model.get_feature_importance()
            feat_imp = {
                FEATURE_ORDER[i]: float(v)
                for i, v in enumerate(importances)
                if i < len(FEATURE_ORDER)
            }
        except Exception:  # noqa: BLE001
            feat_imp = {}

        return MLResult(
            score=attack_prob,
            model_used="catboost",
            feature_importances=feat_imp,
        )
