"""
Self-Supervised Trainer – background loop that periodically retrains the
CatBoost model from accumulated investigation data.

Runs every RETRAIN_INTERVAL_SEC (default 6 hours).
Saves model atomically via os.replace (temp → final path).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, List, Optional

import numpy as np  # type: ignore

from config import (
    CATBOOST_MODEL_PATH,
    CLICKHOUSE_DATABASE,
    MIN_TRAINING_SAMPLES,
    RETRAIN_INTERVAL_SEC,
)
from training import label_builder

log = logging.getLogger(__name__)


class SelfSupervisedTrainer:
    """
    Manages the background retraining cycle.
    Call `start()` during the application lifespan.
    """

    def __init__(self, ch_client: Any) -> None:
        self._ch = ch_client
        self._training_count: int = 0
        self._last_train_ts: float = 0.0

    async def start(self) -> None:
        """Launch the background training loop as an asyncio Task."""
        asyncio.create_task(self._training_loop(), name="hunter-trainer")

    async def _training_loop(self) -> None:
        # Initial delay so the service is fully online before first attempt
        await asyncio.sleep(60)
        while True:
            try:
                await self._maybe_retrain()
            except Exception as exc:  # noqa: BLE001
                log.error("Training loop error: %s", exc)
            await asyncio.sleep(RETRAIN_INTERVAL_SEC)

    async def _maybe_retrain(self) -> None:
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(
            None,
            label_builder.fetch_training_set,
            self._ch,
            MIN_TRAINING_SAMPLES,
        )
        if data is None:
            return

        log.info("Starting CatBoost retraining with %d samples …", len(data))
        await loop.run_in_executor(None, self._train_and_save, data)

    def _train_and_save(self, data: List[dict]) -> None:
        """Parse feature vectors, train CatBoost, atomically write model."""
        try:
            from catboost import CatBoostClassifier, Pool  # type: ignore
        except ImportError:
            log.error("catboost not installed, skipping training")
            return

        X: List[List[float]] = []
        y: List[int] = []

        for row in data:
            try:
                features = json.loads(row["feature_vector_json"])
                X.append([float(v) for v in features])
                y.append(int(row["label"]))
            except Exception as exc:  # noqa: BLE001
                log.debug("Skipping malformed training row: %s", exc)

        if len(X) < MIN_TRAINING_SAMPLES:
            log.warning("After parsing, only %d valid rows – skipping", len(X))
            return

        X_arr = np.array(X, dtype=np.float32)
        y_arr = np.array(y, dtype=np.int32)

        model = CatBoostClassifier(
            iterations=300,
            learning_rate=0.05,
            depth=6,
            loss_function="Logloss",
            eval_metric="AUC",
            random_seed=42,
            verbose=False,
            class_weights=[1, 3],   # up-weight positives
        )

        train_pool = Pool(X_arr, y_arr)
        model.fit(train_pool)

        # Atomic write
        CATBOOST_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=CATBOOST_MODEL_PATH.parent,
            suffix=".cbm.tmp",
            delete=False,
        ) as tmp:
            tmp_path = tmp.name

        try:
            model.save_model(tmp_path)
            os.replace(tmp_path, str(CATBOOST_MODEL_PATH))
            self._training_count += 1
            log.info(
                "CatBoost model saved to %s (train #%d, %d samples)",
                CATBOOST_MODEL_PATH,
                self._training_count,
                len(X),
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to save model: %s", exc)
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
