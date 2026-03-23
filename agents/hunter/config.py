"""
Hunter Agent – centralised configuration.

All values sourced from environment variables (injected by docker-compose).
Sane defaults provided so the module can be imported in unit-test context
without a running container.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _float(key: str, default: float) -> float:
    try:
        return float(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Kafka
# ---------------------------------------------------------------------------
KAFKA_BROKERS: str = _env("KAFKA_BROKERS", "redpanda01:9092")
CONSUMER_GROUP_ID: str = _env("CONSUMER_GROUP_ID", "clif-hunter-agent")
TOPIC_HUNTER_TASKS: str = _env("TOPIC_HUNTER_TASKS", "hunter-tasks")
TOPIC_HUNTER_RESULTS: str = _env("TOPIC_HUNTER_RESULTS", "hunter-results")
KAFKA_AUTO_OFFSET_RESET: str = _env("KAFKA_AUTO_OFFSET_RESET", "earliest")
KAFKA_MAX_POLL_RECORDS: int = _int("KAFKA_MAX_POLL_RECORDS", 100)

# ---------------------------------------------------------------------------
# Concurrency & Dedup
# ---------------------------------------------------------------------------
# Max concurrent investigations (semaphore-bounded)
HUNTER_CONCURRENCY: int = _int("HUNTER_CONCURRENCY", 8)
# Dedup window: skip same (hostname, source_type) within this many seconds
DEDUP_WINDOW_SEC: int = _int("DEDUP_WINDOW_SEC", 300)

# ---------------------------------------------------------------------------
# ClickHouse
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST: str = _env("CLICKHOUSE_HOST", "clickhouse01")
CLICKHOUSE_PORT: int = _int("CLICKHOUSE_PORT", 8123)
CLICKHOUSE_USER: str = _env("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD: str = _env("CLICKHOUSE_PASSWORD", "")
CLICKHOUSE_DATABASE: str = _env("CLICKHOUSE_DATABASE", "clif_logs")

# ---------------------------------------------------------------------------
# LanceDB HTTP service
# ---------------------------------------------------------------------------
LANCEDB_URL: str = _env("LANCEDB_URL", "http://lancedb:8100")
LANCEDB_TIMEOUT_SEC: float = _float("LANCEDB_TIMEOUT_SEC", 5.0)
LANCEDB_BACKOFF_SEC: float = _float("LANCEDB_BACKOFF_SEC", 2.0)
LANCEDB_CIRCUIT_THRESHOLD: int = _int("LANCEDB_CIRCUIT_THRESHOLD", 3)

# ---------------------------------------------------------------------------
# Hunter service
# ---------------------------------------------------------------------------
HUNTER_PORT: int = _int("HUNTER_PORT", 8400)
LOG_LEVEL: str = _env("LOG_LEVEL", "INFO")

# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------
# Minimum triage adjusted_score to pass secondary gate.
# v7: raised from 0.70 to 0.80 — triage v7 produces better-calibrated
# scores, so only investigate events triage is confident about.
HUNTER_SCORE_GATE: float = _float("HUNTER_SCORE_GATE", 0.80)
# Look-back window for temporal correlation (minutes)
INVESTIGATION_WINDOW_MIN: int = _int("INVESTIGATION_WINDOW_MIN", 15)
BATCH_SIZE: int = _int("BATCH_SIZE", 100)

# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------
SIGMA_RULES_DIR: Path = Path(_env("SIGMA_RULES_DIR", "/app/sigma/rules"))

# ---------------------------------------------------------------------------
# ML / CatBoost
# ---------------------------------------------------------------------------
CATBOOST_MODEL_PATH: Path = Path(
    _env("CATBOOST_MODEL_PATH", "/app/models/hunter_catboost.cbm")
)
MIN_TRAINING_SAMPLES: int = _int("MIN_TRAINING_SAMPLES", 100)
RETRAIN_INTERVAL_SEC: int = _int("RETRAIN_INTERVAL_SEC", 21_600)  # 6 hours

# ---------------------------------------------------------------------------
# SPC (Statistical Process Control)
# ---------------------------------------------------------------------------
SPC_BASELINE_REFRESH_SEC: int = _int("SPC_BASELINE_REFRESH_SEC", 60)
SPC_WINDOW_HOURS: int = _int("SPC_WINDOW_HOURS", 24)
SPC_SIGMA_THRESHOLD: float = _float("SPC_SIGMA_THRESHOLD", 3.0)

# ---------------------------------------------------------------------------
# Drift monitoring
# ---------------------------------------------------------------------------
DRIFT_BASELINE_DAYS: int = _int("DRIFT_BASELINE_DAYS", 7)
DRIFT_CURRENT_DAYS: int = _int("DRIFT_CURRENT_DAYS", 1)
DRIFT_KL_THRESHOLD: float = _float("DRIFT_KL_THRESHOLD", 0.1)
DRIFT_PSI_THRESHOLD: float = _float("DRIFT_PSI_THRESHOLD", 0.25)
