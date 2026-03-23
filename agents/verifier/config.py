"""
Verifier Agent – centralised configuration.

All values sourced from environment variables (injected by docker-compose).
Sane defaults provided so the module can be imported in unit-test context
without a running container.
"""
from __future__ import annotations

import os


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


def _bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key, "")
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Kafka
# ---------------------------------------------------------------------------
KAFKA_BROKERS: str = _env("KAFKA_BROKERS", "redpanda01:9092")
CONSUMER_GROUP_ID: str = _env("CONSUMER_GROUP_ID", "clif-verifier-agent")
TOPIC_INPUT: str = _env("TOPIC_INPUT", "hunter-results")
TOPIC_OUTPUT: str = _env("TOPIC_OUTPUT", "verifier-results")
TOPIC_DEAD_LETTER: str = _env("TOPIC_DEAD_LETTER", "dead-letter")
KAFKA_AUTO_OFFSET_RESET: str = _env("KAFKA_AUTO_OFFSET_RESET", "earliest")
KAFKA_MAX_POLL_RECORDS: int = _int("KAFKA_MAX_POLL_RECORDS", 5)

# ---------------------------------------------------------------------------
# ClickHouse  (clickhouse-connect uses HTTP port 8123)
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST: str = _env("CLICKHOUSE_HOST", "clickhouse01")
CLICKHOUSE_PORT: int = _int("CLICKHOUSE_PORT", 8123)
CLICKHOUSE_USER: str = _env("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD: str = _env("CLICKHOUSE_PASSWORD", "clif_secure_password_change_me")
CLICKHOUSE_DATABASE: str = _env("CLICKHOUSE_DATABASE", _env("CLICKHOUSE_DB", "clif_logs"))

# ---------------------------------------------------------------------------
# LanceDB HTTP service
# ---------------------------------------------------------------------------
LANCEDB_URL: str = _env("LANCEDB_URL", "http://lancedb:8100")
LANCEDB_TIMEOUT_SEC: float = _float("LANCEDB_TIMEOUT_SEC", 5.0)

# ---------------------------------------------------------------------------
# Verifier service
# ---------------------------------------------------------------------------
VERIFIER_PORT: int = _int("VERIFIER_PORT", 8500)
LOG_LEVEL: str = _env("LOG_LEVEL", "INFO")

# ---------------------------------------------------------------------------
# Verification parameters
# ---------------------------------------------------------------------------
SKIP_NEGATIVE_VERDICTS: bool = _bool("SKIP_NEGATIVE_VERDICTS", True)
REQUIRE_HMAC: bool = _bool("REQUIRE_HMAC", False)
TIMELINE_WINDOW_HOURS: int = _int("TIMELINE_WINDOW_HOURS", 24)
FP_SIMILARITY_THRESHOLD: float = _float("FP_SIMILARITY_THRESHOLD", 0.3)
IOC_LOOKBACK_HOURS: int = _int("IOC_LOOKBACK_HOURS", 72)
EVIDENCE_LOOKBACK_HOURS: int = _int("EVIDENCE_LOOKBACK_HOURS", 2)
