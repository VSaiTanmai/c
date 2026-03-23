"""
CLIF Consumer — Redpanda → ClickHouse High-Performance Ingestion Pipeline.

Production-grade consumer with:
  • Batch polling via consume() — up to 10 000 messages per call
  • Inline deserialization + columnar buffer accumulation
  • Columnar INSERT via clickhouse-driver (columnar=True, native TCP)
  • Per-table concurrent flush via ThreadPoolExecutor (4 workers default)
  • Pipelined flush — non-blocking: main loop resumes polling immediately
  • Optimized Kafka fetch settings (64KB min fetch, 50MB max, 4MB/partition)
  • Back-pressure aware batching with size + time triggers
  • Graceful shutdown with drain and final synchronous commit
  • Connection-pool pattern: one ClickHouseWriter per flush worker
  • Health metrics via StatsReporter with per-second rate tracking
  • Deterministic event_id (UUID5 from Kafka topic:partition:offset)
  • async_insert=1 with 100ms timeout — server-side micro-batch buffering
  • Horizontally scalable: run multiple instances in same consumer group

Environment variables:
    KAFKA_BROKERS               comma-separated broker list
    CLICKHOUSE_HOST             ClickHouse native TCP host
    CLICKHOUSE_ALT_HOSTS        HA failover hosts (comma-separated host:port)
    CLICKHOUSE_PORT             ClickHouse native TCP port (9000)
    CLICKHOUSE_USER             ClickHouse username
    CLICKHOUSE_PASSWORD         ClickHouse password
    CLICKHOUSE_DB               target database (default: clif_logs)
    CONSUMER_GROUP_ID           Kafka consumer group
    CONSUMER_BATCH_SIZE         max events per INSERT batch (default: 200000)
    CONSUMER_FLUSH_INTERVAL_SEC max seconds between flushes (default: 0.5)
    CONSUMER_MAX_RETRIES        retries on ClickHouse insert failure
    CONSUMER_POLL_BATCH         messages per consume() call (default: 10000)
    CONSUMER_FLUSH_WORKERS      parallel flush threads (default: 4)
    LOG_LEVEL                   Python log level (DEBUG/INFO/WARNING/…)
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Event, Lock, Semaphore, Thread
from typing import Any

import uuid as _uuid_mod

from confluent_kafka import Consumer, Producer, KafkaError, KafkaException
from clickhouse_driver import Client as CHClient

# ── Deterministic event_id from Kafka coordinates ────────────────────────────
# Both the consumer and triage agent read the same Kafka messages.
# UUID5(namespace, "topic:partition:offset") produces an identical, stable
# event_id for each message, enabling JOINs across raw_logs ↔ triage_scores.

_CLIF_EVENT_NS = _uuid_mod.UUID("c71f0000-e1d0-4a6b-b5c3-deadbeef0042")


def deterministic_event_id(topic: str, partition: int, offset: int) -> str:
    """Derive a stable UUID-v5 from Kafka message coordinates."""
    return str(_uuid_mod.uuid5(_CLIF_EVENT_NS, f"{topic}:{partition}:{offset}"))

try:
    import orjson as _json  # 3-10x faster JSON parsing (C/Rust)

    def _json_loads(data: bytes | str) -> Any:
        return _json.loads(data)

    def _json_dumps(data: Any) -> bytes:
        return _json.dumps(data)
except ImportError:
    import json as _json  # type: ignore[no-redef]

    def _json_loads(data: bytes | str) -> Any:  # type: ignore[misc]
        return _json.loads(data)

    def _json_dumps(data: Any) -> bytes:  # type: ignore[misc]
        return _json.dumps(data).encode("utf-8")

# ── Configuration ────────────────────────────────────────────────────────────

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda01:9092")
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse01")
CLICKHOUSE_ALT_HOSTS = os.getenv("CLICKHOUSE_ALT_HOSTS", "")  # HA failover: comma-separated host:port
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "clif_secure_password_change_me")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "clif_logs")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP_ID", "clif-clickhouse-consumer")
BATCH_SIZE = int(os.getenv("CONSUMER_BATCH_SIZE", "500000"))
FLUSH_INTERVAL = float(os.getenv("CONSUMER_FLUSH_INTERVAL_SEC", "0.5"))
MAX_RETRIES = int(os.getenv("CONSUMER_MAX_RETRIES", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Performance tuning knobs
POLL_BATCH = int(os.getenv("CONSUMER_POLL_BATCH", "50000"))
FLUSH_WORKERS = int(os.getenv("CONSUMER_FLUSH_WORKERS", "4"))

# Dead-letter logging: count dropped messages per interval for observability
DLQ_LOG_INTERVAL = int(os.getenv("DLQ_LOG_INTERVAL_SEC", "60"))
DLQ_TOPIC = os.getenv("DLQ_TOPIC", "dead-letter")

# Topic → ClickHouse table mapping
# ┌─ Ingestion tier   : raw logs + classified events from Vector
# ├─ Triage tier      : ML-scored events from Triage Agent
# ├─ Agent tier       : investigation & verification results
# └─ Operational tier : analyst feedback for model retraining
TOPIC_TABLE_MAP: dict[str, str] = {
    # Ingestion tier
    "raw-logs": "raw_logs",
    "security-events": "security_events",
    "process-events": "process_events",
    "network-events": "network_events",
    # Triage tier (consumed from Triage Agent output)
    "triage-scores": "triage_scores",
    # Agent tier (consumed from Hunter / Verifier output)
    "hunter-results": "hunter_investigations",
    "verifier-results": "verifier_results",
    # Operational tier
    "feedback-labels": "feedback_labels",
}

# Reverse map for fast stats lookups (table → topic)
_TABLE_TO_TOPIC: dict[str, str] = {v: k for k, v in TOPIC_TABLE_MAP.items()}

TOPICS = list(TOPIC_TABLE_MAP.keys())

# Ingestion-tier tables that receive a deterministic event_id from Kafka coords
_INPUT_TABLES = {"raw_logs", "security_events", "process_events", "network_events"}

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)
log = logging.getLogger("clif.consumer")

# ── Graceful shutdown ────────────────────────────────────────────────────────

_shutdown = Event()


def _handle_signal(sig: int, _frame: Any) -> None:
    log.warning("Received signal %s — initiating graceful shutdown …", sig)
    _shutdown.set()


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ── Helpers ──────────────────────────────────────────────────────────────────

# Pre-compute the UTC timezone object once
_UTC = timezone.utc


def _now_dt() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(_UTC)


def _parse_timestamp(raw: str | None) -> datetime:
    """Parse an ISO-8601 string into a timezone-aware datetime object.

    clickhouse-driver (native TCP) requires real datetime objects for
    DateTime / DateTime64 columns — plain strings cause
    ``'str' object has no attribute 'tzinfo'``.

    Python 3.11+ fromisoformat() handles 'Z' suffix natively — no
    string allocation needed for the common UTC timestamp case.
    """
    if not raw:
        return _now_dt()
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_UTC)
        return dt
    except (ValueError, AttributeError):
        return _now_dt()


def _safe_str(val: Any, default: str = "") -> str:
    return str(val) if val is not None else default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _ensure_dict(meta: Any) -> dict:
    """Normalize metadata to a dict, handling str or None."""
    if meta is None:
        return {}
    if isinstance(meta, str):
        try:
            meta = _json_loads(meta)
        except (ValueError, TypeError):
            return {}
    if isinstance(meta, dict):
        return meta
    return {}


# ── Row builders (one per target table) ──────────────────────────────────────
# event_id is now injected from Kafka coordinates (deterministic UUID5) so that
# the same event gets the same ID in raw_logs AND triage_scores, enabling JOINs.


def _build_raw_log_row(msg: dict) -> list:
    meta = _ensure_dict(msg.get("metadata"))
    return [
        _safe_uuid_str(msg.get("_event_id")),        # event_id (from Kafka coords)
        _parse_timestamp(msg.get("timestamp")),      # timestamp
        _now_dt(),                                   # received_at
        _safe_str(msg.get("level"), "INFO"),         # level
        _safe_str(msg.get("source"), "unknown"),     # source
        _safe_str(msg.get("message")),               # message
        {str(k): str(v) for k, v in meta.items()},  # metadata
        _safe_str(meta.get("user_id")),              # user_id
        _safe_str(msg.get("ip_address", meta.get("ip_address", "0.0.0.0"))),  # ip_address
        _safe_str(meta.get("request_id")),           # request_id
        "",                                          # anchor_tx_id
        "",                                          # anchor_batch_hash
    ]


def _build_security_event_row(msg: dict) -> list:
    meta = _ensure_dict(msg.get("metadata"))
    return [
        _safe_uuid_str(msg.get("_event_id")),        # event_id (from Kafka coords)
        _parse_timestamp(msg.get("timestamp")),
        _safe_int(msg.get("severity"), 0),
        _safe_str(msg.get("category"), "unknown"),
        _safe_str(msg.get("source"), "unknown"),
        _safe_str(msg.get("description")),
        _safe_str(msg.get("user_id")),
        _safe_str(msg.get("ip_address"), "0.0.0.0"),
        _safe_str(msg.get("hostname")),
        _safe_str(msg.get("mitre_tactic")),
        _safe_str(msg.get("mitre_technique")),
        _safe_float(msg.get("ai_confidence")),
        _safe_str(msg.get("ai_explanation")),
        "",                                          # anchor_tx_id
        {str(k): str(v) for k, v in meta.items()},
    ]


def _build_process_event_row(msg: dict) -> list:
    meta = _ensure_dict(msg.get("metadata"))
    return [
        _safe_uuid_str(msg.get("_event_id")),        # event_id (from Kafka coords)
        _parse_timestamp(msg.get("timestamp")),
        _safe_str(msg.get("hostname")),
        _safe_int(msg.get("pid")),
        _safe_int(msg.get("ppid")),
        _safe_int(msg.get("uid")),
        _safe_int(msg.get("gid")),
        _safe_str(msg.get("binary_path")),
        _safe_str(msg.get("arguments")),
        _safe_str(msg.get("cwd")),
        _safe_int(msg.get("exit_code"), -1),
        _safe_str(msg.get("container_id")),
        _safe_str(msg.get("pod_name")),
        _safe_str(msg.get("namespace")),
        _safe_str(msg.get("syscall")),
        _safe_int(msg.get("is_suspicious")),
        _safe_str(msg.get("detection_rule")),
        "",
        {str(k): str(v) for k, v in meta.items()},
    ]


def _build_network_event_row(msg: dict) -> list:
    meta = _ensure_dict(msg.get("metadata"))
    return [
        _safe_uuid_str(msg.get("_event_id")),        # event_id (from Kafka coords)
        _parse_timestamp(msg.get("timestamp")),
        _safe_str(msg.get("hostname")),
        _safe_str(msg.get("src_ip"), "0.0.0.0"),
        _safe_int(msg.get("src_port")),
        _safe_str(msg.get("dst_ip"), "0.0.0.0"),
        _safe_int(msg.get("dst_port")),
        _safe_str(msg.get("protocol"), "TCP"),
        _safe_str(msg.get("direction"), "outbound"),
        _safe_int(msg.get("bytes_sent")),
        _safe_int(msg.get("bytes_received")),
        _safe_int(msg.get("duration_ms")),
        _safe_int(msg.get("pid")),
        _safe_str(msg.get("binary_path")),
        _safe_str(msg.get("container_id")),
        _safe_str(msg.get("pod_name")),
        _safe_str(msg.get("namespace")),
        _safe_str(msg.get("dns_query")),
        _safe_str(msg.get("geo_country")),
        _safe_int(msg.get("is_suspicious")),
        _safe_str(msg.get("detection_rule")),
        "",
        {str(k): str(v) for k, v in meta.items()},
    ]


# ── Additional helpers for AI pipeline tables ────────────────────────────────

_NIL_UUID = "00000000-0000-0000-0000-000000000000"


def _safe_uuid_str(val: Any, default: str = _NIL_UUID) -> str:
    """Return a valid UUID string for ClickHouse UUID columns."""
    if val is None:
        return default
    s = str(val).strip()
    # Quick format check: 8-4-4-4-12 = 36 chars with hyphens
    if len(s) == 36 and s[8] == "-":
        return s
    return default


def _safe_nullable_uuid_str(val: Any) -> str | None:
    """Return UUID string or None for Nullable(UUID) columns."""
    if val is None:
        return None
    s = str(val).strip()
    if len(s) == 36 and s[8] == "-":
        return s
    return None


def _safe_nullable_dt(val: Any) -> datetime | None:
    """Parse a timestamp or return None for Nullable(DateTime64) columns."""
    if val is None:
        return None
    return _parse_timestamp(str(val))


def _safe_str_array(val: Any) -> list[str]:
    """Normalize to a list of strings for Array(String) columns."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def _safe_uuid_array(val: Any) -> list[str]:
    """Normalize to a list of UUID strings for Array(UUID) columns."""
    if val is None:
        return []
    if isinstance(val, list):
        return [_safe_uuid_str(v) for v in val]
    return []


# ── Row builders for AI pipeline tables ──────────────────────────────────────


def _build_triage_score_row(msg: dict) -> list:
    """Build a row for the triage_scores table (Triage Agent output)."""
    return [
        # score_id: server-generated UUID (OMITTED)
        _safe_uuid_str(msg.get("event_id")),         # event_id
        _parse_timestamp(msg.get("timestamp")),       # timestamp
        _safe_str(msg.get("source_type")),            # source_type
        _safe_str(msg.get("hostname")),               # hostname
        _safe_str(msg.get("source_ip")),              # source_ip
        _safe_str(msg.get("user_id")),                # user_id
        # Template mining
        _safe_str(msg.get("template_id")),            # template_id
        _safe_float(msg.get("template_rarity")),      # template_rarity
        # ML scores
        _safe_float(msg.get("combined_score")),       # combined_score
        _safe_float(msg.get("lgbm_score")),           # lgbm_score
        _safe_float(msg.get("eif_score")),            # eif_score
        _safe_float(msg.get("arf_score")),            # arf_score
        # Confidence interval
        _safe_float(msg.get("score_std_dev")),        # score_std_dev
        _safe_float(msg.get("agreement")),            # agreement
        _safe_float(msg.get("ci_lower")),             # ci_lower
        _safe_float(msg.get("ci_upper")),             # ci_upper
        # Asset adjustment
        _safe_float(msg.get("asset_multiplier"), 1.0),# asset_multiplier
        _safe_float(msg.get("adjusted_score")),       # adjusted_score
        # Routing decision
        _safe_str(msg.get("action"), "discard"),       # action (Enum8)
        # Threat intel
        _safe_int(msg.get("ioc_match")),              # ioc_match
        _safe_int(msg.get("ioc_confidence")),         # ioc_confidence
        # MITRE
        _safe_str(msg.get("mitre_tactic")),           # mitre_tactic
        _safe_str(msg.get("mitre_technique")),        # mitre_technique
        # SHAP explainability
        _safe_str(msg.get("shap_top_features")),      # shap_top_features
        _safe_str(msg.get("shap_summary")),           # shap_summary
        # Flags
        _safe_int(msg.get("features_stale")),         # features_stale
        _safe_str(msg.get("model_version")),          # model_version
        _safe_int(msg.get("disagreement_flag")),      # disagreement_flag
    ]


def _build_hunter_investigation_row(msg: dict) -> list:
    """Build a row for the hunter_investigations table (Hunter Agent output)."""
    return [
        # investigation_id: server-generated UUID (OMITTED)
        _safe_uuid_str(msg.get("alert_id")),           # alert_id
        _parse_timestamp(msg.get("started_at")),       # started_at
        _safe_nullable_dt(msg.get("completed_at")),    # completed_at (Nullable)
        _safe_str(msg.get("status"), "pending"),       # status (Enum8)
        _safe_str(msg.get("hostname")),                # hostname
        _safe_str(msg.get("source_ip")),               # source_ip
        _safe_str(msg.get("user_id")),                 # user_id
        _safe_float(msg.get("trigger_score")),         # trigger_score
        _safe_str(msg.get("severity"), "info"),        # severity (Enum8)
        _safe_str(msg.get("finding_type")),            # finding_type
        _safe_str(msg.get("summary")),                 # summary
        _safe_str(msg.get("evidence_json")),           # evidence_json
        _safe_uuid_array(msg.get("correlated_events")),# correlated_events Array(UUID)
        _safe_str_array(msg.get("mitre_tactics")),     # mitre_tactics Array(String)
        _safe_str_array(msg.get("mitre_techniques")),  # mitre_techniques Array(String)
        _safe_str(msg.get("recommended_action")),      # recommended_action
        _safe_float(msg.get("confidence")),            # confidence
    ]


def _build_verifier_result_row(msg: dict) -> list:
    """Build a row for the verifier_results table (Verifier Agent output)."""
    return [
        # verification_id: server-generated UUID (OMITTED)
        _safe_uuid_str(msg.get("investigation_id")),   # investigation_id
        _safe_uuid_str(msg.get("alert_id")),           # alert_id
        _parse_timestamp(msg.get("started_at")),       # started_at
        _safe_nullable_dt(msg.get("completed_at")),    # completed_at (Nullable)
        _safe_str(msg.get("status"), "pending"),       # status (Enum8)
        _safe_str(msg.get("verdict"), "inconclusive"), # verdict (Enum8)
        _safe_float(msg.get("confidence")),            # confidence
        _safe_int(msg.get("evidence_verified")),       # evidence_verified
        _safe_str_array(msg.get("merkle_batch_ids")),  # merkle_batch_ids Array(String)
        _safe_str(msg.get("timeline_json")),           # timeline_json
        _safe_str(msg.get("ioc_correlations")),        # ioc_correlations
        _safe_str(msg.get("priority"), "P4"),          # priority (Enum8)
        _safe_str(msg.get("recommended_action")),      # recommended_action
        _safe_str(msg.get("analyst_summary")),         # analyst_summary
    ]


def _build_feedback_label_row(msg: dict) -> list:
    """Build a row for the feedback_labels table (analyst feedback)."""
    return [
        # feedback_id: server-generated UUID (OMITTED)
        _safe_uuid_str(msg.get("event_id")),           # event_id
        _safe_nullable_uuid_str(msg.get("score_id")),  # score_id (Nullable UUID)
        _parse_timestamp(msg.get("timestamp")),        # timestamp
        _safe_str(msg.get("label"), "unknown"),         # label (Enum8)
        _safe_str(msg.get("confidence"), "medium"),     # confidence (Enum8)
        _safe_str(msg.get("analyst_id")),              # analyst_id
        _safe_str(msg.get("notes")),                   # notes
        _safe_float(msg.get("original_combined")),     # original_combined
        _safe_float(msg.get("original_lgbm")),         # original_lgbm
        _safe_float(msg.get("original_eif")),          # original_eif
        _safe_float(msg.get("original_arf")),          # original_arf
    ]


# Column lists — event_id NOW explicitly supplied from deterministic Kafka UUID5.
# ClickHouse DEFAULT generateUUIDv4() only fires when the column is omitted;
# providing it here ensures raw_logs.event_id == triage_scores.event_id.
RAW_LOGS_COLUMNS = [
    "event_id",
    "timestamp", "received_at", "level", "source", "message",
    "metadata", "user_id", "ip_address", "request_id",
    "anchor_tx_id", "anchor_batch_hash",
]
SECURITY_EVENTS_COLUMNS = [
    "event_id",
    "timestamp", "severity", "category", "source", "description",
    "user_id", "ip_address", "hostname",
    "mitre_tactic", "mitre_technique", "ai_confidence", "ai_explanation",
    "anchor_tx_id", "metadata",
]
PROCESS_EVENTS_COLUMNS = [
    "event_id",
    "timestamp", "hostname", "pid", "ppid", "uid", "gid",
    "binary_path", "arguments", "cwd", "exit_code",
    "container_id", "pod_name", "namespace", "syscall",
    "is_suspicious", "detection_rule", "anchor_tx_id", "metadata",
]
NETWORK_EVENTS_COLUMNS = [
    "event_id",
    "timestamp", "hostname",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "direction", "bytes_sent", "bytes_received", "duration_ms",
    "pid", "binary_path", "container_id", "pod_name", "namespace",
    "dns_query", "geo_country", "is_suspicious", "detection_rule",
    "anchor_tx_id", "metadata",
]

# ── AI pipeline column lists (score_id still server-generated; event_id from triage agent) ──

TRIAGE_SCORES_COLUMNS = [
    "event_id", "timestamp", "source_type", "hostname", "source_ip", "user_id",
    "template_id", "template_rarity",
    "combined_score", "lgbm_score", "eif_score", "arf_score",
    "score_std_dev", "agreement", "ci_lower", "ci_upper",
    "asset_multiplier", "adjusted_score",
    "action", "ioc_match", "ioc_confidence",
    "mitre_tactic", "mitre_technique",
    "shap_top_features", "shap_summary",
    "features_stale", "model_version", "disagreement_flag",
]
HUNTER_INVESTIGATIONS_COLUMNS = [
    "alert_id", "started_at", "completed_at", "status",
    "hostname", "source_ip", "user_id", "trigger_score",
    "severity", "finding_type", "summary", "evidence_json",
    "correlated_events", "mitre_tactics", "mitre_techniques",
    "recommended_action", "confidence",
]
VERIFIER_RESULTS_COLUMNS = [
    "investigation_id", "alert_id", "started_at", "completed_at", "status",
    "verdict", "confidence", "evidence_verified", "merkle_batch_ids",
    "timeline_json", "ioc_correlations",
    "priority", "recommended_action", "analyst_summary",
]
FEEDBACK_LABELS_COLUMNS = [
    "event_id", "score_id", "timestamp",
    "label", "confidence", "analyst_id", "notes",
    "original_combined", "original_lgbm", "original_eif", "original_arf",
]
DEAD_LETTER_EVENTS_COLUMNS = [
    "timestamp", "failed_stage", "source_topic",
    "error_message", "raw_payload", "retry_count",
]

TABLE_META: dict[str, dict] = {
    "raw_logs":        {"columns": RAW_LOGS_COLUMNS,        "builder": _build_raw_log_row},
    "security_events": {"columns": SECURITY_EVENTS_COLUMNS, "builder": _build_security_event_row},
    "process_events":  {"columns": PROCESS_EVENTS_COLUMNS,  "builder": _build_process_event_row},
    "network_events":  {"columns": NETWORK_EVENTS_COLUMNS,  "builder": _build_network_event_row},
    # AI pipeline tables
    "triage_scores":         {"columns": TRIAGE_SCORES_COLUMNS,        "builder": _build_triage_score_row},
    "hunter_investigations": {"columns": HUNTER_INVESTIGATIONS_COLUMNS,"builder": _build_hunter_investigation_row},
    "verifier_results":      {"columns": VERIFIER_RESULTS_COLUMNS,     "builder": _build_verifier_result_row},
    "feedback_labels":       {"columns": FEEDBACK_LABELS_COLUMNS,      "builder": _build_feedback_label_row},
    # Operational (DLQ events written directly by _buffer_dlq_event, builder=None)
    "dead_letter_events":    {"columns": DEAD_LETTER_EVENTS_COLUMNS,   "builder": None},
}

# ── ClickHouse Writer Pool ──────────────────────────────────────────────────


class ClickHouseWriter:
    """
    Manages batched inserts into ClickHouse with connection resilience.
    Each writer owns a single native TCP connection. Create one per
    flush-worker thread to avoid contention on a shared socket.
    """

    def __init__(self, writer_id: int = 0) -> None:
        self._id = writer_id
        self.client = self._connect()

    def _connect(self):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                client = CHClient(
                    host=CLICKHOUSE_HOST,
                    port=CLICKHOUSE_PORT,
                    user=CLICKHOUSE_USER,
                    password=CLICKHOUSE_PASSWORD,
                    database=CLICKHOUSE_DB,
                    alt_hosts=CLICKHOUSE_ALT_HOSTS if CLICKHOUSE_ALT_HOSTS else None,
                    connect_timeout=30,
                    send_receive_timeout=120,
                    compression='lz4',  # LZ4 wire compression
                    settings={
                        # async_insert with wait=1 — INSERT blocks until CH
                        # has persisted the async buffer (≤100ms). This
                        # guarantees data durability: if INSERT returns
                        # success → data is on disk. Without wait=1, a CH
                        # crash between INSERT-return and async-flush loses
                        # data that we already committed offsets for.
                        "async_insert": 1,
                        "wait_for_async_insert": 1,
                        "async_insert_busy_timeout_ms": 100,
                        "async_insert_max_data_size": 104857600,  # 100 MB
                        # Parallel INSERT processing within ClickHouse
                        "max_insert_threads": 4,
                    },
                )
                # Verify connectivity with a lightweight ping
                client.execute("SELECT 1")
                log.info(
                    "Writer-%d connected to ClickHouse %s:%s (attempt %d)",
                    self._id, CLICKHOUSE_HOST, CLICKHOUSE_PORT, attempt,
                )
                return client
            except Exception as exc:
                log.warning("Writer-%d connection attempt %d failed: %s", self._id, attempt, exc)
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(min(2 ** attempt, 30))
        raise RuntimeError("unreachable")

    def insert(self, table: str, columns: list[str], col_data: list[list]) -> int:
        """Insert columnar data with retries. Returns row count on success."""
        if not col_data or not col_data[0]:
            return 0
        row_count = len(col_data[0])
        col_str = ", ".join(columns)
        sql = f"INSERT INTO {table} ({col_str}) VALUES"
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self.client.execute(
                    sql, col_data, columnar=True, types_check=False,
                )
                return row_count
            except Exception as exc:
                log.warning(
                    "Writer-%d insert into %s failed (attempt %d/%d, %d rows): %s",
                    self._id, table, attempt, MAX_RETRIES, row_count, exc,
                )
                if attempt == MAX_RETRIES:
                    raise
                time.sleep(min(2 ** attempt, 15))
                try:
                    self.client = self._connect()
                except Exception:
                    pass
        return 0


class WriterPool:
    """
    Pool of ClickHouseWriter instances — one per flush worker thread.
    Eliminates socket contention by giving each thread its own connection.
    Uses a Semaphore for efficient blocking instead of spin-wait.
    """

    def __init__(self, size: int) -> None:
        self._writers: list[ClickHouseWriter] = []
        self._lock = Lock()
        self._semaphore = Semaphore(0)  # starts empty
        self._available: list[ClickHouseWriter] = []
        log.info("Initializing ClickHouse writer pool (size=%d) …", size)
        for i in range(size):
            w = ClickHouseWriter(writer_id=i)
            self._writers.append(w)
            self._available.append(w)
            self._semaphore.release()  # signal one writer available

    def acquire(self) -> ClickHouseWriter:
        """Borrow a writer from the pool (blocks efficiently via semaphore)."""
        self._semaphore.acquire()  # blocks without spinning
        with self._lock:
            return self._available.pop()

    def release(self, writer: ClickHouseWriter) -> None:
        """Return a writer to the pool."""
        with self._lock:
            self._available.append(writer)
        self._semaphore.release()


# ── Stats reporter ───────────────────────────────────────────────────────────


class StatsReporter(Thread):
    """Periodically logs ingestion stats with per-second throughput rates."""

    def __init__(self) -> None:
        super().__init__(daemon=True, name="stats-reporter")
        self._lock = Lock()
        self._counts: dict[str, int] = {t: 0 for t in TOPICS}
        self._errors: int = 0
        self._parse_errors: int = 0     # JSON / builder failures (DLQ candidates)
        self._flush_count: int = 0
        self._flush_rows: int = 0
        self._last_total: int = 0
        self._last_time: float = time.monotonic()

    def record_messages(self, topic: str, count: int) -> None:
        with self._lock:
            self._counts[topic] = self._counts.get(topic, 0) + count

    def record_error(self, count: int = 1) -> None:
        with self._lock:
            self._errors += count

    def record_parse_error(self, count: int = 1) -> None:
        """Track JSON deserialization / row builder failures (potential DLQ events)."""
        with self._lock:
            self._parse_errors += count

    def record_flush(self, rows: int) -> None:
        with self._lock:
            self._flush_count += 1
            self._flush_rows += rows

    def run(self) -> None:
        while not _shutdown.is_set():
            _shutdown.wait(15)
            with self._lock:
                total = sum(self._counts.values())
                now = time.monotonic()
                elapsed = now - self._last_time
                rate = (total - self._last_total) / max(elapsed, 0.001)
                self._last_total = total
                self._last_time = now
                log.info(
                    "Stats — total=%d  rate=%.0f msg/s  flushes=%d  flush_rows=%d  "
                    "errors=%d  parse_drops=%d  %s",
                    total, rate, self._flush_count, self._flush_rows,
                    self._errors, self._parse_errors,
                    "  ".join(f"{t}={c}" for t, c in self._counts.items()),
                )


# ── Dead-Letter Queue (DLQ) ──────────────────────────────────────────────────
# Failed events are (1) buffered for the dead_letter_events ClickHouse table
# (for dashboard visibility) and (2) published to the dead-letter Redpanda topic
# (for external replay / alerting).

_dlq_producer: Producer | None = None


def _publish_to_dlq(raw_msg: Any, error_msg: str, stage: str) -> None:
    """Non-blocking publish of a failed event to the dead-letter Redpanda topic."""
    if _dlq_producer is None:
        return
    try:
        dlq_event = _json_dumps({
            "timestamp": _now_dt().isoformat(),
            "failed_stage": stage,
            "source_topic": raw_msg.topic() if raw_msg else "",
            "error_message": error_msg[:500],
            "raw_payload": (
                raw_msg.value().decode("utf-8", errors="replace")[:10000]
                if raw_msg and raw_msg.value() else ""
            ),
            "retry_count": 0,
        })
        _dlq_producer.produce(DLQ_TOPIC, value=dlq_event)
    except Exception:
        pass  # never let DLQ publishing crash the main pipeline


def _buffer_dlq_event(
    buffers: dict[str, list[list]],
    source_topic: str,
    raw_payload: bytes | None,
    error_msg: str,
    stage: str,
) -> None:
    """Buffer a dead-letter event for the next ClickHouse flush cycle."""
    col_bufs = buffers.get("dead_letter_events")
    if col_bufs is None:
        return
    try:
        col_bufs[0].append(_now_dt())                     # timestamp
        col_bufs[1].append(stage)                          # failed_stage
        col_bufs[2].append(source_topic)                   # source_topic
        col_bufs[3].append(error_msg[:500])                # error_message
        col_bufs[4].append(                                # raw_payload
            raw_payload.decode("utf-8", errors="replace")[:10000]
            if isinstance(raw_payload, bytes) else str(raw_payload or "")[:10000]
        )
        col_bufs[5].append(0)                              # retry_count
    except Exception:
        pass


# ── Batch deserializer ───────────────────────────────────────────────────────


def _deserialize_and_build(raw_msg) -> tuple[str, list] | None:
    """
    Full pipeline: deserialize a Kafka message → build a ClickHouse row.
    Returns (table_name, row) or None on error. Thread-safe / stateless.
    """
    if raw_msg is None:
        return None
    if raw_msg.error():
        if raw_msg.error().code() == KafkaError._PARTITION_EOF:
            return None
        return None

    topic = raw_msg.topic()
    table = TOPIC_TABLE_MAP.get(topic)
    if table is None:
        return None

    try:
        payload = _json_loads(raw_msg.value())
    except (ValueError, UnicodeDecodeError, TypeError):
        return None

    builder = TABLE_META[table]["builder"]
    try:
        row = builder(payload)
        return (table, row)
    except Exception:
        return None


# ── Parallel flush ───────────────────────────────────────────────────────────


def _flush_table(
    writer_pool: WriterPool,
    table: str,
    columns: list[str],
    col_data: list[list],
) -> int:
    """Flush a single table's columnar data using a pooled writer."""
    writer = writer_pool.acquire()
    try:
        return writer.insert(table, columns, col_data)
    finally:
        writer_pool.release(writer)


def _flush_all_parallel(
    writer_pool: WriterPool,
    buffers: dict[str, list[list]],
    stats: StatsReporter,
    flush_executor: ThreadPoolExecutor,
    pending_futures: list,
) -> bool:
    """
    Pipelined flush: collect results from any PREVIOUS flush that finished,
    then snapshot-and-submit the current buffers WITHOUT blocking.
    The main loop resumes polling immediately after submission.

    ``pending_futures`` is a mutable list shared across calls — it accumulates
    futures and is drained as they complete.

    Returns True if ALL previous flushes succeeded (safe to commit offsets),
    False if any flush failed (do NOT commit offsets).
    """
    all_ok = True

    # ── 1. Harvest completed futures from previous flush (non-blocking) ──
    still_pending = []
    total_flushed = 0
    for fut, table, count in pending_futures:
        if fut.done():
            try:
                flushed = fut.result()
                total_flushed += flushed
                log.debug("Flushed %d rows → %s", flushed, table)
            except Exception as exc:
                log.error("Failed to flush %d rows → %s: %s", count, table, exc)
                stats.record_error(count)
                all_ok = False
        else:
            still_pending.append((fut, table, count))
    pending_futures.clear()
    pending_futures.extend(still_pending)
    if total_flushed > 0:
        stats.record_flush(total_flushed)

    # ── 2. Back-pressure: if too many pending, wait for oldest ──
    while len(pending_futures) >= 16:  # cap in-flight flushes
        fut, table, count = pending_futures.pop(0)
        try:
            flushed = fut.result(timeout=30)
            stats.record_flush(flushed)
        except Exception as exc:
            log.error("Back-pressured flush %d rows → %s failed: %s", count, table, exc)
            stats.record_error(count)
            all_ok = False

    # ── 3. Snapshot + submit new flush tasks (non-blocking) ──
    for table, col_bufs in buffers.items():
        if not col_bufs[0]:
            continue
        row_count = len(col_bufs[0])
        snapshot = [list(col) for col in col_bufs]
        for col in col_bufs:
            col.clear()
        columns = TABLE_META[table]["columns"]
        future = flush_executor.submit(
            _flush_table, writer_pool, table, columns, snapshot,
        )
        pending_futures.append((future, table, row_count))

    return all_ok


def _drain_pending_and_commit(
    pending_futures: list[tuple],
    stats: StatsReporter,
    consumer: Consumer,
    flush_ok: bool,
) -> None:
    """Wait for ALL pending flush futures, then commit offsets if all OK.

    This prevents the pipelined-commit race condition where offsets are
    committed for batch N before batch N's ClickHouse INSERT is confirmed.
    Without this drain, a failed INSERT after offset commit means those
    events are never re-consumed on restart → permanent data loss.
    """
    drain_ok = True
    total_drained = 0
    for fut, table, count in pending_futures:
        try:
            flushed = fut.result(timeout=60)
            total_drained += flushed
        except Exception as exc:
            log.error("Drain: flush %d rows → %s failed: %s", count, table, exc)
            stats.record_error(count)
            drain_ok = False
    if total_drained > 0:
        stats.record_flush(total_drained)
    pending_futures.clear()

    if flush_ok and drain_ok:
        consumer.commit(asynchronous=True)
    else:
        log.warning("Skipping offset commit — flush had errors")


def main() -> None:
    log.info(
        "Starting CLIF consumer  brokers=%s  group=%s  batch=%d  flush=%.1fs  "
        "poll_batch=%d  flush_workers=%d",
        KAFKA_BROKERS, CONSUMER_GROUP, BATCH_SIZE, FLUSH_INTERVAL,
        POLL_BATCH, FLUSH_WORKERS,
    )

    # ── Initialize writer pool (one connection per flush worker) ──
    writer_pool = WriterPool(size=FLUSH_WORKERS)

    stats = StatsReporter()
    stats.start()

    # ── DLQ producer for publishing failed events to dead-letter topic ──
    global _dlq_producer
    _dlq_producer = Producer({
        "bootstrap.servers": KAFKA_BROKERS,
        "linger.ms": 50,              # batch DLQ messages for 50ms before send
        "compression.type": "lz4",
        "queue.buffering.max.messages": 100000,
    })

    # ── Kafka consumer with optimized fetch settings ──
    consumer = Consumer({
        "bootstrap.servers": KAFKA_BROKERS,
        "group.id": CONSUMER_GROUP,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        # ── Fetch tuning: batch at the broker to reduce round-trips ──
        "fetch.min.bytes": 65536,                # 64 KB — wait for a decent batch
        "fetch.max.bytes": 52428800,             # 50 MB — max per fetch response
        "max.partition.fetch.bytes": 4194304,    # 4 MB per partition
        "fetch.wait.max.ms": 100,                # max 100ms broker-side wait
        # ── Session / poll tuning ──
        "session.timeout.ms": 30000,
        "max.poll.interval.ms": 300000,
        "heartbeat.interval.ms": 10000,
        # ── Consumer prefetch buffer ──
        "queued.min.messages": 50000,
        "queued.max.messages.kbytes": 131072,    # 128 MB prefetch buffer
        # ── Partition EOF is not an error ──
        "enable.partition.eof": False,
    })
    consumer.subscribe(TOPICS)
    log.info("Subscribed to topics: %s", TOPICS)

    # ── Thread pools ──
    flush_pool = ThreadPoolExecutor(
        max_workers=FLUSH_WORKERS, thread_name_prefix="flush",
    )

    # Per-table columnar buffers: {table: [col0_vals, col1_vals, ...]}
    buffers: dict[str, list[list]] = {
        table: [[] for _ in TABLE_META[table]["columns"]]
        for table in TABLE_META
    }
    last_flush = time.monotonic()
    total_buffered = 0
    # Pipelined flush: pending futures carried across flush cycles
    pending_futures: list[tuple] = []

    try:
        while not _shutdown.is_set():
            # Trigger DLQ producer delivery callbacks (non-blocking)
            if _dlq_producer:
                _dlq_producer.poll(0)

            # ── Batch poll: up to POLL_BATCH messages in one syscall ──
            messages = consumer.consume(num_messages=POLL_BATCH, timeout=0.5)

            if not messages:
                # No messages — check time-based flush
                if time.monotonic() - last_flush >= FLUSH_INTERVAL and total_buffered > 0:
                    flush_ok = _flush_all_parallel(writer_pool, buffers, stats, flush_pool, pending_futures)
                    _drain_pending_and_commit(pending_futures, stats, consumer, flush_ok)
                    total_buffered = 0
                    last_flush = time.monotonic()
                continue

            # ── Inline deserialization + columnar distribution ──
            msg_count = 0
            error_count = 0
            topic_counts: dict[str, int] = defaultdict(int)

            for raw_msg in messages:
                if raw_msg is None:
                    continue
                err = raw_msg.error()
                if err:
                    if err.code() != KafkaError._PARTITION_EOF:
                        error_count += 1
                    continue

                topic = raw_msg.topic()
                table = TOPIC_TABLE_MAP.get(topic)
                if table is None:
                    continue

                try:
                    payload = _json_loads(raw_msg.value())
                except (ValueError, UnicodeDecodeError, TypeError) as exc:
                    error_count += 1
                    stats.record_parse_error()
                    _buffer_dlq_event(buffers, topic, raw_msg.value(), str(exc), "json_parse")
                    _publish_to_dlq(raw_msg, str(exc), "json_parse")
                    continue

                # Inject deterministic event_id for ingestion-tier tables
                # so raw_logs.event_id == triage_scores.event_id for the
                # same Kafka message (both services derive the same UUID5).
                if table in _INPUT_TABLES:
                    payload["_event_id"] = deterministic_event_id(
                        topic, raw_msg.partition(), raw_msg.offset(),
                    )

                try:
                    row = TABLE_META[table]["builder"](payload)
                except Exception as exc:
                    error_count += 1
                    stats.record_parse_error()
                    _buffer_dlq_event(buffers, topic, raw_msg.value(), str(exc), "row_build")
                    _publish_to_dlq(raw_msg, str(exc), "row_build")
                    continue

                # Distribute row values into columnar buffers
                col_bufs = buffers[table]
                for i, val in enumerate(row):
                    col_bufs[i].append(val)

                msg_count += 1
                topic_counts[topic] += 1

            total_buffered += msg_count

            # Update stats
            for topic, count in topic_counts.items():
                if topic:
                    stats.record_messages(topic, count)
            if error_count > 0:
                stats.record_error(error_count)

            # ── Size-based flush ──
            if total_buffered >= BATCH_SIZE:
                flush_ok = _flush_all_parallel(writer_pool, buffers, stats, flush_pool, pending_futures)
                _drain_pending_and_commit(pending_futures, stats, consumer, flush_ok)
                total_buffered = 0
                last_flush = time.monotonic()
                continue

            # ── Time-based flush ──
            if time.monotonic() - last_flush >= FLUSH_INTERVAL:
                flush_ok = _flush_all_parallel(writer_pool, buffers, stats, flush_pool, pending_futures)
                _drain_pending_and_commit(pending_futures, stats, consumer, flush_ok)
                total_buffered = 0
                last_flush = time.monotonic()

    except KeyboardInterrupt:
        log.info("Interrupted.")
    finally:
        log.info("Draining remaining buffers …")
        _flush_all_parallel(writer_pool, buffers, stats, flush_pool, pending_futures)
        # Wait for all pending flushes to complete before final commit
        all_final_ok = True
        for fut, table, count in pending_futures:
            try:
                fut.result(timeout=60)
            except Exception as exc:
                log.error("Final flush %d rows \u2192 %s failed: %s", count, table, exc)
                all_final_ok = False
        pending_futures.clear()
        if all_final_ok:
            try:
                consumer.commit(asynchronous=False)  # final commit is synchronous
            except Exception:
                pass
        else:
            log.error("Final flush had errors — offsets NOT committed to prevent data loss")
        consumer.close()
        flush_pool.shutdown(wait=True, cancel_futures=False)
        if _dlq_producer:
            try:
                _dlq_producer.flush(timeout=10)
            except Exception:
                pass
        log.info("Consumer shut down cleanly.")


if __name__ == "__main__":
    main()
