"""
CLIF Triage Agent v7 — Configuration
========================================
All configuration via environment variables with production defaults.

v7 changes:
  - 32-feature vector (Universal 12 + Network 8 + Text 6 + Behavioral 6)
  - 2-model ensemble (LightGBM 0.85 + Autoencoder 0.15)
  - ARF and EIF removed
  - Batch size increased 500 → 2000
  - EWMA-based rate tracking replaces fixed windows
  - Kill-chain state machine for multi-stage attack detection
"""

import os

# ── Kafka / Redpanda ────────────────────────────────────────────────────────

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda01:9092")
CONSUMER_GROUP_ID = os.getenv("CONSUMER_GROUP_ID", "clif-triage-agent")

INPUT_TOPICS = [
    t.strip()
    for t in os.getenv(
        "INPUT_TOPICS", "raw-logs,security-events,process-events,network-events"
    ).split(",")
]

TOPIC_TRIAGE_SCORES = os.getenv("TOPIC_TRIAGE_SCORES", "triage-scores")
TOPIC_ANOMALY_ALERTS = os.getenv("TOPIC_ANOMALY_ALERTS", "anomaly-alerts")
TOPIC_HUNTER_TASKS = os.getenv("TOPIC_HUNTER_TASKS", "hunter-tasks")
TOPIC_DEAD_LETTER = os.getenv("TOPIC_DEAD_LETTER", "dead-letter")

# ── ClickHouse ──────────────────────────────────────────────────────────────

CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse01")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "clif_secure_password_change_me")
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "clif_logs")

# ── Drain3 ──────────────────────────────────────────────────────────────────

DRAIN3_DEPTH = int(os.getenv("DRAIN3_DEPTH", "4"))
DRAIN3_SIM_TH = float(os.getenv("DRAIN3_SIM_TH", "0.4"))
DRAIN3_MAX_CHILDREN = int(os.getenv("DRAIN3_MAX_CHILDREN", "100"))
DRAIN3_MAX_CLUSTERS = int(os.getenv("DRAIN3_MAX_CLUSTERS", "1024"))
DRAIN3_STATE_PATH = os.getenv("DRAIN3_STATE_PATH", "/app/drain3_state.bin")
DRAIN3_CONFIG_PATH = os.getenv("DRAIN3_CONFIG_PATH", "/app/drain3.ini")

# ── Models (v7: 2-model ensemble) ──────────────────────────────────────────

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
MODEL_LGBM_PATH = os.getenv("MODEL_LGBM_PATH", "/models/lgbm_v7.onnx")
MODEL_AUTOENCODER_PATH = os.getenv("MODEL_AUTOENCODER_PATH", "/models/autoencoder_v7.onnx")
MODEL_AE_CALIBRATION_PATH = os.getenv(
    "MODEL_AE_CALIBRATION_PATH", "/models/ae_calibration_v7.json"
)
FEATURE_SCALER_PATH = os.getenv("FEATURE_SCALER_PATH", "/models/feature_scaler_v7.json")
MANIFEST_PATH = os.getenv("MANIFEST_PATH", "/models/manifest_v7.json")

# ── Score Weights (v7: 2-model) ─────────────────────────────────────────────

LGBM_WEIGHT = float(os.getenv("LGBM_WEIGHT", "0.85"))
AUTOENCODER_WEIGHT = float(os.getenv("AUTOENCODER_WEIGHT", "0.15"))

# Feature indices masked to 0 in AE (stateful EWMA / connection-tracker features
# that diverge between training accumulation and cold-start inference)
# F08 entity_event_rate, F09 entity_error_rate, F10 entity_unique_actions,
# F11 source_novelty, F16 conn_rate_fast, F17 conn_rate_slow,
# F18 rate_acceleration, F19 port_entropy
AE_MASKED_INDICES = (8, 9, 10, 11, 16, 17, 18, 19)

# ── Thresholds (v7) ────────────────────────────────────────────────────────

DEFAULT_SUSPICIOUS_THRESHOLD = float(
    os.getenv("DEFAULT_SUSPICIOUS_THRESHOLD", "0.40")
)
DEFAULT_ANOMALOUS_THRESHOLD = float(
    os.getenv("DEFAULT_ANOMALOUS_THRESHOLD", "0.90")
)
DISAGREEMENT_THRESHOLD = float(os.getenv("DISAGREEMENT_THRESHOLD", "0.40"))
DISAGREEMENT_ESCALATION_FLOOR = float(
    os.getenv("DISAGREEMENT_ESCALATION_FLOOR", "0.70")
)

# ── Operational ─────────────────────────────────────────────────────────────

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "2000"))
BATCH_TIMEOUT_MS = int(os.getenv("BATCH_TIMEOUT_MS", "500"))
INFERENCE_WORKERS = int(os.getenv("INFERENCE_WORKERS", "4"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
HEALTH_PORT = int(os.getenv("TRIAGE_PORT", "8300"))

# ── EWMA Rate Tracking ─────────────────────────────────────────────────────

EWMA_HALF_LIFE_FAST = float(os.getenv("EWMA_HALF_LIFE_FAST", "2.0"))
EWMA_HALF_LIFE_MEDIUM = float(os.getenv("EWMA_HALF_LIFE_MEDIUM", "60.0"))
EWMA_HALF_LIFE_SLOW = float(os.getenv("EWMA_HALF_LIFE_SLOW", "600.0"))
EWMA_CLEANUP_INTERVAL_SEC = float(os.getenv("EWMA_CLEANUP_INTERVAL_SEC", "60.0"))
EWMA_MAX_ENTITIES = int(os.getenv("EWMA_MAX_ENTITIES", "500000"))

# ── Kill-Chain Tracker ──────────────────────────────────────────────────────

KILL_CHAIN_DECAY_SEC = float(os.getenv("KILL_CHAIN_DECAY_SEC", "3600.0"))
KILL_CHAIN_SCORE_GATE = float(os.getenv("KILL_CHAIN_SCORE_GATE", "0.30"))

# ── Cross-Host Correlation ──────────────────────────────────────────────────

CROSS_HOST_WINDOW_SEC = float(os.getenv("CROSS_HOST_WINDOW_SEC", "900.0"))
CROSS_HOST_MIN_SCORE = float(os.getenv("CROSS_HOST_MIN_SCORE", "0.50"))

# ── Connection Tracker (Sharded) ────────────────────────────────────────────

CONN_TRACKER_SHARDS = int(os.getenv("CONN_TRACKER_SHARDS", "16"))
CONN_TIME_WINDOW_SEC = float(os.getenv("CONN_TIME_WINDOW_SEC", "2.0"))
CONN_HOST_WINDOW_SIZE = int(os.getenv("CONN_HOST_WINDOW_SIZE", "100"))
CONN_CLEANUP_INTERVAL_SEC = float(os.getenv("CONN_CLEANUP_INTERVAL_SEC", "10.0"))

# ── IOC Boost ───────────────────────────────────────────────────────────────

IOC_BOOST_BASE = float(os.getenv("IOC_BOOST_BASE", "0.05"))
IOC_BOOST_SCALE = float(os.getenv("IOC_BOOST_SCALE", "0.15"))

# ── SHAP (Async) ────────────────────────────────────────────────────────────

SHAP_ENABLED = os.getenv("SHAP_ENABLED", "true").lower() == "true"
SHAP_QUEUE_SIZE = int(os.getenv("SHAP_QUEUE_SIZE", "1000"))
SHAP_BATCH_SIZE = int(os.getenv("SHAP_BATCH_SIZE", "50"))

# ── Startup / Health ────────────────────────────────────────────────────────

SELFTEST_ENABLED = os.getenv("SELFTEST_ENABLED", "true").lower() == "true"
STARTUP_HEALTH_RETRIES = int(os.getenv("STARTUP_HEALTH_RETRIES", "30"))
STARTUP_HEALTH_DELAY_SEC = float(os.getenv("STARTUP_HEALTH_DELAY_SEC", "2.0"))

# ── Drift Monitoring ────────────────────────────────────────────────────────

DRIFT_ENABLED = os.getenv("DRIFT_ENABLED", "true").lower() == "true"
DRIFT_INTERVAL_BATCHES = int(os.getenv("DRIFT_INTERVAL_BATCHES", "500"))
DRIFT_WINDOW_SIZE = int(os.getenv("DRIFT_WINDOW_SIZE", "5000"))
DRIFT_PSI_BINS = int(os.getenv("DRIFT_PSI_BINS", "10"))
DRIFT_PSI_WARNING = float(os.getenv("DRIFT_PSI_WARNING", "0.1"))
DRIFT_PSI_CRITICAL = float(os.getenv("DRIFT_PSI_CRITICAL", "0.25"))

# ── Prometheus Metrics ──────────────────────────────────────────────────────

METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").lower() == "true"

# ── Source Type Numeric Mapping ─────────────────────────────────────────────

SOURCE_TYPE_MAP = {
    "syslog": 1, "linux_auth": 1, "sshd": 1, "sudo": 1, "pam": 1,
    "auditd": 1, "docker_logs": 1, "journald": 1,
    "windows_event": 2, "winlogbeat": 2, "wineventlog": 2, "sysmon": 2,
    "firewall": 3, "cef": 3,
    "active_directory": 4, "ldap": 4,
    "dns": 5, "dns_logs": 5,
    "cloudtrail": 6, "aws_cloudtrail": 6,
    "kubernetes": 7, "k8s_audit": 7,
    "nginx": 8, "apache": 8, "web_server": 8,
    "netflow": 9, "ipfix": 9,
    "ids_ips": 10, "zeek": 10, "snort": 10, "suricata": 10,
    "http_json": 1, "file_logs": 1, "unknown": 1,
}

# ── Protocol Numeric Mapping ────────────────────────────────────────────────

PROTOCOL_MAP = {
    "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2,
    "gre": 47, "esp": 50, "ah": 51, "sctp": 132,
}

# ── Severity Text → Numeric ────────────────────────────────────────────────

SEVERITY_MAP = {
    "debug": 0, "info": 0, "notice": 1, "warning": 2, "warn": 2,
    "error": 3, "err": 3, "critical": 4, "alert": 4, "emergency": 4,
    "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
    "low": 1, "medium": 2, "high": 3,
}

# ── Action Type Mapping ────────────────────────────────────────────────────

ACTION_TYPE_MAP = {
    "info": 0,
    "auth_attempt": 1,
    "auth_success": 2,
    "auth_fail": 3,
    "process_create": 4,
    "process_terminate": 5,
    "network_connect": 6,
    "network_deny": 7,
    "policy_change": 8,
    "privilege_use": 9,
    "data_access": 10,
    "config_change": 11,
}

ACTION_NAMES = {v: k for k, v in ACTION_TYPE_MAP.items()}

# ── Event ID Risk Score Mapping ─────────────────────────────────────────────

WINDOWS_EVENT_RISK = {
    4624: 0.1, 4625: 0.7, 4634: 0.05, 4648: 0.6,
    4656: 0.4, 4663: 0.3, 4672: 0.5, 4688: 0.3,
    4689: 0.1, 4697: 0.8, 4698: 0.7, 4720: 0.9,
    4722: 0.7, 4724: 0.6, 4728: 0.8, 4732: 0.8,
    4756: 0.7, 4768: 0.2, 4769: 0.2, 4771: 0.6,
    4776: 0.3, 5140: 0.4, 5145: 0.4, 7045: 0.8,
    1102: 0.9, 4104: 0.6,
}

# ── Security Keyword Patterns ───────────────────────────────────────────────

THREAT_KEYWORDS = (
    "fail", "denied", "error", "attack", "exploit", "malicious",
    "unauthorized", "violation", "brute", "inject", "overflow",
    "escalat", "privilege", "sudo", "root", "admin",
    "backdoor", "payload", "malware", "shellcode", "reverse",
    "c2", "beacon", "exfiltrat", "lateral", "mimikatz",
    "phish", "trojan", "ransomware", "keylog", "credential",
    "dump", "powershell", "encoded", "obfuscat",
)
