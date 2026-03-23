"""
CLIF Triage Agent v7 — Feature Extractor (32 features)
=========================================================
Extracts the 32-feature vector from CLIF pipeline events.

4 feature tracks:
  Track A — Universal (12):  Works for ALL log types
  Track B — Network (8):     Only for events with flow data
  Track C — Text (6):        For events with a message body
  Track D — Behavioral (6):  Computed from temporal state

Design principle: Every feature is computable from ANY log format.
Non-applicable features default to 0.0 (handled by the model
which was trained with the same nulling pattern).

The SAME code is used for training AND production to eliminate
train/serve skew.
"""

from __future__ import annotations

import logging
import math
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

import config

logger = logging.getLogger("clif.triage.features")

# ── Canonical feature order (32 features, v7) ───────────────────────────────

FEATURE_NAMES = [
    # Track A — Universal (12)
    "hour_of_day",              # 0
    "day_of_week",              # 1
    "is_off_hours",             # 2
    "severity_numeric",         # 3
    "event_id_risk_score",      # 4
    "action_type",              # 5
    "is_admin_action",          # 6
    "has_known_ioc",            # 7
    "entity_event_rate",        # 8
    "entity_error_rate",        # 9
    "entity_unique_actions",    # 10
    "source_novelty",           # 11
    # Track B — Network (8)
    "dst_port",                 # 12
    "protocol_numeric",         # 13
    "byte_ratio",               # 14
    "total_bytes_log",          # 15
    "conn_rate_fast",           # 16
    "conn_rate_slow",           # 17
    "rate_acceleration",        # 18
    "port_entropy",             # 19
    # Track C — Text (6)
    "message_entropy",          # 20
    "message_length_log",       # 21
    "numeric_ratio",            # 22
    "special_char_ratio",       # 23
    "keyword_threat_score",     # 24
    "template_novelty",         # 25
    # Track D — Behavioral (6)
    "host_score_baseline_z",    # 26
    "user_score_baseline_z",    # 27
    "kill_chain_stage",         # 28
    "kill_chain_velocity",      # 29
    "cross_host_correlation",   # 30
    "dns_query_entropy",        # 31
]

NUM_FEATURES = len(FEATURE_NAMES)


# ── Sharded Connection Tracker ──────────────────────────────────────────────

@dataclass
class _ConnRecord:
    __slots__ = ("timestamp", "dst_port", "service", "protocol", "error_type")
    timestamp: float
    dst_port: int
    service: str
    protocol: str
    error_type: str


class ShardedConnectionTracker:
    """
    16-shard connection tracker for network-flow KDD-style features.
    Each shard has its own lock — 4 feature extraction threads hit
    different shards ~94% of the time (vs 0% with a single lock).
    """

    def __init__(
        self,
        num_shards: int = 16,
        time_window_sec: float = 2.0,
        host_window_size: int = 100,
    ):
        self._num_shards = num_shards
        self._time_window = time_window_sec
        self._host_window = host_window_size

        self._shards = [
            {
                "lock": threading.Lock(),
                "src": defaultdict(lambda: deque(maxlen=10000)),
                "dst": defaultdict(lambda: deque(maxlen=host_window_size)),
                "port_history": defaultdict(lambda: deque(maxlen=200)),
            }
            for _ in range(num_shards)
        ]

    def _shard_for(self, src_ip: str) -> int:
        return hash(src_ip) % self._num_shards

    def record_and_compute(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str,
        protocol: str,
        error_type: str = "normal",
    ) -> Dict[str, float]:
        """Record a connection and compute all network features at once."""
        now = time.monotonic()
        shard = self._shards[self._shard_for(src_ip)]

        rec = _ConnRecord(
            timestamp=now,
            dst_port=dst_port,
            service=service,
            protocol=protocol,
            error_type=error_type,
        )

        with shard["lock"]:
            shard["src"][src_ip].append(rec)
            shard["dst"][dst_ip].append(rec)
            shard["port_history"][src_ip].append(dst_port)

            # Time-window features
            cutoff = now - self._time_window
            recent = [r for r in shard["src"][src_ip] if r.timestamp >= cutoff]
            count = max(len(recent), 1)

            # Connection rates
            conn_rate_fast = float(count)

            # Slow rate: count in larger window
            slow_cutoff = now - 600.0
            slow_recent = [
                r for r in shard["src"][src_ip]
                if r.timestamp >= slow_cutoff
            ]
            conn_rate_slow = float(len(slow_recent))

            rate_acceleration = conn_rate_fast / max(conn_rate_slow / 300.0, 0.01)

            # Port entropy (Shannon entropy of dst ports)
            ports = list(shard["port_history"][src_ip])
            port_entropy = self._shannon_entropy(ports) if ports else 0.0

        return {
            "conn_rate_fast": conn_rate_fast,
            "conn_rate_slow": conn_rate_slow,
            "rate_acceleration": min(rate_acceleration, 100.0),
            "port_entropy": port_entropy,
        }

    @staticmethod
    def _shannon_entropy(values: List[int]) -> float:
        """Compute Shannon entropy of a list of integer values."""
        if not values:
            return 0.0
        n = len(values)
        counts: Dict[int, int] = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1

        entropy = 0.0
        for c in counts.values():
            p = c / n
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def get_stats(self) -> Dict[str, int]:
        total_src = 0
        total_dst = 0
        for shard in self._shards:
            with shard["lock"]:
                total_src += len(shard["src"])
                total_dst += len(shard["dst"])
        return {"tracked_src_ips": total_src, "tracked_dst_ips": total_dst}


# ── Source Novelty Tracker ──────────────────────────────────────────────────

class SourceNoveltyTracker:
    """
    Tracks (hostname, source_type) pairs seen in the last 24h.
    Returns 1.0 for novel sources, 0.0 for known sources.
    """

    TTL_SEC = 86400.0  # 24 hours

    def __init__(self):
        self._lock = threading.Lock()
        self._seen: Dict[str, float] = {}  # key → last_seen_timestamp

    def check_and_record(
        self, hostname: str, source_type: str, timestamp: float
    ) -> float:
        key = f"{hostname}::{source_type}"
        with self._lock:
            last_seen = self._seen.get(key)
            self._seen[key] = timestamp

            if last_seen is None:
                return 1.0
            if timestamp - last_seen > self.TTL_SEC:
                return 1.0
            return 0.0

    def cleanup(self, now: float) -> int:
        cutoff = now - self.TTL_SEC * 2
        with self._lock:
            stale = [k for k, v in self._seen.items() if v < cutoff]
            for k in stale:
                del self._seen[k]
            return len(stale)


# ── Action Type Classifier ──────────────────────────────────────────────────

# Windows Event ID → action type
_WINDOWS_EVENT_ACTION = {
    4624: "auth_success", 4625: "auth_fail",
    4634: "info", 4648: "auth_attempt",
    4656: "data_access", 4663: "data_access",
    4672: "privilege_use", 4688: "process_create",
    4689: "process_terminate", 4697: "config_change",
    4698: "config_change", 4720: "config_change",
    4722: "config_change", 4724: "config_change",
    4728: "policy_change", 4732: "policy_change",
    4756: "policy_change", 4768: "auth_attempt",
    4769: "auth_attempt", 4771: "auth_fail",
    4776: "auth_attempt", 5140: "data_access",
    7045: "config_change", 1102: "config_change",
    4104: "process_create",
}

# Syslog keyword patterns for action classification
_SYSLOG_ACTION_PATTERNS = [
    (re.compile(r"\b(?:accepted|successful|opened)\b", re.I), "auth_success"),
    (re.compile(r"\b(?:failed|invalid|denied|rejected)\b", re.I), "auth_fail"),
    (re.compile(r"\b(?:session opened|logged in|login)\b", re.I), "auth_attempt"),
    (re.compile(r"\b(?:sudo|su:|root)\b", re.I), "privilege_use"),
    (re.compile(r"\b(?:started|exec|spawn|fork)\b", re.I), "process_create"),
    (re.compile(r"\b(?:stopped|killed|terminated|exit)\b", re.I), "process_terminate"),
    (re.compile(r"\b(?:connect|established|syn)\b", re.I), "network_connect"),
    (re.compile(r"\b(?:blocked|dropped|firewall)\b", re.I), "network_deny"),
    (re.compile(r"\b(?:changed|modified|updated|installed)\b", re.I), "config_change"),
]


def classify_action(event: Dict[str, Any], topic: str) -> int:
    """Classify an event into one of 12 action types."""
    # Windows Event ID lookup
    event_id = event.get("windows_event_id") or event.get("EventID") or event.get("event_id")
    if event_id is not None:
        try:
            eid = int(event_id)
            action_name = _WINDOWS_EVENT_ACTION.get(eid)
            if action_name:
                return config.ACTION_TYPE_MAP[action_name]
        except (ValueError, TypeError):
            pass

    # K8s verb mapping
    k8s_verb = event.get("k8s_verb", "").lower()
    if k8s_verb:
        k8s_map = {
            "get": "data_access", "list": "data_access", "watch": "data_access",
            "create": "config_change", "update": "config_change",
            "patch": "config_change", "delete": "config_change",
            "exec": "process_create", "attach": "process_create",
        }
        action_name = k8s_map.get(k8s_verb, "info")
        return config.ACTION_TYPE_MAP[action_name]

    # Cloud action mapping
    cloud_action = event.get("cloud_action", "").lower()
    if cloud_action:
        if any(k in cloud_action for k in ("create", "put", "attach", "add")):
            return config.ACTION_TYPE_MAP["config_change"]
        if any(k in cloud_action for k in ("delete", "remove", "detach")):
            return config.ACTION_TYPE_MAP["config_change"]
        if any(k in cloud_action for k in ("get", "describe", "list", "head")):
            return config.ACTION_TYPE_MAP["data_access"]
        if "login" in cloud_action or "signin" in cloud_action:
            return config.ACTION_TYPE_MAP["auth_attempt"]
        return config.ACTION_TYPE_MAP["info"]

    # Network events
    if topic == "network-events":
        msg = str(event.get("message", event.get("message_body", ""))).lower()
        if "deny" in msg or "block" in msg or "drop" in msg:
            return config.ACTION_TYPE_MAP["network_deny"]
        return config.ACTION_TYPE_MAP["network_connect"]

    # Syslog / generic: pattern-based classification
    msg = str(event.get("message", event.get("message_body", event.get("description", ""))))
    for pattern, action_name in _SYSLOG_ACTION_PATTERNS:
        if pattern.search(msg):
            return config.ACTION_TYPE_MAP[action_name]

    return config.ACTION_TYPE_MAP["info"]


def detect_admin_action(event: Dict[str, Any]) -> int:
    """
    Detect whether an event represents an administrative action.
    Returns 1 for admin, 0 for non-admin.
    """
    # Windows: LogonType=10 (RemoteInteractive) or privilege assignment
    logon_type = event.get("windows_logon_type") or event.get("LogonType")
    if logon_type is not None:
        try:
            if int(logon_type) == 10:
                return 1
        except (ValueError, TypeError):
            pass

    event_id = event.get("windows_event_id") or event.get("EventID")
    if event_id is not None:
        try:
            if int(event_id) in (4672, 4720, 4728, 4732, 4756, 7045, 1102):
                return 1
        except (ValueError, TypeError):
            pass

    # K8s: system:masters group
    k8s_groups = str(event.get("k8s_groups", ""))
    if "system:masters" in k8s_groups:
        return 1

    k8s_is_admin = event.get("k8s_is_admin")
    if k8s_is_admin:
        return 1

    # Cloud: IAM/policy modification actions
    cloud_action = str(event.get("cloud_action", "")).lower()
    if any(k in cloud_action for k in (
        "iam", "policy", "role", "permission", "createuser", "attachpolicy",
    )):
        return 1

    # Syslog: sudo / root
    msg = str(event.get("message", event.get("message_body", ""))).lower()
    if "sudo" in msg or "root" in msg.split()[:3]:
        return 1

    return 0


def compute_event_risk_score(event: Dict[str, Any]) -> float:
    """
    Compute pre-defined risk score from event type identifiers.
    Windows EventID lookup, CEF severity, syslog keyword matching.
    """
    # Windows Event ID
    event_id = event.get("windows_event_id") or event.get("EventID")
    if event_id is not None:
        try:
            score = config.WINDOWS_EVENT_RISK.get(int(event_id))
            if score is not None:
                return score
        except (ValueError, TypeError):
            pass

    # CEF severity (0-10 scale)
    cef_severity = event.get("cef_severity")
    if cef_severity is not None:
        try:
            return min(float(cef_severity) / 10.0, 1.0)
        except (ValueError, TypeError):
            pass

    # Derive from severity level
    severity_raw = event.get(
        "original_log_level",
        event.get("level", event.get("severity", "info"))
    )
    if isinstance(severity_raw, (int, float)):
        return min(max(float(severity_raw) / 4.0, 0.0), 1.0)

    sev_map = {"debug": 0.0, "info": 0.05, "warning": 0.3, "error": 0.5, "critical": 0.8}
    return sev_map.get(str(severity_raw).lower(), 0.1)


def compute_message_entropy(text: str) -> float:
    """Shannon entropy of message bytes."""
    if not text:
        return 0.0
    n = len(text)
    if n == 0:
        return 0.0

    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def compute_dns_query_entropy(event: Dict[str, Any]) -> float:
    """Shannon entropy of DNS query string (0 if not DNS)."""
    query = event.get("dns_query_name", "")
    if not query:
        return 0.0
    return compute_message_entropy(str(query))


def compute_keyword_threat_score(text: str) -> float:
    """Log-linear count of security keywords in message text."""
    if not text:
        return 0.0
    text_lower = text.lower()
    count = sum(1 for kw in config.THREAT_KEYWORDS if kw in text_lower)
    if count == 0:
        return 0.0
    return math.log1p(count) / math.log1p(len(config.THREAT_KEYWORDS))


# ── Main Feature Extractor ──────────────────────────────────────────────────

class FeatureExtractor:
    """
    Extracts the 32-feature vector from CLIF pipeline events.

    Combines:
    - Direct field extraction (temporal, severity, action)
    - EWMA entity rate tracking (rate, error rate, action diversity)
    - Sharded connection tracking (network flow features)
    - Text analysis (entropy, keyword scoring)
    - Drain3 template mining (template novelty)
    - IOC cache lookup
    - Kill-chain state (passed in from external tracker)

    Thread-safe: designed to be called from 4 parallel workers.
    """

    def __init__(
        self,
        drain3_miner,
        ewma_tracker,
        conn_tracker: Optional[ShardedConnectionTracker] = None,
        novelty_tracker: Optional[SourceNoveltyTracker] = None,
        ioc_lookup_fn=None,
    ):
        self._drain3 = drain3_miner
        self._ewma = ewma_tracker
        self._conn_tracker = conn_tracker or ShardedConnectionTracker(
            num_shards=config.CONN_TRACKER_SHARDS,
            time_window_sec=config.CONN_TIME_WINDOW_SEC,
            host_window_size=config.CONN_HOST_WINDOW_SIZE,
        )
        self._novelty = novelty_tracker or SourceNoveltyTracker()
        self._ioc_lookup = ioc_lookup_fn

    @property
    def feature_names(self) -> List[str]:
        return FEATURE_NAMES

    def extract(
        self,
        event: Dict[str, Any],
        topic: str,
        kill_chain_stage: float = 0.0,
        kill_chain_velocity: float = 0.0,
        cross_host_corr: float = 0.0,
        host_baseline_z: float = 0.0,
        user_baseline_z: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Extract 32 features from a single event.

        Behavioral features (kill_chain_*, cross_host_*, baselines)
        are computed externally and passed in, since they depend on
        scores which create a circular dependency if computed here.

        Returns:
            Dict with 32 features + metadata keys prefixed with '_'.
        """
        now_mono = time.monotonic()
        is_network = topic == "network-events"
        is_security = topic == "security-events"

        # Parse embedded network fields from security event text
        _parsed_net: Dict[str, Any] = {}
        if is_security:
            desc = event.get("description", event.get("message_body", ""))
            _parsed_net = self._parse_network_from_text(str(desc))

        has_network_data = is_network or bool(
            _parsed_net.get("src_ip") and _parsed_net.get("dst_ip")
        )

        # ── TRACK A: Universal Features (12) ────────────────────────────

        # F0-F1: Temporal
        ts = self._parse_timestamp(event.get("timestamp"))
        hour_of_day = float(ts.hour)
        day_of_week = float(ts.weekday())

        # F2: Off-hours flag
        is_weekend = ts.weekday() >= 5
        is_off_hours = 1.0 if (ts.hour in range(0, 6) or ts.hour >= 22 or is_weekend) else 0.0

        # F3: Severity (from original source log level)
        severity_raw = event.get(
            "original_log_level",
            event.get("level", event.get("severity", "info"))
        )
        severity_numeric = float(self._map_severity(severity_raw))

        # F4: Event ID risk score
        event_id_risk_score = compute_event_risk_score(event)

        # F5: Action type
        action_type = float(classify_action(event, topic))

        # F6: Admin action
        is_admin_action = float(detect_admin_action(event))

        # F7: IOC lookup
        has_known_ioc = 0.0
        if self._ioc_lookup is not None:
            src_ip = event.get("src_ip", _parsed_net.get("src_ip", ""))
            dst_ip = event.get("dst_ip", _parsed_net.get("dst_ip", ""))
            if (src_ip and self._ioc_lookup(str(src_ip))) or \
               (dst_ip and self._ioc_lookup(str(dst_ip))):
                has_known_ioc = 1.0

        # F8-F10: Entity rates (EWMA)
        hostname = str(event.get("hostname", event.get("host", "unknown")))
        user = str(event.get("user", event.get("windows_target_user",
                   event.get("k8s_user", event.get("cloud_user", "")))))
        entity_key = f"{hostname}::{user}" if user else hostname
        is_error = severity_numeric >= 3.0

        ewma_rates = self._ewma.update(
            entity_key=entity_key,
            timestamp=now_mono,
            is_error=is_error,
            action_type=int(action_type),
        )

        # F11: Source novelty
        source_type_raw = str(event.get("source_type", event.get("source", "unknown")))
        source_novelty = self._novelty.check_and_record(
            hostname, source_type_raw, now_mono
        )

        # ── TRACK B: Network Features (8) ───────────────────────────────

        if has_network_data:
            src_ip = str(event.get("src_ip", _parsed_net.get("src_ip", "0.0.0.0")))
            dst_ip = str(event.get("dst_ip", _parsed_net.get("dst_ip", "0.0.0.0")))

            dst_port = self._safe_float(
                event.get("dst_port", _parsed_net.get("dst_port", 0))
            )
            proto_raw = event.get("protocol", _parsed_net.get("protocol", "tcp"))
            protocol_numeric = float(
                config.PROTOCOL_MAP.get(str(proto_raw).lower(), 6)
            )

            # Byte metrics
            src_bytes = min(self._safe_float(
                event.get("bytes_sent", _parsed_net.get("bytes_sent", 0))
            ), 1e9)
            dst_bytes = min(self._safe_float(
                event.get("bytes_received", _parsed_net.get("bytes_received", 0))
            ), 1e9)

            total_bytes = src_bytes + dst_bytes
            byte_ratio = src_bytes / max(total_bytes, 1.0)
            total_bytes_log = math.log10(1.0 + total_bytes)

            # Connection tracking
            service = self._port_to_service(int(dst_port))
            conn_features = self._conn_tracker.record_and_compute(
                src_ip=src_ip, dst_ip=dst_ip,
                dst_port=int(dst_port), service=service,
                protocol=str(proto_raw).lower(),
            )
        else:
            dst_port = 0.0
            protocol_numeric = 0.0
            byte_ratio = 0.0
            total_bytes_log = 0.0
            conn_features = {
                "conn_rate_fast": 0.0, "conn_rate_slow": 0.0,
                "rate_acceleration": 0.0, "port_entropy": 0.0,
            }

        # ── TRACK C: Text Features (6) ──────────────────────────────────

        message_body = str(event.get("message_body", event.get("message", "")))
        if is_network and not message_body:
            message_body = (
                f"{event.get('protocol', 'TCP')} "
                f"{event.get('src_ip', '?')}:{event.get('src_port', 0)} → "
                f"{event.get('dst_ip', '?')}:{event.get('dst_port', 0)}"
            )

        # F20: Message entropy
        message_entropy = compute_message_entropy(message_body) if message_body else 0.0

        # F21: Message length (log)
        message_length_log = math.log10(1.0 + len(message_body)) if message_body else 0.0

        # F22: Numeric ratio
        if message_body:
            digit_count = sum(1 for c in message_body if c.isdigit())
            numeric_ratio = digit_count / max(len(message_body), 1)
        else:
            numeric_ratio = 0.0

        # F23: Special character ratio
        if message_body:
            special_count = sum(
                1 for c in message_body
                if not c.isalnum() and not c.isspace()
            )
            special_char_ratio = special_count / max(len(message_body), 1)
        else:
            special_char_ratio = 0.0

        # F24: Keyword threat score
        keyword_threat_score = compute_keyword_threat_score(message_body)

        # F25: Template novelty (Drain3)
        template_id, template_str, template_rarity = self._drain3.mine(
            message_body if message_body else ""
        )
        template_novelty = template_rarity  # Drain3 already computes 0-1 novelty

        # F31: DNS query entropy
        dns_query_entropy = compute_dns_query_entropy(event)

        # ── Assemble 32-feature vector ──────────────────────────────────

        features = {
            # Track A — Universal
            "hour_of_day": hour_of_day,
            "day_of_week": day_of_week,
            "is_off_hours": is_off_hours,
            "severity_numeric": severity_numeric,
            "event_id_risk_score": event_id_risk_score,
            "action_type": action_type,
            "is_admin_action": is_admin_action,
            "has_known_ioc": has_known_ioc,
            "entity_event_rate": ewma_rates["entity_event_rate"],
            "entity_error_rate": ewma_rates["entity_error_rate"],
            "entity_unique_actions": ewma_rates["entity_unique_actions"],
            "source_novelty": source_novelty,
            # Track B — Network
            "dst_port": dst_port,
            "protocol_numeric": protocol_numeric,
            "byte_ratio": byte_ratio,
            "total_bytes_log": total_bytes_log,
            "conn_rate_fast": conn_features["conn_rate_fast"],
            "conn_rate_slow": conn_features["conn_rate_slow"],
            "rate_acceleration": conn_features["rate_acceleration"],
            "port_entropy": conn_features["port_entropy"],
            # Track C — Text
            "message_entropy": message_entropy,
            "message_length_log": message_length_log,
            "numeric_ratio": numeric_ratio,
            "special_char_ratio": special_char_ratio,
            "keyword_threat_score": keyword_threat_score,
            "template_novelty": template_novelty,
            # Track D — Behavioral (passed in externally)
            "host_score_baseline_z": host_baseline_z,
            "user_score_baseline_z": user_baseline_z,
            "kill_chain_stage": kill_chain_stage,
            "kill_chain_velocity": kill_chain_velocity,
            "cross_host_correlation": cross_host_corr,
            "dns_query_entropy": dns_query_entropy,
        }

        # Attach metadata (not fed to models)
        features["_template_id"] = template_id
        features["_template_str"] = template_str
        features["_source_type"] = source_type_raw
        features["_hostname"] = hostname
        features["_user"] = user
        features["_entity_key"] = entity_key
        features["_topic"] = topic
        features["_action_type_name"] = config.ACTION_NAMES.get(int(action_type), "info")

        return features

    def extract_batch(
        self, events: List[Dict[str, Any]], topic: str, **kwargs
    ) -> List[Dict[str, Any]]:
        """Extract features from a batch of events."""
        return [self.extract(e, topic, **kwargs) for e in events]

    def to_numpy(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert a feature dict to numpy array in canonical order."""
        return np.array(
            [features[name] for name in FEATURE_NAMES], dtype=np.float32
        )

    def batch_to_numpy(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dicts to a 2D numpy array (N, 32)."""
        arr = np.array(
            [[f[name] for name in FEATURE_NAMES] for f in features_list],
            dtype=np.float32,
        )
        return np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(raw) -> datetime:
        if isinstance(raw, datetime):
            return raw
        if not raw:
            return datetime.now(timezone.utc)
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc)

    @staticmethod
    def _map_severity(raw) -> int:
        if isinstance(raw, (int, float)):
            return max(0, min(4, int(raw)))
        return config.SEVERITY_MAP.get(str(raw).lower().strip(), 0)

    @staticmethod
    def _safe_float(val, default: float = 0.0) -> float:
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _port_to_service(port: int) -> str:
        port_map = {
            20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 445: "smb", 993: "imaps",
            1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
            8080: "http_alt", 8443: "https_alt", 9092: "kafka",
        }
        return port_map.get(port, f"port_{port}")

    # ── Network field extraction from text (regex) ───────────────────────

    _RE_IP_PORT_ARROW = re.compile(
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*(?:→|->)\s*(\d+\.\d+\.\d+\.\d+):(\d+)"
    )
    _RE_SRC_IP = re.compile(r"\bsrc=(\d+\.\d+\.\d+\.\d+)")
    _RE_DST_IP = re.compile(r"\bdst=(\d+\.\d+\.\d+\.\d+)")
    _RE_DST_PORT = re.compile(r"\bdst=\d+\.\d+\.\d+\.\d+:(\d+)")
    _RE_PROTO = re.compile(r"\bproto=(\w+)", re.IGNORECASE)
    _RE_BYTES_SENT = re.compile(r"\b(?:bytes_sent|src_bytes)=(\d+)")
    _RE_BYTES_RECV = re.compile(r"\b(?:bytes_recv|dst_bytes)=(\d+)")

    @classmethod
    def _parse_network_from_text(cls, text: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if not text:
            return result

        m = cls._RE_IP_PORT_ARROW.search(text)
        if m:
            result["src_ip"] = m.group(1)
            result["src_port"] = int(m.group(2))
            result["dst_ip"] = m.group(3)
            result["dst_port"] = int(m.group(4))
        else:
            ms = cls._RE_SRC_IP.search(text)
            if ms:
                result["src_ip"] = ms.group(1)
            md = cls._RE_DST_IP.search(text)
            if md:
                result["dst_ip"] = md.group(1)
            mdp = cls._RE_DST_PORT.search(text)
            if mdp:
                result["dst_port"] = int(mdp.group(1))

        mp = cls._RE_PROTO.search(text)
        if mp:
            result["protocol"] = mp.group(1)

        mbs = cls._RE_BYTES_SENT.search(text)
        if mbs:
            result["bytes_sent"] = int(mbs.group(1))
        mbr = cls._RE_BYTES_RECV.search(text)
        if mbr:
            result["bytes_received"] = int(mbr.group(1))

        return result

    def get_stats(self) -> Dict:
        return {
            "drain3": self._drain3.get_stats(),
            "connection_tracker": self._conn_tracker.get_stats(),
            "ewma_tracker": self._ewma.get_stats(),
            "feature_count": NUM_FEATURES,
            "ioc_lookup_enabled": self._ioc_lookup is not None,
        }
