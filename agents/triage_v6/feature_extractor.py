"""
CLIF Triage Agent — Feature Extractor
========================================
Extracts the 19 canonical features from CLIF pipeline events (v6).

The same 19 features are used by all three models (LightGBM, EIF, ARF).
Feature ordering must exactly match the training-time feature_cols.pkl.

Features 12-19 (same_srv_rate through dst_host_srv_count) are KDD-style
time-window aggregation features. For network events (including security
events with embedded network data), these are computed from a real-time
sliding-window connection tracker.  For pure non-network events (syslog,
Windows, K8s, etc.), these are correctly set to 0.

Security events (ids_ips, firewall) carry network fields inside the
description/message_body text.  A regex parser extracts src_ip, dst_ip,
dst_port, proto, bytes so the connection tracker can operate on them.

The ConnectionTracker implements the standard 2-second time window and
100-connection host window used in the original KDD99 feature engineering.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

import numpy as np

import config
from drain3_miner import Drain3Miner

logger = logging.getLogger("clif.triage.features")

# ── Canonical feature order (must match feature_cols.pkl) ────────────────────
# v6: template_rarity REMOVED from model features (unreliable in production).
#     It's still computed by Drain3 for metadata/ClickHouse, just not fed to
#     LGBM/EIF/ARF via batch_to_numpy().

FEATURE_NAMES = [
    "hour_of_day",
    "day_of_week",
    "severity_numeric",
    "source_type_numeric",
    "src_bytes",
    "dst_bytes",
    "event_freq_1m",
    "protocol",
    "dst_port",
    "threat_intel_flag",
    "duration",
    "same_srv_rate",
    "diff_srv_rate",
    "serror_rate",
    "rerror_rate",
    "count",
    "srv_count",
    "dst_host_count",
    "dst_host_srv_count",
]


@dataclass
class ConnectionRecord:
    """A single connection record in the sliding window."""

    timestamp: float  # monotonic seconds
    src_ip: str
    dst_ip: str
    dst_port: int
    service: str
    protocol: str
    error_type: str  # "normal", "syn_error", "rej_error"


class ConnectionTracker:
    """
    Production-grade sliding-window connection tracker for KDD-style features.

    Maintains two window types:
    1. Time-based:  2-second rolling window per (src_ip → dst_ip) pair
       → Computes: count, srv_count, same_srv_rate, diff_srv_rate,
                   serror_rate, rerror_rate
    2. Count-based: Last 100 connections per dst_ip
       → Computes: dst_host_count, dst_host_srv_count

    Thread-safe via fine-grained locking (one lock per dst_ip bucket).
    Automatic cleanup of stale entries runs on a configurable interval.
    """

    def __init__(
        self,
        time_window_sec: float = 2.0,
        host_window_size: int = 100,
        cleanup_interval_sec: float = 10.0,
    ):
        self._time_window = time_window_sec
        self._host_window = host_window_size
        self._cleanup_interval = cleanup_interval_sec

        # Time-based: key = src_ip, value = deque of ConnectionRecord
        self._src_connections: Dict[str, Deque[ConnectionRecord]] = defaultdict(
            lambda: deque(maxlen=10000)
        )
        # Count-based: key = dst_ip, value = deque of ConnectionRecord
        self._dst_connections: Dict[str, Deque[ConnectionRecord]] = defaultdict(
            lambda: deque(maxlen=self._host_window)
        )

        self._lock = threading.Lock()
        self._last_cleanup = time.monotonic()

    def record_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        service: str,
        protocol: str,
        error_type: str = "normal",
    ) -> None:
        """Record a new connection for feature computation."""
        now = time.monotonic()
        rec = ConnectionRecord(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            service=service,
            protocol=protocol,
            error_type=error_type,
        )

        with self._lock:
            self._src_connections[src_ip].append(rec)
            self._dst_connections[dst_ip].append(rec)

            # Periodic cleanup of stale src_ip buckets
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup_stale(now)
                self._last_cleanup = now

    def compute_features(
        self, src_ip: str, dst_ip: str, dst_port: int, service: str
    ) -> Dict[str, float]:
        """
        Compute the 8 KDD-style aggregation features for a connection.

        Returns dict with keys: count, srv_count, same_srv_rate, diff_srv_rate,
                                serror_rate, rerror_rate, dst_host_count,
                                dst_host_srv_count
        """
        now = time.monotonic()
        cutoff = now - self._time_window

        with self._lock:
            # ── Time-window features (src_ip → dst_ip in last 2 seconds) ──
            src_conns = self._src_connections.get(src_ip, deque())
            recent = [r for r in src_conns if r.timestamp >= cutoff and r.dst_ip == dst_ip]

            count = len(recent)
            if count == 0:
                count = 1  # Current connection

            # Connections to same service
            same_srv = sum(1 for r in recent if r.service == service)
            srv_count = same_srv if same_srv > 0 else 1

            same_srv_rate = srv_count / count
            diff_srv_rate = 1.0 - same_srv_rate

            # Error rates
            syn_errors = sum(1 for r in recent if r.error_type == "syn_error")
            rej_errors = sum(1 for r in recent if r.error_type == "rej_error")
            serror_rate = syn_errors / count
            rerror_rate = rej_errors / count

            # ── Host-window features (last 100 connections to dst_ip) ─────
            dst_conns = self._dst_connections.get(dst_ip, deque())
            dst_list = list(dst_conns)[-self._host_window :]

            if dst_list:
                # Unique source IPs connecting to this dst_ip
                unique_src_ips = len(set(r.src_ip for r in dst_list))
                dst_host_count = unique_src_ips

                # Connections to same service on this dst_ip
                same_svc_on_host = sum(1 for r in dst_list if r.service == service)
                dst_host_srv_count = same_svc_on_host
            else:
                dst_host_count = 1
                dst_host_srv_count = 1

        return {
            "count": float(count),
            "srv_count": float(srv_count),
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "serror_rate": serror_rate,
            "rerror_rate": rerror_rate,
            "dst_host_count": float(dst_host_count),
            "dst_host_srv_count": float(dst_host_srv_count),
        }

    def _cleanup_stale(self, now: float) -> None:
        """Remove entries older than 10x the time window from src_connections."""
        stale_cutoff = now - (self._time_window * 10)
        stale_keys = []
        for key, dq in self._src_connections.items():
            while dq and dq[0].timestamp < stale_cutoff:
                dq.popleft()
            if not dq:
                stale_keys.append(key)
        for key in stale_keys:
            del self._src_connections[key]

    def get_stats(self) -> Dict[str, int]:
        """Return tracker statistics."""
        with self._lock:
            return {
                "tracked_src_ips": len(self._src_connections),
                "tracked_dst_ips": len(self._dst_connections),
                "total_src_records": sum(
                    len(dq) for dq in self._src_connections.values()
                ),
                "total_dst_records": sum(
                    len(dq) for dq in self._dst_connections.values()
                ),
            }


class FeatureExtractor:
    """
    Extracts the 20 canonical features from CLIF pipeline events.

    Combines:
    - Direct field extraction (timestamp, severity, bytes, port, protocol)
    - Drain3 template mining (template_rarity)
    - IOC cache lookup (threat_intel_flag)
    - In-memory connection tracking (8 KDD-style aggregation features)
    """

    def __init__(
        self,
        drain3_miner: Drain3Miner,
        ioc_lookup_fn=None,
        conn_tracker: Optional[ConnectionTracker] = None,
    ):
        self._drain3 = drain3_miner
        self._ioc_lookup = ioc_lookup_fn  # Callable[[str], bool]
        self._conn_tracker = conn_tracker or ConnectionTracker(
            time_window_sec=config.CONN_TIME_WINDOW_SEC,
            host_window_size=config.CONN_HOST_WINDOW_SIZE,
            cleanup_interval_sec=config.CONN_CLEANUP_INTERVAL_SEC,
        )

    @property
    def feature_names(self) -> List[str]:
        return FEATURE_NAMES

    def extract(self, event: Dict[str, Any], topic: str) -> Dict[str, Any]:
        """
        Extract features from a single event.

        Args:
            event: Deserialized JSON event from Redpanda.
            topic: Source topic name (determines event schema).

        Returns:
            Dict with 19 features + metadata (template_id, template_str).
        """
        is_network = topic == "network-events"
        is_security = topic == "security-events"

        # ── Parse embedded network fields from security event text ───────
        # Security events (ids_ips, firewall) carry network data inside
        # the description/message_body.  Extract structured fields so we
        # can populate byte counts and connection-tracker features.
        _parsed_net: Dict[str, Any] = {}
        if is_security:
            desc = event.get("description", event.get("message_body", ""))
            _parsed_net = self._parse_network_from_text(str(desc))

        # Treat security events WITH parsed network data as network-like
        has_network_data = is_network or bool(
            _parsed_net.get("src_ip") and _parsed_net.get("dst_ip")
        )

        # ── Feature 1-2: Temporal ────────────────────────────────────────
        ts = self._parse_timestamp(event.get("timestamp"))
        hour_of_day = ts.hour
        day_of_week = ts.weekday()  # 0=Monday

        # ── Feature 3: Severity (from ORIGINAL source log level) ─────────
        # Vector CCS now emits 'original_log_level' (0-4) captured in
        # Section B BEFORE Section C classification overwrites .severity.
        # This breaks the circular dependency where Vector's own regex
        # classification leaked into the models via severity_numeric,
        # causing novel anomalies (no regex match → severity=0) to be
        # systematically under-scored.
        #
        # Fallback chain for backward compatibility:
        #   1. original_log_level  — honest source-system severity (preferred)
        #   2. level               — raw events still carry this
        #   3. severity            — legacy events without the fix
        severity_raw = event.get(
            "original_log_level",
            event.get("level", event.get("severity", "info"))
        )
        severity_numeric = self._map_severity(severity_raw)

        # ── Feature 4: Source Type ───────────────────────────────────────
        source_type_raw = event.get("source_type", event.get("source", "unknown"))
        source_type_numeric = self._map_source_type(source_type_raw, topic)

        # ── Feature 5-6: Byte Counts ────────────────────────────────────
        if is_network:
            src_bytes = float(event.get("bytes_sent", 0))
            dst_bytes = float(event.get("bytes_received", 0))
        elif _parsed_net.get("bytes_sent") is not None:
            # Security event with parsed network bytes
            src_bytes = float(_parsed_net.get("bytes_sent", 0))
            dst_bytes = float(_parsed_net.get("bytes_received", 0))
        elif has_network_data:
            # Security event with parsed IPs but NO parsed byte counts.
            # Use 0 instead of message length — matches training data where
            # network connections without byte info had 0 bytes.
            src_bytes = 0.0
            dst_bytes = 0.0
        else:
            # For non-network events, estimate from message length.
            msg = event.get("message", event.get("message_body",
                            event.get("description", "")))
            src_bytes = float(len(str(msg))) if msg else 0.0
            dst_bytes = 0.0

        # Clamp to prevent inf/extreme values from poisoning model scores
        # (training data had inf in src_bytes from CICIDS2017)
        src_bytes = min(max(src_bytes, 0.0), 1e9)
        dst_bytes = min(max(dst_bytes, 0.0), 1e9)

        # ── Feature 7: Event Frequency ──────────────────────────────────
        duration_raw = event.get("duration_ms", event.get("duration", 0))
        duration_sec = self._safe_float(duration_raw) / 1000.0 if is_network else 0.0
        if is_network and event.get("duration_ms") is not None:
            duration_sec = self._safe_float(event["duration_ms"]) / 1000.0

        if duration_sec > 0:
            event_freq_1m = 60.0 / duration_sec
        else:
            event_freq_1m = 0.0

        # ── Feature 8: Protocol ─────────────────────────────────────────
        proto_raw = event.get("protocol",
                              _parsed_net.get("protocol", "tcp"))
        protocol = config.PROTOCOL_MAP.get(str(proto_raw).lower(), 6)

        # ── Feature 9: Destination Port ─────────────────────────────────
        dst_port = self._safe_float(
            event.get("dst_port",
                       event.get("dest_port",
                                 _parsed_net.get("dst_port", 0)))
        )

        # ── Feature 10: Template Rarity (Drain3) ────────────────────────
        message_body = event.get("message_body", event.get("message", ""))
        if is_network and not message_body:
            # Network events are structured — build a synthetic template string
            message_body = (
                f"{event.get('protocol', 'TCP')} {event.get('src_ip', '?')}"
                f":{event.get('src_port', 0)} → {event.get('dst_ip', '?')}"
                f":{event.get('dst_port', 0)}"
            )
        template_id, template_str, template_rarity = self._drain3.mine(
            str(message_body) if message_body else ""
        )

        # ── Feature 11: Threat Intel Flag ───────────────────────────────
        threat_intel_flag = 0
        if self._ioc_lookup is not None:
            # Check source and destination IPs (structured or parsed)
            src_ip_ioc = event.get("src_ip",
                                   _parsed_net.get("src_ip",
                                                   event.get("ip_address", "")))
            dst_ip_ioc = event.get("dst_ip",
                                   _parsed_net.get("dst_ip", ""))
            if src_ip_ioc and self._ioc_lookup(str(src_ip_ioc)):
                threat_intel_flag = 1
            elif dst_ip_ioc and self._ioc_lookup(str(dst_ip_ioc)):
                threat_intel_flag = 1

        # ── Feature 12: Duration ────────────────────────────────────────
        duration = duration_sec

        # ── Features 12-19: KDD Aggregation Features ────────────────────
        if has_network_data:
            # Use structured fields for network-events, parsed fields for
            # security events with embedded network data.
            src_ip = str(event.get("src_ip",
                                   _parsed_net.get("src_ip", "0.0.0.0")))
            dst_ip = str(event.get("dst_ip",
                                   _parsed_net.get("dst_ip", "0.0.0.0")))
            dst_port_int = int(dst_port)
            service = self._port_to_service(dst_port_int)

            # Determine error type from connection metadata
            error_type = "normal"
            direction = str(event.get("direction", "")).lower()
            # Vector CCS network events have message_body, not message
            msg_lower = str(event.get("message", event.get("message_body", ""))).lower()
            if "syn" in msg_lower and ("error" in msg_lower or "timeout" in msg_lower):
                error_type = "syn_error"
            elif "reject" in msg_lower or "refused" in msg_lower or "rst" in msg_lower:
                error_type = "rej_error"
            # Zero bytes + short duration often indicates SYN/RST
            if src_bytes == 0 and dst_bytes == 0 and duration < 0.001:
                error_type = "syn_error"

            # Record in tracker and compute features
            self._conn_tracker.record_connection(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port_int,
                service=service,
                protocol=str(proto_raw).lower(),
                error_type=error_type,
            )
            agg = self._conn_tracker.compute_features(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port_int,
                service=service,
            )
        else:
            # Non-network events: aggregation features are 0
            # This matches training data — non-network log types had zeros.
            agg = {
                "count": 0.0,
                "srv_count": 0.0,
                "same_srv_rate": 0.0,
                "diff_srv_rate": 0.0,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "dst_host_count": 0.0,
                "dst_host_srv_count": 0.0,
            }

        # ── Assemble feature vector in canonical order ───────────────────
        features = {
            "hour_of_day": float(hour_of_day),
            "day_of_week": float(day_of_week),
            "severity_numeric": float(severity_numeric),
            "source_type_numeric": float(source_type_numeric),
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "event_freq_1m": event_freq_1m,
            "protocol": float(protocol),
            "dst_port": dst_port,
            "threat_intel_flag": float(threat_intel_flag),
            "duration": duration,
            "same_srv_rate": agg["same_srv_rate"],
            "diff_srv_rate": agg["diff_srv_rate"],
            "serror_rate": agg["serror_rate"],
            "rerror_rate": agg["rerror_rate"],
            "count": agg["count"],
            "srv_count": agg["srv_count"],
            "dst_host_count": agg["dst_host_count"],
            "dst_host_srv_count": agg["dst_host_srv_count"],
        }

        # Attach metadata for downstream use (not fed to models)
        features["_template_id"] = template_id
        features["_template_str"] = template_str
        features["_template_rarity"] = template_rarity  # for replay buffer / diagnostics
        features["_source_type"] = str(source_type_raw)
        features["_topic"] = topic

        return features

    def extract_batch(
        self, events: List[Dict[str, Any]], topic: str
    ) -> List[Dict[str, Any]]:
        """Extract features from a batch of events."""
        return [self.extract(e, topic) for e in events]

    def to_numpy(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert a feature dict to numpy array in canonical order."""
        return np.array(
            [features[name] for name in FEATURE_NAMES], dtype=np.float32
        )

    def batch_to_numpy(self, features_list: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dicts to a 2D numpy array."""
        arr = np.array(
            [[f[name] for name in FEATURE_NAMES] for f in features_list],
            dtype=np.float32,
        )
        # Defensive: replace inf/NaN that may come from raw event data
        # (e.g. CICIDS2017 has inf in src_bytes). This prevents model crashes.
        return np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

    # ── Private helpers ──────────────────────────────────────────────────

    @staticmethod
    def _parse_timestamp(raw) -> datetime:
        """Parse ISO-8601 timestamp string to datetime."""
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
        """Map severity to numeric 0-4."""
        if isinstance(raw, (int, float)):
            return max(0, min(4, int(raw)))
        return config.SEVERITY_MAP.get(str(raw).lower().strip(), 0)

    @staticmethod
    def _map_source_type(raw: str, topic: str) -> int:
        """Map source type string to numeric 1-10."""
        raw_lower = str(raw).lower().strip()
        mapped = config.SOURCE_TYPE_MAP.get(raw_lower)
        if mapped is not None:
            return mapped

        # Fallback: infer from topic
        topic_map = {
            "raw-logs": 1,          # syslog default
            "security-events": 2,   # windows_event default
            "process-events": 1,    # syslog default
            "network-events": 9,    # netflow default
        }
        return topic_map.get(topic, 1)

    @staticmethod
    def _safe_float(val, default: float = 0.0) -> float:
        """Safely convert to float."""
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _port_to_service(port: int) -> str:
        """Map port number to a service name for connection tracking."""
        port_map = {
            20: "ftp_data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3",
            111: "sunrpc", 123: "ntp", 139: "netbios", 143: "imap",
            161: "snmp", 389: "ldap", 443: "https", 445: "smb",
            514: "syslog", 993: "imaps", 995: "pop3s", 1433: "mssql",
            1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
            5900: "vnc", 6379: "redis", 8080: "http_alt", 8443: "https_alt",
            9092: "kafka", 9200: "elasticsearch", 27017: "mongodb",
        }
        return port_map.get(port, f"port_{port}")

    def get_stats(self) -> Dict:
        """Return extractor statistics."""
        return {
            "drain3": self._drain3.get_stats(),
            "connection_tracker": self._conn_tracker.get_stats(),
            "feature_count": len(FEATURE_NAMES),
            "ioc_lookup_enabled": self._ioc_lookup is not None,
        }

    # ── Compiled regexes for network field extraction from text ──────────
    # Patterns match formats emitted by the Vector CCS pipeline for
    # security events with embedded network information.
    _RE_IP_PORT_ARROW = re.compile(
        r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*(?:→|->)\s*(\d+\.\d+\.\d+\.\d+):(\d+)"
    )
    _RE_SRC_IP   = re.compile(r"\bsrc=(\d+\.\d+\.\d+\.\d+)")
    _RE_DST_IP   = re.compile(r"\bdst=(\d+\.\d+\.\d+\.\d+)")
    _RE_DST_PORT = re.compile(r"\bdst=\d+\.\d+\.\d+\.\d+:(\d+)")
    _RE_PROTO    = re.compile(r"\bproto=(\w+)", re.IGNORECASE)
    _RE_BYTES_SENT = re.compile(r"\b(?:bytes_sent|src_bytes)=(\d+)")
    _RE_BYTES_RECV = re.compile(r"\b(?:bytes_recv|dst_bytes)=(\d+)")
    _RE_SRC_PORT   = re.compile(r"\bsrc=\d+\.\d+\.\d+\.\d+:(\d+)")

    @classmethod
    def _parse_network_from_text(cls, text: str) -> Dict[str, Any]:
        """Extract network fields from description/message_body text.

        Returns dict that may contain: src_ip, dst_ip, dst_port, src_port,
        protocol, bytes_sent, bytes_received.  Missing fields are omitted.
        """
        result: Dict[str, Any] = {}
        if not text:
            return result

        # Try "IP:PORT → IP:PORT" pattern first (firewall format)
        m = cls._RE_IP_PORT_ARROW.search(text)
        if m:
            result["src_ip"] = m.group(1)
            result["src_port"] = int(m.group(2))
            result["dst_ip"] = m.group(3)
            result["dst_port"] = int(m.group(4))
        else:
            # Try "src=IP dst=IP:PORT" pattern (IDS format)
            ms = cls._RE_SRC_IP.search(text)
            if ms:
                result["src_ip"] = ms.group(1)
            md = cls._RE_DST_IP.search(text)
            if md:
                result["dst_ip"] = md.group(1)
            mp = cls._RE_DST_PORT.search(text)
            if mp:
                result["dst_port"] = int(mp.group(1))
            msp = cls._RE_SRC_PORT.search(text)
            if msp:
                result["src_port"] = int(msp.group(1))

        # Protocol
        mp = cls._RE_PROTO.search(text)
        if mp:
            result["protocol"] = mp.group(1).lower()

        # Bytes
        mb_s = cls._RE_BYTES_SENT.search(text)
        if mb_s:
            result["bytes_sent"] = int(mb_s.group(1))
        mb_r = cls._RE_BYTES_RECV.search(text)
        if mb_r:
            result["bytes_received"] = int(mb_r.group(1))

        return result
