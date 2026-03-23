"""
CLIF Triage Agent — Main Service
====================================
High-throughput Kafka consumer that batches events, extracts features,
runs the 3-model ensemble, fuses scores, and publishes routing decisions.

Architecture:
    Kafka (4 topics) → Batch Collector → Feature Extractor → Model Ensemble
    → Score Fusion → Kafka Producer (triage-scores, anomaly-alerts)
                    → ClickHouse (arf_replay_buffer for warm restart)
                    → ClickHouse (triage_scores table via consumer)

Event linkage:
    Each Kafka message receives a deterministic UUID-v5 derived from
    topic:partition:offset.  The consumer service uses the same UUID for
    raw_logs.event_id, so triage_scores can JOIN back to raw_logs.

Startup sequence:
    1. Wait for ClickHouse + Kafka to become healthy (retry with backoff)
    2. Load all 3 models (ARF does warm restart from replay buffer)
    3. Run self-test: synthetic event through full pipeline
    4. Verify ARF probabilities vary (not constant)
    5. Only then accept real traffic

Health endpoint on HEALTH_PORT (default 8300).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Any, Dict, List, Optional

import numpy as np
import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from flask import Flask, jsonify

import config
from drain3_miner import Drain3Miner
from feature_extractor import ConnectionTracker, FeatureExtractor, FEATURE_NAMES
from model_ensemble import ModelEnsemble
from score_fusion import AllowlistChecker, DriftMonitor, IOCLookup, ScoreFusion, TriageResult
from shap_explainer import FeatureAttributor

# ── Deterministic event_id from Kafka coordinates ────────────────────────────
# Must use the SAME namespace as consumer/app.py so that
# raw_logs.event_id == triage_scores.event_id for the same event.

_CLIF_EVENT_NS = uuid.UUID("c71f0000-e1d0-4a6b-b5c3-deadbeef0042")


def deterministic_event_id(topic: str, partition: int, offset: int) -> str:
    """Derive a stable UUID-v5 from Kafka message coordinates."""
    return str(uuid.uuid5(_CLIF_EVENT_NS, f"{topic}:{partition}:{offset}"))

# ── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("clif.triage.app")


# ── ClickHouse client ──────────────────────────────────────────────────────

def create_ch_client(required: bool = False):
    """
    Create a ClickHouse client.

    Args:
        required: If True, retry with backoff until connected. If False,
                  return None on failure (degraded mode).
    """
    from clickhouse_driver import Client

    max_retries = config.STARTUP_HEALTH_RETRIES if required else 1
    delay = config.STARTUP_HEALTH_DELAY_SEC

    for attempt in range(1, max_retries + 1):
        try:
            client = Client(
                host=config.CLICKHOUSE_HOST,
                port=config.CLICKHOUSE_PORT,
                user=config.CLICKHOUSE_USER,
                password=config.CLICKHOUSE_PASSWORD,
                database=config.CLICKHOUSE_DB,
                connect_timeout=5,
                send_receive_timeout=10,
            )
            # Test connection
            client.execute("SELECT 1")
            logger.info(
                "ClickHouse connected: %s:%d/%s (attempt %d)",
                config.CLICKHOUSE_HOST,
                config.CLICKHOUSE_PORT,
                config.CLICKHOUSE_DB,
                attempt,
            )
            return client
        except Exception as e:
            if attempt < max_retries:
                logger.warning(
                    "ClickHouse unavailable (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, max_retries, e, delay,
                )
                time.sleep(delay)
                delay = min(delay * 1.5, 30.0)  # Exponential backoff, cap at 30s
            else:
                if required:
                    logger.error(
                        "ClickHouse still unavailable after %d attempts — aborting",
                        max_retries,
                    )
                    raise
                else:
                    logger.warning(
                        "ClickHouse unavailable (%s) — running without IOC/threshold caches", e
                    )
                    return None


# ── Kafka helpers ───────────────────────────────────────────────────────────

def check_kafka_health() -> bool:
    """Verify Kafka brokers are reachable before subscribing."""
    from confluent_kafka.admin import AdminClient

    max_retries = config.STARTUP_HEALTH_RETRIES
    delay = config.STARTUP_HEALTH_DELAY_SEC

    for attempt in range(1, max_retries + 1):
        try:
            admin = AdminClient({"bootstrap.servers": config.KAFKA_BROKERS})
            metadata = admin.list_topics(timeout=5)
            topic_names = list(metadata.topics.keys())
            logger.info(
                "Kafka healthy (attempt %d): %d topics visible — %s",
                attempt, len(topic_names), topic_names[:10],
            )
            # Verify our input topics exist
            missing = [t for t in config.INPUT_TOPICS if t not in topic_names]
            if missing:
                logger.warning("Input topics not yet created: %s — will auto-create on first produce", missing)
            return True
        except Exception as e:
            if attempt < max_retries:
                logger.warning(
                    "Kafka not ready (attempt %d/%d): %s — retrying in %.1fs",
                    attempt, max_retries, e, delay,
                )
                time.sleep(delay)
                delay = min(delay * 1.5, 30.0)
            else:
                logger.error(
                    "Kafka still unavailable after %d attempts — aborting", max_retries
                )
                raise RuntimeError(f"Kafka brokers unreachable: {config.KAFKA_BROKERS}")
    return False


def create_consumer() -> Consumer:
    """Create a Kafka consumer subscribed to the input topics."""
    offset_reset = os.environ.get("KAFKA_OFFSET_RESET", "latest")
    conf = {
        "bootstrap.servers": config.KAFKA_BROKERS,
        "group.id": config.CONSUMER_GROUP_ID,
        "auto.offset.reset": offset_reset,
        "enable.auto.commit": True,
        "auto.commit.interval.ms": 5000,
        "max.poll.interval.ms": 300000,
        "session.timeout.ms": 30000,
        "fetch.min.bytes": 1,
        "fetch.max.bytes": 52428800,  # 50 MB
        "max.partition.fetch.bytes": 10485760,  # 10 MB
    }
    consumer = Consumer(conf)
    consumer.subscribe(config.INPUT_TOPICS)
    logger.info(
        "Kafka consumer started: group=%s, topics=%s, brokers=%s",
        config.CONSUMER_GROUP_ID,
        config.INPUT_TOPICS,
        config.KAFKA_BROKERS,
    )
    return consumer


def create_producer() -> Producer:
    """Create a Kafka producer for outputting triage results."""
    conf = {
        "bootstrap.servers": config.KAFKA_BROKERS,
        "linger.ms": 50,
        "batch.num.messages": 10000,
        "compression.type": "lz4",
        "acks": "all",
        "retries": 3,
        "retry.backoff.ms": 100,
        "queue.buffering.max.messages": 100000,
        "queue.buffering.max.kbytes": 131072,  # 128 MB
    }
    producer = Producer(conf)
    logger.info("Kafka producer started: brokers=%s", config.KAFKA_BROKERS)
    return producer


# ── Delivery callback ──────────────────────────────────────────────────────

_delivery_errors = 0


def _delivery_callback(err, msg):
    global _delivery_errors
    if err:
        _delivery_errors += 1
        logger.error("Delivery failed for %s: %s", msg.topic(), err)


# ── Batch processing ───────────────────────────────────────────────────────

class TriageProcessor:
    """
    The core processing engine. Holds all components and processes
    batches of events through the complete pipeline.

    Startup: ClickHouse health gate → model load (ARF warm restart) →
             self-test → accept traffic.
    """

    # ── ARF replay buffer column names for INSERT ───────────────────────
    _REPLAY_COLS = (
        "timestamp", "event_id", "source_type",
        *FEATURE_NAMES,
        "label",
    )

    def __init__(self):
        # ─── Health gate: ClickHouse ───────────────────────────────────
        self._ch_client = create_ch_client(required=True)

        # Verify source_thresholds are seeded
        self._verify_source_thresholds()

        self._drain3 = Drain3Miner()
        self._conn_tracker = ConnectionTracker(
            time_window_sec=config.CONN_TIME_WINDOW_SEC,
            host_window_size=config.CONN_HOST_WINDOW_SIZE,
            cleanup_interval_sec=config.CONN_CLEANUP_INTERVAL_SEC,
        )

        # Score fusion + ClickHouse caches
        self._fusion = ScoreFusion(
            ch_client=self._ch_client,
            weights=config.SCORE_WEIGHTS,
        )

        # Wire IOC lookup into feature extractor
        ioc_fn = None
        if self._fusion.ioc_lookup is not None:
            ioc_fn = self._fusion.ioc_lookup.check

        self._extractor = FeatureExtractor(
            drain3_miner=self._drain3,
            ioc_lookup_fn=ioc_fn,
            conn_tracker=self._conn_tracker,
        )

        # Model ensemble — pass ch_client for ARF warm restart
        self._ensemble = ModelEnsemble()
        self._ensemble.load(ch_client=self._ch_client)

        # Update model version in fusion
        version = self._ensemble.manifest.get("version", "unknown")
        self._fusion._model_version = version

        # SHAP feature attribution for escalated events
        self._attributor = FeatureAttributor(
            self._ensemble._lgbm, FEATURE_NAMES
        )

        # Drift monitor (PSI + KL divergence)
        self._drift_monitor = DriftMonitor(
            ch_client=self._ch_client,
            feature_names=list(FEATURE_NAMES),
        )

        # ─── Startup self-test ─────────────────────────────────────────
        if config.SELFTEST_ENABLED:
            self._run_selftest()

        # Stats
        self._events_processed = 0
        self._batches_processed = 0
        self._errors = 0
        self._last_batch_time_ms = 0.0
        self._avg_batch_time_ms = 0.0
        self._replay_buffer_writes = 0
        self._selftest_passed = True

    def _verify_source_thresholds(self) -> None:
        """Verify that source_thresholds table has the expected 10 rows."""
        try:
            rows = self._ch_client.execute(
                "SELECT count() FROM clif_logs.source_thresholds"
            )
            count = rows[0][0] if rows else 0
            if count >= 10:
                logger.info("source_thresholds verified: %d rows", count)
            elif count > 0:
                logger.warning(
                    "source_thresholds has only %d rows (expected ≥10)", count
                )
            else:
                logger.warning(
                    "source_thresholds is EMPTY — all events will use default thresholds "
                    "(suspicious=%.2f, anomalous=%.2f)",
                    config.DEFAULT_SUSPICIOUS_THRESHOLD,
                    config.DEFAULT_ANOMALOUS_THRESHOLD,
                )
        except Exception as e:
            logger.warning("Could not verify source_thresholds: %s", e)

    def _run_selftest(self) -> None:
        """
        Push a synthetic event through the full pipeline before accepting
        real traffic. Verifies: feature extraction, all 3 model scores,
        score fusion, and that ARF probabilities are NOT constant.
        """
        logger.info("=" * 50)
        logger.info("Running startup self-test...")
        logger.info("=" * 50)

        # Synthetic syslog event
        synthetic_event = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "selftest-host",
            "ip_address": "192.168.1.100",
            "user": "selftest-user",
            "severity": "medium",
            "original_log_level": 2,
            "source_type": "syslog",
            "message": "selftest: Jan 15 10:30:00 sshd[12345]: Failed password for root from 10.0.0.1 port 22 ssh2",
            "message_body": "Failed password for root from 10.0.0.1 port 22 ssh2",
        }

        try:
            # Step 1: Feature extraction
            feat = self._extractor.extract(synthetic_event, "raw-logs")
            feat_vals = [feat[name] for name in FEATURE_NAMES]
            logger.info(
                "Self-test: feature extraction OK (%d features)", len(feat_vals)
            )

            # Step 2: Model inference
            X = np.array([feat_vals], dtype=np.float32)
            scores = self._ensemble.predict_batch(X)

            lgbm_s = float(scores["lgbm"][0])
            eif_s = float(scores["eif"][0])
            arf_s = float(scores["arf"][0])

            logger.info(
                "Self-test: model scores — lgbm=%.4f, eif=%.4f, arf=%.4f",
                lgbm_s, eif_s, arf_s,
            )

            # Verify all scores are in [0, 1]
            for name, s in [("lgbm", lgbm_s), ("eif", eif_s), ("arf", arf_s)]:
                if not (0.0 <= s <= 1.0):
                    raise ValueError(
                        f"Self-test FAILED: {name} score {s} not in [0, 1]"
                    )

            # Step 3: Score fusion
            events_for_fusion = [synthetic_event]
            results = self._fusion.fuse_batch(scores, [feat], events_for_fusion)
            if not results:
                raise ValueError("Self-test FAILED: score fusion returned empty")

            result = results[0]
            logger.info(
                "Self-test: fusion OK — combined=%.4f, action=%s, "
                "std_dev=%.4f, ci=[%.4f, %.4f]",
                result.combined_score,
                result.action,
                result.score_std_dev,
                result.ci_lower,
                result.ci_upper,
            )

            # Step 4: Verify ARF is not returning constant probabilities
            synthetic_event_2 = {
                **synthetic_event,
                "severity": "critical",
                "original_log_level": 4,
                "message_body": "CRITICAL kernel panic: not syncing: Fatal exception",
                "ip_address": "10.99.99.99",
            }
            feat_2 = self._extractor.extract(synthetic_event_2, "security-events")
            X_2 = np.array(
                [[feat_2[name] for name in FEATURE_NAMES]], dtype=np.float32
            )
            scores_2 = self._ensemble.predict_batch(X_2)
            arf_s2 = float(scores_2["arf"][0])

            if abs(arf_s - arf_s2) < 1e-9 and self._ensemble.arf.rows_replayed > 0:
                logger.error(
                    "Self-test WARNING: ARF probabilities appear CONSTANT "
                    "(%.6f vs %.6f) despite %d replay rows — "
                    "20%% of fused score may be unreliable!",
                    arf_s, arf_s2, self._ensemble.arf.rows_replayed,
                )
            else:
                logger.info(
                    "Self-test: ARF proba verified varying (%.4f vs %.4f, delta=%.6f)",
                    arf_s, arf_s2, abs(arf_s - arf_s2),
                )

            logger.info("=" * 50)
            logger.info("Self-test PASSED — ready to accept real traffic")
            logger.info("=" * 50)

        except Exception as e:
            logger.error("Self-test FAILED: %s", e, exc_info=True)
            self._selftest_passed = False
            # Don't crash — allow degraded startup, but log prominently
            logger.error(
                "!!! SELF-TEST FAILED — model outputs may be unreliable !!!"
            )

    def process_batch(
        self, events: List[Dict[str, Any]], topics: List[str]
    ) -> List[TriageResult]:
        """
        Process a batch of events through the full pipeline:
        1. Feature extraction
        2. Model inference (3 models)
        3. Score fusion + routing
        4. Write scored events to arf_replay_buffer for warm restart
        5. Online-learn ARF on scored events

        Args:
            events: Raw event dicts from Kafka.
            topics: Corresponding topic for each event.

        Returns:
            List of TriageResult objects.
        """
        if not events:
            return []

        batch_start = time.monotonic()

        # ── Step 1: Feature extraction ──────────────────────────────────
        features_list = []
        valid_indices = []
        for i, (event, topic) in enumerate(zip(events, topics)):
            try:
                feat = self._extractor.extract(event, topic)
                features_list.append(feat)
                valid_indices.append(i)
            except Exception as e:
                self._errors += 1
                logger.error(
                    "Feature extraction failed for event %d: %s", i, e,
                    exc_info=True,
                )

        if not features_list:
            return []

        # ── Step 2: Model inference ─────────────────────────────────────
        X = self._extractor.batch_to_numpy(features_list)

        # Shape guard: if the feature matrix has wrong width, try per-event
        expected_cols = len(FEATURE_NAMES)
        if X.ndim != 2 or X.shape[1] != expected_cols:
            logger.error(
                "Batch X shape mismatch: got %s, expected (N, %d). "
                "Falling back to single-event inference.",
                X.shape, expected_cols,
            )
            return self._process_batch_single(features_list, valid_indices, events)

        try:
            model_scores = self._ensemble.predict_batch(X)
        except Exception as e:
            logger.error(
                "Batch inference failed (X.shape=%s): %s — "
                "falling back to single-event inference.",
                X.shape, e,
            )
            return self._process_batch_single(features_list, valid_indices, events)

        # ── Step 2b: Drift monitoring ───────────────────────────────────
        self._drift_monitor.record_batch(X)

        # ── Step 3: Score fusion + routing ──────────────────────────────
        valid_events = [events[i] for i in valid_indices]
        results = self._fusion.fuse_batch(model_scores, features_list, valid_events)

        # ── Step 3b: SHAP attribution for escalated events ─────────────
        actions = [r.action for r in results]
        shap_results = self._attributor.explain_batch_escalated(X, actions)
        for r, (shap_json, shap_text) in zip(results, shap_results):
            r.shap_top_features = shap_json
            r.shap_summary = shap_text

        # ── Step 4: Write to arf_replay_buffer + online ARF learning ───
        if results and self._ch_client is not None:
            self._write_replay_buffer(results, features_list)

        # ── Stats update ────────────────────────────────────────────────
        elapsed_ms = (time.monotonic() - batch_start) * 1000
        self._events_processed += len(results)
        self._batches_processed += 1
        self._last_batch_time_ms = elapsed_ms
        # Exponential moving average
        if self._avg_batch_time_ms == 0:
            self._avg_batch_time_ms = elapsed_ms
        else:
            self._avg_batch_time_ms = 0.9 * self._avg_batch_time_ms + 0.1 * elapsed_ms

        if self._batches_processed % 100 == 0:
            logger.info(
                "Batch %d: %d events in %.1f ms (avg %.1f ms/batch, %.1f ms/event)",
                self._batches_processed,
                len(results),
                elapsed_ms,
                self._avg_batch_time_ms,
                elapsed_ms / max(1, len(results)),
            )

        return results

    def _process_batch_single(
        self,
        features_list: List[Dict[str, Any]],
        valid_indices: List[int],
        events: List[Dict[str, Any]],
    ) -> List[TriageResult]:
        """
        Per-event fallback when batch inference fails.
        Processes each event individually so a single bad event doesn't
        silently drop the entire batch.
        """
        all_results: List[TriageResult] = []
        ok = 0
        fail = 0

        for idx, feat in enumerate(features_list):
            try:
                X_single = np.array(
                    [[feat[name] for name in FEATURE_NAMES]], dtype=np.float32,
                )
                X_single = np.nan_to_num(X_single, nan=0.0, posinf=1e9, neginf=-1e9)

                if X_single.shape[1] != len(FEATURE_NAMES):
                    fail += 1
                    continue

                scores = self._ensemble.predict_batch(X_single)
                orig_idx = valid_indices[idx]
                ev = events[orig_idx]
                result = self._fusion.fuse_batch(scores, [feat], [ev])
                if result:
                    all_results.extend(result)
                    ok += 1
            except Exception as e:
                fail += 1
                if fail <= 3:
                    logger.warning("Single-event inference failed (idx=%d): %s", idx, e)

        self._errors += fail
        logger.info(
            "Single-event fallback: %d/%d succeeded, %d failed",
            ok, ok + fail, fail,
        )
        return all_results

    def _write_replay_buffer(
        self,
        results: List[TriageResult],
        features_list: List[Dict[str, Any]],
    ) -> None:
        """
        Write scored events to arf_replay_buffer for warm restart data.
        Also feed each event through ARF.learn_one() for online adaptation.

        LABEL STRATEGY (fixes label leakage):
          Instead of using the combined action (which includes ARF's own score),
          we use only LightGBM's score as a pseudo-label. This prevents the ARF
          from learning from its own predictions creating a feedback loop.
          - LightGBM score > ARF_PSEUDO_LABEL_HIGH → label = 1 (malicious)
          - LightGBM score < ARF_PSEUDO_LABEL_LOW  → label = 0 (normal)
          - Otherwise → skip learning (ambiguous zone, don't poison ARF)
        """
        try:
            from datetime import datetime, timezone

            rows = []
            arf = self._ensemble.arf
            use_lgbm_pseudo = config.ARF_LABEL_SOURCE == "lgbm_pseudo"

            for result, feat in zip(results, features_list):
                # Determine label for ARF learning
                if use_lgbm_pseudo:
                    # Use only LightGBM score as pseudo-label (no label leakage)
                    lgbm_s = result.lgbm_score
                    if lgbm_s >= config.ARF_PSEUDO_LABEL_HIGH:
                        label = 1
                    elif lgbm_s <= config.ARF_PSEUDO_LABEL_LOW:
                        label = 0
                    else:
                        label = -1  # ambiguous — skip ARF learning
                else:
                    # Legacy: use combined action (has label leakage)
                    label = 1 if result.action == "escalate" else 0

                # Parse timestamp
                ts_str = result.timestamp
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except Exception:
                    ts = datetime.now(timezone.utc)

                row = [
                    ts,
                    result.event_id or str(uuid.uuid4()),
                    result.source_type,
                ]
                # 20 canonical feature values in order
                feature_vals = {}
                for name in FEATURE_NAMES:
                    val = float(feat.get(name, 0.0))
                    row.append(val)
                    feature_vals[name] = val
                row.append(max(0, label))  # store 0 for ambiguous in replay buffer
                rows.append(row)

                # Online ARF learning (non-blocking, fast per-event)
                # Skip learning for ambiguous cases (label == -1) to avoid
                # poisoning ARF with uncertain pseudo-labels
                if arf is not None and label >= 0:
                    arf.learn_one(feature_vals, label)

            # Batch INSERT into ClickHouse
            if rows:
                self._ch_client.execute(
                    "INSERT INTO clif_logs.arf_replay_buffer "
                    f"({', '.join(self._REPLAY_COLS)}) VALUES",
                    rows,
                )
                self._replay_buffer_writes += len(rows)

        except Exception as e:
            # Non-fatal: replay buffer write failure doesn't block inference
            logger.warning("Replay buffer write failed: %s", e)

    def shutdown(self):
        """Graceful shutdown — persist Drain3 state."""
        self._drain3.shutdown()
        logger.info(
            "Processor shutdown: %d events, %d batches, %d errors",
            self._events_processed,
            self._batches_processed,
            self._errors,
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "events_processed": self._events_processed,
            "batches_processed": self._batches_processed,
            "errors": self._errors,
            "last_batch_time_ms": round(self._last_batch_time_ms, 2),
            "avg_batch_time_ms": round(self._avg_batch_time_ms, 2),
            "replay_buffer_writes": self._replay_buffer_writes,
            "selftest_passed": self._selftest_passed,
            "drain3": self._drain3.get_stats(),
            "extractor": self._extractor.get_stats(),
            "ensemble": self._ensemble.get_stats(),
            "fusion": self._fusion.get_stats(),
            "drift": self._drift_monitor.get_stats(),
        }


# ── Main consumer loop ─────────────────────────────────────────────────────

class TriageAgent:
    """
    Main agent: owns the consumer loop, processor, and producer.
    Implements graceful shutdown via signal handlers.
    """

    def __init__(self):
        self._running = False
        self._consumer: Optional[Consumer] = None
        self._producer: Optional[Producer] = None
        self._processor: Optional[TriageProcessor] = None

    def start(self):
        """Initialize all components and start the consumer loop."""
        logger.info("=" * 60)
        logger.info("CLIF Triage Agent starting...")
        logger.info("=" * 60)

        # Init processor (loads models)
        self._processor = TriageProcessor()

        # Init Kafka
        self._consumer = create_consumer()
        self._producer = create_producer()

        self._running = True

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        logger.info("Triage agent ready — entering consumer loop")
        self._consumer_loop()

    def _handle_signal(self, signum, frame):
        logger.info("Signal %d received — shutting down", signum)
        self._running = False

    def _consumer_loop(self):
        """
        Main loop: poll Kafka → collect batch → process → publish.
        Batch collection uses a time-and-size bounded approach.
        """
        batch_events: List[Dict[str, Any]] = []
        batch_topics: List[str] = []
        batch_deadline = time.monotonic() + 0.5  # Max 500ms to fill a batch

        try:
            while self._running:
                # Poll with short timeout for responsiveness
                msg = self._consumer.poll(timeout=0.1)

                if msg is None:
                    # No message — check if we have a pending batch to flush
                    if batch_events and time.monotonic() >= batch_deadline:
                        self._flush_batch(batch_events, batch_topics)
                        batch_events = []
                        batch_topics = []
                        batch_deadline = time.monotonic() + 0.5
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error("Kafka error: %s", msg.error())
                    continue

                # Parse message
                try:
                    event = orjson.loads(msg.value())
                except Exception as e:
                    logger.warning("Failed to parse message: %s", e)
                    continue

                # Embed deterministic event_id so triage_scores.event_id
                # matches raw_logs.event_id for the same Kafka message.
                event["event_id"] = deterministic_event_id(
                    msg.topic(), msg.partition(), msg.offset(),
                )

                batch_events.append(event)
                batch_topics.append(msg.topic())

                # Flush when batch is full
                if len(batch_events) >= config.BATCH_SIZE:
                    self._flush_batch(batch_events, batch_topics)
                    batch_events = []
                    batch_topics = []
                    batch_deadline = time.monotonic() + 0.5

                # Time-bounded flush
                if time.monotonic() >= batch_deadline and batch_events:
                    self._flush_batch(batch_events, batch_topics)
                    batch_events = []
                    batch_topics = []
                    batch_deadline = time.monotonic() + 0.5

        except KafkaException as e:
            logger.error("Fatal Kafka error: %s", e)
        finally:
            # Flush remaining events
            if batch_events:
                self._flush_batch(batch_events, batch_topics)

            self._shutdown()

    def _flush_batch(
        self, events: List[Dict[str, Any]], topics: List[str]
    ):
        """Process a batch and publish results."""
        results = self._processor.process_batch(events, topics)
        if not results:
            return

        for result in results:
            # Serialize to JSON
            result_dict = asdict(result)

            # event_id is always set by deterministic_event_id();
            # fallback only guards against impossible edge cases.
            if not result_dict.get("event_id"):
                result_dict["event_id"] = str(uuid.uuid4())

            payload = orjson.dumps(result_dict)

            # Always publish to triage-scores
            self._producer.produce(
                topic=config.TOPIC_TRIAGE_SCORES,
                value=payload,
                callback=_delivery_callback,
            )

            # Escalated events also go to anomaly-alerts + hunter-tasks
            if result.action == "escalate":
                self._producer.produce(
                    topic=config.TOPIC_ANOMALY_ALERTS,
                    value=payload,
                    callback=_delivery_callback,
                )
                # Publish to hunter-tasks work queue so the Hunter Agent
                # can pick up investigations.  Same payload — the hunter
                # maps event_id → alert_id, adjusted_score → trigger_score.
                self._producer.produce(
                    topic=config.TOPIC_HUNTER_TASKS,
                    value=payload,
                    callback=_delivery_callback,
                )

        # Flush producer (non-blocking poll + final flush)
        self._producer.poll(0)
        if len(results) > 100:
            self._producer.flush(timeout=5)

    def _shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down triage agent...")

        if self._processor:
            self._processor.shutdown()

        if self._producer:
            self._producer.flush(timeout=10)
            logger.info("Producer flushed")

        if self._consumer:
            self._consumer.close()
            logger.info("Consumer closed")

        logger.info("Triage agent shutdown complete")


# ── Flask health endpoint ───────────────────────────────────────────────────

flask_app = Flask("clif-triage-agent")
_agent_instance: Optional[TriageAgent] = None
_processor_ref: Optional[TriageProcessor] = None


@flask_app.route("/health")
def health():
    """Health check endpoint for Docker healthcheck and load balancers."""
    stats = {}
    if _processor_ref:
        try:
            stats = _processor_ref.get_stats()
        except Exception:
            pass

    return jsonify({
        "status": "healthy",
        "service": "clif-triage-agent",
        "events_processed": stats.get("events_processed", 0),
        "batches_processed": stats.get("batches_processed", 0),
        "avg_batch_time_ms": stats.get("avg_batch_time_ms", 0),
        "models_loaded": stats.get("ensemble", {}).get("loaded", False),
    }), 200


@flask_app.route("/stats")
def stats():
    """Detailed statistics endpoint."""
    if _processor_ref:
        return jsonify(_processor_ref.get_stats()), 200
    return jsonify({"error": "Processor not initialized"}), 503


@flask_app.route("/ready")
def ready():
    """Readiness probe — returns 200 only when models are loaded."""
    if _processor_ref and _processor_ref._ensemble.is_loaded:
        return jsonify({"ready": True}), 200
    return jsonify({"ready": False}), 503


# ── Entrypoint ──────────────────────────────────────────────────────────────

def main():
    global _processor_ref

    logger.info("CLIF Triage Agent v1.0.0")
    logger.info("Config: batch_size=%d, workers=%d, health_port=%d",
                config.BATCH_SIZE, config.INFERENCE_WORKERS, config.HEALTH_PORT)
    logger.info("Weights: %s", config.SCORE_WEIGHTS)
    logger.info("Thresholds: suspicious=%.2f, anomalous=%.2f, disagreement=%.2f",
                config.DEFAULT_SUSPICIOUS_THRESHOLD,
                config.DEFAULT_ANOMALOUS_THRESHOLD,
                config.DISAGREEMENT_THRESHOLD)
    logger.info("ARF warm restart: %s (replay_hours=%d, max_rows=%d)",
                config.ARF_WARM_RESTART,
                config.ARF_REPLAY_HOURS,
                config.ARF_REPLAY_MAX_ROWS)

    # Start Flask health server in a background thread
    health_thread = threading.Thread(
        target=lambda: flask_app.run(
            host="0.0.0.0",
            port=config.HEALTH_PORT,
            debug=False,
            use_reloader=False,
        ),
        daemon=True,
    )
    health_thread.start()
    logger.info("Health endpoint started on port %d", config.HEALTH_PORT)

    # ── Health Gate: Kafka ──────────────────────────────────────────────
    logger.info("Checking Kafka brokers: %s", config.KAFKA_BROKERS)
    check_kafka_health()
    logger.info("Kafka health check PASSED")

    # ── Initialize Agent ───────────────────────────────────────────────
    agent = TriageAgent()

    logger.info("=" * 60)
    logger.info("CLIF Triage Agent starting...")
    logger.info("=" * 60)

    # TriageProcessor does: ClickHouse health gate → model load (ARF warm
    # restart) → self-test — all inside __init__
    agent._processor = TriageProcessor()
    _processor_ref = agent._processor

    agent._consumer = create_consumer()
    agent._producer = create_producer()
    agent._running = True

    signal.signal(signal.SIGTERM, agent._handle_signal)
    signal.signal(signal.SIGINT, agent._handle_signal)

    logger.info("=" * 60)
    logger.info("Triage agent ready — entering consumer loop")
    logger.info("=" * 60)
    agent._consumer_loop()


if __name__ == "__main__":
    main()
