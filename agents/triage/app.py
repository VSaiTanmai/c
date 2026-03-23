"""
CLIF Triage Agent v7 — Main Service
========================================
High-throughput Kafka consumer that batches events, extracts 32 features
in parallel, runs the 2-model ONNX ensemble, fuses scores with kill-chain
and cross-host context, and publishes routing decisions.

Architecture:
    Kafka (4 topics) → Batch Collector (2000 events)
      → Feature Extraction (ThreadPoolExecutor, 4 workers)
      → Model Inference (batched ONNX: LGBM + AE)
      → Score Fusion (vectorized numpy + kill-chain + cross-host)
      → Kafka Producer (triage-scores, anomaly-alerts, hunter-tasks)
      → Async SHAP (background thread, escalated only)

v7 changes:
  - 32-feature vector (Universal 12 + Network 8 + Text 6 + Behavioral 6)
  - 2-model ensemble (LightGBM 0.85 + Autoencoder 0.15)
  - Parallel feature extraction (4 threads)
  - Async SHAP (background thread)
  - Kill-chain state machine per host
  - Cross-host correlation for campaign detection
  - EWMA entity rate tracking
  - Batch size 2000 (up from 500)
  - Removed: ARF, EIF, replay buffer, warm restart

Event linkage:
    Deterministic UUID-v5 from topic:partition:offset ensures
    triage_scores.event_id == raw_logs.event_id for joins.

Startup sequence:
    1. Wait for Kafka to become healthy
    2. Load 2 ONNX models + scaler + calibration
    3. Run self-test: synthetic event through full pipeline
    4. Accept real traffic

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import numpy as np
import orjson
from confluent_kafka import Consumer, KafkaError, KafkaException, Producer
from flask import Flask, jsonify

import config
from drain3_miner import Drain3Miner
from ewma_tracker import CrossHostCorrelator, EWMATracker
from feature_extractor import (
    FeatureExtractor,
    FEATURE_NAMES,
    NUM_FEATURES,
    ShardedConnectionTracker,
    SourceNoveltyTracker,
    classify_action,
)
from kill_chain import KillChainTracker
from model_ensemble import ModelEnsemble
from score_fusion import ScoreFusion
from shap_explainer import AsyncSHAPWorker

# ── Deterministic event_id ──────────────────────────────────────────────────

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
                "Kafka healthy (attempt %d): %d topics — %s",
                attempt, len(topic_names), topic_names[:10],
            )
            missing = [t for t in config.INPUT_TOPICS if t not in topic_names]
            if missing:
                logger.warning("Input topics not yet created: %s", missing)
            return True
        except Exception as e:
            if attempt < max_retries:
                logger.warning(
                    "Kafka not ready (%d/%d): %s — retrying in %.1fs",
                    attempt, max_retries, e, delay,
                )
                time.sleep(delay)
                delay = min(delay * 1.5, 30.0)
            else:
                raise RuntimeError(
                    f"Kafka brokers unreachable after {max_retries} attempts: "
                    f"{config.KAFKA_BROKERS}"
                )
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
        "fetch.max.bytes": 52428800,
        "max.partition.fetch.bytes": 10485760,
    }
    consumer = Consumer(conf)
    consumer.subscribe(config.INPUT_TOPICS)
    logger.info(
        "Kafka consumer: group=%s, topics=%s",
        config.CONSUMER_GROUP_ID, config.INPUT_TOPICS,
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
        "queue.buffering.max.kbytes": 131072,
    }
    return Producer(conf)


_delivery_errors = 0


def _delivery_callback(err, msg):
    global _delivery_errors
    if err:
        _delivery_errors += 1
        if _delivery_errors <= 10 or _delivery_errors % 100 == 0:
            logger.error("Delivery failed for %s: %s", msg.topic(), err)


# ── Triage Processor ───────────────────────────────────────────────────────

class TriageProcessor:
    """
    Core processing engine. Holds all stateful components and processes
    batches through the full pipeline.

    Pipeline per batch:
      1. Parallel feature extraction (4 threads)
      2. Batched ONNX inference (LGBM + AE)
      3. Kill-chain state update
      4. Score fusion with adjustments
      5. Async SHAP for escalated events
    """

    def __init__(self):
        # ── Shared stateful components ─────────────────────────────────
        self._drain3 = Drain3Miner()
        self._ewma = EWMATracker(
            half_lives=[
                config.EWMA_HALF_LIFE_FAST,
                config.EWMA_HALF_LIFE_MEDIUM,
                config.EWMA_HALF_LIFE_SLOW,
            ],
            max_entities=config.EWMA_MAX_ENTITIES,
        )
        self._kill_chain = KillChainTracker(
            decay_sec=config.KILL_CHAIN_DECAY_SEC,
            score_gate=config.KILL_CHAIN_SCORE_GATE,
        )
        self._cross_host = CrossHostCorrelator(
            window_sec=config.CROSS_HOST_WINDOW_SEC,
        )
        self._conn_tracker = ShardedConnectionTracker(
            num_shards=config.CONN_TRACKER_SHARDS,
            time_window_sec=config.CONN_TIME_WINDOW_SEC,
            host_window_size=config.CONN_HOST_WINDOW_SIZE,
        )
        self._novelty = SourceNoveltyTracker()

        # ── Feature extractor ──────────────────────────────────────────
        self._extractor = FeatureExtractor(
            drain3_miner=self._drain3,
            ewma_tracker=self._ewma,
            conn_tracker=self._conn_tracker,
            novelty_tracker=self._novelty,
            ioc_lookup_fn=None,  # IOC loaded separately if available
        )

        # ── Model ensemble ─────────────────────────────────────────────
        self._ensemble = ModelEnsemble()
        self._ensemble.load()

        # ── Score fusion ───────────────────────────────────────────────
        self._fusion = ScoreFusion()

        # ── Thread pool for parallel feature extraction ────────────────
        self._executor = ThreadPoolExecutor(
            max_workers=config.INFERENCE_WORKERS,
            thread_name_prefix="feat-worker",
        )

        # ── Async SHAP ─────────────────────────────────────────────────
        self._shap_worker: Optional[AsyncSHAPWorker] = None
        self._shap_results: Dict[str, tuple] = {}  # event_id → (json, summary)
        self._shap_lock = threading.Lock()

        if config.SHAP_ENABLED:
            self._shap_worker = AsyncSHAPWorker(
                lgbm_model=self._ensemble._lgbm,
                result_callback=self._shap_callback,
                max_queue_size=config.SHAP_QUEUE_SIZE,
            )
            self._shap_worker.start()

        # ── Self-test ──────────────────────────────────────────────────
        self._selftest_passed = True
        if config.SELFTEST_ENABLED:
            self._run_selftest()

        # ── Stats ──────────────────────────────────────────────────────
        self._events_processed = 0
        self._batches_processed = 0
        self._errors = 0
        self._last_batch_time_ms = 0.0
        self._avg_batch_time_ms = 0.0

    def _shap_callback(self, event_id: str, shap_json: str, shap_summary: str):
        """Async SHAP results callback — stores for later retrieval."""
        with self._shap_lock:
            self._shap_results[event_id] = (shap_json, shap_summary)
            # Trim old results
            if len(self._shap_results) > config.SHAP_QUEUE_SIZE * 2:
                keys = list(self._shap_results.keys())
                for k in keys[:len(keys) // 2]:
                    self._shap_results.pop(k, None)

    def _run_selftest(self) -> None:
        """Push synthetic events through the full pipeline."""
        logger.info("=" * 50)
        logger.info("Running startup self-test...")
        logger.info("=" * 50)

        synthetic_event = {
            "timestamp": "2024-01-15T10:30:00Z",
            "hostname": "selftest-host",
            "ip_address": "192.168.1.100",
            "user": "selftest-user",
            "severity": "medium",
            "original_log_level": 2,
            "source_type": "syslog",
            "message_body": "Failed password for root from 10.0.0.1 port 22 ssh2",
        }

        try:
            feat = self._extractor.extract(synthetic_event, "raw-logs")
            X = self._extractor.batch_to_numpy([feat])
            scores = self._ensemble.predict_batch(X)

            logger.info(
                "Self-test: lgbm=%.4f, ae=%.4f, combined=%.4f",
                float(scores["lgbm_scores"][0]),
                float(scores["ae_scores"][0]),
                float(scores["combined"][0]),
            )

            results = self._fusion.fuse_batch([feat], scores)
            r = results[0]
            logger.info(
                "Self-test: fusion OK — score=%.4f, label=%s",
                r["final_score"], r["label"],
            )

            logger.info("=" * 50)
            logger.info("Self-test PASSED")
            logger.info("=" * 50)

        except Exception as e:
            logger.error("Self-test FAILED: %s", e, exc_info=True)
            self._selftest_passed = False

    def process_batch(
        self, events: List[Dict[str, Any]], topics: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Process a batch through the full pipeline.

        1. Parallel feature extraction (4 workers)
        2. Batched model inference
        3. Kill-chain update + score fusion
        4. Async SHAP for escalated events

        Returns list of result dicts ready for Kafka produce.
        """
        if not events:
            return []

        batch_start = time.monotonic()
        n = len(events)

        # ── Step 1: Parallel feature extraction ────────────────────────
        features_list = [None] * n
        chunk_size = max(1, n // config.INFERENCE_WORKERS)
        futures = {}

        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            chunk_events = events[start:end]
            chunk_topics = topics[start:end]
            future = self._executor.submit(
                self._extract_chunk, chunk_events, chunk_topics, start
            )
            futures[future] = (start, end)

        valid_mask = [False] * n
        for future in as_completed(futures):
            start_idx, _ = futures[future]
            try:
                chunk_results = future.result()
                for offset, feat in chunk_results:
                    features_list[offset] = feat
                    valid_mask[offset] = True
            except Exception as e:
                self._errors += 1
                logger.error("Feature extraction chunk failed: %s", e)

        # Filter valid
        valid_features = [f for f, ok in zip(features_list, valid_mask) if ok and f]
        valid_events = [e for e, ok in zip(events, valid_mask) if ok]
        valid_topics = [t for t, ok in zip(topics, valid_mask) if ok]

        if not valid_features:
            return []

        # ── Step 2: Batched model inference ────────────────────────────
        X = self._extractor.batch_to_numpy(valid_features)
        source_types = [f.get("_source_type", "unknown") for f in valid_features]

        try:
            model_scores = self._ensemble.predict_batch(X, source_types)
        except Exception as e:
            logger.error("Batch inference failed: %s", e)
            self._errors += len(valid_features)
            return []

        # ── Step 3: Kill-chain update ──────────────────────────────────
        combined = model_scores["combined"]

        for i, feat in enumerate(valid_features):
            score = float(combined[i])
            hostname = feat.get("_hostname", "unknown")
            action_type = int(feat.get("action_type", 0))

            # Update kill-chain (only advances if score > gate)
            ts = float(feat.get("_epoch", time.time()))
            kc_stage, kc_velocity = self._kill_chain.update(
                hostname, action_type, score, ts
            )
            valid_features[i]["kill_chain_stage"] = float(kc_stage)
            valid_features[i]["kill_chain_velocity"] = kc_velocity

            # Update cross-host correlation
            count = self._cross_host.record(ts, hostname, score)
            valid_features[i]["cross_host_correlation"] = float(count)

        # ── Step 4: Score fusion with adjustments ──────────────────────
        results = self._fusion.fuse_batch(valid_features, model_scores)

        # ── Step 5: Enrich results with event metadata ─────────────────
        for i, result in enumerate(results):
            event = valid_events[i]
            result["event_id"] = event.get("event_id", "")
            result["timestamp"] = event.get("timestamp", "")
            result["model_version"] = self._ensemble.manifest.get("version", "v7")

            # Async SHAP for escalated events
            if (
                result["label"] == "escalate"
                and self._shap_worker is not None
            ):
                x_single = X[i:i+1].copy()
                self._shap_worker.enqueue(result["event_id"], x_single)

        # ── Stats ──────────────────────────────────────────────────────
        elapsed_ms = (time.monotonic() - batch_start) * 1000
        self._events_processed += len(results)
        self._batches_processed += 1
        self._last_batch_time_ms = elapsed_ms
        if self._avg_batch_time_ms == 0:
            self._avg_batch_time_ms = elapsed_ms
        else:
            self._avg_batch_time_ms = (
                0.9 * self._avg_batch_time_ms + 0.1 * elapsed_ms
            )

        if self._batches_processed % 50 == 0:
            eps = self._events_processed / max(
                time.monotonic() - batch_start, 0.001
            )
            logger.info(
                "Batch %d: %d events in %.1f ms (avg %.1f ms/batch, "
                "%.1f ms/event, ~%.0f EPS total)",
                self._batches_processed,
                len(results),
                elapsed_ms,
                self._avg_batch_time_ms,
                elapsed_ms / max(len(results), 1),
                self._events_processed / max(
                    (time.monotonic() - batch_start) * self._batches_processed, 1
                ),
            )

        return results

    def _extract_chunk(
        self,
        events: List[Dict[str, Any]],
        topics: List[str],
        start_idx: int,
    ) -> List[tuple]:
        """Extract features for a chunk of events. Returns (global_idx, features)."""
        results = []
        for i, (event, topic) in enumerate(zip(events, topics)):
            try:
                feat = self._extractor.extract(event, topic)
                results.append((start_idx + i, feat))
            except Exception as e:
                logger.warning(
                    "Feature extraction failed for event %d: %s",
                    start_idx + i, e,
                )
        return results

    def shutdown(self):
        """Graceful shutdown."""
        if self._shap_worker:
            self._shap_worker.stop()
        self._executor.shutdown(wait=False)
        self._drain3.shutdown()
        logger.info(
            "Processor shutdown: %d events, %d batches, %d errors",
            self._events_processed, self._batches_processed, self._errors,
        )

    def get_stats(self) -> Dict[str, Any]:
        stats = {
            "events_processed": self._events_processed,
            "batches_processed": self._batches_processed,
            "errors": self._errors,
            "last_batch_time_ms": round(self._last_batch_time_ms, 2),
            "avg_batch_time_ms": round(self._avg_batch_time_ms, 2),
            "selftest_passed": self._selftest_passed,
            "drain3": self._drain3.get_stats(),
            "extractor": self._extractor.get_stats(),
            "ensemble": self._ensemble.get_stats(),
            "fusion": self._fusion.get_stats(),
            "ewma": self._ewma.get_stats(),
            "kill_chain": self._kill_chain.get_stats(),
            "cross_host": self._cross_host.get_stats(),
        }
        if self._shap_worker:
            stats["shap"] = self._shap_worker.get_stats()
        return stats


# ── Main Agent ──────────────────────────────────────────────────────────────

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
        self._processor = TriageProcessor()
        self._consumer = create_consumer()
        self._producer = create_producer()
        self._running = True

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
        Time-and-size bounded batch collection.
        """
        batch_events: List[Dict[str, Any]] = []
        batch_topics: List[str] = []
        batch_timeout_sec = config.BATCH_TIMEOUT_MS / 1000.0
        batch_deadline = time.monotonic() + batch_timeout_sec

        try:
            while self._running:
                msg = self._consumer.poll(timeout=0.1)

                if msg is None:
                    if batch_events and time.monotonic() >= batch_deadline:
                        self._flush_batch(batch_events, batch_topics)
                        batch_events = []
                        batch_topics = []
                        batch_deadline = time.monotonic() + batch_timeout_sec
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    logger.error("Kafka error: %s", msg.error())
                    continue

                try:
                    event = orjson.loads(msg.value())
                except Exception as e:
                    logger.warning("Failed to parse message: %s", e)
                    continue

                event["event_id"] = deterministic_event_id(
                    msg.topic(), msg.partition(), msg.offset(),
                )

                batch_events.append(event)
                batch_topics.append(msg.topic())

                if len(batch_events) >= config.BATCH_SIZE:
                    self._flush_batch(batch_events, batch_topics)
                    batch_events = []
                    batch_topics = []
                    batch_deadline = time.monotonic() + batch_timeout_sec

                elif time.monotonic() >= batch_deadline and batch_events:
                    self._flush_batch(batch_events, batch_topics)
                    batch_events = []
                    batch_topics = []
                    batch_deadline = time.monotonic() + batch_timeout_sec

        except KafkaException as e:
            logger.error("Fatal Kafka error: %s", e)
        finally:
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
            payload = orjson.dumps(result)

            # Always publish to triage-scores
            self._producer.produce(
                topic=config.TOPIC_TRIAGE_SCORES,
                value=payload,
                callback=_delivery_callback,
            )

            # Escalated events also → anomaly-alerts + hunter-tasks
            if result.get("label") == "escalate":
                self._producer.produce(
                    topic=config.TOPIC_ANOMALY_ALERTS,
                    value=payload,
                    callback=_delivery_callback,
                )

                # Enrich hunter-task with kill-chain context
                hunter_payload = self._build_hunter_task(result)
                self._producer.produce(
                    topic=config.TOPIC_HUNTER_TASKS,
                    value=orjson.dumps(hunter_payload),
                    callback=_delivery_callback,
                )

        self._producer.poll(0)
        if len(results) > 100:
            self._producer.flush(timeout=5)

    def _build_hunter_task(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Build hunter-tasks payload with kill-chain context and v7 features."""
        hostname = result.get("hostname", "")
        kc_state = self._processor._kill_chain.get_host_state(hostname)

        task = {
            "event_id": result.get("event_id", ""),
            "alert_id": result.get("event_id", ""),
            "trigger_score": result.get("final_score", 0.0),
            "lgbm_score": result.get("lgbm_score", 0.0),
            "ae_score": result.get("ae_score", 0.0),
            "hostname": hostname,
            "user": result.get("user", ""),
            "source_type": result.get("source_type", ""),
            "timestamp": result.get("timestamp", ""),
            "action_type": result.get("action_type_name", ""),
            "adjustments": result.get("adjustments", ""),
            "model_version": result.get("model_version", "v7"),
            # v7: entity EWMA rates for Hunter feature vector
            "entity_event_rate": result.get("entity_event_rate", 0.0),
            "entity_error_rate": result.get("entity_error_rate", 0.0),
        }

        if kc_state:
            task["kill_chain_stage"] = kc_state["stage"]
            task["kill_chain_velocity"] = kc_state["velocity"]
            task["kill_chain_history"] = kc_state.get("stage_events", [])

        return task

    def _shutdown(self):
        """Graceful shutdown."""
        logger.info("Shutting down triage agent...")

        if self._processor:
            self._processor.shutdown()
        if self._producer:
            self._producer.flush(timeout=10)
        if self._consumer:
            self._consumer.close()

        logger.info("Triage agent shutdown complete")


# ── Flask health endpoint ──────────────────────────────────────────────────

flask_app = Flask("clif-triage-agent")
_processor_ref: Optional[TriageProcessor] = None


@flask_app.route("/health")
def health():
    stats = {}
    if _processor_ref:
        try:
            stats = _processor_ref.get_stats()
        except Exception:
            pass
    return jsonify({
        "status": "healthy",
        "service": "clif-triage-agent-v7",
        "events_processed": stats.get("events_processed", 0),
        "batches_processed": stats.get("batches_processed", 0),
        "avg_batch_time_ms": stats.get("avg_batch_time_ms", 0),
    }), 200


@flask_app.route("/stats")
def stats():
    if _processor_ref:
        return jsonify(_processor_ref.get_stats()), 200
    return jsonify({"error": "Processor not initialized"}), 503


@flask_app.route("/ready")
def ready():
    if _processor_ref and _processor_ref._ensemble.is_ready:
        return jsonify({"ready": True}), 200
    return jsonify({"ready": False}), 503


# ── Entrypoint ──────────────────────────────────────────────────────────────

def main():
    global _processor_ref

    logger.info("CLIF Triage Agent v7.0.0")
    logger.info(
        "Config: batch=%d, workers=%d, port=%d",
        config.BATCH_SIZE, config.INFERENCE_WORKERS, config.HEALTH_PORT,
    )
    logger.info(
        "Weights: lgbm=%.2f, ae=%.2f",
        config.LGBM_WEIGHT, config.AUTOENCODER_WEIGHT,
    )
    logger.info(
        "Thresholds: suspicious=%.2f, anomalous=%.2f",
        config.DEFAULT_SUSPICIOUS_THRESHOLD,
        config.DEFAULT_ANOMALOUS_THRESHOLD,
    )

    # Health server
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
    logger.info("Health endpoint on port %d", config.HEALTH_PORT)

    # Kafka health gate
    check_kafka_health()

    # Initialize and start
    agent = TriageAgent()
    agent._processor = TriageProcessor()
    _processor_ref = agent._processor

    agent._consumer = create_consumer()
    agent._producer = create_producer()
    agent._running = True

    signal.signal(signal.SIGTERM, agent._handle_signal)
    signal.signal(signal.SIGINT, agent._handle_signal)

    logger.info("=" * 60)
    logger.info("CLIF Triage Agent v7 ready — entering consumer loop")
    logger.info("=" * 60)
    agent._consumer_loop()


if __name__ == "__main__":
    main()
