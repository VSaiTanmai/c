"""
Hunter Agent – main application entry point.

FastAPI + aiokafka async consumer.

Pipeline position:
    Triage Agent → [hunter-tasks topic] → Hunter Agent
                                               │
                                               ▼
                                    [hunter-results topic] → Consumer

Investigation flow per message:
    1. Secondary score gate (adjusted_score > HUNTER_SCORE_GATE)
    2. Parallel L1 threads: Sigma, SPC, Graph, Temporal, Similarity
    3. Parallel L2 threads: MITRE, Campaign
    4. Sigma fast-path check → if high severity hit, bypass ML
    5. Scorer (heuristic → CatBoost auto-switch)
    6. FusionEngine → finding_type + hunter_score + feature_vector
    7. NarrativeBuilder → summary + severity + recommended_action
    8. OutputWriter → publish to hunter-results + optional training write
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, Optional

import clickhouse_connect  # type: ignore
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer  # type: ignore
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from config import (
    CLICKHOUSE_DATABASE,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USER,
    CONSUMER_GROUP_ID,
    DEDUP_WINDOW_SEC,
    HUNTER_CONCURRENCY,
    HUNTER_PORT,
    HUNTER_SCORE_GATE,
    KAFKA_AUTO_OFFSET_RESET,
    KAFKA_BROKERS,
    KAFKA_MAX_POLL_RECORDS,
    LANCEDB_URL,
    LOG_LEVEL,
    TOPIC_HUNTER_RESULTS,
    TOPIC_HUNTER_TASKS,
)
from attack_graph import build_attack_graph
from fusion import FusionEngine
from models import MLResult as _MLResult
from investigation import (
    campaign_detector,
    graph_builder,
    mitre_mapper,
    similarity_searcher,
    spc_engine as spc_module,
    temporal_correlator,
)
from models import HunterVerdict
from monitoring.drift_detector import DriftDetector
from narrative_builder import (
    build_narrative,
    collect_mitre_arrays,
    determine_recommended_action,
    determine_severity,
)
from output_writer import OutputWriter
from scoring.scorer import Scorer
from sigma.engine import SigmaEngine
from training.self_supervised_trainer import SelfSupervisedTrainer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("hunter.app")

# ---------------------------------------------------------------------------
# Application state (set during lifespan)
# ---------------------------------------------------------------------------
_state: Dict[str, Any] = {}
_stats: Dict[str, Any] = {
    "messages_received": 0,
    "messages_processed": 0,
    "messages_skipped_gate": 0,
    "messages_skipped_dedup": 0,
    "fast_path_count": 0,
    "errors": 0,
    "started_at": None,
}

# Concurrency semaphore — limits parallel investigations
_sem: asyncio.Semaphore = asyncio.Semaphore(HUNTER_CONCURRENCY)

# Dedup cache: (hostname, source_type) → last_investigation_epoch
_dedup_cache: Dict[tuple, float] = {}


def _new_ch_client():
    """Create a fresh ClickHouse client (each coroutine needs its own)."""
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )


# ---------------------------------------------------------------------------
# Lifespan – startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Initialise all shared components and start background tasks."""
    log.info("Hunter Agent starting up …")
    _stats["started_at"] = datetime.now(tz=timezone.utc).isoformat()

    # ClickHouse client (synchronous, blocking calls run in executor)
    ch = clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST,
        port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER,
        password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )
    _state["ch"] = ch

    # SPC Engine (loads baselines on first refresh)
    spc = spc_module.SPCEngine(ch)
    _state["spc"] = spc
    asyncio.create_task(spc.start_background_refresh(), name="spc-refresh")

    # Sigma Engine
    sigma = SigmaEngine()
    _state["sigma"] = sigma

    # Scorer (auto-switch heuristic → CatBoost)
    scorer = Scorer(ch)
    _state["scorer"] = scorer
    asyncio.create_task(scorer.start_model_reload_loop(), name="model-reload")

    # Fusion Engine
    fusion = FusionEngine()
    _state["fusion"] = fusion

    # Self-Supervised Trainer
    trainer = SelfSupervisedTrainer(ch)
    await trainer.start()
    _state["trainer"] = trainer

    # Drift Detector
    drift_detector = DriftDetector(ch)
    _state["drift_detector"] = drift_detector

    # Kafka producer
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: v if isinstance(v, bytes) else v.encode("utf-8"),
    )
    await producer.start()
    _state["producer"] = producer

    # Output writer
    output_writer = OutputWriter(producer, ch)
    _state["output_writer"] = output_writer

    # Kafka consumer
    consumer = AIOKafkaConsumer(
        TOPIC_HUNTER_TASKS,
        bootstrap_servers=KAFKA_BROKERS,
        group_id=CONSUMER_GROUP_ID,
        auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
        max_poll_records=KAFKA_MAX_POLL_RECORDS,
        enable_auto_commit=True,
    )
    await consumer.start()
    _state["consumer"] = consumer

    # Start the main processing loop
    asyncio.create_task(_consume_loop(), name="hunter-consume")

    log.info("Hunter Agent ready – consuming from %s", TOPIC_HUNTER_TASKS)

    yield  # ← application runs here

    # --------------- Shutdown ---------------
    log.info("Hunter Agent shutting down …")
    await consumer.stop()
    await producer.stop()
    log.info("Hunter Agent stopped.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CLIF Hunter Agent",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> JSONResponse:
    """Kubernetes / docker-compose healthcheck endpoint."""
    return JSONResponse(
        {
            "status": "ok",
            "sigma_rules": _state.get("sigma", SigmaEngine.__new__(SigmaEngine)).rule_count
            if "sigma" in _state
            else 0,
            "model_used": "unknown",
        }
    )


@app.get("/stats")
async def stats() -> JSONResponse:
    """Operational metrics."""
    return JSONResponse(_stats)


# ---------------------------------------------------------------------------
# Main Kafka consume loop
# ---------------------------------------------------------------------------

def _dedup_key(payload: Dict[str, Any]) -> tuple:
    """Build dedup key from hostname + source_type."""
    return (
        str(payload.get("hostname", "")),
        str(payload.get("source_type", "")),
    )


def _is_duplicate(payload: Dict[str, Any]) -> bool:
    """Check if this (hostname, source_type) was investigated recently."""
    if DEDUP_WINDOW_SEC <= 0:
        return False
    key = _dedup_key(payload)
    now = time.monotonic()
    last = _dedup_cache.get(key)
    if last is not None and (now - last) < DEDUP_WINDOW_SEC:
        return True
    _dedup_cache[key] = now
    # Evict stale entries periodically (keep cache bounded)
    if len(_dedup_cache) > 10_000:
        cutoff = now - DEDUP_WINDOW_SEC
        stale = [k for k, v in _dedup_cache.items() if v < cutoff]
        for k in stale:
            del _dedup_cache[k]
    return False


async def _guarded_process(payload: Dict[str, Any]) -> None:
    """Run a single investigation under the concurrency semaphore."""
    async with _sem:
        try:
            await _process_message(payload)
            _stats["messages_processed"] += 1
        except Exception as exc:  # noqa: BLE001
            _stats["errors"] += 1
            log.error("Error processing message: %s", exc, exc_info=True)


async def _consume_loop() -> None:
    consumer: AIOKafkaConsumer = _state["consumer"]
    pending: list = []

    while True:
        try:
            async for msg in consumer:
                _stats["messages_received"] += 1

                # --- Deserialize value ---
                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    _stats["errors"] += 1
                    log.warning("Skipping malformed message offset=%s: %s", msg.offset, exc)
                    continue

                # --- Dedup check ---
                if _is_duplicate(payload):
                    _stats["messages_skipped_dedup"] += 1
                    continue

                # Launch bounded-concurrent investigation
                task = asyncio.create_task(_guarded_process(payload))
                pending.append(task)

                # Reap finished tasks to avoid unbounded growth
                pending = [t for t in pending if not t.done()]
        except Exception as exc:  # noqa: BLE001
            _stats["errors"] += 1
            log.error("Consume loop error (restarting in 2s): %s", exc, exc_info=True)
            await asyncio.sleep(2)


# ---------------------------------------------------------------------------
# Per-message investigation pipeline
# ---------------------------------------------------------------------------

async def _process_message(payload: Dict[str, Any]) -> None:
    """
    Full investigation pipeline for one TriageResult message.
    """
    # Triage publishes asdict(TriageResult) — the primary key is event_id.
    # We surface it as alert_id to match the consumer's hunter_investigations schema.
    alert_id = str(payload.get("event_id") or str(uuid.uuid4()))
    adjusted_score = float(payload.get("adjusted_score", 0.0))
    started_at = datetime.now(tz=timezone.utc).isoformat()

    # -----------------------------------------------------------------------
    # Secondary gate
    # -----------------------------------------------------------------------
    if adjusted_score < HUNTER_SCORE_GATE:
        _stats["messages_skipped_gate"] += 1
        log.debug("Skipped alert_id=%s score=%.3f < gate=%.3f", alert_id, adjusted_score, HUNTER_SCORE_GATE)
        return

    log.info("Investigating alert_id=%s score=%.3f", alert_id, adjusted_score)

    sigma: SigmaEngine = _state["sigma"]
    spc: spc_module.SPCEngine = _state["spc"]
    scorer: Scorer = _state["scorer"]
    fusion: FusionEngine = _state["fusion"]
    writer: OutputWriter = _state["output_writer"]

    # -----------------------------------------------------------------------
    # L1 threads – run concurrently (each gets its own CH client)
    # -----------------------------------------------------------------------
    (
        sigma_hits_raw,
        spc_result,
        graph_result,
        temporal_result,
        similarity_result,
    ) = await asyncio.gather(
        asyncio.get_event_loop().run_in_executor(
            None,
            lambda: sigma.evaluate(payload, _new_ch_client()),
        ),
        spc.evaluate(payload),
        graph_builder.run(payload, _new_ch_client()),
        temporal_correlator.run(payload, _new_ch_client()),
        similarity_searcher.run(payload, LANCEDB_URL),
    )

    # Unpack sigma return (hits, count, max_sev)
    if isinstance(sigma_hits_raw, tuple):
        sigma_hits, sigma_hit_count, sigma_max_severity = sigma_hits_raw
    else:
        sigma_hits, sigma_hit_count, sigma_max_severity = [], 0, 0

    # -----------------------------------------------------------------------
    # Sigma fast-path: high-severity hit → fire immediately in background,
    # continue with L2 + ML for feature vector completeness
    # -----------------------------------------------------------------------
    is_fast_path = sigma.should_fast_path(sigma_hits)
    fast_path_task: Optional[asyncio.Task] = None

    if is_fast_path:
        _stats["fast_path_count"] += 1
        log.info("Fast-path triggered for alert_id=%s", alert_id)
        # Fire a quick fast-path verdict immediately (no ML score needed)
        fast_path_task = asyncio.create_task(
            _publish_fast_path_verdict(
                payload=payload,
                alert_id=alert_id,
                started_at=started_at,
                sigma_hits=sigma_hits,
                writer=writer,
            )
        )

    # -----------------------------------------------------------------------
    # L2 threads – run concurrently (always, for feature vector)
    # -----------------------------------------------------------------------
    mitre_result, campaign_result = await asyncio.gather(
        mitre_mapper.run(payload, _new_ch_client()),
        campaign_detector.run(payload, _new_ch_client()),
    )

    # -----------------------------------------------------------------------
    # ML Scoring
    # -----------------------------------------------------------------------
    # Build preliminary feature vector (without ML score) for the scorer
    _, _, feature_vector = fusion.fuse(
        payload=payload,
        sigma_hits=sigma_hits,
        sigma_max_severity=sigma_max_severity,
        spc_result=spc_result,
        graph_result=graph_result,
        temporal_result=temporal_result,
        similarity_result=similarity_result,
        mitre_result=mitre_result,
        campaign_result=campaign_result,
        ml_result=_MLResult(score=0.0),
    )

    ml_result = await scorer.score(feature_vector)

    # -----------------------------------------------------------------------
    # Fusion – final verdict
    # -----------------------------------------------------------------------
    finding_type, hunter_score, feature_vector = fusion.fuse(
        payload=payload,
        sigma_hits=sigma_hits,
        sigma_max_severity=sigma_max_severity,
        spc_result=spc_result,
        graph_result=graph_result,
        temporal_result=temporal_result,
        similarity_result=similarity_result,
        mitre_result=mitre_result,
        campaign_result=campaign_result,
        ml_result=ml_result,
    )
    # -----------------------------------------------------------------------
    # Narrative
    # -----------------------------------------------------------------------
    severity = determine_severity(finding_type)
    recommended_action = determine_recommended_action(finding_type)
    summary = build_narrative(
        payload=payload,
        finding_type=finding_type,
        hunter_score=hunter_score,
        sigma_hits=sigma_hits,
        spc_result=spc_result,
        graph_result=graph_result,
        temporal_result=temporal_result,
        similarity_result=similarity_result,
        mitre_result=mitre_result,
        campaign_result=campaign_result,
        ml_result=ml_result,
    )

    mitre_tactics, mitre_techniques = collect_mitre_arrays(mitre_result)
    correlated_events = list(
        set(temporal_result.related_alert_ids + campaign_result.related_host_ids)
    )[:50]

    # -----------------------------------------------------------------------
    # Attack Graph
    # -----------------------------------------------------------------------
    attack_graph_data = build_attack_graph(
        payload=payload,
        finding_type=finding_type,
        hunter_score=hunter_score,
        sigma_hits=sigma_hits,
        spc_result=spc_result,
        graph_result=graph_result,
        temporal_result=temporal_result,
        similarity_result=similarity_result,
        mitre_result=mitre_result,
        campaign_result=campaign_result,
        ml_result=ml_result,
    )

    evidence = {
        "sigma_hits": [
            {"rule_id": h.rule_id, "title": h.rule_title, "severity": h.severity}
            for h in sigma_hits
        ],
        "spc_z_score": spc_result.max_z_score,
        "graph_hop_count": graph_result.hop_count,
        "has_ioc_neighbor": graph_result.has_ioc_neighbor,
        "campaign_detected": campaign_result.is_campaign,
        "ml_model": ml_result.model_used,
        "attack_graph_mermaid": attack_graph_data["mermaid"],
        "attack_graph": attack_graph_data["graph"],
    }

    completed_at = datetime.now(tz=timezone.utc).isoformat()

    verdict = HunterVerdict(
        alert_id=alert_id,
        started_at=started_at,
        completed_at=completed_at,
        status="completed",
        hostname=str(payload.get("hostname", "")),
        source_ip=str(payload.get("source_ip", "")),
        user_id=str(payload.get("user_id", "")),
        trigger_score=adjusted_score,
        severity=severity,
        finding_type=finding_type,
        summary=summary,
        evidence_json=json.dumps(evidence, default=str),
        correlated_events=correlated_events,
        mitre_tactics=mitre_tactics,
        mitre_techniques=mitre_techniques,
        recommended_action=recommended_action,
        confidence=hunter_score,
        hunter_score=hunter_score,
        feature_vector=feature_vector,
        is_fast_path=False,
        model_used=ml_result.model_used,
        sigma_hits=sigma_hits,
    )

    # -----------------------------------------------------------------------
    # Publish + training write
    # -----------------------------------------------------------------------
    await writer.publish_verdict(TOPIC_HUNTER_RESULTS, verdict)
    writer.write_training_data(verdict)

    # Ensure fast-path task completed cleanly
    if fast_path_task is not None:
        try:
            await fast_path_task
        except Exception as exc:  # noqa: BLE001
            log.warning("Fast-path task error: %s", exc)


async def _publish_fast_path_verdict(
    payload: Dict[str, Any],
    alert_id: str,
    started_at: str,
    sigma_hits: list,
    writer: OutputWriter,
) -> None:
    """
    Publish a lightweight fast-path verdict immediately for high-severity
    Sigma hits, without waiting for ML scoring.
    """
    completed_at = datetime.now(tz=timezone.utc).isoformat()

    verdict = HunterVerdict(
        alert_id=alert_id,
        started_at=started_at,
        completed_at=completed_at,
        status="completed",
        hostname=str(payload.get("hostname", "")),
        source_ip=str(payload.get("source_ip", "")),
        user_id=str(payload.get("user_id", "")),
        trigger_score=float(payload.get("adjusted_score", 0.0)),
        severity="critical",
        finding_type="CONFIRMED_ATTACK",
        summary=(
            f"High-severity Sigma rule hit on {payload.get('hostname')} – "
            f"immediate escalation. "
            + "; ".join(h.rule_title for h in sigma_hits[:3])
        ),
        evidence_json=json.dumps(
            {
                "fast_path": True,
                "sigma_hits": [
                    {"rule_id": h.rule_id, "title": h.rule_title, "severity": h.severity}
                    for h in sigma_hits
                ],
            },
            default=str,
        ),
        correlated_events=[],
        mitre_tactics=[],
        mitre_techniques=[],
        recommended_action=(
            "Immediately isolate the host and escalate to Incident Response."
        ),
        confidence=0.95,
        hunter_score=0.95,
        feature_vector=[],
        is_fast_path=True,
        sigma_hits=sigma_hits,
    )
    await writer.publish_verdict(TOPIC_HUNTER_RESULTS, verdict)
