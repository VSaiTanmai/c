"""
Verifier Agent — main application entry point.

FastAPI + aiokafka async consumer.

Pipeline position:
    Hunter Agent → [hunter-results topic] → Verifier Agent
                                                  │
                                                  ▼
                                       [verifier-results topic] → Consumer

Verification flow per message:
    1. Parse hunter-results payload
    2. Parallel verification threads:
       a. Evidence integrity (merkle chain)
       b. IOC correlation (ioc_cache + network_events)
       c. Timeline reconstruction (raw_logs + triage_scores + hunter)
       d. FP analysis (feedback_labels + similarity search)
    3. Verdict engine — decision matrix → verdict + confidence + priority
    4. Summary builder — analyst-friendly field-notes summary
    5. Report builder — full forensic story narrative
    6. Attack graph — enriched Mermaid diagram + JSON graph
    7. Output writer — publish to verifier-results
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict

import clickhouse_connect  # type: ignore
import httpx
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
    EVIDENCE_LOOKBACK_HOURS,
    FP_SIMILARITY_THRESHOLD,
    IOC_LOOKBACK_HOURS,
    KAFKA_AUTO_OFFSET_RESET,
    KAFKA_BROKERS,
    KAFKA_MAX_POLL_RECORDS,
    LANCEDB_URL,
    LANCEDB_TIMEOUT_SEC,
    LOG_LEVEL,
    REQUIRE_HMAC,
    SKIP_NEGATIVE_VERDICTS,
    TIMELINE_WINDOW_HOURS,
    TOPIC_INPUT,
    TOPIC_OUTPUT,
    VERIFIER_PORT,
)
import message_signer
from models import VerifierVerdict, NEGATIVE_TYPES
from output_writer import OutputWriter
import report_builder
import summary_builder
import verdict_engine
from verifier_attack_graph import build_verified_attack_graph
from verification.evidence_integrity import verify
from verification.fp_analyzer import analyze
from verification.ioc_correlator import correlate
from verification.timeline_builder import build

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("verifier.app")

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------
_state: Dict[str, Any] = {}
_stats: Dict[str, Any] = {
    "messages_received": 0,
    "messages_processed": 0,
    "messages_skipped_negative": 0,
    "verdicts_true_positive": 0,
    "verdicts_false_positive": 0,
    "verdicts_inconclusive": 0,
    "errors": 0,
    "started_at": None,
}


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
# Health gates — wait for dependencies before consuming
# ---------------------------------------------------------------------------

async def _wait_for_clickhouse(max_retries: int = 30, delay: float = 2.0) -> None:
    for attempt in range(1, max_retries + 1):
        try:
            ch = _new_ch_client()
            ch.query("SELECT 1")
            log.info("ClickHouse ready (attempt %d)", attempt)
            return
        except Exception:
            log.warning("ClickHouse not ready (attempt %d/%d)", attempt, max_retries)
            await asyncio.sleep(delay)
    raise RuntimeError("ClickHouse not reachable after retries")


async def _wait_for_lancedb(max_retries: int = 20, delay: float = 3.0) -> None:
    async with httpx.AsyncClient(timeout=5.0) as client:
        for attempt in range(1, max_retries + 1):
            try:
                resp = await client.get(f"{LANCEDB_URL}/health")
                if resp.status_code < 500:
                    log.info("LanceDB ready (attempt %d)", attempt)
                    return
            except Exception:
                pass
            log.warning("LanceDB not ready (attempt %d/%d)", attempt, max_retries)
            await asyncio.sleep(delay)
    log.warning("LanceDB not reachable — similarity checks will be skipped")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    log.info("Verifier Agent starting up …")
    _stats["started_at"] = datetime.now(tz=timezone.utc).isoformat()

    # Health gates
    await _wait_for_clickhouse()
    await _wait_for_lancedb()

    # ClickHouse client (for health endpoint)
    _state["ch"] = _new_ch_client()

    # Kafka producer
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BROKERS,
        value_serializer=lambda v: v if isinstance(v, bytes) else v.encode("utf-8"),
    )
    await producer.start()
    _state["producer"] = producer

    # Output writer
    _state["output_writer"] = OutputWriter(producer)

    # Kafka consumer
    consumer = AIOKafkaConsumer(
        TOPIC_INPUT,
        bootstrap_servers=KAFKA_BROKERS,
        group_id=CONSUMER_GROUP_ID,
        auto_offset_reset=KAFKA_AUTO_OFFSET_RESET,
        max_poll_records=KAFKA_MAX_POLL_RECORDS,
        enable_auto_commit=True,
    )
    await consumer.start()
    _state["consumer"] = consumer

    # Start the main processing loop
    asyncio.create_task(_consume_loop(), name="verifier-consume")

    log.info("Verifier Agent ready — consuming from %s", TOPIC_INPUT)

    yield

    # Shutdown
    log.info("Verifier Agent shutting down …")
    await consumer.stop()
    await producer.stop()
    log.info("Verifier Agent stopped.")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CLIF Verifier Agent",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.get("/stats")
async def stats() -> JSONResponse:
    return JSONResponse(_stats)


@app.get("/ready")
async def ready() -> JSONResponse:
    """Readiness probe — verifies ClickHouse is accessible."""
    try:
        ch = _state.get("ch")
        if ch:
            ch.query("SELECT 1")
        return JSONResponse({"ready": True})
    except Exception:
        return JSONResponse({"ready": False}, status_code=503)


# ---------------------------------------------------------------------------
# Kafka consume loop
# ---------------------------------------------------------------------------

async def _consume_loop() -> None:
    consumer: AIOKafkaConsumer = _state["consumer"]

    while True:
        try:
            async for msg in consumer:
                _stats["messages_received"] += 1
                if REQUIRE_HMAC and not message_signer.extract_and_verify(msg.value, msg.headers):
                    _stats["errors"] += 1
                    log.warning("HMAC verification failed for message offset=%s", msg.offset)
                    continue
                try:
                    payload = json.loads(msg.value.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    _stats["errors"] += 1
                    log.warning("Skipping malformed message offset=%s: %s", msg.offset, exc)
                    continue
                try:
                    await _process_message(payload)
                    _stats["messages_processed"] += 1
                except Exception as exc:  # noqa: BLE001
                    _stats["errors"] += 1
                    log.error("Error processing message: %s", exc, exc_info=True)
        except Exception as exc:  # noqa: BLE001
            _stats["errors"] += 1
            log.error("Consume loop error (restarting in 2s): %s", exc, exc_info=True)
            await asyncio.sleep(2)


# ---------------------------------------------------------------------------
# Per-message verification pipeline
# ---------------------------------------------------------------------------

async def _process_message(payload: Dict[str, Any]) -> None:
    """Full verification pipeline for one HunterResult message."""

    alert_id = str(payload.get("alert_id") or str(uuid.uuid4()))
    investigation_id = str(uuid.uuid4())
    finding_type = str(payload.get("finding_type", ""))
    started_at = datetime.now(tz=timezone.utc).isoformat()

    # -------------------------------------------------------------------
    # Skip negative verdicts if configured
    # -------------------------------------------------------------------
    if SKIP_NEGATIVE_VERDICTS and finding_type in NEGATIVE_TYPES:
        _stats["messages_skipped_negative"] += 1
        log.debug("Skipped negative verdict alert_id=%s type=%s", alert_id, finding_type)
        return

    log.info("Verifying alert_id=%s finding_type=%s", alert_id, finding_type)

    hostname = str(payload.get("hostname", ""))
    source_ip = str(payload.get("source_ip", ""))
    user_id = str(payload.get("user_id", ""))

    # Entity for lookups
    entity = hostname or source_ip or user_id

    # -------------------------------------------------------------------
    # Parallel verification (async — each gets its own CH client)
    # -------------------------------------------------------------------
    evidence_result, ioc_result, timeline_result, fp_result = await asyncio.gather(
        verify(
            _new_ch_client(), payload, EVIDENCE_LOOKBACK_HOURS
        ),
        correlate(
            _new_ch_client(), payload, IOC_LOOKBACK_HOURS
        ),
        build(
            _new_ch_client(), payload, TIMELINE_WINDOW_HOURS
        ),
        analyze(
            _new_ch_client(), payload, LANCEDB_URL,
            LANCEDB_TIMEOUT_SEC, FP_SIMILARITY_THRESHOLD,
        ),
    )

    # -------------------------------------------------------------------
    # Verdict engine
    # -------------------------------------------------------------------
    verd, confidence, priority, status, explanation_json = verdict_engine.decide(
        payload=payload,
        evidence=evidence_result,
        ioc=ioc_result,
        timeline=timeline_result,
        fp=fp_result,
    )

    action = verdict_engine.recommended_action(verd, priority, payload)

    # -------------------------------------------------------------------
    # Summary + Report + Attack Graph
    # -------------------------------------------------------------------
    analyst_summary = summary_builder.build(
        payload=payload,
        evidence=evidence_result,
        ioc=ioc_result,
        timeline=timeline_result,
        fp=fp_result,
        verdict=verd,
        confidence=confidence,
        priority=priority,
        action=action,
    )

    report_narrative = report_builder.build_report(
        payload=payload,
        evidence=evidence_result,
        ioc=ioc_result,
        timeline=timeline_result,
        fp=fp_result,
        verdict=verd,
        confidence=confidence,
        priority=priority,
        action=action,
    )

    attack_graph_data = build_verified_attack_graph(
        payload=payload,
        evidence=evidence_result,
        ioc=ioc_result,
        timeline=timeline_result,
        fp=fp_result,
        verdict=verd,
        confidence=confidence,
        priority=priority,
    )

    completed_at = datetime.now(tz=timezone.utc).isoformat()

    # -------------------------------------------------------------------
    # Build final verdict object
    # -------------------------------------------------------------------
    final = VerifierVerdict(
        investigation_id=investigation_id,
        alert_id=alert_id,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        verdict=verd,
        confidence=confidence,
        evidence_verified=1 if evidence_result.evidence_verified else 0,
        merkle_batch_ids=evidence_result.merkle_batch_ids,
        timeline_json=timeline_result.timeline_json,
        ioc_correlations=ioc_result.correlation_json,
        priority=priority,
        recommended_action=action,
        analyst_summary=analyst_summary,
        report_narrative=report_narrative,
        evidence_json=json.dumps(attack_graph_data, default=str),
        explanation_json=explanation_json,
    )

    # -------------------------------------------------------------------
    # Publish
    # -------------------------------------------------------------------
    writer: OutputWriter = _state["output_writer"]
    await writer.publish_verdict(TOPIC_OUTPUT, final)

    # Update stats
    if verd == "true_positive":
        _stats["verdicts_true_positive"] += 1
    elif verd == "false_positive":
        _stats["verdicts_false_positive"] += 1
    else:
        _stats["verdicts_inconclusive"] += 1

    log.info(
        "Verified alert_id=%s → verdict=%s conf=%.3f priority=%s",
        alert_id, verd, confidence, priority,
    )
