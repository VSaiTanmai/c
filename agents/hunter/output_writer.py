"""
Output Writer – publishes the HunterVerdict to the `hunter-results` Kafka
topic and optionally writes training data to ClickHouse.

The Kafka message schema must match what consumer/app.py
`_build_hunter_investigation_row()` expects.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

from aiokafka import AIOKafkaProducer  # type: ignore

from models import HunterVerdict
from training import feature_store, label_builder

log = logging.getLogger(__name__)


class OutputWriter:
    def __init__(self, producer: AIOKafkaProducer, ch_client: Any) -> None:
        self._producer = producer
        self._ch = ch_client

    async def publish_verdict(
        self,
        topic: str,
        verdict: HunterVerdict,
    ) -> None:
        """
        Serialise *verdict* to JSON and publish to *topic*.
        Key = alert_id (bytes) for partition stability.
        """
        msg = _verdict_to_dict(verdict)
        value_bytes = json.dumps(msg, default=str).encode("utf-8")
        key_bytes = str(verdict.alert_id).encode("utf-8")

        try:
            await self._producer.send_and_wait(
                topic,
                value=value_bytes,
                key=key_bytes,
            )
            log.debug(
                "Published verdict alert_id=%s finding_type=%s score=%.3f",
                verdict.alert_id,
                verdict.finding_type,
                verdict.hunter_score,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Failed to publish verdict for alert_id=%s: %s",
                verdict.alert_id,
                exc,
            )
            raise

    def write_training_data(self, verdict: HunterVerdict) -> None:
        """
        Write a training row to ClickHouse if this verdict is eligible.
        Guards: not fast_path, feature_vector present.
        """
        if not label_builder.should_include_in_training(verdict):
            return

        label = label_builder.get_label(verdict.finding_type)
        # Create a fresh CH client to avoid concurrent-session errors
        import clickhouse_connect  # type: ignore
        from config import (
            CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_USER,
            CLICKHOUSE_PASSWORD, CLICKHOUSE_DATABASE,
        )
        ch = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
            database=CLICKHOUSE_DATABASE,
        )
        feature_store.write_training_row(verdict, label, ch)


def _verdict_to_dict(verdict: HunterVerdict) -> Dict[str, Any]:
    """
    Convert HunterVerdict to the dict shape expected by the consumer.
    Only includes fields that _build_hunter_investigation_row() uses.
    """
    return {
        "alert_id": str(verdict.alert_id),
        "started_at": verdict.started_at,
        "completed_at": verdict.completed_at,
        "status": verdict.status,
        "hostname": verdict.hostname,
        "source_ip": verdict.source_ip,
        "user_id": verdict.user_id,
        "trigger_score": verdict.trigger_score,
        "severity": verdict.severity,
        "finding_type": verdict.finding_type,
        "summary": verdict.summary,
        "evidence_json": verdict.evidence_json,
        "correlated_events": verdict.correlated_events,
        "mitre_tactics": verdict.mitre_tactics,
        "mitre_techniques": verdict.mitre_techniques,
        "recommended_action": verdict.recommended_action,
        "confidence": verdict.confidence,
    }
