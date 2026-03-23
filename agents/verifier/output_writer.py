"""
Output Writer — publish VerifierVerdict to the ``verifier-results`` Kafka
topic.

The message dict shape must exactly match what consumer/app.py
``_build_verifier_result_row()`` expects (16 fields).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aiokafka import AIOKafkaProducer  # type: ignore

import message_signer
from models import VerifierVerdict

log = logging.getLogger(__name__)


class OutputWriter:
    def __init__(self, producer: AIOKafkaProducer) -> None:
        self._producer = producer

    async def publish_verdict(
        self,
        topic: str,
        verdict: VerifierVerdict,
    ) -> None:
        """
        Serialise *verdict* and publish to *topic*.
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
                headers=message_signer.make_headers(value_bytes),
            )
            log.debug(
                "Published verdict alert_id=%s verdict=%s conf=%.3f",
                verdict.alert_id,
                verdict.verdict,
                verdict.confidence,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Failed to publish verdict for alert_id=%s: %s",
                verdict.alert_id,
                exc,
            )
            raise


def _verdict_to_dict(v: VerifierVerdict) -> dict[str, Any]:
    """
    Convert VerifierVerdict to the dict shape expected by the consumer's
    ``_build_verifier_result_row()``.
    """
    return {
        "investigation_id": str(v.investigation_id),
        "alert_id": str(v.alert_id),
        "started_at": v.started_at,
        "completed_at": v.completed_at,
        "status": v.status,
        "verdict": v.verdict,
        "confidence": v.confidence,
        "evidence_verified": v.evidence_verified,
        "merkle_batch_ids": v.merkle_batch_ids,
        "timeline_json": v.timeline_json,
        "ioc_correlations": v.ioc_correlations,
        "priority": v.priority,
        "recommended_action": v.recommended_action,
        "analyst_summary": v.analyst_summary,
        "report_narrative": v.report_narrative,
        "evidence_json": v.evidence_json,
        "explanation_json": v.explanation_json,
    }
