"""
Summary Builder — generate analyst-friendly verification summaries in a
structured "field-notes" format, matching the style of Hunter's
narrative_builder.py.
"""
from __future__ import annotations

from models import (
    EvidenceResult,
    FPResult,
    IOCResult,
    TimelineResult,
)


def build(
    payload: dict,
    evidence: EvidenceResult,
    ioc: IOCResult,
    timeline: TimelineResult,
    fp: FPResult,
    verdict: str,
    confidence: float,
    priority: str,
    action: str,
) -> str:
    """
    Build an analyst-readable verification summary.

    Returns:
        Multi-line string summary.
    """
    alert_id = payload.get("alert_id", "?")
    hostname = payload.get("hostname", "?")
    source_ip = payload.get("source_ip", "?")
    user_id = payload.get("user_id", "?")
    finding_type = payload.get("finding_type", "?")
    hunter_conf = float(payload.get("confidence", 0.0))
    severity = payload.get("severity", "?")

    mitre = payload.get("mitre_tactics", [])
    tactics_str = " → ".join(mitre) if isinstance(mitre, list) else str(mitre)

    evidence_status = "verified" if evidence.evidence_verified else "unverified"
    chain_status = (
        "intact" if evidence.chain_intact
        else ("broken" if evidence.evidence_verified else "unknown")
    )

    ioc_status = "corroborated" if ioc.corroborated else "not_found"

    seq_status = "coherent" if timeline.sequence_coherent else "broken"

    fp_status = "flagged" if fp.has_fp_history else "clean"

    lines = [
        f"VERIFICATION: alert_id={alert_id} | host={hostname} "
        f"| src={source_ip} | user={user_id}",

        f"HUNTER VERDICT: {finding_type} "
        f"(conf={hunter_conf:.2f}, severity={severity})",

        f"EVIDENCE: {evidence_status} "
        f"| merkle_batches={len(evidence.merkle_batch_ids)} "
        f"| chain={chain_status}",

        f"IOC: {ioc_status} "
        f"| matches={len(ioc.ioc_matches)} "
        f"| flows={ioc.network_flows_found}",

        f"TIMELINE: {timeline.event_count} events "
        f"| {timeline.raw_events} raw / {timeline.triage_events} triage "
        f"/ {timeline.hunter_events} hunter | sequence={seq_status}",

        f"FP CHECK: {fp_status} "
        f"| fp_history={fp.fp_feedback_count} "
        f"| tp_history={fp.tp_feedback_count} "
        f"| similar_attacks={fp.similar_attack_count}",

        f"KILL CHAIN: {tactics_str or 'N/A'}",

        f"VERIFIER VERDICT: {verdict} (conf={confidence:.2f}) "
        f"| priority={priority}",

        f"ACTION: {action}",
    ]

    return "\n".join(lines)
