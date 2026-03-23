"""
Verdict Engine — decision matrix that produces the final ``verdict``,
``confidence``, and ``priority`` from the four verification sub-results.

Also generates a structured explanation_json for full XAI traceability.
"""
from __future__ import annotations

import json
import logging

from models import (
    AMBIGUOUS_TYPES,
    DEFINITE_POSITIVE_TYPES,
    NEGATIVE_TYPES,
    EvidenceResult,
    FPResult,
    IOCResult,
    TimelineResult,
)

log = logging.getLogger(__name__)


def decide(
    payload: dict,
    evidence: EvidenceResult,
    ioc: IOCResult,
    timeline: TimelineResult,
    fp: FPResult,
) -> tuple[str, float, str, str, str]:
    """
    Apply the verdict decision matrix.

    Returns:
        (verdict, confidence, priority, status, explanation_json) tuple.
        verdict:          true_positive | false_positive | inconclusive
        priority:         P1 | P2 | P3 | P4
        status:           verified | false_positive | inconclusive | failed
        explanation_json: structured JSON decision trail for XAI
    """
    finding_type: str = payload.get("finding_type", "")
    hunter_conf: float = float(payload.get("confidence", 0.0))

    # Build explanation as we go
    explanation: dict = {
        "input": {
            "finding_type": finding_type,
            "hunter_confidence": hunter_conf,
        },
        "checks": {
            "evidence": {
                "verified": evidence.evidence_verified,
                "chain_intact": evidence.chain_intact,
                "coverage_gap": evidence.coverage_gap,
                "merkle_batch_count": len(evidence.merkle_batch_ids),
            },
            "ioc": {
                "corroborated": ioc.corroborated,
                "match_count": len(ioc.ioc_matches),
                "network_flows": ioc.network_flows_found,
            },
            "timeline": {
                "event_count": timeline.event_count,
                "raw_events": timeline.raw_events,
                "triage_events": timeline.triage_events,
                "hunter_events": timeline.hunter_events,
                "sequence_coherent": timeline.sequence_coherent,
            },
            "fp_analysis": {
                "has_fp_history": fp.has_fp_history,
                "fp_feedback_count": fp.fp_feedback_count,
                "tp_feedback_count": fp.tp_feedback_count,
                "similar_attack_count": fp.similar_attack_count,
                "fp_confidence": fp.fp_confidence,
            },
        },
        "decision_path": [],
        "calibration": None,
    }

    # ── Negative types from Hunter → auto FP ──────────────────────────────
    if finding_type in NEGATIVE_TYPES:
        conf = max(0.7, 1.0 - hunter_conf)
        explanation["decision_path"].append(
            f"finding_type '{finding_type}' is in NEGATIVE_TYPES → auto false_positive"
        )
        explanation["output"] = {
            "verdict": "false_positive", "confidence": conf,
            "priority": "P4", "status": "false_positive",
        }
        return "false_positive", conf, "P4", "false_positive", json.dumps(explanation)

    # ── FP history detected for non-definite positives ────────────────────
    if fp.has_fp_history and finding_type not in DEFINITE_POSITIVE_TYPES:
        explanation["decision_path"].append(
            f"FP history detected (fp_conf={fp.fp_confidence:.3f}, "
            f"fp_count={fp.fp_feedback_count}) and finding_type "
            f"'{finding_type}' not in DEFINITE_POSITIVE_TYPES → false_positive"
        )
        explanation["output"] = {
            "verdict": "false_positive", "confidence": fp.fp_confidence,
            "priority": "P4", "status": "false_positive",
        }
        return "false_positive", fp.fp_confidence, "P4", "false_positive", json.dumps(explanation)

    # ── Evidence tampered — force inconclusive ────────────────────────────
    if evidence.evidence_verified and not evidence.chain_intact:
        explanation["decision_path"].append(
            "Evidence verified BUT chain NOT intact → possible tampering → inconclusive"
        )
        explanation["output"] = {
            "verdict": "inconclusive", "confidence": 0.5,
            "priority": "P2", "status": "inconclusive",
        }
        return "inconclusive", 0.5, "P2", "inconclusive", json.dumps(explanation)

    # ── Definite positives from Hunter ────────────────────────────────────
    if finding_type in DEFINITE_POSITIVE_TYPES:
        if hunter_conf >= 0.80 and ioc.corroborated:
            priority = "P1"
            explanation["decision_path"].append(
                f"DEFINITE_POSITIVE + hunter_conf={hunter_conf:.3f}>=0.80 "
                f"+ IOC corroborated → P1 true_positive"
            )
        elif finding_type == "ACTIVE_CAMPAIGN":
            priority = "P1"
            explanation["decision_path"].append(
                f"ACTIVE_CAMPAIGN → P1 true_positive"
            )
        else:
            priority = "P2"
            explanation["decision_path"].append(
                f"DEFINITE_POSITIVE '{finding_type}' → P2 true_positive"
            )
        conf, calibration = _calibrate(hunter_conf, evidence, ioc, fp, timeline)
        explanation["calibration"] = calibration
        explanation["output"] = {
            "verdict": "true_positive", "confidence": conf,
            "priority": priority, "status": "verified",
        }
        return "true_positive", conf, priority, "verified", json.dumps(explanation)

    # ── Ambiguous types ───────────────────────────────────────────────────
    if finding_type in AMBIGUOUS_TYPES:
        conf, calibration = _calibrate(hunter_conf, evidence, ioc, fp, timeline)
        explanation["calibration"] = calibration
        if hunter_conf >= 0.60 and ioc.corroborated:
            explanation["decision_path"].append(
                f"AMBIGUOUS '{finding_type}' + hunter_conf={hunter_conf:.3f}>=0.60 "
                f"+ IOC corroborated → P2 true_positive"
            )
            explanation["output"] = {
                "verdict": "true_positive", "confidence": conf,
                "priority": "P2", "status": "verified",
            }
            return "true_positive", conf, "P2", "verified", json.dumps(explanation)
        if hunter_conf >= 0.60:
            explanation["decision_path"].append(
                f"AMBIGUOUS '{finding_type}' + hunter_conf={hunter_conf:.3f}>=0.60 "
                f"but no IOC corroboration → P3 inconclusive"
            )
            explanation["output"] = {
                "verdict": "inconclusive", "confidence": conf,
                "priority": "P3", "status": "inconclusive",
            }
            return "inconclusive", conf, "P3", "inconclusive", json.dumps(explanation)
        explanation["decision_path"].append(
            f"AMBIGUOUS '{finding_type}' + hunter_conf={hunter_conf:.3f}<0.60 "
            f"→ low-confidence inconclusive"
        )
        low_conf = hunter_conf * 0.8
        explanation["output"] = {
            "verdict": "inconclusive", "confidence": low_conf,
            "priority": "P3", "status": "inconclusive",
        }
        return "inconclusive", low_conf, "P3", "inconclusive", json.dumps(explanation)

    # ── Fallback ──────────────────────────────────────────────────────────
    fallback_conf = hunter_conf * 0.7
    explanation["decision_path"].append(
        f"Unknown finding_type '{finding_type}' → fallback inconclusive"
    )
    explanation["output"] = {
        "verdict": "inconclusive", "confidence": fallback_conf,
        "priority": "P3", "status": "inconclusive",
    }
    return "inconclusive", fallback_conf, "P3", "inconclusive", json.dumps(explanation)


def _calibrate(
    base_conf: float,
    evidence: EvidenceResult,
    ioc: IOCResult,
    fp: FPResult,
    timeline: TimelineResult,
) -> tuple[float, dict]:
    """
    Weighted confidence calibration.

    Weight split (sums to 1.0):
        0.40  Hunter base confidence
        0.20  Evidence integrity boost/penalty
        0.20  IOC corroboration boost
        0.10  FP penalty (inverted)
        0.10  Timeline coherence boost

    Evidence has three states:
        - verified + chain_intact  → full boost  (1.0)
        - coverage_gap (not yet anchored) → neutral (0.5)
        - verified + chain broken  → penalty     (0.0)

    Returns:
        (calibrated_confidence, calibration_details_dict)
    """
    if evidence.evidence_verified and evidence.chain_intact:
        evidence_boost = 1.0
        evidence_state = "verified_intact"
    elif evidence.coverage_gap and evidence.chain_intact:
        evidence_boost = 0.5
        evidence_state = "coverage_gap_neutral"
    else:
        evidence_boost = 0.0
        evidence_state = "unverified_or_broken"

    ioc_boost = 1.0 if ioc.corroborated else 0.0
    fp_penalty = 1.0 - fp.fp_confidence
    timeline_boost = 1.0 if timeline.sequence_coherent else 0.0

    modifier = (
        0.40
        + 0.20 * evidence_boost
        + 0.20 * ioc_boost
        + 0.10 * fp_penalty
        + 0.10 * timeline_boost
    )
    calibrated = base_conf * modifier
    calibrated = max(0.0, min(1.0, calibrated))

    calibration_details = {
        "base_confidence": base_conf,
        "weights": {
            "base": 0.40,
            "evidence": 0.20,
            "ioc": 0.20,
            "fp_penalty": 0.10,
            "timeline": 0.10,
        },
        "factors": {
            "evidence_boost": evidence_boost,
            "evidence_state": evidence_state,
            "ioc_boost": ioc_boost,
            "fp_penalty": fp_penalty,
            "fp_confidence_raw": fp.fp_confidence,
            "timeline_boost": timeline_boost,
        },
        "modifier": round(modifier, 4),
        "formula": f"{base_conf:.4f} × {modifier:.4f} = {calibrated:.4f}",
        "calibrated_confidence": calibrated,
    }

    return calibrated, calibration_details


def recommended_action(
    verdict: str,
    priority: str,
    payload: dict,
) -> str:
    """Generate a recommended action string based on verdict + priority."""
    hostname = payload.get("hostname", "unknown")
    source_ip = payload.get("source_ip", "unknown")
    finding_type = payload.get("finding_type", "")
    mitre = payload.get("mitre_tactics", [])
    tactics_str = ", ".join(mitre) if isinstance(mitre, list) else str(mitre)

    if verdict == "true_positive":
        if priority == "P1":
            return (
                f"IMMEDIATE: Isolate {hostname} ({source_ip}), "
                f"revoke active sessions, engage IR team. "
                f"Tactics: {tactics_str or 'N/A'}."
            )
        return (
            f"INVESTIGATE: Review {hostname} ({source_ip}) activity, "
            f"check lateral movement, collect forensic artifacts. "
            f"Finding: {finding_type}."
        )

    if verdict == "inconclusive":
        return (
            f"MONITOR: Increase monitoring for {hostname} ({source_ip}). "
            f"Collect additional context before escalation. "
            f"Finding: {finding_type}."
        )

    # false_positive
    return (
        f"NO ACTION: Verified as false positive for {hostname}. "
        f"Consider adding allowlist entry if recurring."
    )
