"""
Report Builder — generate the full analyst-facing story report for a
verified investigation.

This is the Verifier's primary narrative output — a multi-paragraph
forensic report that tells the *story* of the investigation from initial
alert through verification, suitable for SOC analysts and IR teams.

The Hunter's narrative_builder.py explicitly delegates this responsibility:
    "The full analyst-facing story report and attack graph are the
    Verifier Agent's responsibility."
"""
from __future__ import annotations

from models import (
    EvidenceResult,
    FPResult,
    IOCResult,
    TimelineResult,
)


def build_report(
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
    Build a multi-section forensic investigation report.

    Returns:
        Multi-line string report suitable for analyst review, incident
        tickets, and PDF export.
    """
    alert_id = payload.get("alert_id", "?")
    hostname = payload.get("hostname", "?")
    source_ip = payload.get("source_ip", "?")
    user_id = payload.get("user_id", "?")
    finding_type = payload.get("finding_type", "?")
    hunter_conf = float(payload.get("confidence", 0.0))
    severity = payload.get("severity", "?")
    hunter_summary = payload.get("summary", "")
    trigger_score = float(payload.get("trigger_score", 0.0))

    mitre = payload.get("mitre_tactics", [])
    techniques = payload.get("mitre_techniques", [])
    tactics_str = ", ".join(mitre) if isinstance(mitre, list) else str(mitre)
    techniques_str = ", ".join(techniques) if isinstance(techniques, list) else str(techniques)

    sections: list[str] = []

    # ── Header ────────────────────────────────────────────────────────
    sections.append(
        f"═══════════════════════════════════════════════════════════════\n"
        f"  CLIF VERIFICATION REPORT — {verdict.upper()}\n"
        f"  Alert: {alert_id}\n"
        f"  Priority: {priority}  |  Confidence: {confidence:.1%}\n"
        f"═══════════════════════════════════════════════════════════════"
    )

    # ── 1. Executive Summary ──────────────────────────────────────────
    verdict_label = {
        "true_positive": "CONFIRMED THREAT",
        "false_positive": "FALSE POSITIVE",
        "inconclusive": "INCONCLUSIVE — REQUIRES MANUAL REVIEW",
    }.get(verdict, verdict.upper())

    sections.append(
        f"\n1. EXECUTIVE SUMMARY\n"
        f"{'─' * 40}\n"
        f"Verdict: {verdict_label}\n"
        f"An investigation into {finding_type} activity on host {hostname} "
        f"(IP: {source_ip}, user: {user_id}) has been independently verified "
        f"by the CLIF Verifier Agent. The original Hunter Agent classified "
        f"this as {finding_type} with {hunter_conf:.1%} confidence "
        f"(severity: {severity}). After cross-referencing evidence integrity, "
        f"IOC feeds, historical timeline, and false-positive patterns, the "
        f"Verifier assigns a final verdict of {verdict} at {confidence:.1%} "
        f"confidence with {priority} priority."
    )

    # ── 2. Investigation Origin ───────────────────────────────────────
    sections.append(
        f"\n2. INVESTIGATION ORIGIN\n"
        f"{'─' * 40}\n"
        f"Triage Score:    {trigger_score:.3f}\n"
        f"Hunter Finding:  {finding_type}\n"
        f"Hunter Conf:     {hunter_conf:.1%}\n"
        f"Severity:        {severity}\n"
        f"Target Host:     {hostname}\n"
        f"Source IP:       {source_ip}\n"
        f"User:            {user_id}"
    )

    if hunter_summary:
        # Include first 500 chars of Hunter's narrative
        truncated = hunter_summary[:500]
        if len(hunter_summary) > 500:
            truncated += " [...]"
        sections.append(
            f"\nHunter Narrative:\n  {truncated}"
        )

    # ── 3. Evidence Integrity ─────────────────────────────────────────
    ev_status = "VERIFIED ✓" if evidence.evidence_verified else "UNVERIFIED ✗"
    chain_status = "INTACT" if evidence.chain_intact else "BROKEN — POSSIBLE TAMPERING"
    gap_status = "NO GAPS DETECTED" if not evidence.coverage_gap else "COVERAGE GAPS PRESENT"

    sections.append(
        f"\n3. EVIDENCE INTEGRITY\n"
        f"{'─' * 40}\n"
        f"Status:          {ev_status}\n"
        f"Merkle Chain:    {chain_status}\n"
        f"Coverage:        {gap_status}\n"
        f"Batches Verified: {len(evidence.merkle_batch_ids)}"
    )

    if evidence.merkle_batch_ids:
        batch_list = "\n  ".join(evidence.merkle_batch_ids[:10])
        sections.append(f"  {batch_list}")
        if len(evidence.merkle_batch_ids) > 10:
            sections.append(f"  ... and {len(evidence.merkle_batch_ids) - 10} more")

    if not evidence.chain_intact:
        sections.append(
            "  ⚠ WARNING: Merkle chain discontinuity detected. Log data may "
            "have been tampered with between collection and analysis. This "
            "significantly impacts the reliability of all downstream findings."
        )

    # ── 4. IOC Correlation ────────────────────────────────────────────
    ioc_status = "CORROBORATED" if ioc.corroborated else "NO MATCHES"
    sections.append(
        f"\n4. THREAT INTELLIGENCE CORRELATION\n"
        f"{'─' * 40}\n"
        f"Status:          {ioc_status}\n"
        f"IOC Matches:     {len(ioc.ioc_matches)}\n"
        f"Network Flows:   {ioc.network_flows_found}"
    )

    if ioc.ioc_matches:
        for match in ioc.ioc_matches[:5]:
            ioc_val = match.get("ioc_value", match.get("dst_ip", "?"))
            ioc_type = match.get("ioc_type", "unknown")
            ioc_source = match.get("source", "unknown")
            sections.append(f"  • {ioc_val} [{ioc_type}] (source: {ioc_source})")
        if len(ioc.ioc_matches) > 5:
            sections.append(f"  ... and {len(ioc.ioc_matches) - 5} more")

    # ── 5. Timeline Reconstruction ────────────────────────────────────
    seq_status = "COHERENT" if timeline.sequence_coherent else "ANOMALOUS ORDERING"
    sections.append(
        f"\n5. TIMELINE RECONSTRUCTION\n"
        f"{'─' * 40}\n"
        f"Total Events:    {timeline.event_count}\n"
        f"  Raw Logs:      {timeline.raw_events}\n"
        f"  Triage Scores: {timeline.triage_events}\n"
        f"  Hunter Events: {timeline.hunter_events}\n"
        f"Sequence:        {seq_status}"
    )

    if not timeline.sequence_coherent:
        sections.append(
            "  ⚠ Significant out-of-order events detected (>5% clock skew). "
            "Timeline may not accurately represent the attack sequence."
        )

    # ── 6. False Positive Analysis ────────────────────────────────────
    fp_status = "FP PATTERNS DETECTED" if fp.has_fp_history else "NO FP HISTORY"
    sections.append(
        f"\n6. FALSE POSITIVE ANALYSIS\n"
        f"{'─' * 40}\n"
        f"Status:          {fp_status}\n"
        f"Prior FP Labels: {fp.fp_feedback_count}\n"
        f"Prior TP Labels: {fp.tp_feedback_count}\n"
        f"Similar Attacks:  {fp.similar_attack_count}\n"
        f"FP Confidence:   {fp.fp_confidence:.1%}"
    )

    if fp.has_fp_history and fp.fp_feedback_count > 0:
        ratio = fp.fp_feedback_count / max(fp.fp_feedback_count + fp.tp_feedback_count, 1)
        sections.append(
            f"  Historical FP ratio: {ratio:.1%} — "
            f"{'HIGH — similar alerts frequently false positive' if ratio > 0.5 else 'moderate — some prior false positives noted'}"
        )

    # ── 7. Kill Chain ─────────────────────────────────────────────────
    if tactics_str:
        sections.append(
            f"\n7. KILL CHAIN ANALYSIS\n"
            f"{'─' * 40}\n"
            f"MITRE Tactics:    {tactics_str}\n"
            f"MITRE Techniques: {techniques_str or 'N/A'}"
        )

        if isinstance(mitre, list) and len(mitre) > 1:
            sections.append(
                f"  Attack progression spans {len(mitre)} kill chain phases, "
                f"suggesting {'advanced persistent threat activity' if len(mitre) >= 3 else 'multi-stage attack'}."
            )

    # ── 8. Verdict & Recommendation ───────────────────────────────────
    sections.append(
        f"\n8. VERDICT & RECOMMENDED ACTION\n"
        f"{'─' * 40}\n"
        f"Final Verdict:   {verdict_label}\n"
        f"Confidence:      {confidence:.1%}\n"
        f"Priority:        {priority}\n"
        f"Action:          {action}"
    )

    # Confidence breakdown
    sections.append(
        f"\n  Confidence Factors:\n"
        f"    Evidence:    {'strong' if evidence.evidence_verified and evidence.chain_intact else 'weak'}\n"
        f"    IOC:         {'corroborated' if ioc.corroborated else 'unmatched'}\n"
        f"    Timeline:    {'coherent' if timeline.sequence_coherent else 'anomalous'}\n"
        f"    FP History:  {'clean' if not fp.has_fp_history else 'flagged'}"
    )

    # ── Footer ────────────────────────────────────────────────────────
    sections.append(
        f"\n{'═' * 63}\n"
        f"  Report generated by CLIF Verifier Agent v1.0.0\n"
        f"  This is an automated forensic verification report.\n"
        f"  All findings are based on available log data and threat intel.\n"
        f"{'═' * 63}"
    )

    return "\n".join(sections)
