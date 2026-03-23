"""
Narrative Builder – assembles the structured investigation summary and
determines the finding type's recommended action and severity label.

Output style: **detective field-notes** – concise, signal-focused,
machine-readable but human-scannable.  The full analyst-facing story
report and attack graph are the Verifier Agent's responsibility.
"""
from __future__ import annotations

from typing import Any, Dict, List

from models import (
    CampaignResult,
    GraphResult,
    MITREResult,
    MLResult,
    SigmaHit,
    SimilarityResult,
    SPCResult,
    TemporalResult,
)

# ── severity / recommended-action maps ────────────────────────────────────

_SEVERITY_LABEL: Dict[str, str] = {
    "CONFIRMED_ATTACK": "critical",
    "ACTIVE_CAMPAIGN": "critical",
    "BEHAVIOURAL_ANOMALY": "high",
    "SIGMA_MATCH": "high",
    "ANOMALOUS_PATTERN": "medium",
    "NORMAL_BEHAVIOUR": "low",
    "FALSE_POSITIVE": "low",
}

_RECOMMENDED_ACTION: Dict[str, str] = {
    "CONFIRMED_ATTACK": (
        "Immediately isolate the affected host and revoke active sessions. "
        "Escalate to Incident Response and preserve forensic artefacts."
    ),
    "ACTIVE_CAMPAIGN": (
        "Activate the coordinated-attack runbook. Isolate all hosts listed in "
        "correlated_events, block source IPs at the perimeter, and alert the SOC lead."
    ),
    "BEHAVIOURAL_ANOMALY": (
        "Investigate the anomalous behaviour on the host. "
        "Review recent user activity and correlate with HR records if applicable. "
        "Escalate if additional IOCs are discovered."
    ),
    "SIGMA_MATCH": (
        "Validate the Sigma rule match against raw logs. "
        "If confirmed, treat as BEHAVIOURAL_ANOMALY and escalate."
    ),
    "ANOMALOUS_PATTERN": (
        "Monitor the entity for further anomalous activity over the next 2 hours. "
        "Create a low-priority tracking ticket."
    ),
    "NORMAL_BEHAVIOUR": "No action required. Continue standard monitoring.",
    "FALSE_POSITIVE": "No action required.  Consider tuning the originating triage rule.",
}

_SEV_INT_TO_WORD = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# ── public helpers ─────────────────────────────────────────────────────────

def determine_severity(finding_type: str) -> str:
    return _SEVERITY_LABEL.get(finding_type, "medium")


def determine_recommended_action(finding_type: str) -> str:
    return _RECOMMENDED_ACTION.get(finding_type, "Investigate further.")


# ── narrative builder ──────────────────────────────────────────────────────

def build_narrative(
    payload: Dict[str, Any],
    finding_type: str,
    hunter_score: float,
    sigma_hits: List[SigmaHit],
    spc_result: SPCResult,
    graph_result: GraphResult,
    temporal_result: TemporalResult,
    similarity_result: SimilarityResult,
    mitre_result: MITREResult,
    campaign_result: CampaignResult,
    ml_result: MLResult | None = None,
) -> str:
    """Build a structured investigation narrative (detective field-notes).

    Format
    ------
    INVESTIGATION: <host> | triage=<score> | verdict=<type> | score=<score>

    SIGNALS FIRED:
      [TAG] detail ...

    SIGNALS NEGATIVE:
      [TAG] reason ...

    KILL CHAIN:   (only when MITRE matches exist)
      tactic → tactic → ...

    CAMPAIGN:     (only when campaign detected)
      ...

    VERDICT: <finding_type> (<score>) — <action hint>
    """
    lines: List[str] = []
    NL = "\n"

    # ── entity context ────────────────────────────────────────────────────
    hostname = payload.get("hostname", "unknown")
    source_ip = payload.get("source_ip") or "n/a"
    user_id = payload.get("user_id") or "n/a"
    trigger_score = float(payload.get("adjusted_score", 0.0))
    message = payload.get("message", "")
    source_type = payload.get("source_type", "unknown")

    lines.append(
        f"INVESTIGATION: {hostname} | src={source_ip} | user={user_id} "
        f"| triage={trigger_score:.3f} | verdict={finding_type} "
        f"| score={hunter_score:.3f}"
    )
    lines.append("")

    # ── trigger context ───────────────────────────────────────────────────
    lines.append("TRIGGER:")
    lines.append(f"  source_type={source_type}  triage_score={trigger_score:.3f}")
    if message:
        # Truncate long messages but keep enough for context
        short_msg = (message[:200] + "...") if len(message) > 200 else message
        lines.append(f"  message: {short_msg}")
    lines.append("")

    # ── signals that fired ────────────────────────────────────────────────
    fired: List[str] = []
    negative: List[str] = []

    # Sigma
    if sigma_hits:
        for h in sigma_hits[:5]:
            sev_word = _SEV_INT_TO_WORD.get(h.severity, str(h.severity))
            fired.append(
                f"  [SIGMA] {h.rule_title} (rule={h.rule_id}, "
                f"category={h.category}, severity={sev_word})"
            )
        if len(sigma_hits) > 5:
            fired.append(f"  [SIGMA] ... +{len(sigma_hits) - 5} more rule(s)")
    else:
        negative.append("  [SIGMA] 0 hits — no signature match")

    # SPC
    if spc_result.is_anomaly:
        fired.append(
            f"  [SPC] anomaly detected — z={spc_result.max_z_score:.2f} "
            f"(baseline μ={spc_result.baseline_mean:.1f}, "
            f"σ={spc_result.baseline_stddev:.1f})"
        )
    else:
        negative.append(
            f"  [SPC] no baseline deviation (z={spc_result.max_z_score:.2f})"
        )

    # Graph
    _graph_fired = False
    if graph_result.unique_destinations > 0 or graph_result.has_ioc_neighbor:
        parts = []
        parts.append(f"destinations={graph_result.unique_destinations}")
        parts.append(f"hops={graph_result.hop_count}")
        if graph_result.has_ioc_neighbor:
            parts.append("IOC_NEIGHBOR=YES")
        if graph_result.lateral_movement_score > 0:
            parts.append(f"lateral_mvmt={graph_result.lateral_movement_score:.2f}")
        if graph_result.c2_candidate_score > 0:
            parts.append(f"c2_score={graph_result.c2_candidate_score:.2f}")
        if graph_result.high_risk_neighbors > 0:
            parts.append(f"high_risk_neighbors={graph_result.high_risk_neighbors}")
        fired.append(f"  [GRAPH] {', '.join(parts)}")
        _graph_fired = True
    else:
        negative.append(
            "  [GRAPH] no network neighbours, no IOC links, "
            "lateral_movement=0.0"
        )

    # Temporal
    if temporal_result.escalation_count > 0:
        fired.append(
            f"  [TEMPORAL] {temporal_result.escalation_count} escalation(s) "
            f"across {temporal_result.unique_categories} category(ies), "
            f"tactic_diversity={temporal_result.tactic_diversity}, "
            f"mean_score={temporal_result.mean_score:.3f}"
        )
        if temporal_result.related_alert_ids:
            ids_str = ", ".join(
                a[:8] for a in temporal_result.related_alert_ids[:6]
            )
            extra = ""
            if len(temporal_result.related_alert_ids) > 6:
                extra = f" +{len(temporal_result.related_alert_ids) - 6} more"
            fired.append(f"  [TEMPORAL] related_alerts: [{ids_str}{extra}]")
    else:
        negative.append("  [TEMPORAL] 0 escalations in window")

    # Similarity
    if similarity_result.confirmed_neighbor_count > 0:
        fired.append(
            f"  [SIMILARITY] {similarity_result.confirmed_neighbor_count} "
            f"confirmed-attack neighbour(s), min_dist="
            f"{similarity_result.min_confirmed_dist:.3f}, "
            f"label_confidence={similarity_result.label_confidence:.2f}"
        )
    else:
        negative.append("  [SIMILARITY] no confirmed-attack neighbours")
    if similarity_result.false_positive_count > 0:
        fired.append(
            f"  [SIMILARITY] {similarity_result.false_positive_count} "
            f"false-positive neighbour(s) — score moderated"
        )

    # ML
    model_name = ml_result.model_used if ml_result else "unknown"
    fired.append(f"  [ML] {model_name}={hunter_score:.3f}")

    # Assemble fired / negative sections
    lines.append("SIGNALS FIRED:")
    lines.extend(fired)
    lines.append("")
    if negative:
        lines.append("SIGNALS NEGATIVE:")
        lines.extend(negative)
        lines.append("")

    # ── MITRE kill chain ──────────────────────────────────────────────────
    if mitre_result.match_count > 0:
        tactics = list(dict.fromkeys(m.tactic for m in mitre_result.matches))
        techniques = list(dict.fromkeys(m.technique for m in mitre_result.matches))
        lines.append("KILL CHAIN:")
        lines.append(f"  tactics ({len(tactics)}):    {' → '.join(tactics)}")
        lines.append(f"  techniques ({len(techniques)}): {', '.join(techniques)}")
        lines.append("")

    # ── Campaign ──────────────────────────────────────────────────────────
    if campaign_result.is_campaign:
        lines.append("CAMPAIGN DETECTED:")
        lines.append(
            f"  id={campaign_result.campaign_id}  "
            f"hosts={campaign_result.host_count}  "
            f"tactics={campaign_result.tactic_count}"
        )
        if campaign_result.related_host_ids:
            hosts_str = ", ".join(campaign_result.related_host_ids[:10])
            lines.append(f"  related_hosts: [{hosts_str}]")
        lines.append("")

    # ── Verdict ───────────────────────────────────────────────────────────
    severity = determine_severity(finding_type)
    action_hint = {
        "CONFIRMED_ATTACK": "isolate + escalate to IR",
        "ACTIVE_CAMPAIGN": "activate coordinated-attack runbook",
        "BEHAVIOURAL_ANOMALY": "investigate + monitor",
        "SIGMA_MATCH": "validate rule match",
        "ANOMALOUS_PATTERN": "monitor 2h + low-pri ticket",
        "NORMAL_BEHAVIOUR": "no action",
        "FALSE_POSITIVE": "tune triage rule",
    }.get(finding_type, "investigate further")

    lines.append(
        f"VERDICT: {finding_type} ({hunter_score:.3f}) | "
        f"severity={severity} | action={action_hint}"
    )

    return NL.join(lines)


def collect_mitre_arrays(
    mitre_result: MITREResult,
) -> tuple[List[str], List[str]]:
    """Extract ordered unique tactic and technique lists."""
    tactics = list(dict.fromkeys(m.tactic for m in mitre_result.matches))
    techniques = list(dict.fromkeys(m.technique for m in mitre_result.matches))
    return tactics, techniques
