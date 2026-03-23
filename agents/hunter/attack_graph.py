"""
Attack Graph Builder – generates a per-investigation attack graph.

Produces two outputs stored in evidence_json:
  1. Mermaid diagram string  – renderable in any Markdown viewer / dashboard
  2. JSON graph (nodes/edges) – for programmatic consumption by UIs or Verifier

The graph is built from all L1/L2 investigation results that Hunter already
computes.  No extra queries are needed; we re-use the data that's available
at investigation time.

Graph density adapts automatically:
  - Sparse  : only ML fired → minimal graph (host → verdict)
  - Medium  : temporal / MITRE / SPC fired → chain graph
  - Rich    : sigma + graph + campaign + MITRE → full kill-chain graph
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

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

log = logging.getLogger(__name__)

# ── Mermaid-safe label escaping ───────────────────────────────────────────

_MERMAID_UNSAFE = re.compile(r'["\[\]{}()<>|#&]')
_SEV_WORD = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _m(text: str, max_len: int = 40) -> str:
    """Escape a string for safe use inside a Mermaid node label."""
    text = _MERMAID_UNSAFE.sub("", str(text))
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


# ── Style maps ────────────────────────────────────────────────────────────

_FINDING_COLOR = {
    "CONFIRMED_ATTACK": "#dc3545",
    "ACTIVE_CAMPAIGN": "#dc3545",
    "BEHAVIOURAL_ANOMALY": "#fd7e14",
    "SIGMA_MATCH": "#fd7e14",
    "ANOMALOUS_PATTERN": "#ffc107",
    "NORMAL_BEHAVIOUR": "#28a745",
    "FALSE_POSITIVE": "#6c757d",
}

_HOST_COLOR = {
    "CONFIRMED_ATTACK": "#ff6b6b",
    "ACTIVE_CAMPAIGN": "#ff6b6b",
    "BEHAVIOURAL_ANOMALY": "#ffa500",
    "NORMAL_BEHAVIOUR": "#28a745",
}

# ══════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════


def build_attack_graph(
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
    ml_result: Optional[MLResult] = None,
) -> Dict[str, Any]:
    """Build the attack graph and return ``{"mermaid": str, "graph": dict}``."""
    try:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        hostname = str(payload.get("hostname", "unknown"))
        source_ip = str(payload.get("source_ip", "")) or "n/a"
        user_id = str(payload.get("user_id", "")) or "n/a"
        trigger_score = float(payload.get("adjusted_score", 0.0))

        # Track how many signals actually fired (for metadata)
        signals_fired = 0
        signals_checked = 7  # sigma, spc, graph, temporal, similarity, mitre, campaign

        # ── Subject host node ────────────────────────────────────────────
        host_id = f"host-{_safe_id(hostname)}"
        nodes.append({
            "id": host_id,
            "type": "host",
            "label": hostname,
            "ip": source_ip,
            "user": user_id,
            "triage_score": round(trigger_score, 3),
            "is_subject": True,
        })

        # ── Sigma detection nodes ────────────────────────────────────────
        if sigma_hits:
            signals_fired += 1
            for i, hit in enumerate(sigma_hits[:5]):
                sig_id = f"sigma-{i}-{_safe_id(hit.rule_id)}"
                sev_word = _SEV_WORD.get(hit.severity, str(hit.severity))
                nodes.append({
                    "id": sig_id,
                    "type": "sigma",
                    "label": hit.rule_title,
                    "rule_id": hit.rule_id,
                    "severity": sev_word,
                    "category": hit.category,
                })
                edges.append({
                    "from": host_id,
                    "to": sig_id,
                    "type": "detection",
                    "label": f"Sigma: {sev_word}",
                })

        # ── SPC anomaly node ─────────────────────────────────────────────
        if spc_result.is_anomaly:
            signals_fired += 1
            spc_id = "spc-anomaly"
            nodes.append({
                "id": spc_id,
                "type": "spc",
                "label": f"SPC Anomaly z={spc_result.max_z_score:.2f}",
                "z_score": round(spc_result.max_z_score, 2),
                "baseline_mean": round(spc_result.baseline_mean, 1),
                "baseline_stddev": round(spc_result.baseline_stddev, 1),
            })
            edges.append({
                "from": host_id,
                "to": spc_id,
                "type": "statistical",
                "label": f"z={spc_result.max_z_score:.1f}",
            })

        # ── Graph / network destination nodes ────────────────────────────
        has_graph = (
            graph_result.unique_destinations > 0
            or graph_result.has_ioc_neighbor
            or graph_result.hop_count > 0
        )
        if has_graph:
            signals_fired += 1
            # Destinations summary node
            if graph_result.unique_destinations > 0:
                dst_id = "graph-destinations"
                nodes.append({
                    "id": dst_id,
                    "type": "network_summary",
                    "label": f"{graph_result.unique_destinations} destination(s)",
                    "unique_destinations": graph_result.unique_destinations,
                    "hop_count": graph_result.hop_count,
                    "has_ioc": graph_result.has_ioc_neighbor,
                })
                edge_label_parts = [f"{graph_result.hop_count} hop(s)"]
                if graph_result.has_ioc_neighbor:
                    edge_label_parts.append("IOC!")
                edges.append({
                    "from": host_id,
                    "to": dst_id,
                    "type": "network",
                    "label": ", ".join(edge_label_parts),
                })

            # IOC neighbor node
            if graph_result.has_ioc_neighbor:
                ioc_id = "graph-ioc"
                nodes.append({
                    "id": ioc_id,
                    "type": "ioc",
                    "label": "IOC Neighbour Detected",
                    "is_ioc": True,
                })
                src = dst_id if graph_result.unique_destinations > 0 else host_id
                edges.append({
                    "from": src,
                    "to": ioc_id,
                    "type": "ioc_link",
                    "label": "IOC match",
                })

            # Lateral movement indicator
            if graph_result.lateral_movement_score > 0.1:
                lat_id = "graph-lateral"
                nodes.append({
                    "id": lat_id,
                    "type": "indicator",
                    "label": f"Lateral Movement {graph_result.lateral_movement_score:.2f}",
                    "score": round(graph_result.lateral_movement_score, 2),
                })
                edges.append({
                    "from": host_id,
                    "to": lat_id,
                    "type": "lateral",
                    "label": f"score={graph_result.lateral_movement_score:.2f}",
                })

            # C2 candidate indicator
            if graph_result.c2_candidate_score > 0.1:
                c2_id = "graph-c2"
                nodes.append({
                    "id": c2_id,
                    "type": "indicator",
                    "label": f"C2 Candidate {graph_result.c2_candidate_score:.2f}",
                    "score": round(graph_result.c2_candidate_score, 2),
                })
                edges.append({
                    "from": host_id,
                    "to": c2_id,
                    "type": "c2",
                    "label": f"score={graph_result.c2_candidate_score:.2f}",
                })

        # ── Temporal correlation nodes ───────────────────────────────────
        if temporal_result.escalation_count > 0:
            signals_fired += 1
            # Summary node for temporal window
            temp_id = "temporal-summary"
            nodes.append({
                "id": temp_id,
                "type": "temporal",
                "label": (
                    f"{temporal_result.escalation_count} escalation(s), "
                    f"{temporal_result.unique_categories} cat(s)"
                ),
                "escalation_count": temporal_result.escalation_count,
                "unique_categories": temporal_result.unique_categories,
                "mean_score": round(temporal_result.mean_score, 3),
            })
            edges.append({
                "from": temp_id,
                "to": host_id,
                "type": "temporal",
                "label": f"mean={temporal_result.mean_score:.2f}",
            })

            # Individual related alert nodes (max 6)
            for j, aid in enumerate(temporal_result.related_alert_ids[:6]):
                alert_id_short = aid[:8] if len(aid) > 8 else aid
                a_id = f"alert-{j}-{alert_id_short}"
                nodes.append({
                    "id": a_id,
                    "type": "related_alert",
                    "label": f"alert {alert_id_short}",
                    "full_id": aid,
                })
                edges.append({
                    "from": a_id,
                    "to": temp_id,
                    "type": "temporal_link",
                    "label": "correlated",
                })

        # ── Similarity nodes ─────────────────────────────────────────────
        if similarity_result.confirmed_neighbor_count > 0:
            signals_fired += 1
            sim_id = "similarity-matches"
            nodes.append({
                "id": sim_id,
                "type": "similarity",
                "label": (
                    f"{similarity_result.confirmed_neighbor_count} similar "
                    f"attack(s), dist={similarity_result.min_confirmed_dist:.3f}"
                ),
                "neighbor_count": similarity_result.confirmed_neighbor_count,
                "min_dist": round(similarity_result.min_confirmed_dist, 3),
                "label_confidence": round(similarity_result.label_confidence, 2),
            })
            edges.append({
                "from": sim_id,
                "to": host_id,
                "type": "similarity",
                "label": f"confidence={similarity_result.label_confidence:.2f}",
            })

        # ── MITRE kill-chain nodes ───────────────────────────────────────
        if mitre_result.match_count > 0:
            signals_fired += 1
            tactics_seen: List[str] = []
            prev_tactic_id: Optional[str] = None
            for match in mitre_result.matches:
                tactic = match.tactic
                if not tactic or tactic in tactics_seen:
                    continue
                tactics_seen.append(tactic)
                tactic_id = f"mitre-{_safe_id(tactic)}"
                nodes.append({
                    "id": tactic_id,
                    "type": "mitre_tactic",
                    "label": tactic,
                    "technique": match.technique,
                    "confidence": round(match.confidence, 2),
                })
                # Chain tactics in kill-chain order
                if prev_tactic_id:
                    edges.append({
                        "from": prev_tactic_id,
                        "to": tactic_id,
                        "type": "kill_chain",
                        "label": "progresses to",
                    })
                else:
                    # Link first tactic to host
                    edges.append({
                        "from": host_id,
                        "to": tactic_id,
                        "type": "mitre_link",
                        "label": match.technique,
                    })
                prev_tactic_id = tactic_id

            # Link sigma hits to their matching MITRE tactics
            if sigma_hits and tactics_seen:
                first_tactic_id = f"mitre-{_safe_id(tactics_seen[0])}"
                for i, hit in enumerate(sigma_hits[:3]):
                    sig_id = f"sigma-{i}-{_safe_id(hit.rule_id)}"
                    # Only link if the sigma node exists
                    if any(n["id"] == sig_id for n in nodes):
                        edges.append({
                            "from": sig_id,
                            "to": first_tactic_id,
                            "type": "detection_to_tactic",
                            "label": "triggers",
                        })

        # ── Campaign nodes ───────────────────────────────────────────────
        if campaign_result.is_campaign:
            signals_fired += 1
            camp_id = "campaign"
            nodes.append({
                "id": camp_id,
                "type": "campaign",
                "label": (
                    f"Campaign: {campaign_result.host_count} host(s), "
                    f"{campaign_result.tactic_count} tactic(s)"
                ),
                "campaign_id": campaign_result.campaign_id or "unknown",
                "host_count": campaign_result.host_count,
                "tactic_count": campaign_result.tactic_count,
            })
            edges.append({
                "from": host_id,
                "to": camp_id,
                "type": "campaign",
                "label": f"campaign {(campaign_result.campaign_id or '')[:8]}",
            })
            # Related campaign hosts
            for k, rh in enumerate(campaign_result.related_host_ids[:5]):
                rh_id = f"camp-host-{k}-{_safe_id(rh)}"
                nodes.append({
                    "id": rh_id,
                    "type": "campaign_host",
                    "label": rh,
                })
                edges.append({
                    "from": camp_id,
                    "to": rh_id,
                    "type": "campaign_link",
                    "label": "coordinated",
                })

        # ── Verdict node ─────────────────────────────────────────────────
        verdict_id = "verdict"
        model_name = ml_result.model_used if ml_result else "unknown"
        nodes.append({
            "id": verdict_id,
            "type": "verdict",
            "label": f"{finding_type} ({hunter_score:.3f})",
            "finding_type": finding_type,
            "score": round(hunter_score, 3),
            "model": model_name,
        })
        edges.append({
            "from": host_id,
            "to": verdict_id,
            "type": "verdict",
            "label": f"{model_name}={hunter_score:.3f}",
        })

        # ── Determine graph density ──────────────────────────────────────
        if signals_fired >= 4:
            density = "rich"
        elif signals_fired >= 2:
            density = "medium"
        else:
            density = "sparse"

        # ── Build Mermaid string ─────────────────────────────────────────
        mermaid = _build_mermaid(
            nodes, edges, finding_type, hostname, source_ip,
            user_id, trigger_score, hunter_score, density,
        )

        # ── Assemble result ──────────────────────────────────────────────
        graph_result_dict = {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "finding_type": finding_type,
                "hunter_score": round(hunter_score, 3),
                "signals_fired": signals_fired,
                "signals_checked": signals_checked,
                "graph_density": density,
                "model": model_name,
            },
        }

        return {
            "mermaid": mermaid,
            "graph": graph_result_dict,
        }

    except Exception as exc:
        log.warning("attack_graph build failed: %s", exc, exc_info=True)
        return {
            "mermaid": f"graph TD\n    ERR[Graph generation failed: {_m(str(exc))}]",
            "graph": {"nodes": [], "edges": [], "metadata": {"error": str(exc)}},
        }


# ══════════════════════════════════════════════════════════════════════════
# Mermaid renderer
# ══════════════════════════════════════════════════════════════════════════

def _build_mermaid(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    finding_type: str,
    hostname: str,
    source_ip: str,
    user_id: str,
    trigger_score: float,
    hunter_score: float,
    density: str,
) -> str:
    """Render nodes + edges into a Mermaid graph TD string."""
    lines: List[str] = ["graph TD"]

    # ── Node definitions ─────────────────────────────────────────────────
    for n in nodes:
        nid = _mid(n["id"])
        ntype = n["type"]
        label = _m(n.get("label", n["id"]))

        if ntype == "host":
            ip = _m(n.get("ip", ""))
            usr = _m(n.get("user", ""))
            ts = n.get("triage_score", 0.0)
            lines.append(
                f'    {nid}["{hostname}<br/>'
                f'src: {ip}<br/>'
                f'user: {usr}<br/>'
                f'triage: {ts:.3f}"]'
            )
        elif ntype == "sigma":
            sev = n.get("severity", "?")
            lines.append(f'    {nid}[/"SIGMA: {label}<br/>severity: {sev}"/]')
        elif ntype == "spc":
            lines.append(f'    {nid}[("SPC: {label}")]')
        elif ntype == "network_summary":
            hops = n.get("hop_count", 0)
            ioc = "IOC!" if n.get("has_ioc") else ""
            lines.append(
                f'    {nid}["{label}<br/>{hops} hop(s) {ioc}"]'
            )
        elif ntype == "ioc":
            lines.append(f'    {nid}{{{{"{label}"}}}}')
        elif ntype == "indicator":
            lines.append(f'    {nid}(["{label}"])')
        elif ntype == "temporal":
            lines.append(f'    {nid}["{label}"]')
        elif ntype == "related_alert":
            lines.append(f'    {nid}(["{label}"])')
        elif ntype == "similarity":
            lines.append(f'    {nid}[("{label}")]')
        elif ntype == "mitre_tactic":
            tech = _m(n.get("technique", ""))
            lines.append(f'    {nid}[/"{label}<br/>{tech}"\\]')
        elif ntype == "campaign":
            lines.append(f'    {nid}{{{{"{label}"}}}}')
        elif ntype == "campaign_host":
            lines.append(f'    {nid}(["{label}"])')
        elif ntype == "verdict":
            lines.append(f'    {nid}["{label}"]')
        else:
            lines.append(f'    {nid}["{label}"]')

    lines.append("")

    # ── Edge definitions ─────────────────────────────────────────────────
    for e in edges:
        src = _mid(e["from"])
        dst = _mid(e["to"])
        label = _m(e.get("label", ""), max_len=30)
        etype = e.get("type", "")

        if etype in ("temporal_link", "similarity", "detection_to_tactic"):
            # Dotted line for indirect relationships
            lines.append(f'    {src} -.->|"{label}"| {dst}')
        elif etype == "kill_chain":
            # Thick arrow for kill chain progression
            lines.append(f'    {src} ==>|"{label}"| {dst}')
        else:
            # Solid line for direct relationships
            lines.append(f'    {src} -->|"{label}"| {dst}')

    lines.append("")

    # ── Style definitions ────────────────────────────────────────────────
    host_nid = _mid(f"host-{_safe_id(hostname)}")
    verdict_nid = _mid("verdict")

    host_fill = _HOST_COLOR.get(finding_type, "#ff6b6b")
    verdict_fill = _FINDING_COLOR.get(finding_type, "#dc3545")

    lines.append(f"    style {host_nid} fill:{host_fill},stroke:#333,color:#fff")
    lines.append(f"    style {verdict_nid} fill:{verdict_fill},stroke:#333,color:#fff")

    # Style IOC nodes red
    for n in nodes:
        if n["type"] == "ioc":
            lines.append(f"    style {_mid(n['id'])} fill:#ff0000,stroke:#333,color:#fff")
        elif n["type"] == "campaign":
            lines.append(f"    style {_mid(n['id'])} fill:#ff4500,stroke:#333,color:#fff")
        elif n["type"] == "sigma":
            sev = n.get("severity", "low")
            if sev in ("critical", 4):
                lines.append(f"    style {_mid(n['id'])} fill:#dc3545,stroke:#333,color:#fff")
            elif sev in ("high", 3):
                lines.append(f"    style {_mid(n['id'])} fill:#fd7e14,stroke:#333,color:#fff")

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════

def _safe_id(value: str) -> str:
    """Convert arbitrary string to a safe identifier fragment."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(value))[:30]


def _mid(raw_id: str) -> str:
    """Convert a node id to a valid Mermaid identifier (alphanumeric + _)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)
