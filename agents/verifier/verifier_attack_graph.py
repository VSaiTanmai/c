"""
Verifier Attack Graph — enrich the Hunter's attack graph with
verification annotations and produce an updated Mermaid diagram.

Takes the Hunter's ``evidence_json`` (which contains both a JSON graph
and a Mermaid string), adds verification nodes (evidence, IOC, FP,
timeline, verdict), and re-renders an enriched Mermaid diagram.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from models import (
    EvidenceResult,
    FPResult,
    IOCResult,
    TimelineResult,
)

log = logging.getLogger(__name__)


def build_verified_attack_graph(
    payload: dict,
    evidence: EvidenceResult,
    ioc: IOCResult,
    timeline: TimelineResult,
    fp: FPResult,
    verdict: str,
    confidence: float,
    priority: str,
) -> Dict[str, Any]:
    """
    Build an enriched attack graph with verification overlay.

    Returns:
        {
            "mermaid": str,         # Renderable Mermaid diagram
            "graph": {              # Programmatic JSON graph
                "nodes": [...],
                "edges": [...],
            },
            "hunter_graph": ...,    # Original Hunter graph (preserved)
        }
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    alert_id = str(payload.get("alert_id", "?"))
    hostname = str(payload.get("hostname", "?"))
    source_ip = str(payload.get("source_ip", "?"))
    finding_type = str(payload.get("finding_type", "?"))
    hunter_conf = float(payload.get("confidence", 0.0))

    # ── Extract Hunter's original graph ───────────────────────────────
    hunter_evidence = payload.get("evidence_json", "{}")
    hunter_graph = {}
    if isinstance(hunter_evidence, str):
        try:
            hunter_graph = json.loads(hunter_evidence)
        except (json.JSONDecodeError, TypeError):
            pass

    original_nodes = hunter_graph.get("graph", {}).get("nodes", [])
    original_edges = hunter_graph.get("graph", {}).get("edges", [])

    # ── Core nodes (from Hunter context) ──────────────────────────────
    nodes.append({
        "id": "alert",
        "label": f"Alert {alert_id[:8]}",
        "type": "alert",
        "detail": finding_type,
    })
    nodes.append({
        "id": "host",
        "label": hostname,
        "type": "host",
    })
    nodes.append({
        "id": "src_ip",
        "label": source_ip,
        "type": "ip",
    })
    edges.append({"from": "alert", "to": "host", "type": "target"})
    edges.append({"from": "src_ip", "to": "host", "type": "connection"})

    # ── Hunter verdict node ───────────────────────────────────────────
    nodes.append({
        "id": "hunter",
        "label": f"Hunter: {finding_type}",
        "type": "hunter_verdict",
        "confidence": hunter_conf,
    })
    edges.append({"from": "alert", "to": "hunter", "type": "investigation"})

    # ── Evidence integrity node ───────────────────────────────────────
    ev_label = (
        f"Evidence: {'VERIFIED' if evidence.evidence_verified else 'UNVERIFIED'}"
    )
    ev_detail = (
        f"chain={'intact' if evidence.chain_intact else 'BROKEN'}, "
        f"batches={len(evidence.merkle_batch_ids)}"
    )
    nodes.append({
        "id": "evidence",
        "label": ev_label,
        "type": "verification",
        "status": "pass" if evidence.evidence_verified and evidence.chain_intact else "fail",
        "detail": ev_detail,
    })
    edges.append({"from": "hunter", "to": "evidence", "type": "verify"})

    # Individual merkle batch nodes (max 5)
    for i, batch_id in enumerate(evidence.merkle_batch_ids[:5]):
        bid = f"batch_{i}"
        nodes.append({"id": bid, "label": batch_id, "type": "merkle_batch"})
        edges.append({"from": "evidence", "to": bid, "type": "merkle_chain"})

    # ── IOC correlation node ──────────────────────────────────────────
    ioc_label = (
        f"IOC: {'CORROBORATED' if ioc.corroborated else 'NO MATCH'}"
    )
    nodes.append({
        "id": "ioc_check",
        "label": ioc_label,
        "type": "verification",
        "status": "pass" if ioc.corroborated else "neutral",
        "detail": f"matches={len(ioc.ioc_matches)}, flows={ioc.network_flows_found}",
    })
    edges.append({"from": "hunter", "to": "ioc_check", "type": "verify"})

    # Individual IOC match nodes
    for i, match in enumerate(ioc.ioc_matches[:5]):
        ioc_id = f"ioc_{i}"
        ioc_val = match.get("ioc_value", match.get("dst_ip", "?"))
        ioc_type = match.get("ioc_type", "unknown")
        nodes.append({
            "id": ioc_id,
            "label": f"{ioc_val} [{ioc_type}]",
            "type": "ioc",
        })
        edges.append({"from": "ioc_check", "to": ioc_id, "type": "ioc_match"})

    # ── Timeline node ─────────────────────────────────────────────────
    tl_label = f"Timeline: {timeline.event_count} events"
    nodes.append({
        "id": "timeline",
        "label": tl_label,
        "type": "verification",
        "status": "pass" if timeline.sequence_coherent else "warn",
        "detail": (
            f"raw={timeline.raw_events}, triage={timeline.triage_events}, "
            f"hunter={timeline.hunter_events}, "
            f"coherent={'yes' if timeline.sequence_coherent else 'NO'}"
        ),
    })
    edges.append({"from": "hunter", "to": "timeline", "type": "verify"})

    # ── FP analysis node ──────────────────────────────────────────────
    fp_label = (
        f"FP Check: {'FLAGGED' if fp.has_fp_history else 'CLEAN'}"
    )
    nodes.append({
        "id": "fp_check",
        "label": fp_label,
        "type": "verification",
        "status": "fail" if fp.has_fp_history else "pass",
        "detail": (
            f"fp={fp.fp_feedback_count}, tp={fp.tp_feedback_count}, "
            f"similar={fp.similar_attack_count}, "
            f"fp_conf={fp.fp_confidence:.2f}"
        ),
    })
    edges.append({"from": "hunter", "to": "fp_check", "type": "verify"})

    # ── MITRE kill chain nodes ────────────────────────────────────────
    mitre = payload.get("mitre_tactics", [])
    if isinstance(mitre, list) and mitre:
        prev_tactic_id = None
        for i, tactic in enumerate(mitre):
            tactic_id = f"tactic_{i}"
            nodes.append({
                "id": tactic_id,
                "label": tactic,
                "type": "mitre_tactic",
            })
            if prev_tactic_id:
                edges.append({
                    "from": prev_tactic_id, "to": tactic_id,
                    "type": "kill_chain",
                })
            else:
                edges.append({"from": "host", "to": tactic_id, "type": "kill_chain"})
            prev_tactic_id = tactic_id

    # ── Final verdict node (central destination) ──────────────────────
    verdict_label = {
        "true_positive": "TRUE POSITIVE",
        "false_positive": "FALSE POSITIVE",
        "inconclusive": "INCONCLUSIVE",
    }.get(verdict, verdict.upper())

    nodes.append({
        "id": "verdict",
        "label": f"VERDICT: {verdict_label}",
        "type": "verdict",
        "priority": priority,
        "confidence": confidence,
    })
    edges.append({"from": "evidence", "to": "verdict", "type": "contributes"})
    edges.append({"from": "ioc_check", "to": "verdict", "type": "contributes"})
    edges.append({"from": "timeline", "to": "verdict", "type": "contributes"})
    edges.append({"from": "fp_check", "to": "verdict", "type": "contributes"})

    # ── Build Mermaid diagram ─────────────────────────────────────────
    mermaid = _build_mermaid(nodes, edges, verdict, priority)

    return {
        "mermaid": mermaid,
        "graph": {"nodes": nodes, "edges": edges},
        "hunter_graph": {
            "nodes": original_nodes,
            "edges": original_edges,
        },
    }


# ── Mermaid renderer ─────────────────────────────────────────────────────

_NODE_STYLES = {
    "alert":          ("([{label}])",  "#ff9800"),  # orange pill
    "host":           ("({label})",    "#2196f3"),  # blue rounded
    "ip":             ("({label})",    "#2196f3"),
    "hunter_verdict": ("[[{label}]]",  "#9c27b0"),  # purple box
    "verification":   ("{{{label}}}",  None),        # dynamic colour
    "merkle_batch":   ("[{label}]",    "#78909c"),   # grey
    "ioc":            ("(({label}))",  "#f44336"),   # red circle
    "mitre_tactic":   (">{label}]",    "#e91e63"),   # pink flag
    "verdict":        ("[/{label}\\]",  None),       # dynamic colour
}

_VERIFICATION_COLOURS = {
    "pass": "#4caf50",   # green
    "fail": "#f44336",   # red
    "warn": "#ff9800",   # orange
    "neutral": "#78909c",# grey
}

_VERDICT_COLOURS = {
    "true_positive": "#f44336",   # red
    "false_positive": "#4caf50",  # green
    "inconclusive": "#ff9800",    # orange
}


def _build_mermaid(
    nodes: List[Dict], edges: List[Dict], verdict: str, priority: str
) -> str:
    lines = ["graph TD"]
    style_lines: List[str] = []

    for node in nodes:
        nid = node["id"]
        label = node["label"]
        ntype = node.get("type", "")

        shape_tpl, colour = _NODE_STYLES.get(ntype, ("[{label}]", "#78909c"))

        # Dynamic colours for verification and verdict nodes
        if ntype == "verification":
            colour = _VERIFICATION_COLOURS.get(node.get("status", "neutral"), "#78909c")
        elif ntype == "verdict":
            colour = _VERDICT_COLOURS.get(verdict, "#ff9800")

        shape = shape_tpl.format(label=label)
        lines.append(f"    {nid}{shape}")
        if colour:
            style_lines.append(f"    style {nid} fill:{colour},color:#fff,stroke:#333")

    for edge in edges:
        etype = edge.get("type", "")
        arrow = "-->|" + etype + "|" if etype else "-->"
        lines.append(f"    {edge['from']} {arrow} {edge['to']}")

    lines.extend(style_lines)

    return "\n".join(lines)
