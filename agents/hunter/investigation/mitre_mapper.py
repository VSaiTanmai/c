"""
MITRE Mapper – L2 investigation thread.

Queries `mitre_mapping_rules` to find ATT&CK mappings matching this event's
characteristics. Derives 2 feature-vector dimensions:
  [mitre_match_count, mitre_tactic_breadth]

Actual mitre_mapping_rules schema (verified against schema.sql):
  rule_id           String
  priority          UInt8
  trigger_features  Array(String)   — e.g. ['known_malicious_ip', 'off_hours']
  trigger_threshold Float32         — adjusted_score must be >= this
  mitre_id          String          — e.g. 'T1110'
  mitre_name        String
  mitre_tactic      String
  confidence        Enum8('LOW'=1, 'MEDIUM'=2, 'HIGH'=3)
  description       String
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List

from config import CLICKHOUSE_DATABASE
from models import MITREMatch, MITREResult

log = logging.getLogger(__name__)

# Map Enum confidence label → float
_CONF_MAP: Dict[str, float] = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}


async def run(
    payload: Dict[str, Any],
    ch_client: Any,
) -> MITREResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query, payload, ch_client)


def _query(payload: Dict[str, Any], ch_client: Any) -> MITREResult:
    adjusted_score: float = float(payload.get("adjusted_score", 0.0))
    ioc_match: int = int(payload.get("ioc_match", 0))
    ioc_confidence: int = int(payload.get("ioc_confidence", 0))
    template_id: str = str(payload.get("template_id", "")).lower()
    score_std_dev: float = float(payload.get("score_std_dev", 0.0))
    disagreement_flag: int = int(payload.get("disagreement_flag", 0))
    ae_score: float = float(payload.get("ae_score", 0.0))

    # ------------------------------------------------------------------
    # Derive active trigger feature names from TriageResult payload.
    # These correspond to the string values stored in trigger_features[].
    # ------------------------------------------------------------------
    active: List[str] = []

    if ioc_match:
        active.append("known_malicious_ip")
    if _detect_off_hours():
        active.append("off_hours")
    if any(kw in template_id for kw in ("auth", "login", "password", "credential")):
        active.append("template_auth")
    if any(kw in template_id for kw in ("lateral", "smb", "rdp", "remote")):
        active.append("template_lateral")
    if any(kw in template_id for kw in ("user_created", "new_user", "account")):
        active.append("template_user_created")
    if any(kw in template_id for kw in ("priv", "escalat", "sudo")):
        active.append("template_priv_escalation")
    if any(kw in template_id for kw in ("exfil", "upload", "transfer")):
        active.append("template_data_exfil")
    if any(kw in template_id for kw in ("scan", "port", "recon", "discovery")):
        active.append("template_port_scan")
    if any(kw in template_id for kw in ("outbound", "c2", "beacon")):
        active.append("outbound")
    if score_std_dev > 0.3 or disagreement_flag:
        active.append("std_dev_high")
    if ae_score > 0.7:
        active.append("ae_high")

    result = MITREResult()

    # Triage's own MITRE fields (passthrough from TriageResult)
    triage_tactic = str(payload.get("mitre_tactic", "")).strip()
    triage_technique = str(payload.get("mitre_technique", "")).strip()

    try:
        if active:
            arr_literal = "[" + ",".join(f"'{_s(f)}'" for f in active) + "]"
            q = f"""
                SELECT rule_id, mitre_id, mitre_name, mitre_tactic,
                       toString(confidence) AS confidence_str
                FROM {CLICKHOUSE_DATABASE}.mitre_mapping_rules
                WHERE {adjusted_score:.4f} >= trigger_threshold
                  AND hasAny(trigger_features, {arr_literal})
                ORDER BY priority ASC
                LIMIT 25
            """
        else:
            # Fallback: score-threshold only, top-5 highest-priority rules
            q = f"""
                SELECT rule_id, mitre_id, mitre_name, mitre_tactic,
                       toString(confidence) AS confidence_str
                FROM {CLICKHOUSE_DATABASE}.mitre_mapping_rules
                WHERE {adjusted_score:.4f} >= trigger_threshold
                ORDER BY priority ASC
                LIMIT 5
            """

        rows = ch_client.query(q).result_rows
        matches: List[MITREMatch] = []
        seen_tactics: set = set()

        for rule_id, mitre_id, mitre_name, mitre_tactic, conf_str in rows:
            conf = _CONF_MAP.get(str(conf_str).upper(), 0.3)
            matches.append(
                MITREMatch(
                    rule_id=str(rule_id),
                    tactic=str(mitre_tactic),
                    technique=str(mitre_id),
                    confidence=conf,
                )
            )
            if mitre_tactic:
                seen_tactics.add(mitre_tactic)

        # Merge triage's own MITRE passthrough if not covered by rule matches
        if triage_tactic and not any(m.tactic == triage_tactic for m in matches):
            matches.append(
                MITREMatch(
                    rule_id="triage_passthrough",
                    tactic=triage_tactic,
                    technique=triage_technique,
                    confidence=float(ioc_confidence) / 100.0 if ioc_confidence else 0.5,
                )
            )
            seen_tactics.add(triage_tactic)

        result.matches = matches
        result.match_count = len(matches)
        result.tactic_breadth = len(seen_tactics)

    except Exception as exc:  # noqa: BLE001
        log.warning(
            "MITREMapper failed for adjusted_score=%.3f active=%s: %s",
            adjusted_score, active, exc,
        )

    return result


def _detect_off_hours() -> bool:
    from datetime import datetime, timezone
    hour = datetime.now(tz=timezone.utc).hour
    return not (8 <= hour < 18)


def _s(value: Any) -> str:
    return re.sub(r"[';\"\\]", "", str(value))
