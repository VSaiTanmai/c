"""
Sigma Engine – loads YAML Sigma-style rules and evaluates them against
a TriageResult dict, querying ClickHouse for supporting evidence.

Rule format (subset of Sigma spec used by CLIF):
    title: <string>
    id: <uuid>
    severity: low | medium | high | critical
    category: <one of the 7 vendor categories>
    detection:
        condition: and | or
        keywords:     # optional list of substrings to scan in summary/evidence
        clickhouse:   # optional direct CH SQL template
    tags:
        - attack.tXXXX
        - attack.tactic_name
    
SQL templates support the following placeholders:
    {hostname}        – TriageResult.hostname
    {source_ip}       – TriageResult.source_ip (first value if list)
    {user_id}         – TriageResult.user_id
    {window_minutes}  – config.INVESTIGATION_WINDOW_MIN
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

import clickhouse_connect

from config import (
    CLICKHOUSE_DATABASE,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USER,
    INVESTIGATION_WINDOW_MIN,
    SIGMA_RULES_DIR,
)
from models import SigmaHit

log = logging.getLogger(__name__)

_SEVERITY_MAP: Dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class SigmaEngine:
    """
    Loads all YAML rules from SIGMA_RULES_DIR (recursively) once at startup,
    compiles them to SQL where applicable, and evaluates each rule against
    a supplied TriageResult payload dict.
    """

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self._rules_dir = rules_dir or SIGMA_RULES_DIR
        self._rules: List[Dict[str, Any]] = []
        self._load_rules()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """Walk rules_dir recursively and load every .yml / .yaml file."""
        loaded = 0
        errors = 0
        if not self._rules_dir.exists():
            log.warning("Sigma rules dir not found: %s", self._rules_dir)
            return

        for path in sorted(self._rules_dir.rglob("*.y*ml")):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    rule = yaml.safe_load(fh)
                if self._validate_rule(rule, path):
                    self._rules.append(rule)
                    loaded += 1
            except Exception as exc:  # noqa: BLE001
                log.error("Failed to load sigma rule %s: %s", path, exc)
                errors += 1

        log.info(
            "SigmaEngine: loaded %d rules from %s (%d errors)",
            loaded,
            self._rules_dir,
            errors,
        )

    def _validate_rule(self, rule: Any, path: Path) -> bool:
        """Return True if mandatory fields are present."""
        required = ("title", "id", "severity", "detection")
        if not isinstance(rule, dict):
            log.warning("Skipping non-dict rule at %s", path)
            return False
        for field in required:
            if field not in rule:
                log.warning("Rule %s missing field '%s', skipping", path, field)
                return False
        if rule.get("severity", "").lower() not in _SEVERITY_MAP:
            log.warning("Rule %s has unknown severity '%s', skipping", path, rule.get("severity"))
            return False
        return True

    # ------------------------------------------------------------------
    # Fast-path detection
    # ------------------------------------------------------------------

    def should_fast_path(self, hits: List[SigmaHit]) -> bool:
        """
        Return True if any hit with severity >= 3 (high/critical) warrants
        immediate escalation without waiting for ML scoring.
        """
        return any(h.severity >= 3 for h in hits)

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        triage_payload: Dict[str, Any],
        ch_client: Optional[Any] = None,
    ) -> Tuple[List[SigmaHit], int, int]:
        """
        Evaluate all loaded rules against *triage_payload*.

        Returns:
            hits       – list of SigmaHit for matching rules
            hit_count  – len(hits)
            max_sev    – highest severity integer (0 if no hits)
        """
        hits: List[SigmaHit] = []

        for rule in self._rules:
            try:
                hit = self._evaluate_rule(rule, triage_payload, ch_client)
                if hit:
                    hits.append(hit)
            except Exception as exc:  # noqa: BLE001
                log.debug("Error evaluating rule %s: %s", rule.get("id"), exc)

        max_sev = max((h.severity for h in hits), default=0)
        return hits, len(hits), max_sev

    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        payload: Dict[str, Any],
        ch_client: Optional[Any],
    ) -> Optional[SigmaHit]:
        """Return a SigmaHit if *rule* fires, else None."""
        detection = rule.get("detection", {})
        condition = str(detection.get("condition", "or")).lower()
        results: List[bool] = []

        # --- keyword check ---------------------------------------------------
        keywords: List[str] = detection.get("keywords", [])
        if keywords:
            # Build haystack from ALL payload values (not just summary/evidence)
            # so keywords can match triage fields like source_type, mitre_tactic,
            # mitre_technique, action, hostname, etc.
            haystack = " ".join(str(v) for v in payload.values() if v).lower()
            kw_match = (
                all(kw.lower() in haystack for kw in keywords)
                if condition == "and"
                else any(kw.lower() in haystack for kw in keywords)
            )
            results.append(kw_match)

        # --- ClickHouse SQL check --------------------------------------------
        sql_template: str = detection.get("clickhouse", "")
        if sql_template and ch_client is not None:
            sql = self._render_sql(sql_template, payload)
            if sql:
                try:
                    rows = ch_client.query(sql).result_rows
                    results.append(bool(rows and rows[0][0]))
                except Exception as exc:  # noqa: BLE001
                    log.debug("CH query failed for rule %s: %s", rule.get("id"), exc)
                    results.append(False)

        if not results:
            return None  # no detection defined

        fired = all(results) if condition == "and" else any(results)
        if not fired:
            return None

        return SigmaHit(
            rule_id=str(rule.get("id", "")),
            rule_title=str(rule.get("title", "")),
            severity=_SEVERITY_MAP.get(rule.get("severity", "").lower(), 1),
            category=str(rule.get("category", "unknown")),
            matched_fields={
                "hostname": payload.get("hostname"),
                "source_ip": payload.get("source_ip"),
                "user_id": payload.get("user_id"),
            },
        )

    # ------------------------------------------------------------------
    # SQL rendering
    # ------------------------------------------------------------------

    def _render_sql(self, template: str, payload: Dict[str, Any]) -> str:
        """
        Replace placeholders in a SQL template with sanitised values.
        Returns empty string if critical values are missing.
        """
        hostname = str(payload.get("hostname", ""))
        source_ip_raw = payload.get("source_ip", "")
        source_ip = (
            source_ip_raw[0]
            if isinstance(source_ip_raw, list) and source_ip_raw
            else str(source_ip_raw)
        )
        user_id = str(payload.get("user_id", ""))

        # Basic sanitisation – strip anything that looks like injection
        def _sanitise(value: str) -> str:
            return re.sub(r"[';\"\\]", "", value)

        try:
            rendered = template.format(
                hostname=_sanitise(hostname),
                source_ip=_sanitise(source_ip),
                user_id=_sanitise(user_id),
                window_minutes=INVESTIGATION_WINDOW_MIN,
                database=CLICKHOUSE_DATABASE,
            )
        except (KeyError, IndexError) as exc:
            log.debug("SQL template rendering failed: %s", exc)
            return ""

        # Use event timestamp instead of now() for backlog processing.
        # When the Hunter is catching up on historical messages, now()
        # would miss the actual data window.  Fall back to now() if the
        # payload has no timestamp.
        event_ts = str(payload.get("timestamp", "")).strip()
        if event_ts:
            rendered = rendered.replace(
                "now()", f"parseDateTimeBestEffort('{_sanitise(event_ts)}')"
            )

        return rendered

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def reload(self) -> None:
        """Hot-reload all rules from disk (called by trainer after model refresh)."""
        self._rules.clear()
        self._load_rules()
