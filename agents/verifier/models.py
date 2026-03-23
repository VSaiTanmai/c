"""
Verifier Agent – data models.

Field names and types intentionally match what consumer/app.py
``_build_verifier_result_row()`` expects.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


# ── Hunter finding-type constants (same as agents/hunter/models.py) ────────
DEFINITE_POSITIVE_TYPES = frozenset({"CONFIRMED_ATTACK", "ACTIVE_CAMPAIGN"})
AMBIGUOUS_TYPES = frozenset({"BEHAVIOURAL_ANOMALY", "ANOMALOUS_PATTERN", "SIGMA_MATCH"})
NEGATIVE_TYPES = frozenset({"NORMAL_BEHAVIOUR", "FALSE_POSITIVE"})


# ── Verification sub-results ──────────────────────────────────────────────

@dataclass
class EvidenceResult:
    """Merkle-based evidence integrity check."""
    evidence_verified: bool = False
    merkle_batch_ids: List[str] = field(default_factory=list)
    chain_intact: bool = True
    coverage_gap: bool = True          # True until proven otherwise


@dataclass
class IOCResult:
    """IOC cross-correlation across ioc_cache and network_events."""
    corroborated: bool = False
    ioc_matches: List[Dict] = field(default_factory=list)
    network_flows_found: int = 0
    correlation_json: str = "{}"


@dataclass
class TimelineResult:
    """Chronological entity activity reconstruction."""
    event_count: int = 0
    raw_events: int = 0
    triage_events: int = 0
    hunter_events: int = 0
    timeline_json: str = "[]"
    sequence_coherent: bool = True


@dataclass
class FPResult:
    """False-positive pattern analysis."""
    has_fp_history: bool = False
    fp_feedback_count: int = 0
    tp_feedback_count: int = 0
    similar_attack_count: int = 0
    fp_confidence: float = 0.0


# ── Final output ──────────────────────────────────────────────────────────

@dataclass
class VerifierVerdict:
    """
    Maps 1-to-1 with VERIFIER_RESULTS_COLUMNS in consumer/app.py.

    Enum constraints (from ClickHouse schema):
      status:   pending | running | verified | false_positive | inconclusive | failed
      verdict:  true_positive | false_positive | inconclusive
      priority: P1 | P2 | P3 | P4
    """
    investigation_id: str = ""
    alert_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    status: str = "pending"
    verdict: str = "inconclusive"
    confidence: float = 0.0
    evidence_verified: int = 0
    merkle_batch_ids: List[str] = field(default_factory=list)
    timeline_json: str = "[]"
    ioc_correlations: str = "{}"
    priority: str = "P4"
    recommended_action: str = ""
    analyst_summary: str = ""
    report_narrative: str = ""
    evidence_json: str = "{}"
    explanation_json: str = "{}"  # structured decision trail for XAI
