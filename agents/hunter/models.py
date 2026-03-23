"""
Hunter Agent – shared data-models and constants.

All dataclasses are frozen where mutation is not required, enabling safe
use as dict keys and in sets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Feature vector definition — 46 dimensions, strictly ordered
# ---------------------------------------------------------------------------
FEATURE_ORDER: List[str] = [
    # --- Triage passthrough (13) ---
    "adjusted_score",
    "base_score",
    "entity_risk",
    "ioc_boost",
    "temporal_boost",
    "destination_risk",
    "off_hours_boost",
    "high_severity_count",
    "medium_severity_count",
    "distinct_categories",
    "event_count",
    "correlated_alert_count",
    "template_risk",
    # --- Graph features (8) ---
    "graph_unique_destinations",
    "graph_unique_src_ips",
    "graph_has_ioc_neighbor",
    "graph_hop_count",
    "graph_high_risk_neighbors",
    "graph_escalation_count",
    "graph_lateral_movement_score",
    "graph_c2_candidate_score",
    # --- Temporal features (4) ---
    "temporal_escalation_count",
    "temporal_unique_categories",
    "temporal_tactic_diversity",
    "temporal_mean_score",
    # --- Similarity features (7) ---
    "similarity_attack_embed_dist",
    "similarity_historical_dist",
    "similarity_log_embed_matches",
    "similarity_confirmed_neighbor_count",
    "similarity_min_confirmed_dist",
    "similarity_false_positive_count",
    "similarity_label_confidence",
    # --- MITRE features (2) ---
    "mitre_match_count",
    "mitre_tactic_breadth",
    # --- Campaign features (2) ---
    "campaign_host_count",
    "campaign_tactic_count",
    # --- Sigma features (2) ---
    "sigma_hit_count",
    "sigma_max_severity",
    # --- SPC features (4) ---
    "spc_z_score",
    "spc_is_anomaly",
    "spc_baseline_mean",
    "spc_baseline_stddev",
    # --- Triage v7 context (4) --- NEW
    "ae_score",
    "kill_chain_stage",
    "kill_chain_velocity",
    "entity_event_rate",
]

assert len(FEATURE_ORDER) == 46, f"FEATURE_ORDER must have 46 entries, got {len(FEATURE_ORDER)}"

# ---------------------------------------------------------------------------
# Finding-type classification sets
# ---------------------------------------------------------------------------
DEFINITE_POSITIVE_TYPES = frozenset(
    {
        "CONFIRMED_ATTACK",
        "ACTIVE_CAMPAIGN",
    }
)

AMBIGUOUS_TYPES = frozenset(
    {
        "BEHAVIOURAL_ANOMALY",
        "ANOMALOUS_PATTERN",
        "SIGMA_MATCH",
    }
)

NEGATIVE_TYPES = frozenset(
    {
        "NORMAL_BEHAVIOUR",
        "FALSE_POSITIVE",
    }
)


# ---------------------------------------------------------------------------
# Layer 1 investigation results
# ---------------------------------------------------------------------------

@dataclass
class SigmaHit:
    """Single Sigma rule evaluation result."""
    rule_id: str
    rule_title: str
    severity: int          # 1-4  (low=1, medium=2, high=3, critical=4)
    category: str
    matched_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SPCDeviation:
    """Single entity showing statistical deviation."""
    hostname: str
    source_ip: str
    user_id: str
    z_score: float
    observed: float
    baseline_mean: float
    baseline_stddev: float


@dataclass
class SPCResult:
    """Aggregated SPC analysis for an alert."""
    deviations: List[SPCDeviation] = field(default_factory=list)
    # Scalar features extracted onto the feature vector
    max_z_score: float = 0.0
    is_anomaly: bool = False
    baseline_mean: float = 0.0
    baseline_stddev: float = 0.0


@dataclass
class GraphResult:
    """L1 graph analysis result."""
    unique_destinations: int = 0
    unique_src_ips: int = 0
    has_ioc_neighbor: bool = False
    hop_count: int = 0
    high_risk_neighbors: int = 0
    escalation_count: int = 0
    lateral_movement_score: float = 0.0
    c2_candidate_score: float = 0.0


@dataclass
class TemporalResult:
    """L1 temporal correlation result."""
    escalation_count: int = 0
    unique_categories: int = 0
    tactic_diversity: int = 0
    mean_score: float = 0.0
    related_alert_ids: List[str] = field(default_factory=list)


@dataclass
class SimilarityResult:
    """L1 similarity search result."""
    attack_embed_dist: float = 1.0      # min distance to attack_embeddings
    historical_dist: float = 1.0        # min distance to historical_incidents
    log_embed_matches: int = 0          # number of close log matches
    confirmed_neighbor_count: int = 0   # confirmed-attack neighbours < 0.3
    min_confirmed_dist: float = 1.0
    false_positive_count: int = 0       # false-positive neighbours < 0.3
    label_confidence: float = 0.0       # fraction of confirmed among all <0.5


# ---------------------------------------------------------------------------
# Layer 2 investigation results
# ---------------------------------------------------------------------------

@dataclass
class MITREMatch:
    """Single MITRE ATT&CK rule match."""
    rule_id: str
    tactic: str
    technique: str
    confidence: float


@dataclass
class MITREResult:
    """Aggregated MITRE mapping result."""
    matches: List[MITREMatch] = field(default_factory=list)
    match_count: int = 0
    tactic_breadth: int = 0     # distinct tactics


@dataclass
class CampaignResult:
    """Campaign detection result."""
    is_campaign: bool = False
    host_count: int = 0
    tactic_count: int = 0
    campaign_id: Optional[str] = None
    related_host_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class MLResult:
    """CatBoost or heuristic scorer output."""
    score: float = 0.0
    model_used: str = "heuristic"   # "heuristic" | "catboost"
    feature_importances: Dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Drift monitoring
# ---------------------------------------------------------------------------

@dataclass
class DriftReport:
    """Drift detection output written to hunter_model_health."""
    kl_divergence: float = 0.0
    psi: float = 0.0
    triage_anchor_divergence: float = 0.0
    drift_detected: bool = False
    affected_features: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Final verdict (maps to hunter-results Kafka message)
# ---------------------------------------------------------------------------

@dataclass
class HunterVerdict:
    """
    Complete Hunter investigation result.  
    Field names intentionally match those expected by
    consumer/_build_hunter_investigation_row().
    """
    alert_id: str
    started_at: str            # ISO-8601 UTC
    completed_at: str          # ISO-8601 UTC
    status: str                # "COMPLETED" | "FAST_PATH" | "ERROR"

    # Entity context (passed through from TriageResult)
    hostname: str
    source_ip: str
    user_id: str
    trigger_score: float

    # Verdict
    severity: str              # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    finding_type: str          # one of the type constants above
    summary: str
    evidence_json: str         # JSON-serialised evidence dict
    correlated_events: List[str]  # list of related UUID alert_ids
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    recommended_action: str
    confidence: float          # 0.0–1.0

    # Internal (not forwarded to consumer, used for training data)
    hunter_score: float = 0.0
    feature_vector: List[float] = field(default_factory=list)
    is_fast_path: bool = False
    model_used: str = "heuristic"   # "heuristic" or "catboost"
    sigma_hits: List[SigmaHit] = field(default_factory=list)
