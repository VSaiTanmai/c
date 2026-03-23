"""
Heuristic Scorer – weighted linear combination of the 46-dim feature vector.

Weights are calibrated so that events passing the score gate (≥0.80)
produce heuristic scores in a usable range (0.30–0.65) for the fusion
decision matrix.  Features that are always zero in the current pipeline
(temporal_boost, destination_risk, high/medium_severity_count) are zeroed
so the weight budget goes to features that actually carry signal.

v4  – 2026: added triage v7 context features (ae_score, kill_chain_stage,
      kill_chain_velocity, entity_event_rate).  Score gate raised to 0.80.
"""
from __future__ import annotations

from typing import Dict, List

from models import FEATURE_ORDER

# ---------------------------------------------------------------------------
# Heuristic weight map  (abs sum ≈ 1.05)
# ---------------------------------------------------------------------------
HEURISTIC_WEIGHTS: Dict[str, float] = {
    # Triage passthrough — dominant signal for cold-start
    "adjusted_score": 0.38,        # primary, always ≥ 0.70 after gate
    "base_score": 0.10,            # combined_score
    "entity_risk": 0.05,           # asset_multiplier
    "ioc_boost": 0.06,             # ioc_match * ioc_confidence/100
    "temporal_boost": 0.00,        # not in TriageResult → always 0
    "destination_risk": 0.00,      # not in TriageResult → always 0
    "off_hours_boost": 0.01,       # enriched from current UTC hour
    "high_severity_count": 0.00,   # not in TriageResult → always 0
    "medium_severity_count": 0.00, # not in TriageResult → always 0
    "distinct_categories": 0.01,   # enriched from temporal_correlator
    "event_count": 0.01,           # enriched from temporal_correlator
    "correlated_alert_count": 0.01,# enriched from temporal_correlator
    "template_risk": 0.01,
    # Graph
    "graph_unique_destinations": 0.02,
    "graph_unique_src_ips": 0.01,
    "graph_has_ioc_neighbor": 0.04,
    "graph_hop_count": 0.02,
    "graph_high_risk_neighbors": 0.02,
    "graph_escalation_count": 0.02,
    "graph_lateral_movement_score": 0.03,
    "graph_c2_candidate_score": 0.03,
    # Temporal
    "temporal_escalation_count": 0.04,
    "temporal_unique_categories": 0.02,
    "temporal_tactic_diversity": 0.02,
    "temporal_mean_score": 0.03,
    # Similarity
    "similarity_attack_embed_dist": 0.03,
    "similarity_historical_dist": 0.02,
    "similarity_log_embed_matches": 0.01,
    "similarity_confirmed_neighbor_count": 0.02,
    "similarity_min_confirmed_dist": 0.01,
    "similarity_false_positive_count": -0.02,  # negative! more FP → lower score
    "similarity_label_confidence": 0.02,
    # MITRE
    "mitre_match_count": 0.02,
    "mitre_tactic_breadth": 0.02,
    # Campaign
    "campaign_host_count": 0.03,
    "campaign_tactic_count": 0.02,
    # Sigma
    "sigma_hit_count": 0.04,
    "sigma_max_severity": 0.03,
    # SPC
    "spc_z_score": 0.03,
    "spc_is_anomaly": 0.03,
    "spc_baseline_mean": 0.00,   # informational only
    "spc_baseline_stddev": 0.00, # informational only
    # Triage v7 context — NEW
    "ae_score": 0.06,              # autoencoder anomaly signal
    "kill_chain_stage": 0.04,      # higher stage → higher threat
    "kill_chain_velocity": 0.03,   # rapid progression → higher threat
    "entity_event_rate": 0.02,     # burst activity from EWMA tracker
}

# Sanity check at import time
assert len(HEURISTIC_WEIGHTS) == len(FEATURE_ORDER), (
    f"Weight count {len(HEURISTIC_WEIGHTS)} != FEATURE_ORDER {len(FEATURE_ORDER)}"
)

# ---------------------------------------------------------------------------
# Normalisation caps – raw feature values are clipped to these maxima
# before weighting so a single extreme value cannot dominate the score.
# ---------------------------------------------------------------------------
_CAPS: Dict[str, float] = {
    "sigma_hit_count": 5.0,
    "temporal_escalation_count": 20.0,
    "graph_escalation_count": 20.0,
    "graph_unique_destinations": 50.0,
    "graph_unique_src_ips": 50.0,
    "graph_hop_count": 10.0,
    "graph_high_risk_neighbors": 10.0,
    "temporal_unique_categories": 10.0,
    "mitre_match_count": 10.0,
    "similarity_confirmed_neighbor_count": 10.0,
    "similarity_false_positive_count": 10.0,
    "similarity_log_embed_matches": 20.0,
    "campaign_host_count": 20.0,
    "campaign_tactic_count": 10.0,
    "event_count": 1000.0,
    "correlated_alert_count": 50.0,
    "spc_z_score": 10.0,
    "kill_chain_stage": 5.0,         # stages 0-5
    "kill_chain_velocity": 5.0,      # transitions/min
    "entity_event_rate": 100.0,      # EWMA event rate
}


def score(feature_vector: List[float]) -> float:
    """
    Compute a heuristic hunter score in the range [0, 1].

    Parameters
    ----------
    feature_vector : list of 46 floats in FEATURE_ORDER.

    Returns
    -------
    float : 0.0 – 1.0
    """
    if len(feature_vector) != len(FEATURE_ORDER):
        raise ValueError(
            f"Expected {len(FEATURE_ORDER)} features, got {len(feature_vector)}"
        )

    total = 0.0
    for i, name in enumerate(FEATURE_ORDER):
        raw = float(feature_vector[i])
        cap = _CAPS.get(name)
        weight = HEURISTIC_WEIGHTS[name]

        # Normalise continuous features to [0, 1], booleans already 0/1
        if cap is not None and cap > 0:
            normalised = min(raw / cap, 1.0)
        else:
            normalised = max(0.0, min(raw, 1.0))

        # Invert distance metrics: (1 - distance) so lower distance → higher score
        if "dist" in name and weight > 0:
            normalised = 1.0 - normalised

        total += weight * normalised

    # Clamp to [0, 1]
    return max(0.0, min(total, 1.0))
