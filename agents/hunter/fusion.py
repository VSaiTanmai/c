"""
Fusion Engine – implements the Triple-Layer decision matrix.

Takes the combined output from all L1/L2 threads, builds the 46-dim
feature vector, and derives the final hunter_score plus finding_type
using the 9-cell decision table from the plan.

Decision matrix (v3 – adds triage-confidence tier):
  ┌──────────────────────┬──────────────────┬─────────────────────────────┐
  │  Signal tier         │  Condition       │  Outcome                     │
  ├──────────────────────┼──────────────────┼─────────────────────────────┤
  │  Sigma hit ≥ HIGH    │  any             │ → CONFIRMED_ATTACK (fast)    │
  │  campaign=True       │  any             │ → ACTIVE_CAMPAIGN (override) │
  │  Sigma hit + SPC     │  anomaly=True    │ → CONFIRMED_ATTACK           │
  │  Sigma + triage≥.89  │  any             │ → CONFIRMED_ATTACK           │
  │  triage≥.89          │  SPC or MITRE    │ → CONFIRMED_ATTACK           │
  │  Sigma hit only      │  or triage≥.89   │ → BEHAVIOURAL_ANOMALY        │
  │  SPC anomaly         │  score≥.42       │ → CONFIRMED_ATTACK           │
  │  SPC anomaly         │  score<.42       │ → ANOMALOUS_PATTERN          │
  │  no signals          │  score≥.50       │ → CONFIRMED_ATTACK           │
  │  no signals          │  .33≤score<.50   │ → BEHAVIOURAL_ANOMALY        │
  │  no signals          │  score<.33       │ → NORMAL_BEHAVIOUR           │
  └──────────────────────┴──────────────────┴─────────────────────────────┘
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from models import (
    FEATURE_ORDER,
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


class FusionEngine:
    """
    Stateless – call `fuse()` for each investigation result.
    """

    def fuse(
        self,
        payload: Dict[str, Any],
        sigma_hits: List[SigmaHit],
        sigma_max_severity: int,
        spc_result: SPCResult,
        graph_result: GraphResult,
        temporal_result: TemporalResult,
        similarity_result: SimilarityResult,
        mitre_result: MITREResult,
        campaign_result: CampaignResult,
        ml_result: MLResult,
    ) -> tuple[str, float, List[float]]:
        """
        Returns:
            finding_type : str
            hunter_score : float (0-1)
            feature_vector : list[float] (46 dims, in FEATURE_ORDER)
        """
        fv = self._build_feature_vector(
            payload,
            sigma_hits,
            sigma_max_severity,
            spc_result,
            graph_result,
            temporal_result,
            similarity_result,
            mitre_result,
            campaign_result,
        )

        # ---------------------------------------------------------------
        # Derived signals
        # ---------------------------------------------------------------
        has_sigma_hit = len(sigma_hits) > 0
        sigma_high = sigma_max_severity >= 3       # high or critical
        spc_anomaly = spc_result.is_anomaly
        score = ml_result.score

        # Triage confidence: the triage agent already validated this event
        # with an ensemble model.  adjusted_score >= 0.89 is the
        # anomalous/escalation threshold → treat as strong evidence.
        triage_score_raw = float(payload.get("adjusted_score", 0.0))
        triage_escalation = triage_score_raw >= 0.89

        # Known MITRE tactic (not empty, not "unknown") — check BOTH triage
        # payload AND the Hunter's own L2 MITRE mapper result so that events
        # with mitre_tactic="unknown" in triage can still be confirmed if the
        # MITRE mapper found matching rules.
        _mt = str(payload.get("mitre_tactic", "")).strip().lower()
        has_known_mitre = (
            (bool(_mt) and _mt != "unknown")
            or mitre_result.match_count > 0
        )

        # ---------------------------------------------------------------
        # Triple-layer + triage-confidence matrix  (v3)
        # ---------------------------------------------------------------

        if sigma_high:
            finding_type = "CONFIRMED_ATTACK"

        elif campaign_result.is_campaign:
            finding_type = "ACTIVE_CAMPAIGN"

        elif has_sigma_hit and spc_anomaly:
            finding_type = "CONFIRMED_ATTACK"

        elif has_sigma_hit and triage_escalation:
            # Sigma corroborates triage escalation
            finding_type = "CONFIRMED_ATTACK"

        elif triage_escalation and (spc_anomaly or has_known_mitre):
            # Triage is highly confident + at least one corroborating signal
            finding_type = "CONFIRMED_ATTACK"

        elif has_sigma_hit or triage_escalation:
            # Strong signal, but no corroboration → anomaly
            finding_type = "BEHAVIOURAL_ANOMALY"

        elif spc_anomaly:
            if score >= 0.42:
                finding_type = "CONFIRMED_ATTACK"
            else:
                finding_type = "ANOMALOUS_PATTERN"

        else:
            # No Sigma hit, no SPC anomaly, no triage escalation
            if score >= 0.50:
                finding_type = "CONFIRMED_ATTACK"
            elif score >= 0.33:
                finding_type = "BEHAVIOURAL_ANOMALY"
            else:
                finding_type = "NORMAL_BEHAVIOUR"

        return finding_type, score, fv

    # ------------------------------------------------------------------
    # Feature vector construction – strict FEATURE_ORDER
    # ------------------------------------------------------------------

    def _build_feature_vector(
        self,
        payload: Dict[str, Any],
        sigma_hits: List[SigmaHit],
        sigma_max_severity: int,
        spc_result: SPCResult,
        graph_result: GraphResult,
        temporal_result: TemporalResult,
        similarity_result: SimilarityResult,
        mitre_result: MITREResult,
        campaign_result: CampaignResult,
    ) -> List[float]:
        """Return 46-dim float list in FEATURE_ORDER."""

        # Group 1 – Triage passthrough (13)
        # Field mapping: TriageResult field → feature name
        #   combined_score   → base_score
        #   asset_multiplier → entity_risk
        #   ioc_match (0/1)  → ioc_boost  (scaled by ioc_confidence)
        #   template_rarity  → template_risk
        #
        # v2: Four previously-dead features are now enriched:
        #   off_hours_boost       ← 1.0 if current UTC hour is outside 08–18
        #   distinct_categories   ← temporal_result.unique_categories
        #   event_count           ← 1 + temporal_result.escalation_count
        #   correlated_alert_count← len(temporal_result.related_alert_ids)
        ioc_boost = (
            float(payload.get("ioc_match", 0))
            * float(payload.get("ioc_confidence", 0))
            / 100.0
        )

        from datetime import datetime, timezone
        _hour = datetime.now(tz=timezone.utc).hour
        off_hours = 1.0 if not (8 <= _hour < 18) else 0.0

        triage = [
            float(payload.get("adjusted_score", 0.0)),    # adjusted_score
            float(payload.get("combined_score", 0.0)),    # base_score
            float(payload.get("asset_multiplier", 1.0)),  # entity_risk
            ioc_boost,                                     # ioc_boost
            0.0,                                           # temporal_boost (N/A)
            0.0,                                           # destination_risk (N/A)
            off_hours,                                     # off_hours_boost (enriched)
            0.0,                                           # high_severity_count (N/A)
            0.0,                                           # medium_severity_count (N/A)
            float(temporal_result.unique_categories),      # distinct_categories (enriched)
            float(1 + temporal_result.escalation_count),   # event_count (enriched)
            float(len(temporal_result.related_alert_ids)), # correlated_alert_count (enriched)
            float(payload.get("template_rarity", 0.0)),   # template_risk
        ]

        # Group 2 – Graph (8)
        graph = [
            float(graph_result.unique_destinations),
            float(graph_result.unique_src_ips),
            float(graph_result.has_ioc_neighbor),
            float(graph_result.hop_count),
            float(graph_result.high_risk_neighbors),
            float(graph_result.escalation_count),
            float(graph_result.lateral_movement_score),
            float(graph_result.c2_candidate_score),
        ]

        # Group 3 – Temporal (4)
        temporal = [
            float(temporal_result.escalation_count),
            float(temporal_result.unique_categories),
            float(temporal_result.tactic_diversity),
            float(temporal_result.mean_score),
        ]

        # Group 4 – Similarity (7)
        sim = [
            float(similarity_result.attack_embed_dist),
            float(similarity_result.historical_dist),
            float(similarity_result.log_embed_matches),
            float(similarity_result.confirmed_neighbor_count),
            float(similarity_result.min_confirmed_dist),
            float(similarity_result.false_positive_count),
            float(similarity_result.label_confidence),
        ]

        # Group 5 – MITRE (2)
        mitre = [
            float(mitre_result.match_count),
            float(mitre_result.tactic_breadth),
        ]

        # Group 6 – Campaign (2)
        campaign = [
            float(campaign_result.host_count),
            float(campaign_result.tactic_count),
        ]

        # Group 7 – Sigma (2)
        sigma = [
            float(len(sigma_hits)),
            float(sigma_max_severity),
        ]

        # Group 8 – SPC (4)
        spc = [
            float(spc_result.max_z_score),
            float(spc_result.is_anomaly),
            float(spc_result.baseline_mean),
            float(spc_result.baseline_stddev),
        ]

        # Group 9 – Triage v7 context (4) — NEW
        triage_v7 = [
            float(payload.get("ae_score", 0.0)),            # ae_score
            float(payload.get("kill_chain_stage", 0.0)),    # kill_chain_stage (0-5)
            float(payload.get("kill_chain_velocity", 0.0)), # kill_chain_velocity
            float(payload.get("entity_event_rate", 0.0)),   # entity_event_rate (EWMA)
        ]

        fv = triage + graph + temporal + sim + mitre + campaign + sigma + spc + triage_v7
        assert len(fv) == len(FEATURE_ORDER), (
            f"Feature vector length {len(fv)} != FEATURE_ORDER {len(FEATURE_ORDER)}"
        )
        return fv
