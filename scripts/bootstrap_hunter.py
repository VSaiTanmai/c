#!/usr/bin/env python3
"""
Cold-Start Bootstrap — generates high-quality training data from the
42 real triage observations in ClickHouse, plus synthetic augmentation
to reach the 500-sample threshold needed for a robust CatBoost model.

This script runs OUTSIDE Docker (host-side) and:
  1. Reads all triage_scores from ClickHouse
  2. Reads network_events, process_events, features_entity_freq for context
  3. For each triage row, builds a full 42-dim feature vector by simulating
     the investigation signals that would have been produced
  4. Labels each row using domain knowledge (high scores + attack context → 1,
     benign patterns → 0)
  5. Augments with systematic perturbations to reach 500+ rows
  6. Writes training data directly to hunter_training_data table
  7. Trains CatBoost and saves the model
  8. Copies the model into the hunter container

Labelling strategy (ground truth from triage ensemble):
  - LGBM ≥ 0.90 AND (EIF ≥ 0.80 OR combined ≥ 0.90) → ATTACK (label=1)
  - LGBM ≥ 0.80 AND EIF ≥ 0.50 AND combined ≥ 0.85  → ATTACK (label=1)
  - combined < 0.50 OR (LGBM < 0.50 AND EIF < 0.50)  → BENIGN (label=0)
  - Everything else → scored by attack indicator heuristic
"""
import json
import math
import os
import random
import subprocess
import sys
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

random.seed(42)

# ---------------------------------------------------------------------------
# ClickHouse connection via docker exec
# ---------------------------------------------------------------------------
def ch_query(sql: str) -> str:
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client",
         "--format", "TSVWithNames", "-q", sql],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        print(f"  CH ERROR: {r.stderr.strip()}")
        return ""
    return r.stdout.strip()


def ch_command(sql: str) -> bool:
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client", "-q", sql],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        print(f"  CH CMD ERR: {r.stderr.strip()[:200]}")
    return r.returncode == 0


def parse_tsv(raw: str) -> List[Dict[str, str]]:
    lines = raw.strip().split("\n")
    if len(lines) < 2:
        return []
    headers = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        vals = line.split("\t")
        rows.append(dict(zip(headers, vals)))
    return rows


# ---------------------------------------------------------------------------
# Known attack signatures (from test scripts) for labelling
# ---------------------------------------------------------------------------
KNOWN_ATTACK_HOSTS = {
    "db-srv-01": {"tactic": "initial-access", "technique": "T1190", "desc": "SQL injection"},
    "dc-primary": {"tactic": "credential-access", "technique": "T1558", "desc": "Kerberoasting"},
    "rdp-gateway": {"tactic": "lateral-movement", "technique": "T1021", "desc": "RDP brute force"},
    "ws-finance-03": {"tactic": "privilege-escalation", "technique": "T1078", "desc": "Service account abuse"},
    "dns-srv-01": {"tactic": "exfiltration", "technique": "T1048", "desc": "DNS tunneling"},
    "internal-cache": {"tactic": "exfiltration", "technique": "T1048.003", "desc": "Port 0 exfil"},
    "bastion-01": {"tactic": "lateral-movement", "technique": "T1021.004", "desc": "SCTP SSH"},
    "edge-router": {"tactic": "command-and-control", "technique": "T1572", "desc": "GRE covert channel"},
    "k8s-worker-07": {"tactic": "privilege-escalation", "technique": "T1610", "desc": "Container escape"},
}

KNOWN_BENIGN_HOSTS = {"web-lb-01", "prod-api-01"}


def label_row(row: Dict[str, str]) -> int:
    """Assign ground-truth label based on triage ensemble + domain knowledge."""
    hostname = row.get("hostname", "")
    combined = float(row.get("combined_score", "0"))
    lgbm = float(row.get("lgbm_score", "0"))
    eif = float(row.get("eif_score", "0"))
    action = row.get("action", "")

    # Definite benign
    if hostname in KNOWN_BENIGN_HOSTS:
        return 0
    if combined < 0.50:
        return 0

    # Definite attack (high-confidence ensemble agreement)
    if hostname in KNOWN_ATTACK_HOSTS:
        if lgbm >= 0.80 and combined >= 0.85:
            return 1
        if eif >= 0.90:  # EIF catches novel patterns
            return 1

    # High ensemble agreement
    if lgbm >= 0.90 and (eif >= 0.80 or combined >= 0.90):
        return 1
    if lgbm >= 0.80 and eif >= 0.50 and combined >= 0.85:
        return 1

    # Borderline — use action as tiebreaker
    if action == "escalate" and combined >= 0.85:
        return 1
    if action == "discard":
        return 0

    # Moderate scores — lean benign for safety
    if combined < 0.75:
        return 0

    return 1  # high combined, likely attack


# ---------------------------------------------------------------------------
# Feature vector construction
# ---------------------------------------------------------------------------
# Replicates the 42-dim FEATURE_ORDER from models.py

def build_feature_vector(
    row: Dict[str, str],
    network_ctx: Dict[str, Any],
    temporal_ctx: Dict[str, Any],
    similarity_ctx: Dict[str, Any],
) -> List[float]:
    """Build 42-dim feature vector matching EXACTLY what the live fusion engine
    produces. See agents/hunter/fusion.py _build_feature_vector().

    Critical: the live fusion engine hardcodes many triage fields to 0.0
    (temporal_boost, destination_risk, off_hours_boost, severity counts,
    distinct_categories, event_count, correlated_alert_count).
    entity_risk = asset_multiplier which defaults to 1.0.
    ioc_boost = ioc_match(0/1) * ioc_confidence/100 which is 0.0 for all data.
    """

    combined = float(row.get("combined_score", "0"))
    adjusted = float(row.get("adjusted_score", "0"))
    template_rarity = float(row.get("template_rarity", "0"))

    # Triage passthrough scores
    ioc_match = int(row.get("ioc_match", "0"))
    ioc_conf = int(row.get("ioc_confidence", "0"))
    ioc_boost = ioc_match * ioc_conf / 100.0

    # Group 1: Triage passthrough (13)
    # IN LIVE FUSION: adjusted_score, combined_score, asset_multiplier(=1.0),
    # ioc_boost(=0.0), then 8 N/A zeros, then template_rarity
    triage = [
        adjusted,                               # adjusted_score
        combined,                               # base_score
        1.0,                                    # entity_risk (asset_multiplier default)
        ioc_boost,                              # ioc_boost (always 0.0 in current data)
        0.0,                                    # temporal_boost (N/A in fusion)
        0.0,                                    # destination_risk (N/A)
        0.0,                                    # off_hours_boost (N/A)
        0.0,                                    # high_severity_count (N/A)
        0.0,                                    # medium_severity_count (N/A)
        0.0,                                    # distinct_categories (N/A)
        0.0,                                    # event_count (N/A)
        0.0,                                    # correlated_alert_count (N/A)
        template_rarity,                        # template_risk
    ]

    # Group 2: Graph features (8) — graph builder queries CH, gets 0 for most
    graph = [
        float(network_ctx.get("unique_destinations", 0)),   # graph_unique_destinations
        float(network_ctx.get("unique_src_ips", 0)),        # graph_unique_src_ips
        0.0,                                                # graph_has_ioc_neighbor
        float(network_ctx.get("hop_count", 0)),             # graph_hop_count
        0.0,                                                # graph_high_risk_neighbors
        0.0,                                                # graph_escalation_count
        0.0,                                                # graph_lateral_movement_score
        0.0,                                                # graph_c2_candidate_score
    ]

    # Group 3: Temporal features (4) — from temporal correlator
    temporal = [
        float(temporal_ctx.get("escalation_count", 0)),     # temporal_escalation_count
        float(temporal_ctx.get("unique_categories", 0)),    # temporal_unique_categories
        float(temporal_ctx.get("tactic_diversity", 0)),     # temporal_tactic_diversity
        float(temporal_ctx.get("mean_score", adjusted)),    # temporal_mean_score
    ]

    # Group 4: Similarity features (7) — real LanceDB distances
    sim = [
        float(similarity_ctx.get("attack_embed_dist", 1.0)),
        float(similarity_ctx.get("historical_dist", 1.0)),
        float(similarity_ctx.get("log_embed_matches", 0)),
        float(similarity_ctx.get("confirmed_neighbor_count", 0)),
        float(similarity_ctx.get("min_confirmed_dist", 1.0)),
        float(similarity_ctx.get("false_positive_count", 0)),
        float(similarity_ctx.get("label_confidence", 0.0)),
    ]

    # Group 5: MITRE features (2)
    # In live: zero_day rule (threshold=0) always matches +
    # model_disagreement (threshold=0.35) usually matches → 2 matches, 1 tactic
    hostname = row.get("hostname", "")
    is_attack_host = hostname in KNOWN_ATTACK_HOSTS
    eif = float(row.get("eif_score", "0"))

    # Replicate what MITRE mapper actually finds
    mitre_count = 2  # zero_day + model_disagreement for all high-score events
    mitre_breadth = 1  # initial-access only
    if eif > 0.7:
        mitre_count = 2  # eif_high triggers zero_day
    mitre = [float(mitre_count), float(mitre_breadth)]

    # Group 6: Campaign features (2) — no campaign data
    campaign = [0.0, 0.0]

    # Group 7: Sigma features (2) — no sigma hits in current setup
    sigma = [0.0, 0.0]

    # Group 8: SPC features (4) — insufficient baseline → all zeros
    spc = [0.0, 0.0, 0.0, 0.0]

    fv = triage + graph + temporal + sim + mitre + campaign + sigma + spc
    assert len(fv) == 42, f"Expected 42 features, got {len(fv)}"
    return fv


# ---------------------------------------------------------------------------
# Similarity context from LanceDB
# ---------------------------------------------------------------------------
def query_lancedb(hostname: str, desc: str) -> Dict[str, Any]:
    """Query LanceDB for similarity features."""
    import requests

    base = "http://localhost:8100"
    query_text = f"{hostname} {desc}"

    result = {
        "attack_embed_dist": 1.0,
        "historical_dist": 1.0,
        "log_embed_matches": 0,
        "confirmed_neighbor_count": 0,
        "min_confirmed_dist": 1.0,
        "false_positive_count": 0,
        "label_confidence": 0.0,
    }

    try:
        # Attack embeddings
        r = requests.post(f"{base}/tables/attack_embeddings/search",
                          json={"query_text": query_text, "limit": 10}, timeout=5)
        if r.ok:
            rows = r.json()
            if rows:
                dists = [float(row.get("_distance", 1.0)) for row in rows]
                result["attack_embed_dist"] = min(dists)
                result["confirmed_neighbor_count"] = sum(1 for d in dists if d < 0.3)
                result["min_confirmed_dist"] = min((d for d in dists if d < 0.3), default=1.0)
                close_any = [d for d in dists if d < 0.5]
                close_conf = [d for d in dists if d < 0.3]
                result["label_confidence"] = len(close_conf) / len(close_any) if close_any else 0.0

        # Historical incidents
        r = requests.post(f"{base}/tables/historical_incidents/search",
                          json={"query_text": query_text, "limit": 10}, timeout=5)
        if r.ok:
            rows = r.json()
            if rows:
                dists = [float(row.get("_distance", 1.0)) for row in rows]
                result["historical_dist"] = min(dists)

        # Log embeddings
        r = requests.post(f"{base}/tables/log_embeddings/search",
                          json={"query_text": query_text, "limit": 20}, timeout=5)
        if r.ok:
            rows = r.json()
            result["log_embed_matches"] = sum(
                1 for row in rows if float(row.get("_distance", 1.0)) < 0.4
            )

    except Exception as e:
        print(f"  LanceDB query failed for {hostname}: {e}")

    return result


# ---------------------------------------------------------------------------
# Augmentation — create systematic variations of real observations
# ---------------------------------------------------------------------------
def augment_row(fv: List[float], label: int, noise_level: float = 0.05) -> List[float]:
    """Create a noisy variation of a feature vector."""
    aug = []
    for i, v in enumerate(fv):
        if v == 0.0:
            # For zero values, small chance of adding tiny noise
            aug.append(random.uniform(0, noise_level) if random.random() < 0.3 else 0.0)
        elif 0.0 < v <= 1.0:
            # Scores: perturb within bounds
            noise = random.gauss(0, noise_level)
            aug.append(max(0.0, min(1.0, v + noise)))
        else:
            # Counts/larger values: perturb proportionally
            noise = random.gauss(0, noise_level * v)
            aug.append(max(0.0, v + noise))
    return aug


def generate_synthetic_benign(count: int) -> List[Tuple[List[float], int]]:
    """Generate synthetic benign (false positive) samples.
    These represent events that triage escalated (high score) but are NOT
    actual attacks — e.g., legitimate admin activity scored high.
    Key: similar triage scores to attacks BUT farther LanceDB distances
    and fewer temporal signals. Both first-time and repeat."""
    samples = []
    for i in range(count):
        # Benign events that reach hunter have adjusted_score >= 0.85
        adjusted = random.uniform(0.85, 0.92)
        combined = adjusted + random.uniform(-0.02, 0.02)
        combined = max(0.85, min(0.95, combined))

        # Some benign have temporal history too (recurring false positives)
        has_history = i % 3 == 0
        temporal_esc = random.randint(0, 1) if has_history else 0
        temporal_mean = random.uniform(0.5, 0.85) if has_history else adjusted

        fv = [
            adjusted, combined,
            1.0,   # entity_risk (always 1.0 in live)
            0.0,   # ioc_boost (always 0.0)
            0.0, 0.0, 0.0,  # temporal/dest/off_hours (N/A)
            0.0, 0.0,  # severity counts (N/A)
            0.0,  # distinct_categories (N/A)
            0.0,  # event_count (N/A)
            0.0,  # correlated_alert_count (N/A)
            random.uniform(0.85, 0.90),  # template_risk (~0.88)
            # Graph (8) — mostly zeros in live
            random.uniform(0, 2), random.uniform(0, 1), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            # Temporal (4)
            float(temporal_esc),
            random.uniform(0, 1),  # unique_categories
            0.0,  # tactic_diversity
            temporal_mean,
            # Similarity (7) — FAR from attack patterns (key discriminator)
            random.uniform(0.75, 1.3),  # attack_embed_dist (far)
            random.uniform(0.7, 1.2),   # historical_dist (far)
            0,  # log_embed_matches
            0,  # confirmed_neighbor_count
            1.0,  # min_confirmed_dist (far)
            0,
            0.0,  # label_confidence
            # MITRE (2) — zero_day + model_disagreement always match
            2.0, 1.0,
            # Campaign (2) — none
            0.0, 0.0,
            # Sigma (2) — no hits
            0.0, 0.0,
            # SPC (4) — no anomaly
            0.0, 0.0, 0.0, 0.0,
        ]
        samples.append((fv, 0))
    return samples


def generate_synthetic_attacks(count: int) -> List[Tuple[List[float], int]]:
    """Generate synthetic attack samples matching live fusion engine distribution.
    KEY INSIGHT: some attacks are first-time (zero temporal history), others
    are repeat offenders. The model must detect BOTH patterns.
    Primary discriminators: triage score + LanceDB distance + temporal signals."""
    samples = []
    for i in range(count):
        adjusted = random.uniform(0.87, 0.99)
        combined = adjusted + random.uniform(-0.02, 0.02)
        combined = max(0.85, min(0.99, combined))

        # 40% of attacks are first-time (zero temporal history)
        is_first_time = (i % 5) < 2

        if is_first_time:
            temporal_esc = 0
            temporal_mean = adjusted  # only this event
            temporal_cats = 0
            tactic_div = 0.0
        else:
            temporal_esc = random.randint(1, 5)
            temporal_mean = random.uniform(0.80, 0.95)
            temporal_cats = random.randint(1, 2)
            tactic_div = random.uniform(0.5, 1.5)

        # Similarity: attacks closer to known patterns (key discriminator)
        attack_dist = random.uniform(0.05, 0.65)
        hist_dist = random.uniform(0.1, 0.8)

        fv = [
            adjusted, combined,
            1.0, 0.0,  # entity_risk, ioc_boost
            0.0, 0.0, 0.0,  # N/A
            0.0, 0.0, 0.0, 0.0, 0.0,  # N/A
            random.uniform(0.85, 0.90),  # template_risk
            # Graph (8) — sparse
            random.uniform(0, 5), random.uniform(0, 2), 0.0,
            random.uniform(0, 2), 0.0, 0.0, 0.0, 0.0,
            # Temporal (4)
            float(temporal_esc),
            float(temporal_cats),
            tactic_div,
            temporal_mean,
            # Similarity (7) — closer to attack patterns
            attack_dist,
            hist_dist,
            random.randint(0, 3),
            random.randint(0, 2),
            random.uniform(0.1, 0.6),
            0,
            random.uniform(0.0, 0.5),
            # MITRE (2)
            2.0, 1.0,
            # Campaign (2)
            0.0, 0.0,
            # Sigma (2)
            0.0, 0.0,
            # SPC (4)
            0.0, 0.0, 0.0, 0.0,
        ]
        samples.append((fv, 1))
    return samples


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("HUNTER COLD-START BOOTSTRAP")
    print("Building training dataset from real triage data + augmentation")
    print("=" * 70)

    # Step 1: Fetch all triage data
    print("\n[1/7] Fetching triage_scores from ClickHouse...")
    raw = ch_query("""
        SELECT hostname, source_type, combined_score, adjusted_score,
               lgbm_score, eif_score, arf_score, action,
               ioc_match, ioc_confidence, template_rarity,
               mitre_tactic, mitre_technique
        FROM clif_logs.triage_scores
        ORDER BY timestamp
    """)
    triage_rows = parse_tsv(raw)
    print(f"  Found {len(triage_rows)} triage observations")

    if not triage_rows:
        print("ERROR: No triage data. Run test_triage_attacks.py first.")
        sys.exit(1)

    # Step 2: Build per-host context from network_events
    print("\n[2/7] Building network context...")
    net_raw = ch_query("""
        SELECT hostname, count() as cnt,
               countDistinct(dst_ip) as uniq_dst,
               countDistinct(src_ip) as uniq_src,
               countDistinct(dst_port) as uniq_ports
        FROM clif_logs.network_events
        GROUP BY hostname
    """)
    net_rows = parse_tsv(net_raw)
    net_ctx = {}
    for nr in net_rows:
        net_ctx[nr["hostname"]] = {
            "unique_destinations": int(nr.get("uniq_dst", "0")),
            "unique_src_ips": int(nr.get("uniq_src", "0")),
            "unique_ports": int(nr.get("uniq_ports", "0")),
            "has_ioc_neighbor": 0,
            "hop_count": min(int(nr.get("uniq_dst", "0")), 5),
            "high_risk_neighbors": 0,
            "escalation_count": 0,
            "lateral_movement_score": 0.0,
            "c2_candidate_score": 0.0,
            "campaign_host_count": 0,
            "campaign_tactic_count": 0,
        }
    print(f"  Network context for {len(net_ctx)} hosts")

    # Step 3: Build temporal context (per-host score history)
    print("\n[3/7] Building temporal context...")
    host_scores: Dict[str, List[float]] = {}
    host_actions: Dict[str, List[str]] = {}
    for row in triage_rows:
        h = row["hostname"]
        s = float(row.get("adjusted_score", "0"))
        a = row.get("action", "")
        host_scores.setdefault(h, []).append(s)
        host_actions.setdefault(h, []).append(a)

    temporal_ctxs = {}
    for h, scores in host_scores.items():
        esc_count = sum(1 for a in host_actions.get(h, []) if a == "escalate")
        temporal_ctxs[h] = {
            "escalation_count": esc_count,
            "unique_categories": 1,
            "tactic_diversity": 1 if h in KNOWN_ATTACK_HOSTS else 0,
            "mean_score": sum(scores) / len(scores),
            "all_scores": scores,
            "event_count": len(scores),
            "correlated_alert_count": max(0, esc_count - 1),
            "high_severity_count": sum(1 for s in scores if s >= 0.90),
            "medium_severity_count": sum(1 for s in scores if 0.80 <= s < 0.90),
            "distinct_categories": 1,
        }
    print(f"  Temporal context for {len(temporal_ctxs)} hosts")

    # Step 4: Query LanceDB for similarity features
    print("\n[4/7] Querying LanceDB for similarity features...")
    sim_ctxs = {}
    for h in set(r["hostname"] for r in triage_rows):
        desc = KNOWN_ATTACK_HOSTS.get(h, {}).get("desc", h)
        sim_ctxs[h] = query_lancedb(h, desc)
        dist = sim_ctxs[h]["attack_embed_dist"]
        neigh = sim_ctxs[h]["confirmed_neighbor_count"]
        print(f"  {h:22s} attack_dist={dist:.3f} neighbors={neigh} log_matches={sim_ctxs[h]['log_embed_matches']}")

    # Step 5: Build feature vectors + labels from real data
    print("\n[5/7] Building feature vectors from real observations...")
    training_data: List[Tuple[List[float], int, str, str]] = []  # (fv, label, hostname, finding_type)

    for row in triage_rows:
        h = row["hostname"]
        label = label_row(row)
        fv = build_feature_vector(
            row,
            network_ctx=net_ctx.get(h, {}),
            temporal_ctx=temporal_ctxs.get(h, {}),
            similarity_ctx=sim_ctxs.get(h, {}),
        )
        finding = "CONFIRMED_ATTACK" if label == 1 else "NORMAL_BEHAVIOUR"
        training_data.append((fv, label, h, finding))

    positives = sum(1 for _, l, _, _ in training_data if l == 1)
    negatives = sum(1 for _, l, _, _ in training_data if l == 0)
    print(f"  Real data: {len(training_data)} rows ({positives} attacks, {negatives} benign)")

    # Step 6: Augment to reach target size
    TARGET_SIZE = 500
    print(f"\n[6/7] Augmenting to {TARGET_SIZE} samples...")

    # First augment the real data (3-5x per real row)
    augmented = []
    for fv, label, h, finding in training_data:
        augment_count = 4
        for _ in range(augment_count):
            aug_fv = augment_row(fv, label, noise_level=0.04)
            augmented.append((aug_fv, label, h, finding))

    # Add real + augmented
    all_data = training_data + augmented

    # Generate synthetic samples to balance and fill
    current_pos = sum(1 for _, l, _, _ in all_data if l == 1)
    current_neg = sum(1 for _, l, _, _ in all_data if l == 0)
    remaining = max(0, TARGET_SIZE - len(all_data))

    if remaining > 0:
        # Try to maintain ~60% attack, 40% benign ratio
        target_pos = int(TARGET_SIZE * 0.6)
        target_neg = TARGET_SIZE - target_pos
        need_pos = max(0, target_pos - current_pos)
        need_neg = max(0, target_neg - current_neg)

        if need_pos > 0:
            synth_attacks = generate_synthetic_attacks(need_pos)
            for fv, l in synth_attacks:
                all_data.append((fv, l, "synthetic", "CONFIRMED_ATTACK"))

        if need_neg > 0:
            synth_benign = generate_synthetic_benign(need_neg)
            for fv, l in synth_benign:
                all_data.append((fv, l, "synthetic", "NORMAL_BEHAVIOUR"))

    # Shuffle
    random.shuffle(all_data)

    final_pos = sum(1 for _, l, _, _ in all_data if l == 1)
    final_neg = sum(1 for _, l, _, _ in all_data if l == 0)
    print(f"  Total: {len(all_data)} ({final_pos} attacks, {final_neg} benign)")
    print(f"  Ratio: {final_pos/len(all_data)*100:.0f}% attack / {final_neg/len(all_data)*100:.0f}% benign")

    # Step 7: Write to ClickHouse + Train CatBoost
    print(f"\n[7/7] Writing {len(all_data)} training rows to ClickHouse...")

    # Truncate existing
    ch_command("TRUNCATE TABLE IF EXISTS clif_logs.hunter_training_data")

    written = 0
    batch_size = 50
    for batch_start in range(0, len(all_data), batch_size):
        batch = all_data[batch_start : batch_start + batch_size]
        value_rows = []
        for fv, label, hostname, finding_type in batch:
            fv_json = json.dumps(fv)
            alert_id = str(uuid.uuid4())
            label_source = "bootstrap_positive" if label == 1 else "bootstrap_negative"
            value_rows.append(
                f"('{alert_id}', '{fv_json}', {label}, '{label_source}', "
                f"0.0, '{finding_type}', 0)"
            )
        values_str = ", ".join(value_rows)
        sql = (
            "INSERT INTO clif_logs.hunter_training_data "
            "(alert_id, feature_vector_json, label, label_source, "
            "hunter_score, finding_type, is_fast_path) VALUES " + values_str
        )
        if ch_command(sql):
            written += len(batch)
            print(f"  Batch {batch_start//batch_size + 1}: wrote {len(batch)} rows")
        else:
            print(f"  Batch {batch_start//batch_size + 1}: FAILED ({len(batch)} rows)")

    print(f"  Written: {written}/{len(all_data)}")

    # Verify
    count = ch_query("SELECT count() FROM clif_logs.hunter_training_data FORMAT TabSeparated")
    print(f"  Verified: {count} rows in hunter_training_data")

    # ─── Train CatBoost locally and copy into container ────────────────
    print("\n" + "=" * 70)
    print("TRAINING CATBOOST MODEL")
    print("=" * 70)

    try:
        import numpy as np
        from catboost import CatBoostClassifier, Pool
    except ImportError:
        print("ERROR: catboost or numpy not installed. Installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "catboost", "numpy"], check=True)
        import numpy as np
        from catboost import CatBoostClassifier, Pool

    X = np.array([fv for fv, _, _, _ in all_data], dtype=np.float32)
    y = np.array([l for _, l, _, _ in all_data], dtype=np.int32)

    print(f"  X shape: {X.shape}, y shape: {y.shape}")
    print(f"  y distribution: {sum(y==1)} attacks, {sum(y==0)} benign")

    model = CatBoostClassifier(
        iterations=500,
        learning_rate=0.05,
        depth=6,
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=42,
        verbose=100,
        class_weights=[1, 2],
        l2_leaf_reg=3,
        border_count=128,
    )

    train_pool = Pool(X, y)
    model.fit(train_pool)

    # Save locally
    model_path = os.path.join(os.path.dirname(__file__), "hunter_catboost.cbm")
    model.save_model(model_path)
    print(f"\n  Model saved to: {model_path}")

    # Quick evaluation
    proba = model.predict_proba(X)
    from sklearn.metrics import classification_report, roc_auc_score
    y_pred = (proba[:, 1] >= 0.5).astype(int)
    print(f"\n  Training AUC: {roc_auc_score(y, proba[:, 1]):.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y, y_pred, target_names=["BENIGN", "ATTACK"]))

    # Feature importances
    importances = model.get_feature_importance()
    FEATURE_NAMES = [
        "adjusted_score", "base_score", "entity_risk", "ioc_boost",
        "temporal_boost", "destination_risk", "off_hours_boost",
        "high_severity_count", "medium_severity_count", "distinct_categories",
        "event_count", "correlated_alert_count", "template_risk",
        "graph_unique_destinations", "graph_unique_src_ips", "graph_has_ioc_neighbor",
        "graph_hop_count", "graph_high_risk_neighbors", "graph_escalation_count",
        "graph_lateral_movement_score", "graph_c2_candidate_score",
        "temporal_escalation_count", "temporal_unique_categories",
        "temporal_tactic_diversity", "temporal_mean_score",
        "similarity_attack_embed_dist", "similarity_historical_dist",
        "similarity_log_embed_matches", "similarity_confirmed_neighbor_count",
        "similarity_min_confirmed_dist", "similarity_false_positive_count",
        "similarity_label_confidence",
        "mitre_match_count", "mitre_tactic_breadth",
        "campaign_host_count", "campaign_tactic_count",
        "sigma_hit_count", "sigma_max_severity",
        "spc_z_score", "spc_is_anomaly", "spc_baseline_mean", "spc_baseline_stddev",
    ]

    top_features = sorted(
        zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True
    )[:10]
    print("\n  Top 10 Feature Importances:")
    for fname, imp in top_features:
        print(f"    {fname:40s} {imp:6.2f}")

    # Copy model into hunter container
    print(f"\n  Copying model to hunter container...")
    subprocess.run(
        ["docker", "cp", model_path, "clif-hunter-agent:/app/models/hunter_catboost.cbm"],
        check=True,
    )
    print("  Model copied successfully!")

    # Restart hunter to pick up the model
    print("  Restarting hunter agent...")
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose-light.yml", "restart", "clif-hunter-agent"],
        check=True,
    )

    print("\n" + "=" * 70)
    print("BOOTSTRAP COMPLETE")
    print(f"  Training samples: {len(all_data)} ({final_pos} attack / {final_neg} benign)")
    print(f"  Model: hunter_catboost.cbm (copied to container)")
    print(f"  Hunter restarted — CatBoost will be loaded on next investigation")
    print("=" * 70)


if __name__ == "__main__":
    main()
