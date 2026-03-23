#!/usr/bin/env python3
"""
CLIF Triage Ground-Truth Validation v2
========================================
Bypasses Vector entirely — produces LABELED events directly to Kafka topics
via rpk, exactly matching the post-Vector schema that triage expects.

Then queries ClickHouse to compute actual precision/recall.

Usage:
  python scripts/validate_groundtruth_v2.py [--per-class 200]
"""

import argparse
import csv
import json
import os
import random
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

# ── Dataset paths ────────────────────────────────────────────────────────────
BASE = Path(r"C:\CLIF\agents\Data\datasets")
MARKER = f"gt2-{int(time.time())}"


def load_nsl_kdd(max_per_class):
    """Load NSL-KDD: balanced benign + attack."""
    path = BASE / "10_ids_ips_zeek" / "path_a_lightgbm" / "NSL-KDD" / "nsl_kdd_stratified.csv"
    benign, attack = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            label = row.get("label", "normal")
            is_atk = label not in ("normal", "0")
            if is_atk and len(attack) < max_per_class * 3:
                attack.append(row)
            elif not is_atk and len(benign) < max_per_class * 3:
                benign.append(row)
            if len(benign) >= max_per_class * 3 and len(attack) >= max_per_class * 3:
                break
    random.shuffle(benign)
    random.shuffle(attack)
    return benign[:max_per_class], attack[:max_per_class]


def load_unsw(max_per_class):
    """Load UNSW-NB15: balanced benign + attack."""
    path = BASE / "03_firewall_cef" / "path_a_lightgbm" / "UNSW-NB15" / "unsw_stratified.csv"
    benign, attack = [], []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            is_atk = str(row.get("label", "0")) == "1"
            if is_atk and len(attack) < max_per_class * 3:
                attack.append(row)
            elif not is_atk and len(benign) < max_per_class * 3:
                benign.append(row)
            if len(benign) >= max_per_class * 3 and len(attack) >= max_per_class * 3:
                break
    random.shuffle(benign)
    random.shuffle(attack)
    return benign[:max_per_class], attack[:max_per_class]


def nsl_kdd_to_event(row, is_attack):
    """Convert NSL-KDD row to post-Vector security-event schema."""
    proto = row.get("protocol_type", "tcp").upper()
    service = row.get("service", "other")
    flag = row.get("flag", "SF")
    src_bytes = row.get("src_bytes", "0")
    dst_bytes = row.get("dst_bytes", "0")
    label = row.get("label", "normal")
    attack_type = row.get("attack_type", "normal")
    src_ip = f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = f"10.10.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_port = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "dns": 53,
                "telnet": 23}.get(service, random.randint(1, 1024))

    if is_attack:
        desc = (f"IDS alert: {attack_type} ({label}) detected - "
                f"proto={proto} service={service} flag={flag} "
                f"src_bytes={src_bytes} dst_bytes={dst_bytes} "
                f"src={src_ip} dst={dst_ip}:{dst_port}")
    else:
        desc = (f"IDS: normal traffic - proto={proto} service={service} "
                f"flag={flag} duration={row.get('duration','0')}s "
                f"src_bytes={src_bytes} dst_bytes={dst_bytes} "
                f"src={src_ip} dst={dst_ip}:{dst_port}")

    return {
        "event_id": str(uuid4()),
        "clif_event_type": "security",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": 3 if is_attack else 1,
        "category": "ids" if is_attack else "network",
        "source": "ids-01",
        "description": desc,
        "user_id": "",
        "ip_address": src_ip,
        "hostname": MARKER,
        "mitre_tactic": "initial-access" if is_attack else "",
        "mitre_technique": "T1190" if is_attack else "",
        "ai_confidence": 0.0,
        "ai_explanation": "",
        "message_body": desc,
        "source_type": "ids_ips",
        "original_log_level": 3 if is_attack else 0,
        "metadata": {},
    }


def unsw_to_event(row, is_attack):
    """Convert UNSW-NB15 row to post-Vector security-event schema."""
    src_ip = row.get("srcip", "0.0.0.0")
    dst_ip = row.get("dstip", "0.0.0.0")
    sport = row.get("sport", "0")
    dsport = row.get("dsport", "0")
    proto = row.get("proto", "tcp").upper()
    service = row.get("service", "-")
    state = row.get("state", "")
    attack_cat = row.get("attack_cat", "Normal").strip()
    sbytes = row.get("sbytes", "0")
    dbytes = row.get("dbytes", "0")

    if is_attack:
        desc = (f"Firewall alert: {attack_cat} - {src_ip}:{sport} → {dst_ip}:{dsport} "
                f"proto={proto} service={service} state={state} "
                f"bytes_sent={sbytes} bytes_recv={dbytes}")
    else:
        desc = (f"Firewall: connection {src_ip}:{sport} → {dst_ip}:{dsport} "
                f"proto={proto} service={service} state={state} "
                f"bytes_sent={sbytes} bytes_recv={dbytes}")

    return {
        "event_id": str(uuid4()),
        "clif_event_type": "security",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": 3 if is_attack else 1,
        "category": "firewall" if is_attack else "network",
        "source": "fw-01",
        "description": desc,
        "user_id": "",
        "ip_address": src_ip,
        "hostname": MARKER,
        "mitre_tactic": "lateral-movement" if is_attack else "",
        "mitre_technique": "T1021" if is_attack else "",
        "ai_confidence": 0.0,
        "ai_explanation": "",
        "message_body": desc,
        "source_type": "firewall",
        "original_log_level": 3 if is_attack else 0,
        "metadata": {},
    }


def produce_to_kafka(topic, events):
    """Produce events to Kafka topic via rpk one at a time."""
    for ev in events:
        payload = json.dumps(ev, separators=(",", ":"))
        cmd = [
            "docker", "exec", "-i", "clif-redpanda01",
            "rpk", "topic", "produce", topic, "--format", "%v\n",
        ]
        proc = subprocess.run(
            cmd, input=payload + "\n", capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            print(f"  rpk error: {proc.stderr[:100]}")
            return False
    return True


def produce_batch_to_kafka(topic, events, batch_size=50):
    """Produce events to Kafka in batches using rpk stdin."""
    for i in range(0, len(events), batch_size):
        chunk = events[i:i+batch_size]
        payload = "\n".join(json.dumps(ev, separators=(",", ":")) for ev in chunk) + "\n"
        cmd = [
            "docker", "exec", "-i", "clif-redpanda01",
            "rpk", "topic", "produce", topic,
        ]
        proc = subprocess.run(
            cmd, input=payload, capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            print(f"  rpk error at batch {i}: {proc.stderr[:200]}")
    return True


def query_ch(sql):
    """Query ClickHouse via HTTP."""
    req = urllib.request.Request(
        "http://localhost:8123/",
        data=sql.encode("utf-8"),
        headers={
            "X-ClickHouse-User": "clif_admin",
            "X-ClickHouse-Key": "Cl1f_Ch@ngeM3_2026!",
        },
    )
    resp = urllib.request.urlopen(req, timeout=30)
    return resp.read().decode().strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-class", type=int, default=200)
    args = parser.parse_args()
    pc = args.per_class

    print("=" * 65)
    print("  CLIF Triage Ground-Truth Validation (Direct Kafka)")
    print("=" * 65)
    print(f"  Marker: {MARKER}")
    print(f"  Events per class per dataset: {pc}")
    print()

    # ── Load balanced data ──────────────────────────────────────────────
    nsl_b, nsl_a = load_nsl_kdd(pc)
    unsw_b, unsw_a = load_unsw(pc)
    print(f"  NSL-KDD:  {len(nsl_b)} benign + {len(nsl_a)} attack")
    print(f"  UNSW:     {len(unsw_b)} benign + {len(unsw_a)} attack")

    # Convert to events
    events_benign = []
    events_attack = []

    for row in nsl_b:
        events_benign.append(nsl_kdd_to_event(row, False))
    for row in nsl_a:
        events_attack.append(nsl_kdd_to_event(row, True))
    for row in unsw_b:
        events_benign.append(unsw_to_event(row, False))
    for row in unsw_a:
        events_attack.append(unsw_to_event(row, True))

    # Track ground truth by event_id
    gt = {}
    for ev in events_benign:
        gt[ev["event_id"]] = "benign"
    for ev in events_attack:
        gt[ev["event_id"]] = "attack"

    all_events = events_benign + events_attack
    random.shuffle(all_events)

    total = len(all_events)
    n_benign = len(events_benign)
    n_attack = len(events_attack)
    print(f"\n  Total: {total} events ({n_benign} benign, {n_attack} attack)")
    print(f"  Attack ratio: {n_attack/total*100:.1f}%")

    # ── Produce directly to security-events topic ───────────────────────
    print(f"\n  Producing {total} events to security-events via rpk...")
    ok = produce_batch_to_kafka("security-events", all_events)
    if ok:
        print(f"  ✔ All events produced!")
    else:
        print(f"  ⚠ Some errors during produce")

    # ── Wait for triage scoring ─────────────────────────────────────────
    print(f"\n  Waiting for triage to score events...")
    print(f"  (Looking for hostname='{MARKER}' in triage_scores)")

    start_wait = time.time()
    scored_n = 0
    while time.time() - start_wait < 300:
        try:
            n = int(query_ch(
                f"SELECT count() FROM clif_logs.triage_scores "
                f"WHERE hostname='{MARKER}'"
            ))
        except:
            n = 0

        elapsed = int(time.time() - start_wait)
        pct = n / total * 100
        print(f"  [{elapsed:3d}s] {n}/{total} scored ({pct:.0f}%)")
        scored_n = n

        if n >= total * 0.85:
            print(f"  ✔ Sufficient coverage ({n}/{total})")
            break
        time.sleep(10)

    # Extra wait for ClickHouse flush
    if scored_n < total * 0.85:
        print(f"  ⚠ Only {scored_n}/{total} scored after 5 min")
        print(f"  Waiting 30s more for ClickHouse flush...")
        time.sleep(30)
        try:
            scored_n = int(query_ch(
                f"SELECT count() FROM clif_logs.triage_scores "
                f"WHERE hostname='{MARKER}'"
            ))
        except:
            pass

    # ── Fetch results & compute metrics ─────────────────────────────────
    print(f"\n  Fetching scored results from ClickHouse...")
    body = query_ch(f"""
        SELECT event_id, source_type, lgbm_score, combined_score,
               toString(action) AS action, model_version,
               mitre_tactic, mitre_technique, source_ip
        FROM clif_logs.triage_scores
        WHERE hostname='{MARKER}'
        FORMAT JSONEachRow
    """)

    scored = []
    for line in body.split("\n"):
        line = line.strip()
        if line:
            scored.append(json.loads(line))

    print(f"  Retrieved {len(scored)} scored events")

    # ── Match to ground truth via MITRE tactic ──────────────────────────
    # Attack events have non-empty mitre_tactic; benign events have empty.
    # (deterministic_event_id overwrites our original event_id, so we
    #  cannot match by event_id — use MITRE tactic as ground-truth proxy.)
    tp = fp = tn = fn = 0
    details = {"benign": {"discard": 0, "monitor": 0, "escalate": 0, "scores": []},
               "attack": {"discard": 0, "monitor": 0, "escalate": 0, "scores": []}}

    for s in scored:
        mitre = s.get("mitre_tactic", "")
        truth = "attack" if mitre else "benign"
        action = s["action"]
        lgbm = float(s["lgbm_score"])

        details[truth][action] += 1
        details[truth]["scores"].append(lgbm)

        # For metrics: "flagged" = monitor or escalate; "benign" = discard
        flagged = action in ("monitor", "escalate")
        if truth == "attack" and flagged:
            tp += 1
        elif truth == "attack" and not flagged:
            fn += 1
        elif truth == "benign" and flagged:
            fp += 1
        elif truth == "benign" and not flagged:
            tn += 1

    matched = tp + fp + tn + fn

    print(f"\n" + "=" * 65)
    print(f"  GROUND-TRUTH RESULTS (50% benign / 50% attack)")
    print(f"=" * 65)
    print(f"  Events matched to ground truth: {matched}")
    print()

    # Confusion matrix
    print(f"  CONFUSION MATRIX (flagged = monitor+escalate):")
    print(f"                    Predicted")
    print(f"                    Benign    Flagged")
    print(f"  Actual Benign:    {tn:5d}     {fp:5d}   (FPR={fp/(fp+tn)*100:.1f}%)" if (fp+tn) else f"  Actual Benign:    {tn:5d}     {fp:5d}")
    print(f"  Actual Attack:    {fn:5d}     {tp:5d}   (TPR={tp/(tp+fn)*100:.1f}%)" if (tp+fn) else f"  Actual Attack:    {fn:5d}     {tp:5d}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy = (tp + tn) / matched if matched > 0 else 0

    print(f"\n  METRICS:")
    print(f"    Accuracy:  {accuracy*100:.1f}%")
    print(f"    Precision: {precision*100:.1f}%")
    print(f"    Recall:    {recall*100:.1f}%")
    print(f"    F1 Score:  {f1*100:.1f}%")
    print(f"    FPR:       {fp/(fp+tn)*100:.1f}%" if (fp+tn) else "    FPR:       N/A")

    # Detailed class breakdown
    print(f"\n  BENIGN EVENTS ({n_benign} sent, {sum(details['benign'][k] for k in ('discard','monitor','escalate'))} scored):")
    for act in ("discard", "monitor", "escalate"):
        n = details["benign"][act]
        pct = n / n_benign * 100 if n_benign else 0
        print(f"    {act:10s}: {n:5d} ({pct:5.1f}%)")
    if details['benign']['scores']:
        sc = details['benign']['scores']
        print(f"    LGBM score: min={min(sc):.4f}, avg={sum(sc)/len(sc):.4f}, max={max(sc):.4f}")

    print(f"\n  ATTACK EVENTS ({n_attack} sent, {sum(details['attack'][k] for k in ('discard','monitor','escalate'))} scored):")
    for act in ("discard", "monitor", "escalate"):
        n = details["attack"][act]
        pct = n / n_attack * 100 if n_attack else 0
        print(f"    {act:10s}: {n:5d} ({pct:5.1f}%)")
    if details['attack']['scores']:
        sc = details['attack']['scores']
        print(f"    LGBM score: min={min(sc):.4f}, avg={sum(sc)/len(sc):.4f}, max={max(sc):.4f}")

    # Score histogram
    print(f"\n  LGBM Score Histogram (all scored):")
    all_sc = [float(s["lgbm_score"]) for s in scored]
    bins = [(0, 0.1), (0.1, 0.2), (0.2, 0.3), (0.3, 0.4), (0.4, 0.5),
            (0.5, 0.6), (0.6, 0.7), (0.7, 0.8), (0.8, 0.9), (0.9, 1.01)]
    for lo, hi in bins:
        n = sum(1 for s in all_sc if lo <= s < hi)
        bar = "█" * int(n / max(1, len(all_sc)) * 50)
        print(f"    [{lo:.1f}-{hi-.01:.2f}] {n:5d} {bar}")

    print(f"\n  THRESHOLDS: suspicious=0.39, anomalous=0.89")

    # Comparison to v3 behavior
    print(f"\n  COMPARISON TO v3 (last 'working' version):")
    print(f"    v3 thresholds: suspicious=0.39, anomalous=0.89")
    print(f"    v3 overall: 11.5% benign, 40.3% suspicious, 48.2% anomalous")
    print(f"    v3 was running on the SAME attack-enriched data mix")
    esc_pct = (details['attack']['escalate'] + details['benign']['escalate']) / matched * 100 if matched else 0
    dis_pct = (details['attack']['discard'] + details['benign']['discard']) / matched * 100 if matched else 0
    print(f"    v6 now: {dis_pct:.1f}% benign, {100-dis_pct-esc_pct:.1f}% suspicious, {esc_pct:.1f}% anomalous")

    print("\n" + "=" * 65)


if __name__ == "__main__":
    main()
