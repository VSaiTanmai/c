#!/usr/bin/env python3
"""
CLIF — Standalone Triage Scorer for Test Events
==================================================
Runs the full 3-model ensemble (LGBM + EIF + ARF) on the 190 test events
without going through the Kafka queue.

Designed to run INSIDE the clif-triage-agent container where models and
dependencies are already available:

    docker cp tests/score_test_events.py clif-triage-agent:/app/score_test_events.py
    docker exec clif-triage-agent python /app/score_test_events.py

Pipeline:
  1. Query test events from ClickHouse (security + process + raw)
  2. Extract 20 canonical features (FeatureExtractor + Drain3 + ConnectionTracker)
  3. Run 3-model ensemble inference (LGBM + EIF + ARF)
  4. Fuse scores with ScoreFusion (dynamic weighting, thresholds, routing)
  5. Write triage_scores rows to ClickHouse
  6. Print summary table
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import numpy as np

# ── Use the existing triage agent modules (same as prod) ────────────────
sys.path.insert(0, "/app")

import config
from drain3_miner import Drain3Miner
from feature_extractor import FEATURE_NAMES, ConnectionTracker, FeatureExtractor
from model_ensemble import ModelEnsemble
from score_fusion import IOCLookup, ScoreFusion

# Override config for standalone mode (no Kafka needed)
# Point CH to localhost since we run inside the container network
CH_HOST = config.CLICKHOUSE_HOST  # "clickhouse01"
CH_PORT = config.CLICKHOUSE_PORT  # 9000


def create_ch_client():
    """Create a ClickHouse client."""
    from clickhouse_driver import Client

    client = Client(
        host=CH_HOST,
        port=CH_PORT,
        user=config.CLICKHOUSE_USER,
        password=config.CLICKHOUSE_PASSWORD,
        database=config.CLICKHOUSE_DB,
    )
    # Verify connection
    result = client.execute("SELECT 1")
    assert result == [(1,)], f"ClickHouse connection check failed: {result}"
    return client


def fetch_test_events(ch_client) -> List[Dict[str, Any]]:
    """
    Fetch the 190 test events from ClickHouse across all tables.
    Test events have timestamp = 2026-03-04T22:30:00.000.
    """
    events = []
    ts_min = "2026-03-04T22:29:00"
    ts_max = "2026-03-04T22:31:00"

    # ── Security events (46) ────────────────────────────────────────────
    rows = ch_client.execute(
        f"SELECT event_id, timestamp, severity, category, source, description, "
        f"user_id, ip_address, hostname, mitre_tactic, mitre_technique, metadata "
        f"FROM clif_logs.security_events "
        f"WHERE timestamp >= '{ts_min}' AND timestamp <= '{ts_max}'"
    )
    for r in rows:
        events.append({
            "event_id": str(r[0]),
            "timestamp": r[1].isoformat() if hasattr(r[1], 'isoformat') else str(r[1]),
            "severity": r[2],
            "category": str(r[3]),
            "source_type": str(r[4]),
            "source": str(r[4]),
            "message_body": str(r[5]),
            "description": str(r[5]),
            "user_id": str(r[6]),
            "ip_address": str(r[7]),
            "src_ip": str(r[7]),
            "hostname": str(r[8]),
            "mitre_tactic": str(r[9]),
            "mitre_technique": str(r[10]),
            "metadata": dict(r[11]) if r[11] else {},
            "_source_table": "security-events",
        })

    # ── Process events (13) ─────────────────────────────────────────────
    proc_cols = ch_client.execute(
        "DESCRIBE clif_logs.process_events"
    )
    proc_col_names = [c[0] for c in proc_cols]

    rows = ch_client.execute(
        f"SELECT * FROM clif_logs.process_events "
        f"WHERE timestamp >= '{ts_min}' AND timestamp <= '{ts_max}'"
    )
    for r in rows:
        row_dict = {proc_col_names[i]: r[i] for i in range(len(proc_col_names))}
        events.append({
            "event_id": str(row_dict.get("event_id", "")),
            "timestamp": row_dict["timestamp"].isoformat()
                if hasattr(row_dict.get("timestamp"), 'isoformat')
                else str(row_dict.get("timestamp", "")),
            "severity": row_dict.get("severity", 0),
            "category": str(row_dict.get("category", "process")),
            "source_type": str(row_dict.get("source", "")),
            "source": str(row_dict.get("source", "")),
            "message_body": str(row_dict.get("command_line",
                            row_dict.get("description", ""))),
            "description": str(row_dict.get("description", "")),
            "user_id": str(row_dict.get("user_id", "")),
            "hostname": str(row_dict.get("hostname", "")),
            "src_ip": str(row_dict.get("ip_address", "0.0.0.0")),
            "ip_address": str(row_dict.get("ip_address", "0.0.0.0")),
            "metadata": dict(row_dict.get("metadata", {}))
                if row_dict.get("metadata") else {},
            "_source_table": "process-events",
        })

    # ── Raw logs (131) ──────────────────────────────────────────────────
    rows = ch_client.execute(
        f"SELECT event_id, timestamp, level, source, message, user_id, "
        f"ip_address, metadata "
        f"FROM clif_logs.raw_logs "
        f"WHERE timestamp >= '{ts_min}' AND timestamp <= '{ts_max}'"
    )
    for r in rows:
        events.append({
            "event_id": str(r[0]),
            "timestamp": r[1].isoformat() if hasattr(r[1], 'isoformat') else str(r[1]),
            "severity": 0,  # raw logs don't have severity
            "level": str(r[2]),
            "category": "raw",
            "source_type": str(r[3]),
            "source": str(r[3]),
            "message_body": str(r[4]),
            "message": str(r[4]),
            "user_id": str(r[5]),
            "ip_address": str(r[6]),
            "src_ip": str(r[6]),
            "hostname": "",
            "metadata": dict(r[7]) if r[7] else {},
            "_source_table": "raw-logs",
        })

    return events


def determine_topic(event: Dict[str, Any]) -> str:
    """Map event source table to Kafka topic name (for feature extraction)."""
    tbl = event.get("_source_table", "raw-logs")
    topic_map = {
        "security-events": "security-events",
        "process-events": "process-events",
        "network-events": "network-events",
        "raw-logs": "raw-logs",
    }
    return topic_map.get(tbl, "raw-logs")


def write_triage_scores(ch_client, results, features_list):
    """Write TriageResult list to triage_scores table."""
    if not results:
        return 0

    cols = [
        "event_id", "timestamp", "source_type", "hostname", "source_ip",
        "user_id", "template_id", "template_rarity", "combined_score",
        "lgbm_score", "eif_score", "arf_score", "score_std_dev", "agreement",
        "ci_lower", "ci_upper", "asset_multiplier", "adjusted_score",
        "action", "ioc_match", "ioc_confidence", "mitre_tactic",
        "mitre_technique", "features_stale", "model_version",
        "disagreement_flag",
    ]

    rows = []
    for r in results:
        # Parse event_id as UUID
        try:
            eid = uuid.UUID(r.event_id) if r.event_id else uuid.uuid4()
        except (ValueError, AttributeError):
            eid = uuid.uuid4()

        # Parse timestamp
        try:
            ts = datetime.fromisoformat(
                r.timestamp.replace("Z", "+00:00")
            )
        except Exception:
            ts = datetime.now(timezone.utc)

        rows.append([
            eid,
            ts,
            r.source_type,
            r.hostname,
            r.source_ip,
            r.user_id,
            r.template_id,
            r.template_rarity,
            r.combined_score,
            r.lgbm_score,
            r.eif_score,
            r.arf_score,
            r.score_std_dev,
            r.agreement,
            r.ci_lower,
            r.ci_upper,
            r.asset_multiplier,
            r.adjusted_score,
            r.action,
            r.ioc_match,
            r.ioc_confidence,
            r.mitre_tactic,
            r.mitre_technique,
            r.features_stale,
            r.model_version,
            r.disagreement_flag,
        ])

    col_str = ", ".join(cols)
    ch_client.execute(
        f"INSERT INTO clif_logs.triage_scores ({col_str}) VALUES",
        rows,
    )
    return len(rows)


def main():
    print("=" * 70)
    print("CLIF Standalone Triage Scorer — 190 Test Events")
    print("=" * 70)

    # ── 1. Connect to ClickHouse ────────────────────────────────────────
    print("\n[1/6] Connecting to ClickHouse...")
    ch_client = create_ch_client()
    print(f"  Connected: {CH_HOST}:{CH_PORT}/{config.CLICKHOUSE_DB}")

    # ── 2. Fetch test events ────────────────────────────────────────────
    print("\n[2/6] Fetching test events from ClickHouse...")
    events = fetch_test_events(ch_client)
    print(f"  Fetched {len(events)} events:")
    source_counts = {}
    for e in events:
        tbl = e.get("_source_table", "unknown")
        source_counts[tbl] = source_counts.get(tbl, 0) + 1
    for tbl, cnt in sorted(source_counts.items()):
        print(f"    {tbl}: {cnt}")

    if not events:
        print("ERROR: No test events found! Exiting.")
        sys.exit(1)

    # ── 3. Initialize scoring pipeline ──────────────────────────────────
    print("\n[3/6] Initializing scoring pipeline...")
    t0 = time.monotonic()

    # Drain3 (fresh — no persisted state for standalone)
    drain3 = Drain3Miner(
        state_path="/tmp/drain3_standalone.bin",
        config_path=config.DRAIN3_CONFIG_PATH,
    )
    print(f"  Drain3 miner: {drain3.template_count} templates")

    # Connection tracker
    conn_tracker = ConnectionTracker(
        time_window_sec=config.CONN_TIME_WINDOW_SEC,
        host_window_size=config.CONN_HOST_WINDOW_SIZE,
        cleanup_interval_sec=config.CONN_CLEANUP_INTERVAL_SEC,
    )

    # Score fusion (creates IOCLookup, AllowlistChecker, etc.)
    manifest_version = ""
    try:
        with open(config.MANIFEST_PATH) as f:
            manifest = json.load(f)
            manifest_version = manifest.get("version", "v2.0.0")
    except Exception:
        manifest_version = "v2.0.0"

    fusion = ScoreFusion(
        ch_client=ch_client,
        weights=config.SCORE_WEIGHTS,
        model_version=manifest_version,
    )

    # IOC lookup function for feature extractor
    ioc_fn = fusion.ioc_lookup.check if fusion.ioc_lookup else None

    # Feature extractor
    extractor = FeatureExtractor(
        drain3_miner=drain3,
        ioc_lookup_fn=ioc_fn,
        conn_tracker=conn_tracker,
    )

    # Model ensemble (loads LGBM ONNX + EIF + ARF warm restart)
    ensemble = ModelEnsemble()
    ensemble.load(ch_client=ch_client)

    t_init = time.monotonic() - t0
    print(f"  Pipeline initialized in {t_init:.2f}s")
    print(f"  LGBM: loaded")
    print(f"  EIF:  loaded (calibrated={ensemble._eif.is_calibrated})")
    print(f"  ARF:  loaded (rows_replayed={ensemble.arf.rows_replayed}, "
          f"confidence={ensemble.arf.confidence:.3f})")
    print(f"  Weights: {config.SCORE_WEIGHTS}")
    print(f"  Thresholds: suspicious={config.DEFAULT_SUSPICIOUS_THRESHOLD}, "
          f"anomalous={config.DEFAULT_ANOMALOUS_THRESHOLD}")

    # ── 4. Feature extraction ───────────────────────────────────────────
    print("\n[4/6] Extracting features...")
    t0 = time.monotonic()

    features_list = []
    for event in events:
        topic = determine_topic(event)
        feat = extractor.extract(event, topic)
        features_list.append(feat)

    X = extractor.batch_to_numpy(features_list)
    t_feat = time.monotonic() - t0
    print(f"  Extracted {X.shape[0]} × {X.shape[1]} feature matrix in {t_feat:.3f}s")

    # ── 5. Model inference + score fusion ───────────────────────────────
    print("\n[5/6] Running ensemble inference...")
    t0 = time.monotonic()

    model_scores = ensemble.predict_batch(X)
    results = fusion.fuse_batch(model_scores, features_list, events)

    t_infer = time.monotonic() - t0
    print(f"  Inference + fusion in {t_infer:.3f}s ({len(results)} results)")

    # ── Action distribution ──────────────────────────────────────────────
    action_dist = {}
    for r in results:
        action_dist[r.action] = action_dist.get(r.action, 0) + 1
    print(f"\n  Action distribution:")
    for action, cnt in sorted(action_dist.items()):
        print(f"    {action}: {cnt}")

    # ── Score statistics per source table ────────────────────────────────
    print(f"\n  Score statistics by source table:")
    table_scores = {}
    for r, e in zip(results, events):
        tbl = e.get("_source_table", "unknown")
        if tbl not in table_scores:
            table_scores[tbl] = {"combined": [], "lgbm": [], "eif": [], "arf": [], "actions": []}
        table_scores[tbl]["combined"].append(r.combined_score)
        table_scores[tbl]["lgbm"].append(r.lgbm_score)
        table_scores[tbl]["eif"].append(r.eif_score)
        table_scores[tbl]["arf"].append(r.arf_score)
        table_scores[tbl]["actions"].append(r.action)

    for tbl in sorted(table_scores.keys()):
        s = table_scores[tbl]
        n = len(s["combined"])
        esc = sum(1 for a in s["actions"] if a == "escalate")
        mon = sum(1 for a in s["actions"] if a == "monitor")
        dis = sum(1 for a in s["actions"] if a == "discard")
        print(f"\n    {tbl} ({n} events):")
        print(f"      combined: mean={np.mean(s['combined']):.4f}, "
              f"min={np.min(s['combined']):.4f}, max={np.max(s['combined']):.4f}")
        print(f"      lgbm:     mean={np.mean(s['lgbm']):.4f}, "
              f"min={np.min(s['lgbm']):.4f}, max={np.max(s['lgbm']):.4f}")
        print(f"      eif:      mean={np.mean(s['eif']):.4f}, "
              f"min={np.min(s['eif']):.4f}, max={np.max(s['eif']):.4f}")
        print(f"      arf:      mean={np.mean(s['arf']):.4f}, "
              f"min={np.min(s['arf']):.4f}, max={np.max(s['arf']):.4f}")
        print(f"      actions:  escalate={esc}, monitor={mon}, discard={dis}")

    # ── 6. Write to ClickHouse ──────────────────────────────────────────
    print("\n[6/6] Writing triage scores to ClickHouse...")
    written = write_triage_scores(ch_client, results, features_list)
    print(f"  Wrote {written} rows to clif_logs.triage_scores")

    # ── Summary: Top escalations ────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TOP ESCALATIONS (adjusted_score descending)")
    print("=" * 70)
    escalated = [(r, e) for r, e in zip(results, events) if r.action == "escalate"]
    escalated.sort(key=lambda x: x[0].adjusted_score, reverse=True)

    for r, e in escalated[:30]:
        msg = (e.get("message_body") or e.get("message") or e.get("description") or "")[:80]
        print(f"  [{r.adjusted_score:.4f}] lgbm={r.lgbm_score:.3f} eif={r.eif_score:.3f} "
              f"arf={r.arf_score:.3f} | {r.source_type} | {msg}")

    # ── Summary: Top monitor ────────────────────────────────────────────
    print(f"\nTOP MONITOR (adjusted_score descending)")
    print("-" * 70)
    monitored = [(r, e) for r, e in zip(results, events) if r.action == "monitor"]
    monitored.sort(key=lambda x: x[0].adjusted_score, reverse=True)

    for r, e in monitored[:20]:
        msg = (e.get("message_body") or e.get("message") or e.get("description") or "")[:80]
        print(f"  [{r.adjusted_score:.4f}] lgbm={r.lgbm_score:.3f} eif={r.eif_score:.3f} "
              f"arf={r.arf_score:.3f} | {r.source_type} | {msg}")

    # ── Full results dump ───────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"ALL {len(results)} RESULTS (sorted by adjusted_score desc)")
    print(f"{'=' * 70}")

    all_sorted = list(zip(results, events))
    all_sorted.sort(key=lambda x: x[0].adjusted_score, reverse=True)

    for i, (r, e) in enumerate(all_sorted):
        msg = (e.get("message_body") or e.get("message") or e.get("description") or "")[:60]
        tbl = e.get("_source_table", "?")
        print(f"  {i+1:3d}. [{r.action:8s}] adj={r.adjusted_score:.4f} "
              f"comb={r.combined_score:.4f} lgbm={r.lgbm_score:.3f} "
              f"eif={r.eif_score:.3f} arf={r.arf_score:.3f} "
              f"std={r.score_std_dev:.3f} | {tbl:16s} | {msg}")

    print(f"\n{'=' * 70}")
    print(f"DONE — {len(results)} events scored, {written} rows written to CH")
    print(f"Total time: init={t_init:.2f}s, features={t_feat:.3f}s, inference={t_infer:.3f}s")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
