#!/usr/bin/env python3
"""Inject a pre-scored triage event with SHAP data into triage-scores topic
to verify the Go consumer stores SHAP fields in ClickHouse."""
import json, subprocess, datetime, uuid

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
event_id = str(uuid.uuid4())

triage_msg = {
    "score_id": str(uuid.uuid4()),
    "event_id": event_id,
    "timestamp": ts,
    "source_type": "test",
    "hostname": "SHAP-E2E-TEST",
    "source_ip": "10.88.88.88",
    "user_id": "shap_test",
    "template_id": "tmpl_test_001",
    "template_rarity": 0.99,
    "combined_score": 0.97,
    "lgbm_score": 0.995,
    "eif_score": 0.88,
    "arf_score": 0.92,
    "score_std_dev": 0.05,
    "agreement": 0.91,
    "ci_lower": 0.95,
    "ci_upper": 0.99,
    "asset_multiplier": 1.0,
    "adjusted_score": 0.97,
    "action": "escalate",
    "ioc_match": 0,
    "ioc_confidence": 0,
    "mitre_tactic": "",
    "mitre_technique": "",
    "shap_top_features": json.dumps([
        {"feature": "serror_rate", "delta": 0.482, "value": 1.0},
        {"feature": "count", "delta": 0.341, "value": 511},
        {"feature": "dst_host_srv_count", "delta": 0.228, "value": 255},
        {"feature": "dst_host_serror_rate", "delta": 0.195, "value": 1.0},
        {"feature": "srv_count", "delta": 0.167, "value": 511}
    ]),
    "shap_summary": "Score 0.97 driven by: SYN Error Rate=1.00 (+0.482), Connection Count=511 (+0.341), Dest Host Srv Count=255 (+0.228)",
    "features_stale": 0,
    "model_version": "v6.0.0",
    "disagreement_flag": 0,
}

input_data = json.dumps(triage_msg) + "\n"
result = subprocess.run(
    ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", "triage-scores", "--key", event_id],
    input=input_data.encode(), capture_output=True, timeout=15
)
print(f"Injected SHAP triage score at {ts}")
print(f"event_id: {event_id}")
print(f"stdout: {result.stdout.decode().strip()}")
if result.returncode != 0:
    print(f"stderr: {result.stderr.decode().strip()}")
