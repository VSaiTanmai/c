#!/usr/bin/env python3
"""Inject a hunter task to test Hunter -> Verifier -> ClickHouse pipeline."""
import json, subprocess, datetime, uuid

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
alert_id = str(uuid.uuid4())

hunter_task = {
    "alert_id": alert_id,
    "event_id": str(uuid.uuid4()),
    "timestamp": ts,
    "source_type": "netflow",
    "hostname": "HUNTER-E2E-TEST",
    "source_ip": "10.77.77.77",
    "user_id": "e2e_test",
    "combined_score": 0.97,
    "lgbm_score": 0.995,
    "eif_score": 0.88,
    "arf_score": 0.92,
    "template_id": "tmpl_e2e_test",
    "shap_top_features": json.dumps([
        {"feature": "serror_rate", "delta": 0.482, "value": 1.0},
        {"feature": "count", "delta": 0.341, "value": 511},
    ]),
    "shap_summary": "E2E test: SYN Error Rate=1.00 (+0.482), Count=511 (+0.341)",
}

input_data = json.dumps(hunter_task) + "\n"
result = subprocess.run(
    ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", "hunter-tasks", "--key", alert_id],
    input=input_data.encode(), capture_output=True, timeout=15
)
print(f"Injected hunter task at {ts}")
print(f"alert_id: {alert_id}")
print(f"stdout: {result.stdout.decode().strip()}")
