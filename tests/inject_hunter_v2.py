#!/usr/bin/env python3
"""Inject hunter task with no compression."""
import json, subprocess, datetime, uuid

ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
alert_id = str(uuid.uuid4())

task = {
    "alert_id": alert_id,
    "event_id": str(uuid.uuid4()),
    "timestamp": ts,
    "source_type": "netflow",
    "hostname": "HUNTER-E2E-TEST-V2",
    "source_ip": "10.77.77.77",
    "user_id": "e2e_test",
    "combined_score": 0.97,
    "lgbm_score": 0.995,
    "eif_score": 0.88,
    "arf_score": 0.92,
    "template_id": "tmpl_e2e",
    "shap_top_features": json.dumps([{"feature": "serror_rate", "delta": 0.48}]),
    "shap_summary": "E2E test: SYN Error Rate=1.00 (+0.482)",
}

input_data = json.dumps(task) + "\n"
result = subprocess.run(
    ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce",
     "hunter-tasks", "--key", alert_id, "-z", "none"],
    input=input_data.encode(), capture_output=True, timeout=15
)
print(f"Injected hunter task at {ts}")
print(f"alert_id: {alert_id}")
print(f"stdout: {result.stdout.decode().strip()}")
if result.returncode != 0:
    print(f"ERROR: {result.stderr.decode().strip()}")
