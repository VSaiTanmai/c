#!/usr/bin/env python3
"""Inject 20 extreme attack events into raw-logs to trigger escalation pipeline."""
import json, subprocess, datetime, random

ts_base = datetime.datetime.utcnow()
events = []
for i in range(20):
    ts = (ts_base + datetime.timedelta(milliseconds=i*100)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    evt = {
        "timestamp": ts,
        "hostname": f"E2E-ESCALATION-TEST-{i:02d}",
        "source_type": "netflow",  # highest avg escalation rate
        "source_ip": f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "dst_ip": "192.168.1.1",
        "dst_port": random.choice([22, 445, 3389, 4444]),
        "protocol": "TCP",
        "event_type": "connection",
        "message": f"[E2E-TEST-{i:02d}] Extreme anomaly injection for pipeline validation",
        "severity": "critical",
        "user_id": "e2e_test",
        # Features designed for maximum anomaly score
        "duration": 0.0,
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": random.randint(490, 511),
        "srv_count": random.randint(490, 511),
        "serror_rate": round(random.uniform(0.95, 1.0), 4),
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": random.randint(200, 255),
        "dst_host_srv_count": random.randint(200, 255),
        "hour_of_day": 3,
        "is_weekend": 1,
        "log_length": random.randint(80, 150),
        "dst_host_same_srv_rate": 1.0,
        "rerror_rate": round(random.uniform(0.0, 0.1), 4),
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_serror_rate": round(random.uniform(0.9, 1.0), 4),
        "dst_host_srv_serror_rate": round(random.uniform(0.9, 1.0), 4),
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
    events.append(json.dumps(evt))

# Pipe all events to rpk
input_data = "\n".join(events) + "\n"
result = subprocess.run(
    ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", "raw-logs", "--key", "e2e-escalation-test"],
    input=input_data.encode(),
    capture_output=True, timeout=30
)
print(f"Injected 20 extreme events at {ts_base.strftime('%H:%M:%S')} UTC")
print(f"stdout: {result.stdout.decode()[-200:]}")
if result.returncode != 0:
    print(f"stderr: {result.stderr.decode()[-200:]}")
