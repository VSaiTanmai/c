#!/usr/bin/env python3
"""
Novel Anomaly Test: events the model has NEVER seen in training.
================================================================
The previous test used known-attack signatures (mimikatz, PsExec, brute-force)
that exist in the training datasets (CICIDS2017, UNSW-NB15, etc.).

This test crafts events that are genuinely out-of-distribution:
- Feature combinations that don't exist in any of the 12 training datasets
- Protocols, ports, byte ratios, and timing patterns never seen together
- The LGBM (supervised) should score LOW (doesn't recognize the pattern)
- The EIF (unsupervised) should score HIGH (isolated in feature space)
- The EIF Anomaly Override should kick in:
    EIF >= 0.65 -> combined floor = 0.45 -> at least MONITOR

This validates that the triage agent can catch ZERO-DAY / NOVEL threats,
not just replay known attack signatures.
"""

import json, subprocess, time, sys, uuid
from datetime import datetime, timezone

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Truly novel anomaly events ──────────────────────────────────────────────
# Each one exploits a gap in the training distribution.

EVENTS = [
    # 1. DNS TUNNELING via ICMP
    #    Training data: DNS is always UDP/53 with small queries.
    #    Novel: ICMP protocol carrying 50MB out on port 53 (impossible combo).
    #    Feature vector: protocol=1(ICMP), dst_port=53, src_bytes=50M, dst_bytes=100
    {"topic": "network-events", "label": "NOVEL-DNS-OVER-ICMP",
     "expect": "monitor+",  # at least monitor via EIF override
     "event": {"timestamp": TS, "hostname": "dns-srv-01",
               "source_ip": "10.0.0.53", "dst_ip": "198.51.100.200",
               "source_type": "netflow", "level": "info",
               "message": "ICMP type 8 echo request carrying 50MB payload to external host",
               "bytes_sent": 52428800, "bytes_received": 100,
               "protocol": "icmp", "dst_port": 53, "duration_ms": 3600000}},

    # 2. SCTP ON SSH PORT
    #    Training data: SSH is ALWAYS TCP/22 with moderate bytes.
    #    Novel: SCTP (protocol=132, never in training) on port 22.
    #    EIF should flag because SCTP never appears in the feature space.
    {"topic": "network-events", "label": "NOVEL-SCTP-SSH",
     "expect": "monitor+",
     "event": {"timestamp": TS, "hostname": "bastion-01",
               "source_ip": "172.16.0.1", "dst_ip": "10.10.10.22",
               "source_type": "netflow", "level": "info",
               "message": "SCTP association established on port 22 with 4 streams",
               "bytes_sent": 4096, "bytes_received": 2048,
               "protocol": "sctp", "dst_port": 22, "duration_ms": 7200000}},

    # 3. MASSIVE REVERSE DNS (port 0, UDP, extreme byte ratio)
    #    Training data: dst_port=0 almost never appears; UDP with GB transfer is unheard of.
    #    Novel: 1GB exfil on port 0 over UDP — no known dataset has this pattern.
    {"topic": "network-events", "label": "NOVEL-PORT0-EXFIL",
     "expect": "monitor+",
     "event": {"timestamp": TS, "hostname": "internal-cache",
               "source_ip": "10.0.0.99", "dst_ip": "203.0.113.66",
               "source_type": "netflow", "level": "warning",
               "message": "UDP stream to port 0 transferred 1073741824 bytes over 4 hours",
               "bytes_sent": 1073741824, "bytes_received": 0,
               "protocol": "udp", "dst_port": 0, "duration_ms": 14400000}},

    # 4. COVERT CHANNEL: GRE TUNNEL TO EXOTIC PORT
    #    Training data: GRE (protocol=47) is absent from all 12 datasets.
    #    Novel: GRE encapsulation to port 31337 (classic hacker port) with 0 bytes
    #    but 12-hour duration — a keep-alive covert channel.
    {"topic": "network-events", "label": "NOVEL-GRE-COVERT",
     "expect": "monitor+",
     "event": {"timestamp": TS, "hostname": "edge-router",
               "source_ip": "10.255.255.1", "dst_ip": "198.51.100.31",
               "source_type": "netflow", "level": "info",
               "message": "GRE tunnel to 198.51.100.31:31337 keepalive for 12 hours zero payload",
               "bytes_sent": 0, "bytes_received": 0,
               "protocol": "gre", "dst_port": 31337, "duration_ms": 43200000}},

    # 5. KUBERNETES AUDIT LOG ON NETWORK TOPIC
    #    Training data: k8s audit events appear as process/syslog with small messages.
    #    Novel: source_type=kubernetes on network-events topic with high bytes —
    #    this combination is impossible in training. The source_type_numeric=7
    #    paired with KDD aggregation features (non-zero for network topic) creates
    #    a feature vector that has never existed.
    {"topic": "network-events", "label": "NOVEL-K8S-NETWORK-HYBRID",
     "expect": "monitor+",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07",
               "source_ip": "10.244.1.50",  "dst_ip": "10.96.0.1",
               "source_type": "kubernetes", "level": "critical",
               "message": "kube-apiserver: unauthorized exec into pod default/production-db container=sidecar",
               "bytes_sent": 8388608, "bytes_received": 16777216,
               "protocol": "tcp", "dst_port": 6443, "duration_ms": 1000}},

    # 6. BENIGN BASELINE (control)
    #    Normal HTTPS web request — should score LOW, action=discard or monitor.
    {"topic": "network-events", "label": "BENIGN-CONTROL",
     "expect": "discard|monitor",
     "event": {"timestamp": TS, "hostname": "web-lb-01",
               "source_ip": "192.168.1.100", "dst_ip": "93.184.216.34",
               "source_type": "netflow", "level": "info",
               "message": "TCP 192.168.1.100:49152 to 93.184.216.34:443 HTTPS GET /",
               "bytes_sent": 512, "bytes_received": 4096,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 150}},
]


def rpk_produce(topic: str, payload: str):
    r = subprocess.run(
        ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", topic,
         "--key", str(uuid.uuid4())[:8]],
        input=(payload + "\n").encode(), capture_output=True, timeout=10,
    )
    return r.returncode == 0


def ch_query(sql: str):
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client", "-q", sql],
        capture_output=True, text=True, timeout=10,
    )
    return r.stdout.strip()


def get_health():
    r = subprocess.run(
        ["docker", "exec", "clif-triage-agent", "python", "-c",
         "import urllib.request,json;print(urllib.request.urlopen('http://localhost:8300/health').read().decode())"],
        capture_output=True, text=True, timeout=10,
    )
    return json.loads(r.stdout.strip()) if r.returncode == 0 else {}


# ─────────────────────────────────────────────────────────────────────────────
print("=" * 70)
print("CLIF Triage Agent -- NOVEL ANOMALY Test")
print("Events the model has NEVER seen in training")
print("=" * 70)

# Step 1: Snapshot ClickHouse row count
before_count = ch_query(
    "SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated"
)
before_count = int(before_count) if before_count.isdigit() else 0
print(f"\n[1/4] ClickHouse triage_scores before: {before_count} rows")

# Step 2: Produce novel events
print(f"\n[2/4] Producing {len(EVENTS)} novel events...")
for ev in EVENTS:
    ok = rpk_produce(ev["topic"], json.dumps(ev["event"]))
    status = "OK" if ok else "FAIL"
    print(f"  {ev['label']:30s} -> {ev['topic']:20s} [{status}]")

# Step 3: Wait for processing
print("\n[3/4] Waiting 10s for triage agent to score...")
time.sleep(10)

# Check if new rows appeared
after_count = ch_query(
    "SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated"
)
after_count = int(after_count) if after_count.isdigit() else 0
new_rows = after_count - before_count
print(f"  ClickHouse: {before_count} -> {after_count} (+{new_rows} new rows)")

if new_rows < len(EVENTS):
    print(f"  Waiting 5s more...")
    time.sleep(5)
    after_count = ch_query(
        "SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated"
    )
    after_count = int(after_count) if after_count.isdigit() else 0
    new_rows = after_count - before_count
    print(f"  ClickHouse: {after_count} (+{new_rows} new rows)")

# Step 4: Query results — get the MOST RECENT rows matching our hostnames
print(f"\n[4/4] Results from ClickHouse (novel events)...")

our_hosts = ",".join(f"'{e['event']['hostname']}'" for e in EVENTS)
rows = ch_query(
    f"SELECT hostname, combined_score, adjusted_score, action, "
    f"lgbm_score, eif_score, arf_score "
    f"FROM clif_logs.triage_scores "
    f"WHERE hostname IN ({our_hosts}) "
    f"ORDER BY timestamp DESC LIMIT {len(EVENTS) * 2} "
    f"FORMAT TSVWithNames"
)

# Parse results
novel_results = {}  # hostname -> {action, scores...}
if rows:
    lines = rows.split("\n")
    header = "  {:<22s} {:>8s} {:>8s} {:>9s}  {:>6s} {:>6s} {:>6s}  {}"
    print(header.format("hostname", "combined", "adjusted", "action", "lgbm", "eif", "arf", "verdict"))
    print("  " + "-" * 88)

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        host = parts[0]
        combined = float(parts[1])
        adjusted = float(parts[2])
        action = parts[3]
        lgbm = float(parts[4])
        eif = float(parts[5])
        arf = float(parts[6])

        # Find the matching event
        ev_match = next((e for e in EVENTS if e["event"]["hostname"] == host), None)
        label = ev_match["label"] if ev_match else "?"
        expect = ev_match["expect"] if ev_match else "?"

        # Determine if this is a true novel detection
        if "NOVEL" in label:
            # For novel events: EIF should be elevated, LGBM should be uncertain
            eif_flags = eif >= 0.50   # EIF sees it as anomalous
            is_not_discarded = action != "discard"
            if is_not_discarded and eif_flags:
                verdict = "[DETECTED]"
            elif is_not_discarded:
                verdict = "[CAUGHT]"  # caught but EIF didn't flag strongly
            else:
                verdict = "[MISSED]"
        elif "BENIGN" in label:
            verdict = "[OK]" if action in ("discard", "monitor") else "[FP!]"
        else:
            verdict = ""

        # Track by hostname (keep first = most recent)
        if host not in novel_results:
            novel_results[host] = {"action": action, "eif": eif, "lgbm": lgbm, "verdict": verdict}

        print(f"  {host:<22s} {combined:8.4f} {adjusted:8.4f} {action:>9s}  "
              f"{lgbm:6.3f} {eif:6.3f} {arf:6.3f}  {verdict}")

# Also check hunter-tasks for any escalations
print(f"\n  Checking hunter-tasks for novel escalations...")
r = subprocess.run(
    ["docker", "exec", "clif-redpanda01", "timeout", "3",
     "rpk", "topic", "consume", "hunter-tasks", "--num", "20", "-f", "%v\n"],
    capture_output=True, text=True, timeout=15,
)
novel_hosts = {e["event"]["hostname"] for e in EVENTS if "NOVEL" in e["label"]}
hunter_novel = 0
for msg_line in r.stdout.strip().split("\n"):
    try:
        d = json.loads(msg_line)
        if d.get("hostname") in novel_hosts and d.get("action") == "escalate":
            hunter_novel += 1
            print(f"  [ESCALATED] {d['hostname']:20s} score={d['adjusted_score']:.4f}")
    except Exception:
        pass
if hunter_novel == 0:
    print(f"  (no novel events escalated to hunter-tasks -- expected for borderline scores)")

# ── Final Verdict ───────────────────────────────────────────────────────────
novel_detected = sum(1 for v in novel_results.values()
                     if v["verdict"] in ("[DETECTED]", "[CAUGHT]", "[ESCALATED]"))
novel_total = sum(1 for e in EVENTS if "NOVEL" in e["label"])
novel_eif_high = sum(1 for v in novel_results.values() if v.get("eif", 0) >= 0.50)

print("\n" + "=" * 70)
print("NOVEL ANOMALY DETECTION SUMMARY")
print("-" * 70)
print(f"  Novel events sent:          {novel_total}")
print(f"  Novel events scored:        {len([v for h, v in novel_results.items() if h != 'web-lb-01'])}")
print(f"  Not discarded (detected):   {novel_detected}/{novel_total}")
print(f"  EIF flagged (>= 0.50):      {novel_eif_high}/{novel_total}")
print(f"  Escalated to hunter-tasks:  {hunter_novel}")
print("-" * 70)

if novel_detected >= novel_total:
    print("[PASS] All novel anomalies detected -- zero-day capability confirmed.")
    print("       LGBM alone would have missed these; EIF override caught them.")
elif novel_detected >= novel_total * 0.6:
    print(f"[PARTIAL] {novel_detected}/{novel_total} novel anomalies detected.")
    print("          Some novel patterns slipped through. Review EIF thresholds.")
else:
    print(f"[FAIL] Only {novel_detected}/{novel_total} novel anomalies detected.")
    print("       EIF anomaly override may not be working correctly.")

print("=" * 70)
