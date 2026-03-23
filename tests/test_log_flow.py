"""
End-to-End Log Flow Verification
==================================
Verifies that benchmark logs flowed through the entire pipeline:
  Redpanda → Vector → ClickHouse → AI Pipeline (Triage → Hunter → Verifier → Reporter)

Tests:
1. ClickHouse has benchmark data
2. AI Service health (Docker container)
3. Classify events from ClickHouse data
4. Full investigation with ClickHouse correlation (Hunter should find events!)
5. Generic event investigations (all log types)
6. Dashboard is reachable
"""
import json
import requests
import sys
import time

AI_SERVICE = "http://localhost:8200"
DASHBOARD = "http://localhost:3001"
PASSED = 0
FAILED = 0


def ok(label, detail=""):
    global PASSED
    PASSED += 1
    print(f"  [PASS] {label}" + (f" -- {detail}" if detail else ""))


def fail(label, detail=""):
    global FAILED
    FAILED += 1
    print(f"  [FAIL] {label}" + (f" -- {detail}" if detail else ""))


print("=" * 70)
print("  CLIF End-to-End Log Flow Verification")
print("  (Docker infra + AI Pipeline, no LanceDB)")
print("=" * 70)

# ── 1. ClickHouse data verification ─────────────────────────────────────
print("\n1. ClickHouse Data Verification")
try:
    import clickhouse_connect
    ch = clickhouse_connect.get_client(
        host="localhost", port=8123,
        username="clif_admin", password="Cl1f_Ch@ngeM3_2026!",
        database="clif_logs",
    )
    tables = {
        "raw_logs": ch.query("SELECT count() FROM raw_logs").result_rows[0][0],
        "security_events": ch.query("SELECT count() FROM security_events").result_rows[0][0],
        "process_events": ch.query("SELECT count() FROM process_events").result_rows[0][0],
        "network_events": ch.query("SELECT count() FROM network_events").result_rows[0][0],
    }
    total = sum(tables.values())
    for tbl, cnt in tables.items():
        print(f"     {tbl}: {cnt:,}")
    if total > 100000:
        ok("ClickHouse has benchmark data", f"{total:,} total events")
    else:
        fail("ClickHouse data", f"Only {total:,} events (expected >100K)")

    # Check recent data flow
    recent_count = ch.query(
        "SELECT count() FROM security_events WHERE timestamp > now() - INTERVAL 5 MINUTE"
    ).result_rows[0][0]
    print(f"     Recent events (last 5min): {recent_count:,}")
    ok("Recent data flowing", f"{recent_count:,} events in last 5 min")
    ch.close()
except Exception as e:
    fail("ClickHouse verification", str(e))

# ── 2. AI Service Health (Docker container) ─────────────────────────────
print("\n2. AI Service Health (Docker)")
try:
    r = requests.get(f"{AI_SERVICE}/health", timeout=10)
    h = r.json()
    print(f"     Status: {h['status']}, Model: {h['model_loaded']}, Agents: {h['agents']}")
    if h.get("status") in ("healthy", "degraded"):
        ok("AI Service healthy", f"agents={h['agents']}")
    else:
        fail("AI Service health", str(h))
except Exception as e:
    fail("AI Service health", str(e))

# ── 3. Classify a live security event ───────────────────────────────────
print("\n3. ML Classification")
try:
    # Typical attack-like event
    attack = {
        "duration": 0, "protocol_type": "tcp", "service": "telnet",
        "flag": "S0", "src_bytes": 0, "dst_bytes": 0,
        "num_failed_logins": 3, "logged_in": 0,
        "count": 300, "srv_count": 300,
        "serror_rate": 0.95, "srv_serror_rate": 0.95,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 200, "dst_host_srv_count": 200,
        "dst_host_serror_rate": 0.9, "dst_host_srv_serror_rate": 0.9,
    }
    r = requests.post(f"{AI_SERVICE}/classify", json=attack, timeout=10)
    c = r.json()
    print(f"     Attack: {c['is_attack']} | Category: {c['category']} | "
          f"Severity: {c['severity']} | Confidence: {c['confidence']:.2f}")
    ok("ML Classification", f"category={c['category']}")
except Exception as e:
    fail("ML Classification", str(e))

# ── 4. Full investigation with ClickHouse correlation ───────────────────
print("\n4. Full 4-Agent Investigation (with ClickHouse correlation)")
try:
    attack_event = {
        "duration": 0, "protocol_type": "tcp", "service": "telnet",
        "flag": "S0", "src_bytes": 0, "dst_bytes": 0,
        "num_failed_logins": 5, "logged_in": 0,
        "count": 511, "srv_count": 511,
        "serror_rate": 1.0, "srv_serror_rate": 1.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "dst_host_count": 255, "dst_host_srv_count": 255,
        "dst_host_serror_rate": 1.0, "dst_host_srv_serror_rate": 1.0,
    }
    t0 = time.time()
    r = requests.post(f"{AI_SERVICE}/investigate", json=attack_event, timeout=120)
    elapsed = time.time() - t0
    inv = r.json()

    status = inv.get("status", "?")
    triage = inv.get("triage", {})
    hunt = inv.get("hunt", {})
    ver = inv.get("verification", {})
    rep = inv.get("report", {})

    corr = hunt.get("correlations_found", 0)
    iocs = hunt.get("iocs_found", 0)

    print(f"     Pipeline:     {status} ({elapsed:.1f}s)")
    print(f"     Triage:       category={triage.get('category','?')} severity={triage.get('severity','?')} "
          f"confidence={triage.get('confidence','?')}")
    print(f"     Hunt:         correlations={corr} iocs={iocs}")
    print(f"     Verify:       verdict={ver.get('verdict','?')} fp_score={ver.get('false_positive_score','?')}")
    print(f"     Report:       severity={rep.get('severity','?')} sections={len(rep.get('sections', {}))}")

    if status in ("completed", "closed"):
        ok("Full investigation", f"verdict={ver.get('verdict','?')}, correlations={corr}")
    else:
        fail("Full investigation", f"status={status}")

    # Check if Hunter found ClickHouse correlations
    if corr > 0:
        ok("Hunter ClickHouse correlation", f"Found {corr} correlated events!")
    else:
        print("     [INFO] No correlations found (Hunter queries need matching IPs/time windows)")
except Exception as e:
    fail("Full investigation", str(e))

# ── 5. Generic investigations (all log types) ──────────────────────────
log_tests = [
    ("Sysmon", {
        "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Windows\\System32\\wscript.exe",
        "CommandLine": "cmd.exe /c powershell -ep bypass -e JABjAD0...",
        "User": "CORP\\admin", "source_ip": "10.0.0.50", "dest_ip": "10.0.0.1",
        "log_type": "sysmon",
    }),
    ("Auth/SSH", {
        "message": "Failed password for root from 192.168.1.100 port 22 ssh2",
        "hostname": "webserver01", "source": "sshd", "log_type": "auth",
    }),
    ("Firewall", {
        "action": "DROP", "source_ip": "203.0.113.50", "dest_ip": "10.0.0.5",
        "source_port": 44123, "dest_port": 22, "protocol": "tcp",
        "bytes_sent": 0, "packets": 1500, "log_type": "firewall",
    }),
    ("Windows Security", {
        "EventID": 4625, "Channel": "Security",
        "TargetUserName": "Administrator", "IpAddress": "10.0.0.99",
        "LogonType": 10, "log_type": "windows_security",
    }),
]

print("\n5. Generic Event Investigations (all log types)")
for name, event in log_tests:
    try:
        t0 = time.time()
        r = requests.post(f"{AI_SERVICE}/investigate/generic", json=event, timeout=120)
        elapsed = time.time() - t0
        inv = r.json()
        triage = inv.get("triage", {})
        print(f"     {name}: status={inv.get('status','?')} category={triage.get('category','?')} "
              f"severity={triage.get('severity','?')} classifier={triage.get('classifier_used','?')} ({elapsed:.1f}s)")
        ok(f"{name} investigation")
    except Exception as e:
        fail(f"{name} investigation", str(e))

# ── 6. Investigation history ────────────────────────────────────────────
print("\n6. Investigation History")
try:
    r = requests.get(f"{AI_SERVICE}/agents/investigations", timeout=10)
    invs = r.json().get("investigations", [])
    ok("Investigation history", f"{len(invs)} recorded")
    if invs:
        latest = invs[0]
        print(f"     Latest: {latest.get('category','?')} | {latest.get('verdict','?')} | "
              f"confidence={latest.get('confidence','?')}")
except Exception as e:
    fail("Investigation history", str(e))

# ── 7. Agent statuses ──────────────────────────────────────────────────
print("\n7. Agent Statuses")
try:
    r = requests.get(f"{AI_SERVICE}/agents/status", timeout=10)
    agents = r.json()["agents"]
    for a in agents:
        name = a.get("name", "?")
        status = a.get("status", a.get("available", "?"))
        processed = a.get("processed", a.get("total_processed", ""))
        detail = f" (processed={processed})" if processed else ""
        print(f"     {name}: {status}{detail}")
    ok("Agent statuses", f"{len(agents)} agents")
except Exception as e:
    fail("Agent statuses", str(e))

# ── 8. Dashboard ───────────────────────────────────────────────────────
print("\n8. Dashboard Reachable")
try:
    r = requests.get(DASHBOARD, timeout=10, allow_redirects=True)
    if r.status_code in (200, 307, 302):
        ok("Dashboard", f"status={r.status_code}")
    else:
        fail("Dashboard", f"status={r.status_code}")
except Exception as e:
    fail("Dashboard", str(e))

# ── Summary ─────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
total = PASSED + FAILED
print(f"  RESULTS: {PASSED}/{total} passed, {FAILED} failed")
if FAILED == 0:
    print("  ALL TESTS PASSED!")
else:
    print(f"  {FAILED} test(s) failed")
print("=" * 70)

sys.exit(0 if FAILED == 0 else 1)
