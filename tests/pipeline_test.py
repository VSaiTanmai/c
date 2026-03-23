#!/usr/bin/env python3
"""
CLIF Pipeline End-to-End Validation Script
===========================================
Tests every component of the deployed pipeline.
Run from PC1 (Windows) — connects to ClickHouse, Redpanda, XAI, etc.
"""
import json
import sys
import urllib.request
import urllib.error
import time

CH_BASE = "http://10.180.247.221:8123"
CH_USER = "clif_admin"
CH_PASS = "Cl1f_Ch@ngeM3_2026!"
XAI_BASE = "http://10.180.247.241:8200"
GRAFANA_BASE = "http://10.180.247.241:3002"
PROMETHEUS_BASE = "http://10.180.247.241:9090"
REDPANDA_CONSOLE = "http://10.180.247.241:8080"

passed = 0
failed = 0
results = []

def ch_query(sql):
    url = f"{CH_BASE}/?user={CH_USER}&password={CH_PASS}"
    req = urllib.request.Request(url, data=sql.encode())
    resp = urllib.request.urlopen(req, timeout=10)
    return resp.read().decode().strip()

def http_get(url, timeout=10):
    req = urllib.request.Request(url)
    resp = urllib.request.urlopen(req, timeout=timeout)
    return resp.read().decode()

def http_post_json(url, data, timeout=15):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(resp.read().decode())

def test(name, fn):
    global passed, failed
    try:
        result = fn()
        passed += 1
        results.append(("PASS", name, result))
        print(f"  [PASS] {name}: {result}")
    except Exception as e:
        failed += 1
        results.append(("FAIL", name, str(e)))
        print(f"  [FAIL] {name}: {e}")

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 1. CLICKHOUSE CLUSTER ===")
# ═══════════════════════════════════════════════════════════════════════

test("CH01 ping", lambda: ch_query("SELECT 1"))

test("CH cluster replicas", lambda: (
    r := ch_query("SELECT count() FROM system.clusters WHERE cluster='clif_cluster'"),
    f"{r} nodes"
)[-1])

test("Database exists", lambda: ch_query(
    "SELECT count() FROM system.databases WHERE name='clif_logs'"
))

tables_result = ch_query(
    "SELECT name FROM system.tables WHERE database='clif_logs' ORDER BY name FORMAT TSV"
)
tables = [t.strip() for t in tables_result.split('\n') if t.strip()]
test("Tables count", lambda: f"{len(tables)} tables: {', '.join(tables[:10])}...")

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 2. DATA TABLES — ROW COUNTS ===")
# ═══════════════════════════════════════════════════════════════════════

key_tables = [
    "raw_logs", "triage_scores", "anomaly_alerts", "hunter_investigations",
    "verifier_results", "evidence_chain", "ioc_cache", "source_thresholds",
    "asset_criticality", "allowlist", "arf_replay_buffer",
]

for tbl in key_tables:
    test(f"{tbl} rows", lambda t=tbl: ch_query(
        f"SELECT count() FROM clif_logs.{t}"
    ))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 3. DATA FRESHNESS ===")
# ═══════════════════════════════════════════════════════════════════════

freshness_tables = [
    ("raw_logs", "timestamp"),
    ("triage_scores", "timestamp"),
]
for tbl, col in freshness_tables:
    test(f"{tbl} latest", lambda t=tbl, c=col: ch_query(
        f"SELECT max({c}) FROM clif_logs.{t}"
    ))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 4. TRIAGE SCORING QUALITY ===")
# ═══════════════════════════════════════════════════════════════════════

test("Triage action distribution", lambda: ch_query(
    "SELECT action, count() as cnt FROM clif_logs.triage_scores GROUP BY action ORDER BY cnt DESC FORMAT TSV"
))

test("Triage score stats", lambda: ch_query(
    "SELECT round(avg(combined_score),4) as avg_score, "
    "round(min(combined_score),4) as min_score, "
    "round(max(combined_score),4) as max_score, "
    "round(avg(agreement),4) as avg_agreement "
    "FROM clif_logs.triage_scores FORMAT TSV"
))

test("Triage model version", lambda: ch_query(
    "SELECT model_version, count() FROM clif_logs.triage_scores GROUP BY model_version FORMAT TSV"
))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 5. SHAP ATTRIBUTION ===")
# ═══════════════════════════════════════════════════════════════════════

test("SHAP data in triage_scores", lambda: ch_query(
    "SELECT countIf(length(shap_top_features) > 2) as with_shap, "
    "countIf(length(shap_summary) > 2) as with_summary, "
    "count() as total FROM clif_logs.triage_scores"
    " FORMAT TSV"
))

test("SHAP sample (latest)", lambda: ch_query(
    "SELECT shap_top_features FROM clif_logs.triage_scores "
    "WHERE length(shap_top_features) > 2 ORDER BY timestamp DESC LIMIT 1 FORMAT TSV"
))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 6. HUNTER INVESTIGATIONS ===")
# ═══════════════════════════════════════════════════════════════════════

test("Hunter investigation count", lambda: ch_query(
    "SELECT count() FROM clif_logs.hunter_investigations"
))

test("Hunter verdict distribution", lambda: ch_query(
    "SELECT verdict, count() as cnt FROM clif_logs.hunter_investigations GROUP BY verdict ORDER BY cnt DESC FORMAT TSV"
))

test("Hunter sigma hits", lambda: ch_query(
    "SELECT countIf(sigma_hits > 0) as with_sigma, count() as total "
    "FROM clif_logs.hunter_investigations FORMAT TSV"
))

test("Hunter MITRE tactics found", lambda: ch_query(
    "SELECT countIf(length(mitre_tactics) > 2) as with_mitre, count() as total "
    "FROM clif_logs.hunter_investigations FORMAT TSV"
))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 7. VERIFIER VERDICTS ===")
# ═══════════════════════════════════════════════════════════════════════

test("Verifier result count", lambda: ch_query(
    "SELECT count() FROM clif_logs.verifier_results"
))

test("Verifier verdict distribution", lambda: ch_query(
    "SELECT verdict, count() as cnt FROM clif_logs.verifier_results GROUP BY verdict ORDER BY cnt DESC FORMAT TSV"
))

test("Verifier explanation_json present", lambda: ch_query(
    "SELECT countIf(length(explanation_json) > 10) as with_xai, count() as total "
    "FROM clif_logs.verifier_results FORMAT TSV"
))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 8. EVIDENCE CHAIN (MERKLE) ===")
# ═══════════════════════════════════════════════════════════════════════

test("Evidence chain entries", lambda: ch_query(
    "SELECT count() FROM clif_logs.evidence_chain"
))

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 9. XAI SERVICE (port 8200) ===")
# ═══════════════════════════════════════════════════════════════════════

test("XAI /health", lambda: (
    r := json.loads(http_get(f"{XAI_BASE}/health")),
    f"status={r['status']}, ready={r['ready']}"
)[-1])

test("XAI /xai/status", lambda: (
    r := json.loads(http_get(f"{XAI_BASE}/xai/status")),
    f"available={r['available']}, features={r['feature_count']}, model={r['model_version']}"
)[-1])

test("XAI /model/features", lambda: (
    r := json.loads(http_get(f"{XAI_BASE}/model/features")),
    f"{r['total_features']} features, top={r['features'][0]['feature']}({r['features'][0]['importance']:.3f})"
)[-1])

# SYN Flood test
test("XAI /explain (SYN Flood)", lambda: (
    r := http_post_json(f"{XAI_BASE}/explain", {
        "duration": 0, "protocol": 6, "src_bytes": 0, "dst_bytes": 0,
        "count": 511, "srv_count": 511, "serror_rate": 1.0,
        "same_srv_rate": 1.0, "dst_host_count": 255, "dst_host_srv_count": 255,
    }),
    f"attack={r['is_attack']}, severity={r['severity']}, confidence={r['confidence']}, "
    f"top_feature={r['xai']['top_features'][0]['feature']}"
)[-1])

# Normal traffic test
test("XAI /explain (Normal HTTP)", lambda: (
    r := http_post_json(f"{XAI_BASE}/explain", {
        "duration": 0.01, "protocol": 6, "src_bytes": 200, "dst_bytes": 4000,
        "count": 2, "srv_count": 2, "serror_rate": 0.0, "rerror_rate": 0.0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "dst_host_count": 10,
        "dst_host_srv_count": 10, "dst_port": 80,
    }),
    f"attack={r['is_attack']}, severity={r['severity']}, confidence={r['confidence']}"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 10. PROMETHEUS ===")
# ═══════════════════════════════════════════════════════════════════════

test("Prometheus healthy", lambda: (
    r := http_get(f"{PROMETHEUS_BASE}/-/healthy"),
    r.strip()
)[-1])

test("Prometheus targets", lambda: (
    r := json.loads(http_get(f"{PROMETHEUS_BASE}/api/v1/targets?state=active")),
    f"status={r['status']}, active_targets={len(r['data']['activeTargets'])}"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 11. GRAFANA ===")
# ═══════════════════════════════════════════════════════════════════════

test("Grafana healthy", lambda: (
    r := json.loads(http_get(f"{GRAFANA_BASE}/api/health")),
    f"version={r.get('version','?')}, db={r.get('database','?')}"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 12. REDPANDA CONSOLE ===")
# ═══════════════════════════════════════════════════════════════════════

test("Redpanda Console reachable", lambda: (
    http_get(f"{REDPANDA_CONSOLE}/admin/health"),
    "OK"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 13. MINIO OBJECT STORE ===")
# ═══════════════════════════════════════════════════════════════════════

test("MinIO health", lambda: (
    http_get("http://10.180.247.221:9002/minio/health/live"),
    "OK"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
print("\n=== 14. VECTOR LOG SHIPPER ===")
# ═══════════════════════════════════════════════════════════════════════

test("Vector health", lambda: (
    r := json.loads(http_get("http://10.180.247.221:8686/health")),
    f"ok={r.get('ok', '?')}"
)[-1])

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════

print(f"\n{'='*60}")
print(f"PIPELINE VALIDATION SUMMARY")
print(f"{'='*60}")
print(f"  Total tests:  {passed + failed}")
print(f"  Passed:       {passed}")
print(f"  Failed:       {failed}")
print(f"{'='*60}")

if failed > 0:
    print("\nFAILED TESTS:")
    for status, name, detail in results:
        if status == "FAIL":
            print(f"  - {name}: {detail}")

print()
sys.exit(1 if failed > 0 else 0)
