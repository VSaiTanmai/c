"""
CLIF LanceDB Integration Test — Validates the full LanceDB pipeline.

Tests:
  1. Service health check
  2. Ingest log events with embeddings
  3. Ingest threat intelligence IOCs
  4. Semantic search (log_embeddings)
  5. Semantic search (threat_intel)
  6. Similar event lookup
  7. Table stats verification
  8. Historical incidents RAG seed check

Usage:
    python test_lancedb.py [--url http://localhost:8100]
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

DEFAULT_URL = "http://localhost:8100"


import pytest


@pytest.fixture
def url() -> str:
    """LanceDB service URL fixture."""
    return DEFAULT_URL


def api(url: str, path: str, method: str = "GET", body: dict | None = None) -> dict:
    """Make an API call and return the JSON response."""
    full_url = f"{url}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = urllib.request.Request(full_url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode()[:200]}")
        raise
    except urllib.error.URLError as e:
        print(f"  Connection error: {e.reason}")
        raise


def test_health(url: str) -> bool:
    print("\n[1/8] Health Check")
    try:
        r = api(url, "/health")
        assert r["status"] == "healthy", f"Unexpected status: {r['status']}"
        print(f"  ✓ Service healthy — model: {r['model']}, dim: {r['embedding_dim']}")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_ingest_logs(url: str) -> bool:
    print("\n[2/8] Ingest Log Events")
    events = [
        {
            "event_id": "test-001",
            "timestamp": "2026-02-13T10:00:00Z",
            "source_table": "security_events",
            "log_source": "ids",
            "hostname": "SRV-WEB01",
            "severity": 8,
            "text": "SQL injection attempt detected on /api/users endpoint from IP 185.220.101.34",
        },
        {
            "event_id": "test-002",
            "timestamp": "2026-02-13T10:01:00Z",
            "source_table": "security_events",
            "log_source": "edr",
            "hostname": "WKS-0142",
            "severity": 10,
            "text": "Mimikatz credential dumping tool executed — LSASS memory access from PID 4892",
        },
        {
            "event_id": "test-003",
            "timestamp": "2026-02-13T10:02:00Z",
            "source_table": "network_events",
            "log_source": "firewall",
            "hostname": "FW-EDGE01",
            "severity": 6,
            "text": "Outbound connection to known C2 server 91.219.236.15:443 from internal host 10.0.8.42",
        },
        {
            "event_id": "test-004",
            "timestamp": "2026-02-13T10:03:00Z",
            "source_table": "process_events",
            "log_source": "tetragon",
            "hostname": "SRV-APP01",
            "severity": 9,
            "text": "PowerShell encoded command execution: whoami /all && net group 'Domain Admins' /domain",
        },
        {
            "event_id": "test-005",
            "timestamp": "2026-02-13T10:04:00Z",
            "source_table": "raw_logs",
            "log_source": "syslog",
            "hostname": "DC-01",
            "severity": 3,
            "text": "Failed login attempt for user admin — 5 attempts in 60 seconds from 10.0.1.15",
        },
    ]
    try:
        r = api(url, "/ingest/logs", method="POST", body={"events": events})
        assert r["ingested"] == 5, f"Expected 5 ingested, got {r['ingested']}"
        print(f"  ✓ Ingested {r['ingested']} log events with embeddings")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_ingest_threat_intel(url: str) -> bool:
    print("\n[3/8] Ingest Threat Intelligence IOCs")
    iocs = [
        {
            "ioc_id": "ioc-001",
            "ioc_type": "ip",
            "ioc_value": "185.220.101.34",
            "source": "AlienVault OTX",
            "confidence": 0.95,
            "severity": 9,
            "description": "Known SQL injection attack source — part of automated scanning botnet",
            "tags": ["sql-injection", "scanner", "botnet"],
            "first_seen": "2025-11-01T00:00:00Z",
            "last_seen": "2026-02-13T08:00:00Z",
        },
        {
            "ioc_id": "ioc-002",
            "ioc_type": "ip",
            "ioc_value": "91.219.236.15",
            "source": "VirusTotal",
            "confidence": 0.99,
            "severity": 10,
            "description": "Cobalt Strike C2 server — associated with APT28/Fancy Bear campaigns",
            "tags": ["cobalt-strike", "c2", "apt28"],
            "first_seen": "2025-08-15T00:00:00Z",
            "last_seen": "2026-02-12T22:00:00Z",
        },
        {
            "ioc_id": "ioc-003",
            "ioc_type": "hash",
            "ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source": "MISP",
            "confidence": 0.88,
            "severity": 8,
            "description": "Ransomware dropper — LockBit 3.0 initial payload",
            "tags": ["ransomware", "lockbit", "dropper"],
            "first_seen": "2025-12-20T00:00:00Z",
            "last_seen": "2026-01-15T00:00:00Z",
        },
    ]
    try:
        r = api(url, "/ingest/threat-intel", method="POST", body={"iocs": iocs})
        assert r["ingested"] == 3, f"Expected 3 ingested, got {r['ingested']}"
        print(f"  ✓ Ingested {r['ingested']} threat intel IOCs with embeddings")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_semantic_search_logs(url: str) -> bool:
    print("\n[4/8] Semantic Search — Log Embeddings")
    try:
        # Search for credential theft — should find Mimikatz event
        r = api(url, "/search", method="POST", body={
            "query": "credential theft LSASS memory dump",
            "table": "log_embeddings",
            "limit": 5,
        })
        assert r["count"] > 0, "No results returned"
        top = r["results"][0]
        print(f"  ✓ Found {r['count']} results")
        print(f"    Top match: {top.get('text', '')[:80]}...")
        print(f"    Distance: {top.get('_distance', 'N/A')}")

        # Second search — lateral movement / C2
        r2 = api(url, "/search", method="POST", body={
            "query": "command and control outbound connection suspicious",
            "table": "log_embeddings",
            "limit": 3,
        })
        print(f"    C2 search: {r2['count']} results — top: {r2['results'][0].get('text', '')[:60]}...")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_semantic_search_threat_intel(url: str) -> bool:
    print("\n[5/8] Semantic Search — Threat Intelligence")
    try:
        r = api(url, "/search", method="POST", body={
            "query": "APT group cobalt strike command control",
            "table": "threat_intel",
            "limit": 3,
        })
        assert r["count"] > 0, "No results returned"
        top = r["results"][0]
        print(f"  ✓ Found {r['count']} IOCs")
        print(f"    Top match: {top.get('ioc_type', '')} {top.get('ioc_value', '')} — {top.get('description', '')[:60]}")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_similar_events(url: str) -> bool:
    print("\n[6/8] Similar Event Lookup")
    try:
        r = api(url, "/similar", method="POST", body={
            "event_id": "test-002",
            "table": "log_embeddings",
            "limit": 3,
        })
        print(f"  ✓ Found {r['count']} similar events to Mimikatz event")
        for i, evt in enumerate(r["results"][:3]):
            print(f"    [{i+1}] {evt.get('text', '')[:70]}... (distance: {evt.get('_distance', 'N/A'):.4f})")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_table_stats(url: str) -> bool:
    print("\n[7/8] Table Statistics")
    try:
        r = api(url, "/tables")
        assert "tables" in r, "Missing 'tables' key"
        print(f"  ✓ {len(r['tables'])} tables:")
        for name, info in r["tables"].items():
            print(f"    {name}: {info['rows']} rows")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def test_historical_incidents(url: str) -> bool:
    print("\n[8/8] Historical Incidents RAG")
    try:
        r = api(url, "/search", method="POST", body={
            "query": "ransomware phishing email file encryption",
            "table": "historical_incidents",
            "limit": 3,
        })
        assert r["count"] > 0, "No historical incidents found"
        top = r["results"][0]
        print(f"  ✓ Found {r['count']} relevant past incidents")
        print(f"    Top: {top.get('title', 'N/A')}")
        print(f"    Resolution: {top.get('resolution', 'N/A')[:80]}...")
        return True
    except Exception as e:
        print(f"  ✗ FAILED: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="CLIF LanceDB Integration Test")
    parser.add_argument("--url", default=DEFAULT_URL, help="LanceDB service URL")
    args = parser.parse_args()

    print("=" * 60)
    print("  CLIF LanceDB Integration Test")
    print(f"  Target: {args.url}")
    print("=" * 60)

    tests = [
        test_health,
        test_ingest_logs,
        test_ingest_threat_intel,
        test_semantic_search_logs,
        test_semantic_search_threat_intel,
        test_similar_events,
        test_table_stats,
        test_historical_incidents,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            if test(args.url):
                passed += 1
            else:
                failed += 1
        except Exception:
            failed += 1

    print("\n" + "=" * 60)
    print(f"  Results: {passed}/{len(tests)} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
