#!/usr/bin/env python3
"""
Seed LanceDB with known attack patterns and historical incident data.

Populates three tables:
  - attack_embeddings:    Known MITRE ATT&CK patterns
  - historical_incidents: Past investigated incidents
  - log_embeddings:       Example malicious log snippets per host

This gives the hunter's similarity_searcher real data to compare against,
so it can identify when a new alert resembles a known attack pattern.
"""
import json
import requests
import sys
from datetime import datetime, timedelta

BASE = "http://localhost:8100"

# ─── Attack Embeddings (known MITRE patterns) ──────────────────────────────
ATTACKS = [
    # Credential attacks
    {"text": "dc-primary domain_admin kerberoasting initial-access T1078 brute force credential dump LDAP",
     "metadata": {"hostname": "dc-primary", "source_ip": "10.0.0.5", "tactic": "credential-access",
                  "technique": "T1558", "severity": "high", "timestamp": "2026-01-15T08:00:00Z"}},
    {"text": "dc-primary golden ticket kerberos TGT forgery persistence lateral-movement T1558.001",
     "metadata": {"hostname": "dc-primary", "source_ip": "10.0.0.5", "tactic": "credential-access",
                  "technique": "T1558.001", "severity": "critical", "timestamp": "2026-01-20T10:00:00Z"}},
    {"text": "rdp-gateway admin brute force RDP lateral-movement T1021.001 multiple failed login",
     "metadata": {"hostname": "rdp-gateway", "source_ip": "203.0.113.50", "tactic": "lateral-movement",
                  "technique": "T1021.001", "severity": "high", "timestamp": "2026-01-10T14:00:00Z"}},
    # SQL injection / DB attacks
    {"text": "db-srv-01 SQL injection database exfiltration initial-access T1190 web exploit",
     "metadata": {"hostname": "db-srv-01", "source_ip": "198.51.100.25", "tactic": "initial-access",
                  "technique": "T1190", "severity": "critical", "timestamp": "2026-02-01T09:00:00Z"}},
    {"text": "db-srv-01 unauthorized SELECT FROM users passwords data exfiltration collection T1005",
     "metadata": {"hostname": "db-srv-01", "source_ip": "10.0.0.50", "tactic": "collection",
                  "technique": "T1005", "severity": "high", "timestamp": "2026-02-01T09:15:00Z"}},
    # Network exfiltration
    {"text": "dns-srv-01 DNS tunneling exfiltration high volume ICMP covert channel T1048",
     "metadata": {"hostname": "dns-srv-01", "source_ip": "10.0.0.53", "tactic": "exfiltration",
                  "technique": "T1048", "severity": "critical", "timestamp": "2026-02-10T03:00:00Z"}},
    {"text": "internal-cache port 0 UDP exfiltration unusual protocol data transfer T1048.003",
     "metadata": {"hostname": "internal-cache", "source_ip": "10.0.0.80", "tactic": "exfiltration",
                  "technique": "T1048.003", "severity": "critical", "timestamp": "2026-02-12T01:00:00Z"}},
    {"text": "edge-router GRE tunnel covert channel C2 command-and-control persistence T1572 port 31337",
     "metadata": {"hostname": "edge-router", "source_ip": "192.168.1.1", "tactic": "command-and-control",
                  "technique": "T1572", "severity": "high", "timestamp": "2026-02-15T22:00:00Z"}},
    # Lateral movement / privilege escalation
    {"text": "ws-finance-03 svc_backup privilege escalation service account abuse T1078.002 lateral-movement",
     "metadata": {"hostname": "ws-finance-03", "source_ip": "10.0.0.103", "tactic": "privilege-escalation",
                  "technique": "T1078.002", "severity": "high", "timestamp": "2026-01-25T16:00:00Z"}},
    {"text": "bastion-01 SSH brute force unusual protocol SCTP suspicious port 22 lateral-movement T1021.004",
     "metadata": {"hostname": "bastion-01", "source_ip": "203.0.113.99", "tactic": "lateral-movement",
                  "technique": "T1021.004", "severity": "high", "timestamp": "2026-02-20T11:00:00Z"}},
    # Container / K8s attacks
    {"text": "k8s-worker-07 kubernetes exec pod escape container breakout T1610 privilege-escalation",
     "metadata": {"hostname": "k8s-worker-07", "source_ip": "10.244.1.50", "tactic": "privilege-escalation",
                  "technique": "T1610", "severity": "critical", "timestamp": "2026-02-25T07:00:00Z"}},
    {"text": "k8s-worker unauthorized kube-apiserver access RBAC bypass T1078.004 initial-access",
     "metadata": {"hostname": "k8s-worker-07", "source_ip": "10.244.1.50", "tactic": "initial-access",
                  "technique": "T1078.004", "severity": "critical", "timestamp": "2026-02-25T07:05:00Z"}},
    # Web attacks
    {"text": "web-01 path traversal directory listing ../etc/passwd initial-access T1190 exploit",
     "metadata": {"hostname": "web-01", "source_ip": "198.51.100.30", "tactic": "initial-access",
                  "technique": "T1190", "severity": "medium", "timestamp": "2026-01-05T12:00:00Z"}},
    {"text": "prod-api-01 API abuse rate limit bypass reconnaissance T1595 automated scanning",
     "metadata": {"hostname": "prod-api-01", "source_ip": "198.51.100.40", "tactic": "reconnaissance",
                  "technique": "T1595", "severity": "medium", "timestamp": "2026-01-08T18:00:00Z"}},
    # Ransomware / destruction
    {"text": "file encryption ransomware impact T1486 mass file modification crypto locker wiper",
     "metadata": {"hostname": "file-server-01", "source_ip": "10.0.0.200", "tactic": "impact",
                  "technique": "T1486", "severity": "critical", "timestamp": "2026-02-28T04:00:00Z"}},
]

# ─── Historical Incidents (past hunter verdicts) ──────────────────────────
HISTORICAL = [
    {"text": "db-srv-01 SQL injection confirmed CONFIRMED_THREAT hunter investigation revealed data exfil via web app vuln",
     "metadata": {"hostname": "db-srv-01", "finding_type": "CONFIRMED_THREAT", "hunter_score": 0.92,
                  "timestamp": "2026-02-01T10:00:00Z"}},
    {"text": "dc-primary kerberoasting domain_admin confirmed credential theft CONFIRMED_THREAT golden ticket",
     "metadata": {"hostname": "dc-primary", "finding_type": "CONFIRMED_THREAT", "hunter_score": 0.88,
                  "timestamp": "2026-01-20T12:00:00Z"}},
    {"text": "dns-srv-01 DNS tunneling 50MB ICMP exfiltration CONFIRMED_THREAT covert channel detected",
     "metadata": {"hostname": "dns-srv-01", "finding_type": "CONFIRMED_THREAT", "hunter_score": 0.95,
                  "timestamp": "2026-02-10T04:00:00Z"}},
    {"text": "edge-router GRE covert channel command-and-control SUSPICIOUS_PATTERN port 31337",
     "metadata": {"hostname": "edge-router", "finding_type": "SUSPICIOUS_PATTERN", "hunter_score": 0.78,
                  "timestamp": "2026-02-15T23:00:00Z"}},
    {"text": "bastion-01 SCTP SSH brute force unusual protocol SUSPICIOUS_PATTERN lateral movement attempt",
     "metadata": {"hostname": "bastion-01", "finding_type": "SUSPICIOUS_PATTERN", "hunter_score": 0.72,
                  "timestamp": "2026-02-20T12:00:00Z"}},
    {"text": "internal-cache port 0 exfiltration UDP CONFIRMED_THREAT massive data transfer to unknown dest",
     "metadata": {"hostname": "internal-cache", "finding_type": "CONFIRMED_THREAT", "hunter_score": 0.94,
                  "timestamp": "2026-02-12T02:00:00Z"}},
    {"text": "web-lb-01 normal HTTPS traffic NORMAL_BEHAVIOUR benign web request no threat",
     "metadata": {"hostname": "web-lb-01", "finding_type": "NORMAL_BEHAVIOUR", "hunter_score": 0.15,
                  "timestamp": "2026-02-28T12:00:00Z"}},
    {"text": "rdp-gateway admin login multiple failures then success SUSPICIOUS_PATTERN brute force",
     "metadata": {"hostname": "rdp-gateway", "finding_type": "SUSPICIOUS_PATTERN", "hunter_score": 0.75,
                  "timestamp": "2026-01-10T15:00:00Z"}},
    {"text": "k8s-worker-07 kubernetes pod exec unauthorized CONFIRMED_THREAT container escape sidecar",
     "metadata": {"hostname": "k8s-worker-07", "finding_type": "CONFIRMED_THREAT", "hunter_score": 0.91,
                  "timestamp": "2026-02-25T08:00:00Z"}},
    {"text": "ws-finance-03 svc_backup lateral movement SUSPICIOUS_PATTERN service account privilege escalation",
     "metadata": {"hostname": "ws-finance-03", "finding_type": "SUSPICIOUS_PATTERN", "hunter_score": 0.68,
                  "timestamp": "2026-01-25T17:00:00Z"}},
]

# ─── Log Embeddings (example malicious/suspicious log context) ─────────────
LOG_SNIPPETS = [
    {"text": "db-srv-01 SQL error: syntax error near UNION SELECT FROM information_schema.tables",
     "metadata": {"hostname": "db-srv-01", "source_type": "syslog", "level": "error",
                  "timestamp": "2026-02-01T09:01:00Z"}},
    {"text": "db-srv-01 mysql: 1000 rows sent to 198.51.100.25:4444 unusual outbound connection",
     "metadata": {"hostname": "db-srv-01", "source_type": "syslog", "level": "warning",
                  "timestamp": "2026-02-01T09:10:00Z"}},
    {"text": "dc-primary Event 4769 Kerberos TGS request encryption RC4 anomalous ticket",
     "metadata": {"hostname": "dc-primary", "source_type": "windows_event", "level": "warning",
                  "timestamp": "2026-01-20T10:05:00Z"}},
    {"text": "dns-srv-01 ICMP packet 65535 bytes to 198.51.100.99 DNS over ICMP tunneling detected",
     "metadata": {"hostname": "dns-srv-01", "source_type": "netflow", "level": "critical",
                  "timestamp": "2026-02-10T03:05:00Z"}},
    {"text": "edge-router GRE keepalive 0-byte payload to 198.51.100.77:31337 every 12 hours",
     "metadata": {"hostname": "edge-router", "source_type": "netflow", "level": "warning",
                  "timestamp": "2026-02-15T22:10:00Z"}},
    {"text": "bastion-01 sshd: connection from 203.0.113.99 port 22 protocol SCTP unusual transport",
     "metadata": {"hostname": "bastion-01", "source_type": "syslog", "level": "warning",
                  "timestamp": "2026-02-20T11:01:00Z"}},
    {"text": "internal-cache UDP 0.0.0.0:0 to 198.51.100.55:0 1073741824 bytes port zero exfil",
     "metadata": {"hostname": "internal-cache", "source_type": "netflow", "level": "critical",
                  "timestamp": "2026-02-12T01:05:00Z"}},
    {"text": "k8s-worker-07 kube-apiserver: unauthorized exec into pod default/production-db container=sidecar",
     "metadata": {"hostname": "k8s-worker-07", "source_type": "kubernetes", "level": "critical",
                  "timestamp": "2026-02-25T07:02:00Z"}},
    {"text": "rdp-gateway 47 failed RDP logins from 203.0.113.50 in 120 seconds brute force",
     "metadata": {"hostname": "rdp-gateway", "source_type": "windows_event", "level": "warning",
                  "timestamp": "2026-01-10T14:02:00Z"}},
    {"text": "ws-finance-03 svc_backup accessed \\\\dc-primary\\SYSVOL unusual share lateral movement",
     "metadata": {"hostname": "ws-finance-03", "source_type": "syslog", "level": "warning",
                  "timestamp": "2026-01-25T16:05:00Z"}},
    {"text": "web-lb-01 GET / HTTP/1.1 200 OK normal traffic benign request",
     "metadata": {"hostname": "web-lb-01", "source_type": "netflow", "level": "info",
                  "timestamp": "2026-03-01T12:00:00Z"}},
    {"text": "prod-api-01 429 Too Many Requests rate limit exceeded from 198.51.100.40 scanning",
     "metadata": {"hostname": "prod-api-01", "source_type": "syslog", "level": "warning",
                  "timestamp": "2026-01-08T18:02:00Z"}},
]


def ingest_table(table: str, rows: list, label: str):
    ok = 0
    fail = 0
    for row in rows:
        try:
            r = requests.post(
                f"{BASE}/tables/{table}/ingest",
                json=row,
                timeout=30,
            )
            r.raise_for_status()
            ok += 1
        except Exception as e:
            fail += 1
            print(f"  FAIL: {e}")
    print(f"  {label}: {ok}/{len(rows)} ingested ({fail} failed)")


def test_search(table: str, query: str, limit: int = 3):
    """Quick search test to verify data is retrievable."""
    try:
        r = requests.post(
            f"{BASE}/tables/{table}/search",
            json={"query_text": query, "limit": limit},
            timeout=10,
        )
        r.raise_for_status()
        results = r.json()
        print(f"  Search '{query[:40]}...' → {len(results)} results")
        for i, row in enumerate(results):
            dist = row.get("_distance", "?")
            text = row.get("text", "")[:60]
            print(f"    [{i}] dist={dist:.4f}  {text}")
    except Exception as e:
        print(f"  Search FAILED: {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("Seeding LanceDB with attack patterns")
    print("=" * 60)

    # Check health first
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        health = r.json()
        print(f"LanceDB status: {health['status']}, tables: {health['tables']}")
    except Exception as e:
        print(f"ERROR: LanceDB not reachable at {BASE}: {e}")
        sys.exit(1)

    print(f"\n[1/3] Ingesting {len(ATTACKS)} attack embeddings...")
    ingest_table("attack_embeddings", ATTACKS, "attack_embeddings")

    print(f"\n[2/3] Ingesting {len(HISTORICAL)} historical incidents...")
    ingest_table("historical_incidents", HISTORICAL, "historical_incidents")

    print(f"\n[3/3] Ingesting {len(LOG_SNIPPETS)} log embeddings...")
    ingest_table("log_embeddings", LOG_SNIPPETS, "log_embeddings")

    # Verify
    print("\n" + "=" * 60)
    print("Verification searches")
    print("=" * 60)

    print("\nattack_embeddings:")
    test_search("attack_embeddings", "SQL injection database exfiltration web exploit")
    test_search("attack_embeddings", "DNS tunneling ICMP covert channel exfiltration")

    print("\nhistorical_incidents:")
    test_search("historical_incidents", "kerberoasting domain admin credential theft")
    test_search("historical_incidents", "port 0 UDP exfiltration")

    print("\nlog_embeddings:")
    test_search("log_embeddings", "UNION SELECT information_schema SQL injection")
    test_search("log_embeddings", "kubernetes exec pod unauthorized sidecar")

    # Final counts
    print("\n" + "=" * 60)
    r = requests.get(f"{BASE}/health", timeout=5)
    health = r.json()
    print(f"Done. Tables: {health['tables']}")
    print("=" * 60)
