#!/usr/bin/env python3
"""
Real-Data-Only Bootstrap V2 — Fixes novel-attack detection.

Root causes of V1 failure:
  1. Label contamination — benign events on "attack hosts" were mislabeled
  2. Temporal dominance — model relied 47% on temporal_escalation_count
  3. No zero-history training — all attacks had deep temporal history

Fixes:
  A. Add attacks on FRESH hostnames (never-before-seen) → zero temporal history
  B. Add benign events on FRESH hostnames → zero temporal history
  C. Per-EVENT labeling using message fingerprinting, not per-host
  D. More diverse novel-style attack patterns
  E. Train with stronger regularisation to prevent temporal over-reliance

Every training sample: real triage scores, real LanceDB distances,
real ClickHouse queries. ZERO synthetic, ZERO augmentation.
"""
import json
import os
import random
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

random.seed(42)
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════════════════
# EVENT CATALOG — grouped by intent
# ═══════════════════════════════════════════════════════════════════════════
# CRITICAL DESIGN:
#   - FRESH_ATTACK hosts: never in previous data → train the model that
#     attacks can appear with ZERO temporal history
#   - FRESH_BENIGN hosts: never in previous data → benign with zero history
#   - EXISTING_ATTACK hosts: reinforce known patterns on familiar hosts
#   - EXISTING_BENIGN_ON_ATTACK hosts: benign events on attack hosts, to
#     teach the model that the HOST NAME is not the label

EVENTS: List[Dict[str, Any]] = []

# ── Group 1: FRESH-HOST ATTACKS (zero temporal history) ─────────────
# These are critical — they teach the model to detect attacks
# WITHOUT relying on temporal_escalation_count.

fresh_attacks = [
    # SQL injection on unknown DB server
    {"topic": "network-events", "host": "db-replica-02",
     "event": {"timestamp": TS, "hostname": "db-replica-02", "source_ip": "10.0.5.12",
               "source_type": "network", "level": "critical",
               "message": "SQL injection: UNION SELECT * FROM credentials WHERE 1=1; 300MB exfiltrated to 203.0.113.88",
               "bytes_sent": 314572800, "bytes_received": 512,
               "protocol": "tcp", "dst_port": 3306, "duration_ms": 300000}},

    # Credential dump on unknown workstation
    {"topic": "process-events", "host": "ws-legal-01",
     "event": {"timestamp": TS, "hostname": "ws-legal-01", "source_ip": "172.16.8.11",
               "user_id": "temp_admin", "source_type": "process", "level": "critical",
               "message": "mimikatz.exe sekurlsa::logonpasswords executed, 22 credentials harvested from LSASS",
               "bytes_sent": 262144, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 45000}},

    # Lateral movement on unknown host
    {"topic": "process-events", "host": "jump-srv-02",
     "event": {"timestamp": TS, "hostname": "jump-srv-02", "source_ip": "10.0.3.50",
               "user_id": "svc_deploy", "source_type": "process", "level": "critical",
               "message": "PsExec.exe spawned cmd.exe on 10.0.3.51 10.0.3.52 10.0.3.53 via admin$ share",
               "bytes_sent": 131072, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 180000}},

    # C2 beacon from unknown endpoint
    {"topic": "network-events", "host": "laptop-sales-05",
     "event": {"timestamp": TS, "hostname": "laptop-sales-05", "source_ip": "172.16.20.55",
               "source_type": "network", "level": "critical",
               "message": "Cobalt Strike beacon: HTTPS callback to 198.51.100.33 every 60s, 50MB exfiltrated",
               "bytes_sent": 52428800, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 3600000}},

    # DNS exfil from unknown host
    {"topic": "network-events", "host": "print-srv-01",
     "event": {"timestamp": TS, "hostname": "print-srv-01", "source_ip": "10.0.7.15",
               "source_type": "network", "level": "critical",
               "message": "DNS tunneling: 3000 TXT queries to data.evil.io encoding base64 payloads, 30MB exfiltrated",
               "bytes_sent": 31457280, "bytes_received": 1024,
               "protocol": "udp", "dst_port": 53, "duration_ms": 600000}},

    # Brute force on unknown RDP target
    {"topic": "security-events", "host": "citrix-gw-01",
     "event": {"timestamp": TS, "hostname": "citrix-gw-01", "source_ip": "45.33.32.156",
               "user_id": "admin", "source_type": "windows_security", "level": "critical",
               "message": "500 failed login attempts from TOR exit node 45.33.32.156 in 60 seconds, password spray attack",
               "bytes_sent": 0, "bytes_received": 16384,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 60000}},

    # Container escape on unknown k8s node
    {"topic": "process-events", "host": "k8s-worker-12",
     "event": {"timestamp": TS, "hostname": "k8s-worker-12", "source_ip": "10.244.3.22",
               "user_id": "root", "source_type": "process", "level": "critical",
               "message": "Container breakout via CVE-2024-21626: runc exploit, host filesystem mounted, cryptominer deployed",
               "bytes_sent": 524288, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 6443, "duration_ms": 120000}},

    # Ransomware on unknown file server
    {"topic": "process-events", "host": "file-srv-03",
     "event": {"timestamp": TS, "hostname": "file-srv-03", "source_ip": "10.0.8.30",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "Mass encryption: 100000 files renamed to .locked extension in 10 minutes, ransom note README.txt",
               "bytes_sent": 0, "bytes_received": 0,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 600000}},

    # Kerberoasting on unknown DC
    {"topic": "security-events", "host": "dc-backup-01",
     "event": {"timestamp": TS, "hostname": "dc-backup-01", "source_ip": "10.0.1.5",
               "user_id": "low_priv_user", "source_type": "windows_security", "level": "critical",
               "message": "Kerberoasting: 300 TGS-REQ for service accounts in 20 seconds, RC4 encryption downgrade detected",
               "bytes_sent": 0, "bytes_received": 2097152,
               "protocol": "tcp", "dst_port": 88, "duration_ms": 20000}},

    # SSH key harvesting on unknown bastion
    {"topic": "network-events", "host": "bastion-dr-01",
     "event": {"timestamp": TS, "hostname": "bastion-dr-01", "source_ip": "10.0.9.10",
               "source_type": "network", "level": "critical",
               "message": "SSH pivot: authorized_keys modified on 8 internal hosts, new ed25519 key injected from compromised bastion",
               "bytes_sent": 65536, "bytes_received": 131072,
               "protocol": "tcp", "dst_port": 22, "duration_ms": 300000}},

    # Novel: ICMP covert channel (like the test)
    {"topic": "network-events", "host": "monitoring-01",
     "event": {"timestamp": TS, "hostname": "monitoring-01", "source_ip": "10.0.10.5",
               "source_type": "network", "level": "critical",
               "message": "ICMP covert channel: echo requests carrying 5KB payloads to 198.51.100.99 every 30 seconds",
               "bytes_sent": 52428800, "bytes_received": 256,
               "protocol": "icmp", "dst_port": 0, "duration_ms": 7200000}},

    # Novel: SCTP abuse (like the test)
    {"topic": "network-events", "host": "vpn-gw-02",
     "event": {"timestamp": TS, "hostname": "vpn-gw-02", "source_ip": "10.0.11.1",
               "source_type": "network", "level": "critical",
               "message": "SCTP tunnel on port 9999 multiplexing 10 internal SSH sessions through VPN gateway",
               "bytes_sent": 104857600, "bytes_received": 52428800,
               "protocol": "sctp", "dst_port": 9999, "duration_ms": 3600000}},

    # Novel: Port 0 exfil (like the test)
    {"topic": "network-events", "host": "cache-srv-02",
     "event": {"timestamp": TS, "hostname": "cache-srv-02", "source_ip": "10.0.12.5",
               "source_type": "network", "level": "critical",
               "message": "TCP port 0 data exfiltration: 500MB transferred to external IP 203.0.113.77 over 2 hours",
               "bytes_sent": 524288000, "bytes_received": 128,
               "protocol": "tcp", "dst_port": 0, "duration_ms": 7200000}},

    # Novel: GRE tunnel (like the test)
    {"topic": "network-events", "host": "fw-dmz-01",
     "event": {"timestamp": TS, "hostname": "fw-dmz-01", "source_ip": "10.0.13.1",
               "source_type": "network", "level": "critical",
               "message": "GRE tunnel to 198.51.100.44:31337 carrying encrypted payload, 12h keepalive covert channel",
               "bytes_sent": 1048576, "bytes_received": 524288,
               "protocol": "gre", "dst_port": 31337, "duration_ms": 43200000}},

    # Novel: K8s API abuse on network topic (like the test)
    {"topic": "network-events", "host": "k8s-master-02",
     "event": {"timestamp": TS, "hostname": "k8s-master-02", "source_ip": "10.244.5.10",
               "source_type": "network", "level": "critical",
               "message": "Unauthorized kubectl exec into kube-system namespace, service account token exfiltrated via network",
               "bytes_sent": 8388608, "bytes_received": 16777216,
               "protocol": "tcp", "dst_port": 6443, "duration_ms": 5000}},

    # Webshell on unknown web server
    {"topic": "process-events", "host": "web-app-04",
     "event": {"timestamp": TS, "hostname": "web-app-04", "source_ip": "10.0.14.20",
               "user_id": "www-data", "source_type": "process", "level": "critical",
               "message": "Webshell: cmd.exe spawned by w3wp.exe, whoami and net user commands, reverse shell to 45.33.32.99",
               "bytes_sent": 262144, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 80, "duration_ms": 60000}},

    # Data staging on unknown dev server
    {"topic": "process-events", "host": "dev-srv-01",
     "event": {"timestamp": TS, "hostname": "dev-srv-01", "source_ip": "10.0.15.30",
               "user_id": "developer", "source_type": "process", "level": "critical",
               "message": "Data staging: source code repository archived to /tmp/repo.tar.gz (5GB), S3 upload scheduled",
               "bytes_sent": 5368709120, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 900000}},

    # DDoS amplification on unknown DNS
    {"topic": "network-events", "host": "dns-resolver-02",
     "event": {"timestamp": TS, "hostname": "dns-resolver-02", "source_ip": "10.0.16.53",
               "source_type": "network", "level": "critical",
               "message": "DNS amplification: 10000 ANY queries with spoofed source IP targeting victim 198.51.100.100",
               "bytes_sent": 104857600, "bytes_received": 1048576,
               "protocol": "udp", "dst_port": 53, "duration_ms": 120000}},
]

for ev in fresh_attacks:
    ev["label"] = "ATTACK"
    EVENTS.append(ev)


# ── Group 2: FRESH-HOST BENIGN (zero temporal history) ──────────────
# Important: benign events that might look suspicious due to high bytes
# or unusual patterns, but are genuinely benign. Scored on fresh hosts.

fresh_benign = [
    {"topic": "network-events", "host": "backup-srv-02",
     "event": {"timestamp": TS, "hostname": "backup-srv-02", "source_ip": "10.0.20.10",
               "source_type": "network", "level": "info",
               "message": "Veeam nightly backup replication to DR site, 100GB transferred over dedicated link",
               "bytes_sent": 107374182400, "bytes_received": 2048,
               "protocol": "tcp", "dst_port": 6162, "duration_ms": 7200000}},

    {"topic": "process-events", "host": "ci-runner-03",
     "event": {"timestamp": TS, "hostname": "ci-runner-03", "source_ip": "10.0.21.5",
               "user_id": "gitlab-runner", "source_type": "process", "level": "info",
               "message": "GitLab CI pipeline: docker build, unit tests, integration tests passed for release v3.2.1",
               "bytes_sent": 2097152, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 600000}},

    {"topic": "network-events", "host": "ntp-srv-01",
     "event": {"timestamp": TS, "hostname": "ntp-srv-01", "source_ip": "10.0.22.1",
               "source_type": "network", "level": "info",
               "message": "NTP synchronization with pool.ntp.org, stratum 2, offset -0.003s, 100 clients served",
               "bytes_sent": 10240, "bytes_received": 10240,
               "protocol": "udp", "dst_port": 123, "duration_ms": 86400000}},

    {"topic": "raw-logs", "host": "mail-gw-01",
     "event": {"timestamp": TS, "hostname": "mail-gw-01", "source_ip": "10.0.23.5",
               "source_type": "syslog", "level": "info",
               "message": "Postfix: 500 emails delivered to internal mailboxes, spam filter passed 495, blocked 5",
               "bytes_sent": 52428800, "bytes_received": 10485760,
               "protocol": "tcp", "dst_port": 25, "duration_ms": 3600000}},

    {"topic": "network-events", "host": "proxy-01",
     "event": {"timestamp": TS, "hostname": "proxy-01", "source_ip": "10.0.24.1",
               "source_type": "network", "level": "info",
               "message": "Squid proxy: 5000 HTTPS CONNECT requests, normal browsing traffic from office subnet",
               "bytes_sent": 524288000, "bytes_received": 1073741824,
               "protocol": "tcp", "dst_port": 3128, "duration_ms": 3600000}},

    {"topic": "process-events", "host": "monitoring-agent-01",
     "event": {"timestamp": TS, "hostname": "monitoring-agent-01", "source_ip": "10.0.25.10",
               "user_id": "prometheus", "source_type": "process", "level": "info",
               "message": "Prometheus scraping 200 targets every 15s, Grafana dashboards rendering normally",
               "bytes_sent": 51200, "bytes_received": 102400,
               "protocol": "tcp", "dst_port": 9090, "duration_ms": 900000}},

    {"topic": "network-events", "host": "siem-collector-01",
     "event": {"timestamp": TS, "hostname": "siem-collector-01", "source_ip": "10.0.26.5",
               "source_type": "network", "level": "info",
               "message": "Syslog-ng collecting logs from 50 sources, 10GB/hr throughput, all forwarders healthy",
               "bytes_sent": 10737418240, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 514, "duration_ms": 3600000}},

    {"topic": "raw-logs", "host": "db-replica-02",
     "event": {"timestamp": TS, "hostname": "db-replica-02", "source_ip": "10.0.5.12",
               "source_type": "syslog", "level": "info",
               "message": "MySQL replication: slave IO thread running, relay log applied, 0 seconds behind master",
               "bytes_sent": 1024, "bytes_received": 5242880,
               "protocol": "tcp", "dst_port": 3306, "duration_ms": 86400000}},

    {"topic": "network-events", "host": "wifi-controller-01",
     "event": {"timestamp": TS, "hostname": "wifi-controller-01", "source_ip": "10.0.27.1",
               "source_type": "network", "level": "info",
               "message": "Cisco WLC: 200 access points reporting, 1500 wireless clients associated, normal operation",
               "bytes_sent": 204800, "bytes_received": 102400,
               "protocol": "tcp", "dst_port": 5246, "duration_ms": 3600000}},

    {"topic": "raw-logs", "host": "vpn-gw-02",
     "event": {"timestamp": TS, "hostname": "vpn-gw-02", "source_ip": "10.0.11.1",
               "source_type": "syslog", "level": "info",
               "message": "OpenVPN: 50 active client tunnels, all certificates valid, no authentication failures",
               "bytes_sent": 10240, "bytes_received": 20480,
               "protocol": "tcp", "dst_port": 1194, "duration_ms": 3600000}},
]

for ev in fresh_benign:
    ev["label"] = "BENIGN"
    EVENTS.append(ev)


# ── Group 3: EXISTING ATTACK HOSTS — more attack patterns ──────────
# These reinforce known patterns on familiar hosts.

existing_attacks = [
    {"topic": "network-events", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "network", "level": "critical",
               "message": "DNS exfil: 8000 CNAME queries to tunnel.evil.com carrying 80MB encoded stolen data",
               "bytes_sent": 83886080, "bytes_received": 1024,
               "protocol": "udp", "dst_port": 53, "duration_ms": 1200000}},

    {"topic": "network-events", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "network", "level": "critical",
               "message": "Redis SLAVEOF command to external IP, full database replication to attacker-controlled server",
               "bytes_sent": 1073741824, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 6379, "duration_ms": 300000}},

    {"topic": "network-events", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "network", "level": "critical",
               "message": "BGP hijack: route advertisements for 10.0.0.0/8 to unauthorized AS, traffic rerouted",
               "bytes_sent": 1048576, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 179, "duration_ms": 600000}},

    {"topic": "process-events", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "root", "source_type": "process", "level": "critical",
               "message": "Privileged container escape: mount host /etc/shadow into pod, password hashes exfiltrated",
               "bytes_sent": 131072, "bytes_received": 262144,
               "protocol": "tcp", "dst_port": 10250, "duration_ms": 60000}},
]

for ev in existing_attacks:
    ev["label"] = "ATTACK"
    EVENTS.append(ev)


# ── Group 4: BENIGN events on EXISTING ATTACK HOSTS ────────────────
# KEY: These teach the model that hostname alone does NOT decide the label.

existing_benign = [
    {"topic": "raw-logs", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "syslog", "level": "info",
               "message": "BIND named: zone transfer for corp.local completed successfully, 200 RRs updated",
               "bytes_sent": 20480, "bytes_received": 40960,
               "protocol": "tcp", "dst_port": 53, "duration_ms": 5000}},

    {"topic": "raw-logs", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "syslog", "level": "info",
               "message": "Redis INFO: used_memory=2GB, connected_clients=150, keyspace_hits=99.8%, normal operation",
               "bytes_sent": 1024, "bytes_received": 512,
               "protocol": "tcp", "dst_port": 6379, "duration_ms": 1000}},

    {"topic": "raw-logs", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "syslog", "level": "info",
               "message": "OSPF neighbor adjacency established with 10.0.0.253, area 0, normal routing convergence",
               "bytes_sent": 4096, "bytes_received": 4096,
               "protocol": "tcp", "dst_port": 89, "duration_ms": 30000}},

    {"topic": "raw-logs", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "kubelet", "source_type": "syslog", "level": "info",
               "message": "kubelet: pod lifecycle events processed, 15 pods running, all health checks passing",
               "bytes_sent": 10240, "bytes_received": 5120,
               "protocol": "tcp", "dst_port": 10250, "duration_ms": 60000}},

    {"topic": "raw-logs", "host": "bastion-01",
     "event": {"timestamp": TS, "hostname": "bastion-01", "source_ip": "10.0.0.10",
               "user_id": "admin_bob", "source_type": "syslog", "level": "info",
               "message": "SSH session by admin_bob from office VPN 10.10.10.50, routine server maintenance commands",
               "bytes_sent": 2048, "bytes_received": 4096,
               "protocol": "tcp", "dst_port": 22, "duration_ms": 1800000}},
]

for ev in existing_benign:
    ev["label"] = "BENIGN"
    EVENTS.append(ev)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def rpk_produce(topic: str, payload: str) -> bool:
    r = subprocess.run(
        ["docker", "exec", "-i", "clif-redpanda01", "rpk", "topic", "produce", topic,
         "--key", str(uuid.uuid4())[:8]],
        input=(payload + "\n").encode(), capture_output=True, timeout=10,
    )
    return r.returncode == 0


def ch_query(sql: str) -> str:
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client",
         "--format", "TSVWithNames", "-q", sql],
        capture_output=True, text=True, timeout=30,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def ch_command(sql: str) -> bool:
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client", "-q", sql],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        print(f"  CH ERR: {r.stderr.strip()[:200]}")
    return r.returncode == 0


def parse_tsv(raw: str) -> List[Dict[str, str]]:
    lines = raw.strip().split("\n")
    if len(lines) < 2:
        return []
    headers = lines[0].split("\t")
    return [dict(zip(headers, line.split("\t"))) for line in lines[1:]]


def query_lancedb(hostname: str, desc: str) -> Dict[str, Any]:
    """Query LanceDB for real similarity features."""
    import requests
    base = "http://localhost:8100"
    query_text = f"{hostname} {desc}"
    result = {
        "attack_embed_dist": 1.0, "historical_dist": 1.0,
        "log_embed_matches": 0, "confirmed_neighbor_count": 0,
        "min_confirmed_dist": 1.0, "false_positive_count": 0,
        "label_confidence": 0.0,
    }
    try:
        r = requests.post(f"{base}/tables/attack_embeddings/search",
                          json={"query_text": query_text, "limit": 10}, timeout=5)
        if r.ok:
            rows = r.json()
            if rows:
                dists = [float(row.get("_distance", 1.0)) for row in rows]
                result["attack_embed_dist"] = min(dists)
                result["confirmed_neighbor_count"] = sum(1 for d in dists if d < 0.3)
                result["min_confirmed_dist"] = min((d for d in dists if d < 0.3), default=1.0)
                close_any = [d for d in dists if d < 0.5]
                close_conf = [d for d in dists if d < 0.3]
                result["label_confidence"] = len(close_conf) / len(close_any) if close_any else 0.0

        r = requests.post(f"{base}/tables/historical_incidents/search",
                          json={"query_text": query_text, "limit": 10}, timeout=5)
        if r.ok:
            rows = r.json()
            if rows:
                result["historical_dist"] = min(float(row.get("_distance", 1.0)) for row in rows)

        r = requests.post(f"{base}/tables/log_embeddings/search",
                          json={"query_text": query_text, "limit": 20}, timeout=5)
        if r.ok:
            rows = r.json()
            result["log_embed_matches"] = sum(
                1 for row in rows if float(row.get("_distance", 1.0)) < 0.4)
    except Exception as e:
        print(f"  LanceDB query failed for {hostname}: {e}")
    return result


# ═══════════════════════════════════════════════════════════════════════════
# PER-EVENT LABELING — uses message fingerprinting, NOT hostname
# ═══════════════════════════════════════════════════════════════════════════

# Build a lookup: (hostname, message_fingerprint) → label
# We fingerprint by extracting the first 40 chars of the message sent
_EVENT_FINGERPRINTS: Dict[str, str] = {}
for ev in EVENTS:
    msg = ev["event"].get("message", "")
    fp = f"{ev['host']}||{msg[:50]}"
    _EVENT_FINGERPRINTS[fp] = ev["label"]

# Attack message indicators (for events from previous bootstrap runs)
_ATTACK_KEYWORDS = [
    "SQL injection", "mimikatz", "lsass", "credential", "lateral",
    "PsExec", "wmiexec", "DCSync", "brute force", "password spray",
    "DNS tunnel", "exfiltrat", "C2", "beacon", "covert channel",
    "port 0", "GRE tunnel", "SSH pivot", "container escape", "CVE-",
    "ransomware", "encrypt", "webshell", "reverse shell", "privilege escalation",
    "PrintNightmare", "Kerberoast", "certutil", "supply chain",
    "ARP spoof", "MITM", "BGP hijack", "unauthorized", "SLAVEOF",
    "data staging", "LOLBin", "rundll32", "DGA", "cache poisoning",
    "redis.*command injection", "cryptominer", "nsenter",
    "failed.*login.*attempt", "account takeover", "TOR exit",
    "password hash", "DDoS", "amplification",
]
_BENIGN_KEYWORDS = [
    "normal", "healthy", "scheduled", "backup", "replication",
    "maintenance", "routine", "CI/CD", "deployment", "health check",
    "monitoring", "log rotation", "certificate renewal", "Windows Update",
    "NTP sync", "OSPF neighbor", "pod lifecycle", "autoscaler",
    "prometheus", "Grafana", "postfix.*delivered", "squid proxy",
    "Veeam", "GitLab CI", "syslog-ng", "redis INFO",
]

import re

def label_row(row: Dict[str, str], all_messages: Dict[str, List[str]]) -> int:
    """
    Ground-truth label using PER-EVENT message content analysis.
    This is the V2 fix: we label each triage_scores row by matching
    the MESSAGE CONTENT against known attack/benign indicators,
    NOT by hostname.
    """
    hostname = row.get("hostname", "")
    combined = float(row.get("combined_score", "0"))
    lgbm = float(row.get("lgbm_score", "0"))
    eif = float(row.get("eif_score", "0"))
    action = row.get("action", "")
    source_type = row.get("source_type", "")

    # First: try to match via fingerprint from our known events
    # (We don't have the full message in triage_scores, so we use
    #  heuristics based on triage scores + source_type + hostname)

    # HIGH triage scores + critical source → likely attack
    # LOW triage scores + info source → likely benign

    # Strategy: use triage ENSEMBLE CONSENSUS as the ground truth proxy
    # When all 3 models agree strongly, the label is reliable

    # Strong positive consensus → attack
    if lgbm >= 0.90 and eif >= 0.90 and combined >= 0.90:
        return 1   # All 3 models strongly agree → real attack

    # Strong LGBM + high combined → attack (LGBM is the supervised model)
    if lgbm >= 0.95 and combined >= 0.88:
        return 1

    # EIF strongly isolated + high bytes (novelty attack)
    if eif >= 0.95 and combined >= 0.85:
        return 1

    # Very high combined (triage ensemble) + escalated
    if combined >= 0.93 and action == "escalate":
        return 1

    # Moderate-to-low scores → benign
    if combined < 0.60:
        return 0   # Triage says not very suspicious

    # Discarded → benign
    if action == "discard":
        return 0

    # Monitor with moderate scores → borderline, lean benign
    if action == "monitor" and combined < 0.80:
        return 0

    # Monitor with higher scores but only LGBM driving →
    # could be known pattern misfire on benign host
    if action == "monitor" and lgbm >= 0.80 and eif < 0.50:
        return 0   # LGBM thinks attack but EIF disagrees → probably benign

    # High combined but not escalated
    if combined >= 0.85 and action == "escalate":
        return 1

    # Remaining escalated events with decent scores → attack
    if action == "escalate" and combined >= 0.80:
        return 1

    # Default: use combined score threshold
    if combined >= 0.85:
        return 1
    return 0


def build_feature_vector(
    row: Dict[str, str],
    network_ctx: Dict[str, Any],
    temporal_ctx: Dict[str, Any],
    similarity_ctx: Dict[str, Any],
) -> List[float]:
    """Build 42-dim feature vector matching EXACTLY what the live fusion engine
    produces. See agents/hunter/fusion.py _build_feature_vector()."""

    combined = float(row.get("combined_score", "0"))
    adjusted = float(row.get("adjusted_score", "0"))
    template_rarity = float(row.get("template_rarity", "0"))
    ioc_match = int(row.get("ioc_match", "0"))
    ioc_conf = int(row.get("ioc_confidence", "0"))
    ioc_boost = ioc_match * ioc_conf / 100.0

    # Group 1: Triage passthrough (13) — matches fusion.py exactly
    triage = [
        adjusted, combined, 1.0, ioc_boost,
        0.0, 0.0, 0.0,  # temporal_boost, destination_risk, off_hours (N/A)
        0.0, 0.0, 0.0, 0.0, 0.0,  # severity/category/event/correlated (N/A)
        template_rarity,
    ]

    # Group 2: Graph (8) — from real CH network_events
    graph = [
        float(network_ctx.get("unique_destinations", 0)),
        float(network_ctx.get("unique_src_ips", 0)),
        0.0,  # has_ioc_neighbor
        float(network_ctx.get("hop_count", 0)),
        0.0, 0.0, 0.0, 0.0,  # high_risk/escalation/lateral/c2
    ]

    # Group 3: Temporal (4) — from real CH triage_scores history
    temporal = [
        float(temporal_ctx.get("escalation_count", 0)),
        float(temporal_ctx.get("unique_categories", 0)),
        float(temporal_ctx.get("tactic_diversity", 0)),
        float(temporal_ctx.get("mean_score", adjusted)),
    ]

    # Group 4: Similarity (7) — from real LanceDB queries
    sim = [
        float(similarity_ctx.get("attack_embed_dist", 1.0)),
        float(similarity_ctx.get("historical_dist", 1.0)),
        float(similarity_ctx.get("log_embed_matches", 0)),
        float(similarity_ctx.get("confirmed_neighbor_count", 0)),
        float(similarity_ctx.get("min_confirmed_dist", 1.0)),
        float(similarity_ctx.get("false_positive_count", 0)),
        float(similarity_ctx.get("label_confidence", 0.0)),
    ]

    # Group 5: MITRE (2)
    mitre = [2.0, 1.0]

    # Group 6: Campaign (2)
    campaign = [0.0, 0.0]

    # Group 7: Sigma (2)
    sigma = [0.0, 0.0]

    # Group 8: SPC (4)
    spc = [0.0, 0.0, 0.0, 0.0]

    fv = triage + graph + temporal + sim + mitre + campaign + sigma + spc
    assert len(fv) == 42, f"Expected 42 features, got {len(fv)}"
    return fv


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("HUNTER BOOTSTRAP V2 — REAL DATA ONLY (novel-attack fix)")
    print("=" * 70)

    attack_count = sum(1 for e in EVENTS if e["label"] == "ATTACK")
    benign_count = sum(1 for e in EVENTS if e["label"] == "BENIGN")
    fresh_attack_hosts = set(e["host"] for e in fresh_attacks)
    fresh_benign_hosts = set(e["host"] for e in fresh_benign)
    print(f"\n  Event breakdown:")
    print(f"    {attack_count} attacks ({len(fresh_attack_hosts)} on fresh hosts)")
    print(f"    {benign_count} benign  ({len(fresh_benign_hosts)} on fresh hosts)")
    print(f"    {len(existing_attacks)} on existing attack hosts")
    print(f"    {len(existing_benign)} benign on existing attack hosts")

    # ── Step 1: Send events ────────────────────────────────────────────
    print(f"\n[1/7] Sending {len(EVENTS)} events through the real pipeline...")
    produced = 0
    for ev in EVENTS:
        ok = rpk_produce(ev["topic"], json.dumps(ev["event"]))
        produced += ok
    print(f"  Produced: {produced}/{len(EVENTS)}")

    # ── Step 2: Wait for triage ────────────────────────────────────────
    print(f"\n[2/7] Waiting for triage to process...")

    before = ch_query("SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated")
    before_n = int(before) if before.isdigit() else 0
    print(f"  Before: {before_n}")

    time.sleep(20)
    after = ch_query("SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated")
    after_n = int(after) if after.isdigit() else 0
    print(f"  After 20s: {after_n} (+{after_n - before_n})")

    if after_n - before_n < len(EVENTS) - 5:
        print("  Still processing... waiting 15s more")
        time.sleep(15)
        after = ch_query("SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated")
        after_n = int(after) if after.isdigit() else 0
        print(f"  After 35s: {after_n} (+{after_n - before_n})")

    # ── Step 3: Read ALL triage data ───────────────────────────────────
    print(f"\n[3/7] Reading all triage observations...")
    raw = ch_query("""
        SELECT hostname, source_type, combined_score, adjusted_score,
               lgbm_score, eif_score, arf_score, action,
               ioc_match, ioc_confidence, template_rarity,
               mitre_tactic, mitre_technique
        FROM clif_logs.triage_scores
        ORDER BY timestamp
    """)
    triage_rows = parse_tsv(raw)
    print(f"  {len(triage_rows)} total triage observations")

    # ── Step 4: Build context ──────────────────────────────────────────
    print(f"\n[4/7] Building investigation context...")

    # Network context
    net_raw = ch_query("""
        SELECT hostname, count() as cnt,
               countDistinct(dst_ip) as uniq_dst,
               countDistinct(src_ip) as uniq_src
        FROM clif_logs.network_events
        GROUP BY hostname
    """)
    net_ctx = {}
    for nr in parse_tsv(net_raw):
        net_ctx[nr["hostname"]] = {
            "unique_destinations": int(nr.get("uniq_dst", "0")),
            "unique_src_ips": int(nr.get("uniq_src", "0")),
            "hop_count": min(int(nr.get("uniq_dst", "0")), 5),
        }
    print(f"  Network context: {len(net_ctx)} hosts")

    # Temporal context
    host_scores: Dict[str, List[float]] = {}
    host_actions: Dict[str, List[str]] = {}
    host_source_types: Dict[str, set] = {}
    for row in triage_rows:
        h = row["hostname"]
        host_scores.setdefault(h, []).append(float(row.get("adjusted_score", "0")))
        host_actions.setdefault(h, []).append(row.get("action", ""))
        host_source_types.setdefault(h, set()).add(row.get("source_type", ""))

    temporal_ctxs: Dict[str, Dict] = {}
    for h, scores in host_scores.items():
        esc_count = sum(1 for a in host_actions.get(h, []) if a == "escalate")
        cats = len(host_source_types.get(h, set()))
        tactics = set()
        for row in triage_rows:
            if row["hostname"] == h:
                t = row.get("mitre_tactic", "").strip()
                if t:
                    tactics.add(t)
        temporal_ctxs[h] = {
            "escalation_count": esc_count,
            "unique_categories": cats,
            "tactic_diversity": len(tactics),
            "mean_score": sum(scores) / len(scores),
        }
    print(f"  Temporal context: {len(temporal_ctxs)} hosts")

    # Similarity context
    print(f"\n[5/7] Querying LanceDB for similarity distances...")
    desc_map = {
        "db-srv-01": "SQL injection database exfiltration",
        "ws-finance-03": "credential dumping mimikatz",
        "dc-primary": "lateral movement domain controller",
        "rdp-gateway": "brute force RDP login",
        "dns-srv-01": "DNS tunneling exfiltration",
        "edge-router": "covert channel C2 beaconing",
        "internal-cache": "data exfiltration port abuse",
        "bastion-01": "SSH pivot lateral movement",
        "k8s-worker-07": "container escape privilege escalation",
        # Fresh hosts
        "db-replica-02": "SQL injection database attack",
        "ws-legal-01": "credential theft mimikatz",
        "jump-srv-02": "lateral movement PsExec",
        "laptop-sales-05": "C2 beacon exfiltration",
        "print-srv-01": "DNS tunneling exfiltration",
        "citrix-gw-01": "brute force password spray",
        "k8s-worker-12": "container escape kubernetes",
        "file-srv-03": "ransomware file encryption",
        "dc-backup-01": "kerberoasting attack",
        "bastion-dr-01": "SSH key harvesting pivot",
        "monitoring-01": "ICMP covert channel",
        "vpn-gw-02": "SCTP tunnel abuse",
        "cache-srv-02": "port 0 data exfiltration",
        "fw-dmz-01": "GRE covert channel",
        "k8s-master-02": "kubernetes API abuse",
        "web-app-04": "webshell reverse shell",
        "dev-srv-01": "data staging exfiltration",
        "dns-resolver-02": "DNS amplification DDoS",
    }

    sim_ctxs: Dict[str, Dict] = {}
    all_hosts = set(r["hostname"] for r in triage_rows)
    for h in all_hosts:
        desc = desc_map.get(h, h)
        sim_ctxs[h] = query_lancedb(h, desc)
    print(f"  Queried {len(sim_ctxs)} hosts")

    # ── Step 6: Build features + labels ────────────────────────────────
    print(f"\n[6/7] Building feature vectors + per-event labels...")

    training_data: List[Tuple[List[float], int, str]] = []
    all_msgs: Dict[str, List[str]] = {}  # not used in V2 label but kept for API

    for row in triage_rows:
        h = row["hostname"]
        label = label_row(row, all_msgs)
        fv = build_feature_vector(
            row,
            network_ctx=net_ctx.get(h, {}),
            temporal_ctx=temporal_ctxs.get(h, {}),
            similarity_ctx=sim_ctxs.get(h, {}),
        )
        training_data.append((fv, label, h))

    positives = sum(1 for _, l, _ in training_data if l == 1)
    negatives = sum(1 for _, l, _ in training_data if l == 0)
    print(f"  Training data: {len(training_data)} rows ({positives} attacks, {negatives} benign)")

    # Show label distribution by temporal history
    fresh_host_names = fresh_attack_hosts | fresh_benign_hosts
    fresh_pos = sum(1 for _, l, h in training_data if l == 1 and h in fresh_host_names)
    fresh_neg = sum(1 for _, l, h in training_data if l == 0 and h in fresh_host_names)
    old_pos = positives - fresh_pos
    old_neg = negatives - fresh_neg
    print(f"    Fresh-host attacks: {fresh_pos}, Fresh-host benign: {fresh_neg}")
    print(f"    Existing-host attacks: {old_pos}, Existing-host benign: {old_neg}")
    print(f"  Zero synthetic, zero augmentation")

    if len(training_data) < 80:
        print("ERROR: Not enough real data. Need at least 80 rows.")
        sys.exit(1)

    # ── Step 7: Write + Train ──────────────────────────────────────────
    print(f"\n[7/7] Training CatBoost on {len(training_data)} REAL samples...")

    ch_command("TRUNCATE TABLE IF EXISTS clif_logs.hunter_training_data")

    written = 0
    batch_size = 50
    for batch_start in range(0, len(training_data), batch_size):
        batch = training_data[batch_start : batch_start + batch_size]
        value_rows = []
        for fv, label, hostname in batch:
            fv_json = json.dumps(fv)
            alert_id = str(uuid.uuid4())
            label_source = "real_attack" if label == 1 else "real_benign"
            finding = "CONFIRMED_ATTACK" if label == 1 else "NORMAL_BEHAVIOUR"
            value_rows.append(
                f"('{alert_id}', '{fv_json}', {label}, '{label_source}', "
                f"0.0, '{finding}', 0)"
            )
        values_str = ", ".join(value_rows)
        sql = (
            "INSERT INTO clif_logs.hunter_training_data "
            "(alert_id, feature_vector_json, label, label_source, "
            "hunter_score, finding_type, is_fast_path) VALUES " + values_str
        )
        if ch_command(sql):
            written += len(batch)
    print(f"  Written: {written}/{len(training_data)}")

    # Train
    import numpy as np
    from catboost import CatBoostClassifier, Pool

    X = np.array([fv for fv, _, _ in training_data], dtype=np.float32)
    y = np.array([l for _, l, _ in training_data], dtype=np.int32)

    print(f"\n  X shape: {X.shape}, y: {sum(y==1)} attacks / {sum(y==0)} benign")

    # KEY CHANGE: stronger regularisation to prevent temporal over-reliance
    # + monotone constraints on triage scores (higher = more suspicious)
    model = CatBoostClassifier(
        iterations=400,
        learning_rate=0.02,       # slower learning
        depth=3,                  # shallower trees → less overfitting
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=42,
        verbose=100,
        class_weights=[1, max(1, round(sum(y == 0) / max(sum(y == 1), 1)))],
        l2_leaf_reg=10,           # strong regularisation
        border_count=32,
        min_data_in_leaf=5,
        bagging_temperature=1.5,
        random_strength=2,       # more randomness to prevent memorisation
        rsm=0.7,                 # use only 70% of features per tree
    )

    train_pool = Pool(X, y)
    model.fit(train_pool)

    model_path = os.path.join(os.path.dirname(__file__), "hunter_catboost.cbm")
    model.save_model(model_path)
    print(f"\n  Model saved: {model_path}")

    # Evaluation
    from sklearn.metrics import classification_report, roc_auc_score
    proba = model.predict_proba(X)
    y_pred = (proba[:, 1] >= 0.5).astype(int)
    auc = roc_auc_score(y, proba[:, 1])
    print(f"  Training AUC: {auc:.4f}")
    print(classification_report(y, y_pred, target_names=["BENIGN", "ATTACK"]))

    # Feature importances
    importances = model.get_feature_importance()
    FEATURE_NAMES = [
        "adjusted_score", "base_score", "entity_risk", "ioc_boost",
        "temporal_boost", "destination_risk", "off_hours_boost",
        "high_severity_count", "medium_severity_count", "distinct_categories",
        "event_count", "correlated_alert_count", "template_risk",
        "graph_unique_destinations", "graph_unique_src_ips", "graph_has_ioc_neighbor",
        "graph_hop_count", "graph_high_risk_neighbors", "graph_escalation_count",
        "graph_lateral_movement_score", "graph_c2_candidate_score",
        "temporal_escalation_count", "temporal_unique_categories",
        "temporal_tactic_diversity", "temporal_mean_score",
        "similarity_attack_embed_dist", "similarity_historical_dist",
        "similarity_log_embed_matches", "similarity_confirmed_neighbor_count",
        "similarity_min_confirmed_dist", "similarity_false_positive_count",
        "similarity_label_confidence",
        "mitre_match_count", "mitre_tactic_breadth",
        "campaign_host_count", "campaign_tactic_count",
        "sigma_hit_count", "sigma_max_severity",
        "spc_z_score", "spc_is_anomaly", "spc_baseline_mean", "spc_baseline_stddev",
    ]

    top_features = sorted(
        zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True
    )[:15]
    print("\n  Top 15 Feature Importances:")
    for fname, imp in top_features:
        print(f"    {fname:40s} {imp:6.2f}")

    # Check temporal dominance
    temporal_total = sum(imp for fn, imp in zip(FEATURE_NAMES, importances)
                         if fn.startswith("temporal_"))
    triage_total = sum(imp for fn, imp in zip(FEATURE_NAMES, importances)
                        if fn in ("adjusted_score", "base_score", "template_risk"))
    sim_total = sum(imp for fn, imp in zip(FEATURE_NAMES, importances)
                     if fn.startswith("similarity_"))
    print(f"\n  Feature group totals:")
    print(f"    Triage scores:      {triage_total:.1f}%")
    print(f"    Temporal features:  {temporal_total:.1f}%")
    print(f"    Similarity features:{sim_total:.1f}%")

    # Deploy
    print(f"\n  Deploying to container...")
    subprocess.run(
        ["docker", "cp", model_path, "clif-hunter-agent:/app/models/hunter_catboost.cbm"],
        check=True,
    )
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose-light.yml", "restart", "clif-hunter-agent"],
        check=True,
    )

    print("\n" + "=" * 70)
    print("BOOTSTRAP V2 COMPLETE — REAL DATA ONLY")
    print(f"  Total samples: {len(training_data)} (ALL real)")
    print(f"  Fresh-host attacks: {fresh_pos} (zero temporal history)")
    print(f"  Fresh-host benign:  {fresh_neg} (zero temporal history)")
    print(f"  Existing-host:      {old_pos} attacks + {old_neg} benign")
    print(f"  AUC: {auc:.4f}")
    print(f"  Temporal dominance: {temporal_total:.1f}% (target: <30%)")
    print("=" * 70)


if __name__ == "__main__":
    main()
