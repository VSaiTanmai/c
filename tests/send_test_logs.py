#!/usr/bin/env python3
"""
Send 130 combined_test_logs through the CLIF pipeline via Vector TCP (port 9514).
Each log is wrapped in JSON with a test_batch_id for easy retrieval from ClickHouse.
"""

import json
import socket
import time
import uuid
import sys
import re

TEST_BATCH_ID = f"test-{uuid.uuid4().hex[:12]}"
VECTOR_HOST = "localhost"
VECTOR_PORT = 9514

def extract_logs(filepath: str) -> list[dict]:
    """Parse combined_test_logs.txt and extract individual log entries with metadata."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    logs = []
    lines = content.split("\n")
    current_category = ""
    current_format = ""
    log_num = 0
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()

        # Track category
        if line.startswith("# CATEGORY"):
            current_category = line.split(":")[1].strip() if ":" in line else line
        if line.startswith("--- Format"):
            current_format = line.strip("- ")

        # Skip headers, comments, blank lines, separators
        if (not line or
            line.startswith("#") or
            line.startswith("=") or
            line.startswith("---") or
            line.startswith("Generated:") or
            line.startswith("Total Entries:") or
            line.startswith("Purpose:") or
            line.startswith("WARNING:") or
            line.startswith("SUMMARY:") or
            line.startswith("--------") or
            line.startswith("Category ") or
            line.startswith("TOTAL:") or
            line.startswith("END OF LOG FILE")):
            i += 1
            continue

        # === CATEGORY 1A: Raw Zeek Tab-Delimited ===
        if line.startswith("2026-03-04T22:") and "\t" in line:
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "network",
                "sub_format": "zeek_tab",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 1B: JSON Zeek Conn Logs ===
        if line.startswith('{"ts":'):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "network",
                "sub_format": "zeek_json",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 1C / 2C / 3C / 4C / 5D: Extended [LOG-XXX] format ===
        m = re.match(r'^\[LOG-(\d+)\]\s+\[(.+?)\]\s+(.+)', line)
        if m:
            log_id = int(m.group(1))
            log_type = m.group(2)
            # Accumulate multi-line log until next [LOG-] or blank or section header
            full_log = line
            i += 1
            while i < len(lines):
                nl = lines[i].rstrip()
                if (not nl or nl.startswith("[LOG-") or nl.startswith("#") or
                    nl.startswith("---") or nl.startswith("===")):
                    break
                full_log += "\n" + nl
                i += 1
            log_num += 1
            cat = "network" if log_type in ("NetFlow", "Zeek Conn") else \
                  "auth" if "Auth" in log_type or "SSH" in log_type else \
                  "security" if log_type in ("Snort", "Suricata", "Firewall") else \
                  "system" if log_type == "Syslog" else \
                  "process" if log_type == "Audit" else "raw"
            logs.append({
                "log_num": log_num,
                "category": cat,
                "sub_format": f"extended_{log_type.lower().replace('/', '_')}",
                "raw": full_log
            })
            continue

        # === CATEGORY 2A: Standard SSH Auth Logs (Mar  4 ...) ===
        if re.match(r'^Mar\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\w+\s+sshd\[', line):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "auth",
                "sub_format": "ssh_auth",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 2B: Brute Force SSH Logs (Mar 15 ...) ===
        if re.match(r'^Mar\s+15\s+\d{2}:\d{2}:\d{2}\s+server\d+\s+sshd\[', line):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "auth",
                "sub_format": "ssh_brute_force",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 3A: Snort/Suricata text alerts ===
        if line.startswith("[**]") or line.startswith("[DROP]") or line.startswith("[UFW"):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "security",
                "sub_format": "snort_suricata_text",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 3B: Dated Suricata/Snort alerts ===
        if re.match(r'^\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+\s+\[\*\*\]', line):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "security",
                "sub_format": "snort_dated",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 4A: Linux System Logs ===
        if re.match(r'^Mar\s+\d+\s+\d{2}:\d{2}:\d{2}\s+srv\d+\s+', line):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "system",
                "sub_format": "linux_syslog",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 4B: UFW Blocks & Session Logs ===
        if re.match(r'^Mar\s+15\s+\d{2}:\d{2}:\d{2}\s+(webserver|dbserver)\d+\s+', line):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "system",
                "sub_format": "ufw_session",
                "raw": line
            })
            i += 1
            continue

        # === CATEGORY 5A: Linux Audit EXECVE ===
        if line.startswith("type=EXECVE") or line.startswith("type=PROCTITLE") or \
           line.startswith("type=SYSCALL") or line.startswith("type=PATH"):
            log_num += 1
            logs.append({
                "log_num": log_num,
                "category": "process",
                "sub_format": "audit_execve",
                "raw": line
            })
            i += 1
            continue

        # === Extended Auth lines that start with "Mar 15" or "Mar 16" (from C format content) ===
        if re.match(r'^Mar\s+1[56]\s+\d{2}:\d{2}:\d{2}\s+', line):
            log_num += 1
            # Determine category from content
            if 'sshd[' in line or 'pam_unix' in line:
                cat = "auth"
            elif 'Microsoft-Windows-Security-Auditing' in line:
                cat = "auth"
            elif 'sudo:' in line:
                cat = "auth"
            elif 'kernel:' in line or 'systemd' in line or 'cron' in line or \
                 'rsyslog' in line or 'auditd' in line or 'mysqld' in line or \
                 'squid' in line or 'samba' in line:
                cat = "system"
            elif 'fw01' in line:
                cat = "security"
            else:
                cat = "raw"
            logs.append({
                "log_num": log_num,
                "category": cat,
                "sub_format": "extended_line",
                "raw": line
            })
            i += 1
            continue

        # Fallback: skip non-log lines
        i += 1

    return logs


def send_logs(logs: list[dict]):
    """Send each log as NDJSON to Vector TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((VECTOR_HOST, VECTOR_PORT))

    sent = 0
    for entry in logs:
        # Build JSON payload with message field for Vector
        payload = {
            "message": entry["raw"],
            "test_batch_id": TEST_BATCH_ID,
            "test_log_num": entry["log_num"],
            "test_category": entry["category"],
            "test_sub_format": entry["sub_format"],
            "timestamp": "2026-03-04T22:30:00.000Z"
        }

        # For JSON Zeek logs, parse and merge the JSON fields for richer classification
        if entry["sub_format"] == "zeek_json":
            try:
                parsed = json.loads(entry["raw"])
                # Send the parsed fields directly so Vector sees src_ip, dst_ip etc.
                payload.update(parsed)
                payload["message"] = entry["raw"]  # keep original as message too
            except json.JSONDecodeError:
                pass

        line = json.dumps(payload, separators=(',', ':')) + "\n"
        sock.sendall(line.encode('utf-8'))
        sent += 1

    sock.shutdown(socket.SHUT_WR)
    sock.close()
    return sent


def main():
    filepath = r"c:\CLIF\tests\combined_test_logs.txt"
    print(f"[*] Extracting logs from {filepath}...")
    logs = extract_logs(filepath)
    print(f"[*] Extracted {len(logs)} log entries")

    # Print breakdown
    from collections import Counter
    cats = Counter(l["category"] for l in logs)
    formats = Counter(l["sub_format"] for l in logs)
    print(f"\n    Category breakdown:")
    for cat, count in sorted(cats.items()):
        print(f"      {cat}: {count}")
    print(f"\n    Format breakdown:")
    for fmt, count in sorted(formats.items()):
        print(f"      {fmt}: {count}")

    print(f"\n[*] Test batch ID: {TEST_BATCH_ID}")
    print(f"[*] Sending {len(logs)} logs to Vector TCP {VECTOR_HOST}:{VECTOR_PORT}...")

    sent = send_logs(logs)
    print(f"[*] Sent {sent} logs successfully")
    print(f"\n[*] Use this batch ID to query results:")
    print(f"    {TEST_BATCH_ID}")


if __name__ == "__main__":
    main()
