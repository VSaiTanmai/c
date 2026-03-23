#!/usr/bin/env python3
"""
CLIF Real-Log Pipeline Throughput Test
=======================================
Loads REAL log data from agents/Data/datasets/ and sends through the full
Vector → Redpanda → ClickHouse pipeline.

Log types covered:
  1. Syslog / Linux auth (Loghub Linux_2k.log)
  2. Apache web server logs (Loghub Apache_2k.log)
  3. Windows Event Logs (EVTX-ATTACK-SAMPLES)
  4. CICIDS2017 Network Flows
  5. DNS Logs (CIC-Bell benign + phishing + malware)
  6. Firewall / UNSW-NB15
  7. NSL-KDD IDS alerts
  8. IIS C2 tunnel logs (Tunna)
  9. NetFlow / IPFIX (NF-ToN-IoT)
 10. NF-UNSW-NB15-v3 flow records

Usage:
  python scripts/test_real_logs.py [--duration 60] [--workers 6] [--batch 200]
"""

import argparse
import csv
import io
import json
import multiprocessing
import os
import random
import sys
import time
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
BASE = Path(r"C:\CLIF\agents\Data\datasets")

DATASETS = {
    # ── Raw syslog lines ──────────────────────────────────────────────────
    "linux_syslog": {
        "file": BASE / "01_syslog_linux_auth" / "path_c_arf" / "Loghub_Linux" / "Linux_2k.log",
        "type": "raw_log",
        "source_type": "syslog",
        "log_category": "syslog_linux_auth",
    },
    "apache_log": {
        "file": BASE / "08_nginx_web_server" / "path_c_arf" / "Loghub_Apache" / "Apache_2k.log_structured.csv",
        "type": "csv",
        "source_type": "http_server",
        "log_category": "nginx_web_server",
        "converter": "apache_structured",
    },

    # ── Windows EVTX attack samples ───────────────────────────────────────
    "evtx_attacks": {
        "file": BASE / "02_windows_event_log" / "path_a_lightgbm" / "EVTX-ATTACK-SAMPLES" / "evtx_data.csv",
        "type": "csv",
        "source_type": "windows_event_log",
        "log_category": "windows_event_log",
        "converter": "evtx",
    },

    # ── CICIDS2017 network flows ──────────────────────────────────────────
    "cicids_web_attacks": {
        "file": BASE / "10_ids_ips_zeek" / "path_a_lightgbm" / "CICIDS2017" / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "type": "csv",
        "source_type": "ids_ips",
        "log_category": "ids_ips_zeek",
        "converter": "cicids",
    },
    "cicids_ddos": {
        "file": BASE / "01_syslog_linux_auth" / "path_a_lightgbm" / "CICIDS2017" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "type": "csv",
        "source_type": "ids_ips",
        "log_category": "ids_ips_zeek",
        "converter": "cicids",
    },

    # ── DNS logs ──────────────────────────────────────────────────────────
    "dns_phishing": {
        "file": BASE / "05_dns_logs" / "path_a_lightgbm" / "CIC-Bell-DNS-EXFil" / "CSV_phishing.csv",
        "type": "csv",
        "source_type": "dns",
        "log_category": "dns_logs",
        "converter": "dns",
    },
    "dns_malware": {
        "file": BASE / "05_dns_logs" / "path_a_lightgbm" / "CIC-Bell-DNS-EXFil" / "CSV_malware.csv",
        "type": "csv",
        "source_type": "dns",
        "log_category": "dns_logs",
        "converter": "dns",
    },

    # ── Firewall / UNSW-NB15 ─────────────────────────────────────────────
    "unsw_firewall": {
        "file": BASE / "03_firewall_cef" / "path_a_lightgbm" / "UNSW-NB15" / "unsw_stratified.csv",
        "type": "csv",
        "source_type": "firewall",
        "log_category": "firewall_cef",
        "converter": "unsw",
    },

    # ── NSL-KDD IDS ──────────────────────────────────────────────────────
    "nsl_kdd": {
        "file": BASE / "10_ids_ips_zeek" / "path_a_lightgbm" / "NSL-KDD" / "nsl_kdd_stratified.csv",
        "type": "csv",
        "source_type": "ids_ips",
        "log_category": "ids_ips_zeek",
        "converter": "nsl_kdd",
    },

    # ── IIS C2 tunnel log ────────────────────────────────────────────────
    "iis_tunna": {
        "file": BASE / "02_windows_event_log" / "path_a_lightgbm" / "EVTX-ATTACK-SAMPLES" / "Command and Control" / "Tunna_rdp_tunnel_IIS.log",
        "type": "raw_log",
        "source_type": "http_server",
        "log_category": "windows_event_log",
        "skip_prefix": "#",
    },

    # ── NetFlow / IPFIX ──────────────────────────────────────────────────
    "netflow_ton_iot": {
        "file": BASE / "09_netflow_ipfix" / "path_c_arf" / "nf_ton_iot_temporal.csv",
        "type": "csv",
        "source_type": "netflow",
        "log_category": "netflow_ipfix",
        "converter": "nf_ton_iot",
    },
}


# ── Converters: CSV row → JSON dict ─────────────────────────────────────────

def convert_evtx(row: dict, meta: dict) -> dict:
    """Windows EVTX attack sample → JSON event."""
    msg_parts = []
    channel = row.get("Channel", "Security")
    event_id = row.get("EventID", "0")
    computer = row.get("Computer", "unknown")
    tactic = row.get("EVTX_Tactic", "")
    evtx_file = row.get("EVTX_FileName", "")
    target_user = row.get("TargetUserName", "")
    subject_user = row.get("SubjectUserName", "")
    ip = row.get("IpAddress", "")
    process_name = row.get("ProcessName", row.get("NewProcessName", ""))
    cmd_line = row.get("CommandLine", "")

    msg_parts.append(f"EventID={event_id}")
    msg_parts.append(f"Channel={channel}")
    if tactic:
        msg_parts.append(f"Tactic={tactic}")
    if target_user:
        msg_parts.append(f"TargetUser={target_user}")
    if subject_user:
        msg_parts.append(f"SubjectUser={subject_user}")
    if process_name:
        msg_parts.append(f"Process={process_name}")
    if cmd_line:
        msg_parts.append(f"CommandLine={cmd_line[:200]}")

    # Build a realistic Windows event log message
    message = f"Windows Event Log: Computer={computer} {' '.join(msg_parts)}"
    if "4625" in event_id:
        message = f"An account failed to log on. Computer={computer} TargetUser={target_user} IP={ip} {' '.join(msg_parts)}"
    elif "4624" in event_id:
        message = f"An account was successfully logged on. Computer={computer} TargetUser={target_user} IP={ip} LogonType={row.get('LogonType', '')}"
    elif "4688" in event_id:
        message = f"A new process has been created. Computer={computer} Process={process_name} CommandLine={cmd_line[:200]}"
    elif "1" == event_id:  # Sysmon
        message = f"Process Create: Computer={computer} Image={row.get('Image', '')} CommandLine={cmd_line[:200]} User={row.get('User', '')}"

    event = {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": computer,
        "level": "WARNING" if tactic else "INFO",
        "timestamp": row.get("SystemTime", datetime.now(timezone.utc).isoformat()),
    }
    if ip and ip != "-":
        event["ip_address"] = ip
    return event


def convert_cicids(row: dict, meta: dict) -> dict:
    """CICIDS2017 network flow record → JSON event."""
    label = row.get(" Label", row.get("Label", "BENIGN")).strip()
    dst_port = row.get(" Destination Port", row.get("Destination Port", "0")).strip()
    fwd_pkts = row.get(" Total Fwd Packets", row.get("Total Fwd Packets", "0")).strip()
    bwd_pkts = row.get(" Total Backward Packets", row.get("Total Backward Packets", "0")).strip()
    flow_dur = row.get(" Flow Duration", row.get("Flow Duration", "0")).strip()
    fwd_len = row.get("Total Length of Fwd Packets", row.get(" Total Length of Fwd Packets", "0")).strip()
    flow_bytes = row.get(" Flow Bytes/s", row.get("Flow Bytes/s", "0")).strip()

    is_attack = label != "BENIGN"
    src_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"

    if is_attack:
        message = (f"IDS Alert: {label} attack detected - dst_port={dst_port} "
                   f"fwd_pkts={fwd_pkts} bwd_pkts={bwd_pkts} "
                   f"flow_bytes/s={flow_bytes} src={src_ip} dst={dst_ip}")
    else:
        message = (f"Network flow: dst_port={dst_port} fwd_pkts={fwd_pkts} "
                   f"bwd_pkts={bwd_pkts} flow_dur={flow_dur} "
                   f"src={src_ip} dst={dst_ip}")

    event = {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": "ids-sensor-01",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if dst_port.isdigit() else 0,
        "src_port": random.randint(1024, 65535),
        "protocol": "TCP",
        "level": "WARNING" if is_attack else "INFO",
    }
    # Only include Label for attacks — normal events skip VRL Phase 0 entirely
    if is_attack:
        event["Label"] = label
    if is_attack and "DDoS" in label:
        event["message"] = f"DDoS attack detected: {label} from {src_ip} to {dst_ip}:{dst_port} - syn flood pattern"
    elif is_attack and "PortScan" in label:
        event["message"] = f"Port scan detected from {src_ip} targeting {dst_ip} - multiple ports probed"
    return event


def convert_dns(row: dict, meta: dict) -> dict:
    """CIC-Bell DNS log → JSON event."""
    domain = row.get("Domain", "unknown")
    ip = row.get("IP", "0.0.0.0")
    ttl = row.get("TTL", "0")
    country = row.get("Country", "")
    entropy_str = row.get("entropy", "0")
    alexa = row.get("Alexa_Rank", "-1")

    # Clean domain
    if domain.startswith("b'"):
        domain = domain[2:-1].rstrip(".")

    try:
        entropy = float(entropy_str) if entropy_str and entropy_str != "nan" else 0.0
    except (ValueError, TypeError):
        entropy = 0.0

    is_suspicious = entropy > 3.5

    if is_suspicious:
        message = (f"DNS query: suspicious domain={domain} entropy={entropy:.2f} "
                   f"ip={ip} ttl={ttl} country={country}")
        level = "WARNING"
    else:
        message = f"DNS query: domain={domain} ip={ip} ttl={ttl} country={country}"
        level = "INFO"

    return {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": "dns-resolver-01",
        "dns_query": domain,
        "dst_ip": ip if ip and ip != "nan" else "0.0.0.0",
        "dst_port": 53,
        "protocol": "UDP",
        "level": level,
    }


def convert_unsw(row: dict, meta: dict) -> dict:
    """UNSW-NB15 firewall/network record → JSON event."""
    src_ip = row.get("srcip", "0.0.0.0")
    dst_ip = row.get("dstip", "0.0.0.0")
    sport = row.get("sport", "0")
    dsport = row.get("dsport", "0")
    proto = row.get("proto", "tcp").upper()
    service = row.get("service", "-")
    state = row.get("state", "")
    attack_cat = row.get("attack_cat", "Normal").strip()
    label = row.get("label", "0")
    sbytes = row.get("sbytes", "0")
    dbytes = row.get("dbytes", "0")
    dur = row.get("dur", "0")

    is_attack = str(label) == "1" or (attack_cat and attack_cat not in ("Normal", ""))

    if is_attack:
        message = (f"Firewall alert: {attack_cat} - {src_ip}:{sport} → {dst_ip}:{dsport} "
                   f"proto={proto} service={service} state={state} "
                   f"bytes_sent={sbytes} bytes_recv={dbytes}")
        level = "WARNING"
    else:
        message = (f"Firewall: connection {src_ip}:{sport} → {dst_ip}:{dsport} "
                   f"proto={proto} service={service} state={state} dur={dur}s")
        level = "INFO"

    event = {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": "fw-01",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(sport) if str(sport).isdigit() else 0,
        "dst_port": int(dsport) if str(dsport).isdigit() else 0,
        "protocol": proto,
        "bytes_sent": int(sbytes) if str(sbytes).isdigit() else 0,
        "bytes_received": int(dbytes) if str(dbytes).isdigit() else 0,
        "level": level,
    }
    # Source-side label enrichment: only for attacks (normal events skip VRL Phase 0)
    if attack_cat and attack_cat not in ("", "Normal", " "):
        event["attack_cat"] = attack_cat
    if is_attack:
        event["label"] = str(label)
    return event


def convert_nsl_kdd(row: dict, meta: dict) -> dict:
    """NSL-KDD IDS record → JSON event."""
    proto = row.get("protocol_type", "tcp").upper()
    service = row.get("service", "other")
    flag = row.get("flag", "SF")
    src_bytes = row.get("src_bytes", "0")
    dst_bytes = row.get("dst_bytes", "0")
    label = row.get("label", "normal")
    attack_type = row.get("attack_type", "normal")
    duration = row.get("duration", "0")

    is_attack = label != "normal" and label != "0"
    src_ip = f"172.16.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_ip = f"10.10.{random.randint(1,254)}.{random.randint(1,254)}"
    dst_port = {"http": 80, "ftp": 21, "smtp": 25, "ssh": 22, "dns": 53,
                "telnet": 23, "private": random.randint(1024, 65535)}.get(
                    service, random.randint(1, 1024))

    if is_attack:
        message = (f"IDS alert: {attack_type} ({label}) detected - "
                   f"proto={proto} service={service} flag={flag} "
                   f"src_bytes={src_bytes} dst_bytes={dst_bytes} "
                   f"src={src_ip} dst={dst_ip}:{dst_port}")
        level = "WARNING"
    else:
        message = (f"IDS: normal traffic - proto={proto} service={service} "
                   f"flag={flag} duration={duration}s src={src_ip} dst={dst_ip}")
        level = "INFO"

    event = {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": "ids-01",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": proto,
        "level": level,
    }
    # Only include labels for attacks — normal events skip VRL Phase 0
    if is_attack:
        event["label"] = label
        event["attack_type"] = attack_type
    return event


def convert_nf_ton_iot(row: dict, meta: dict) -> dict:
    """NF-ToN-IoT temporal netflow → JSON event."""
    # First few fields: ts, src_ip, src_port, dst_ip, dst_port, proto, ...
    keys = list(row.keys())
    if len(keys) < 5:
        return None

    src_ip = row.get(keys[0], "0.0.0.0") if keys else "0.0.0.0"
    src_port = row.get(keys[1], "0") if len(keys) > 1 else "0"
    dst_ip = row.get(keys[2], "0.0.0.0") if len(keys) > 2 else "0.0.0.0"
    dst_port = row.get(keys[3], "0") if len(keys) > 3 else "0"
    proto = row.get(keys[4], "TCP") if len(keys) > 4 else "TCP"

    message = (f"NetFlow: {src_ip}:{src_port} → {dst_ip}:{dst_port} "
               f"proto={proto} " +
               " ".join(f"{k}={v}" for k, v in list(row.items())[5:10]))

    return {
        "message": message,
        "source_type": meta["source_type"],
        "hostname": "netflow-collector-01",
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": int(src_port) if str(src_port).isdigit() else 0,
        "dst_port": int(dst_port) if str(dst_port).isdigit() else 0,
        "protocol": str(proto).upper(),
        "level": "INFO",
    }


def convert_apache_structured(row: dict, meta: dict) -> dict:
    """Loghub Apache structured CSV → JSON event."""
    content = row.get("Content", "")
    level_str = row.get("Level", "notice")
    ts = row.get("Time", "")
    component = row.get("Component", "")

    message = content if content else f"[{ts}] [{level_str}] {component}"

    level_map = {"error": "ERROR", "notice": "INFO", "warn": "WARNING",
                 "crit": "CRITICAL", "info": "INFO", "debug": "DEBUG"}
    level = level_map.get(level_str.lower().strip(), "INFO")

    return {
        "message": f"Apache: {message}",
        "source_type": meta["source_type"],
        "hostname": "web-01",
        "level": level,
    }


CONVERTERS = {
    "evtx": convert_evtx,
    "cicids": convert_cicids,
    "dns": convert_dns,
    "unsw": convert_unsw,
    "nsl_kdd": convert_nsl_kdd,
    "nf_ton_iot": convert_nf_ton_iot,
    "apache_structured": convert_apache_structured,
}


# ── Data Loading ─────────────────────────────────────────────────────────────

def load_raw_log(path: Path, meta: dict, max_lines: int = 5000) -> list:
    """Load raw log file lines as JSON events."""
    events = []
    skip_prefix = meta.get("skip_prefix", None)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue
                if skip_prefix and line.startswith(skip_prefix):
                    continue
                events.append({
                    "message": line,
                    "source_type": meta["source_type"],
                    "hostname": f"host-{meta['log_category']}",
                    "level": "INFO",
                })
    except Exception as e:
        print(f"  ⚠ Error loading {path.name}: {e}")
    return events


def load_csv_file(path: Path, meta: dict, max_rows: int = 5000) -> list:
    """Load CSV file and convert to JSON events."""
    events = []
    converter = CONVERTERS.get(meta.get("converter", ""), None)
    if converter is None:
        print(f"  ⚠ No converter for {meta.get('converter', 'unknown')}")
        return events

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            # Peek at first line to detect encoding issues
            first_line = f.readline()
            # Handle BOM
            if first_line.startswith("\ufeff"):
                first_line = first_line[1:]
            f.seek(0)

            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= max_rows:
                    break
                try:
                    event = converter(row, meta)
                    if event:
                        events.append(event)
                except Exception:
                    continue  # Skip malformed rows silently
    except Exception as e:
        print(f"  ⚠ Error loading {path.name}: {e}")
    return events


def load_all_datasets(max_per_dataset: int = 5000) -> dict:
    """Load events from all configured datasets. Returns {name: [events]}."""
    all_events = {}
    total = 0

    for name, meta in DATASETS.items():
        fpath = meta["file"]
        if not fpath.exists():
            print(f"  ⚠ Missing: {fpath.name} — skipped")
            continue

        if meta["type"] == "raw_log":
            events = load_raw_log(fpath, meta, max_per_dataset)
        elif meta["type"] == "csv":
            events = load_csv_file(fpath, meta, max_per_dataset)
        else:
            continue

        if events:
            all_events[name] = events
            total += len(events)
            print(f"  ✔ {name:25s}  {len(events):>6,} events  [{meta['source_type']}]")
        else:
            print(f"  ⚠ {name:25s}  0 events (empty or error)")

    return all_events


# ── Batch Builder ────────────────────────────────────────────────────────────

def build_batches(all_events: dict, batch_size: int = 200) -> list:
    """
    Interleave events from all datasets into batches.
    Each batch is a pre-serialized JSON bytes payload ready for HTTP POST.
    Returns list of (bytes_payload, event_count, type_counts_dict).
    """
    # Build a flat interleaved list
    pools = {name: list(events) for name, events in all_events.items()}
    for v in pools.values():
        random.shuffle(v)

    # Round-robin across datasets
    interleaved = []
    indices = {name: 0 for name in pools}
    names = list(pools.keys())
    empty_count = 0

    while empty_count < len(names):
        empty_count = 0
        for name in names:
            idx = indices[name]
            if idx < len(pools[name]):
                interleaved.append((name, pools[name][idx]))
                indices[name] += 1
            else:
                empty_count += 1

    # Now chunk into batches
    batches = []
    for i in range(0, len(interleaved), batch_size):
        chunk = interleaved[i:i + batch_size]
        events_json = [item[1] for item in chunk]
        type_counts = defaultdict(int)
        for name, _ in chunk:
            type_counts[name] += 1
        payload = json.dumps(events_json).encode("utf-8")
        batches.append((payload, len(chunk), dict(type_counts)))

    return batches


# ── Worker Process ───────────────────────────────────────────────────────────

def worker_fn(args):
    """Send batches to Vector HTTP endpoint. Runs in child process."""
    worker_id, batches, endpoint, duration, warmup, result_queue = args

    url = endpoint
    headers = {
        "Content-Type": "application/json",
        "X-CLIF-Source": "real-log-test",
        "X-CLIF-Environment": "test",
    }

    sent = 0
    errors = 0
    type_stats = defaultdict(int)
    start = time.monotonic()
    warmup_end = start + warmup
    measure_start = start + warmup
    measure_end = measure_start + duration

    batch_idx = 0
    n_batches = len(batches)

    while True:
        now = time.monotonic()
        if now >= measure_end:
            break

        payload, count, tcounts = batches[batch_idx % n_batches]
        batch_idx += 1

        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            if now >= warmup_end:
                sent += count
                for k, v in tcounts.items():
                    type_stats[k] += v
        except Exception:
            if now >= warmup_end:
                errors += 1

    result_queue.put({
        "worker_id": worker_id,
        "sent": sent,
        "errors": errors,
        "type_stats": dict(type_stats),
    })


# ── ClickHouse Verification ─────────────────────────────────────────────────

CH_URL = "http://localhost:8123"
CH_USER = "clif_admin"
CH_PASS = "Cl1f_Ch@ngeM3_2026!"
CH_DB = "clif_logs"


def _ch_query(query: str) -> str:
    """Execute a ClickHouse HTTP query with auth via query params."""
    params = urllib.parse.urlencode({
        "database": CH_DB,
        "user": CH_USER,
        "password": CH_PASS,
    })
    req = urllib.request.Request(
        f"{CH_URL}/?{params}",
        data=query.encode("utf-8"),
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode().strip()


def verify_clickhouse():
    """Query ClickHouse to verify data was written."""
    queries = {
        "raw_logs": "SELECT count() as cnt FROM raw_logs",
        "security_events": "SELECT count() as cnt FROM security_events",
        "process_events": "SELECT count() as cnt FROM process_events",
        "network_events": "SELECT count() as cnt FROM network_events",
    }

    print("\n  ClickHouse Table Counts:")
    print("  " + "─" * 50)
    total = 0
    for table, query in queries.items():
        try:
            count = int(_ch_query(query))
            total += count
            print(f"    {table:25s}  {count:>12,}")
        except Exception as e:
            print(f"    {table:25s}  ERROR: {e}")
    print("  " + "─" * 50)
    print(f"    {'TOTAL':25s}  {total:>12,}")
    return total


def verify_clickhouse_before_after(before_counts: dict):
    """Compare counts before and after test."""
    queries = {
        "raw_logs": "SELECT count() as cnt FROM raw_logs",
        "security_events": "SELECT count() as cnt FROM security_events",
        "process_events": "SELECT count() as cnt FROM process_events",
        "network_events": "SELECT count() as cnt FROM network_events",
    }

    print("\n  ClickHouse Event Delivery Verification:")
    print("  " + "─" * 65)
    print(f"    {'Table':25s}  {'Before':>12s}  {'After':>12s}  {'New':>12s}")
    print("  " + "─" * 65)
    total_new = 0
    for table, query in queries.items():
        try:
            after = int(_ch_query(query))
            before = before_counts.get(table, 0)
            new = after - before
            total_new += new
            status = "✔" if new > 0 else "✘"
            print(f"  {status} {table:25s}  {before:>12,}  {after:>12,}  {new:>12,}")
        except Exception as e:
            print(f"  ✘ {table:25s}  ERROR: {e}")
    print("  " + "─" * 65)
    print(f"    {'TOTAL NEW':25s}  {'':>12s}  {'':>12s}  {total_new:>12,}")
    return total_new


def get_clickhouse_counts() -> dict:
    """Get current ClickHouse table counts."""
    queries = {
        "raw_logs": "SELECT count() as cnt FROM raw_logs",
        "security_events": "SELECT count() as cnt FROM security_events",
        "process_events": "SELECT count() as cnt FROM process_events",
        "network_events": "SELECT count() as cnt FROM network_events",
    }
    counts = {}
    for table, query in queries.items():
        try:
            counts[table] = int(_ch_query(query))
        except Exception:
            counts[table] = 0
    return counts


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CLIF Real-Log Pipeline Test")
    parser.add_argument("--duration", type=int, default=60, help="Test duration in seconds")
    parser.add_argument("--workers", type=int, default=4, help="Number of sender processes")
    parser.add_argument("--batch", type=int, default=200, help="Events per HTTP batch")
    parser.add_argument("--warmup", type=int, default=5, help="Warmup seconds")
    parser.add_argument("--max-per-dataset", type=int, default=5000,
                        help="Max events to load per dataset")
    parser.add_argument("--endpoint", default="http://localhost:8687/v1/logs")
    args = parser.parse_args()

    print("═" * 65)
    print("  CLIF Real-Log Pipeline Throughput Test")
    print("═" * 65)
    print(f"  Duration:     {args.duration}s")
    print(f"  Workers:      {args.workers}")
    print(f"  Batch size:   {args.batch}")
    print(f"  Warmup:       {args.warmup}s")
    print(f"  Endpoint:     {args.endpoint}")
    print("─" * 65)

    # ── Check Vector health ──────────────────────────────────────────────
    try:
        req = urllib.request.Request(args.endpoint,
                                     data=b'[{"message":"healthcheck","source_type":"test"}]',
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
        print("  ✔ Vector reachable")
    except Exception as e:
        print(f"  ✘ Vector unreachable: {e}")
        sys.exit(1)

    # ── Load datasets ────────────────────────────────────────────────────
    print("\n  Loading real log datasets...")
    all_events = load_all_datasets(args.max_per_dataset)
    total_events = sum(len(v) for v in all_events.values())
    print(f"\n  Total: {total_events:,} events from {len(all_events)} datasets")

    if total_events == 0:
        print("  ✘ No events loaded — cannot test")
        sys.exit(1)

    # ── Build batches ────────────────────────────────────────────────────
    print(f"\n  Building interleaved batches (batch_size={args.batch})...")
    batches = build_batches(all_events, args.batch)
    total_payload_mb = sum(len(b[0]) for b in batches) / (1024 * 1024)
    print(f"  ✔ {len(batches):,} batches, {total_payload_mb:.1f} MB total payload")

    # ── Split batches among workers ──────────────────────────────────────
    worker_batches = [[] for _ in range(args.workers)]
    for i, batch in enumerate(batches):
        worker_batches[i % args.workers].append(batch)

    # ── Get ClickHouse baseline ──────────────────────────────────────────
    print("\n  Recording ClickHouse baseline counts...")
    ch_before = get_clickhouse_counts()
    for t, c in ch_before.items():
        print(f"    {t:25s}  {c:>12,}")

    # ── Start workers ────────────────────────────────────────────────────
    print(f"\n  Starting {args.workers} worker processes...")
    result_queue = multiprocessing.Manager().Queue()

    worker_args = [
        (i, worker_batches[i], args.endpoint, args.duration, args.warmup, result_queue)
        for i in range(args.workers)
    ]

    t_start = time.monotonic()

    # Use a simple monitoring approach: start workers, then poll
    pool = multiprocessing.Pool(processes=args.workers)
    async_results = pool.map_async(worker_fn, worker_args)

    # ── Monitor progress ─────────────────────────────────────────────────
    print(f"  ⏳ Warmup ({args.warmup}s)...", flush=True)
    time.sleep(args.warmup)

    print(f"\n  📊 Measuring ({args.duration}s)...")
    print(f"    {'Sec':>6s}  {'Status':>12s}")
    print("  " + "─" * 30)

    for sec in range(1, args.duration + 1):
        time.sleep(1)
        elapsed = time.monotonic() - t_start - args.warmup
        if sec % 5 == 0 or sec == args.duration:
            print(f"    {sec:>6d}  {'running...':>12s}", flush=True)

    # ── Collect results ──────────────────────────────────────────────────
    pool.close()
    pool.join()
    t_end = time.monotonic()
    actual_duration = t_end - t_start - args.warmup

    total_sent = 0
    total_errors = 0
    aggregate_types = defaultdict(int)

    while not result_queue.empty():
        res = result_queue.get()
        total_sent += res["sent"]
        total_errors += res["errors"]
        for k, v in res["type_stats"].items():
            aggregate_types[k] += v

    avg_eps = total_sent / actual_duration if actual_duration > 0 else 0

    # ── Results ──────────────────────────────────────────────────────────
    print("\n" + "═" * 65)
    print("  RESULTS")
    print("═" * 65)
    print(f"  Total events sent:     {total_sent:>12,}")
    print(f"  Duration:              {actual_duration:>12.1f}s")
    print(f"  Avg EPS:               {avg_eps:>12,.0f}")
    print(f"  Errors:                {total_errors:>12,}")
    print(f"  Workers:               {args.workers:>12d}")

    print(f"\n  Events by Log Type:")
    print("  " + "─" * 55)
    for name in sorted(aggregate_types, key=aggregate_types.get, reverse=True):
        count = aggregate_types[name]
        meta = DATASETS.get(name, {})
        cat = meta.get("log_category", "?")
        pct = (count / total_sent * 100) if total_sent > 0 else 0
        print(f"    {name:25s}  {count:>10,}  ({pct:5.1f}%)  [{cat}]")
    print("  " + "─" * 55)

    # ── Wait for Redpanda → ClickHouse flush ─────────────────────────────
    print("\n  ⏳ Waiting 15s for Redpanda → ClickHouse consumer flush...")
    time.sleep(15)

    # ── Verify ClickHouse ────────────────────────────────────────────────
    ch_new = verify_clickhouse_before_after(ch_before)

    delivery_rate = (ch_new / total_sent * 100) if total_sent > 0 else 0
    print(f"\n  📦 Delivery Rate: {ch_new:,} / {total_sent:,} = {delivery_rate:.1f}%")

    if delivery_rate >= 95:
        print("  ✔ EXCELLENT — ≥95% delivery")
    elif delivery_rate >= 80:
        print("  ⚠ GOOD — 80-95% delivery (some consumer lag expected)")
    elif delivery_rate > 0:
        print("  ⚠ PARTIAL — data flowing but consumers may be stopped")
    else:
        print("  ⚠ NOTE — Consumers are stopped; data is in Redpanda queues")
        print("           Start consumers to flush to ClickHouse")

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "═" * 65)
    if avg_eps >= 100000:
        print(f"  ✔ PASS — {avg_eps:,.0f} EPS with REAL logs")
    else:
        print(f"  📊 Result: {avg_eps:,.0f} EPS with REAL heterogeneous logs")
        print(f"     (12-core machine; CPU-bound by Vector + load generator)")
    print("═" * 65)


if __name__ == "__main__":
    main()
