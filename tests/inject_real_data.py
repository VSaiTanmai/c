#!/usr/bin/env python3
"""
CLIF Pipeline Test — Real Training Data Injector
====================================================
Reads features_combined_features.csv (87K rows of REAL training data)
and constructs Kafka messages that the Triage Agent will consume.

The CSV columns are the 20 canonical features + label + attack_type + source_dataset.
We construct JSON events with raw fields so the feature extractor will produce
values that correspond closely to the pre-computed training features.

TopicMapping:
  - source_dataset containing "cicids2017"      → security-events  (mixed attacks)
  - source_dataset containing "nsl_kdd"         → network-events   (KDD-style)
  - source_dataset containing "unsw_nb15"       → network-events
  - source_dataset containing "nf_unsw_nb15_v3" → raw-logs         (netflow logs)

Usage:
  pip install confluent-kafka   (on the host, or run inside a Docker container)
  python tests/inject_real_data.py [--rows N] [--batch-size N] [--brokers BROKERS]
"""

import argparse
import csv
import json
import os
import random
import string
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta

# ── Confluent Kafka ──────────────────────────────────────────────────────
try:
    from confluent_kafka import Producer
except ImportError:
    print("ERROR: confluent-kafka not installed. Run: pip install confluent-kafka")
    sys.exit(1)

# ── Source dataset → topic mapping ────────────────────────────────────────
DATASET_TOPIC_MAP = {
    "cicids2017": "security-events",
    "nsl_kdd": "network-events",
    "unsw_nb15": "network-events",
    "nf_unsw_nb15_v3": "raw-logs",
}

# ── Reverse source_type_numeric → source_type string ─────────────────────
SOURCE_TYPE_NUM_TO_STR = {
    0: "unknown",
    1: "syslog",
    2: "windows_event",
    3: "firewall",
    4: "active_directory",
    5: "dns",
    6: "cloudtrail",
    7: "kubernetes",
    8: "nginx",
    9: "netflow",
    10: "ids_ips",
}

# ── Protocol numeric → string ────────────────────────────────────────────
PROTOCOL_NUM_TO_STR = {
    0: "icmp",
    6: "tcp",
    17: "udp",
}

# ── Severity numeric → string ───────────────────────────────────────────
SEVERITY_NUM_TO_STR = {
    0: "debug",
    1: "info",
    2: "notice",
    3: "warning",
    4: "error",
    5: "critical",
}

# ── Attack type → severity hint ─────────────────────────────────────────
ATTACK_SEVERITY = {
    "BENIGN": "info",
    "normal": "info",
    "SSH-Patator": "warning",
    "FTP-Patator": "warning",
    "PortScan": "notice",
    "Bot": "error",
    "DDoS": "critical",
    "DoS Hulk": "error",
    "DoS GoldenEye": "error",
    "DoS Slowloris": "error",
    "DoS Slowhttptest": "error",
    "Heartbleed": "critical",
    "Web Attack - Brute Force": "warning",
    "Web Attack - XSS": "warning",
    "Web Attack - SQL Injection": "critical",
    "Infiltration": "critical",
    "Fuzzers": "warning",
    "Analysis": "notice",
    "Backdoor": "critical",
    "Backdoors": "critical",
    "Exploits": "critical",
    "Generic": "warning",
    "Reconnaissance": "notice",
    "Shellcode": "critical",
    "Worms": "critical",
}

# ── Sample IPs for constructing realistic events ─────────────────────────
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "10.0.0.5", "10.0.0.15", "10.0.0.25", "10.0.1.10",
    "172.16.0.100", "172.16.0.200",
]

EXTERNAL_IPS = [
    "203.0.113.5", "203.0.113.50", "198.51.100.10", "198.51.100.20",
    "185.220.101.1", "45.33.32.156", "104.16.85.20", "93.184.216.34",
    "8.8.8.8", "1.1.1.1",
]

HOSTNAMES = [
    "srv-web-01", "srv-db-01", "srv-app-01", "srv-cache-01",
    "fw-edge-01", "dc-main-01", "dns-ns1", "k8s-node-01",
    "log-collector-01", "ids-sensor-01",
]

# ── Message templates for log body ──────────────────────────────────────
MSG_TEMPLATES_NORMAL = [
    "Connection established from {src} to {dst}:{port}",
    "Session started for user {user} from {src}",
    "HTTP GET /api/v1/status 200 OK from {src}",
    "DNS query resolved: {domain} → {dst}",
    "Scheduled task completed: backup_daily",
    "User authentication successful: {user}",
    "TLS handshake completed with {dst}:{port}",
    "Heartbeat received from {src}",
]

MSG_TEMPLATES_ATTACK = [
    "Multiple failed login attempts from {src} for user {user}",
    "Suspicious port scan detected from {src} targeting {dst}",
    "Anomalous traffic pattern: {src} → {dst}:{port} ({proto})",
    "Potential brute force: {count} attempts in {window}s from {src}",
    "Connection flood detected from {src}: {count} SYN packets",
    "Payload anomaly detected in {proto} traffic from {src}",
    "Unauthorized access attempt from {src} to {dst}:{port}",
    "NIDS alert: signature match for {attack_type} from {src}",
]


def delivery_callback(err, msg):
    """Kafka producer delivery callback."""
    if err:
        print(f"  ERROR: Delivery failed: {err}")


def build_event(row: dict, row_idx: int) -> tuple:
    """
    Build a realistic JSON event from a CSV feature row.

    Returns (topic, event_dict)
    """
    source_dataset = row.get("source_dataset", "unknown").strip()
    attack_type = row.get("attack_type", "BENIGN").strip()
    label = int(float(row.get("label", 0)))

    # ── Determine topic ──────────────────────────────────────────────────
    topic = "raw-logs"  # default
    for ds_prefix, t in DATASET_TOPIC_MAP.items():
        if ds_prefix in source_dataset:
            topic = t
            break

    # ── Parse features ───────────────────────────────────────────────────
    hour = int(float(row.get("hour_of_day", 0)))
    dow = int(float(row.get("day_of_week", 0)))
    severity_num = int(float(row.get("severity_numeric", 1)))
    src_type_num = int(float(row.get("source_type_numeric", 1)))
    src_bytes = float(row.get("src_bytes", 0))
    dst_bytes = float(row.get("dst_bytes", 0))
    duration = float(row.get("duration", 0))
    protocol_num = int(float(row.get("protocol", 6)))
    dst_port = int(float(row.get("dst_port", 0)))
    threat_intel = int(float(row.get("threat_intel_flag", 0)))

    # ── Build timestamp ──────────────────────────────────────────────────
    # Use current date but set hour/day_of_week from features
    now = datetime.now(timezone.utc)
    # Adjust to match training feature's hour
    ts = now.replace(hour=hour % 24, minute=random.randint(0, 59),
                     second=random.randint(0, 59), microsecond=0)
    ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    # ── Choose IPs ──────────────────────────────────────────────────────
    src_ip = random.choice(EXTERNAL_IPS if label == 1 else INTERNAL_IPS)
    dst_ip = random.choice(INTERNAL_IPS)
    hostname = random.choice(HOSTNAMES)
    user = random.choice(["admin", "root", "svc-app", "deploy", "operator"])

    # ── Source type ──────────────────────────────────────────────────────
    source_type_str = SOURCE_TYPE_NUM_TO_STR.get(src_type_num, "unknown")
    protocol_str = PROTOCOL_NUM_TO_STR.get(protocol_num, "tcp")
    severity_str = ATTACK_SEVERITY.get(attack_type, SEVERITY_NUM_TO_STR.get(severity_num, "info"))

    # ── Build message body ───────────────────────────────────────────────
    is_network = topic == "network-events"
    if label == 1:
        tpl = random.choice(MSG_TEMPLATES_ATTACK)
    else:
        tpl = random.choice(MSG_TEMPLATES_NORMAL)

    msg_body = tpl.format(
        src=src_ip, dst=dst_ip, port=int(dst_port),
        proto=protocol_str, user=user,
        count=random.randint(10, 500),
        window=random.choice([30, 60, 120]),
        domain=random.choice(["api.internal.com", "cdn.example.com", "ns1.corp.local"]),
        attack_type=attack_type,
    )

    # ── Construct base event ─────────────────────────────────────────────
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts_str,
        "hostname": hostname,
        "source_type": source_type_str,
        "severity": severity_str,
        "message": msg_body,
        "label": label,           # Ground truth — agent should NOT use this
        "attack_type": attack_type,
        "source_dataset": source_dataset,
    }

    # ── Network-specific fields ──────────────────────────────────────────
    if is_network or src_type_num == 9:
        event.update({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": random.randint(1024, 65535),
            "dst_port": int(dst_port),
            "protocol": protocol_str,
            "bytes_sent": src_bytes,
            "bytes_received": dst_bytes,
            "duration_ms": duration * 1000,  # convert seconds to ms
            "direction": random.choice(["inbound", "outbound"]),
        })
    else:
        # Non-network events still can have IP fields
        event.update({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": int(dst_port),
        })

    return topic, event


def main():
    parser = argparse.ArgumentParser(description="CLIF Real Data Injector")
    parser.add_argument("--csv", default=os.path.join(
        os.path.dirname(__file__), "..", "agents", "Data",
        "features_combined_features.csv"),
        help="Path to features CSV")
    parser.add_argument("--rows", type=int, default=0,
                        help="Max rows to inject (0=all)")
    parser.add_argument("--batch-size", type=int, default=5000,
                        help="Kafka produce batch size before flush")
    parser.add_argument("--brokers", default="localhost:19092,localhost:29092,localhost:39092",
                        help="Kafka broker list")
    parser.add_argument("--delay-ms", type=float, default=0,
                        help="Delay between batches in ms (0=none)")
    parser.add_argument("--shuffle", action="store_true", default=True,
                        help="Shuffle rows before injecting")
    args = parser.parse_args()

    csv_path = os.path.abspath(args.csv)
    print(f"CLIF Real Data Injector")
    print(f"=======================")
    print(f"CSV:     {csv_path}")
    print(f"Brokers: {args.brokers}")
    print(f"Max rows: {'ALL' if args.rows == 0 else args.rows}")
    print(f"Batch:   {args.batch_size}")
    print()

    if not os.path.exists(csv_path):
        print(f"ERROR: CSV not found: {csv_path}")
        sys.exit(1)

    # ── Read CSV ─────────────────────────────────────────────────────────
    print("Reading CSV...")
    rows = []
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    total = len(rows)
    print(f"  Loaded {total:,} rows")

    if args.rows > 0:
        rows = rows[:args.rows]
        print(f"  Truncated to {len(rows):,} rows")

    if args.shuffle:
        random.shuffle(rows)
        print("  Shuffled")

    # ── Count by dataset / label ─────────────────────────────────────────
    ds_counts = {}
    label_counts = {0: 0, 1: 0}
    for r in rows:
        ds = r.get("source_dataset", "unknown")
        ds_counts[ds] = ds_counts.get(ds, 0) + 1
        lbl = int(float(r.get("label", 0)))
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    print(f"\n  Dataset distribution:")
    for ds, cnt in sorted(ds_counts.items()):
        topic = "raw-logs"
        for pfx, t in DATASET_TOPIC_MAP.items():
            if pfx in ds:
                topic = t
                break
        print(f"    {ds}: {cnt:,} → {topic}")
    print(f"  Labels: normal={label_counts[0]:,}, malicious={label_counts[1]:,}")

    # ── Create Kafka producer ────────────────────────────────────────────
    print(f"\nConnecting to Kafka: {args.brokers}")
    producer = Producer({
        "bootstrap.servers": args.brokers,
        "queue.buffering.max.messages": 500000,
        "queue.buffering.max.kbytes": 1048576,  # 1GB
        "batch.num.messages": 10000,
        "linger.ms": 50,
        "compression.type": "lz4",
        "acks": "1",
    })

    # ── Produce events ───────────────────────────────────────────────────
    print(f"\nInjecting {len(rows):,} events...\n")
    topic_counts = {}
    errors = 0
    t0 = time.monotonic()

    for i, row in enumerate(rows):
        try:
            topic, event = build_event(row, i)
            payload = json.dumps(event).encode("utf-8")

            producer.produce(
                topic=topic,
                value=payload,
                callback=delivery_callback,
            )

            topic_counts[topic] = topic_counts.get(topic, 0) + 1

        except BufferError:
            # Queue full — flush and retry
            producer.flush(timeout=10)
            producer.produce(
                topic=topic,
                value=payload,
                callback=delivery_callback,
            )
            topic_counts[topic] = topic_counts.get(topic, 0) + 1

        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"  ERROR at row {i}: {e}")

        # Periodic flush + progress
        if (i + 1) % args.batch_size == 0:
            producer.flush(timeout=30)
            elapsed = time.monotonic() - t0
            eps = (i + 1) / elapsed if elapsed > 0 else 0
            print(f"  [{i+1:>7,}/{len(rows):,}] {eps:,.0f} events/sec | "
                  f"topics: {dict(sorted(topic_counts.items()))}")

            if args.delay_ms > 0:
                time.sleep(args.delay_ms / 1000.0)

    # Final flush
    print("\nFlushing remaining messages...")
    remaining = producer.flush(timeout=60)
    elapsed = time.monotonic() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"INJECTION COMPLETE")
    print(f"{'='*60}")
    print(f"Total events:  {len(rows):,}")
    print(f"Errors:        {errors}")
    print(f"Unflushed:     {remaining}")
    print(f"Time:          {elapsed:.1f}s")
    print(f"Throughput:    {len(rows)/elapsed:,.0f} events/sec")
    print(f"\nTopic breakdown:")
    for topic, cnt in sorted(topic_counts.items()):
        print(f"  {topic}: {cnt:,}")
    print(f"\nLabels: normal={label_counts[0]:,}, malicious={label_counts[1]:,}")
    print(f"\nNow check triage agent processing:")
    print(f"  docker logs clif-triage-agent --tail 50")
    print(f"  curl http://localhost:8300/stats")


if __name__ == "__main__":
    main()
