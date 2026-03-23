#!/usr/bin/env python3
"""Send exactly ~50k real log events through Vector for pipeline testing."""
import csv
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

VECTOR_HOST = "localhost"
TCP_PORT = 9514    # NDJSON
SYSLOG_PORT = 1514 # Syslog
DATA_DIR = r"C:\CLIF\agents\Data\Latest_Dataset"

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def send_syslog_lines(sock, filepath, max_lines=0):
    """Send raw syslog lines through TCP syslog port."""
    if not os.path.exists(filepath):
        print(f"  [SKIP] {filepath}")
        return 0
    count = 0
    batch = bytearray()
    with open(filepath, "r", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            if raw.startswith("<"):
                batch.extend(raw.encode("utf-8", errors="replace") + b"\n")
            else:
                batch.extend(b"<34>" + raw.encode("utf-8", errors="replace") + b"\n")
            count += 1
            if len(batch) > 256 * 1024:
                sock.sendall(bytes(batch))
                batch = bytearray()
            if max_lines and count >= max_lines:
                break
    if batch:
        sock.sendall(bytes(batch))
    return count

def send_csv_as_ndjson(sock, filepath, source_name, max_rows=0):
    """Convert CSV rows to NDJSON and send through TCP port."""
    if not os.path.exists(filepath):
        print(f"  [SKIP] {filepath}")
        return 0
    count = 0
    batch = bytearray()
    with open(filepath, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return 0
        for row in reader:
            event = {"timestamp": now_iso(), "source_dataset": source_name}
            for k, v in row.items():
                if k and v is not None:
                    clean_k = k.strip().replace(" ", "_").replace("/", "_")
                    event[clean_k] = v.strip() if isinstance(v, str) else v
            line = json.dumps(event) + "\n"
            batch.extend(line.encode("utf-8"))
            count += 1
            if len(batch) > 256 * 1024:
                sock.sendall(bytes(batch))
                batch = bytearray()
            if max_rows and count >= max_rows:
                break
    if batch:
        sock.sendall(bytes(batch))
    return count

def main():
    print("\n" + "="*60)
    print("  CLIF 50K Real-Data Pipeline Test")
    print("="*60)

    # ── Syslog data ──
    print("\n[1/2] Sending syslog data to Vector :1514 ...")
    syslog_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    syslog_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    syslog_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    try:
        syslog_sock.connect((VECTOR_HOST, SYSLOG_PORT))
    except Exception as e:
        print(f"  FAILED to connect syslog port {SYSLOG_PORT}: {e}")
        sys.exit(1)

    total = 0
    t0 = time.monotonic()

    # Linux.log — 25,567 lines (all)
    n = send_syslog_lines(syslog_sock, os.path.join(DATA_DIR, "01_Syslog", "Linux.log"))
    print(f"  Linux.log:       {n:>8,} lines")
    total += n

    # OpenSSH_2k.log — 2,000 lines (all)
    n = send_syslog_lines(syslog_sock, os.path.join(DATA_DIR, "01_Syslog", "OpenSSH_2k.log"))
    print(f"  OpenSSH_2k.log:  {n:>8,} lines")
    total += n

    # Linux_2k.log — 2,000 lines (all)
    n = send_syslog_lines(syslog_sock, os.path.join(DATA_DIR, "01_Syslog", "loghub-linux", "Linux_2k.log"))
    print(f"  Linux_2k.log:    {n:>8,} lines")
    total += n

    syslog_sock.close()
    syslog_elapsed = time.monotonic() - t0
    print(f"  Syslog subtotal: {total:>8,} events ({syslog_elapsed:.1f}s)")

    # ── NDJSON data ──
    print("\n[2/2] Sending NDJSON data to Vector :9514 ...")
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    try:
        tcp_sock.connect((VECTOR_HOST, TCP_PORT))
    except Exception as e:
        print(f"  FAILED to connect TCP port {TCP_PORT}: {e}")
        sys.exit(1)

    t1 = time.monotonic()

    # EVTX attack data — ~10K rows
    n = send_csv_as_ndjson(tcp_sock,
        os.path.join(DATA_DIR, "02_Windows_Event", "evtx_attack_data.csv"),
        "evtx_attack_samples")
    print(f"  evtx_attack:     {n:>8,} rows")
    total += n

    # CICIDS2017 — 10K rows
    n = send_csv_as_ndjson(tcp_sock,
        os.path.join(DATA_DIR, "10_IDS_IPS", "cicids2017_stratified.csv"),
        "cicids2017", max_rows=10000)
    print(f"  cicids2017:      {n:>8,} rows")
    total += n

    # NSL-KDD — remaining to reach ~50K
    remaining = max(50000 - total, 0)
    if remaining > 0:
        n = send_csv_as_ndjson(tcp_sock,
            os.path.join(DATA_DIR, "10_IDS_IPS", "nsl_kdd_stratified.csv"),
            "nsl_kdd", max_rows=remaining)
        print(f"  nsl_kdd:         {n:>8,} rows")
        total += n

    tcp_sock.close()
    total_elapsed = time.monotonic() - t0

    print(f"\n{'='*60}")
    print(f"  TOTAL SENT: {total:>10,} events")
    print(f"  ELAPSED:    {total_elapsed:>10.1f}s")
    print(f"  AVG EPS:    {int(total/total_elapsed) if total_elapsed > 0 else 0:>10,}")
    print(f"{'='*60}")
    print(f"\n  Pipeline: Script → Vector → Redpanda → Consumer → ClickHouse")
    print(f"  Wait 30-60s for Go consumer batch flush, then check ClickHouse.\n")

if __name__ == "__main__":
    main()
