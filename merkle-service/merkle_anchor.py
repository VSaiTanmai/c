"""
CLIF Merkle Evidence Chain Service
===================================
Periodically batches events from all 4 ClickHouse tables, computes SHA-256
Merkle trees, stores roots in `evidence_anchors`, and uploads immutable
proof objects to MinIO (S3 Object Lock).

Architecture:
  ┌────────────┐     SHA-256      ┌───────────────┐     S3 PutObject
  │ ClickHouse │ ──► Merkle Tree ─┤ evidence_anchors │ ──► MinIO (locked)
  │ 4 tables   │     per batch    │ (ClickHouse)     │
  └────────────┘                  └───────────────────┘

Run:  python merkle_anchor.py                    (one-shot)
      python merkle_anchor.py --daemon           (continuous every 30s)
      python merkle_anchor.py --verify BATCH-ID  (re-verify a batch)
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from clickhouse_driver import Client as CHClient

try:
    import boto3
    from botocore.config import Config as BotoConfig
    HAS_S3 = True
except ImportError:
    HAS_S3 = False

try:
    import orjson
    def _json_dumps(obj: Any) -> str:
        return orjson.dumps(obj).decode()
except ImportError:
    def _json_dumps(obj: Any) -> str:
        return json.dumps(obj, default=str)

# ── Configuration ────────────────────────────────────────────────────────────

CH_HOST     = os.getenv("CLICKHOUSE_HOST", "localhost")
CH_PORT     = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CH_USER     = os.getenv("CLICKHOUSE_USER", "clif_admin")
CH_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
CH_DB       = os.getenv("CLICKHOUSE_DB", "clif_logs")

S3_ENDPOINT   = os.getenv("MINIO_ENDPOINT", "http://localhost:9002")
S3_ACCESS_KEY = os.getenv("MINIO_ROOT_USER", "")
S3_SECRET_KEY = os.getenv("MINIO_ROOT_PASSWORD", "")
S3_BUCKET     = os.getenv("MINIO_BUCKET_EVIDENCE", "clif-evidence-archive")

BATCH_WINDOW_SEC = int(os.getenv("MERKLE_BATCH_WINDOW", "1800"))   # 30 min
DAEMON_INTERVAL  = int(os.getenv("MERKLE_DAEMON_INTERVAL", "30"))  # seconds
LOG_LEVEL        = os.getenv("LOG_LEVEL", "INFO").upper()

TABLES = [
    "raw_logs", "security_events", "process_events", "network_events",
    "triage_scores", "hunter_investigations", "verifier_results",
]

# Will be set by CLI args if provided
_batch_window: int = BATCH_WINDOW_SEC

logging.basicConfig(
    format="%(asctime)s  %(levelname)-8s  [%(name)s]  %(message)s",
    level=getattr(logging, LOG_LEVEL, logging.INFO),
)
log = logging.getLogger("clif.merkle")

# ── ClickHouse helpers ───────────────────────────────────────────────────────

# Reusable connection pool (thread-local per caller)
_ch_pool: CHClient | None = None


def _ch_client() -> CHClient:
    global _ch_pool
    if _ch_pool is not None:
        try:
            _ch_pool.execute("SELECT 1")
            return _ch_pool
        except Exception:
            log.warning("Cached ClickHouse connection stale, reconnecting")
            _ch_pool = None

    client = CHClient(
        host=CH_HOST, port=CH_PORT,
        user=CH_USER, password=CH_PASSWORD,
        database=CH_DB,
        connect_timeout=10, send_receive_timeout=600,
    )
    _ch_pool = client
    return client


def get_last_anchor_time(ch: CHClient, table: str) -> datetime:
    """Get the latest anchored time window end for a table."""
    rows = ch.execute(
        "SELECT max(time_to) FROM evidence_anchors WHERE table_name = %(t)s",
        {"t": table},
    )
    val = rows[0][0] if rows and rows[0][0] else None
    if val is None:
        # First run — look back from the earliest event
        ts_col = _ts_column(table)
        earliest = ch.execute(f"SELECT min({ts_col}) FROM {table}")
        if earliest and earliest[0][0]:
            return earliest[0][0]
        return datetime.now(timezone.utc)
    return val


# Column helpers — agent tables use different timestamp/ID column names
def _ts_column(table: str) -> str:
    """Return the timestamp column name for a table."""
    if table in ("hunter_investigations", "verifier_results"):
        return "started_at"
    return "timestamp"


def _id_column(table: str) -> str:
    """Return the primary ID column for ordering."""
    if table == "hunter_investigations":
        return "investigation_id"
    if table == "verifier_results":
        return "verification_id"
    if table == "triage_scores":
        return "score_id"
    return "event_id"


def fetch_event_hashes(ch: CHClient, table: str, time_from: datetime, time_to: datetime) -> list[str]:
    """
    Fetch deterministic SHA-256 hashes for every event in the window.
    Uses ClickHouse's built-in hex(SHA256(...)) for speed.
    """
    # Build a deterministic string per row: event_id + timestamp + key fields
    if table == "raw_logs":
        hash_expr = "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(source), toString(level), message)))"
    elif table == "security_events":
        hash_expr = "hex(SHA256(concat(toString(event_id), toString(timestamp), toString(severity), toString(category), toString(source), description, toString(mitre_tactic), toString(mitre_technique))))"
    elif table == "process_events":
        hash_expr = "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, toString(pid), toString(ppid), binary_path, arguments)))"
    elif table == "network_events":
        hash_expr = "hex(SHA256(concat(toString(event_id), toString(timestamp), hostname, IPv4NumToString(src_ip), IPv4NumToString(dst_ip), toString(src_port), toString(dst_port), protocol)))"
    elif table == "triage_scores":
        hash_expr = "hex(SHA256(concat(toString(event_id), toString(timestamp), source_type, hostname, toString(adjusted_score), toString(action), mitre_tactic, mitre_technique)))"
    elif table == "hunter_investigations":
        hash_expr = "hex(SHA256(concat(toString(investigation_id), toString(started_at), hostname, source_ip, toString(severity), finding_type, summary)))"
    elif table == "verifier_results":
        hash_expr = "hex(SHA256(concat(toString(verification_id), toString(started_at), toString(verdict), toString(confidence), toString(priority), analyst_summary)))"
    else:
        raise ValueError(f"Unknown table: {table}")

    # Tables use different timestamp and ID columns
    ts_col = _ts_column(table)
    id_col = _id_column(table)
    rows = ch.execute(
        f"SELECT {hash_expr} AS h FROM {table} "
        f"WHERE {ts_col} >= %(t0)s AND {ts_col} < %(t1)s "
        f"ORDER BY {id_col}",
        {"t0": time_from, "t1": time_to},
    )
    log.info("Fetched %d hashes from %s [%s, %s)", len(rows), table, time_from, time_to)
    return [r[0] for r in rows]


# ── Merkle Tree ──────────────────────────────────────────────────────────────

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def build_merkle_tree(leaf_hashes: list[str]) -> tuple[str, int]:
    """
    Build a binary Merkle tree from leaf hashes.
    Returns (merkle_root, depth).
    If empty, returns a hash of the empty string.
    """
    if not leaf_hashes:
        return sha256_hex("EMPTY_BATCH"), 0

    # Pad to power of 2 by duplicating last leaf
    n = len(leaf_hashes)
    depth = max(1, math.ceil(math.log2(n))) if n > 1 else 1
    target = 2 ** depth
    padded = leaf_hashes + [leaf_hashes[-1]] * (target - n)

    level = padded
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(sha256_hex(combined))
        level = next_level

    return level[0], depth


def verify_merkle_root(leaf_hashes: list[str], expected_root: str) -> bool:
    """Re-compute the Merkle root and compare to stored value."""
    computed, _ = build_merkle_tree(leaf_hashes)
    return computed == expected_root


# ── S3 Object Lock ───────────────────────────────────────────────────────────

def get_s3_client():
    if not HAS_S3:
        return None
    return boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        config=BotoConfig(signature_version="s3v4"),
        region_name="us-east-1",
    )


def ensure_bucket_with_lock(s3) -> bool:
    """Create the evidence bucket with Object Lock if it doesn't exist."""
    if s3 is None:
        return False
    try:
        s3.head_bucket(Bucket=S3_BUCKET)
        return True
    except s3.exceptions.ClientError:
        pass
    try:
        s3.create_bucket(
            Bucket=S3_BUCKET,
            ObjectLockEnabledForBucket=True,
        )
        # Set default retention: GOVERNANCE mode, 365 days
        s3.put_object_lock_configuration(
            Bucket=S3_BUCKET,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "GOVERNANCE",
                        "Days": 365,
                    }
                },
            },
        )
        log.info("Created S3 bucket %s with Object Lock", S3_BUCKET)
        return True
    except Exception as e:
        log.warning("S3 bucket setup failed (non-fatal): %s", e)
        return False


def upload_proof_to_s3(
    s3, batch_id: str, proof: dict
) -> tuple[str, str]:
    """Upload Merkle proof JSON to S3 with Object Lock. Returns (key, version_id)."""
    if s3 is None:
        return "", ""

    key = f"merkle-proofs/{batch_id}.json"
    body = _json_dumps(proof).encode()

    try:
        resp = s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=body,
            ContentType="application/json",
            Metadata={
                "batch-id": batch_id,
                "merkle-root": proof.get("merkle_root", ""),
                "event-count": str(proof.get("event_count", 0)),
            },
        )
        version_id = resp.get("VersionId", "")
        log.info("S3 upload: %s (version=%s)", key, version_id)
        return key, version_id
    except Exception as e:
        log.warning("S3 upload failed (non-fatal): %s", e)
        return key, ""


# ── Anchor Pipeline ──────────────────────────────────────────────────────────

def anchor_batch(
    ch: CHClient,
    s3,
    table: str,
    time_from: datetime,
    time_to: datetime,
    prev_root: str,
) -> dict | None:
    """
    Anchor a single batch:
      1. Fetch event hashes from ClickHouse
      2. Build Merkle tree
      3. Upload proof to S3 (immutable)
      4. Insert anchor record into evidence_anchors
    """
    leaf_hashes = fetch_event_hashes(ch, table, time_from, time_to)
    if not leaf_hashes:
        log.debug("No events in %s [%s, %s)", table, time_from, time_to)
        return None

    merkle_root, depth = build_merkle_tree(leaf_hashes)

    # Chain: include previous root in this batch's identity
    if prev_root:
        chain_hash = sha256_hex(prev_root + merkle_root)
    else:
        chain_hash = merkle_root

    batch_id = f"BATCH-{table}-{time_from.strftime('%Y%m%d-%H%M%S')}"

    # Build proof document
    proof = {
        "batch_id": batch_id,
        "table": table,
        "time_from": time_from.isoformat(),
        "time_to": time_to.isoformat(),
        "event_count": len(leaf_hashes),
        "merkle_root": chain_hash,
        "merkle_depth": depth,
        "prev_merkle_root": prev_root,
        "leaf_count": len(leaf_hashes),
        "sample_leaves": leaf_hashes[:5],  # First 5 for quick verification
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    # S3 upload with Object Lock
    s3_key, s3_version = upload_proof_to_s3(s3, batch_id, proof)

    # Store only first 100 + last 100 leaf hashes to keep storage reasonable
    stored_leaves = leaf_hashes[:100] + leaf_hashes[-100:] if len(leaf_hashes) > 200 else leaf_hashes

    # Insert into ClickHouse
    ch.execute(
        """INSERT INTO evidence_anchors
           (batch_id, table_name, time_from, time_to, event_count,
            merkle_root, merkle_depth, leaf_hashes,
            s3_key, s3_version_id, status, prev_merkle_root)
           VALUES""",
        [{
            "batch_id": batch_id,
            "table_name": table,
            "time_from": time_from,
            "time_to": time_to,
            "event_count": len(leaf_hashes),
            "merkle_root": chain_hash,
            "merkle_depth": depth,
            "leaf_hashes": stored_leaves,
            "s3_key": s3_key,
            "s3_version_id": s3_version,
            "status": "Verified" if s3_key else "Anchored",
            "prev_merkle_root": prev_root,
        }],
    )

    log.info(
        "✓ %s  events=%d  depth=%d  root=%s…  s3=%s",
        batch_id, len(leaf_hashes), depth, chain_hash[:16], s3_key or "N/A",
    )
    return proof


def run_anchor_cycle(ch: CHClient, s3, daemon_mode: bool = False) -> int:
    """Run one anchoring cycle across all tables. Returns total batches created."""
    total = 0

    for table in TABLES:
        # Check if we already have anchors for this table
        existing = ch.execute(
            "SELECT count() FROM evidence_anchors WHERE table_name = %(t)s",
            {"t": table},
        )
        existing_count = existing[0][0] if existing else 0

        if existing_count > 0 and not daemon_mode:
            log.info("Table %s already anchored (%d batches), skipping", table, existing_count)
            continue

        if existing_count > 0 and daemon_mode:
            # Daemon mode: anchor NEW events since last anchor
            last_anchor = get_last_anchor_time(ch, table)
            t_from = last_anchor

            # Get max timestamp (column varies per table)
            ts_col = _ts_column(table)
            range_rows = ch.execute(
                f"SELECT toString(max({ts_col})), count() FROM {table} WHERE {ts_col} > %(since)s",
                {"since": t_from},
            )
            if not range_rows or range_rows[0][1] == 0:
                log.debug("No new events in %s since %s", table, t_from)
                continue

            max_ts_str, event_count = range_rows[0]
            t_to = datetime.strptime(max_ts_str[:19], "%Y-%m-%d %H:%M:%S") + timedelta(seconds=1)
            log.info("Table %s: %d new events since %s", table, event_count, t_from)

            # Get prev root for chaining
            prev_rows = ch.execute(
                "SELECT merkle_root FROM evidence_anchors "
                "WHERE table_name = %(t)s ORDER BY created_at DESC LIMIT 1",
                {"t": table},
            )
            prev_root = prev_rows[0][0] if prev_rows else ""

            cursor = t_from
            batch_num = 0
            while cursor < t_to:
                batch_end = cursor + timedelta(seconds=_batch_window)
                if batch_end > t_to:
                    batch_end = t_to
                result = anchor_batch(ch, s3, table, cursor, batch_end, prev_root)
                if result:
                    prev_root = result["merkle_root"]
                    total += 1
                    batch_num += 1
                cursor = batch_end

            if batch_num > 0:
                log.info("Table %s: created %d new batches", table, batch_num)
            continue

        # Get actual data range (use toString for reliable parsing)
        ts_col = _ts_column(table)
        range_rows = ch.execute(
            f"SELECT toString(min({ts_col})), toString(max({ts_col})), count() FROM {table}"
        )
        if not range_rows or range_rows[0][2] == 0:
            log.info("No events in %s, skipping", table)
            continue

        min_ts_str, max_ts_str, event_count = range_rows[0]
        log.info("Table %s: %d events, range [%s, %s]", table, event_count, min_ts_str, max_ts_str)

        # Parse timestamps reliably from strings
        t_from = datetime.strptime(min_ts_str[:19], "%Y-%m-%d %H:%M:%S")
        t_to = datetime.strptime(max_ts_str[:19], "%Y-%m-%d %H:%M:%S") + timedelta(seconds=1)

        # Get the previous merkle root for chaining
        prev_rows = ch.execute(
            "SELECT merkle_root FROM evidence_anchors "
            "WHERE table_name = %(t)s ORDER BY created_at DESC LIMIT 1",
            {"t": table},
        )
        prev_root = prev_rows[0][0] if prev_rows else ""

        # Create batches in _batch_window intervals
        cursor = t_from
        batch_num = 0
        while cursor < t_to:
            batch_end = cursor + timedelta(seconds=_batch_window)
            if batch_end > t_to:
                batch_end = t_to

            result = anchor_batch(ch, s3, table, cursor, batch_end, prev_root)
            if result:
                prev_root = result["merkle_root"]
                total += 1
                batch_num += 1

            cursor = batch_end

        log.info("Table %s: created %d batches", table, batch_num)

    return total


def verify_batch(ch: CHClient, batch_id: str) -> dict:
    """Re-verify a specific batch by recomputing its Merkle root."""
    rows = ch.execute(
        "SELECT table_name, time_from, time_to, merkle_root, event_count, prev_merkle_root "
        "FROM evidence_anchors WHERE batch_id = %(b)s",
        {"b": batch_id},
    )
    if not rows:
        return {"verified": False, "error": f"Batch {batch_id} not found"}

    table, t_from, t_to, stored_root, stored_count, prev_root = rows[0]

    leaf_hashes = fetch_event_hashes(ch, table, t_from, t_to)
    computed_root, depth = build_merkle_tree(leaf_hashes)

    # Apply chain hash
    if prev_root:
        computed_root = sha256_hex(prev_root + computed_root)

    verified = computed_root == stored_root
    return {
        "batch_id": batch_id,
        "table": table,
        "stored_root": stored_root,
        "computed_root": computed_root,
        "stored_count": stored_count,
        "actual_count": len(leaf_hashes),
        "verified": verified,
        "depth": depth,
        "status": "PASS ✓" if verified else "FAIL ✗ — TAMPERING DETECTED",
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="CLIF Merkle Evidence Chain Service")
    parser.add_argument("--daemon", action="store_true", help="Run continuously")
    parser.add_argument("--verify", type=str, help="Verify a specific batch ID")
    parser.add_argument("--window", type=int, default=BATCH_WINDOW_SEC,
                       help=f"Batch window in seconds (default: {BATCH_WINDOW_SEC})")
    args = parser.parse_args()

    global _batch_window
    _batch_window = args.window

    ch = _ch_client()
    s3 = get_s3_client() if HAS_S3 else None

    if s3:
        ensure_bucket_with_lock(s3)

    if args.verify:
        result = verify_batch(ch, args.verify)
        print(json.dumps(result, indent=2, default=str))
        sys.exit(0 if result["verified"] else 1)

    print("=" * 70)
    print("  CLIF Merkle Evidence Chain Service")
    print("=" * 70)
    print(f"  ClickHouse: {CH_HOST}:{CH_PORT}")
    print(f"  S3:         {S3_ENDPOINT}/{S3_BUCKET}" if s3 else "  S3:         disabled")
    print(f"  Window:     {_batch_window}s")
    print(f"  Mode:       {'daemon' if args.daemon else 'one-shot'}")
    print("=" * 70)

    if args.daemon:
        import signal as _signal
        _running = True

        def _stop(sig, frame):
            nonlocal _running
            log.info("Received signal %s — shutting down gracefully", sig)
            _running = False

        _signal.signal(_signal.SIGINT, _stop)
        _signal.signal(_signal.SIGTERM, _stop)

        while _running:
            try:
                n = run_anchor_cycle(ch, s3, daemon_mode=True)
                if n > 0:
                    log.info("Cycle complete: %d batches anchored", n)
                else:
                    log.debug("Cycle complete: no new events to anchor")
            except Exception as e:
                log.error("Anchor cycle failed: %s", e)
            # Interruptible sleep
            for _ in range(DAEMON_INTERVAL):
                if not _running:
                    break
                time.sleep(1)
        log.info("Merkle service stopped gracefully")
    else:
        n = run_anchor_cycle(ch, s3)
        print(f"\n  Anchored {n} batches across {len(TABLES)} tables.")
        if n == 0:
            print("  (No new events found — run a load test first)")


if __name__ == "__main__":
    main()
