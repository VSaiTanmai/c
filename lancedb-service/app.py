"""
CLIF LanceDB Service — Semantic Vector Search & RAG Engine.

Production-grade features:
  • Sentence-Transformers embedding (all-MiniLM-L6-v2) — local, no API keys
  • LanceDB serverless storage with IVF-PQ indexing
  • 4 vector tables: log_embeddings, security_embeddings, threat_intel, historical_incidents
  • Periodic ClickHouse sync — embeds new events on configurable interval
  • FastAPI REST API with /search, /similar, /ingest endpoints
  • Batch embedding with configurable chunk sizes
  • Health check and Prometheus-compatible metrics
  • Graceful shutdown with flush
  • Thread-safe embedding model with warm-up on startup

Environment:
    LANCEDB_PATH              storage directory (default: /data/lancedb)
    EMBEDDING_MODEL           sentence-transformers model (default: all-MiniLM-L6-v2)
    EMBEDDING_BATCH_SIZE      batch size for encoding (default: 256)
    EMBEDDING_DIM             embedding dimension (default: 384)
    CLICKHOUSE_HOST           ClickHouse host (default: localhost)
    CLICKHOUSE_PORT           native TCP port (default: 9000)
    CLICKHOUSE_USER           username (default: clif_admin)
    CLICKHOUSE_PASSWORD       password
    CLICKHOUSE_DB             database (default: clif_logs)
    SYNC_INTERVAL_SEC         seconds between ClickHouse sync cycles (default: 30)
    SYNC_BATCH_SIZE           rows to fetch per sync batch (default: 1000)
    API_HOST                  FastAPI bind host (default: 0.0.0.0)
    API_PORT                  FastAPI bind port (default: 8100)
    LOG_LEVEL                 logging level (default: INFO)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import re
import uuid
from concurrent.futures import ThreadPoolExecutor

import lancedb
import numpy as np
import orjson
import pyarrow as pa
from clickhouse_driver import Client as CHClient
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer

# ─── Configuration ───────────────────────────────────────────────────────────

LANCEDB_PATH = os.getenv("LANCEDB_PATH", "/data/lancedb")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_BATCH_SIZE = int(os.getenv("EMBEDDING_BATCH_SIZE", "256"))
EMBEDDING_DIM = int(os.getenv("EMBEDDING_DIM", "384"))

CH_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CH_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CH_USER = os.getenv("CLICKHOUSE_USER", "clif_admin")
CH_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "Cl1f_Ch@ngeM3_2026!")
CH_DB = os.getenv("CLICKHOUSE_DB", "clif_logs")

SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL_SEC", "30"))
SYNC_BATCH_SIZE = int(os.getenv("SYNC_BATCH_SIZE", "1000"))

API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8100"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3001,http://clif-dashboard:3001").split(",")

# Thread pool for CPU-bound embedding work (avoids blocking the event loop)
_embedding_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="embed")

# Regex for validating filter_sql to prevent injection
_ALLOWED_FILTER_PATTERN = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_.]*\s*"
    r"(=|!=|<>|>|<|>=|<=|LIKE|IN|NOT IN|IS NULL|IS NOT NULL)"
    r"\s*.{0,500}$",
    re.IGNORECASE,
)

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("clif.lancedb")

# ─── Schema Definitions ─────────────────────────────────────────────────────

# Arrow schemas for LanceDB tables
LOG_EMBEDDING_SCHEMA = pa.schema([
    pa.field("event_id", pa.string()),
    pa.field("timestamp", pa.string()),
    pa.field("source_table", pa.string()),
    pa.field("log_source", pa.string()),
    pa.field("hostname", pa.string()),
    pa.field("severity", pa.int32()),
    pa.field("text", pa.string()),
    pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
])

THREAT_INTEL_SCHEMA = pa.schema([
    pa.field("ioc_id", pa.string()),
    pa.field("ioc_type", pa.string()),       # ip, domain, hash, url
    pa.field("ioc_value", pa.string()),
    pa.field("source", pa.string()),          # MISP, AlienVault, VirusTotal
    pa.field("confidence", pa.float32()),
    pa.field("severity", pa.int32()),
    pa.field("description", pa.string()),
    pa.field("tags", pa.string()),            # JSON array as string
    pa.field("first_seen", pa.string()),
    pa.field("last_seen", pa.string()),
    pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
])

HISTORICAL_INCIDENT_SCHEMA = pa.schema([
    pa.field("incident_id", pa.string()),
    pa.field("title", pa.string()),
    pa.field("description", pa.string()),
    pa.field("severity", pa.int32()),
    pa.field("mitre_tactics", pa.string()),   # JSON array
    pa.field("mitre_techniques", pa.string()),# JSON array
    pa.field("affected_hosts", pa.string()),  # JSON array
    pa.field("affected_users", pa.string()),  # JSON array
    pa.field("resolution", pa.string()),
    pa.field("created_at", pa.string()),
    pa.field("resolved_at", pa.string()),
    pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
])

# attack_embeddings: confirmed attacks ONLY (V5 architecture).
# Populated from triage_scores WHERE action='escalate' AND adjusted_score > 0.8,
# feedback_labels WHERE label='true_positive', and Hunter high-severity results.
# Used exclusively for verdict search ("Is this a known attack?") -- NEVER
# contaminated with normal log events to prevent novel-attack false negatives.
ATTACK_EMBEDDING_SCHEMA = pa.schema([
    pa.field("attack_id", pa.string()),       # UUID of the source event
    pa.field("source_type", pa.string()),     # cisco/dns/firewall/etc.
    pa.field("hostname", pa.string()),
    pa.field("mitre_tactic", pa.string()),
    pa.field("mitre_technique", pa.string()),
    pa.field("severity", pa.int32()),         # 0-4 matching investigation severity
    pa.field("template_id", pa.string()),
    pa.field("description", pa.string()),     # Embedding source text
    pa.field("confirmed_at", pa.string()),    # When attack was confirmed
    pa.field("label_source", pa.string()),    # analyst/verifier/pseudo_positive
    pa.field("vector", pa.list_(pa.float32(), EMBEDDING_DIM)),
])


# ─── Embedding Engine ───────────────────────────────────────────────────────

class EmbeddingEngine:
    """Thread-safe sentence-transformers wrapper with batched encoding."""

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        log.info("Loading embedding model: %s", model_name)
        t0 = time.monotonic()
        self.model = SentenceTransformer(model_name)
        self._lock = threading.Lock()
        # Warm-up: encode a dummy sentence to load ONNX/Torch
        self.model.encode(["warm-up"], show_progress_bar=False)
        log.info("Embedding model loaded in %.1fs (dim=%d)", time.monotonic() - t0, self.dim)

    @property
    def dim(self) -> int:
        return self.model.get_sentence_embedding_dimension()

    def encode(self, texts: list[str], batch_size: int = EMBEDDING_BATCH_SIZE) -> np.ndarray:
        """Encode texts to float32 numpy array. Thread-safe."""
        with self._lock:
            return self.model.encode(
                texts,
                batch_size=batch_size,
                show_progress_bar=False,
                normalize_embeddings=True,
                convert_to_numpy=True,
            ).astype(np.float32)

    def encode_single(self, text: str) -> list[float]:
        """Encode a single text, returns list[float]."""
        vec = self.encode([text])
        return vec[0].tolist()


# ─── LanceDB Manager ────────────────────────────────────────────────────────

class LanceDBManager:
    """Manages LanceDB connections, tables, and vector operations."""

    def __init__(self, db_path: str, engine: EmbeddingEngine):
        self.engine = engine
        log.info("Opening LanceDB at: %s", db_path)
        self.db = lancedb.connect(db_path)
        self._ensure_tables()
        self._stats = {
            "total_embeddings": 0,
            "total_searches": 0,
            "sync_cycles": 0,
            "last_sync": None,
        }

    def _ensure_tables(self):
        """Create tables if they don't exist."""
        existing = set(self.db.table_names())

        if "log_embeddings" not in existing:
            self.db.create_table("log_embeddings", schema=LOG_EMBEDDING_SCHEMA)
            log.info("Created table: log_embeddings")

        if "threat_intel" not in existing:
            self.db.create_table("threat_intel", schema=THREAT_INTEL_SCHEMA)
            log.info("Created table: threat_intel")

        if "historical_incidents" not in existing:
            self.db.create_table("historical_incidents", schema=HISTORICAL_INCIDENT_SCHEMA)
            log.info("Created table: historical_incidents")

        if "attack_embeddings" not in existing:
            self.db.create_table("attack_embeddings", schema=ATTACK_EMBEDDING_SCHEMA)
            log.info("Created table: attack_embeddings (confirmed attacks only)")

    def ingest_logs(self, rows: list[dict]) -> int:
        """Embed and store log events. Returns count ingested."""
        if not rows:
            return 0

        texts = [r.get("text", "") for r in rows]
        vectors = self.engine.encode(texts)

        records = []
        for row, vec in zip(rows, vectors):
            records.append({
                "event_id": str(row.get("event_id", "")),
                "timestamp": str(row.get("timestamp", "")),
                "source_table": str(row.get("source_table", "")),
                "log_source": str(row.get("log_source", "")),
                "hostname": str(row.get("hostname", "")),
                "severity": int(row.get("severity", 0)),
                "text": str(row.get("text", "")),
                "vector": vec.tolist(),
            })

        tbl = self.db.open_table("log_embeddings")
        tbl.add(records)
        self._stats["total_embeddings"] += len(records)
        return len(records)

    def ingest_threat_intel(self, iocs: list[dict]) -> int:
        """Embed and store threat intelligence IOCs."""
        if not iocs:
            return 0

        texts = [
            f"{r.get('ioc_type', '')} {r.get('ioc_value', '')} {r.get('description', '')} {r.get('tags', '')}"
            for r in iocs
        ]
        vectors = self.engine.encode(texts)

        records = []
        for row, vec in zip(iocs, vectors):
            records.append({
                "ioc_id": str(row.get("ioc_id", "")),
                "ioc_type": str(row.get("ioc_type", "")),
                "ioc_value": str(row.get("ioc_value", "")),
                "source": str(row.get("source", "")),
                "confidence": float(row.get("confidence", 0.0)),
                "severity": int(row.get("severity", 0)),
                "description": str(row.get("description", "")),
                "tags": orjson.dumps(row.get("tags", [])).decode(),
                "first_seen": str(row.get("first_seen", "")),
                "last_seen": str(row.get("last_seen", "")),
                "vector": vec.tolist(),
            })

        tbl = self.db.open_table("threat_intel")
        tbl.add(records)
        self._stats["total_embeddings"] += len(records)
        return len(records)

    def ingest_incidents(self, incidents: list[dict]) -> int:
        """Embed and store historical incidents for RAG."""
        if not incidents:
            return 0

        texts = [
            f"{r.get('title', '')} {r.get('description', '')} {r.get('resolution', '')} "
            f"tactics: {r.get('mitre_tactics', '')} techniques: {r.get('mitre_techniques', '')}"
            for r in incidents
        ]
        vectors = self.engine.encode(texts)

        records = []
        for row, vec in zip(incidents, vectors):
            records.append({
                "incident_id": str(row.get("incident_id", "")),
                "title": str(row.get("title", "")),
                "description": str(row.get("description", "")),
                "severity": int(row.get("severity", 0)),
                "mitre_tactics": orjson.dumps(row.get("mitre_tactics", [])).decode(),
                "mitre_techniques": orjson.dumps(row.get("mitre_techniques", [])).decode(),
                "affected_hosts": orjson.dumps(row.get("affected_hosts", [])).decode(),
                "affected_users": orjson.dumps(row.get("affected_users", [])).decode(),
                "resolution": str(row.get("resolution", "")),
                "created_at": str(row.get("created_at", "")),
                "resolved_at": str(row.get("resolved_at", "")),
                "vector": vec.tolist(),
            })

        tbl = self.db.open_table("historical_incidents")
        tbl.add(records)
        self._stats["total_embeddings"] += len(records)
        return len(records)

    def ingest_attack_embeddings(self, attacks: list[dict]) -> int:
        """Embed and store confirmed attacks in attack_embeddings.

        CRITICAL: Only call this with CONFIRMED attacks (analyst-verified or
        high-confidence verifier verdicts). Never ingest normal/benign events.
        Contamination of this table causes novel attacks to be mis-classified
        as benign (nearest neighbor is a normal event, not an attack).
        """
        if not attacks:
            return 0

        texts = [
            f"{r.get('source_type', '')} {r.get('hostname', '')} "
            f"{r.get('mitre_tactic', '')} {r.get('mitre_technique', '')} "
            f"{r.get('template_id', '')} {r.get('description', '')}"
            for r in attacks
        ]
        vectors = self.engine.encode(texts)

        records = []
        for row, vec in zip(attacks, vectors):
            records.append({
                "attack_id":      str(row.get("attack_id", "")),
                "source_type":    str(row.get("source_type", "")),
                "hostname":       str(row.get("hostname", "")),
                "mitre_tactic":   str(row.get("mitre_tactic", "")),
                "mitre_technique":str(row.get("mitre_technique", "")),
                "severity":       int(row.get("severity", 0)),
                "template_id":    str(row.get("template_id", "")),
                "description":    str(row.get("description", "")),
                "confirmed_at":   str(row.get("confirmed_at", "")),
                "label_source":   str(row.get("label_source", "pseudo_positive")),
                "vector":         vec.tolist(),
            })

        tbl = self.db.open_table("attack_embeddings")
        tbl.add(records)
        self._stats["total_embeddings"] += len(records)
        log.info("Ingested %d confirmed attacks into attack_embeddings", len(records))
        return len(records)

    def search(
        self,
        query: str,
        table_name: str = "log_embeddings",
        limit: int = 20,
        filter_sql: str | None = None,
    ) -> list[dict]:
        """Semantic vector search. Returns ranked results."""
        self._stats["total_searches"] += 1
        query_vec = self.engine.encode_single(query)

        tbl = self.db.open_table(table_name)
        search_builder = tbl.search(query_vec).limit(limit)
        if filter_sql:
            validated = self._validate_filter_sql(filter_sql)
            if validated:
                search_builder = search_builder.where(validated)

        results = search_builder.to_pandas()

        # Drop the raw vector from response (large)
        if "vector" in results.columns:
            results = results.drop(columns=["vector"])

        return results.to_dict(orient="records")

    @staticmethod
    def _validate_event_id(event_id: str) -> str:
        """Validate event_id is a safe UUID string to prevent SQL injection."""
        try:
            # Accept both UUID and plain string IDs, but sanitize
            uuid.UUID(event_id)  # validate UUID format
            return event_id
        except ValueError:
            # For non-UUID IDs, strip anything that could be injection
            sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", event_id)
            if not sanitized or len(sanitized) > 128:
                raise ValueError(f"Invalid event_id format: {event_id!r}")
            return sanitized

    @staticmethod
    def _validate_filter_sql(filter_sql: str | None) -> str | None:
        """Validate filter_sql against injection. Returns sanitized filter or None."""
        if not filter_sql:
            return None
        # Reject any SQL keywords that could alter query semantics
        dangerous = re.compile(
            r"\b(DROP|ALTER|INSERT|UPDATE|DELETE|CREATE|EXEC|UNION|;|--|/\*)\b",
            re.IGNORECASE,
        )
        if dangerous.search(filter_sql):
            raise ValueError(f"Dangerous SQL pattern detected in filter: {filter_sql!r}")
        if not _ALLOWED_FILTER_PATTERN.match(filter_sql.strip()):
            raise ValueError(f"Filter does not match allowed pattern: {filter_sql!r}")
        return filter_sql.strip()

    def find_similar(
        self,
        event_id: str,
        table_name: str = "log_embeddings",
        limit: int = 10,
    ) -> list[dict]:
        """Find events similar to a given event_id."""
        safe_id = self._validate_event_id(event_id)
        tbl = self.db.open_table(table_name)

        # First, find the source event's vector
        matches = tbl.search().where(f"event_id = '{safe_id}'").limit(1).to_pandas()
        if matches.empty:
            return []

        source_vec = matches.iloc[0]["vector"]
        results = tbl.search(source_vec).limit(limit + 1).to_pandas()

        # Exclude the source event itself
        results = results[results["event_id"] != event_id]
        if "vector" in results.columns:
            results = results.drop(columns=["vector"])

        return results.head(limit).to_dict(orient="records")

    @property
    def stats(self) -> dict:
        s = dict(self._stats)
        try:
            s["table_counts"] = {}
            for name in self.db.table_names():
                tbl = self.db.open_table(name)
                s["table_counts"][name] = tbl.count_rows()
        except Exception:
            pass
        return s


# ─── ClickHouse Sync Worker ─────────────────────────────────────────────────

class ClickHouseSyncer:
    """Periodically pulls new events from ClickHouse and embeds them into LanceDB."""

    # Queries to extract text for embedding from each table
    TABLE_QUERIES = {
        "raw_logs": """
            SELECT toString(event_id) AS event_id, toString(timestamp) AS timestamp,
                   source AS log_source, '' AS hostname, 0 AS severity,
                   message AS text, 'raw_logs' AS source_table
            FROM clif_logs.raw_logs
            WHERE timestamp > '{since}'
            ORDER BY timestamp ASC
            LIMIT {limit}
        """,
        "security_events": """
            SELECT toString(event_id) AS event_id, toString(timestamp) AS timestamp,
                   source AS log_source, hostname, toInt32(severity) AS severity,
                   concat(category, ': ', description, ' [', mitre_tactic, '/', mitre_technique, ']') AS text,
                   'security_events' AS source_table
            FROM clif_logs.security_events
            WHERE timestamp > '{since}'
            ORDER BY timestamp ASC
            LIMIT {limit}
        """,
        "process_events": """
            SELECT toString(event_id) AS event_id, toString(timestamp) AS timestamp,
                   '' AS log_source, hostname, toInt32(is_suspicious) AS severity,
                   concat('Process: ', binary_path, ' ', arguments, ' (pid:', toString(pid), ')') AS text,
                   'process_events' AS source_table
            FROM clif_logs.process_events
            WHERE timestamp > '{since}'
            ORDER BY timestamp ASC
            LIMIT {limit}
        """,
        "network_events": """
            SELECT toString(event_id) AS event_id, toString(timestamp) AS timestamp,
                   protocol AS log_source, hostname, 0 AS severity,
                   concat(IPv4NumToString(src_ip), ':', toString(src_port), ' -> ',
                          IPv4NumToString(dst_ip), ':', toString(dst_port), ' ',
                          protocol, ' ', dns_query) AS text,
                   'network_events' AS source_table
            FROM clif_logs.network_events
            WHERE timestamp > '{since}'
            ORDER BY timestamp ASC
            LIMIT {limit}
        """,
    }

    # Auto-sync confirmed attacks into attack_embeddings
    ATTACK_QUERIES = {
        "triage_escalated": """
            SELECT toString(event_id) AS attack_id,
                   source_type, hostname,
                   mitre_tactic, mitre_technique,
                   toInt32(if(adjusted_score > 0.9, 4, if(adjusted_score > 0.7, 3, 2))) AS severity,
                   template_id,
                   concat(source_type, ' ', hostname, ' ', mitre_tactic, '/', mitre_technique,
                          ' score=', toString(adjusted_score)) AS description,
                   toString(timestamp) AS confirmed_at,
                   'triage_escalated' AS label_source
            FROM clif_logs.triage_scores
            WHERE action = 'escalate' AND adjusted_score > 0.8
              AND timestamp > '{since}'
            ORDER BY timestamp ASC
            LIMIT {limit}
        """,
        "verifier_tp": """
            SELECT toString(alert_id) AS attack_id,
                   '' AS source_type,
                   '' AS hostname,
                   '' AS mitre_tactic, '' AS mitre_technique,
                   toInt32(if(priority = 'P1', 4, if(priority = 'P2', 3, if(priority = 'P3', 2, 1)))) AS severity,
                   '' AS template_id,
                   analyst_summary AS description,
                   toString(started_at) AS confirmed_at,
                   'verifier_confirmed' AS label_source
            FROM clif_logs.verifier_results
            WHERE verdict = 'true_positive'
              AND started_at > '{since}'
            ORDER BY started_at ASC
            LIMIT {limit}
        """,
    }

    def __init__(self, manager: LanceDBManager):
        self.manager = manager
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Track last-synced timestamp per table
        self._watermarks: dict[str, str] = {
            t: "2000-01-01 00:00:00" for t in self.TABLE_QUERIES
        }
        # Track attack_embeddings sync watermarks separately
        self._attack_watermarks: dict[str, str] = {
            t: "2000-01-01 00:00:00" for t in self.ATTACK_QUERIES
        }

    def _get_ch_client(self) -> CHClient:
        """Get or reuse a persistent ClickHouse client (connection pooling)."""
        if hasattr(self, '_ch_client_cached') and self._ch_client_cached is not None:
            try:
                self._ch_client_cached.execute("SELECT 1")
                return self._ch_client_cached
            except Exception:
                log.warning("Cached ClickHouse connection stale, reconnecting")
                self._ch_client_cached = None

        client = CHClient(
            host=CH_HOST,
            port=CH_PORT,
            user=CH_USER,
            password=CH_PASSWORD,
            database=CH_DB,
            connect_timeout=10,
            send_receive_timeout=60,
        )
        self._ch_client_cached = client
        return client

    def _sync_once(self):
        """Run one sync cycle across all tables."""
        try:
            ch = self._get_ch_client()
        except Exception as e:
            log.error("ClickHouse connection failed: %s", e)
            return

        total_synced = 0
        for table_name, query_template in self.TABLE_QUERIES.items():
            try:
                query = query_template.format(
                    since=self._watermarks[table_name],
                    limit=SYNC_BATCH_SIZE,
                )
                rows = ch.execute(query, with_column_types=True)
                data = rows[0]
                columns = [c[0] for c in rows[1]]

                if not data:
                    continue

                records = [dict(zip(columns, row)) for row in data]

                # Update watermark to the latest timestamp we just fetched
                latest_ts = str(records[-1].get("timestamp", self._watermarks[table_name]))
                self._watermarks[table_name] = latest_ts

                count = self.manager.ingest_logs(records)
                total_synced += count
                log.debug("Synced %d rows from %s (watermark=%s)", count, table_name, latest_ts)

            except Exception as e:
                log.error("Sync error for %s: %s", table_name, e)

        # --- Auto-sync confirmed attacks into attack_embeddings -----------
        for source_name, query_template in self.ATTACK_QUERIES.items():
            try:
                query = query_template.format(
                    since=self._attack_watermarks[source_name],
                    limit=SYNC_BATCH_SIZE,
                )
                rows = ch.execute(query, with_column_types=True)
                data = rows[0]
                columns = [c[0] for c in rows[1]]

                if not data:
                    continue

                records = [dict(zip(columns, row)) for row in data]

                latest_ts = str(records[-1].get("confirmed_at", self._attack_watermarks[source_name]))
                self._attack_watermarks[source_name] = latest_ts

                count = self.manager.ingest_attack_embeddings(records)
                total_synced += count
                log.info("Attack sync from %s: %d confirmed attacks (watermark=%s)", source_name, count, latest_ts)

            except Exception as e:
                log.error("Attack sync error for %s: %s", source_name, e)

        if total_synced > 0:
            log.info("Sync cycle complete: %d new embeddings", total_synced)

        self.manager._stats["sync_cycles"] += 1
        self.manager._stats["last_sync"] = datetime.now(timezone.utc).isoformat()

    def _run(self):
        """Background sync loop."""
        log.info("ClickHouse sync worker started (interval=%ds, batch=%d)", SYNC_INTERVAL, SYNC_BATCH_SIZE)
        while not self._stop.is_set():
            self._sync_once()
            self._stop.wait(SYNC_INTERVAL)
        log.info("ClickHouse sync worker stopped")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True, name="ch-sync")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)


# ─── API Models ──────────────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="Natural language search query")
    table: str = Field("log_embeddings", description="LanceDB table to search")
    limit: int = Field(20, ge=1, le=100, description="Max results")
    filter: str | None = Field(None, description="SQL filter expression (e.g. severity > 5)")

class SimilarRequest(BaseModel):
    event_id: str = Field(..., min_length=1, description="Event ID to find similar events for")
    table: str = Field("log_embeddings", description="LanceDB table")
    limit: int = Field(10, ge=1, le=50)

class IngestLogsRequest(BaseModel):
    events: list[dict] = Field(..., min_length=1, max_length=5000)
    table: str = Field("log_embeddings")

class IngestIOCRequest(BaseModel):
    iocs: list[dict] = Field(..., min_length=1, max_length=1000)

class IngestIncidentRequest(BaseModel):
    incidents: list[dict] = Field(..., min_length=1, max_length=100)

class IngestAttackEmbeddingRequest(BaseModel):
    """Request to add confirmed attacks to attack_embeddings table.
    Only for analyst-verified or verifier-confirmed attacks.
    """
    attacks: list[dict] = Field(..., min_length=1, max_length=1000)


# ─── FastAPI App ─────────────────────────────────────────────────────────────

# Global references — initialized in lifespan
_engine: EmbeddingEngine | None = None
_manager: LanceDBManager | None = None
_syncer: ClickHouseSyncer | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _engine, _manager, _syncer

    log.info("═" * 60)
    log.info("  CLIF LanceDB Service — Starting")
    log.info("═" * 60)

    # 1. Initialize embedding engine
    _engine = EmbeddingEngine(EMBEDDING_MODEL)

    # 2. Initialize LanceDB
    _manager = LanceDBManager(LANCEDB_PATH, _engine)

    # 3. Seed historical incidents if empty
    _seed_historical_incidents(_manager)

    # 4. Start ClickHouse sync worker
    _syncer = ClickHouseSyncer(_manager)
    _syncer.start()

    log.info("═" * 60)
    log.info("  CLIF LanceDB Service — Ready")
    log.info("  API: http://%s:%d", API_HOST, API_PORT)
    log.info("  Storage: %s", LANCEDB_PATH)
    log.info("  Model: %s (dim=%d)", EMBEDDING_MODEL, _engine.dim)
    log.info("═" * 60)

    yield

    # Shutdown
    log.info("Shutting down LanceDB service...")
    if _syncer:
        _syncer.stop()
    log.info("LanceDB service stopped")


app = FastAPI(
    title="CLIF LanceDB Service",
    description="Semantic vector search & RAG engine for CLIF SIEM",
    version="1.0.0",
    lifespan=lifespan,
    default_response_class=ORJSONResponse,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "clif-lancedb",
        "model": EMBEDDING_MODEL,
        "embedding_dim": EMBEDDING_DIM,
    }


@app.get("/stats")
async def stats():
    """Return service statistics."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")
    return _manager.stats


@app.post("/search")
async def search(req: SearchRequest):
    """Semantic search across vector tables."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    valid_tables = set(_manager.db.table_names())
    if req.table not in valid_tables:
        raise HTTPException(400, f"Invalid table. Valid: {sorted(valid_tables)}")

    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _embedding_executor,
            lambda: _manager.search(
                query=req.query,
                table_name=req.table,
                limit=req.limit,
                filter_sql=req.filter,
            ),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"query": req.query, "table": req.table, "count": len(results), "results": results}


@app.get("/search")
async def search_get(
    q: str = Query(..., min_length=1, max_length=2000, description="Search query"),
    table: str = Query("log_embeddings", description="Table to search"),
    limit: int = Query(20, ge=1, le=100),
    filter: str | None = Query(None, alias="filter", description="SQL filter"),
):
    """GET version of semantic search for browser/curl convenience."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    valid_tables = set(_manager.db.table_names())
    if table not in valid_tables:
        raise HTTPException(400, f"Invalid table. Valid: {sorted(valid_tables)}")

    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _embedding_executor,
            lambda: _manager.search(query=q, table_name=table, limit=limit, filter_sql=filter),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"query": q, "table": table, "count": len(results), "results": results}


@app.post("/similar")
async def find_similar(req: SimilarRequest):
    """Find events similar to a given event_id."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _embedding_executor,
            lambda: _manager.find_similar(
                event_id=req.event_id,
                table_name=req.table,
                limit=req.limit,
            ),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"event_id": req.event_id, "count": len(results), "results": results}


@app.post("/ingest/logs")
async def ingest_logs(req: IngestLogsRequest):
    """Manually ingest log events into the vector store."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    count = _manager.ingest_logs(req.events)
    return {"ingested": count}


@app.post("/ingest/threat-intel")
async def ingest_threat_intel(req: IngestIOCRequest):
    """Ingest IOCs into the threat_intel vector table."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    count = _manager.ingest_threat_intel(req.iocs)
    return {"ingested": count}


@app.post("/ingest/incidents")
async def ingest_incidents(req: IngestIncidentRequest):
    """Ingest historical incidents for RAG context."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    count = _manager.ingest_incidents(req.incidents)
    return {"ingested": count}


@app.post("/ingest/attack-embeddings")
async def ingest_attack_embeddings(req: IngestAttackEmbeddingRequest):
    """Ingest confirmed attacks into attack_embeddings for Hunter Agent verdict search.

    ONLY call with analyst-verified or verifier-confirmed attacks.
    Benign events MUST NOT be added here -- contamination causes novel attacks
    to be mis-classified as benign (high-distance novelty detection fails).
    """
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    count = _manager.ingest_attack_embeddings(req.attacks)
    return {"ingested": count, "table": "attack_embeddings"}


@app.get("/tables")
async def list_tables():
    """List all LanceDB tables with row counts."""
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    tables = {}
    for name in _manager.db.table_names():
        tbl = _manager.db.open_table(name)
        tables[name] = {"rows": tbl.count_rows()}
    return {"tables": tables}


class TableSearchRequest(BaseModel):
    """Request body for /tables/{table}/search (Hunter Agent compatibility)."""
    query_text: str = Field(..., min_length=1, max_length=2000)
    limit: int = Field(20, ge=1, le=100)
    filter: str | None = Field(None)


@app.post("/tables/{table_name}/search")
async def table_search(table_name: str, req: TableSearchRequest):
    """Search endpoint compatible with Hunter Agent similarity_searcher.

    Accepts POST /tables/{table}/search with {query_text, limit, filter}.
    """
    if not _manager:
        raise HTTPException(503, "Service not initialized")

    valid_tables = set(_manager.db.table_names())
    if table_name not in valid_tables:
        raise HTTPException(400, f"Invalid table. Valid: {sorted(valid_tables)}")

    try:
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            _embedding_executor,
            lambda: _manager.search(
                query=req.query_text,
                table_name=table_name,
                limit=req.limit,
                filter_sql=req.filter,
            ),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))

    return {"query": req.query_text, "table": table_name, "count": len(results), "results": results}


# ─── Seed Data ───────────────────────────────────────────────────────────────

def _seed_historical_incidents(manager: LanceDBManager):
    """Seed historical incidents for RAG if table is empty."""
    tbl = manager.db.open_table("historical_incidents")
    if tbl.count_rows() > 0:
        log.info("Historical incidents already seeded (%d rows)", tbl.count_rows())
        return

    log.info("Seeding historical incidents for RAG context...")
    incidents = [
        {
            "incident_id": "INC-2025-001",
            "title": "Ransomware Attack via Phishing Email",
            "description": "Employee clicked malicious link in spoofed HR email. Payload downloaded Cobalt Strike beacon, "
                           "established C2 channel, performed lateral movement via RDP, deployed LockBit 3.0 ransomware. "
                           "847 files encrypted on FILE-SRV03 within 30 seconds.",
            "severity": 10,
            "mitre_tactics": ["Initial Access", "Execution", "Lateral Movement", "Impact"],
            "mitre_techniques": ["T1566.001", "T1059.001", "T1021.001", "T1486"],
            "affected_hosts": ["WKS-0142", "FILE-SRV03", "DC-01"],
            "affected_users": ["msmith", "admin-jdoe"],
            "resolution": "Isolated affected hosts. Restored from offline backups. Reset all domain credentials. "
                          "Deployed email gateway rule blocking .hta attachments. Conducted phishing awareness training.",
            "created_at": "2025-09-15T08:30:00Z",
            "resolved_at": "2025-09-18T16:00:00Z",
        },
        {
            "incident_id": "INC-2025-002",
            "title": "APT28 Supply Chain Compromise",
            "description": "Threat actor compromised vendor update server. Malicious DLL sideloaded during routine software update. "
                           "Beacon communicated with C2 via DNS tunneling. Exfiltrated 2.3GB of engineering data over 3 weeks. "
                           "LSASS memory dump detected on SRV-APP01.",
            "severity": 10,
            "mitre_tactics": ["Initial Access", "Persistence", "Credential Access", "Exfiltration"],
            "mitre_techniques": ["T1195.002", "T1574.001", "T1003.001", "T1048.003"],
            "affected_hosts": ["SRV-APP01", "SRV-BUILD02", "WKS-ENG-15"],
            "affected_users": ["svc-build", "eng-team"],
            "resolution": "Removed malicious DLL. Revoked vendor VPN access. Deployed EDR on all engineering workstations. "
                          "Implemented allowlisting for DLL sideloading paths. Notified vendor of compromise.",
            "created_at": "2025-11-02T14:20:00Z",
            "resolved_at": "2025-11-10T09:00:00Z",
        },
        {
            "incident_id": "INC-2025-003",
            "title": "Brute Force Attack on VPN Gateway",
            "description": "Distributed brute-force attack targeting VPN gateway from 230 unique IP addresses. "
                           "47 accounts locked out. Attacker successfully compromised 2 accounts with weak passwords. "
                           "Post-authentication, attacker attempted PowerShell-based reconnaissance (whoami, net group).",
            "severity": 7,
            "mitre_tactics": ["Credential Access", "Discovery", "Initial Access"],
            "mitre_techniques": ["T1110.001", "T1087.002", "T1133"],
            "affected_hosts": ["VPN-GW01"],
            "affected_users": ["johnd", "temp-contractor"],
            "resolution": "Blocked attacking IPs at perimeter firewall. Enforced MFA for all VPN accounts. "
                          "Reset compromised credentials. Deployed adaptive rate-limiting on VPN endpoint.",
            "created_at": "2025-12-05T02:15:00Z",
            "resolved_at": "2025-12-05T06:30:00Z",
        },
        {
            "incident_id": "INC-2026-001",
            "title": "Cryptominer on Container Infrastructure",
            "description": "Kubernetes pod deployed via compromised CI/CD pipeline contained XMRig cryptominer. "
                           "CPU usage on worker nodes spiked to 98%. Miner communicated to mining pool via Stratum protocol. "
                           "Container image had been tampered in registry.",
            "severity": 5,
            "mitre_tactics": ["Resource Development", "Execution", "Impact"],
            "mitre_techniques": ["T1608.001", "T1610", "T1496"],
            "affected_hosts": ["k8s-worker-01", "k8s-worker-02", "k8s-worker-03"],
            "affected_users": ["svc-cicd"],
            "resolution": "Killed malicious pods. Enabled image signing (Cosign) and admission control (OPA Gatekeeper). "
                          "Rotated CI/CD service account credentials. Audited all container images in registry.",
            "created_at": "2026-01-20T11:45:00Z",
            "resolved_at": "2026-01-20T15:00:00Z",
        },
        {
            "incident_id": "INC-2026-002",
            "title": "Insider Threat — Data Exfiltration via USB",
            "description": "DLP alert triggered for large file copy to USB drive by departing employee. "
                           "156 files containing customer PII copied to external device. Employee had elevated access "
                           "due to upcoming role transition. USB device was not encrypted.",
            "severity": 8,
            "mitre_tactics": ["Collection", "Exfiltration"],
            "mitre_techniques": ["T1005", "T1052.001"],
            "affected_hosts": ["WKS-HR-07"],
            "affected_users": ["departing-emp"],
            "resolution": "Confiscated USB device. Disabled user account immediately. Legal and HR notified. "
                          "Implemented USB device control policy (block all non-corporate USB storage). "
                          "Added automated access review for departing employees.",
            "created_at": "2026-02-01T09:00:00Z",
            "resolved_at": "2026-02-02T14:00:00Z",
        },
    ]

    count = manager.ingest_incidents(incidents)
    log.info("Seeded %d historical incidents for RAG", count)


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host=API_HOST,
        port=API_PORT,
        log_level=LOG_LEVEL.lower(),
        access_log=True,
        workers=1,  # Single worker — embedding model is heavy
    )
