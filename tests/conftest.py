"""
Shared fixtures for the CLIF production test suite.
"""
from __future__ import annotations

import os
import re
import pytest

# test_lancedb.py is a standalone CLI script, not a pytest test module.
# Its test functions accept a plain `url: str` parameter (not a fixture),
# so pytest discovery must skip it.
collect_ignore = ["test_lancedb.py"]

from clickhouse_driver import Client as _CHNativeClient
from confluent_kafka import Producer
from confluent_kafka.admin import AdminClient


# ── clickhouse-connect → clickhouse-driver compatibility wrapper ─────────────
# All existing tests use the clickhouse-connect API (.query() with {name:Type}
# param syntax and result.result_rows). This thin adapter lets every test file
# work unchanged over the native TCP protocol.

_PARAM_RE = re.compile(r"\{(\w+):\w+\}")  # matches {tag:String}, {db:UInt32}, …


class _QueryResult:
    """Mimics clickhouse_connect QueryResult with .result_rows."""
    __slots__ = ("result_rows",)

    def __init__(self, rows: list):
        self.result_rows = rows


class ClickHouseClient:
    """Drop-in wrapper around clickhouse-driver that exposes the
    clickhouse-connect query() / insert() / close() surface."""

    def __init__(self, *, host: str, port: int, username: str, password: str,
                 database: str, connect_timeout: int = 30, **kw):
        self._client = _CHNativeClient(
            host=host, port=port, user=username, password=password,
            database=database, connect_timeout=connect_timeout,
            send_receive_timeout=kw.get("send_receive_timeout", 120),
            compression=kw.get("compress", True),
            settings=kw.get("settings", {}),
        )

    # ── query ──────────────────────────────────────────────────────────
    def query(self, sql: str, parameters: dict | None = None) -> _QueryResult:
        """Execute a SELECT and return result with .result_rows."""
        sql = _PARAM_RE.sub(r"%(\1)s", sql)
        if parameters:
            rows = self._client.execute(sql, parameters)
        else:
            rows = self._client.execute(sql)
        return _QueryResult(rows)

    # ── insert (for any test that inserts rows via client) ─────────────
    def insert(self, table: str, rows, column_names=None, **kw):
        if column_names:
            cols = ", ".join(column_names)
            sql = f"INSERT INTO {table} ({cols}) VALUES"
        else:
            sql = f"INSERT INTO {table} VALUES"
        self._client.execute(sql, rows, types_check=False)

    def close(self):
        self._client.disconnect()


# ── Connection parameters (match .env) ───────────────────────────────────────

CH_HOST = os.getenv("CH_HOST", "localhost")
CH_PORT_1 = int(os.getenv("CH_PORT_1", "9000"))
CH_PORT_2 = int(os.getenv("CH_PORT_2", "9001"))
CH_USER = os.getenv("CH_USER", "clif_admin")
CH_PASS = os.getenv("CH_PASS", "Cl1f_Ch@ngeM3_2026!")
CH_DB = os.getenv("CH_DB", "clif_logs")
BROKER = os.getenv("BROKER", "localhost:19092,localhost:29092,localhost:39092")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://localhost:9002")


@pytest.fixture(scope="session")
def ch1():
    """ClickHouse client for node 1 (native TCP)."""
    client = ClickHouseClient(
        host=CH_HOST, port=CH_PORT_1,
        username=CH_USER, password=CH_PASS,
        database=CH_DB, connect_timeout=30,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def ch2():
    """ClickHouse client for node 2 (native TCP)."""
    client = ClickHouseClient(
        host=CH_HOST, port=CH_PORT_2,
        username=CH_USER, password=CH_PASS,
        database=CH_DB, connect_timeout=30,
    )
    yield client
    client.close()


@pytest.fixture(scope="session")
def ch_system():
    """ClickHouse client connected to the system database (node 1)."""
    client = ClickHouseClient(
        host=CH_HOST, port=CH_PORT_1,
        username=CH_USER, password=CH_PASS,
        database="system", connect_timeout=30,
    )
    yield client
    client.close()


# Production-grade Kafka producer config — shared across all tests
PRODUCER_CONFIG: dict = {
    "bootstrap.servers": BROKER,
    "linger.ms": 10,
    "batch.num.messages": 50_000,
    "batch.size": 1_048_576,              # 1 MB wire batch
    "queue.buffering.max.messages": 2_000_000,
    "queue.buffering.max.kbytes": 2_097_152,  # 2 GB librdkafka queue
    "compression.type": "lz4",             # LZ4 — fast compress, low CPU
    "acks": "all",
    "enable.idempotence": True,
    "message.send.max.retries": 3,
    "retry.backoff.ms": 100,
    "socket.send.buffer.bytes": 1_048_576,  # 1 MB kernel send buffer
}


@pytest.fixture(scope="session")
def kafka_producer():
    """High-throughput Kafka producer (single instance, for latency / fan-out tests)."""
    p = Producer(PRODUCER_CONFIG)
    yield p
    p.flush(30)


@pytest.fixture(scope="session")
def kafka_admin():
    """Kafka AdminClient for cluster introspection."""
    return AdminClient({"bootstrap.servers": BROKER})
