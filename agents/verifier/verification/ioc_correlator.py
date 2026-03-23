"""
IOC Cross-Correlator — verify Hunter IOC claims against ioc_cache and
network_events.

Read-only — no writes to any table.
"""
from __future__ import annotations

import asyncio
import json
import logging
from functools import partial
from typing import Any

from models import IOCResult
from utils import sanitize_sql

log = logging.getLogger(__name__)


async def correlate(
    ch: Any,
    payload: dict,
    lookback_hours: int = 72,
) -> IOCResult:
    """
    Cross-reference IOCs mentioned in the Hunter verdict against the
    live ``ioc_cache`` table and corroborate with ``network_events``.

    Args:
        ch: clickhouse-connect client.
        payload: Hunter verdict dict.
        lookback_hours: how far back to search network_events.

    Returns:
        IOCResult with correlation details.
    """
    result = IOCResult()

    source_ip = sanitize_sql(payload.get("source_ip", ""))
    hostname = sanitize_sql(payload.get("hostname", ""))
    if not source_ip:
        return result

    try:
        # --- Direct IOC lookup for source_ip ------------------------------
        ioc_query = (
            "SELECT ioc_type, ioc_value, confidence, source, expires_at "
            "FROM ioc_cache "
            f"WHERE ioc_value = '{source_ip}' "
            "  AND expires_at > now()"
        )
        loop = asyncio.get_event_loop()
        ioc_rows = await loop.run_in_executor(None, partial(ch.query, ioc_query))

        matches = []
        for row in ioc_rows.result_rows:
            matches.append({
                "ioc_type": str(row[0]),
                "ioc_value": str(row[1]),
                "confidence": int(row[2]) if row[2] else 0,
                "source": str(row[3]),
            })

        # --- Network flows from source_ip to known-bad destinations -------
        join_query = (
            "SELECT ne.dst_ip, ne.dst_port, ic.confidence, ic.source "
            "FROM network_events ne "
            "INNER JOIN ioc_cache ic ON toString(ne.dst_ip) = ic.ioc_value "
            f"WHERE ne.src_ip = IPv4StringToNum('{source_ip}') "
            f"  AND ne.timestamp >= now() - INTERVAL {int(lookback_hours)} HOUR "
            "  AND ic.ioc_type = 'ip' "
            "  AND ic.expires_at > now() "
            "LIMIT 50"
        )
        join_rows = await loop.run_in_executor(None, partial(ch.query, join_query))

        for row in join_rows.result_rows:
            matches.append({
                "ioc_type": "dst_ip_ioc",
                "ioc_value": str(row[0]),
                "confidence": int(row[2]) if row[2] else 0,
                "source": str(row[3]),
                "dst_port": int(row[1]) if row[1] else 0,
            })

        # --- Count total network flows for context -----------------------
        flow_query = (
            "SELECT count() "
            "FROM network_events "
            f"WHERE toString(src_ip) = '{source_ip}' "
            f"  AND timestamp >= now() - INTERVAL {int(lookback_hours)} HOUR"
        )
        flow_rows = await loop.run_in_executor(None, partial(ch.query, flow_query))
        flow_count = int(flow_rows.result_rows[0][0]) if flow_rows.result_rows else 0

        result.ioc_matches = matches
        result.corroborated = len(matches) > 0
        result.network_flows_found = flow_count
        result.correlation_json = json.dumps({
            "source_ip": source_ip,
            "hostname": hostname,
            "ioc_matches": matches,
            "network_flows": flow_count,
        })

    except Exception as exc:
        log.error("IOC correlation failed: %s", exc)

    return result
