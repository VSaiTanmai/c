"""
SPC Engine – L1 Statistical Process Control thread.

Uses ClickHouse `features_entity_freq` (materialized view that maintains
per-entity event-frequency baselines) to compute z-scores and detect
statistical anomalies.

Feature dims produced (4):
  [spc_z_score, spc_is_anomaly, spc_baseline_mean, spc_baseline_stddev]
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional

from config import (
    CLICKHOUSE_DATABASE,
    CLICKHOUSE_HOST,
    CLICKHOUSE_PASSWORD,
    CLICKHOUSE_PORT,
    CLICKHOUSE_USER,
    SPC_BASELINE_REFRESH_SEC,
    SPC_SIGMA_THRESHOLD,
    SPC_WINDOW_HOURS,
)
from models import SPCDeviation, SPCResult

log = logging.getLogger(__name__)


def _make_ch():
    """Create a fresh ClickHouse HTTP client."""
    import clickhouse_connect  # type: ignore
    return clickhouse_connect.get_client(
        host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT,
        username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD,
        database=CLICKHOUSE_DATABASE,
    )


class SPCEngine:
    """
    Manages SPC baselines and evaluates new alerts against them.
    Baselines are cached in-process and refreshed periodically.
    """

    def __init__(self, ch_client: Any) -> None:
        # ch_client kept for backward compat but not used directly
        self._baselines: Dict[str, Dict[str, float]] = {}  # key: hostname|source_ip
        self._last_refresh: float = 0.0

    # ------------------------------------------------------------------
    # Background refresh
    # ------------------------------------------------------------------

    async def start_background_refresh(self) -> None:
        """Launch a background task that refreshes baselines periodically."""
        while True:
            try:
                await self.refresh_baselines()
            except Exception as exc:  # noqa: BLE001
                log.warning("SPC baseline refresh failed: %s", exc)
            await asyncio.sleep(SPC_BASELINE_REFRESH_SEC)

    async def refresh_baselines(self) -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._load_baselines)

    def _load_baselines(self) -> None:
        """
        Pull per-entity aggregated statistics from the materialised view
        `features_entity_freq` (built over the last SPC_WINDOW_HOURS hours).
        """
        q = f"""
            SELECT
                hostname,
                source_ip,
                avg(event_count) AS mean_count,
                stddevSamp(event_count) AS std_count
            FROM {CLICKHOUSE_DATABASE}.features_entity_freq
            WHERE window >= now() - INTERVAL {SPC_WINDOW_HOURS} HOUR
            GROUP BY hostname, source_ip
        """
        try:
            ch = _make_ch()
            rows = ch.query(q).result_rows
            new_baselines: Dict[str, Dict[str, float]] = {}
            for hostname, source_ip, mean, std in rows:
                key = f"{hostname}|{source_ip}"
                new_baselines[key] = {
                    "mean": float(mean or 0.0),
                    "stddev": float(std or 0.0),
                }
            self._baselines = new_baselines
            log.debug("SPC baselines refreshed: %d entities", len(new_baselines))
        except Exception as exc:  # noqa: BLE001
            log.warning("SPC baseline load failed: %s", exc)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    async def evaluate(self, payload: Dict[str, Any]) -> SPCResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._evaluate_sync, payload)

    def _evaluate_sync(self, payload: Dict[str, Any]) -> SPCResult:
        hostname = str(payload.get("hostname", ""))
        source_ip = str(payload.get("source_ip", ""))
        user_id = str(payload.get("user_id", ""))
        # Use event timestamp for backlog processing accuracy
        event_ts = str(payload.get("timestamp", "")).strip()

        result = SPCResult()

        # --- Look up in-memory baseline ---
        key = f"{hostname}|{source_ip}"
        baseline = self._baselines.get(key)

        if baseline is None and source_ip:
            # Many entities aggregate under source_ip='0.0.0.0' in the
            # MV while the triage payload carries a per-event IP.
            # Try the aggregated key before falling back to CH.
            baseline = self._baselines.get(f"{hostname}|0.0.0.0")

        if baseline is None:
            # Fall back to direct CH query for this entity
            baseline = self._query_entity_baseline(hostname, source_ip)

        if baseline is None:
            return result  # no data, all features stay 0

        mean = baseline.get("mean", 0.0)
        std = baseline.get("stddev", 0.0)
        result.baseline_mean = mean
        result.baseline_stddev = std

        # --- Compute z-score using current window event count ---
        observed = self._query_current_count(hostname, source_ip, event_ts)

        if std > 0:
            z = (observed - mean) / std
        else:
            z = 0.0

        result.max_z_score = z
        result.is_anomaly = z > SPC_SIGMA_THRESHOLD

        if result.is_anomaly:
            result.deviations.append(
                SPCDeviation(
                    hostname=hostname,
                    source_ip=source_ip,
                    user_id=user_id,
                    z_score=z,
                    observed=observed,
                    baseline_mean=mean,
                    baseline_stddev=std,
                )
            )

        return result

    def _query_entity_baseline(
        self, hostname: str, source_ip: str
    ) -> Optional[Dict[str, float]]:
        """Fallback: compute baseline directly from CH if not in cache.
        
        Tries exact (hostname, source_ip) first, then hostname-only
        to handle entities whose baselines aggregate under 0.0.0.0.
        """
        q = f"""
            SELECT
                avg(event_count) AS mean_count,
                stddevSamp(event_count) AS std_count
            FROM {CLICKHOUSE_DATABASE}.features_entity_freq
            WHERE hostname = '{_s(hostname)}'
              AND (source_ip = '{_s(source_ip)}' OR source_ip = '0.0.0.0')
              AND window >= now() - INTERVAL {SPC_WINDOW_HOURS} HOUR
        """
        try:
            ch = _make_ch()
            rows = ch.query(q).result_rows
            if rows and rows[0][0] is not None:
                return {
                    "mean": float(rows[0][0] or 0.0),
                    "stddev": float(rows[0][1] or 0.0),
                }
        except Exception as exc:  # noqa: BLE001
            log.debug("SPC entity baseline query failed: %s", exc)
        return None

    def _query_current_count(self, hostname: str, source_ip: str, event_ts: str = "") -> float:
        """Count events for this entity in a 1-hour window around the event.

        Queries both network_events and triage_scores because
        features_entity_freq baselines are fed by MVs from ALL three
        source tables (network, security, process), but the old code
        only checked network_events — missing security-event entities.

        Uses the event timestamp (not now()) so backlog processing
        sees the correct activity window.
        """
        # Anchor time: use event timestamp if available, else now()
        if event_ts:
            _anchor = f"parseDateTimeBestEffort('{_s(event_ts)}')"
        else:
            _anchor = "now()"

        q = f"""
            SELECT max(cnt) FROM (
                SELECT count() AS cnt
                FROM {CLICKHOUSE_DATABASE}.network_events
                WHERE hostname = '{_s(hostname)}'
                  AND (toString(src_ip) = '{_s(source_ip)}' OR '{_s(source_ip)}' = '0.0.0.0')
                  AND timestamp >= {_anchor} - INTERVAL 1 HOUR
                  AND timestamp <= {_anchor}
                UNION ALL
                SELECT count() AS cnt
                FROM {CLICKHOUSE_DATABASE}.triage_scores
                WHERE hostname = '{_s(hostname)}'
                  AND (source_ip = '{_s(source_ip)}' OR '{_s(source_ip)}' = '0.0.0.0')
                  AND timestamp >= {_anchor} - INTERVAL 1 HOUR
                  AND timestamp <= {_anchor}
            )
        """
        try:
            ch = _make_ch()
            rows = ch.query(q).result_rows
            return float(rows[0][0]) if rows else 0.0
        except Exception as exc:  # noqa: BLE001
            log.debug("SPC current count query failed: %s", exc)
            return 0.0


def _s(value: Any) -> str:
    return re.sub(r"[';\"\\]", "", str(value))
