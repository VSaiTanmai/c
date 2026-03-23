"""
CLIF Triage Agent — Score Fusion & Threshold Routing
=======================================================
Fuses scores from the 3-model ensemble, applies source-specific thresholds
and asset-criticality multipliers, and produces a routing decision.

Score fusion formula:
    combined = lgbm × w_lgbm + eif × w_eif + arf × w_arf

Confidence interval:
    std_dev   = std(lgbm, eif, arf)
    agreement = 1 - std_dev
    ci_lower  = max(0, combined - 1.96 × std_dev)
    ci_upper  = min(1, combined + 1.96 × std_dev)

Routing:
    adjusted  = combined × asset_multiplier
    adjusted ≥ anomalous_threshold  → escalate
    adjusted ≥ suspicious_threshold → monitor
    otherwise                       → discard
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

import config

logger = logging.getLogger("clif.triage.fusion")


@dataclass
class TriageResult:
    """A single triage scoring result — maps directly to the triage_scores table."""

    event_id: str
    timestamp: str
    source_type: str
    hostname: str
    source_ip: str
    user_id: str
    template_id: str
    template_rarity: float
    combined_score: float
    lgbm_score: float
    eif_score: float
    arf_score: float
    score_std_dev: float
    agreement: float
    ci_lower: float
    ci_upper: float
    asset_multiplier: float
    adjusted_score: float
    action: str  # 'discard', 'monitor', 'escalate'
    ioc_match: int
    ioc_confidence: int
    mitre_tactic: str
    mitre_technique: str
    features_stale: int
    model_version: str
    disagreement_flag: int
    shap_top_features: str = ""
    shap_summary: str = ""


class SourceThresholdCache:
    """
    Caches per-source-type thresholds from ClickHouse.
    Refreshed periodically (default: every 5 minutes).
    Thread-safe.
    """

    def __init__(self, ch_client, refresh_interval_sec: float = 300.0):
        self._ch_client = ch_client
        self._refresh_interval = refresh_interval_sec
        self._cache: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._last_refresh = 0.0

    def get_thresholds(
        self, source_type: str, topic: str = ""
    ) -> Tuple[float, float]:
        """
        Get (suspicious_threshold, anomalous_threshold) for a source.
        Lookup priority: topic → source_type → global defaults.

        Topic-based lookup is preferred because Vector's source_type field
        is often a generic collector name (e.g. "socket") that doesn't
        differentiate log types.  The Redpanda topic (raw-logs, security-
        events, process-events, network-events) is a reliable indicator.
        """
        self._maybe_refresh()
        defaults = (
            config.DEFAULT_SUSPICIOUS_THRESHOLD,
            config.DEFAULT_ANOMALOUS_THRESHOLD,
        )
        with self._lock:
            if topic and topic in self._cache:
                return self._cache[topic]
            return self._cache.get(source_type, defaults)

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return

        try:
            rows = self._ch_client.execute(
                "SELECT source_type, suspicious_threshold, anomalous_threshold "
                "FROM clif_logs.source_thresholds FINAL"
            )
            with self._lock:
                self._cache = {
                    str(r[0]): (float(r[1]), float(r[2])) for r in rows
                }
            self._last_refresh = now
            logger.debug("Refreshed source thresholds: %d entries", len(self._cache))
        except Exception as e:
            logger.warning("Failed to refresh source thresholds: %s", e)
            self._last_refresh = now  # Don't retry immediately


class AssetCriticalityCache:
    """
    Caches hostname → multiplier mapping from ClickHouse.
    Uses LIKE matching on hostname_pattern.
    Thread-safe.
    """

    def __init__(self, ch_client, refresh_interval_sec: float = 600.0):
        self._ch_client = ch_client
        self._refresh_interval = refresh_interval_sec
        self._patterns: List[Tuple[str, float]] = []
        self._lock = threading.Lock()
        self._last_refresh = 0.0

    def get_multiplier(self, hostname: str) -> float:
        """Get asset criticality multiplier for a hostname. Default 1.0."""
        self._maybe_refresh()
        if not hostname:
            return 1.0

        with self._lock:
            for pattern, multiplier in self._patterns:
                # Simple wildcard matching: `%` → any, `_` → single char
                if self._matches(hostname, pattern):
                    return multiplier
        return 1.0

    @staticmethod
    def _matches(hostname: str, pattern: str) -> bool:
        """Simple SQL LIKE matching in Python."""
        import re

        regex = "^"
        for ch in pattern:
            if ch == "%":
                regex += ".*"
            elif ch == "_":
                regex += "."
            else:
                regex += re.escape(ch)
        regex += "$"
        return bool(re.match(regex, hostname, re.IGNORECASE))

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return

        try:
            rows = self._ch_client.execute(
                "SELECT hostname_pattern, multiplier "
                "FROM clif_logs.asset_criticality FINAL"
            )
            with self._lock:
                self._patterns = [(str(r[0]), float(r[1])) for r in rows]
            self._last_refresh = now
            logger.debug(
                "Refreshed asset criticality: %d patterns", len(self._patterns)
            )
        except Exception as e:
            logger.warning("Failed to refresh asset criticality: %s", e)
            self._last_refresh = now


class IOCLookup:
    """Fast IOC lookup backed by ClickHouse ioc_cache table."""

    def __init__(self, ch_client, refresh_interval_sec: float = 300.0):
        self._ch_client = ch_client
        self._refresh_interval = refresh_interval_sec
        self._ip_set: set = set()
        self._domain_set: set = set()
        self._hash_set: set = set()
        self._confidence_map: Dict[str, int] = {}
        self._lock = threading.Lock()
        self._last_refresh = 0.0

    def check(self, indicator: str) -> bool:
        """Check if an indicator is in the IOC cache."""
        self._maybe_refresh()
        indicator = str(indicator).strip().lower()
        with self._lock:
            return (
                indicator in self._ip_set
                or indicator in self._domain_set
                or indicator in self._hash_set
            )

    def get_confidence(self, indicator: str) -> int:
        """Get confidence score (0-100) for an IOC. Returns 0 if not found."""
        self._maybe_refresh()
        with self._lock:
            return self._confidence_map.get(str(indicator).strip().lower(), 0)

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return

        try:
            rows = self._ch_client.execute(
                "SELECT ioc_type, ioc_value, confidence "
                "FROM clif_logs.ioc_cache "
                "WHERE expires_at > now()"
            )
            new_ips = set()
            new_domains = set()
            new_hashes = set()
            new_conf = {}

            for ioc_type, ioc_value, confidence in rows:
                val = str(ioc_value).strip().lower()
                new_conf[val] = int(confidence)
                ioc_type_str = str(ioc_type)
                if ioc_type_str == "ip" or ioc_type == 1:
                    new_ips.add(val)
                elif ioc_type_str == "domain" or ioc_type == 2:
                    new_domains.add(val)
                elif ioc_type_str == "hash" or ioc_type == 3:
                    new_hashes.add(val)

            with self._lock:
                self._ip_set = new_ips
                self._domain_set = new_domains
                self._hash_set = new_hashes
                self._confidence_map = new_conf

            self._last_refresh = now
            logger.debug(
                "Refreshed IOC cache: %d IPs, %d domains, %d hashes",
                len(new_ips), len(new_domains), len(new_hashes),
            )
        except Exception as e:
            logger.warning("Failed to refresh IOC cache: %s", e)
            self._last_refresh = now


class AllowlistChecker:
    """Checks events against the allowlist to suppress known-good patterns."""

    def __init__(self, ch_client, refresh_interval_sec: float = 300.0):
        self._ch_client = ch_client
        self._refresh_interval = refresh_interval_sec
        self._entries: Dict[str, set] = {
            "ip": set(),
            "user": set(),
            "host": set(),
            "template": set(),
            "source": set(),
        }
        self._lock = threading.Lock()
        self._last_refresh = 0.0

    def is_allowed(
        self,
        ip: str = "",
        user: str = "",
        hostname: str = "",
        template_id: str = "",
        source_type: str = "",
    ) -> bool:
        """Check if any part of the event matches the allowlist."""
        self._maybe_refresh()
        with self._lock:
            if ip and ip in self._entries["ip"]:
                return True
            if user and user in self._entries["user"]:
                return True
            if hostname and hostname in self._entries["host"]:
                return True
            if template_id and template_id in self._entries["template"]:
                return True
            if source_type and source_type in self._entries["source"]:
                return True
        return False

    def _maybe_refresh(self) -> None:
        now = time.monotonic()
        if now - self._last_refresh < self._refresh_interval:
            return

        try:
            rows = self._ch_client.execute(
                "SELECT entry_type, entry_value "
                "FROM clif_logs.allowlist "
                "WHERE active = 1 "
                "  AND (expires_at IS NULL OR expires_at > now())"
            )
            new_entries: Dict[str, set] = {
                "ip": set(), "user": set(), "host": set(),
                "template": set(), "source": set(),
            }
            for entry_type, entry_value in rows:
                et = str(entry_type)
                # Handle Enum8 integer representation
                type_map = {1: "ip", 2: "user", 3: "host", 4: "template", 5: "source"}
                if et in type_map.values():
                    new_entries[et].add(str(entry_value).strip())
                elif isinstance(entry_type, int) and entry_type in type_map:
                    new_entries[type_map[entry_type]].add(str(entry_value).strip())

            with self._lock:
                self._entries = new_entries

            self._last_refresh = now
            total = sum(len(s) for s in new_entries.values())
            logger.debug("Refreshed allowlist: %d total entries", total)
        except Exception as e:
            logger.warning("Failed to refresh allowlist: %s", e)
            self._last_refresh = now


class ScoreFusion:
    """
    Fuses 3-model scores, applies thresholds and asset criticality,
    and produces routing decisions.
    """

    def __init__(
        self,
        ch_client=None,
        weights: Optional[Dict[str, float]] = None,
        model_version: str = "",
    ):
        self._weights = weights or config.SCORE_WEIGHTS
        self._model_version = model_version

        # Normalize weights to sum to 1.0
        total_w = sum(self._weights.values())
        if abs(total_w - 1.0) > 0.001:
            for k in self._weights:
                self._weights[k] /= total_w
            logger.info("Normalized weights to: %s", self._weights)

        # ClickHouse-backed caches
        self._source_thresholds: Optional[SourceThresholdCache] = None
        self._asset_criticality: Optional[AssetCriticalityCache] = None
        self._ioc_lookup: Optional[IOCLookup] = None
        self._allowlist: Optional[AllowlistChecker] = None

        if ch_client is not None:
            self._source_thresholds = SourceThresholdCache(ch_client)
            self._asset_criticality = AssetCriticalityCache(ch_client)
            self._ioc_lookup = IOCLookup(ch_client)
            self._allowlist = AllowlistChecker(ch_client)

    @property
    def ioc_lookup(self) -> Optional[IOCLookup]:
        """Expose IOC lookup for use by FeatureExtractor."""
        return self._ioc_lookup

    def fuse_batch(
        self,
        model_scores: Dict[str, np.ndarray],
        features_list: List[Dict[str, Any]],
        events: List[Dict[str, Any]],
    ) -> List[TriageResult]:
        """
        Fuse scores and route a batch of events.

        Dynamic weighting:
          ARF weight is scaled by arf_confidence (0→1 ramp). Remaining
          weight is redistributed proportionally to LightGBM and EIF.
          This prevents the cold-start ARF from adding dead weight.

        Post-model adjusters (compensate for dead training features):
          - Template rarity: rare templates (< threshold) boost the score
          - IOC match: matching IOC boosts the combined score directly

        Args:
            model_scores: Dict with 'lgbm', 'eif', 'arf' arrays (N,)
                          and 'arf_confidence' float.
            features_list: List of feature dicts from extractor (N items)
            events: Original event dicts (N items)

        Returns:
            List of TriageResult objects.
        """
        lgbm = model_scores["lgbm"]
        eif = model_scores["eif"]
        arf = model_scores["arf"]

        # ── Dynamic ARF weighting based on confidence ──────────────────
        arf_conf = float(model_scores.get("arf_confidence", 1.0))
        w_lgbm_base = self._weights.get("lgbm", 0.50)
        w_eif_base = self._weights.get("eif", 0.30)
        w_arf_base = self._weights.get("arf", 0.20)

        # Scale ARF weight by confidence; redistribute remainder to LGBM+EIF
        w_arf = w_arf_base * arf_conf
        redistributed = w_arf_base - w_arf  # weight to redistribute
        lgbm_eif_total = w_lgbm_base + w_eif_base
        if lgbm_eif_total > 0:
            w_lgbm = w_lgbm_base + redistributed * (w_lgbm_base / lgbm_eif_total)
            w_eif = w_eif_base + redistributed * (w_eif_base / lgbm_eif_total)
        else:
            w_lgbm, w_eif = w_lgbm_base, w_eif_base

        # Vectorized fusion
        combined = lgbm * w_lgbm + eif * w_eif + arf * w_arf

        # Per-event std_dev and agreement
        stacked = np.stack([lgbm, eif, arf], axis=1)  # (N, 3)
        std_devs = np.std(stacked, axis=1)
        agreements = 1.0 - std_devs

        # 95% confidence interval
        ci_lowers = np.clip(combined - 1.96 * std_devs, 0.0, 1.0)
        ci_uppers = np.clip(combined + 1.96 * std_devs, 0.0, 1.0)

        results = []
        for i in range(len(events)):
            event = events[i]
            feat = features_list[i]

            source_type = feat.get("_source_type", "")
            hostname = str(event.get("hostname", ""))
            source_ip = str(
                event.get("src_ip", event.get("ip_address", ""))
            )
            user_id = str(event.get("user", event.get("user_id", "")))
            template_id = str(feat.get("_template_id", ""))

            # ── Allowlist check (before scoring) ────────────────────────
            if self._allowlist and self._allowlist.is_allowed(
                ip=source_ip,
                user=user_id,
                hostname=hostname,
                template_id=template_id,
                source_type=source_type,
            ):
                results.append(
                    self._make_discard_result(
                        event, feat, lgbm[i], eif[i], arf[i],
                        combined[i], std_devs[i], agreements[i],
                        ci_lowers[i], ci_uppers[i],
                    )
                )
                continue

            # ── IOC enrichment ──────────────────────────────────────────
            ioc_match = 0
            ioc_confidence = 0
            if self._ioc_lookup:
                if source_ip and self._ioc_lookup.check(source_ip):
                    ioc_match = 1
                    ioc_confidence = self._ioc_lookup.get_confidence(source_ip)
                dst_ip = str(event.get("dst_ip", ""))
                if dst_ip and not ioc_match and self._ioc_lookup.check(dst_ip):
                    ioc_match = 1
                    ioc_confidence = self._ioc_lookup.get_confidence(dst_ip)

            # ── Asset criticality multiplier ────────────────────────────
            asset_multiplier = 1.0
            if self._asset_criticality:
                asset_multiplier = self._asset_criticality.get_multiplier(hostname)

            # IOC match bumps multiplier
            if ioc_match:
                asset_multiplier = max(asset_multiplier, 1.5)

            # ── Post-model adjusters ──────────────────────────────────
            score_boost = 0.0

            # Template rarity: removed from v6 model features.  Use the
            # metadata key (_template_rarity) for any future boost logic.
            # Boost is disabled (config.TEMPLATE_RARITY_BOOST_MAX = 0.0).
            tmpl_rarity = float(feat.get("_template_rarity", feat.get("template_rarity", 0.5)))
            if tmpl_rarity < config.TEMPLATE_RARITY_RARE_THRESHOLD:
                # Linearly scale boost: rarity 0 → full boost, threshold → 0
                rarity_factor = 1.0 - (tmpl_rarity / config.TEMPLATE_RARITY_RARE_THRESHOLD)
                score_boost += config.TEMPLATE_RARITY_BOOST_MAX * rarity_factor

            # IOC match: models trained with constant 0, so IOC info is only
            # usable via the multiplier above AND this direct score boost.
            if ioc_match:
                score_boost += config.IOC_MATCH_SCORE_BOOST

            # ── Adjusted score ──────────────────────────────────────────
            adjusted = min(1.0, (float(combined[i]) + score_boost) * asset_multiplier)

            # ── EIF anomaly override ────────────────────────────────────
            # When the unsupervised EIF strongly flags an event as anomalous
            # but the supervised LightGBM doesn't recognise the pattern,
            # the combined score gets diluted.  This override ensures that
            # novel anomalies are at least investigated (MONITOR).
            eif_override_applied = 0
            if float(eif[i]) >= config.EIF_ANOMALY_OVERRIDE_THRESHOLD:
                floor = config.EIF_ANOMALY_OVERRIDE_FLOOR
                if adjusted < floor:
                    adjusted = floor
                    eif_override_applied = 1

            # ── Per-source thresholds (topic → source_type → global) ──
            topic = str(feat.get("_topic", ""))
            if self._source_thresholds:
                suspicious_th, anomalous_th = self._source_thresholds.get_thresholds(
                    source_type, topic=topic
                )
            else:
                suspicious_th = config.DEFAULT_SUSPICIOUS_THRESHOLD
                anomalous_th = config.DEFAULT_ANOMALOUS_THRESHOLD

            # ── Routing decision ────────────────────────────────────────
            if adjusted >= anomalous_th:
                action = "escalate"
            elif adjusted >= suspicious_th:
                action = "monitor"
            else:
                action = "discard"

            # ── Disagreement flag ───────────────────────────────────────
            disagreement = 1 if float(std_devs[i]) >= config.DISAGREEMENT_THRESHOLD else 0

            # Disagreement with high combined → force escalate
            if disagreement and action == "monitor" and adjusted >= config.DISAGREEMENT_ESCALATION_FLOOR:
                action = "escalate"

            # ── MITRE tags (from original event if present) ─────────────
            mitre_tactic = str(event.get("mitre_tactic", ""))
            mitre_technique = str(event.get("mitre_technique", ""))

            # ── Feature staleness ───────────────────────────────────────
            features_stale = 0

            results.append(
                TriageResult(
                    event_id=str(event.get("event_id", event.get("id", ""))),
                    timestamp=str(event.get("timestamp", "")),
                    source_type=source_type,
                    hostname=hostname,
                    source_ip=source_ip,
                    user_id=user_id,
                    template_id=template_id,
                    template_rarity=float(feat.get("_template_rarity", feat.get("template_rarity", 0.0))),
                    combined_score=float(combined[i]),
                    lgbm_score=float(lgbm[i]),
                    eif_score=float(eif[i]),
                    arf_score=float(arf[i]),
                    score_std_dev=float(std_devs[i]),
                    agreement=float(agreements[i]),
                    ci_lower=float(ci_lowers[i]),
                    ci_upper=float(ci_uppers[i]),
                    asset_multiplier=asset_multiplier,
                    adjusted_score=adjusted,
                    action=action,
                    ioc_match=ioc_match,
                    ioc_confidence=ioc_confidence,
                    mitre_tactic=mitre_tactic,
                    mitre_technique=mitre_technique,
                    features_stale=features_stale,
                    model_version=self._model_version,
                    disagreement_flag=disagreement,
                )
            )

        return results

    def _make_discard_result(
        self, event, feat, lgbm_s, eif_s, arf_s, combined, std_dev, agreement,
        ci_lower, ci_upper,
    ) -> TriageResult:
        """Create a discard result for allowlisted events."""
        return TriageResult(
            event_id=str(event.get("event_id", event.get("id", ""))),
            timestamp=str(event.get("timestamp", "")),
            source_type=str(feat.get("_source_type", "")),
            hostname=str(event.get("hostname", "")),
            source_ip=str(event.get("src_ip", event.get("ip_address", ""))),
            user_id=str(event.get("user", event.get("user_id", ""))),
            template_id=str(feat.get("_template_id", "")),
            template_rarity=float(feat.get("_template_rarity", feat.get("template_rarity", 0.0))),
            combined_score=float(combined),
            lgbm_score=float(lgbm_s),
            eif_score=float(eif_s),
            arf_score=float(arf_s),
            score_std_dev=float(std_dev),
            agreement=float(agreement),
            ci_lower=float(ci_lower),
            ci_upper=float(ci_upper),
            asset_multiplier=1.0,
            adjusted_score=float(combined),
            action="discard",
            ioc_match=0,
            ioc_confidence=0,
            mitre_tactic="",
            mitre_technique="",
            features_stale=0,
            model_version=self._model_version,
            disagreement_flag=0,
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "weights": self._weights,
            "model_version": self._model_version,
            "default_thresholds": {
                "suspicious": config.DEFAULT_SUSPICIOUS_THRESHOLD,
                "anomalous": config.DEFAULT_ANOMALOUS_THRESHOLD,
            },
            "disagreement_threshold": config.DISAGREEMENT_THRESHOLD,
            "post_model_adjusters": {
                "template_rarity_rare_threshold": config.TEMPLATE_RARITY_RARE_THRESHOLD,
                "template_rarity_boost_max": config.TEMPLATE_RARITY_BOOST_MAX,
                "ioc_match_score_boost": config.IOC_MATCH_SCORE_BOOST,
            },
            "arf_confidence_ramp_samples": config.ARF_CONFIDENCE_RAMP_SAMPLES,
        }


class DriftMonitor:
    """
    Monitors feature distribution drift via PSI and KL divergence.

    Collects feature vectors during inference and periodically compares
    them against the training baseline. Results are written to the
    pipeline_metrics table in ClickHouse.

    PSI (Population Stability Index):
        For each feature, bin the training and inference distributions into
        N quantile buckets, then: PSI = sum (p_i - q_i) * ln(p_i / q_i)
        PSI < 0.1 = no drift, 0.1-0.25 = moderate, > 0.25 = significant

    KL Divergence:
        KL(P || Q) = sum p_i * ln(p_i / q_i) where P = inference, Q = training
    """

    def __init__(self, ch_client, feature_names: List[str]):
        self._ch_client = ch_client
        self._feature_names = feature_names
        self._buffer: List[np.ndarray] = []
        self._baseline: Optional[np.ndarray] = None
        self._baseline_quantiles: Optional[Dict[str, np.ndarray]] = None
        self._batch_counter = 0
        self._last_psi: Optional[float] = None
        self._last_kl: Optional[float] = None
        self._per_feature_psi: Dict[str, float] = {}
        self._lock = threading.Lock()

        # Try to load training baseline from the replay buffer
        self._load_baseline()

    def _load_baseline(self) -> None:
        """Load training baseline distribution from arf_replay_buffer."""
        if self._ch_client is None:
            return
        try:
            cols = ", ".join(self._feature_names)
            rows = self._ch_client.execute(
                f"SELECT {cols} FROM clif_logs.arf_replay_buffer "
                f"ORDER BY timestamp ASC LIMIT {config.DRIFT_WINDOW_SIZE}"
            )
            if len(rows) < 100:
                logger.info("Drift baseline too small (%d rows), skipping", len(rows))
                return

            self._baseline = np.array(rows, dtype=np.float32)
            # Pre-compute quantile edges for each feature
            self._baseline_quantiles = {}
            n_bins = config.DRIFT_PSI_BINS
            for i, name in enumerate(self._feature_names):
                col = self._baseline[:, i]
                quantiles = np.linspace(0, 100, n_bins + 1)
                edges = np.percentile(col, quantiles)
                edges = np.unique(edges)
                self._baseline_quantiles[name] = edges

            logger.info(
                "Drift baseline loaded: %d samples, %d features",
                len(rows), len(self._feature_names),
            )
        except Exception as e:
            logger.warning("Failed to load drift baseline: %s", e)

    def record_batch(self, X: np.ndarray) -> None:
        """Record a batch of feature vectors for drift analysis."""
        if not config.DRIFT_ENABLED or self._baseline is None:
            return

        with self._lock:
            self._buffer.append(X.copy())
            self._batch_counter += 1

            if self._batch_counter % config.DRIFT_INTERVAL_BATCHES == 0:
                all_features = np.vstack(self._buffer)
                if len(all_features) > config.DRIFT_WINDOW_SIZE:
                    all_features = all_features[-config.DRIFT_WINDOW_SIZE:]
                self._buffer = [all_features]

                threading.Thread(
                    target=self._compute_and_store_drift,
                    args=(all_features,),
                    daemon=True,
                ).start()

    def _compute_and_store_drift(self, current: np.ndarray) -> None:
        """Compute PSI and KL divergence and store in pipeline_metrics."""
        try:
            eps = 1e-8
            total_psi = 0.0
            total_kl = 0.0
            per_feature_psi: Dict[str, float] = {}

            for i, name in enumerate(self._feature_names):
                baseline_col = self._baseline[:, i]
                current_col = current[:, i]

                edges = self._baseline_quantiles.get(name)
                if edges is None or len(edges) < 2:
                    continue

                baseline_hist = np.histogram(baseline_col, bins=edges)[0].astype(float)
                current_hist = np.histogram(current_col, bins=edges)[0].astype(float)

                baseline_hist = baseline_hist / (baseline_hist.sum() + eps) + eps
                current_hist = current_hist / (current_hist.sum() + eps) + eps

                feature_psi = float(np.sum(
                    (current_hist - baseline_hist) * np.log(current_hist / baseline_hist)
                ))
                per_feature_psi[name] = feature_psi
                total_psi += feature_psi

                total_kl += float(np.sum(current_hist * np.log(current_hist / baseline_hist)))

            n_features = len(self._feature_names)
            avg_psi = total_psi / max(n_features, 1)
            avg_kl = total_kl / max(n_features, 1)

            self._last_psi = avg_psi
            self._last_kl = avg_kl
            self._per_feature_psi = per_feature_psi

            if avg_psi >= config.DRIFT_PSI_CRITICAL:
                logger.warning(
                    "CRITICAL DRIFT detected: PSI=%.4f, KL=%.4f (threshold=%.2f)",
                    avg_psi, avg_kl, config.DRIFT_PSI_CRITICAL,
                )
            elif avg_psi >= config.DRIFT_PSI_WARNING:
                logger.warning(
                    "Moderate drift detected: PSI=%.4f, KL=%.4f",
                    avg_psi, avg_kl,
                )

            if self._ch_client is not None:
                from datetime import datetime, timezone

                ts = datetime.now(timezone.utc)
                rows = [
                    (ts, "psi_drift", float(avg_psi)),
                    (ts, "kl_divergence", float(avg_kl)),
                    (ts, "psi_max", float(max(per_feature_psi.values())) if per_feature_psi else 0.0),
                ]
                top_features = sorted(per_feature_psi.items(), key=lambda x: x[1], reverse=True)[:5]
                for feat_name, feat_psi in top_features:
                    rows.append((ts, f"psi_feature_{feat_name}", float(feat_psi)))

                self._ch_client.execute(
                    "INSERT INTO clif_logs.pipeline_metrics (ts, metric, value) VALUES",
                    rows,
                )
                logger.info(
                    "Drift metrics stored: PSI=%.4f, KL=%.4f, max_feature_PSI=%.4f",
                    avg_psi, avg_kl, max(per_feature_psi.values()) if per_feature_psi else 0.0,
                )

        except Exception as e:
            logger.warning("Drift computation failed: %s", e)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enabled": config.DRIFT_ENABLED,
            "baseline_loaded": self._baseline is not None,
            "baseline_size": len(self._baseline) if self._baseline is not None else 0,
            "batches_since_last_check": self._batch_counter % config.DRIFT_INTERVAL_BATCHES,
            "last_psi": self._last_psi,
            "last_kl": self._last_kl,
            "per_feature_psi": self._per_feature_psi,
        }
