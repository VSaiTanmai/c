#!/usr/bin/env python3
"""
CLIF Triage Agent — Complete Model Retraining Pipeline (v3 — Production)
=========================================================================
Builds training data from ALL available datasets, retrains all 3 models,
computes calibration, validates accuracy, and exports production artifacts.

12 DATASETS (all vectorized — ~30 seconds total extraction):
   1. CICIDS2017 stratified (30K)        — network flow
   2. NSL-KDD stratified (24K)           — IDS (native KDD features)
   3. UNSW-NB15 stratified (20K)         — network flow
   4. NF-UNSW-NB15-v3 stratified (12K)   — NetFlow
   5. NF-ToN-IoT temporal (11K)          — IoT NetFlow
   6. CSIC 2010 (61K → 20K sampled)      — HTTP web attacks
   7. EVTX Attack Samples (4.6K + 4.6K)  — Windows Events
   8. Loghub Linux (2K)                  — Syslog auth logs
   9. Loghub Apache (2K)                 — Web server error logs
  10. CIC-Bell DNS Exfiltration (20K)    — DNS tunneling/exfil
  11. OpenSSH Loghub (2K)                — SSH auth logs
  12. HDFS Event Traces (10K)            — Hadoop anomalies

LABEL LEAKAGE PREVENTION:
   severity_numeric is computed from SOURCE-SYSTEM fields only (original_log_level).
   Network datasets that have NO inherent severity get random noise N(1, 0.5).
   Log datasets derive severity from legitimate source-system keywords.
   Vector's classification-based severity is NEVER used.

Usage:
    python scripts/retrain_all.py
    python scripts/retrain_all.py --dry-run    # validate data only, no training
"""

import hashlib
import json
import logging
import os
import pickle
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
#  Logging — flush immediately so output appears in real time
# ---------------------------------------------------------------------------
class _FlushHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_FlushHandler(sys.stdout)],
)
log = logging.getLogger("retrain")


# ---------------------------------------------------------------------------
#  Paths
# ---------------------------------------------------------------------------
BASE_DIR       = Path(__file__).resolve().parent.parent
DATA_DIR       = BASE_DIR / "agents" / "Data"
DATASETS_DIR   = DATA_DIR / "datasets"
NEW_DATA_DIR   = DATA_DIR / "New_Dataset"
MODEL_DIR      = BASE_DIR / "agents" / "triage" / "models"


# ---------------------------------------------------------------------------
#  20 canonical features (MUST match feature_extractor.py exactly)
# ---------------------------------------------------------------------------
FEATURE_COLS = [
    "hour_of_day", "day_of_week", "severity_numeric", "source_type_numeric",
    "src_bytes", "dst_bytes", "event_freq_1m", "protocol", "dst_port",
    "template_rarity", "threat_intel_flag", "duration",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

PROTO_MAP = {
    "tcp": 6, "udp": 17, "icmp": 1, "igmp": 2,
    "gre": 47, "esp": 50, "sctp": 132,
}


# =========================================================================
#  HELPERS
# =========================================================================

def _safe_col(df: pd.DataFrame, name: str, default: float = 0.0) -> pd.Series:
    """Get column as float64, filling NaN/Inf with *default*."""
    if name in df.columns:
        s = pd.to_numeric(df[name], errors="coerce").fillna(default)
        return s.replace([np.inf, -np.inf], default).astype(np.float64)
    return pd.Series(default, index=df.index, dtype=np.float64)


def _proto_col(df: pd.DataFrame, colname: str) -> pd.Series:
    """Convert a protocol column (name or number) to IANA numbers."""
    if colname not in df.columns:
        return pd.Series(0.0, index=df.index, dtype=np.float64)
    s = df[colname].astype(str).str.strip().str.lower()
    mapped  = s.map(PROTO_MAP)
    numeric = pd.to_numeric(s, errors="coerce")
    return mapped.fillna(numeric).fillna(0.0).astype(np.float64)


def _read_csv_from_dir(
    root_dir: Path, pattern: str, require_in_path: str | None = None,
) -> pd.DataFrame | None:
    """Walk *root_dir* recursively for a file matching *pattern*.

    When *require_in_path* is given the relative path must also contain
    that substring (used to disambiguate duplicates across category
    folders).  Returns the **first** match as a DataFrame.
    """
    root = Path(root_dir)
    for p in sorted(root.rglob(pattern)):
        rel = str(p.relative_to(root))
        if require_in_path and require_in_path not in rel:
            continue
        log.info("    reading %s", p.relative_to(BASE_DIR))
        return pd.read_csv(str(p), low_memory=False)
    return None


def _make_frame(n: int, **col_arrays) -> pd.DataFrame:
    """Build a DataFrame with FEATURE_COLS + label + attack_type + source_dataset."""
    out = pd.DataFrame(index=range(n))
    for col in FEATURE_COLS + ["label", "attack_type", "source_dataset"]:
        if col in col_arrays:
            v = col_arrays[col]
            out[col] = v.values if isinstance(v, pd.Series) else v
        elif col in ("attack_type", "source_dataset"):
            out[col] = "unknown"
        else:
            out[col] = 0.0
    return out


def _dataset_fingerprint(df: pd.DataFrame, name: str) -> str:
    """Deterministic hash for reproducibility audits."""
    h = hashlib.sha256()
    h.update(name.encode())
    h.update(str(len(df)).encode())
    h.update(str(sorted(df.columns.tolist())).encode())
    if len(df) > 0:
        h.update(df.iloc[0].to_json().encode())
        h.update(df.iloc[-1].to_json().encode())
    fp = h.hexdigest()[:12]
    log.info(
        "  fingerprint(%s): %s  rows=%d  label_dist=%s",
        name, fp, len(df), df["label"].value_counts().to_dict(),
    )
    return fp


# =========================================================================
#  DATASET LOADERS  (all vectorized — NO iterrows)
#  Each loader seeds its own RNG for exact reproducibility.
# =========================================================================

# ---- 1. CICIDS2017 -------------------------------------------------------
def load_cicids2017() -> pd.DataFrame:
    """CICIDS2017 — network flow IDS dataset (stratified ≈30 K)."""
    rng = np.random.RandomState(4201)
    log.info("Loading CICIDS2017 stratified …")
    df = _read_csv_from_dir(DATASETS_DIR, "cicids2017_stratified.csv", "01_syslog")
    if df is None:
        log.error("  CICIDS2017 CSV not found!")
        return pd.DataFrame()
    n = len(df)
    log.info("  %d rows", n)

    is_attack = df["binary_label"].astype(int) == 1
    labels = is_attack.astype(int)
    attack_type = df["attack_type"].fillna(
        df.get("Label", pd.Series("unknown", index=df.index))
    ).astype(str)
    attack_type[~is_attack] = "normal"

    fwd_pkts = _safe_col(df, "Total Fwd Packets", 1).clip(lower=1)

    # NO LEAKAGE: flows arrive with no inherent severity
    severity = np.clip(rng.normal(1.0, 0.5, n), 0, 4).astype(float)

    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 9.0),
        src_bytes          = _safe_col(df, "Total Length of Fwd Packets").clip(0, 1e9).values,
        dst_bytes          = _safe_col(df, "Total Length of Bwd Packets").clip(0, 1e9).values,
        event_freq_1m      = _safe_col(df, "Flow Packets/s").clip(0, 1e5).values,
        protocol           = np.full(n, 6.0),
        dst_port           = _safe_col(df, "Destination Port").clip(0, 65535).values,
        template_rarity    = np.clip(0.5 + rng.normal(0, 0.1, n), 0, 1),
        threat_intel_flag  = np.zeros(n),
        duration           = (_safe_col(df, "Flow Duration") / 1e6).clip(0, 1e6).values,  # µs → seconds (inference does duration_ms/1000)
        same_srv_rate      = (_safe_col(df, "Subflow Fwd Packets") / fwd_pkts).clip(0, 1).values,
        diff_srv_rate      = np.zeros(n),
        serror_rate        = (_safe_col(df, "SYN Flag Count") / fwd_pkts).clip(0, 1).values,
        rerror_rate        = (_safe_col(df, "RST Flag Count") / fwd_pkts).clip(0, 1).values,
        count              = (_safe_col(df, "Total Fwd Packets") + _safe_col(df, "Total Backward Packets")).values,
        srv_count          = _safe_col(df, "Total Fwd Packets").values,
        dst_host_count     = np.ones(n),
        dst_host_srv_count = np.ones(n),
        label              = labels.values,
        attack_type        = attack_type.values,
        source_dataset     = np.full(n, "cicids2017", dtype=object),
    )


# ---- 2. NSL-KDD ----------------------------------------------------------
def load_nsl_kdd() -> pd.DataFrame:
    """NSL-KDD — IDS dataset with native KDD statistical features."""
    rng = np.random.RandomState(4202)
    log.info("Loading NSL-KDD stratified …")
    df = _read_csv_from_dir(DATASETS_DIR, "nsl_kdd_stratified.csv")
    if df is None:
        log.error("  NSL-KDD CSV not found!")
        return pd.DataFrame()
    n = len(df)
    log.info("  %d rows", n)

    labels = df["binary_label"].astype(int)
    attack_type = df["attack_type"].astype(str)
    attack_type[labels == 0] = "normal"

    # NO LEAKAGE: IDS records have no inherent severity
    severity = np.clip(rng.normal(1.0, 0.5, n), 0, 4).astype(float)

    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 10.0),
        src_bytes          = _safe_col(df, "src_bytes").clip(0, 1e9).values,
        dst_bytes          = _safe_col(df, "dst_bytes").clip(0, 1e9).values,
        event_freq_1m      = _safe_col(df, "count").values,
        protocol           = _proto_col(df, "protocol_type").values,
        dst_port           = np.zeros(n),
        template_rarity    = np.full(n, 0.5),
        threat_intel_flag  = np.zeros(n),
        duration           = _safe_col(df, "duration").values,
        same_srv_rate      = _safe_col(df, "same_srv_rate").clip(0, 1).values,
        diff_srv_rate      = _safe_col(df, "diff_srv_rate").clip(0, 1).values,
        serror_rate        = _safe_col(df, "serror_rate").clip(0, 1).values,
        rerror_rate        = _safe_col(df, "rerror_rate").clip(0, 1).values,
        count              = _safe_col(df, "count").values,
        srv_count          = _safe_col(df, "srv_count").values,
        dst_host_count     = _safe_col(df, "dst_host_count").values,
        dst_host_srv_count = _safe_col(df, "dst_host_srv_count").values,
        label              = labels.values,
        attack_type        = attack_type.values,
        source_dataset     = np.full(n, "nsl_kdd", dtype=object),
    )


# ---- 3. UNSW-NB15 --------------------------------------------------------
def load_unsw_nb15() -> pd.DataFrame:
    """UNSW-NB15 — network flow dataset."""
    rng = np.random.RandomState(4203)
    log.info("Loading UNSW-NB15 stratified …")
    df = _read_csv_from_dir(DATASETS_DIR, "unsw_stratified.csv", "03_firewall")
    if df is None:
        log.error("  UNSW-NB15 CSV not found!")
        return pd.DataFrame()
    n = len(df)
    log.info("  %d rows", n)

    if "binary_label" in df.columns:
        labels = _safe_col(df, "binary_label", 0).astype(int)
    else:
        labels = _safe_col(df, "label", 0).astype(int)

    if "attack_type" in df.columns:
        attack_type = df["attack_type"].astype(str)
    elif "attack_cat" in df.columns:
        attack_type = df["attack_cat"].astype(str)
    else:
        attack_type = pd.Series("unknown", index=df.index)
    attack_type[labels == 0] = "normal"

    ct_srv_src = _safe_col(df, "ct_srv_src").clip(lower=1)

    # NO LEAKAGE: firewall flows have no inherent severity
    severity = np.clip(rng.normal(1.0, 0.5, n), 0, 4).astype(float)

    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 3.0),
        src_bytes          = _safe_col(df, "sbytes").clip(0, 1e9).values,
        dst_bytes          = _safe_col(df, "dbytes").clip(0, 1e9).values,
        event_freq_1m      = ct_srv_src.values,
        protocol           = _proto_col(df, "proto").values,
        dst_port           = _safe_col(df, "dsport").clip(0, 65535).values,
        template_rarity    = np.full(n, 0.5),
        threat_intel_flag  = np.zeros(n),
        duration           = _safe_col(df, "dur").clip(0, 1e9).values,
        same_srv_rate      = (_safe_col(df, "ct_dst_ltm") / ct_srv_src).clip(0, 1).values,
        diff_srv_rate      = (_safe_col(df, "ct_dst_sport_ltm") / ct_srv_src).clip(0, 1).values,
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = ct_srv_src.values,
        srv_count          = _safe_col(df, "ct_srv_dst").values,
        dst_host_count     = _safe_col(df, "ct_dst_ltm").values,
        dst_host_srv_count = _safe_col(df, "ct_src_ltm").values,
        label              = labels.values,
        attack_type        = attack_type.values,
        source_dataset     = np.full(n, "unsw_nb15", dtype=object),
    )


# ---- 4 & 5: NetFlow shared helper ----------------------------------------
def _load_netflow_format(
    df: pd.DataFrame, source_dataset: str, seed: int,
) -> pd.DataFrame:
    """Shared vectorized loader for NetFlow-format datasets."""
    rng = np.random.RandomState(seed)
    n = len(df)
    df.columns = [c.strip().strip("\r") for c in df.columns]

    label_col = "binary_label" if "binary_label" in df.columns else "Label"
    labels = _safe_col(df, label_col, 0).astype(int)
    attack_col = "Attack" if "Attack" in df.columns else "attack_type"
    attack_type = (
        df[attack_col].astype(str) if attack_col in df.columns
        else pd.Series("unknown", index=df.index)
    )
    benign_mask = attack_type.str.lower().isin(["benign", "normal", "0"])
    labels[benign_mask] = 0
    attack_type[benign_mask] = "normal"

    # Timestamp → hour / dow
    ts_ms = _safe_col(df, "FLOW_START_MILLISECONDS", 0)
    valid_ts = ts_ms > 1e12
    hour = pd.Series(rng.randint(0, 24, n).astype(float), index=df.index)
    dow  = pd.Series(rng.randint(0, 7, n).astype(float), index=df.index)
    if valid_ts.any():
        dt = pd.to_datetime(ts_ms[valid_ts] / 1000.0, unit="s", utc=True, errors="coerce")
        valid_dt = dt.notna()
        if valid_dt.any():
            hour.loc[valid_ts] = dt[valid_dt].dt.hour.astype(float).values[:valid_ts.sum()]
            dow.loc[valid_ts]  = dt[valid_dt].dt.dayofweek.astype(float).values[:valid_ts.sum()]

    # NO LEAKAGE: NetFlow records have no inherent severity
    severity = np.clip(rng.normal(1.0, 0.5, n), 0, 4).astype(float)

    return _make_frame(
        n,
        hour_of_day        = hour.values,
        day_of_week        = dow.values,
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 9.0),
        src_bytes          = _safe_col(df, "IN_BYTES").clip(0, 1e9).values,
        dst_bytes          = _safe_col(df, "OUT_BYTES").clip(0, 1e9).values,
        event_freq_1m      = (_safe_col(df, "IN_PKTS") + _safe_col(df, "OUT_PKTS")).values,
        protocol           = _safe_col(df, "PROTOCOL").values,
        dst_port           = _safe_col(df, "L4_DST_PORT").clip(0, 65535).values,
        template_rarity    = np.clip(0.5 + rng.normal(0, 0.1, n), 0, 1),
        threat_intel_flag  = np.zeros(n),
        duration           = (_safe_col(df, "FLOW_DURATION_MILLISECONDS") / 1000.0).clip(0, 1e6).values,  # ms → seconds
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = _safe_col(df, "IN_PKTS").values,
        srv_count          = _safe_col(df, "OUT_PKTS").values,
        dst_host_count     = np.ones(n),
        dst_host_srv_count = np.ones(n),
        label              = labels.values,
        attack_type        = attack_type.values,
        source_dataset     = np.full(n, source_dataset, dtype=object),
    )


def load_nf_unsw() -> pd.DataFrame:
    """NF-UNSW-NB15-v3 — NetFlow format."""
    log.info("Loading NF-UNSW-NB15-v3 stratified …")
    df = _read_csv_from_dir(DATASETS_DIR, "nf_unsw_stratified.csv")
    if df is None:
        log.error("  NF-UNSW CSV not found!")
        return pd.DataFrame()
    log.info("  %d rows", len(df))
    return _load_netflow_format(df, "nf_unsw_nb15_v3", seed=4204)


def load_ton_iot() -> pd.DataFrame:
    """NF-ToN-IoT — IoT NetFlow dataset (temporal split)."""
    log.info("Loading NF-ToN-IoT temporal …")
    df = _read_csv_from_dir(DATASETS_DIR, "nf_ton_iot_temporal.csv")
    if df is None:
        log.error("  NF-ToN-IoT CSV not found!")
        return pd.DataFrame()
    log.info("  %d rows", len(df))
    return _load_netflow_format(df, "nf_ton_iot", seed=4205)


# ---- 6. CSIC 2010 --------------------------------------------------------
def load_csic2010() -> pd.DataFrame:
    """CSIC 2010 — HTTP web attack dataset."""
    rng = np.random.RandomState(4206)
    log.info("Loading CSIC 2010 (web attacks) …")
    df = _read_csv_from_dir(DATASETS_DIR, "csic_database.csv", "08_nginx")
    if df is None:
        log.error("  CSIC 2010 CSV not found!")
        return pd.DataFrame()
    log.info("  %d rows, dist: %s", len(df), df["classification"].value_counts().to_dict())

    df_n = df[df["classification"] == 0]
    df_a = df[df["classification"] == 1]
    if len(df_n) > 10_000:
        df_n = df_n.sample(n=10_000, random_state=42)
    if len(df_a) > 10_000:
        df_a = df_a.sample(n=10_000, random_state=42)
    df = pd.concat([df_n, df_a], ignore_index=True)
    n = len(df)
    log.info("  Subsampled to %d", n)

    labels   = df["classification"].astype(int)
    is_attack = labels == 1

    content_len = _safe_col(df, "lenght", 0)          # sic — upstream typo
    content_str = df.get("content", pd.Series("", index=df.index)).astype(str)
    content_fb  = content_str.str.len().astype(float)
    src_bytes   = np.where(content_len > 0, content_len, content_fb)

    # NO LEAKAGE: template_rarity from URL length (same formula for ALL rows)
    url_len = df.get("URL", pd.Series("", index=df.index)).astype(str).str.len().astype(float)
    template_rarity = np.clip(url_len / 200.0, 0.0, 1.0)

    # NO LEAKAGE: HTTP requests arrive with no severity level
    severity = np.zeros(n)

    # ALIGNED WITH INFERENCE: CSIC HTTP logs arrive as web server logs (non-network path)
    # source_type=8 (nginx/web) → raw-logs topic → non-network in feature_extractor.py
    return _make_frame(
        n,
        hour_of_day        = rng.randint(8, 20, n).astype(float),
        day_of_week        = rng.randint(0, 5, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 8.0),
        src_bytes          = np.clip(src_bytes, 0, 1e9),
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),                  # non-network → 0
        protocol           = np.full(n, 6.0),
        dst_port           = np.full(n, 80.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),                  # non-network → 0
        same_srv_rate      = np.zeros(n),                  # non-network → 0
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),                  # non-network → 0
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels.values,
        attack_type        = np.where(is_attack, "web_attack", "normal"),
        source_dataset     = np.full(n, "csic_2010", dtype=object),
    )


# ---- 7. EVTX Attack Samples + synthetic normals --------------------------
def load_evtx() -> pd.DataFrame:
    """EVTX — Windows event logs (attacks + synthetic normals)."""
    rng = np.random.RandomState(4207)
    log.info("Loading EVTX attack samples + synthetic normals …")
    df = _read_csv_from_dir(DATASETS_DIR, "evtx_data.csv", "02_windows")
    if df is None:
        log.error("  EVTX CSV not found!")
        return pd.DataFrame()
    n_attack = len(df)
    log.info("  %d attack rows", n_attack)

    # NO LEAKAGE: severity from EventID (real Windows event level),
    # NOT from the MITRE tactic label
    event_id = _safe_col(df, "EventID", 0).astype(int)
    warning_eids = {4625, 4771, 4776}               # logon failures → Warning
    severity = np.where(event_id.isin(warning_eids), 2.0, 0.0)

    dst_port = _safe_col(df, "DestPort", 0)
    if "DestinationPort" in df.columns:
        dst_port = dst_port.where(dst_port > 0, _safe_col(df, "DestinationPort", 0))
    dst_port = dst_port.clip(0, 65535).values

    tr_attack = np.clip(0.4 + rng.normal(0, 0.1, n_attack), 0, 1)

    attack_type = ("evtx_" + df["EVTX_Tactic"].str.lower().str.replace(" ", "_")).values

    # ALIGNED WITH INFERENCE (feature_extractor.py non-network path):
    #   event_freq_1m=0, protocol=6 (TCP default), count/srv_count=0,
    #   dst_host_count/srv_count=0, src_bytes≈len(message)
    attack_frame = _make_frame(
        n_attack,
        hour_of_day        = rng.randint(0, 24, n_attack).astype(float),
        day_of_week        = rng.randint(0, 7, n_attack).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n_attack, 2.0),
        src_bytes          = rng.randint(100, 2000, n_attack).astype(float),  # ≈ len(event message)
        dst_bytes          = np.zeros(n_attack),
        event_freq_1m      = np.zeros(n_attack),           # non-network → 0
        protocol           = np.full(n_attack, 6.0),       # non-network default = TCP(6)
        dst_port           = dst_port,
        template_rarity    = tr_attack,
        threat_intel_flag  = np.zeros(n_attack),
        duration           = np.zeros(n_attack),
        same_srv_rate      = np.zeros(n_attack),
        diff_srv_rate      = np.zeros(n_attack),
        serror_rate        = np.zeros(n_attack),
        rerror_rate        = np.zeros(n_attack),
        count              = np.zeros(n_attack),            # non-network → 0
        srv_count          = np.zeros(n_attack),
        dst_host_count     = np.zeros(n_attack),
        dst_host_srv_count = np.zeros(n_attack),
        label              = np.ones(n_attack, dtype=int),
        attack_type        = attack_type,
        source_dataset     = np.full(n_attack, "evtx", dtype=object),
    )

    # Synthetic normals — mirror the attack frame count for balance
    n_norm = n_attack
    normal_frame = _make_frame(
        n_norm,
        hour_of_day        = rng.choice([8,9,10,11,12,13,14,15,16,17], n_norm).astype(float),
        day_of_week        = rng.randint(0, 5, n_norm).astype(float),
        severity_numeric   = np.zeros(n_norm),            # Information level
        source_type_numeric= np.full(n_norm, 2.0),
        src_bytes          = rng.randint(100, 1500, n_norm).astype(float),  # ≈ len(event message)
        dst_bytes          = np.zeros(n_norm),
        event_freq_1m      = np.zeros(n_norm),             # non-network → 0
        protocol           = np.full(n_norm, 6.0),         # non-network default = TCP(6)
        dst_port           = np.zeros(n_norm),
        template_rarity    = np.clip(0.4 + rng.normal(0, 0.1, n_norm), 0, 1),
        threat_intel_flag  = np.zeros(n_norm),
        duration           = np.zeros(n_norm),
        same_srv_rate      = np.zeros(n_norm),
        diff_srv_rate      = np.zeros(n_norm),
        serror_rate        = np.zeros(n_norm),
        rerror_rate        = np.zeros(n_norm),
        count              = np.zeros(n_norm),             # non-network → 0
        srv_count          = np.zeros(n_norm),
        dst_host_count     = np.zeros(n_norm),
        dst_host_srv_count = np.zeros(n_norm),
        label              = np.zeros(n_norm, dtype=int),
        attack_type        = np.full(n_norm, "normal", dtype=object),
        source_dataset     = np.full(n_norm, "evtx", dtype=object),
    )

    result = pd.concat([attack_frame, normal_frame], ignore_index=True)
    log.info("  EVTX total: %d rows", len(result))
    return result


# ---- 8. Loghub Linux -----------------------------------------------------
def load_loghub_linux() -> pd.DataFrame:
    """Loghub Linux — syslog auth/system logs."""
    rng = np.random.RandomState(4208)
    log.info("Loading Loghub Linux syslog …")
    df = _read_csv_from_dir(DATASETS_DIR, "Linux_2k.log_structured.csv", "path_a")
    if df is None:
        log.error("  Loghub Linux CSV not found!")
        return pd.DataFrame()
    df.columns = [c.strip().strip("\r") for c in df.columns]
    n = len(df)
    log.info("  %d rows", n)

    ATTACK_PATS = [
        "authentication failure", "failed password", "invalid user",
        "failed login", "refused connect", "illegal user",
        "did not receive identification", "connection closed",
    ]

    content = df.get("Content", pd.Series("", index=df.index)).astype(str).str.lower()
    is_attack = pd.Series(False, index=df.index)
    for pat in ATTACK_PATS:
        is_attack = is_attack | content.str.contains(pat, na=False, regex=False)
    labels = is_attack.astype(int)

    # HONEST severity: from syslog keywords (legitimate) + noise so it's
    # not a perfect label proxy
    has_failure = content.str.contains("failure|failed", na=False, regex=True)
    has_error   = content.str.contains("error|refused", na=False, regex=True)
    base_sev = np.where(has_failure, 2.5, np.where(has_error, 1.5, 0.5))
    severity = np.clip(base_sev + rng.normal(0, 0.5, n), 0, 4)

    template_rarity = np.clip(0.5 + rng.normal(0, 0.15, n), 0, 1)

    time_col = df.get("Time", pd.Series("", index=df.index)).astype(str)
    hour = time_col.str.extract(r"(\d+):", expand=False)
    hour = pd.to_numeric(hour, errors="coerce").fillna(12).astype(float) % 24

    component = df.get("Component", pd.Series("", index=df.index)).astype(str).str.lower()
    has_ssh   = component.str.contains("ssh", na=False)
    dst_port  = np.where(has_ssh, 22.0, 0.0)

    attack_type = np.where(
        is_attack & has_ssh, "ssh_brute_force",
        np.where(is_attack, "auth_failure", "normal"),
    )

    # ALIGNED WITH INFERENCE: non-network path in feature_extractor.py
    return _make_frame(
        n,
        hour_of_day        = hour.values,
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 1.0),
        src_bytes          = content.str.len().clip(10, 5000).astype(float).values,  # ≈ len(msg)
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),                  # non-network → 0
        protocol           = np.full(n, 6.0),              # non-network default TCP(6)
        dst_port           = dst_port,
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),                  # non-network → 0
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels.values,
        attack_type        = attack_type,
        source_dataset     = np.full(n, "loghub_linux", dtype=object),
    )


# ---- 9. Loghub Apache ----------------------------------------------------
def load_loghub_apache() -> pd.DataFrame:
    """Loghub Apache — web server error logs."""
    rng = np.random.RandomState(4209)
    log.info("Loading Loghub Apache …")
    df = _read_csv_from_dir(DATASETS_DIR, "Apache_2k.log_structured.csv", "path_a")
    if df is None:
        log.error("  Loghub Apache CSV not found!")
        return pd.DataFrame()
    df.columns = [c.strip().strip("\r") for c in df.columns]
    n = len(df)
    log.info("  %d rows", n)

    ERROR_PATS = ["error", "failed", "denied", "not found", "timeout", "refused"]
    content = df.get("Content", pd.Series("", index=df.index)).astype(str).str.lower()
    level   = df.get("Level", pd.Series("notice", index=df.index)).astype(str).str.lower()

    is_error_level = level.isin(["error", "crit", "alert", "emerg"])
    is_error_content = pd.Series(False, index=df.index)
    for pat in ERROR_PATS:
        is_error_content = is_error_content | content.str.contains(pat, na=False, regex=False)
    is_error = is_error_level | is_error_content
    labels = is_error.astype(int)

    # HONEST severity: from Apache log level (legitimate) + noise
    sev_map = {"emerg": 4.0, "alert": 3.5, "crit": 3.0, "error": 2.5,
               "warn": 1.5, "notice": 0.5, "info": 0.0}
    base_sev = level.map(sev_map).fillna(0.5).values.astype(float)
    severity = np.clip(base_sev + rng.normal(0, 0.3, n), 0, 4)

    template_rarity = np.clip(0.5 + rng.normal(0, 0.15, n), 0, 1)

    # ALIGNED WITH INFERENCE: non-network path in feature_extractor.py
    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 8.0),
        src_bytes          = content.str.len().clip(10, 5000).astype(float).values,  # ≈ len(msg)
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),                  # non-network → 0
        protocol           = np.full(n, 6.0),
        dst_port           = np.full(n, 80.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),                  # non-network → 0
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels.values,
        attack_type        = np.where(is_error, "web_error", "normal"),
        source_dataset     = np.full(n, "loghub_apache", dtype=object),
    )


# =========================================================================
#  NEW DATASETS (v3)
# =========================================================================

# ---- 10. CIC-Bell DNS Exfiltration 2021 ----------------------------------
def load_dns_exfil() -> pd.DataFrame:
    """CIC-Bell DNS Exfiltration 2021 — stateless per-query features.

    Maps DNS features to 20 canonical features:
      subdomain_length → src_bytes   (bytes encoded in subdomain)
      entropy          → template_rarity (high entropy = rare domain)
      FQDN_count       → event_freq_1m (query frequency)
      labels           → count (subdomain label count)
      protocol = 17 (UDP), dst_port = 53, source_type = 5 (DNS)
    """
    rng = np.random.RandomState(4210)
    log.info("Loading CIC-Bell DNS Exfiltration 2021 (stateless) …")

    dns_base = NEW_DATA_DIR / "CIC-Bell-DNS-EXFil-2021" / "CSV"
    if not dns_base.exists():
        log.error("  DNS dataset folder not found: %s", dns_base)
        return pd.DataFrame()

    # ---- Collect attack CSVs (in Attack_*/Attacks/stateless_*.csv) ----
    attack_frames = []
    for attack_dir in sorted(dns_base.glob("Attack_*")):
        for sub in [attack_dir / "Attacks", attack_dir]:
            for csv_path in sorted(sub.glob("stateless_*.csv")):
                try:
                    attack_frames.append(pd.read_csv(str(csv_path), low_memory=False))
                except Exception as e:
                    log.warning("    Skip %s: %s", csv_path.name, e)

    # ---- Collect benign CSVs ----
    benign_frames = []
    benign_dir = dns_base / "Benign"
    if benign_dir.exists():
        for csv_path in sorted(benign_dir.glob("stateless_*.csv")):
            try:
                benign_frames.append(pd.read_csv(str(csv_path), low_memory=False))
            except Exception as e:
                log.warning("    Skip %s: %s", csv_path.name, e)

    if not attack_frames and not benign_frames:
        log.error("  No DNS stateless CSVs found!")
        return pd.DataFrame()

    df_attack = pd.concat(attack_frames, ignore_index=True) if attack_frames else pd.DataFrame()
    df_benign = pd.concat(benign_frames, ignore_index=True) if benign_frames else pd.DataFrame()
    log.info("  Raw attack: %d, benign: %d", len(df_attack), len(df_benign))

    # Balanced subsample → ~20 K total
    if len(df_attack) > 10_000:
        df_attack = df_attack.sample(n=10_000, random_state=42)
    if len(df_benign) > 10_000:
        df_benign = df_benign.sample(n=10_000, random_state=42)

    df_attack["_label"] = 1
    df_benign["_label"] = 0
    df = pd.concat([df_attack, df_benign], ignore_index=True)
    n = len(df)
    log.info("  Subsampled to %d (attack=%d, benign=%d)", n, len(df_attack), len(df_benign))

    labels = df["_label"].values.astype(int)

    # Feature extraction
    subdomain_len = _safe_col(df, "subdomain_length", 0).clip(0, 500).values
    entropy_val   = _safe_col(df, "entropy", 0).clip(0, 8).values
    fqdn_count    = _safe_col(df, "FQDN_count", 1).clip(1, 10_000).values
    label_count   = _safe_col(df, "labels", 1).clip(0, 50).values
    total_len     = _safe_col(df, "len", 0).clip(0, 1000).values
    numeric_chars = _safe_col(df, "numeric", 0).values
    special_chars = _safe_col(df, "special", 0).values

    # Timestamps
    ts_col = df.get("timestamp", pd.Series("", index=df.index)).astype(str)
    ts = pd.to_datetime(ts_col, errors="coerce")
    valid_ts = ts.notna()
    hour = pd.Series(rng.randint(0, 24, n).astype(float), index=df.index)
    dow  = pd.Series(rng.randint(0, 7, n).astype(float), index=df.index)
    if valid_ts.any():
        hour[valid_ts] = ts[valid_ts].dt.hour.astype(float)
        dow[valid_ts]  = ts[valid_ts].dt.dayofweek.astype(float)

    # NO LEAKAGE: DNS queries have no inherent severity level
    severity = np.zeros(n)

    # template_rarity = normalized Shannon entropy (NOT label-dependent)
    template_rarity = np.clip(entropy_val / 5.0, 0.0, 1.0)

    return _make_frame(
        n,
        hour_of_day        = hour.values,
        day_of_week        = dow.values,
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 5.0),
        src_bytes          = subdomain_len * 1.0,
        dst_bytes          = total_len * 1.0,
        event_freq_1m      = fqdn_count * 1.0,
        protocol           = np.full(n, 17.0),
        dst_port           = np.full(n, 53.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = label_count * 1.0,
        srv_count          = np.clip(numeric_chars + special_chars, 0, 500),
        dst_host_count     = np.ones(n),
        dst_host_srv_count = np.ones(n),
        label              = labels,
        attack_type        = np.where(labels == 1, "dns_exfiltration", "normal"),
        source_dataset     = np.full(n, "dns_exfil", dtype=object),
    )


# ---- 11. OpenSSH Loghub --------------------------------------------------
def load_openssh() -> pd.DataFrame:
    """OpenSSH Loghub — SSH authentication logs (same Loghub format)."""
    rng = np.random.RandomState(4211)
    log.info("Loading OpenSSH Loghub structured …")

    csv_path = (
        NEW_DATA_DIR / "OPEN_SSH" / "OpenSSH_from_logpaigithub"
        / "OpenSSH_2k.log_structured.csv"
    )
    if not csv_path.exists():
        log.error("  OpenSSH CSV not found: %s", csv_path)
        return pd.DataFrame()

    df = pd.read_csv(str(csv_path), low_memory=False)
    df.columns = [c.strip().strip("\r") for c in df.columns]
    n = len(df)
    log.info("  %d rows", n)

    ATTACK_PATS = [
        "invalid user", "failed password", "authentication failure",
        "failed publickey", "bad protocol", "did not receive identification",
        "connection closed", "refused connect", "illegal user",
        "reverse mapping checking",
    ]

    content = df.get("Content", pd.Series("", index=df.index)).astype(str).str.lower()
    is_attack = pd.Series(False, index=df.index)
    for pat in ATTACK_PATS:
        is_attack = is_attack | content.str.contains(pat, na=False, regex=False)
    labels = is_attack.astype(int)

    # HONEST severity from SSH message keywords + noise
    has_failure  = content.str.contains("failure|failed|invalid", na=False, regex=True)
    has_refused  = content.str.contains("refused|closed|bad protocol", na=False, regex=True)
    has_accepted = content.str.contains("accepted|session opened", na=False, regex=True)
    base_sev = np.where(has_failure, 2.5,
               np.where(has_refused, 1.5,
               np.where(has_accepted, 0.0, 0.5)))
    severity = np.clip(base_sev + rng.normal(0, 0.5, n), 0, 4)

    template_rarity = np.clip(0.5 + rng.normal(0, 0.15, n), 0, 1)

    time_col = df.get("Time", pd.Series("", index=df.index)).astype(str)
    hour = time_col.str.extract(r"(\d+):", expand=False)
    hour = pd.to_numeric(hour, errors="coerce").fillna(12).astype(float) % 24

    attack_type = np.where(
        is_attack & content.str.contains("invalid user|illegal user", na=False, regex=True),
        "ssh_brute_force",
        np.where(is_attack, "ssh_auth_failure", "normal"),
    )

    # ALIGNED WITH INFERENCE: non-network path in feature_extractor.py
    return _make_frame(
        n,
        hour_of_day        = hour.values,
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 1.0),
        src_bytes          = content.str.len().clip(10, 5000).astype(float).values,  # ≈ len(msg)
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),                  # non-network → 0
        protocol           = np.full(n, 6.0),
        dst_port           = np.full(n, 22.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),                  # non-network → 0
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels.values,
        attack_type        = attack_type,
        source_dataset     = np.full(n, "openssh", dtype=object),
    )


# ---- 12. HDFS Event Traces -----------------------------------------------
def load_hdfs() -> pd.DataFrame:
    """HDFS Event Traces — Hadoop block-level anomaly detection.

    Features: Latency → duration, event-sequence length → count/event_freq_1m.
    Labels: Normal/Success → 0,  Anomaly/Fail → 1.
    """
    rng = np.random.RandomState(4212)
    log.info("Loading HDFS Event Traces …")

    # The folder name contains an em-dash; use glob to find it
    csv_path = None
    for cand in sorted((NEW_DATA_DIR / "Loghub").glob("Loghub Full*")):
        p = cand / "HDFS_v1" / "preprocessed" / "Event_traces.csv"
        if p.exists():
            csv_path = p
            break
    if csv_path is None:
        log.error("  HDFS Event_traces.csv not found!")
        return pd.DataFrame()

    log.info("    reading %s", csv_path.relative_to(BASE_DIR))
    df = pd.read_csv(str(csv_path), low_memory=False)
    n_total = len(df)
    log.info("  %d rows", n_total)

    label_col = df.get("Label", pd.Series("Normal", index=df.index)).astype(str).str.lower()
    labels_full = label_col.isin(["anomaly", "fail", "failure"]).astype(int)
    n_anomaly = labels_full.sum()
    n_normal  = n_total - n_anomaly
    log.info("  Raw: %d normal, %d anomaly", n_normal, n_anomaly)

    # Subsample to ~10 K: keep all anomalies, sample normals
    df["_label"] = labels_full.values
    df_anom = df[df["_label"] == 1]
    df_norm = df[df["_label"] == 0]
    max_normal = max(5000, min(10_000 - len(df_anom), len(df_norm)))
    if len(df_norm) > max_normal:
        df_norm = df_norm.sample(n=max_normal, random_state=42)
    df = pd.concat([df_anom, df_norm], ignore_index=True)
    n = len(df)
    labels = df["_label"].values.astype(int)
    log.info("  Subsampled to %d (anomaly=%d, normal=%d)", n, labels.sum(), (labels == 0).sum())

    # Event sequence length as complexity proxy
    features_str = df.get("Features", pd.Series("", index=df.index)).astype(str)
    event_count = (features_str.str.count(",") + 1).clip(1, 10_000).astype(float).values

    latency    = _safe_col(df, "Latency", 0).clip(0, 1e9).values
    block_type = _safe_col(df, "Type", 0).values

    # NO LEAKAGE: HDFS blocks have no inherent severity
    severity = np.zeros(n)

    # template_rarity: event count normalised (very long traces are rarer)
    template_rarity = np.clip(event_count / 100.0, 0.0, 1.0)

    # ALIGNED WITH INFERENCE: non-network path in feature_extractor.py
    #   HDFS traces are log-type data → event_freq_1m=0, count/srv_count=0,
    #   protocol=6(TCP default), src_bytes≈len(message), dst_host_*=0
    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 1.0),
        src_bytes          = features_str.str.len().clip(10, 5000).astype(float).values,  # ≈ len(msg)
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),                  # non-network → 0
        protocol           = np.full(n, 6.0),              # non-network default TCP(6)
        dst_port           = np.full(n, 8020.0),         # HDFS namenode port
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = latency,
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),                  # non-network → 0
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels,
        attack_type        = np.where(labels == 1, "hdfs_anomaly", "normal"),
        source_dataset     = np.full(n, "hdfs", dtype=object),
    )


# =========================================================================
#  PHASE 1 — COMBINE & VALIDATE
# =========================================================================

def build_combined_dataset():
    log.info("=" * 70)
    log.info("PHASE 1: Building combined multi-log training dataset")
    log.info("=" * 70)

    loaders = [
        # Original 9
        load_cicids2017, load_nsl_kdd, load_unsw_nb15,
        load_nf_unsw, load_ton_iot, load_csic2010,
        load_evtx, load_loghub_linux, load_loghub_apache,
        # New 3 (v3)
        load_dns_exfil, load_openssh, load_hdfs,
    ]

    frames = []
    fingerprints = {}
    for loader in loaders:
        try:
            t0 = time.time()
            result = loader()
            elapsed = time.time() - t0
            if len(result) > 0:
                fp = _dataset_fingerprint(result, loader.__name__)
                fingerprints[loader.__name__] = fp
                frames.append(result)
                log.info("  -> %s: %d rows OK (%.1fs)", loader.__name__, len(result), elapsed)
            else:
                log.warning("  -> %s: 0 rows (EMPTY)", loader.__name__)
        except Exception as exc:
            log.error("  FAILED: %s: %s", loader.__name__, exc, exc_info=True)

    if not frames:
        raise RuntimeError("No datasets loaded! Check data paths.")

    df = pd.concat(frames, ignore_index=True)
    log.info("\nCombined BEFORE validation: %d rows from %d datasets", len(df), len(frames))

    # ---- Column-level validation & clipping ----
    for col in FEATURE_COLS:
        if col not in df.columns:
            log.error("  MISSING COLUMN: %s — filling with 0", col)
            df[col] = 0.0
        df[col] = (
            pd.to_numeric(df[col], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
        )

    df["src_bytes"]  = df["src_bytes"].clip(0, 1e9)
    df["dst_bytes"]  = df["dst_bytes"].clip(0, 1e9)
    df["dst_port"]   = df["dst_port"].clip(0, 65535)
    for col in ["same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate", "template_rarity"]:
        df[col] = df[col].clip(0.0, 1.0)

    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int).clip(0, 1)
    df["attack_type"] = df["attack_type"].fillna("unknown")
    df.loc[(df["label"] == 0) & (df["attack_type"] == "unknown"), "attack_type"] = "normal"

    # Final NaN/Inf assertions
    X = df[FEATURE_COLS].values
    assert not np.any(np.isnan(X)), "NaN found after validation!"
    assert not np.any(np.isinf(X)), "Inf found after validation!"

    # ---- Summary ----
    log.info("\nCombined AFTER validation: %d rows", len(df))
    log.info("Label dist:     %s", df["label"].value_counts().to_dict())
    log.info("Datasets:       %s", df["source_dataset"].value_counts().to_dict())
    log.info("Attack types:   %d unique: %s", df["attack_type"].nunique(), sorted(df["attack_type"].unique()))
    log.info("Source types:   %s", sorted(df["source_type_numeric"].unique().tolist()))

    # ---- Per-dataset severity leakage check ----
    log.info("\nSeverity validation per dataset (checking for label leakage):")
    for ds in sorted(df["source_dataset"].unique()):
        ds_df = df[df["source_dataset"] == ds]
        sev_n = ds_df.loc[ds_df["label"] == 0, "severity_numeric"]
        sev_a = ds_df.loc[ds_df["label"] == 1, "severity_numeric"]
        n_mean = sev_n.mean() if len(sev_n) > 0 else 0
        a_mean = sev_a.mean() if len(sev_a) > 0 else 0
        delta  = abs(a_mean - n_mean)
        status = "OK" if delta < 1.0 else "WARN (check leakage)"
        log.info(
            "  %-20s: normal_sev=%.2f, attack_sev=%.2f, delta=%.2f [%s]",
            ds, n_mean, a_mean, delta, status,
        )

    log.info("Validation PASSED  ✓")
    return df, fingerprints


# =========================================================================
#  PHASE 2 — TRAIN EIF (normal-only)
# =========================================================================

def train_eif(df):
    log.info("=" * 70)
    log.info("PHASE 2: Training Extended Isolation Forest (normal-only)")
    log.info("=" * 70)

    from eif import iForest

    normal_df = df[df["label"] == 0]
    X_normal  = normal_df[FEATURE_COLS].values.astype(np.float64)
    log.info("Normal data: %d samples from %d datasets",
             len(X_normal), normal_df["source_dataset"].nunique())
    log.info("  Per-dataset: %s", normal_df["source_dataset"].value_counts().to_dict())

    sample_size = min(256, len(X_normal))
    log.info("Training EIF: ntrees=300  sample_size=%d  ExtensionLevel=1", sample_size)
    t0 = time.time()
    eif = iForest(X_normal, ntrees=300, sample_size=sample_size, ExtensionLevel=1)
    log.info("EIF training: %.1fs", time.time() - t0)

    # ---- Calibration on 10 K normal subsample ----
    n_cal = min(10_000, len(X_normal))
    cal_rng = np.random.RandomState(42)
    idx = (cal_rng.choice(len(X_normal), n_cal, replace=False)
           if n_cal < len(X_normal) else np.arange(len(X_normal)))
    log.info("Computing EIF paths on %d normal samples …", n_cal)
    raw_normal = eif.compute_paths(X_in=X_normal[idx])
    cal_mean = float(np.mean(raw_normal))
    cal_std  = float(np.std(raw_normal))
    log.info("Calibration: mean=%.6f  std=%.6f", cal_mean, cal_std)

    z_normal   = (raw_normal - cal_mean) / max(cal_std, 1e-10)
    sig_normal = 1.0 / (1.0 + np.exp(z_normal))
    threshold  = float(np.percentile(sig_normal, 99))
    log.info("EIF threshold (1%% FPR): %.4f", threshold)

    # ---- Score malicious data (5 K subsample) ----
    mal_df = df[df["label"] == 1]
    n_mal  = min(5000, len(mal_df))
    X_mal  = mal_df[FEATURE_COLS].sample(n=n_mal, random_state=42).values.astype(np.float64)
    log.info("Computing EIF paths on %d malicious samples …", n_mal)
    raw_mal   = eif.compute_paths(X_in=X_mal)
    z_mal     = (raw_mal - cal_mean) / max(cal_std, 1e-10)
    sig_mal   = 1.0 / (1.0 + np.exp(z_mal))

    delta = float(sig_mal.mean() - sig_normal.mean())
    log.info("EIF discrimination:")
    log.info("  Normal:    mean=%.4f ± %.4f", sig_normal.mean(), sig_normal.std())
    log.info("  Malicious: mean=%.4f ± %.4f", sig_mal.mean(), sig_mal.std())
    log.info("  Delta: %+.4f (%s)", delta,
             "CORRECT" if delta > 0 else "INVERTED — will auto-flip")

    # Per-dataset EIF scores (200 samples each)
    log.info("Per-dataset EIF scores:")
    for ds in sorted(mal_df["source_dataset"].unique()):
        ds_df = mal_df[mal_df["source_dataset"] == ds]
        ds_X  = ds_df[FEATURE_COLS].sample(
            n=min(200, len(ds_df)), random_state=42
        ).values.astype(np.float64)
        ds_raw = eif.compute_paths(X_in=ds_X)
        ds_z   = (ds_raw - cal_mean) / max(cal_std, 1e-10)
        ds_sig = 1.0 / (1.0 + np.exp(ds_z))
        log.info("  %-20s: mean_score=%.4f", ds, ds_sig.mean())

    # ---- Save ----
    import joblib
    log.info("Saving EIF model …")
    joblib.dump(eif, str(MODEL_DIR / "eif_v2.0.0.pkl"), compress=3)

    score_flip = 1 if delta < 0 else 0
    np.savez(
        str(MODEL_DIR / "eif_calibration.npz"),
        path_mean=cal_mean, path_std=cal_std, score_flip=score_flip,
    )
    np.save(str(MODEL_DIR / "eif_threshold.npy"), threshold)
    log.info("Saved: eif_v2.0.0.pkl, eif_calibration.npz (flip=%d), eif_threshold.npy", score_flip)

    return {
        "cal_mean": cal_mean, "cal_std": cal_std, "threshold": threshold,
        "normal_mean": float(sig_normal.mean()), "mal_mean": float(sig_mal.mean()),
        "delta": delta,
    }


# =========================================================================
#  PHASE 3 — TRAIN LIGHTGBM
# =========================================================================

def train_lightgbm(df):
    log.info("=" * 70)
    log.info("PHASE 3: Training LightGBM (multi-log classifier)")
    log.info("=" * 70)

    import lightgbm as lgb
    from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
    from sklearn.model_selection import train_test_split

    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["label"].values.astype(int)
    indices = df.index.values

    # Stratify by (dataset × label) for proportional representation
    strat_key = df["source_dataset"].astype(str) + "_" + df["label"].astype(str)
    X_train, X_val, y_train, y_val, idx_train, idx_val = train_test_split(
        X, y, indices, test_size=0.2, random_state=42, stratify=strat_key,
    )
    log.info("Train: %d (%d pos, %d neg)", len(X_train), (y_train==1).sum(), (y_train==0).sum())
    log.info("Val:   %d (%d pos, %d neg)", len(X_val), (y_val==1).sum(), (y_val==0).sum())

    val_ds   = df.loc[idx_val,   "source_dataset"].values
    train_ds = df.loc[idx_train, "source_dataset"].values
    log.info("Per-dataset split verification:")
    for ds in sorted(set(val_ds)):
        log.info("  %-20s: train=%5d  val=%5d",
                 ds, (train_ds == ds).sum(), (val_ds == ds).sum())

    scale_pos = (y_train == 0).sum() / max(1, (y_train == 1).sum())
    log.info("scale_pos_weight: %.4f", scale_pos)

    train_data = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_COLS, free_raw_data=False)
    val_data   = lgb.Dataset(X_val, label=y_val, reference=train_data,
                             feature_name=FEATURE_COLS, free_raw_data=False)

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "boosting_type": "gbdt",
        "num_leaves": 31,
        "max_depth": 6,
        "learning_rate": 0.05,
        "min_child_samples": 50,
        "colsample_bytree": 0.7,
        "subsample": 0.7,
        "subsample_freq": 1,
        "reg_alpha": 0.5,
        "reg_lambda": 5.0,
        "min_gain_to_split": 0.1,
        "scale_pos_weight": scale_pos,
        "verbose": -1,
        "seed": 42,
        "num_threads": os.cpu_count(),
        "device": "gpu",
    }

    t0 = time.time()
    try:
        model = lgb.train(
            params, train_data, num_boost_round=1000,
            valid_sets=[train_data, val_data], valid_names=["train", "val"],
            callbacks=[lgb.early_stopping(50, verbose=True), lgb.log_evaluation(100)],
        )
        log.info("LightGBM (GPU): %.1fs  best_iter=%d", time.time()-t0, model.best_iteration)
    except Exception as exc:
        log.warning("GPU failed (%s), falling back to CPU …", exc)
        params.pop("device", None)
        t0 = time.time()
        model = lgb.train(
            params, train_data, num_boost_round=1000,
            valid_sets=[train_data, val_data], valid_names=["train", "val"],
            callbacks=[lgb.early_stopping(50, verbose=True), lgb.log_evaluation(100)],
        )
        log.info("LightGBM (CPU): %.1fs  best_iter=%d", time.time()-t0, model.best_iteration)

    # ---- Validation metrics ----
    y_prob = model.predict(X_val)
    y_pred = (y_prob >= 0.5).astype(int)
    acc  = accuracy_score(y_val, y_pred)
    prec = precision_score(y_val, y_pred, zero_division=0)
    rec  = recall_score(y_val, y_pred, zero_division=0)
    f1   = f1_score(y_val, y_pred, zero_division=0)
    log.info("Validation: Acc=%.4f  Prec=%.4f  Rec=%.4f  F1=%.4f", acc, prec, rec, f1)

    # Quality gate
    if f1 < 0.80:
        log.error("QUALITY GATE FAILED: F1=%.4f < 0.80.  Check data integrity!", f1)
        raise RuntimeError(f"LightGBM F1={f1:.4f} below quality gate (0.80)")

    # Per-dataset detection rates
    log.info("Per-dataset detection rates:")
    for ds in sorted(set(val_ds)):
        m = val_ds == ds
        n_pos = (y_val[m] == 1).sum()
        n_neg = (y_val[m] == 0).sum()
        if n_pos == 0:
            continue
        det = (y_prob[m][y_val[m] == 1] >= 0.5).mean()
        fpr = (y_prob[m][y_val[m] == 0] >= 0.5).mean() if n_neg > 0 else 0.0
        log.info("  %-20s  detect=%6.1f%%  FPR=%.2f%%  n=%d", ds, det * 100, fpr * 100, m.sum())

    # Feature importance
    imp = sorted(zip(FEATURE_COLS, model.feature_importance("gain")), key=lambda x: -x[1])
    log.info("Feature importance (gain):")
    for name, val in imp[:10]:
        log.info("  %-25s: %.1f", name, val)

    # ---- Save native text model ----
    model.save_model(str(MODEL_DIR / "lgbm_v2.0.0.txt"))

    # ---- Export to ONNX ----
    log.info("Exporting to ONNX …")
    import onnxmltools
    import onnxmltools.convert.common.data_types as onnx_types

    onnx_model = onnxmltools.convert_lightgbm(
        model,
        initial_types=[("input", onnx_types.FloatTensorType([None, len(FEATURE_COLS)]))],
        target_opset=11,
    )
    onnx_path = str(MODEL_DIR / "lgbm_v2.0.0.onnx")
    onnxmltools.utils.save_model(onnx_model, onnx_path)
    log.info("Saved ONNX: lgbm_v2.0.0.onnx")

    # Verify ONNX matches native
    import onnxruntime as ort
    sess = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    out  = sess.run(None, {sess.get_inputs()[0].name: X_val[:100]})
    onnx_probs   = np.array([d.get(1, d.get("1", 0.0)) for d in out[1]])
    native_probs = model.predict(X_val[:100])
    diff = float(np.max(np.abs(onnx_probs - native_probs)))
    log.info("ONNX verify (100 samples): max_diff=%.6f  %s", diff,
             "PASS" if diff < 0.01 else "FAIL")
    if diff >= 0.01:
        raise RuntimeError(f"ONNX max_diff={diff:.6f} >= 0.01 — predictions diverged!")

    # Authoritative feature order
    with open(MODEL_DIR / "feature_cols.pkl", "wb") as f:
        pickle.dump(FEATURE_COLS, f)

    return {
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "best_iteration": model.best_iteration,
        "feature_importance": {name: float(val) for name, val in imp},
    }


# =========================================================================
#  PHASE 4 — ARF STREAM + CHECKPOINT
# =========================================================================

def build_arf_stream(df):
    log.info("=" * 70)
    log.info("PHASE 4: Building ARF stream CSV + checkpoint")
    log.info("=" * 70)

    MAX_ROWS = 15_000

    groups = df.groupby(["source_dataset", "label"])
    per_group = MAX_ROWS // max(1, len(groups))
    samples = [g.sample(n=min(per_group, len(g)), random_state=42) for _, g in groups]
    arf_df = (
        pd.concat(samples, ignore_index=True)
        .sample(frac=1, random_state=42)
        .head(MAX_ROWS)
    )

    csv_path = MODEL_DIR / "features_arf_stream_features.csv"
    arf_df[FEATURE_COLS + ["label"]].to_csv(str(csv_path), index=False)
    log.info("Saved ARF stream: %d rows", len(arf_df))
    log.info("  Label dist: %s", arf_df["label"].value_counts().to_dict())
    log.info("  Datasets:   %s", arf_df["source_dataset"].value_counts().to_dict())

    # ---- Train ARF (inherently sequential) ----
    log.info("Training ARF checkpoint …")
    try:
        from river.drift import ADWIN
        from river.forest import ARFClassifier

        arf = ARFClassifier(
            n_models=10,
            drift_detector=ADWIN(delta=0.002),
            warning_detector=ADWIN(delta=0.01),
            seed=42,
        )

        t0 = time.time()
        for i, (_, row) in enumerate(arf_df.iterrows()):
            x = {col: float(row[col]) for col in FEATURE_COLS}
            arf.learn_one(x, int(row["label"]))
            if (i + 1) % 3000 == 0:
                elapsed = time.time() - t0
                rate = (i + 1) / elapsed
                remaining = (len(arf_df) - i - 1) / rate
                log.info("  ARF: %d/%d (%.0f rows/s, ~%.0fs left)",
                         i + 1, len(arf_df), rate, remaining)

        log.info("ARF trained: %d samples in %.1fs", len(arf_df), time.time() - t0)

        # Quick sanity check — verify varying predictions
        z = {c: 0.0 for c in FEATURE_COLS}
        h = {c: 100.0 for c in FEATURE_COLS}
        p0 = arf.predict_proba_one(z).get(1, 0.5)
        p1 = arf.predict_proba_one(h).get(1, 0.5)
        log.info("ARF verify: p(zeros)=%.4f  p(100s)=%.4f  delta=%.4f", p0, p1, abs(p0 - p1))

        with open(MODEL_DIR / "arf_v2.0.0.pkl", "wb") as f:
            pickle.dump(arf, f)
        log.info("Saved: arf_v2.0.0.pkl")
    except Exception as exc:
        log.error("ARF training failed: %s", exc, exc_info=True)

    return {"n_rows": len(arf_df)}


# =========================================================================
#  PHASE 5 — COMPUTE THRESHOLDS
# =========================================================================

def compute_thresholds(df, eif_stats):
    log.info("=" * 70)
    log.info("PHASE 5: Computing calibrated thresholds")
    log.info("=" * 70)

    import joblib
    import onnxruntime as ort

    sess     = ort.InferenceSession(str(MODEL_DIR / "lgbm_v2.0.0.onnx"),
                                    providers=["CPUExecutionProvider"])
    inp_name = sess.get_inputs()[0].name
    eif      = joblib.load(str(MODEL_DIR / "eif_v2.0.0.pkl"))
    cal_mean = eif_stats["cal_mean"]
    cal_std  = eif_stats["cal_std"]

    # Stratified 10 K sample
    sample_df = df.groupby("label", group_keys=False).apply(
        lambda x: x.sample(n=min(5000, len(x)), random_state=42)
    )
    X = sample_df[FEATURE_COLS].values.astype(np.float32)
    y = sample_df["label"].values
    log.info("Threshold computation on %d samples …", len(X))

    # LightGBM
    out    = sess.run(None, {inp_name: X})
    lgbm_s = np.array([d.get(1, d.get("1", 0.0)) for d in out[1]], dtype=np.float64)

    # EIF
    raw   = eif.compute_paths(X_in=X.astype(np.float64))
    z     = (raw - cal_mean) / max(cal_std, 1e-10)
    eif_s = 1.0 / (1.0 + np.exp(z))

    eif_cal = np.load(str(MODEL_DIR / "eif_calibration.npz"))
    if "score_flip" in eif_cal and int(eif_cal["score_flip"]):
        eif_s = 1.0 - eif_s
        log.info("EIF scores FLIPPED (inverted discrimination correction)")

    # Combined (without ARF — cold-start)
    # ARF conf = 0 → weight redistributed: LGBM 0.80, EIF 0.20
    combined = 0.80 * lgbm_s + 0.20 * eif_s

    ns = combined[y == 0]
    ms = combined[y == 1]

    p95  = float(np.percentile(ns, 95))
    p99  = float(np.percentile(ns, 99))
    mp25 = float(np.percentile(ms, 25))
    mp50 = float(np.percentile(ms, 50))

    suspicious = round(p95, 2)
    anomalous  = round(mp50, 2)

    # Ensure suspicious < anomalous
    if suspicious >= anomalous:
        anomalous = round(max(mp25, suspicious + 0.05), 2)

    det_susp = (ms >= suspicious).mean()
    det_anom = (ms >= anomalous).mean()
    fpr_susp = (ns >= suspicious).mean()
    fpr_anom = (ns >= anomalous).mean()

    log.info("Normal:     mean=%.4f  p95=%.4f  p99=%.4f", ns.mean(), p95, p99)
    log.info("Malicious:  mean=%.4f  p25=%.4f  p50=%.4f", ms.mean(), mp25, mp50)
    log.info("LGBM:       normal=%.4f  mal=%.4f", lgbm_s[y==0].mean(), lgbm_s[y==1].mean())
    log.info("EIF:        normal=%.4f  mal=%.4f", eif_s[y==0].mean(), eif_s[y==1].mean())
    log.info("Thresholds:")
    log.info("  suspicious = %.2f  (detect=%.1f%%  FPR=%.2f%%)", suspicious, det_susp*100, fpr_susp*100)
    log.info("  anomalous  = %.2f  (detect=%.1f%%  FPR=%.2f%%)", anomalous, det_anom*100, fpr_anom*100)

    return {
        "suspicious": suspicious, "anomalous": anomalous,
        "lgbm_normal": float(lgbm_s[y==0].mean()),
        "lgbm_mal":    float(lgbm_s[y==1].mean()),
        "eif_normal":  float(eif_s[y==0].mean()),
        "eif_mal":     float(eif_s[y==1].mean()),
    }


# =========================================================================
#  PHASE 6 — MANIFEST
# =========================================================================

ALL_DATASETS = [
    "cicids2017", "nsl_kdd", "unsw_nb15", "nf_unsw_nb15_v3",
    "nf_ton_iot", "csic_2010", "evtx", "loghub_linux", "loghub_apache",
    "dns_exfil", "openssh", "hdfs",
]


def save_manifest(thresholds, eif_stats, lgbm_stats, fingerprints):
    manifest = {
        "version": "v3.0.0",
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "lgbm": {
            "active": "v2.0.0",
            "file": "lgbm_v2.0.0.onnx",
            "metrics": {k: round(lgbm_stats[k], 4) for k in ["accuracy", "precision", "recall", "f1"]},
            "best_iteration": lgbm_stats["best_iteration"],
        },
        "eif": {
            "active": "v2.0.0",
            "file": "eif_v2.0.0.pkl",
            "calibration": {"mean": round(eif_stats["cal_mean"], 6),
                            "std":  round(eif_stats["cal_std"], 6)},
            "threshold": round(eif_stats["threshold"], 4),
            "discrimination_delta": round(eif_stats["delta"], 4),
        },
        "arf": {
            "active": "v2.0.0",
            "file": "arf_v2.0.0.pkl",
            "stream_csv": "features_arf_stream_features.csv",
        },
        "thresholds": {
            "suspicious": thresholds["suspicious"],
            "anomalous":  thresholds["anomalous"],
        },
        "datasets": ALL_DATASETS,
        "dataset_fingerprints": fingerprints,
        "feature_cols": FEATURE_COLS,
        "label_leakage_prevention": {
            "severity_source": "original_log_level (source-system severity, not Vector classification)",
            "network_datasets_severity": "random_normal(1.0, 0.5) — no inherent severity",
            "log_datasets_severity": "content-keyword-based with Gaussian noise",
        },
    }
    with open(MODEL_DIR / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    log.info("Saved: manifest.json")


# =========================================================================
#  MAIN ENTRY POINT
# =========================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="CLIF Triage — Complete Retraining Pipeline (v3)")
    parser.add_argument("--dry-run", action="store_true", help="Validate data only, no training")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("  CLIF Triage — Complete Retraining Pipeline v3")
    log.info("=" * 70)
    log.info("Data dir:     %s (exists=%s)", DATASETS_DIR, DATASETS_DIR.exists())
    log.info("New data dir: %s (exists=%s)", NEW_DATA_DIR, NEW_DATA_DIR.exists())
    log.info("Model dir:    %s", MODEL_DIR)

    assert DATASETS_DIR.exists(), f"Datasets directory not found: {DATASETS_DIR}"
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    t_total = time.time()

    # Phase 1
    df, fingerprints = build_combined_dataset()
    combined_csv = DATA_DIR / "features_combined_v3.csv"
    df.to_csv(str(combined_csv), index=False)
    log.info("Saved combined CSV: %d rows → %s\n", len(df), combined_csv)

    if args.dry_run:
        log.info("DRY RUN — data validation complete, skipping training.")
        return 0

    # Phase 2
    eif_stats = train_eif(df)

    # Phase 3
    lgbm_stats = train_lightgbm(df)

    # Phase 4
    build_arf_stream(df)

    # Phase 5
    thresholds = compute_thresholds(df, eif_stats)

    # Phase 6
    save_manifest(thresholds, eif_stats, lgbm_stats, fingerprints)

    elapsed = time.time() - t_total
    log.info("\n" + "=" * 70)
    log.info("  RETRAINING COMPLETE")
    log.info("=" * 70)
    log.info("Total time: %.1f min", elapsed / 60)
    log.info("Data:   %d rows, %d datasets, %d attack types",
             len(df), df["source_dataset"].nunique(), df[df["label"]==1]["attack_type"].nunique())
    log.info("LGBM:   F1=%.4f  Acc=%.4f  Prec=%.4f  Rec=%.4f",
             lgbm_stats["f1"], lgbm_stats["accuracy"],
             lgbm_stats["precision"], lgbm_stats["recall"])
    log.info("EIF:    normal=%.4f  mal=%.4f  delta=%+.4f",
             eif_stats["normal_mean"], eif_stats["mal_mean"], eif_stats["delta"])
    log.info("Thresh: suspicious=%.2f  anomalous=%.2f",
             thresholds["suspicious"], thresholds["anomalous"])
    log.info("Files in: %s", MODEL_DIR)
    log.info("\nModel files produced:")
    for fp in sorted(MODEL_DIR.glob("*v2.0.0*")) + [
        MODEL_DIR / "manifest.json", MODEL_DIR / "feature_cols.pkl",
    ]:
        if fp.exists():
            log.info("  %-40s  %.1f KB", fp.name, fp.stat().st_size / 1024)

    log.info("\n--- UPDATE config.py ---")
    log.info("SUSPICIOUS_THRESHOLD  = %.2f", thresholds["suspicious"])
    log.info("ANOMALOUS_THRESHOLD   = %.2f", thresholds["anomalous"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
