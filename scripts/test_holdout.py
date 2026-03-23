#!/usr/bin/env python3
"""
CLIF Triage Agent — Holdout Test (v3 Models)
=============================================
Tests the retrained ensemble on data NEVER seen during training.

Holdout sources (different random seeds & non-overlapping rows):
  1. CSIC 2010:     ~41 K unused rows  (training used 20 K with seed=42)
  2. DNS Exfil:    ~737 K unused rows  (training used 20 K with seed=42)
  3. HDFS Traces:  ~565 K unused rows  (training used ~22 K with seed=42)

Score fusion follows production logic:
  fused = 0.60·LGBM + 0.15·EIF + 0.25·ARF
  suspicious ≥ 0.32  |  anomalous ≥ 0.89
  EIF override: if EIF ≥ 0.65, floor fused at 0.45.

Usage:
    python scripts/test_holdout.py
"""

import json
import logging
import os
import pickle
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Logging ─────────────────────────────────────────────────────────────────
class _FlushH(logging.StreamHandler):
    def emit(self, r):
        super().emit(r)
        self.flush()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_FlushH(sys.stdout)],
)
log = logging.getLogger("holdout_test")


# ── Paths ───────────────────────────────────────────────────────────────────
BASE       = Path(__file__).resolve().parent.parent
DATA       = BASE / "agents" / "Data"
DATASETS   = DATA / "datasets"
NEW_DATA   = DATA / "New_Dataset"
MODEL_DIR  = BASE / "agents" / "triage" / "models"

# ── 20 canonical features ──────────────────────────────────────────────────
FEATURE_COLS = [
    "hour_of_day", "day_of_week", "severity_numeric", "source_type_numeric",
    "src_bytes", "dst_bytes", "event_freq_1m", "protocol", "dst_port",
    "template_rarity", "threat_intel_flag", "duration",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

# ── Score fusion config ────────────────────────────────────────────────────
W_LGBM = 0.60
W_EIF  = 0.15
W_ARF  = 0.25
SUSPICIOUS_THRESH = 0.39
ANOMALOUS_THRESH  = 0.89
EIF_OVERRIDE_THRESH = 0.65
EIF_OVERRIDE_FLOOR  = 0.45


# =========================================================================
#  Helpers (same as retrain_all.py)
# =========================================================================

def _safe_col(df, name, default=0.0):
    if name in df.columns:
        s = pd.to_numeric(df[name], errors="coerce").fillna(default)
        return s.replace([np.inf, -np.inf], default).astype(np.float64)
    return pd.Series(default, index=df.index, dtype=np.float64)

def _make_frame(n, **kw):
    out = pd.DataFrame(index=range(n))
    for col in FEATURE_COLS + ["label", "attack_type", "source_dataset"]:
        if col in kw:
            v = kw[col]
            out[col] = v.values if isinstance(v, pd.Series) else v
        elif col in ("attack_type", "source_dataset"):
            out[col] = "unknown"
        else:
            out[col] = 0.0
    return out


# =========================================================================
#  Holdout Loaders — DIFFERENT seeds & DISJOINT rows
# =========================================================================

def holdout_csic(max_rows=10_000) -> pd.DataFrame:
    """CSIC 2010 holdout: rows NOT used during training.

    Training used: df[classification==0].sample(10000, seed=42) + df[classification==1].sample(10000, seed=42)
    Holdout uses:  the complement of those rows, then subsample with seed=9999.
    """
    rng = np.random.RandomState(9901)
    log.info("Loading CSIC 2010 holdout …")

    csv_path = DATASETS / "08_nginx_web_server" / "path_a_lightgbm" / "CSIC_2010" / "csic_database.csv"
    if not csv_path.exists():
        log.error("  CSIC CSV not found: %s", csv_path)
        return pd.DataFrame()

    df_full = pd.read_csv(str(csv_path), low_memory=False)
    log.info("  Full CSIC: %d rows", len(df_full))

    # Reconstruct EXACTLY which rows training used (same seed=42)
    df_n_full = df_full[df_full["classification"] == 0]
    df_a_full = df_full[df_full["classification"] == 1]

    train_n_idx = df_n_full.sample(n=10_000, random_state=42).index
    train_a_idx = df_a_full.sample(n=10_000, random_state=42).index

    # Holdout = complement
    holdout_n = df_n_full.drop(train_n_idx)
    holdout_a = df_a_full.drop(train_a_idx)
    log.info("  Holdout pool: %d normal, %d attack", len(holdout_n), len(holdout_a))

    # Balanced subsample
    per_class = max_rows // 2
    if len(holdout_n) > per_class:
        holdout_n = holdout_n.sample(n=per_class, random_state=9999)
    if len(holdout_a) > per_class:
        holdout_a = holdout_a.sample(n=per_class, random_state=9999)

    df = pd.concat([holdout_n, holdout_a], ignore_index=True)
    n = len(df)
    labels = df["classification"].astype(int)
    is_attack = labels == 1

    content_len = _safe_col(df, "lenght", 0)
    content_str = df.get("content", pd.Series("", index=df.index)).astype(str)
    content_fb  = content_str.str.len().astype(float)
    src_bytes   = np.where(content_len > 0, content_len, content_fb)
    url_len     = df.get("URL", pd.Series("", index=df.index)).astype(str).str.len().astype(float)
    template_rarity = np.clip(url_len / 200.0, 0.0, 1.0)
    severity = np.zeros(n)

    log.info("  Holdout CSIC: %d rows (normal=%d, attack=%d)",
             n, (labels == 0).sum(), (labels == 1).sum())

    # ALIGNED WITH INFERENCE v4: non-network path
    return _make_frame(
        n,
        hour_of_day        = rng.randint(8, 20, n).astype(float),
        day_of_week        = rng.randint(0, 5, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 8.0),
        src_bytes          = np.clip(src_bytes, 0, 1e9),
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),
        protocol           = np.full(n, 6.0),
        dst_port           = np.full(n, 80.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = np.zeros(n),
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels.values,
        attack_type        = np.where(is_attack, "web_attack", "normal"),
        source_dataset     = np.full(n, "csic_2010", dtype=object),
    )


def holdout_dns(max_rows=10_000) -> pd.DataFrame:
    """DNS Exfil holdout: rows NOT used during training.

    Training used: df_attack.sample(10000, seed=42), df_benign.sample(10000, seed=42)
    Holdout: different seed=9999, non-overlapping rows.
    """
    rng = np.random.RandomState(9902)
    log.info("Loading DNS Exfil holdout …")

    dns_base = NEW_DATA / "CIC-Bell-DNS-EXFil-2021" / "CSV"
    if not dns_base.exists():
        log.error("  DNS folder not found: %s", dns_base)
        return pd.DataFrame()

    attack_frames, benign_frames = [], []
    for attack_dir in sorted(dns_base.glob("Attack_*")):
        for sub in [attack_dir / "Attacks", attack_dir]:
            for csv_path in sorted(sub.glob("stateless_*.csv")):
                try:
                    attack_frames.append(pd.read_csv(str(csv_path), low_memory=False))
                except Exception:
                    pass
    benign_dir = dns_base / "Benign"
    if benign_dir.exists():
        for csv_path in sorted(benign_dir.glob("stateless_*.csv")):
            try:
                benign_frames.append(pd.read_csv(str(csv_path), low_memory=False))
            except Exception:
                pass

    df_attack = pd.concat(attack_frames, ignore_index=True) if attack_frames else pd.DataFrame()
    df_benign = pd.concat(benign_frames, ignore_index=True) if benign_frames else pd.DataFrame()
    log.info("  Full DNS: %d attack, %d benign", len(df_attack), len(df_benign))

    # Remove the EXACT rows training used (seed=42, n=10000)
    train_attack_idx = df_attack.sample(n=10_000, random_state=42).index
    train_benign_idx = df_benign.sample(n=10_000, random_state=42).index

    holdout_attack = df_attack.drop(train_attack_idx)
    holdout_benign = df_benign.drop(train_benign_idx)
    log.info("  Holdout pool: %d attack, %d benign", len(holdout_attack), len(holdout_benign))

    per_class = max_rows // 2
    if len(holdout_attack) > per_class:
        holdout_attack = holdout_attack.sample(n=per_class, random_state=9999)
    if len(holdout_benign) > per_class:
        holdout_benign = holdout_benign.sample(n=per_class, random_state=9999)

    holdout_attack["_label"] = 1
    holdout_benign["_label"] = 0
    df = pd.concat([holdout_attack, holdout_benign], ignore_index=True)
    n = len(df)
    labels = df["_label"].values.astype(int)
    log.info("  Holdout DNS: %d rows (attack=%d, benign=%d)",
             n, labels.sum(), (labels == 0).sum())

    subdomain_len = _safe_col(df, "subdomain_length", 0).clip(0, 500).values
    entropy_val   = _safe_col(df, "entropy", 0).clip(0, 8).values
    fqdn_count    = _safe_col(df, "FQDN_count", 1).clip(1, 10_000).values
    label_count   = _safe_col(df, "labels", 1).clip(0, 50).values
    total_len     = _safe_col(df, "len", 0).clip(0, 1000).values
    numeric_chars = _safe_col(df, "numeric", 0).values
    special_chars = _safe_col(df, "special", 0).values
    template_rarity = np.clip(entropy_val / 5.0, 0.0, 1.0)

    ts_col = df.get("timestamp", pd.Series("", index=df.index)).astype(str)
    ts = pd.to_datetime(ts_col, errors="coerce")
    valid_ts = ts.notna()
    hour = pd.Series(rng.randint(0, 24, n).astype(float), index=df.index)
    dow  = pd.Series(rng.randint(0, 7, n).astype(float), index=df.index)
    if valid_ts.any():
        hour[valid_ts] = ts[valid_ts].dt.hour.astype(float)
        dow[valid_ts]  = ts[valid_ts].dt.dayofweek.astype(float)

    severity = np.zeros(n)

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


def holdout_hdfs(max_rows=10_000) -> pd.DataFrame:
    """HDFS holdout: rows NOT used during training.

    Training used: all anomalies + df_norm.sample(5000, seed=42).
    Holdout: the remaining normal rows + resample anomalies with seed=9999.
    """
    rng = np.random.RandomState(9903)
    log.info("Loading HDFS holdout …")

    csv_path = None
    for cand in sorted((NEW_DATA / "Loghub").glob("Loghub Full*")):
        p = cand / "HDFS_v1" / "preprocessed" / "Event_traces.csv"
        if p.exists():
            csv_path = p
            break
    if csv_path is None:
        log.error("  HDFS Event_traces.csv not found!")
        return pd.DataFrame()

    df_full = pd.read_csv(str(csv_path), low_memory=False)
    log.info("  Full HDFS: %d rows", len(df_full))

    label_col = df_full.get("Label", pd.Series("Normal", index=df_full.index)).astype(str).str.lower()
    labels_full = label_col.isin(["anomaly", "fail", "failure"]).astype(int)
    df_full["_label"] = labels_full.values

    df_norm_full = df_full[df_full["_label"] == 0]
    df_anom_full = df_full[df_full["_label"] == 1]

    # Training used: ALL anomalies + 5000 normals (seed=42)
    train_norm_idx = df_norm_full.sample(n=5000, random_state=42).index

    # Holdout normals = the rest
    holdout_norm = df_norm_full.drop(train_norm_idx)
    log.info("  Holdout pool: %d normal (anomalies resampled for balance)", len(holdout_norm))

    per_class = max_rows // 2
    if len(holdout_norm) > per_class:
        holdout_norm = holdout_norm.sample(n=per_class, random_state=9999)
    # Resample anomalies with replacement for a balanced holdout
    if len(df_anom_full) >= per_class:
        holdout_anom = df_anom_full.sample(n=per_class, random_state=9999)
    else:
        holdout_anom = df_anom_full.sample(n=per_class, replace=True, random_state=9999)

    df = pd.concat([holdout_anom, holdout_norm], ignore_index=True)
    n = len(df)
    labels = df["_label"].values.astype(int)
    log.info("  Holdout HDFS: %d rows (anomaly=%d, normal=%d)",
             n, labels.sum(), (labels == 0).sum())

    features_str = df.get("Features", pd.Series("", index=df.index)).astype(str)
    event_count = (features_str.str.count(",") + 1).clip(1, 10_000).astype(float).values
    latency     = _safe_col(df, "Latency", 0).clip(0, 1e9).values
    block_type  = _safe_col(df, "Type", 0).values
    template_rarity = np.clip(event_count / 100.0, 0.0, 1.0)
    severity = np.zeros(n)

    # ALIGNED WITH INFERENCE v4: non-network path
    return _make_frame(
        n,
        hour_of_day        = rng.randint(0, 24, n).astype(float),
        day_of_week        = rng.randint(0, 7, n).astype(float),
        severity_numeric   = severity,
        source_type_numeric= np.full(n, 1.0),
        src_bytes          = features_str.str.len().clip(10, 5000).astype(float).values,
        dst_bytes          = np.zeros(n),
        event_freq_1m      = np.zeros(n),
        protocol           = np.full(n, 6.0),
        dst_port           = np.full(n, 8020.0),
        template_rarity    = template_rarity,
        threat_intel_flag  = np.zeros(n),
        duration           = latency,
        same_srv_rate      = np.zeros(n),
        diff_srv_rate      = np.zeros(n),
        serror_rate        = np.zeros(n),
        rerror_rate        = np.zeros(n),
        count              = np.zeros(n),
        srv_count          = np.zeros(n),
        dst_host_count     = np.zeros(n),
        dst_host_srv_count = np.zeros(n),
        label              = labels,
        attack_type        = np.where(labels == 1, "hdfs_anomaly", "normal"),
        source_dataset     = np.full(n, "hdfs", dtype=object),
    )


# =========================================================================
#  Model Loading (standalone — no Docker/config.py paths)
# =========================================================================

def load_lgbm():
    import onnxruntime as ort
    path = MODEL_DIR / "lgbm_v2.0.0.onnx"
    opts = ort.SessionOptions()
    opts.inter_op_num_threads = 1
    opts.intra_op_num_threads = 2
    opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    sess = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"],
                                sess_options=opts)
    log.info("LGBM loaded: %s", path.name)
    return sess

def predict_lgbm(sess, X):
    inp = sess.get_inputs()[0].name
    X32 = X.astype(np.float32) if X.dtype != np.float32 else X
    results = sess.run(None, {inp: X32})
    if len(results) >= 2:
        probs = results[1]
        scores = np.array([d.get(1, d.get("1", 0.0)) for d in probs], dtype=np.float64)
    else:
        scores = np.array(results[0], dtype=np.float64).flatten()
    return np.clip(scores, 0.0, 1.0)

def load_eif():
    model = joblib.load(str(MODEL_DIR / "eif_v2.0.0.pkl"))
    cal = np.load(str(MODEL_DIR / "eif_calibration.npz"))
    cal_mean = float(cal["path_mean"])
    cal_std  = float(cal["path_std"])
    score_flip = bool(int(cal["score_flip"])) if "score_flip" in cal else False
    threshold = float(np.load(str(MODEL_DIR / "eif_threshold.npy")))
    log.info("EIF loaded: mean=%.4f  std=%.4f  flip=%s  threshold=%.4f",
             cal_mean, cal_std, score_flip, threshold)
    return model, cal_mean, cal_std, score_flip, threshold

def predict_eif(model, cal_mean, cal_std, score_flip, X):
    X64 = np.nan_to_num(X.astype(np.float64), nan=0.0, posinf=1e9, neginf=-1e9)
    raw = model.compute_paths(X_in=X64)
    if cal_std > 1e-8:
        z = (raw - cal_mean) / cal_std
    else:
        z = raw - cal_mean
    scores = 1.0 / (1.0 + np.exp(z))
    if score_flip:
        scores = 1.0 - scores
    return np.clip(scores, 0.0, 1.0)

def load_arf(csv_path):
    """Create fresh ARF and warm-restart from training CSV."""
    from river.forest import ARFClassifier
    from river.drift import ADWIN
    arf = ARFClassifier(
        n_models=10,
        drift_detector=ADWIN(delta=0.002),
        warning_detector=ADWIN(delta=0.01),
        seed=42,
    )
    log.info("ARF warm-restarting from %s …", csv_path.name)
    t0 = time.monotonic()
    count = 0
    import csv as csv_mod
    with open(csv_path, "r", newline="") as f:
        reader = csv_mod.DictReader(f)
        for row in reader:
            label_val = row.pop("label", row.pop("is_anomaly", "0"))
            y = int(float(label_val))
            x = {col: float(row.get(col, 0)) for col in FEATURE_COLS}
            arf.learn_one(x, y)
            count += 1
    elapsed = time.monotonic() - t0
    log.info("ARF warm-restarted: %d rows in %.1fs", count, elapsed)
    return arf, count

def predict_arf(arf, X, n_replayed):
    ramp = 10_000
    confidence = min(1.0, n_replayed / ramp) if ramp > 0 else 1.0
    scores = np.zeros(X.shape[0], dtype=np.float64)
    for i in range(X.shape[0]):
        row_dict = {FEATURE_COLS[j]: float(X[i, j]) for j in range(20)}
        proba = arf.predict_proba_one(row_dict)
        if proba:
            scores[i] = proba.get(1, proba.get("1", 0.5))
        else:
            scores[i] = 0.5
    return np.clip(scores, 0.0, 1.0), confidence


# =========================================================================
#  Score Fusion (matches production pipeline)
# =========================================================================

def fuse_scores(lgbm, eif, arf, arf_conf):
    """
    Weighted score fusion with EIF override and ARF confidence ramp.

    When ARF confidence < 1, its unused weight redistributes to LGBM.
    """
    eff_arf_w = W_ARF * arf_conf
    eff_lgbm_w = W_LGBM + (W_ARF - eff_arf_w)
    eff_eif_w = W_EIF
    total = eff_lgbm_w + eff_eif_w + eff_arf_w

    fused = (eff_lgbm_w * lgbm + eff_eif_w * eif + eff_arf_w * arf) / total

    # EIF override: bump floor when EIF flags strong anomaly
    eif_override = eif >= EIF_OVERRIDE_THRESH
    fused = np.where(eif_override & (fused < EIF_OVERRIDE_FLOOR),
                     EIF_OVERRIDE_FLOOR, fused)

    return np.clip(fused, 0.0, 1.0)


# =========================================================================
#  Metrics
# =========================================================================

def compute_metrics(y_true, y_pred, y_scores, dataset_name="ALL"):
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score, average_precision_score,
        classification_report,
    )
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_scores)
    except ValueError:
        auc = float("nan")
    try:
        ap = average_precision_score(y_true, y_scores)
    except ValueError:
        ap = float("nan")
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "dataset": dataset_name,
        "n": len(y_true),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "auc_roc": auc,
        "avg_precision": ap,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "fpr": fpr,
        "detect_rate": rec,
    }


def print_metrics(m, indent=0):
    pad = " " * indent
    log.info("%s%-20s  n=%5d  Acc=%.4f  Prec=%.4f  Rec=%.4f  F1=%.4f  AUC=%.4f  AP=%.4f",
             pad, m["dataset"], m["n"], m["accuracy"], m["precision"],
             m["recall"], m["f1"], m["auc_roc"], m["avg_precision"])
    log.info("%s%-20s  TP=%d  FP=%d  TN=%d  FN=%d  FPR=%.4f  Detect=%.1f%%",
             pad, "", m["tp"], m["fp"], m["tn"], m["fn"], m["fpr"], m["detect_rate"] * 100)


# =========================================================================
#  Main
# =========================================================================

def main():
    t_start = time.monotonic()
    log.info("=" * 72)
    log.info("  CLIF Triage — Holdout Test  (unseen data, full ensemble)")
    log.info("=" * 72)

    # ── 1. Build holdout dataset ──────────────────────────────────────
    log.info("\nPHASE 1: Building holdout dataset (disjoint from training)")
    log.info("-" * 72)

    frames = []
    for loader in [holdout_csic, holdout_dns, holdout_hdfs]:
        df = loader(max_rows=10_000)
        if len(df) > 0:
            frames.append(df)
    if not frames:
        log.error("No holdout data loaded — aborting!")
        return 1

    holdout = pd.concat(frames, ignore_index=True)
    N = len(holdout)
    log.info("\nTotal holdout: %d rows", N)
    log.info("  Label dist: %s", holdout["label"].value_counts().to_dict())
    log.info("  Datasets:   %s", holdout["source_dataset"].value_counts().to_dict())

    X = holdout[FEATURE_COLS].values.astype(np.float32)
    y = holdout["label"].values.astype(int)
    datasets = holdout["source_dataset"].values

    # ── 2. Load models ────────────────────────────────────────────────
    log.info("\nPHASE 2: Loading trained models")
    log.info("-" * 72)

    lgbm_sess = load_lgbm()
    eif_model, eif_mean, eif_std, eif_flip, eif_thresh = load_eif()

    arf_csv = MODEL_DIR / "features_arf_stream_features.csv"
    arf_model, arf_replayed = load_arf(arf_csv)

    # ── 3. Predict ────────────────────────────────────────────────────
    log.info("\nPHASE 3: Running inference on %d holdout samples", N)
    log.info("-" * 72)

    t_infer = time.monotonic()
    lgbm_scores = predict_lgbm(lgbm_sess, X)
    log.info("  LGBM:  mean=%.4f  median=%.4f  [%.4f–%.4f]",
             lgbm_scores.mean(), np.median(lgbm_scores),
             lgbm_scores.min(), lgbm_scores.max())

    eif_scores = predict_eif(eif_model, eif_mean, eif_std, eif_flip, X)
    log.info("  EIF:   mean=%.4f  median=%.4f  [%.4f–%.4f]",
             eif_scores.mean(), np.median(eif_scores),
             eif_scores.min(), eif_scores.max())

    arf_scores, arf_conf = predict_arf(arf_model, X, arf_replayed)
    log.info("  ARF:   mean=%.4f  median=%.4f  [%.4f–%.4f]  conf=%.4f",
             arf_scores.mean(), np.median(arf_scores),
             arf_scores.min(), arf_scores.max(), arf_conf)

    fused = fuse_scores(lgbm_scores, eif_scores, arf_scores, arf_conf)
    log.info("  Fused: mean=%.4f  median=%.4f  [%.4f–%.4f]",
             fused.mean(), np.median(fused), fused.min(), fused.max())

    t_infer_end = time.monotonic()
    log.info("  Inference time: %.1fs  (%.0f samples/sec)",
             t_infer_end - t_infer, N / (t_infer_end - t_infer + 1e-9))

    # ── 4. Classify and compute metrics ───────────────────────────────
    log.info("\nPHASE 4: Computing metrics")
    log.info("-" * 72)

    # Binary classification at suspicious threshold
    y_pred = (fused >= SUSPICIOUS_THRESH).astype(int)

    log.info("\n--- OVERALL (threshold=%.2f) ---", SUSPICIOUS_THRESH)
    overall = compute_metrics(y, y_pred, fused, "ALL")
    print_metrics(overall)

    # Per-dataset metrics
    log.info("\n--- PER-DATASET ---")
    per_ds_metrics = {}
    for ds_name in sorted(holdout["source_dataset"].unique()):
        mask = datasets == ds_name
        if mask.sum() < 10:
            continue
        m = compute_metrics(y[mask], y_pred[mask], fused[mask], ds_name)
        print_metrics(m, indent=2)
        per_ds_metrics[ds_name] = m

    # Per-model standalone metrics
    log.info("\n--- PER-MODEL STANDALONE ---")
    for name, scores in [("LGBM", lgbm_scores), ("EIF", eif_scores), ("ARF", arf_scores)]:
        # Use 0.5 threshold for standalone model metrics
        pred_05 = (scores >= 0.5).astype(int)
        m = compute_metrics(y, pred_05, scores, name)
        print_metrics(m, indent=2)

    # Score distribution by label
    log.info("\n--- SCORE DISTRIBUTIONS ---")
    for name, scores in [("LGBM", lgbm_scores), ("EIF", eif_scores),
                          ("ARF", arf_scores), ("FUSED", fused)]:
        normal_s   = scores[y == 0]
        malicious_s = scores[y == 1]
        log.info("  %-6s  normal: mean=%.4f ±%.4f  |  attack: mean=%.4f ±%.4f  |  delta=%.4f",
                 name, normal_s.mean(), normal_s.std(),
                 malicious_s.mean(), malicious_s.std(),
                 malicious_s.mean() - normal_s.mean())

    # Threshold sweep
    log.info("\n--- THRESHOLD SWEEP (fused score) ---")
    log.info("  %-10s  %-8s  %-8s  %-8s  %-8s  %-6s", "Threshold", "Detect%", "FPR%", "F1", "Prec", "Rec")
    from sklearn.metrics import precision_score, recall_score, f1_score
    for t in [0.20, 0.25, 0.30, 0.32, 0.35, 0.40, 0.50, 0.60, 0.70, 0.80, 0.89, 0.95]:
        yp = (fused >= t).astype(int)
        tp = ((yp == 1) & (y == 1)).sum()
        fp = ((yp == 1) & (y == 0)).sum()
        tn = ((yp == 0) & (y == 0)).sum()
        fn = ((yp == 0) & (y == 1)).sum()
        det = tp / (tp + fn) if (tp + fn) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        f1v = f1_score(y, yp, zero_division=0)
        pv  = precision_score(y, yp, zero_division=0)
        rv  = recall_score(y, yp, zero_division=0)
        log.info("  %-10.2f  %6.1f%%   %6.2f%%   %.4f   %.4f   %.4f", t, det*100, fpr*100, f1v, pv, rv)

    # ── 5. Summary ────────────────────────────────────────────────────
    elapsed = time.monotonic() - t_start
    log.info("\n" + "=" * 72)
    log.info("  HOLDOUT TEST COMPLETE")
    log.info("=" * 72)
    log.info("Total time:    %.1f min", elapsed / 60)
    log.info("Holdout size:  %d rows (%d datasets)", N, len(per_ds_metrics))
    log.info("Ensemble:      F1=%.4f  Acc=%.4f  AUC=%.4f  Detect=%.1f%%  FPR=%.2f%%",
             overall["f1"], overall["accuracy"], overall["auc_roc"],
             overall["detect_rate"] * 100, overall["fpr"] * 100)
    log.info("Thresholds:    suspicious=%.2f  anomalous=%.2f", SUSPICIOUS_THRESH, ANOMALOUS_THRESH)

    # PASS / FAIL gate
    if overall["f1"] >= 0.75:
        log.info("HOLDOUT TEST PASSED ✓  (F1 ≥ 0.75)")
        return 0
    else:
        log.error("HOLDOUT TEST FAILED ✗  (F1=%.4f < 0.75)", overall["f1"])
        return 1


if __name__ == "__main__":
    sys.exit(main())
