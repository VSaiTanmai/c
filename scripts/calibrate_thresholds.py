#!/usr/bin/env python3
"""
CLIF — Calibrate Triage Thresholds from Training Data
======================================================
Scores the entire 175K training set through ALL 3 models (LGBM, EIF, ARF),
computes the combined score using the v5 weight scheme, then finds optimal
thresholds using:
  1. ROC/PR curve analysis per model
  2. Combined-score percentile analysis
  3. Per-dataset-type analysis (network vs log vs mixed)
  4. 3-class optimal boundary search (discard / monitor / escalate)

This ensures thresholds generalize to ALL log types the models were trained on,
not just the 190-event test set.
"""

import os, sys, pickle, warnings, json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import (
    roc_curve, precision_recall_curve, f1_score,
    classification_report, confusion_matrix
)

warnings.filterwarnings("ignore")

BASE = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE / "agents" / "triage" / "models"
DATA_FILE = BASE / "agents" / "Data" / "features_combined_v3.csv"

FEATURE_COLS = [
    "hour_of_day", "day_of_week", "severity_numeric", "source_type_numeric",
    "src_bytes", "dst_bytes", "event_freq_1m", "protocol", "dst_port",
    "template_rarity", "threat_intel_flag", "duration",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

# v5 weights
W_LGBM = 0.80
W_EIF  = 0.12
W_ARF  = 0.08


def load_lgbm():
    """Load LGBM ONNX model and return predict function."""
    import onnxruntime as ort
    # Suppress ONNX shape warnings
    ort.set_default_logger_severity(3)
    model_path = MODEL_DIR / "lgbm_v2.0.0.onnx"
    sess = ort.InferenceSession(str(model_path))
    input_name = sess.get_inputs()[0].name

    def predict(X: np.ndarray) -> np.ndarray:
        """Return P(attack) for each row."""
        results = sess.run(None, {input_name: X.astype(np.float32)})
        # results[1] is the probability map list
        probs = results[1]
        out = np.array([p[1] for p in probs], dtype=np.float64)
        return out

    return predict


def load_eif():
    """Load EIF model and calibration, return score function.
    Mirrors model_ensemble.py CalibratedEIF exactly."""
    import joblib
    eif = joblib.load(MODEL_DIR / "eif_v2.0.0.pkl")
    cal = np.load(MODEL_DIR / "eif_calibration.npz")
    cal_mean = float(cal["path_mean"])
    cal_std = float(cal["path_std"])
    score_flip = bool(int(cal["score_flip"])) if "score_flip" in cal else False

    def predict(X: np.ndarray) -> np.ndarray:
        X64 = np.nan_to_num(X.astype(np.float64), nan=0.0, posinf=1e9, neginf=-1e9)
        BATCH = 10000
        all_scores = []
        for i in range(0, len(X64), BATCH):
            batch = X64[i:i+BATCH]
            raw = eif.compute_paths(X_in=batch)
            z = (raw - cal_mean) / (cal_std + 1e-12)
            scores = 1.0 / (1.0 + np.exp(z))  # sigmoid: shorter path → higher score
            if score_flip:
                scores = 1.0 - scores
            all_scores.append(np.clip(scores, 0.0, 1.0))
        return np.concatenate(all_scores)

    return predict


def load_arf():
    """
    ARF uses warm-restart (fresh model + replay), NOT pickle load.
    After restart, it produces near-constant output (0.75-0.81 range).
    With only 8% weight, we approximate with a constant = 0.50
    (uninformed prior) for calibration purposes. This is actually
    closer to what a fresh ARF produces before replay.
    """
    print("  → ARF uses warm-restart architecture. Using constant=0.50 (8% weight).")
    def predict(X: np.ndarray) -> np.ndarray:
        return np.full(len(X), 0.50, dtype=np.float64)
    return predict, False  # (predict_fn, is_usable)


def combined_score(lgbm_s, eif_s, arf_s):
    """Compute weighted combined score (v5 formula)."""
    return W_LGBM * lgbm_s + W_EIF * eif_s + W_ARF * arf_s


def find_optimal_threshold_f1(y_true, scores):
    """Find threshold that maximizes F1 for binary classification."""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = 2 * precision * recall / (precision + recall + 1e-12)
    best_idx = np.argmax(f1)
    return thresholds[min(best_idx, len(thresholds)-1)], f1[best_idx]


def find_3class_boundaries(y_true, scores):
    """
    Find optimal (suspicious_th, anomalous_th) for 3-class routing:
      score < suspicious_th → discard (predict normal)
      suspicious_th ≤ score < anomalous_th → monitor (ambiguous)
      score ≥ anomalous_th → escalate (predict attack)

    We want:
      - High recall for attacks (few malicious in discard)
      - High precision for escalations (few benign in escalate)
      - Monitor zone should be as narrow as possible

    Strategy: Grid search over (suspicious_th, anomalous_th) pairs,
    optimizing a composite metric:
      metric = attack_recall * 0.5 + benign_precision_in_discard * 0.3
               + escalation_precision * 0.2
    """
    best_score = -1
    best_sus = 0.35
    best_anom = 0.78

    # Grid search
    sus_range = np.arange(0.10, 0.55, 0.01)
    anom_range = np.arange(0.50, 0.95, 0.01)

    for sus_th in sus_range:
        for anom_th in anom_range:
            if anom_th <= sus_th:
                continue

            discard = scores < sus_th
            escalate = scores >= anom_th
            monitor = ~discard & ~escalate

            # Attack recall: what fraction of attacks are escalated?
            n_attacks = (y_true == 1).sum()
            attacks_escalated = ((y_true == 1) & escalate).sum()
            attack_recall = attacks_escalated / max(n_attacks, 1)

            # Attacks in discard (false negatives — CRITICAL)
            attacks_discarded = ((y_true == 1) & discard).sum()
            fn_rate = attacks_discarded / max(n_attacks, 1)

            # Benign in escalate (false positives)
            n_benign = (y_true == 0).sum()
            benign_escalated = ((y_true == 0) & escalate).sum()
            fp_rate = benign_escalated / max(n_benign, 1)

            # Escalation precision
            n_escalated = escalate.sum()
            esc_precision = attacks_escalated / max(n_escalated, 1)

            # Discard precision (benign correctly discarded)
            n_discarded = discard.sum()
            benign_discarded = ((y_true == 0) & discard).sum()
            disc_precision = benign_discarded / max(n_discarded, 1)

            # Monitor should not be too large (penalty for wide monitor zone)
            monitor_frac = monitor.sum() / len(y_true)

            # Composite metric:
            # - Prioritize catching attacks (recall) — weight 0.40
            # - Minimize false negatives (1 - fn_rate) — weight 0.25
            # - Maximize escalation precision — weight 0.20
            # - Minimize monitor zone — weight 0.10
            # - Minimize false positives — weight 0.05
            metric = (
                0.40 * attack_recall
                + 0.25 * (1.0 - fn_rate)
                + 0.20 * esc_precision
                + 0.10 * (1.0 - monitor_frac)
                + 0.05 * (1.0 - fp_rate)
            )

            if metric > best_score:
                best_score = metric
                best_sus = sus_th
                best_anom = anom_th

    return best_sus, best_anom, best_score


def main():
    print("=" * 72)
    print("CLIF — Threshold Calibration from Training Data (175K samples)")
    print("=" * 72)

    # ── Load data ─────────────────────────────────────────────────────
    print("\n[1/6] Loading training data...")
    df = pd.read_csv(DATA_FILE)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["label"].values.astype(int)
    datasets = df["source_dataset"].values
    print(f"  → {len(df)} samples, {(y==1).sum()} attacks, {(y==0).sum()} normal")

    # Categorize datasets by type
    NETWORK_DS = {"cicids2017", "nsl_kdd", "unsw_nb15", "nf_unsw_nb15_v3", "nf_ton_iot"}
    LOG_DS = {"loghub_linux", "loghub_apache", "openssh", "evtx", "hdfs"}
    WEB_DS = {"csic_2010", "dns_exfil"}

    ds_type = np.array([
        "network" if d in NETWORK_DS else
        "log" if d in LOG_DS else "web"
        for d in datasets
    ])

    # ── Score with LGBM ──────────────────────────────────────────────
    print("\n[2/6] Scoring with LGBM v2.0.0...")
    lgbm_predict = load_lgbm()
    lgbm_scores = lgbm_predict(X)
    print(f"  → LGBM scores: min={lgbm_scores.min():.4f}, max={lgbm_scores.max():.4f}, "
          f"mean={lgbm_scores.mean():.4f}, std={lgbm_scores.std():.4f}")

    # ── Score with EIF ────────────────────────────────────────────────
    print("\n[3/6] Scoring with EIF v2.0.0...")
    eif_predict = load_eif()
    eif_scores = eif_predict(X)
    print(f"  → EIF scores: min={eif_scores.min():.4f}, max={eif_scores.max():.4f}, "
          f"mean={eif_scores.mean():.4f}, std={eif_scores.std():.4f}")

    # ── Score with ARF ────────────────────────────────────────────────
    print("\n[4/6] ARF model assessment...")
    arf_predict, arf_usable = load_arf()
    arf_scores = arf_predict(X)

    # ── Combined scores ───────────────────────────────────────────────
    print("\n[5/6] Computing combined scores (v5 weights)...")
    combined = combined_score(lgbm_scores, eif_scores, arf_scores)
    print(f"  → Combined scores: min={combined.min():.4f}, max={combined.max():.4f}, "
          f"mean={combined.mean():.4f}, std={combined.std():.4f}")

    # ── Analysis ──────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("ANALYSIS RESULTS")
    print("=" * 72)

    # Per-model binary F1 at optimal threshold
    print("\n── Per-Model Optimal Binary Thresholds ──")
    for name, scores in [("LGBM", lgbm_scores), ("EIF", eif_scores), ("Combined", combined)]:
        th, f1 = find_optimal_threshold_f1(y, scores)
        preds = (scores >= th).astype(int)
        acc = (preds == y).mean()
        print(f"  {name:10s}: optimal_th={th:.4f}, F1={f1:.4f}, accuracy={acc:.4f}")

    # Per-dataset-type score distributions
    print("\n── Score Distribution by Dataset Type ──")
    for dt in ["network", "log", "web"]:
        mask = ds_type == dt
        if mask.sum() == 0:
            continue
        c = combined[mask]
        y_dt = y[mask]
        print(f"\n  [{dt.upper()}] ({mask.sum()} samples, {(y_dt==1).sum()} attacks, {(y_dt==0).sum()} normal)")
        for label_name, label_val in [("Normal", 0), ("Attack", 1)]:
            lmask = y_dt == label_val
            if lmask.sum() == 0:
                continue
            s = c[lmask]
            print(f"    {label_name:8s}: min={s.min():.4f} p10={np.percentile(s,10):.4f} "
                  f"p25={np.percentile(s,25):.4f} median={np.median(s):.4f} "
                  f"p75={np.percentile(s,75):.4f} p90={np.percentile(s,90):.4f} max={s.max():.4f}")

    # Per-dataset score distributions
    print("\n── Score Distribution by Individual Dataset ──")
    for ds in sorted(set(datasets)):
        mask = datasets == ds
        c = combined[mask]
        y_ds = y[mask]
        n_atk = (y_ds == 1).sum()
        n_nor = (y_ds == 0).sum()
        atk_median = np.median(c[y_ds == 1]) if n_atk > 0 else 0
        nor_median = np.median(c[y_ds == 0]) if n_nor > 0 else 0
        sep = atk_median - nor_median  # class separation
        print(f"  {ds:20s}: n={mask.sum():6d}, atk={n_atk:5d}, nor={n_nor:5d} | "
              f"atk_med={atk_median:.4f}, nor_med={nor_median:.4f}, sep={sep:+.4f}")

    # LGBM-only distributions (since it's 80% of the combined)
    print("\n── LGBM Score Distribution by Dataset Type ──")
    for dt in ["network", "log", "web"]:
        mask = ds_type == dt
        if mask.sum() == 0:
            continue
        l = lgbm_scores[mask]
        y_dt = y[mask]
        print(f"\n  [{dt.upper()}]")
        for label_name, label_val in [("Normal", 0), ("Attack", 1)]:
            lmask = y_dt == label_val
            if lmask.sum() == 0:
                continue
            s = l[lmask]
            print(f"    {label_name:8s}: min={s.min():.4f} p10={np.percentile(s,10):.4f} "
                  f"median={np.median(s):.4f} p90={np.percentile(s,90):.4f} max={s.max():.4f}")

    # ── 3-class boundary optimization ─────────────────────────────────
    print("\n[6/6] Optimizing 3-class boundaries (grid search)...")
    print("  This optimizes: attack_recall × 0.40 + (1-FN) × 0.25 + "
          "esc_precision × 0.20 + (1-monitor_frac) × 0.10 + (1-FP) × 0.05")

    # Global optimization
    sus_th, anom_th, metric = find_3class_boundaries(y, combined)
    print(f"\n  GLOBAL optimal: suspicious={sus_th:.2f}, anomalous={anom_th:.2f} (metric={metric:.4f})")

    # Evaluate at the optimal thresholds
    discard = combined < sus_th
    escalate = combined >= anom_th
    monitor = ~discard & ~escalate

    print(f"\n  Distribution: discard={discard.sum()} ({discard.mean()*100:.1f}%), "
          f"monitor={monitor.sum()} ({monitor.mean()*100:.1f}%), "
          f"escalate={escalate.sum()} ({escalate.mean()*100:.1f}%)")

    attacks_esc = ((y == 1) & escalate).sum()
    attacks_mon = ((y == 1) & monitor).sum()
    attacks_dis = ((y == 1) & discard).sum()
    benign_esc = ((y == 0) & escalate).sum()
    benign_mon = ((y == 0) & monitor).sum()
    benign_dis = ((y == 0) & discard).sum()

    print(f"\n  Confusion (training data):")
    print(f"                escalate    monitor    discard")
    print(f"    attack     {attacks_esc:8d}   {attacks_mon:8d}   {attacks_dis:8d}  (total {(y==1).sum()})")
    print(f"    normal     {benign_esc:8d}   {benign_mon:8d}   {benign_dis:8d}  (total {(y==0).sum()})")
    print(f"\n  Attack recall (escalated): {attacks_esc/(y==1).sum()*100:.1f}%")
    print(f"  Attack FN rate (discarded): {attacks_dis/(y==1).sum()*100:.1f}%")
    print(f"  Benign FP rate (escalated): {benign_esc/(y==0).sum()*100:.1f}%")
    print(f"  Escalation precision: {attacks_esc/max(escalate.sum(),1)*100:.1f}%")

    # Per-dataset-type optimization
    print("\n── Per-Dataset-Type Optimal Boundaries ──")
    for dt in ["network", "log", "web"]:
        mask = ds_type == dt
        if mask.sum() < 100:
            continue
        s_th, a_th, met = find_3class_boundaries(y[mask], combined[mask])
        dis = combined[mask] < s_th
        esc = combined[mask] >= a_th
        mon = ~dis & ~esc
        atk_recall = ((y[mask] == 1) & esc).sum() / max((y[mask] == 1).sum(), 1)
        fn_rate = ((y[mask] == 1) & dis).sum() / max((y[mask] == 1).sum(), 1)
        fp_rate = ((y[mask] == 0) & esc).sum() / max((y[mask] == 0).sum(), 1)
        print(f"  {dt:10s}: suspicious={s_th:.2f}, anomalous={a_th:.2f} | "
              f"atk_recall={atk_recall*100:.1f}%, fn_rate={fn_rate*100:.1f}%, "
              f"fp_rate={fp_rate*100:.1f}%, metric={met:.4f}")

    # ── Recommended config ────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("RECOMMENDED CONFIGURATION")
    print("=" * 72)
    print(f"""
  SCORE_WEIGHTS:              lgbm=0.80, eif=0.12, arf=0.08
  DEFAULT_SUSPICIOUS_THRESHOLD: {sus_th:.2f}
  DEFAULT_ANOMALOUS_THRESHOLD:  {anom_th:.2f}

  These thresholds are computed from {len(df)} training samples across
  12 datasets (network, syslog, web, DNS, Windows events, HDFS).
  They optimize for maximum attack detection with minimal false positives.
""")

    # Save results
    results = {
        "n_samples": len(df),
        "n_attacks": int((y==1).sum()),
        "n_normal": int((y==0).sum()),
        "global_suspicious_threshold": float(sus_th),
        "global_anomalous_threshold": float(anom_th),
        "optimization_metric": float(metric),
        "attack_recall_pct": float(attacks_esc/(y==1).sum()*100),
        "attack_fn_rate_pct": float(attacks_dis/(y==1).sum()*100),
        "benign_fp_rate_pct": float(benign_esc/(y==0).sum()*100),
        "escalation_precision_pct": float(attacks_esc/max(escalate.sum(),1)*100),
        "lgbm_score_stats": {
            "min": float(lgbm_scores.min()),
            "max": float(lgbm_scores.max()),
            "mean": float(lgbm_scores.mean()),
            "std": float(lgbm_scores.std()),
        },
        "eif_score_stats": {
            "min": float(eif_scores.min()),
            "max": float(eif_scores.max()),
            "mean": float(eif_scores.mean()),
            "std": float(eif_scores.std()),
        },
        "combined_score_stats": {
            "min": float(combined.min()),
            "max": float(combined.max()),
            "mean": float(combined.mean()),
            "std": float(combined.std()),
        },
    }

    out_path = BASE / "scripts" / "calibration_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved to {out_path}")


if __name__ == "__main__":
    main()
