#!/usr/bin/env python3
"""
CLIF - Fast Threshold Calibration from Training Data (LGBM-only)
================================================================
LGBM is 80% of combined score and the only model with real discrimination.
EIF (12%) has narrow range 0.34-0.55, ARF (8%) is near-constant ~0.5-0.8.
We score 175K training samples with LGBM only (fast ONNX), add estimated
EIF+ARF offsets, then find optimal 3-class thresholds via grid search.
"""
import json, os, sys, warnings
import numpy as np
import pandas as pd
import onnxruntime as ort
from pathlib import Path

warnings.filterwarnings("ignore")
ort.set_default_logger_severity(3)  # suppress ONNX warnings

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

W_LGBM, W_EIF, W_ARF = 0.80, 0.12, 0.08
# From prior analysis: EIF mean ~0.45, ARF mean ~0.78 (both near-constant)
EIF_CONST = 0.45
ARF_CONST = 0.50

NETWORK_DS = {"cicids2017", "nsl_kdd", "unsw_nb15", "nf_unsw_nb15_v3", "nf_ton_iot"}
LOG_DS = {"loghub_linux", "loghub_apache", "openssh", "evtx", "hdfs"}
WEB_DS = {"csic_2010", "dns_exfil"}

def main():
    print("=" * 70)
    print("CLIF - Fast Threshold Calibration (175K training samples)")
    print("=" * 70)

    # Load data
    print("\n[1/4] Loading training data...")
    df = pd.read_csv(DATA_FILE)
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df["label"].values.astype(int)
    datasets = df["source_dataset"].values
    n_atk, n_nor = (y==1).sum(), (y==0).sum()
    print(f"  {len(df)} samples: {n_atk} attacks, {n_nor} normal")

    ds_type = np.array([
        "network" if d in NETWORK_DS else "log" if d in LOG_DS else "web"
        for d in datasets
    ])

    # Score with LGBM (fast - ONNX batch inference)
    print("\n[2/4] LGBM scoring (ONNX batch)...")
    sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v2.0.0.onnx"))
    inp = sess.get_inputs()[0].name
    # Score in one batch
    results = sess.run(None, {inp: X})
    lgbm = np.array([p[1] for p in results[1]], dtype=np.float64)
    print(f"  LGBM: min={lgbm.min():.4f} max={lgbm.max():.4f} mean={lgbm.mean():.4f} std={lgbm.std():.4f}")
    print(f"  LGBM normal:  median={np.median(lgbm[y==0]):.4f} p90={np.percentile(lgbm[y==0],90):.4f}")
    print(f"  LGBM attack:  median={np.median(lgbm[y==1]):.4f} p10={np.percentile(lgbm[y==1],10):.4f}")

    # Estimate combined score
    combined = W_LGBM * lgbm + W_EIF * EIF_CONST + W_ARF * ARF_CONST
    print(f"\n  Combined (est): min={combined.min():.4f} max={combined.max():.4f} "
          f"mean={combined.mean():.4f} std={combined.std():.4f}")

    # Per-dataset-type LGBM statistics
    print("\n[3/4] Per-dataset LGBM score analysis...")
    print(f"\n  {'Dataset':<22s} {'N':>6s} {'Atk':>5s} {'Nor':>5s} | "
          f"{'Atk_med':>7s} {'Nor_med':>7s} {'Sep':>6s}")
    print("  " + "-" * 68)
    for ds in sorted(set(datasets)):
        m = datasets == ds
        na, nn = (y[m]==1).sum(), (y[m]==0).sum()
        am = np.median(lgbm[m & (y==1)]) if na > 0 else 0
        nm = np.median(lgbm[m & (y==0)]) if nn > 0 else 0
        print(f"  {ds:<22s} {m.sum():>6d} {na:>5d} {nn:>5d} | "
              f"{am:>7.4f} {nm:>7.4f} {am-nm:>+6.4f}")

    # Grid search for optimal 3-class boundaries
    print("\n[4/4] Grid search for optimal thresholds...")
    best_score = -1
    best_sus = 0.35
    best_anom = 0.78

    sus_range = np.arange(0.05, 0.50, 0.005)
    anom_range = np.arange(0.40, 0.95, 0.005)

    for sus_th in sus_range:
        for anom_th in anom_range:
            if anom_th <= sus_th + 0.05:
                continue

            dis = combined < sus_th
            esc = combined >= anom_th

            atk_esc = ((y==1) & esc).sum()
            atk_dis = ((y==1) & dis).sum()
            ben_esc = ((y==0) & esc).sum()

            atk_recall = atk_esc / n_atk
            fn_rate = atk_dis / n_atk
            fp_rate = ben_esc / n_nor
            esc_prec = atk_esc / max(esc.sum(), 1)
            mon_frac = (~dis & ~esc).sum() / len(y)

            # Security-weighted: prioritize catching attacks, penalize FN heavily
            metric = (
                0.40 * atk_recall
                + 0.25 * (1.0 - fn_rate)
                + 0.20 * esc_prec
                + 0.10 * (1.0 - mon_frac)
                + 0.05 * (1.0 - fp_rate)
            )
            if metric > best_score:
                best_score = metric
                best_sus = sus_th
                best_anom = anom_th

    # Evaluate at optimal thresholds
    dis = combined < best_sus
    esc = combined >= best_anom
    mon = ~dis & ~esc

    atk_esc = ((y==1) & esc).sum()
    atk_mon = ((y==1) & mon).sum()
    atk_dis = ((y==1) & dis).sum()
    ben_esc = ((y==0) & esc).sum()
    ben_mon = ((y==0) & mon).sum()
    ben_dis = ((y==0) & dis).sum()

    print(f"\n{'='*70}")
    print(f"OPTIMAL THRESHOLDS (from {len(df)} training samples)")
    print(f"{'='*70}")
    print(f"\n  suspicious_threshold = {best_sus:.3f}")
    print(f"  anomalous_threshold  = {best_anom:.3f}")
    print(f"  optimization_metric  = {best_score:.4f}")

    print(f"\n  Distribution: discard={dis.sum()} ({dis.mean()*100:.1f}%) | "
          f"monitor={mon.sum()} ({mon.mean()*100:.1f}%) | "
          f"escalate={esc.sum()} ({esc.mean()*100:.1f}%)")

    print(f"\n  Confusion matrix ({len(df)} samples):")
    print(f"  {'':15s} {'escalate':>10s} {'monitor':>10s} {'discard':>10s} | Total")
    print(f"  {'attack':15s} {atk_esc:>10d} {atk_mon:>10d} {atk_dis:>10d} | {n_atk}")
    print(f"  {'normal':15s} {ben_esc:>10d} {ben_mon:>10d} {ben_dis:>10d} | {n_nor}")

    print(f"\n  Attack recall (escalated): {atk_esc/n_atk*100:.1f}%")
    print(f"  Attack FN rate (discarded): {atk_dis/n_atk*100:.1f}%")
    print(f"  Benign FP rate (escalated): {ben_esc/n_nor*100:.1f}%")
    print(f"  Escalation precision: {atk_esc/max(esc.sum(),1)*100:.1f}%")

    # Per-type evaluation
    print(f"\n  Per-dataset-type at optimal thresholds:")
    for dt in ["network", "log", "web"]:
        m = ds_type == dt
        if m.sum() < 50: continue
        c = combined[m]; yl = y[m]
        d = c < best_sus; e = c >= best_anom
        ar = ((yl==1) & e).sum() / max((yl==1).sum(),1)
        fn = ((yl==1) & d).sum() / max((yl==1).sum(),1)
        fp = ((yl==0) & e).sum() / max((yl==0).sum(),1)
        print(f"    {dt:10s}: atk_recall={ar*100:.1f}%, fn_rate={fn*100:.1f}%, fp_rate={fp*100:.1f}%")

    # Also test a few alternative threshold pairs for comparison
    print(f"\n  Comparison of threshold pairs:")
    print(f"  {'Sus':>5s} {'Anom':>5s} | {'AtkRecall':>9s} {'FN%':>5s} {'FP%':>5s} {'EscPrec':>7s} {'MonFrac':>7s}")
    print(f"  {'-'*55}")
    for s, a in [(0.10, 0.50), (0.15, 0.55), (0.20, 0.60), (0.25, 0.65),
                 (0.30, 0.70), (0.35, 0.78), (best_sus, best_anom)]:
        d = combined < s; e = combined >= a
        ar = ((y==1)&e).sum()/n_atk*100
        fn = ((y==1)&d).sum()/n_atk*100
        fp = ((y==0)&e).sum()/n_nor*100
        ep = ((y==1)&e).sum()/max(e.sum(),1)*100
        mf = (~d&~e).sum()/len(y)*100
        tag = " <-- optimal" if abs(s-best_sus)<0.001 and abs(a-best_anom)<0.001 else ""
        print(f"  {s:>5.2f} {a:>5.2f} | {ar:>8.1f}% {fn:>4.1f}% {fp:>4.1f}% {ep:>6.1f}% {mf:>6.1f}%{tag}")

    # Save results
    results = {
        "n_samples": len(df),
        "suspicious_threshold": round(float(best_sus), 3),
        "anomalous_threshold": round(float(best_anom), 3),
        "attack_recall_pct": round(atk_esc/n_atk*100, 1),
        "fn_rate_pct": round(atk_dis/n_atk*100, 1),
        "fp_rate_pct": round(ben_esc/n_nor*100, 1),
        "escalation_precision_pct": round(atk_esc/max(esc.sum(),1)*100, 1),
    }
    out = BASE / "scripts" / "calibration_results.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved to {out}")

if __name__ == "__main__":
    main()
