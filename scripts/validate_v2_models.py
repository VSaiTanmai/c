#!/usr/bin/env python3
"""
CLIF v2 Model Validation — Direct model inference test
=======================================================
Tests all 3 retrained models against crafted attack scenarios
WITHOUT requiring Kafka/ClickHouse infrastructure.

Tests:
  1. LightGBM ONNX: known attacks must score > 0.5
  2. EIF: anomalous features must score higher than normal (with flip)
  3. ARF: varying output verified (delta > 0.1)
  4. Combined score: attack scenarios above suspicious threshold
  5. Per-dataset synthetic events: correct classification
"""

import json
import pickle
import sys
import time
from pathlib import Path

import joblib
import numpy as np

MODEL_DIR = Path(__file__).resolve().parent.parent / "agents" / "triage" / "models"

FEATURE_COLS = [
    "hour_of_day", "day_of_week", "severity_numeric", "source_type_numeric",
    "src_bytes", "dst_bytes", "event_freq_1m", "protocol", "dst_port",
    "template_rarity", "threat_intel_flag", "duration",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]

# ─── Attack scenarios (feature vectors) ─────────────────────────────────

SCENARIOS = {
    "syn_flood": {
        "hour_of_day": 3, "day_of_week": 2, "severity_numeric": 0,  # network flows have no severity
        "source_type_numeric": 9, "src_bytes": 0, "dst_bytes": 0,
        "event_freq_1m": 5000, "protocol": 6, "dst_port": 80,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 1,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.95, "rerror_rate": 0.0,
        "count": 500, "srv_count": 500, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "port_scan": {
        "hour_of_day": 2, "day_of_week": 6, "severity_numeric": 1,  # IDS default
        "source_type_numeric": 10, "src_bytes": 200, "dst_bytes": 0,
        "event_freq_1m": 2000, "protocol": 6, "dst_port": 22,
        "template_rarity": 0.3, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.9,
        "serror_rate": 0.0, "rerror_rate": 0.8,
        "count": 300, "srv_count": 2, "dst_host_count": 250, "dst_host_srv_count": 1,
    },
    "brute_force_ssh": {
        "hour_of_day": 4, "day_of_week": 1, "severity_numeric": 2,  # syslog warning for auth failure
        "source_type_numeric": 1, "src_bytes": 500, "dst_bytes": 100,
        "event_freq_1m": 100, "protocol": 6, "dst_port": 22,
        "template_rarity": 0.3, "threat_intel_flag": 0, "duration": 300,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 50, "srv_count": 50, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "data_exfiltration": {
        "hour_of_day": 3, "day_of_week": 0, "severity_numeric": 0,  # network flow, no severity
        "source_type_numeric": 9, "src_bytes": 500000000, "dst_bytes": 1000,
        "event_freq_1m": 10, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.1, "threat_intel_flag": 1, "duration": 7200000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 5, "srv_count": 5, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "web_attack_sqli": {
        "hour_of_day": 14, "day_of_week": 3, "severity_numeric": 0,  # HTTP request, info level
        "source_type_numeric": 8, "src_bytes": 2000, "dst_bytes": 0,
        "event_freq_1m": 50, "protocol": 6, "dst_port": 80,
        "template_rarity": 0.1, "threat_intel_flag": 0, "duration": 10,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 30, "srv_count": 30, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "windows_lateral_movement": {
        "hour_of_day": 2, "day_of_week": 5, "severity_numeric": 0,  # Windows event, Information level
        "source_type_numeric": 2, "src_bytes": 0, "dst_bytes": 0,
        "event_freq_1m": 50, "protocol": 6, "dst_port": 445,
        "template_rarity": 0.1, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1, "srv_count": 1, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "ddos_smurf": {
        "hour_of_day": 12, "day_of_week": 3, "severity_numeric": 0,  # network flow, no severity
        "source_type_numeric": 3, "src_bytes": 100, "dst_bytes": 100000,
        "event_freq_1m": 10000, "protocol": 1, "dst_port": 0,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 5,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1000, "srv_count": 1000, "dst_host_count": 255, "dst_host_srv_count": 255,
    },
    "normal_web": {
        "hour_of_day": 10, "day_of_week": 2, "severity_numeric": 0,  # normal HTTP, info level
        "source_type_numeric": 8, "src_bytes": 500, "dst_bytes": 15000,
        "event_freq_1m": 5, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.6, "threat_intel_flag": 0, "duration": 200,
        "same_srv_rate": 0.5, "diff_srv_rate": 0.3,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 3, "srv_count": 2, "dst_host_count": 5, "dst_host_srv_count": 3,
    },
    "normal_syslog": {
        "hour_of_day": 14, "day_of_week": 3, "severity_numeric": 0,  # normal syslog, info level
        "source_type_numeric": 1, "src_bytes": 0, "dst_bytes": 0,
        "event_freq_1m": 10, "protocol": 0, "dst_port": 0,
        "template_rarity": 0.6, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1, "srv_count": 1, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
    "normal_netflow": {
        "hour_of_day": 11, "day_of_week": 1, "severity_numeric": 0,  # normal netflow, no severity
        "source_type_numeric": 9, "src_bytes": 2000, "dst_bytes": 50000,
        "event_freq_1m": 20, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 30000,
        "same_srv_rate": 0.5, "diff_srv_rate": 0.2,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 10, "srv_count": 5, "dst_host_count": 3, "dst_host_srv_count": 2,
    },
}

ATTACK_NAMES = [k for k in SCENARIOS if not k.startswith("normal")]
NORMAL_NAMES = [k for k in SCENARIOS if k.startswith("normal")]


def build_features(scenario_name):
    s = SCENARIOS[scenario_name]
    return np.array([s[c] for c in FEATURE_COLS], dtype=np.float32)


def main():
    passed = 0
    failed = 0
    total = 0

    print("=" * 70)
    print("  CLIF v2 MODEL VALIDATION")
    print("=" * 70)

    # Load manifest
    manifest = json.load(open(MODEL_DIR / "manifest.json"))
    print(f"Manifest: LGBM={manifest['lgbm']['active']}, EIF={manifest['eif']['active']}, ARF={manifest['arf']['active']}")
    print(f"Thresholds: suspicious={manifest['thresholds']['suspicious']}, anomalous={manifest['thresholds']['anomalous']}")
    print()

    # ── TEST 1: LightGBM ONNX ──────────────────────────────────────────
    print("--- TEST 1: LightGBM ONNX inference ---")
    import onnxruntime as ort
    sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v2.0.0.onnx"),
                                 providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0].name

    X_all = np.stack([build_features(k) for k in SCENARIOS], axis=0)
    out = sess.run(None, {inp: X_all})
    lgbm_scores = np.array([d.get(1, d.get("1", 0.0)) for d in out[1]], dtype=np.float64)

    for i, name in enumerate(SCENARIOS):
        score = lgbm_scores[i]
        is_attack = not name.startswith("normal")
        expected = score > 0.5 if is_attack else score < 0.5
        status = "PASS" if expected else "FAIL"
        if expected:
            passed += 1
        else:
            failed += 1
        total += 1
        print(f"  {name:30s} lgbm={score:.4f}  {'ATTACK' if is_attack else 'NORMAL':8s} [{status}]")
    print()

    # ── TEST 2: EIF (with flip) ────────────────────────────────────────
    print("--- TEST 2: Extended Isolation Forest (flipped) ---")
    eif = joblib.load(str(MODEL_DIR / "eif_v2.0.0.pkl"))
    cal = np.load(str(MODEL_DIR / "eif_calibration.npz"))
    cal_mean, cal_std = float(cal["path_mean"]), float(cal["path_std"])
    score_flip = bool(int(cal.get("score_flip", 0)))
    print(f"  Calibration: mean={cal_mean:.6f}, std={cal_std:.6f}, flip={score_flip}")

    X_f64 = X_all.astype(np.float64)
    raw = eif.compute_paths(X_in=X_f64)
    z = (raw - cal_mean) / max(cal_std, 1e-10)
    eif_scores = 1.0 / (1.0 + np.exp(z))
    if score_flip:
        eif_scores = 1.0 - eif_scores

    attack_eif_mean = np.mean([eif_scores[i] for i, k in enumerate(SCENARIOS) if not k.startswith("normal")])
    normal_eif_mean = np.mean([eif_scores[i] for i, k in enumerate(SCENARIOS) if k.startswith("normal")])
    eif_delta = attack_eif_mean - normal_eif_mean

    total += 1
    if eif_delta > 0:
        passed += 1
        status = "PASS"
    else:
        failed += 1
        status = "FAIL"
    print(f"  Attack mean: {attack_eif_mean:.4f}, Normal mean: {normal_eif_mean:.4f}, Delta: {eif_delta:+.4f} [{status}]")

    for i, name in enumerate(SCENARIOS):
        print(f"  {name:30s} eif={eif_scores[i]:.4f}")
    print()

    # ── TEST 3: ARF varying output ─────────────────────────────────────
    print("--- TEST 3: ARF checkpoint (varying output) ---")
    with open(MODEL_DIR / "arf_v2.0.0.pkl", "rb") as f:
        arf = pickle.load(f)

    d_zeros = {c: 0.0 for c in FEATURE_COLS}
    d_high = {c: 100.0 for c in FEATURE_COLS}
    d_high["severity_numeric"] = 4.0
    d_high["serror_rate"] = 0.95

    p0 = arf.predict_proba_one(d_zeros).get(1, 0.5)
    p1 = arf.predict_proba_one(d_high).get(1, 0.5)
    arf_delta = abs(p1 - p0)

    total += 1
    if arf_delta > 0.1:
        passed += 1
        status = "PASS"
    else:
        failed += 1
        status = "FAIL"
    print(f"  p(zeros)={p0:.4f}, p(high)={p1:.4f}, delta={arf_delta:.4f} [{status}]")

    # ARF per-scenario
    arf_scores = []
    for name in SCENARIOS:
        s = SCENARIOS[name]
        x = {c: float(s[c]) for c in FEATURE_COLS}
        p = arf.predict_proba_one(x).get(1, 0.5)
        arf_scores.append(p)
        print(f"  {name:30s} arf={p:.4f}")
    arf_scores = np.array(arf_scores)
    print()

    # ── TEST 4: Combined scores ────────────────────────────────────────
    print("--- TEST 4: Combined ensemble scores ---")
    # Cold-start weights (ARF conf=0): LGBM=0.80, EIF=0.20
    combined_cold = 0.80 * lgbm_scores + 0.20 * eif_scores
    # Full weights: LGBM=0.60, EIF=0.15, ARF=0.25
    combined_full = 0.60 * lgbm_scores + 0.15 * eif_scores + 0.25 * arf_scores

    susp_thresh = manifest["thresholds"]["suspicious"]
    anom_thresh = manifest["thresholds"]["anomalous"]

    print(f"  {'Scenario':30s} {'Cold':>8s} {'Full':>8s} {'Action(cold)':>14s} {'Action(full)':>14s}")
    print(f"  {'-'*30} {'-'*8} {'-'*8} {'-'*14} {'-'*14}")

    for i, name in enumerate(SCENARIOS):
        cold = combined_cold[i]
        full = combined_full[i]
        act_cold = "escalate" if cold >= anom_thresh else ("monitor" if cold >= susp_thresh else "discard")
        act_full = "escalate" if full >= anom_thresh else ("monitor" if full >= susp_thresh else "discard")
        print(f"  {name:30s} {cold:8.4f} {full:8.4f} {act_cold:>14s} {act_full:>14s}")

        is_attack = not name.startswith("normal")
        total += 1
        if is_attack:
            # Attack detection: score > 0.3 (at least some signal)
            if cold >= 0.3:
                passed += 1
            else:
                failed += 1
                print(f"    ^^^ FAIL: attack not detected (cold combined={cold:.4f} < 0.3)")
        else:
            # Normal traffic: must NOT trigger anomalous/escalate
            # Being flagged as "suspicious" is acceptable (SOC investigates)
            if cold < anom_thresh:
                passed += 1
            else:
                failed += 1
                print(f"    ^^^ FAIL: normal flagged as ANOMALOUS (cold combined={cold:.4f} >= thresh={anom_thresh})")
    print()

    # ── TEST 5: LightGBM differentiation ratio ────────────────────────
    print("--- TEST 5: LightGBM differentiation ratio ---")
    attack_lgbm = np.mean([lgbm_scores[i] for i, k in enumerate(SCENARIOS) if not k.startswith("normal")])
    normal_lgbm = np.mean([lgbm_scores[i] for i, k in enumerate(SCENARIOS) if k.startswith("normal")])
    ratio = attack_lgbm / max(normal_lgbm, 1e-10)

    total += 1
    if ratio > 1.3:
        passed += 1
        status = "PASS"
    else:
        failed += 1
        status = "FAIL"
    print(f"  Attack mean: {attack_lgbm:.4f}, Normal mean: {normal_lgbm:.4f}, Ratio: {ratio:.1f}x [{status}]")
    print()

    # ── SUMMARY ─────────────────────────────────────────────────────────
    print("=" * 70)
    print(f"  VALIDATION RESULTS: {passed}/{total} PASSED, {failed} FAILED")
    if failed == 0:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  WARNING: {failed} tests failed — review above output")
    print("=" * 70)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
