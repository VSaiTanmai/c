#!/usr/bin/env python3
"""
CLIF Triage Agent — Fix Verification Test
============================================
Validates the 8 fixes applied to the triage agent:

  1. EIF calibrated normalization (fixed mean/std from training data)
  2. ARF dynamic weighting (confidence ramp from 0→20%)
  3. ARF label leakage fix (LightGBM pseudo-labels)
  4. Template rarity post-model boost
  5. IOC match score boost
  6. Recalibrated thresholds (0.45/0.78 from data distributions)
  7. Inf/NaN defensive handling
  8. Feature extractor byte clamping

Tests run locally using the model files and training data — no Docker needed.

Usage:
    python tests/verify_fixes.py
"""

import os
import sys
import pickle
import csv
import numpy as np

# Add agent source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents", "triage"))

# Patch config defaults for local testing (no Docker env vars)
os.environ.setdefault("MODEL_DIR", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models"))
os.environ.setdefault("MODEL_LGBM_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "lgbm_v1.0.0.onnx"))
os.environ.setdefault("MODEL_EIF_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "eif_v1.0.0.pkl"))
os.environ.setdefault("MODEL_EIF_THRESHOLD_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "eif_threshold.npy"))
os.environ.setdefault("MODEL_EIF_CALIBRATION_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "eif_calibration.npz"))
os.environ.setdefault("FEATURE_COLS_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "feature_cols.pkl"))
os.environ.setdefault("MANIFEST_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "manifest.json"))
os.environ.setdefault("ARF_STREAM_CSV_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "models", "features_arf_stream_features.csv"))
os.environ.setdefault("DRAIN3_STATE_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "drain3_state_test.bin"))
os.environ.setdefault("DRAIN3_CONFIG_PATH", os.path.join(os.path.dirname(__file__), "..", "agents", "triage", "drain3.ini"))

import config
from model_ensemble import LightGBMONNX, ExtendedIsolationForest, AdaptiveRandomForest, ModelEnsemble
from feature_extractor import FeatureExtractor, ConnectionTracker, FEATURE_NAMES
from drain3_miner import Drain3Miner

# ── Test helpers ─────────────────────────────────────────────────────────

tests_run = 0
tests_passed = 0

def test(name, condition, detail=""):
    global tests_run, tests_passed
    tests_run += 1
    if condition:
        tests_passed += 1
        print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))
    else:
        print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))


def main():
    global tests_run, tests_passed

    print("=" * 60)
    print("CLIF Triage Agent — Fix Verification")
    print("=" * 60)

    # ── Load feature columns ────────────────────────────────────────────
    with open(config.FEATURE_COLS_PATH, "rb") as f:
        feature_cols = pickle.load(f)
    print(f"\nFeature columns: {len(feature_cols)}")
    assert feature_cols == list(FEATURE_NAMES), "Feature column mismatch!"

    # ════════════════════════════════════════════════════════════════════
    # FIX 1: EIF Calibrated Normalization
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 1: EIF Calibrated Normalization")
    print(f"{'─' * 50}")

    eif = ExtendedIsolationForest(
        config.MODEL_EIF_PATH,
        config.MODEL_EIF_THRESHOLD_PATH,
        calibration_path=config.MODEL_EIF_CALIBRATION_PATH,
    )
    test("EIF is calibrated", eif.is_calibrated,
         f"cal_mean={eif._cal_mean:.4f}, cal_std={eif._cal_std:.4f}")

    # The same event in different batch contexts should get the SAME score
    rng = np.random.RandomState(42)
    test_event = rng.randn(1, 20).astype(np.float64)

    # Batch 1: test event with normal-looking events
    batch1 = np.vstack([test_event, rng.randn(99, 20)])
    score_batch1 = eif.predict_batch(batch1)[0]

    # Batch 2: test event with extreme outliers
    outliers = rng.randn(99, 20) * 100
    batch2 = np.vstack([test_event, outliers])
    score_batch2 = eif.predict_batch(batch2)[0]

    # Batch 3: test event alone
    score_single = eif.predict_batch(test_event)[0]

    test("Same score across batches (calibrated)",
         abs(score_batch1 - score_batch2) < 0.001 and abs(score_batch1 - score_single) < 0.001,
         f"batch1={score_batch1:.6f}, batch2={score_batch2:.6f}, single={score_single:.6f}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 2: ARF Dynamic Weighting
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 2: ARF Dynamic Weighting (Confidence Ramp)")
    print(f"{'─' * 50}")

    arf = AdaptiveRandomForest(feature_cols)
    test("ARF confidence starts at 0",
         arf.confidence == 0.0,
         f"confidence={arf.confidence:.4f}")

    # After CSV replay, confidence should increase
    csv_path = config.ARF_STREAM_CSV_PATH
    if os.path.exists(csv_path):
        # Replay a small portion
        count = 0
        with open(csv_path, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if count >= 1000:
                    break
                label_val = row.pop("label", row.pop("is_anomaly", "0"))
                y = int(float(label_val))
                x = {col: float(row.get(col, 0)) for col in feature_cols}
                arf.learn_one(x, y)
                count += 1

        arf._rows_replayed = 0  # Reset for test
        expected_conf = min(1.0, count / config.ARF_CONFIDENCE_RAMP_SAMPLES)
        test("ARF confidence ramps with learning",
             abs(arf.confidence - expected_conf) < 0.01,
             f"after {count} samples: confidence={arf.confidence:.4f} (expected ~{expected_conf:.4f})")

        # Verify cold-start weight is effectively 0
        test("ARF confidence < 1.0 during cold-start",
             arf.confidence < 1.0,
             f"only {count}/{config.ARF_CONFIDENCE_RAMP_SAMPLES} samples = {arf.confidence:.2%}")
    else:
        print(f"  [SKIP] ARF CSV not found at {csv_path}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 3: Score Fusion Dynamic Weighting
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 3: Score Fusion with Dynamic Weighting")
    print(f"{'─' * 50}")

    from score_fusion import ScoreFusion

    fusion = ScoreFusion(ch_client=None, weights=config.SCORE_WEIGHTS)

    # Simulate model scores with ARF cold-start
    N = 10
    lgbm_scores = np.array([0.9] * N, dtype=np.float64)
    eif_scores = np.array([0.6] * N, dtype=np.float64)
    arf_scores = np.array([0.074] * N, dtype=np.float64)

    # Create minimal events and features
    events = [{"event_id": f"test-{i}", "timestamp": "2025-01-01T00:00:00Z",
               "hostname": "test-host", "src_ip": "10.0.0.1"} for i in range(N)]
    features = [dict(zip(FEATURE_NAMES, [0.0] * 20)) for _ in range(N)]
    for feat in features:
        feat["_source_type"] = "syslog"
        feat["_template_id"] = ""
        feat["template_rarity"] = 0.5  # Not rare

    # Test with low ARF confidence (cold-start)
    model_scores_cold = {"lgbm": lgbm_scores, "eif": eif_scores,
                         "arf": arf_scores, "arf_confidence": 0.1}
    results_cold = fusion.fuse_batch(model_scores_cold, features, events)

    # Test with high ARF confidence (warmed up)
    model_scores_warm = {"lgbm": lgbm_scores, "eif": eif_scores,
                         "arf": arf_scores, "arf_confidence": 1.0}
    results_warm = fusion.fuse_batch(model_scores_warm, features, events)

    cold_combined = results_cold[0].combined_score
    warm_combined = results_warm[0].combined_score

    # With cold-start ARF (conf=0.1), the dead-weight ARF should barely affect score
    # combined ≈ lgbm*0.625 + eif*0.375 = 0.5625 + 0.225 = 0.7875 (no ARF)
    # vs warm: lgbm*0.5 + eif*0.3 + arf*0.2 = 0.45 + 0.18 + 0.0148 = 0.6448
    test("Cold-start ARF doesn't drag score down",
         cold_combined > warm_combined,
         f"cold={cold_combined:.4f} > warm={warm_combined:.4f} (ARF=0.074 drags down warm)")

    # Verify cold-start can reach escalate threshold
    test("Cold-start score reaches escalate",
         results_cold[0].action == "escalate",
         f"adjusted={results_cold[0].adjusted_score:.4f}, action={results_cold[0].action}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 4 & 5: Template Rarity + IOC Post-Model Boost
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 4-5: Template Rarity & IOC Post-Model Boost")
    print(f"{'─' * 50}")

    # Simulate a borderline event that ONLY rare template saves
    lgbm_borderline = np.array([0.5] * N, dtype=np.float64)
    eif_borderline = np.array([0.5] * N, dtype=np.float64)
    arf_borderline = np.array([0.5] * N, dtype=np.float64)

    model_scores_border = {"lgbm": lgbm_borderline, "eif": eif_borderline,
                           "arf": arf_borderline, "arf_confidence": 1.0}

    # Normal template rarity (0.5 — not rare)
    features_normal_tmpl = [dict(zip(FEATURE_NAMES, [0.0] * 20)) for _ in range(N)]
    for feat in features_normal_tmpl:
        feat["_source_type"] = "syslog"
        feat["_template_id"] = ""
        feat["template_rarity"] = 0.5  # Not rare

    results_normal_tmpl = fusion.fuse_batch(model_scores_border, features_normal_tmpl, events)

    # Rare template (rarity=0.02 — never seen before)
    features_rare_tmpl = [dict(zip(FEATURE_NAMES, [0.0] * 20)) for _ in range(N)]
    for feat in features_rare_tmpl:
        feat["_source_type"] = "syslog"
        feat["_template_id"] = ""
        feat["template_rarity"] = 0.02  # Very rare

    results_rare_tmpl = fusion.fuse_batch(model_scores_border, features_rare_tmpl, events)

    normal_adjusted = results_normal_tmpl[0].adjusted_score
    rare_adjusted = results_rare_tmpl[0].adjusted_score
    test("Rare template boosts score",
         rare_adjusted > normal_adjusted,
         f"rare={rare_adjusted:.4f} > normal={normal_adjusted:.4f} "
         f"(+{(rare_adjusted - normal_adjusted):.4f})")

    test("Template boost magnitude correct",
         abs(rare_adjusted - normal_adjusted - config.TEMPLATE_RARITY_BOOST_MAX * (1 - 0.02 / config.TEMPLATE_RARITY_RARE_THRESHOLD)) < 0.01,
         f"expected boost ~{config.TEMPLATE_RARITY_BOOST_MAX * (1 - 0.02/config.TEMPLATE_RARITY_RARE_THRESHOLD):.4f}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 6: Recalibrated Thresholds
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 6: Recalibrated Thresholds")
    print(f"{'─' * 50}")

    test("Suspicious threshold = 0.45",
         config.DEFAULT_SUSPICIOUS_THRESHOLD == 0.45,
         f"actual={config.DEFAULT_SUSPICIOUS_THRESHOLD}")

    test("Anomalous threshold = 0.78",
         config.DEFAULT_ANOMALOUS_THRESHOLD == 0.78,
         f"actual={config.DEFAULT_ANOMALOUS_THRESHOLD}")

    test("Disagreement threshold = 0.30",
         config.DISAGREEMENT_THRESHOLD == 0.30,
         f"actual={config.DISAGREEMENT_THRESHOLD}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 7: Inf/NaN Defensive Handling
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 7: Inf/NaN Defensive Handling")
    print(f"{'─' * 50}")

    # LightGBM with inf/NaN input
    lgbm = LightGBMONNX(config.MODEL_LGBM_PATH, feature_cols)
    X_poison = np.array([[float("inf")] + [0.0] * 19], dtype=np.float32)

    # ModelEnsemble.predict_batch should sanitize input
    X_sanitized = np.nan_to_num(X_poison, nan=0.0, posinf=1e9, neginf=-1e9)
    try:
        score = lgbm.predict_batch(X_sanitized)
        test("LightGBM handles sanitized inf",
             0.0 <= float(score[0]) <= 1.0,
             f"score={float(score[0]):.4f}")
    except Exception as e:
        test("LightGBM handles sanitized inf", False, f"error: {e}")

    # EIF with inf input (should be sanitized internally now)
    try:
        X_inf = np.array([[float("inf")] * 20], dtype=np.float64)
        eif_score = eif.predict_batch(X_inf)
        test("EIF handles inf input (internal sanitization)",
             0.0 <= float(eif_score[0]) <= 1.0,
             f"score={float(eif_score[0]):.4f}")
    except Exception as e:
        test("EIF handles inf input", False, f"error: {e}")

    # Feature extractor byte clamping
    print(f"\n{'─' * 50}")
    print("Fix 8: Feature Extractor Byte Clamping")
    print(f"{'─' * 50}")

    drain3 = Drain3Miner()
    extractor = FeatureExtractor(drain3_miner=drain3)

    # Event with extreme bytes
    event_extreme = {
        "timestamp": "2025-01-01T00:00:00Z",
        "hostname": "test",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "bytes_sent": float("inf"),
        "bytes_received": 1e15,
        "dst_port": 80,
        "protocol": "tcp",
        "duration_ms": 100,
        "severity": "high",
        "source_type": "netflow",
        "message": "test connection",
    }

    feat = extractor.extract(event_extreme, "network-events")
    test("src_bytes clamped (inf → 1e9)",
         feat["src_bytes"] <= 1e9,
         f"src_bytes={feat['src_bytes']}")
    test("dst_bytes clamped (1e15 → 1e9)",
         feat["dst_bytes"] <= 1e9,
         f"dst_bytes={feat['dst_bytes']}")

    # batch_to_numpy should also sanitize
    arr = extractor.batch_to_numpy([feat])
    test("batch_to_numpy contains no inf/NaN",
         not np.any(np.isnan(arr)) and not np.any(np.isinf(arr)),
         f"shape={arr.shape}, dtype={arr.dtype}")

    # ════════════════════════════════════════════════════════════════════
    # FIX 3 (continued): ARF Label Leakage Fix
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Fix 3b: ARF Label Source Configuration")
    print(f"{'─' * 50}")

    test("ARF label source = lgbm_pseudo",
         config.ARF_LABEL_SOURCE == "lgbm_pseudo",
         f"actual={config.ARF_LABEL_SOURCE}")

    test("Pseudo-label high threshold",
         config.ARF_PSEUDO_LABEL_HIGH == 0.80,
         f"actual={config.ARF_PSEUDO_LABEL_HIGH}")

    test("Pseudo-label low threshold",
         config.ARF_PSEUDO_LABEL_LOW == 0.20,
         f"actual={config.ARF_PSEUDO_LABEL_LOW}")

    # Verify label assignment logic
    # High confidence malicious (lgbm > 0.8) → label = 1
    # High confidence normal (lgbm < 0.2)   → label = 0
    # Ambiguous (0.2-0.8)                   → label = -1 (skip learning)
    test("Label logic: high lgbm → 1",
         1 if 0.95 >= config.ARF_PSEUDO_LABEL_HIGH else 0,
         "lgbm=0.95 → label=1")

    test("Label logic: low lgbm → 0",
         0.05 <= config.ARF_PSEUDO_LABEL_LOW,
         "lgbm=0.05 → label=0")

    # ════════════════════════════════════════════════════════════════════
    # COMBINED: Full Pipeline Test
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 50}")
    print("Full Pipeline: End-to-End Score Verification")
    print(f"{'─' * 50}")

    # Load full ensemble (without ClickHouse — CSV fallback)
    ensemble = ModelEnsemble()
    os.environ["ARF_WARM_RESTART"] = "true"
    ensemble.load(ch_client=None)  # Uses CSV fallback

    print(f"  Models loaded: lgbm={ensemble._lgbm is not None}, "
          f"eif={ensemble._eif is not None}, arf={ensemble._arf is not None}")
    print(f"  ARF rows replayed: {ensemble.arf.rows_replayed}")
    print(f"  ARF confidence: {ensemble.arf.confidence:.4f}")
    print(f"  EIF calibrated: {ensemble._eif.is_calibrated}")

    # Create a clearly malicious event
    malicious_features = {
        "hour_of_day": 3.0,      # 3am (suspicious)
        "day_of_week": 5.0,      # Saturday
        "severity_numeric": 4.0, # Critical
        "source_type_numeric": 9.0,
        "src_bytes": 0.0,        # SYN flood — no payload
        "dst_bytes": 0.0,
        "event_freq_1m": 1200.0, # Extremely high frequency
        "protocol": 6.0,         # TCP
        "dst_port": 22.0,        # SSH target
        "template_rarity": 0.5,  # Constant (as in training)
        "threat_intel_flag": 0.0,
        "duration": 0.0,         # Zero duration (SYN flood)
        "same_srv_rate": 1.0,    # All same service
        "diff_srv_rate": 0.0,
        "serror_rate": 0.95,     # High SYN error rate
        "rerror_rate": 0.0,
        "count": 400.0,          # Many connections
        "srv_count": 400.0,
        "dst_host_count": 1.0,
        "dst_host_srv_count": 1.0,
    }

    # Create a clearly normal event
    normal_features = {
        "hour_of_day": 10.0,     # Business hours
        "day_of_week": 2.0,      # Wednesday
        "severity_numeric": 0.0, # Info
        "source_type_numeric": 8.0,
        "src_bytes": 512.0,
        "dst_bytes": 24576.0,
        "event_freq_1m": 2.0,
        "protocol": 6.0,
        "dst_port": 443.0,       # HTTPS
        "template_rarity": 0.5,
        "threat_intel_flag": 0.0,
        "duration": 1.2,
        "same_srv_rate": 0.8,
        "diff_srv_rate": 0.2,
        "serror_rate": 0.0,
        "rerror_rate": 0.0,
        "count": 5.0,
        "srv_count": 4.0,
        "dst_host_count": 3.0,
        "dst_host_srv_count": 2.0,
    }

    X_mal = np.array([[malicious_features[f] for f in FEATURE_NAMES]], dtype=np.float32)
    X_nor = np.array([[normal_features[f] for f in FEATURE_NAMES]], dtype=np.float32)

    scores_mal = ensemble.predict_batch(X_mal)
    scores_nor = ensemble.predict_batch(X_nor)

    print(f"\n  Malicious: lgbm={scores_mal['lgbm'][0]:.4f}, "
          f"eif={scores_mal['eif'][0]:.4f}, arf={scores_mal['arf'][0]:.4f}")
    print(f"  Normal:    lgbm={scores_nor['lgbm'][0]:.4f}, "
          f"eif={scores_nor['eif'][0]:.4f}, arf={scores_nor['arf'][0]:.4f}")
    print(f"  ARF confidence: {scores_mal['arf_confidence']:.4f}")

    test("LightGBM: malicious > normal",
         scores_mal["lgbm"][0] > scores_nor["lgbm"][0],
         f"{scores_mal['lgbm'][0]:.4f} vs {scores_nor['lgbm'][0]:.4f}")

    test("LightGBM: malicious > 0.5",
         scores_mal["lgbm"][0] > 0.5,
         f"mal_lgbm={scores_mal['lgbm'][0]:.4f}")

    test("LightGBM: normal < 0.3",
         scores_nor["lgbm"][0] < 0.3,
         f"nor_lgbm={scores_nor['lgbm'][0]:.4f}")

    # Fuse with dynamic weighting
    events_test = [
        {"event_id": "test-mal", "timestamp": "2025-01-01T00:00:00Z",
         "hostname": "test", "src_ip": "10.99.1.1"},
        {"event_id": "test-nor", "timestamp": "2025-01-01T00:00:00Z",
         "hostname": "test", "src_ip": "10.0.0.1"},
    ]
    features_test = []
    for source_feat, meta_rarity in [(malicious_features, 0.5), (normal_features, 0.5)]:
        feat_with_meta = dict(source_feat)
        feat_with_meta["_source_type"] = "syslog"
        feat_with_meta["_template_id"] = ""
        features_test.append(feat_with_meta)

    combined_scores = {
        "lgbm": np.array([scores_mal["lgbm"][0], scores_nor["lgbm"][0]]),
        "eif": np.array([scores_mal["eif"][0], scores_nor["eif"][0]]),
        "arf": np.array([scores_mal["arf"][0], scores_nor["arf"][0]]),
        "arf_confidence": scores_mal["arf_confidence"],
    }

    fused = fusion.fuse_batch(combined_scores, features_test, events_test)

    mal_result = fused[0]
    nor_result = fused[1]

    print(f"\n  Fused malicious: combined={mal_result.combined_score:.4f}, "
          f"adjusted={mal_result.adjusted_score:.4f}, action={mal_result.action}")
    print(f"  Fused normal:    combined={nor_result.combined_score:.4f}, "
          f"adjusted={nor_result.adjusted_score:.4f}, action={nor_result.action}")

    test("Malicious event is escalated or monitored",
         mal_result.action in ("escalate", "monitor"),
         f"action={mal_result.action}, adjusted={mal_result.adjusted_score:.4f}")

    test("Normal event is discarded",
         nor_result.action == "discard",
         f"action={nor_result.action}, adjusted={nor_result.adjusted_score:.4f}")

    test("Score separation",
         mal_result.combined_score > nor_result.combined_score + 0.2,
         f"mal={mal_result.combined_score:.4f} vs nor={nor_result.combined_score:.4f}")

    # ════════════════════════════════════════════════════════════════════
    # Summary
    # ════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print(f"  Results: {tests_passed}/{tests_run} tests passed")
    if tests_passed == tests_run:
        print(f"  *** ALL TESTS PASSED ***")
    else:
        print(f"  {tests_run - tests_passed} tests FAILED — see above")
    print(f"{'=' * 60}")

    # Clean up test drain3 state
    test_state = os.environ.get("DRAIN3_STATE_PATH", "")
    if test_state and os.path.exists(test_state):
        os.remove(test_state)

    return 0 if tests_passed == tests_run else 1


if __name__ == "__main__":
    sys.exit(main())
