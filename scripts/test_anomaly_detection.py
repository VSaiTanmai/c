#!/usr/bin/env python3
"""
CLIF Anomaly Detection Test — Novel Attack Patterns
=====================================================
Tests the triage agent's ability to detect NOVEL anomalies that were
NOT in any of the 9 training datasets.

This is the critical test: LightGBM is a supervised classifier that only
catches known patterns. The EIF and ARF models are supposed to catch
anomalies — things that DEVIATE from the learned normal baseline.

TRAINING DATA COVERED:
  - CICIDS2017: DoS, DDoS, PortScan, BruteForce, WebAttack, Infiltration, Botnet
  - NSL-KDD: neptune, smurf, satan, portsweep, nmap, guess_passwd, teardrop, etc.
  - UNSW-NB15: Fuzzers, Backdoors, DoS, Exploits, Reconnaissance, Shellcode, Worms
  - CSIC 2010: SQLi, XSS, path traversal
  - EVTX: Lateral Movement, Execution, PrivEsc, Credential Access, C2
  - Loghub: SSH brute force, auth failures

NOVEL ANOMALIES (NOT in training):
  1. Cryptomining beacon      — periodic small outbound, unusual port 3333
  2. DNS tunneling             — huge DNS packets, extreme query frequency
  3. Slowloris HTTP           — extremely long duration, near-zero byte rate
  4. Data staging (insider)   — bulk transfer at 3AM, unusual byte ratio
  5. Living-off-the-land      — PowerShell/WMI at 2AM, internal traffic
  6. Supply chain C2 beacon   — periodic HTTPS to unknown IP, tiny payloads
  7. Protocol anomaly         — non-HTTP on port 80 (encapsulated traffic)
  8. Encrypted tunnel on 443  — massive bytes but no typical web pattern
  9. RDP brute force          — unusual port 3389, repeated connections
  10. ICMP covert channel     — ICMP with unusually large payloads
  11. Database exfiltration   — huge outbound on port 3306/5432 at night
  12. ARP/VLAN hopping        — protocol 0, unusual byte patterns
  13. Reverse shell           — outbound connection on high port, bidirectional
  14. Credential stuffing API — HTTP POST flood to API endpoint
  15. IoT device compromise   — unusual outbound from device source type

NORMAL BASELINES (must NOT be flagged):
  16. Standard HTTPS browsing
  17. Regular SSH session
  18. Normal email (SMTP)
  19. Internal DNS queries
  20. Business-hours syslog

Usage:
    python scripts/test_anomaly_detection.py
"""

import json
import os
import pickle
import sys
import time
from pathlib import Path

import joblib
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "agents" / "triage" / "models"

FEATURE_COLS = [
    "hour_of_day", "day_of_week", "severity_numeric", "source_type_numeric",
    "src_bytes", "dst_bytes", "event_freq_1m", "protocol", "dst_port",
    "template_rarity", "threat_intel_flag", "duration",
    "same_srv_rate", "diff_srv_rate", "serror_rate", "rerror_rate",
    "count", "srv_count", "dst_host_count", "dst_host_srv_count",
]


# ═════════════════════════════════════════════════════════════════════════
#  NOVEL ANOMALY SCENARIOS (NOT in any of the 9 training datasets)
# ═════════════════════════════════════════════════════════════════════════

ANOMALY_SCENARIOS = {
    # 1. Cryptomining beacon: periodic small outbound to mining pool on port 3333
    # WHY anomalous: unusual port, steady low-rate traffic, long duration
    "cryptomining_beacon": {
        "hour_of_day": 3, "day_of_week": 4, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 500, "dst_bytes": 200,
        "event_freq_1m": 60, "protocol": 6, "dst_port": 3333,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 86400000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 60, "srv_count": 60, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 2. DNS tunneling: massive DNS traffic, absurd packet count
    # WHY anomalous: DNS on port 53 with huge byte volume
    "dns_tunneling": {
        "hour_of_day": 14, "day_of_week": 2, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 500000, "dst_bytes": 2000000,
        "event_freq_1m": 5000, "protocol": 17, "dst_port": 53,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 600000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 5000, "srv_count": 5000, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 3. Slowloris: extremely long HTTP connection, near-zero byte transfer
    # WHY anomalous: duration 10x normal, almost no data — keeps connection alive
    "slowloris_http": {
        "hour_of_day": 11, "day_of_week": 3, "severity_numeric": 0,
        "source_type_numeric": 8, "src_bytes": 50, "dst_bytes": 0,
        "event_freq_1m": 1, "protocol": 6, "dst_port": 80,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 600000000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1, "srv_count": 1, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 4. Insider data staging: 3AM bulk internal transfer
    # WHY anomalous: huge bytes, unusual hour, asymmetric traffic
    "insider_data_staging": {
        "hour_of_day": 3, "day_of_week": 0, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 800000000, "dst_bytes": 5000,
        "event_freq_1m": 5, "protocol": 6, "dst_port": 445,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 3600000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 5, "srv_count": 5, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 5. Living-off-the-land: PowerShell beacon at 2AM, Windows event
    # WHY anomalous: unusual hour for Windows admin activity, EVTX source
    "lotl_powershell": {
        "hour_of_day": 2, "day_of_week": 5, "severity_numeric": 0,
        "source_type_numeric": 2, "src_bytes": 1000, "dst_bytes": 500,
        "event_freq_1m": 30, "protocol": 6, "dst_port": 5985,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 5000,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 30, "srv_count": 30, "dst_host_count": 5, "dst_host_srv_count": 5,
    },

    # 6. Supply chain C2 beacon: tiny periodic HTTPS to single unknown IP
    # WHY anomalous: perfect periodicity, single destination, minimal data
    "supply_chain_c2": {
        "hour_of_day": 10, "day_of_week": 1, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 100, "dst_bytes": 100,
        "event_freq_1m": 1, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 500,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1, "srv_count": 1, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 7. Protocol anomaly: non-HTTP on port 80 (GRE encapsulated)
    # WHY anomalous: GRE protocol (47) on port 80 — tunneling
    "protocol_anomaly_gre_80": {
        "hour_of_day": 15, "day_of_week": 2, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 50000, "dst_bytes": 50000,
        "event_freq_1m": 100, "protocol": 47, "dst_port": 80,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 300000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 100, "srv_count": 100, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 8. Encrypted bulk tunnel on 443: massive data, single destination
    # WHY anomalous: 900MB in one session via HTTPS — way above normal
    "encrypted_bulk_tunnel": {
        "hour_of_day": 22, "day_of_week": 6, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 900000000, "dst_bytes": 10000,
        "event_freq_1m": 10, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 7200000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 10, "srv_count": 10, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 9. RDP brute force on port 3389: many failed connections
    # WHY anomalous: unusual port, high error rate, many connection attempts
    "rdp_brute_force": {
        "hour_of_day": 4, "day_of_week": 0, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 300, "dst_bytes": 100,
        "event_freq_1m": 500, "protocol": 6, "dst_port": 3389,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.85,
        "count": 500, "srv_count": 500, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 10. ICMP covert channel: ICMP with unusually large payloads
    # WHY anomalous: ICMP (proto=1) should have small packets, not 50KB
    "icmp_covert_channel": {
        "hour_of_day": 1, "day_of_week": 4, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 50000, "dst_bytes": 50000,
        "event_freq_1m": 200, "protocol": 1, "dst_port": 0,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 60000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 200, "srv_count": 200, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 11. Database exfiltration at night: huge outbound on DB port
    # WHY anomalous: 500MB outbound on MySQL port at 2AM
    "database_exfil_mysql": {
        "hour_of_day": 2, "day_of_week": 3, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 500000000, "dst_bytes": 2000,
        "event_freq_1m": 5, "protocol": 6, "dst_port": 3306,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 1800000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 5, "srv_count": 5, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 12. Reverse shell: outbound connection on high ephemeral port, bidirectional
    # WHY anomalous: unusual high port, bidirectional with near-equal bytes
    "reverse_shell": {
        "hour_of_day": 23, "day_of_week": 5, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 10000, "dst_bytes": 8000,
        "event_freq_1m": 50, "protocol": 6, "dst_port": 4444,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 600000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 50, "srv_count": 50, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 13. Credential stuffing API: HTTP POST flood to single endpoint
    # WHY anomalous: very high request rate to same endpoint, all src_bytes ~same
    "credential_stuffing_api": {
        "hour_of_day": 16, "day_of_week": 2, "severity_numeric": 0,
        "source_type_numeric": 8, "src_bytes": 500, "dst_bytes": 200,
        "event_freq_1m": 3000, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 100,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 3000, "srv_count": 3000, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # 14. IoT botnet recruitment: compromised IoT device calling out
    # WHY anomalous: IoT source type, outbound to unusual port
    "iot_botnet_recruit": {
        "hour_of_day": 5, "day_of_week": 6, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 2000, "dst_bytes": 50000,
        "event_freq_1m": 20, "protocol": 6, "dst_port": 23,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 30000,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.8,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 20, "srv_count": 1, "dst_host_count": 20, "dst_host_srv_count": 1,
    },

    # 15. Kerberoasting: Windows auth anomaly, many service ticket requests
    # WHY anomalous: EVTX source, unusual auth pattern
    "kerberoasting": {
        "hour_of_day": 1, "day_of_week": 6, "severity_numeric": 0,
        "source_type_numeric": 2, "src_bytes": 0, "dst_bytes": 0,
        "event_freq_1m": 200, "protocol": 6, "dst_port": 88,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 200, "srv_count": 200, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
}


# ═════════════════════════════════════════════════════════════════════════
#  NORMAL BASELINES (must NOT be flagged as anomalous)
# ═════════════════════════════════════════════════════════════════════════

NORMAL_SCENARIOS = {
    # Standard HTTPS web browsing
    "normal_https_browse": {
        "hour_of_day": 10, "day_of_week": 2, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 2000, "dst_bytes": 50000,
        "event_freq_1m": 10, "protocol": 6, "dst_port": 443,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 30000,
        "same_srv_rate": 0.5, "diff_srv_rate": 0.3,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 10, "srv_count": 5, "dst_host_count": 5, "dst_host_srv_count": 3,
    },

    # Regular SSH admin session
    "normal_ssh_session": {
        "hour_of_day": 9, "day_of_week": 1, "severity_numeric": 0,
        "source_type_numeric": 1, "src_bytes": 5000, "dst_bytes": 20000,
        "event_freq_1m": 5, "protocol": 6, "dst_port": 22,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 1800000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 5, "srv_count": 5, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # Normal email (SMTP)
    "normal_smtp_email": {
        "hour_of_day": 11, "day_of_week": 3, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 15000, "dst_bytes": 500,
        "event_freq_1m": 3, "protocol": 6, "dst_port": 587,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 2000,
        "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 3, "srv_count": 3, "dst_host_count": 1, "dst_host_srv_count": 1,
    },

    # Internal DNS queries
    "normal_dns_query": {
        "hour_of_day": 14, "day_of_week": 2, "severity_numeric": 0,
        "source_type_numeric": 9, "src_bytes": 100, "dst_bytes": 500,
        "event_freq_1m": 20, "protocol": 17, "dst_port": 53,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 50,
        "same_srv_rate": 0.5, "diff_srv_rate": 0.3,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 20, "srv_count": 10, "dst_host_count": 2, "dst_host_srv_count": 2,
    },

    # Business-hours syslog info
    "normal_syslog_info": {
        "hour_of_day": 14, "day_of_week": 3, "severity_numeric": 0,
        "source_type_numeric": 1, "src_bytes": 0, "dst_bytes": 0,
        "event_freq_1m": 5, "protocol": 0, "dst_port": 0,
        "template_rarity": 0.5, "threat_intel_flag": 0, "duration": 0,
        "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "serror_rate": 0.0, "rerror_rate": 0.0,
        "count": 1, "srv_count": 1, "dst_host_count": 1, "dst_host_srv_count": 1,
    },
}


def build_feature_vec(scenario: dict) -> np.ndarray:
    return np.array([scenario[c] for c in FEATURE_COLS], dtype=np.float32)


def main():
    print("=" * 78)
    print("  CLIF ANOMALY DETECTION TEST — NOVEL ATTACK PATTERNS")
    print("  Testing EIF + ARF + LightGBM + Combined Ensemble")
    print("=" * 78)
    print()

    # ─── Load models ────────────────────────────────────────────────────
    import onnxruntime as ort

    manifest = json.load(open(MODEL_DIR / "manifest.json"))
    susp_thresh = manifest["thresholds"]["suspicious"]
    anom_thresh = manifest["thresholds"]["anomalous"]
    print(f"Thresholds: suspicious={susp_thresh}, anomalous={anom_thresh}")

    # LightGBM
    sess = ort.InferenceSession(str(MODEL_DIR / "lgbm_v2.0.0.onnx"),
                                providers=["CPUExecutionProvider"])
    inp_name = sess.get_inputs()[0].name

    # EIF
    eif = joblib.load(str(MODEL_DIR / "eif_v2.0.0.pkl"))
    cal = np.load(str(MODEL_DIR / "eif_calibration.npz"))
    cal_mean, cal_std = float(cal["path_mean"]), float(cal["path_std"])
    score_flip = bool(int(cal.get("score_flip", 0)))
    print(f"EIF: cal_mean={cal_mean:.6f}, cal_std={cal_std:.6f}, flip={score_flip}")

    # ARF
    with open(MODEL_DIR / "arf_v2.0.0.pkl", "rb") as f:
        arf = pickle.load(f)

    print()

    # ─── Helper functions ───────────────────────────────────────────────
    def score_lgbm(X):
        out = sess.run(None, {inp_name: X})
        return np.array([d.get(1, d.get("1", 0.0)) for d in out[1]], dtype=np.float64)

    def score_eif(X):
        X64 = X.astype(np.float64)
        raw = eif.compute_paths(X_in=X64)
        z = (raw - cal_mean) / max(cal_std, 1e-10)
        s = 1.0 / (1.0 + np.exp(z))
        if score_flip:
            s = 1.0 - s
        return s

    def score_arf(X):
        scores = []
        for i in range(X.shape[0]):
            x_dict = {FEATURE_COLS[j]: float(X[i, j]) for j in range(len(FEATURE_COLS))}
            p = arf.predict_proba_one(x_dict).get(1, 0.5)
            scores.append(p)
        return np.array(scores, dtype=np.float64)

    def combined_cold(lgbm_s, eif_s):
        """Cold-start combined (ARF conf=0): LGBM=0.80, EIF=0.20"""
        return 0.80 * lgbm_s + 0.20 * eif_s

    def combined_full(lgbm_s, eif_s, arf_s):
        """Full ensemble: LGBM=0.60, EIF=0.15, ARF=0.25"""
        return 0.60 * lgbm_s + 0.15 * eif_s + 0.25 * arf_s

    # EIF anomaly override parameters (from config.py)
    EIF_OVERRIDE_THRESH = 0.65
    EIF_OVERRIDE_FLOOR = 0.45

    def apply_eif_override(combined_score, eif_score):
        """If EIF fires strongly, enforce a score floor."""
        if eif_score >= EIF_OVERRIDE_THRESH and combined_score < EIF_OVERRIDE_FLOOR:
            return EIF_OVERRIDE_FLOOR
        return combined_score

    def route(score):
        if score >= anom_thresh:
            return "ESCALATE"
        elif score >= susp_thresh:
            return "MONITOR "
        else:
            return "DISCARD "

    # ─── Run ALL anomaly scenarios ──────────────────────────────────────
    print("=" * 78)
    print("  SECTION 1: NOVEL ANOMALY SCENARIOS (should be detected)")
    print("=" * 78)
    header = f"  {'Scenario':<30s} {'LGBM':>6s} {'EIF':>6s} {'ARF':>6s} {'Cold':>6s} {'Adj':>6s}  {'Route':>12s} {'Override':>8s} {'Result':>8s}"
    sep = "  " + "-" * (len(header) - 2)
    print(header)
    print(sep)

    anom_passed = 0
    anom_failed = 0
    anom_details = []

    for name, scenario in ANOMALY_SCENARIOS.items():
        X = build_feature_vec(scenario).reshape(1, -1)
        lg = score_lgbm(X)[0]
        ei = score_eif(X)[0]
        ar = score_arf(X)[0]
        cc = combined_cold(lg, ei)

        # Apply EIF anomaly override (production behavior)
        adj = apply_eif_override(cc, ei)

        route_adj = route(adj)
        override_flag = "YES" if adj != cc else "  -"

        # Detection: adjusted score >= suspicious threshold (production routing)
        detected = adj >= susp_thresh

        status = "PASS" if detected else "**MISS**"
        if detected:
            anom_passed += 1
        else:
            anom_failed += 1

        anom_details.append((name, lg, ei, ar, cc, adj, detected, override_flag))
        print(f"  {name:<30s} {lg:6.3f} {ei:6.3f} {ar:6.3f} {cc:6.3f} {adj:6.3f}  {route_adj:>12s} {override_flag:>8s} [{status:>6s}]")

    print(sep)
    print(f"  ANOMALY DETECTION: {anom_passed}/{anom_passed + anom_failed} detected "
          f"({100*anom_passed/(anom_passed+anom_failed):.1f}%)")
    print()

    # ─── Run ALL normal scenarios ───────────────────────────────────────
    print("=" * 78)
    print("  SECTION 2: NORMAL BASELINES (should NOT be flagged)")
    print("=" * 78)
    print(header)
    print(sep)

    norm_passed = 0
    norm_failed = 0

    for name, scenario in NORMAL_SCENARIOS.items():
        X = build_feature_vec(scenario).reshape(1, -1)
        lg = score_lgbm(X)[0]
        ei = score_eif(X)[0]
        ar = score_arf(X)[0]
        cc = combined_cold(lg, ei)
        adj = apply_eif_override(cc, ei)

        route_adj = route(adj)
        override_flag = "YES" if adj != cc else "  -"

        # Normal is CORRECT if adjusted score < anomalous threshold
        # (being suspicious is acceptable — SOC investigates — but escalate is bad)
        correct = adj < anom_thresh
        status = "PASS" if correct else "**FP**"
        if correct:
            norm_passed += 1
        else:
            norm_failed += 1

        print(f"  {name:<30s} {lg:6.3f} {ei:6.3f} {ar:6.3f} {cc:6.3f} {adj:6.3f}  {route_adj:>12s} {override_flag:>8s} [{status:>6s}]")

    print(sep)
    print(f"  FALSE POSITIVE CHECK: {norm_passed}/{norm_passed + norm_failed} correct "
          f"({100*norm_passed/(norm_passed+norm_failed):.1f}%)")
    print()

    # ─── Per-model analysis ─────────────────────────────────────────────
    print("=" * 78)
    print("  SECTION 3: PER-MODEL ANOMALY DETECTION BREAKDOWN")
    print("=" * 78)

    anom_names = list(ANOMALY_SCENARIOS.keys())
    lgbm_catches = sum(1 for _, lg, _, _, _, _, _, _ in anom_details if lg >= 0.50)
    eif_catches = sum(1 for _, _, ei, _, _, _, _, _ in anom_details if ei >= 0.55)
    arf_catches = sum(1 for _, _, _, ar, _, _, _, _ in anom_details if ar >= 0.55)
    combined_catches = sum(1 for _, _, _, _, cc, _, _, _ in anom_details if cc >= susp_thresh)
    adjusted_catches = sum(1 for _, _, _, _, _, adj, _, _ in anom_details if adj >= susp_thresh)

    total = len(anom_details)
    print(f"  LightGBM alone (>= 0.50):          {lgbm_catches:2d}/{total} ({100*lgbm_catches/total:.0f}%)")
    print(f"  EIF alone (>= 0.55):                {eif_catches:2d}/{total} ({100*eif_catches/total:.0f}%)")
    print(f"  ARF alone (>= 0.55):                {arf_catches:2d}/{total} ({100*arf_catches/total:.0f}%)")
    print(f"  Raw combined (>= {susp_thresh}):          {combined_catches:2d}/{total} ({100*combined_catches/total:.0f}%)")
    print(f"  With EIF override (>= {susp_thresh}):     {adjusted_catches:2d}/{total} ({100*adjusted_catches/total:.0f}%)  <-- PRODUCTION")
    print(f"  Detection improvement:             +{adjusted_catches - combined_catches} scenarios saved by EIF override")
    print()

    # ─── Which anomalies were MISSED and why ────────────────────────────
    missed = [(n, lg, ei, ar, cc, adj) for n, lg, ei, ar, cc, adj, det, _ in anom_details if not det]
    if missed:
        print("=" * 78)
        print("  SECTION 4: MISSED ANOMALIES — ROOT CAUSE")
        print("=" * 78)
        for name, lg, ei, ar, cc, cf in missed:
            print(f"  {name}:")
            print(f"    LGBM={lg:.3f} (<0.50)  EIF={ei:.3f} (<0.55)  ARF={ar:.3f}")
            print(f"    Cold={cc:.3f} (<{susp_thresh})  Full={cf:.3f}")
            print(f"    WHY: This pattern's features fall within the 'normal' envelope")
            print(f"           learned during training. The anomaly is too subtle for")
            print(f"           the current feature space to distinguish.")
            print()

    # ─── OVERALL VERDICT ────────────────────────────────────────────────
    total_tests = (anom_passed + anom_failed + norm_passed + norm_failed)
    total_pass = anom_passed + norm_passed
    print("=" * 78)
    print(f"  OVERALL: {total_pass}/{total_tests} tests passed")
    print(f"  Anomaly detection rate:  {100*anom_passed/(anom_passed+anom_failed):.1f}%  ({anom_passed}/{anom_passed+anom_failed})")
    print(f"  False positive control:  {100*norm_passed/(norm_passed+norm_failed):.1f}%  ({norm_passed}/{norm_passed+norm_failed})")
    print("=" * 78)

    return 0 if (anom_failed == 0 and norm_failed == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
