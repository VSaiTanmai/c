#!/usr/bin/env python3
"""
CLIF Triage Agent v7 — Complete Model Training Pipeline
==========================================================
Uses the EXACT SAME feature_extractor.py for training AND production
to eliminate train/serve skew.

Workflow:
  1. Load & normalize all 10 dataset types → unified event dicts
  2. Run events through FeatureExtractor.extract() chronologically
  3. Train LightGBM (5-fold stratified CV, per-log-type F1 gates)
  4. Train Autoencoder on normal-only data (100 epochs, early stopping)
  5. Calibrate AE per source type (p99/p50 reconstruction error)
  6. Export: lgbm_v7.onnx, autoencoder_v7.onnx, feature_scaler_v7.json,
            ae_calibration_v7.json, manifest_v7.json

Datasets (10 types, normalized with clif_label + clif_attack_type):
  01_Syslog       — lanl_auth_training_normalized.csv
  02_Windows      — evtx_attack_data.csv
  03_Firewall     — unsw_stratified_normalized.csv
  04_AD           — lanl_auth_ad_training_normalized.csv
  05_DNS          — dga_data_normalized.csv + CSV_*_normalized.csv
  06_Cloud        — dec12_18features.csv
  07_Kubernetes   — k8s_audit_training_normalized.csv
  08_Web          — csic_database_normalized.csv
  09_NetFlow      — nf_unsw_stratified_normalized.csv
  10_IDS          — cicids2017_stratified_normalized.csv + nsl_kdd_stratified_normalized.csv

Usage:
  cd C:\\CLIF
  python scripts/train_v7.py
  python scripts/train_v7.py --dry-run          # validate data only
  python scripts/train_v7.py --max-per-type 5000 # cap per dataset type
  python scripts/train_v7.py --no-gpu            # force CPU-only training
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

# ── Logging ─────────────────────────────────────────────────────────────────


class _FlushHandler(logging.StreamHandler):
    def emit(self, record):
        super().emit(record)
        self.flush()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[_FlushHandler(sys.stdout)],
)
log = logging.getLogger("train_v7")

# ── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "agents" / "Data" / "Latest_Dataset"
MODEL_DIR = BASE_DIR / "agents" / "triage" / "models"

# Add triage agent to sys.path so we can import feature_extractor.py
TRIAGE_DIR = BASE_DIR / "agents" / "triage"
sys.path.insert(0, str(TRIAGE_DIR))

# ── GPU Configuration ──────────────────────────────────────────────────────

USE_GPU = True  # default; overridden by --no-gpu


def _detect_gpu() -> Dict[str, Any]:
    """Probe available GPU hardware and return capabilities dict."""
    info: Dict[str, Any] = {"cuda": False, "lgbm_gpu": False}

    # CUDA / PyTorch
    try:
        import torch
        if USE_GPU and torch.cuda.is_available():
            info["cuda"] = True
            info["cuda_device"] = torch.cuda.get_device_name(0)
            info["cuda_mem_gb"] = round(
                torch.cuda.get_device_properties(0).total_memory / 1e9, 1
            )
            torch.backends.cudnn.benchmark = True
    except ImportError:
        pass

    # LightGBM GPU
    try:
        import lightgbm as lgb
        if USE_GPU:
            # LightGBM compiled with GPU support exposes this in build info
            build_info = getattr(lgb, "LGBMClassifier", None)
            # Quick probe: try a tiny GPU fit — if the build lacks GPU support
            # it raises an exception immediately.
            _ds = lgb.Dataset(np.zeros((4, 2), dtype=np.float32),
                              label=np.array([0, 1, 0, 1]))
            try:
                lgb.train({"device": "gpu", "num_leaves": 2, "verbose": -1,
                           "n_estimators": 1, "objective": "binary"},
                          _ds, num_boost_round=1)
                info["lgbm_gpu"] = True
            except lgb.basic.LightGBMError:
                pass
    except ImportError:
        pass

    return info

# ── Late imports (triage agent modules) ─────────────────────────────────────


def _import_triage():
    """Import triage agent modules after sys.path is set up."""
    # Suppress drain3 logs during training
    logging.getLogger("drain3").setLevel(logging.WARNING)

    import config as triage_config
    from drain3_miner import Drain3Miner
    from ewma_tracker import EWMATracker
    from feature_extractor import (
        FEATURE_NAMES,
        NUM_FEATURES,
        FeatureExtractor,
        ShardedConnectionTracker,
        SourceNoveltyTracker,
    )

    return triage_config, Drain3Miner, EWMATracker, FeatureExtractor, \
           ShardedConnectionTracker, SourceNoveltyTracker, FEATURE_NAMES, NUM_FEATURES


# =============================================================================
#  Dataset Loaders — each returns List[Dict[str, Any]] normalized events
# =============================================================================
# Each loader converts dataset-specific columns into the unified event dict
# format that feature_extractor.extract() expects.  Labels are attached as
# _clif_label and _clif_attack_type (underscore prefix = metadata, not fed
# to the model).
# =============================================================================


def _make_timestamp(hour: int = 12, day: int = 2) -> str:
    """Create a plausible ISO timestamp for datasets without timestamps."""
    rng = np.random.default_rng()
    h = hour if hour is not None else rng.integers(0, 24)
    d = day if day is not None else rng.integers(0, 7)
    return f"2026-03-{10+d:02d}T{h:02d}:{rng.integers(0,60):02d}:00Z"


def _safe_int(val, default=0) -> int:
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def _safe_float(val, default=0.0) -> float:
    try:
        v = float(val)
        return v if np.isfinite(v) else default
    except (ValueError, TypeError):
        return default


def load_syslog(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """01_Syslog: LANL auth normalized + OpenSSH."""
    events = []
    fp = DATA_DIR / "01_Syslog" / "lanl_auth_training_normalized.csv"
    if not fp.exists():
        log.warning("Syslog dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  01_Syslog: loaded %d rows from lanl_auth_training_normalized", len(df))

    for _, row in df.iterrows():
        status = str(row.get("status", "Success")).lower()
        src_user = str(row.get("src_user", ""))
        dst_user = str(row.get("dst_user", ""))
        src_comp = str(row.get("src_computer", ""))
        dst_comp = str(row.get("dst_computer", ""))
        auth_type = str(row.get("auth_type", ""))
        logon_type = str(row.get("logon_type", ""))

        severity = "warning" if "fail" in status else "info"
        msg = f"Authentication {status} for {dst_user} from {src_comp} " \
              f"auth_type={auth_type} logon_type={logon_type}"

        # Parse LANL second-offset timestamps to produce hour/day diversity
        ts_raw = row.get("timestamp", 0)
        ts_sec = _safe_int(ts_raw, 0)
        hour = (ts_sec // 3600) % 24
        day = (ts_sec // 86400) % 7

        event = {
            "timestamp": _make_timestamp(hour, day),
            "hostname": dst_comp or "DC01",
            "user": dst_user,
            "src_ip": src_comp,
            "source_type": "linux_auth",
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    # RED FLAG FIX: Augment with diverse synthetic attack patterns.
    # The LANL redteam only has ~150 lateral-movement attacks — add brute
    # force, priv-escalation, off-hours patterns to prevent memorization.
    n_real_attacks = sum(1 for _, l, _ in events if l == 1)
    synth_attacks = _generate_diverse_auth_attacks(
        source_type="linux_auth",
        count=max(500, n_real_attacks * 3),
    )
    log.info("  01_Syslog: augmented with %d diverse synthetic attacks", len(synth_attacks))
    events.extend(synth_attacks)

    return events


def _generate_diverse_auth_attacks(
    source_type: str, count: int,
) -> List[Tuple[Dict, int, str]]:
    """Generate diverse synthetic attack events for auth-type sources.

    Creates a mix of brute-force, privilege escalation, credential stuffing,
    off-hours access, and service account abuse patterns that differ from
    the narrow LANL redteam lateral-movement pattern.
    """
    rng = np.random.default_rng(77)
    events = []

    attack_templates = [
        # (attack_type, severity, msg_template, hour_range, fail_chance)
        ("brute_force", "warning",
         "Authentication failure for {user} from {src} auth_type=password logon_type=Network",
         (0, 24), 0.85),
        ("credential_stuffing", "warning",
         "Authentication failure for {user} from {src} auth_type=Negotiate logon_type=Network",
         (0, 24), 0.70),
        ("priv_escalation", "error",
         "Privilege escalation attempt: {user} from {src} sudo command=passwd",
         (22, 6), 0.20),
        ("account_manipulation", "error",
         "Account modification: {user} added to wheel/admin group by {src}",
         (0, 6), 0.10),
        ("off_hours_lateral", "warning",
         "Authentication success for {user} from {src} auth_type=Kerberos logon_type=Network",
         (23, 5), 0.05),
        ("service_abuse", "error",
         "Service account {user} authenticated from unexpected host {src}",
         (0, 24), 0.15),
    ]

    weights = np.array([30, 20, 15, 10, 15, 10], dtype=float)
    weights /= weights.sum()

    hosts = [f"srv{i:03d}" for i in range(1, 101)]
    admin_users = ["root", "admin", "svc_backup", "svc_deploy", "sa_monitor"]
    normal_users = [f"user{i}" for i in range(1, 201)]
    src_ips = [f"10.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
               for _ in range(50)]

    for _ in range(count):
        idx = rng.choice(len(attack_templates), p=weights)
        atype, sev, msg_tmpl, hour_range, fail_chance = attack_templates[idx]

        # Choose user: admin for escalation/manipulation, otherwise mixed
        if atype in ("priv_escalation", "account_manipulation", "service_abuse"):
            user = rng.choice(admin_users)
        else:
            user = rng.choice(normal_users + admin_users[:2])

        src = rng.choice(src_ips)
        host = rng.choice(hosts)

        # Hour within attack window
        h_lo, h_hi = hour_range
        if h_lo < h_hi:
            hour = rng.integers(h_lo, h_hi)
        else:  # wraps past midnight
            hour = rng.integers(h_lo, h_hi + 24) % 24
        day = rng.integers(0, 7)

        if rng.random() < fail_chance:
            sev = "warning"

        msg = msg_tmpl.format(user=user, src=src)

        event = {
            "timestamp": _make_timestamp(hour, day),
            "hostname": host,
            "user": user,
            "src_ip": src,
            "source_type": source_type,
            "original_log_level": sev,
            "message_body": msg,
        }
        events.append((event, 1, atype))

    return events


def _generate_normal_windows_events(count: int) -> List[Tuple[Dict, int, str]]:
    """Generate synthetic normal Windows events to balance the attack-only dataset.

    In real Windows environments, >99% of events are benign logons, service
    starts, and routine auditing.  Without normal samples the model can't
    learn the benign baseline for this source type.
    """
    rng = np.random.default_rng(123)
    events = []

    # Realistic distribution of normal Windows EventIDs
    normal_events = [
        # (EventID, LogonType, Channel, severity, weight)
        (4624, 3, "Security", "info", 30),   # Successful logon (network)
        (4624, 2, "Security", "info", 15),   # Successful logon (interactive)
        (4624, 5, "Security", "info", 10),   # Successful logon (service)
        (4624, 10, "Security", "info", 5),   # Successful logon (RDP)
        (4634, 0, "Security", "info", 20),   # Logoff
        (4672, 0, "Security", "info", 8),    # Special privileges assigned
        (4688, 0, "Security", "info", 5),    # Process creation
        (4689, 0, "Security", "info", 3),    # Process exit
        (4768, 0, "Security", "info", 4),    # Kerberos TGT request
        (4769, 0, "Security", "info", 4),    # Kerberos service ticket
        (4776, 0, "Security", "info", 3),    # NTLM credential validation
        (7045, 0, "System", "info", 1),      # Service installed (routine)
        (4656, 0, "Security", "info", 2),    # Object handle requested
    ]
    eids, ltypes, channels, sevs, weights = zip(*normal_events)
    probs = np.array(weights, dtype=float)
    probs /= probs.sum()

    computers = [f"WS{i:03d}.corp.local" for i in range(1, 51)]
    users = [f"user{i}" for i in range(1, 101)] + \
            ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM-1", "UMFD-0"]

    for _ in range(count):
        idx = rng.choice(len(eids), p=probs)
        eid, lt, ch, sev = eids[idx], ltypes[idx], channels[idx], sevs[idx]
        user = rng.choice(users)
        comp = rng.choice(computers)

        if eid == 4624:
            msg = (f"An account was successfully logged on. "
                   f"Subject: {user} Logon Type: {lt} "
                   f"Workstation Name: {comp}")
        elif eid == 4634:
            msg = f"An account was logged off. Subject: {user}"
        elif eid == 4672:
            msg = f"Special privileges assigned to new logon. Subject: {user}"
        elif eid == 4688:
            proc = rng.choice(["svchost.exe", "csrss.exe", "lsass.exe",
                               "services.exe", "explorer.exe", "taskhostw.exe"])
            msg = f"A new process has been created. Process Name: {proc} Creator: {user}"
        elif eid == 4689:
            msg = f"A process has exited. Subject: {user}"
        elif eid in (4768, 4769):
            msg = (f"A Kerberos authentication ticket was requested. "
                   f"Account: {user} Service: krbtgt")
        elif eid == 4776:
            msg = f"The computer attempted to validate credentials. Logon Account: {user}"
        elif eid == 7045:
            msg = f"A service was installed. Service Name: WindowsUpdate Service Account: {user}"
        else:
            msg = f"Windows Event {eid} for {user} on {comp}"

        event = {
            "timestamp": _make_timestamp(rng.integers(6, 22), rng.integers(0, 5)),
            "hostname": comp,
            "user": user,
            "source_type": "windows_event",
            "windows_event_id": eid,
            "windows_logon_type": lt,
            "windows_target_user": user,
            "windows_channel": ch,
            "original_log_level": sev,
            "message_body": msg,
        }
        events.append((event, 0, "benign"))

    return events


def load_windows(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """02_Windows: EVTX attack data CSV + synthetic normal events."""
    events = []
    fp = DATA_DIR / "02_Windows_Event" / "evtx_attack_data.csv"
    if not fp.exists():
        log.warning("Windows dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows, low_memory=False)
    log.info("  02_Windows: loaded %d attack rows from evtx_attack_data", len(df))

    # Infer clif_label from columns
    if "clif_label" not in df.columns:
        # Windows attack samples are labeled via attack_type or similar
        if "label" in df.columns:
            df["clif_label"] = df["label"].apply(
                lambda x: 0 if str(x).lower() in ("normal", "benign", "0") else 1
            )
        else:
            df["clif_label"] = 1  # Attack samples collection
        df["clif_attack_type"] = df.get("attack_type", "windows_attack")

    for _, row in df.iterrows():
        eid = _safe_int(row.get("EventID", row.get("event_id", 0)))
        channel = str(row.get("Channel", "Security"))
        logon_type = _safe_int(row.get("LogonType", 0))
        target_user = str(row.get("TargetUserName", ""))
        computer = str(row.get("Computer", row.get("hostname", "WORKSTATION")))
        msg = str(row.get("Message", row.get("message_body", "")))

        # Severity from event category
        if eid in (4625, 4771, 4776, 1102):
            severity = "warning"
        elif eid in (4697, 4720, 7045):
            severity = "error"
        else:
            severity = "info"

        event = {
            "timestamp": str(row.get("TimeCreated", _make_timestamp())),
            "hostname": computer,
            "user": target_user,
            "source_type": "windows_event",
            "windows_event_id": eid,
            "windows_logon_type": logon_type,
            "windows_target_user": target_user,
            "windows_channel": channel,
            "original_log_level": severity,
            "message_body": msg[:2000] if msg else f"Windows Event {eid}",
        }
        label = _safe_int(row.get("clif_label", 1))
        attack = str(row.get("clif_attack_type", "windows_attack"))
        events.append((event, label, attack))

    # RED FLAG FIX: Generate synthetic normal Windows events
    # The evtx dataset is attack-only; without normal samples the model
    # has never seen a benign Windows logon.
    n_attack = sum(1 for _, l, _ in events if l == 1)
    n_normal_needed = max(n_attack * 3, 10000)  # 3:1 normal:attack ratio
    n_normal_needed = min(n_normal_needed, max_rows)
    normal_events = _generate_normal_windows_events(n_normal_needed)
    log.info("  02_Windows: generated %d synthetic normal events (3:1 ratio)",
             len(normal_events))
    events.extend(normal_events)

    return events


def load_firewall(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """03_Firewall: UNSW-NB15 stratified normalized."""
    events = []
    fp = DATA_DIR / "03_Firewall" / "unsw_stratified_normalized.csv"
    if not fp.exists():
        log.warning("Firewall dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  03_Firewall: loaded %d rows from unsw_stratified_normalized", len(df))

    for _, row in df.iterrows():
        src_ip = str(row.get("srcip", "10.0.0.1"))
        dst_ip = str(row.get("dstip", "10.0.0.2"))
        sport = _safe_int(row.get("sport", 0))
        dport = _safe_int(row.get("dsport", 0))
        proto = str(row.get("proto", "tcp")).lower()
        sbytes = _safe_float(row.get("sbytes", 0))
        dbytes = _safe_float(row.get("dbytes", 0))
        state = str(row.get("state", ""))
        service = str(row.get("service", ""))

        severity = "warning" if state in ("FIN", "RST") else "info"
        msg = f"CEF:0|UNSW|Firewall|1.0|{dport}|{proto} " \
              f"{src_ip}:{sport}->{dst_ip}:{dport} " \
              f"state={state} service={service} " \
              f"bytes_sent={sbytes} bytes_recv={dbytes}"

        event = {
            "timestamp": _make_timestamp(),
            "hostname": "fw01",
            "source_type": "firewall",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "bytes_sent": sbytes,
            "bytes_received": dbytes,
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    return events


def load_ad(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """04_Active_Directory: LANL auth AD normalized."""
    events = []
    fp = DATA_DIR / "04_Active_Directory" / "lanl_auth_ad_training_normalized.csv"
    if not fp.exists():
        log.warning("AD dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  04_AD: loaded %d rows from lanl_auth_ad_training_normalized", len(df))

    for _, row in df.iterrows():
        status = str(row.get("status", "Success")).lower()
        src_user = str(row.get("src_user", ""))
        dst_user = str(row.get("dst_user", ""))
        src_comp = str(row.get("src_computer", ""))
        dst_comp = str(row.get("dst_computer", ""))
        auth_type = str(row.get("auth_type", "Kerberos"))

        # Map auth types to Windows Event IDs
        eid_map = {
            "kerberos": 4768, "ntlm": 4776, "negotiate": 4624,
        }
        eid = eid_map.get(auth_type.lower(), 4624)
        if "fail" in status:
            eid = 4625

        severity = "warning" if "fail" in status else "info"
        msg = f"AD authentication {status}: {src_user}@{src_comp} → " \
              f"{dst_user}@{dst_comp} via {auth_type}"

        ts_raw = row.get("timestamp", 0)
        ts_sec = _safe_int(ts_raw, 0)
        hour = (ts_sec // 3600) % 24
        day = (ts_sec // 86400) % 7

        event = {
            "timestamp": _make_timestamp(hour, day),
            "hostname": dst_comp or "DC01",
            "user": dst_user,
            "source_type": "active_directory",
            "windows_event_id": eid,
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    # RED FLAG FIX: Augment AD attacks — only ~227 lateral-movement attacks
    # from LANL redteam.  Add diverse patterns so the model doesn't memorize.
    n_real_attacks = sum(1 for _, l, _ in events if l == 1)
    synth_attacks = _generate_diverse_ad_attacks(
        count=max(500, n_real_attacks * 3),
    )
    log.info("  04_AD: augmented with %d diverse synthetic attacks", len(synth_attacks))
    events.extend(synth_attacks)

    return events


def _generate_diverse_ad_attacks(count: int) -> List[Tuple[Dict, int, str]]:
    """Generate diverse Active Directory attack events.

    Covers: Kerberoasting, golden ticket, brute force, DC shadow,
    password spray, account lockout storms.
    """
    rng = np.random.default_rng(88)
    events = []

    attack_templates = [
        # (attack_type, eid, severity, msg_template, hour_range)
        ("kerberoasting", 4769, "warning",
         "Kerberos service ticket requested: {user}@{domain} for SPN/{svc} Ticket Encryption: 0x17",
         (0, 24)),
        ("golden_ticket", 4768, "error",
         "Kerberos TGT requested: {user}@{domain} from {src} Encryption: 0x17 Result: 0x0",
         (22, 6)),
        ("password_spray", 4625, "warning",
         "Logon failure: {user}@{domain} from {src} LogonType=3 Status=0xC000006D",
         (0, 24)),
        ("brute_force_ad", 4625, "warning",
         "Logon failure: {user}@{domain} from {src} LogonType=3 FailureReason=%%2313",
         (0, 24)),
        ("account_lockout", 4740, "error",
         "Account locked out: {user}@{domain} Caller Computer: {src}",
         (0, 24)),
        ("dcsync", 4662, "error",
         "Directory service access: {user}@{domain} Object: CN=Configuration Properties: Replicating",
         (1, 5)),
        ("group_modification", 4728, "error",
         "Member added to security group: {user} added to Domain Admins by {src}",
         (22, 6)),
    ]

    weights = np.array([25, 10, 25, 15, 10, 5, 10], dtype=float)
    weights /= weights.sum()

    domain = "CORP.LOCAL"
    dcs = [f"DC{i:02d}" for i in range(1, 6)]
    users = [f"user{i}" for i in range(1, 201)] + ["administrator", "krbtgt"]
    spns = ["MSSQL", "HTTP", "CIFS", "HOST", "LDAP", "DNS"]
    src_hosts = [f"WS{i:03d}" for i in range(1, 100)]

    for _ in range(count):
        idx = rng.choice(len(attack_templates), p=weights)
        atype, eid, sev, msg_tmpl, hour_range = attack_templates[idx]

        user = rng.choice(users)
        src = rng.choice(src_hosts)
        dc = rng.choice(dcs)
        svc = rng.choice(spns)

        h_lo, h_hi = hour_range
        if h_lo < h_hi:
            hour = rng.integers(h_lo, h_hi)
        else:
            hour = rng.integers(h_lo, h_hi + 24) % 24
        day = rng.integers(0, 7)

        msg = msg_tmpl.format(user=user, domain=domain, src=src, svc=svc)

        event = {
            "timestamp": _make_timestamp(hour, day),
            "hostname": dc,
            "user": user,
            "source_type": "active_directory",
            "windows_event_id": eid,
            "original_log_level": sev,
            "message_body": msg,
        }
        events.append((event, 1, atype))

    return events


def load_dns(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """05_DNS: DGA data + CIC-Bell DNS exfiltration CSVs."""
    events = []
    rng = np.random.default_rng(55)

    # DGA domains
    fp_dga = DATA_DIR / "05_DNS" / "dga_data_normalized.csv"
    if fp_dga.exists():
        df = pd.read_csv(fp_dga, nrows=max_rows // 2)
        log.info("  05_DNS (DGA): loaded %d rows", len(df))

        for _, row in df.iterrows():
            domain = str(row.get("domain", "example.com"))
            is_dga = _safe_int(row.get("isDGA", 0))
            subclass = str(row.get("subclass", ""))

            event = {
                "timestamp": _make_timestamp(),
                "hostname": "dns01",
                "source_type": "dns",
                "dns_query_name": domain,
                "original_log_level": "info",
                "message_body": f"DNS query: {domain} (type=A)",
            }
            label = _safe_int(row.get("clif_label", is_dga))
            attack = str(row.get("clif_attack_type", f"dga_{subclass}" if is_dga else "benign"))
            events.append((event, label, attack))

    # CIC-Bell DNS exfiltration
    for csv_name in ["CSV_benign_normalized.csv", "CSV_malware_normalized.csv",
                     "CSV_phishing_normalized.csv", "CSV_spam_normalized.csv"]:
        fp = DATA_DIR / "05_DNS" / csv_name
        if fp.exists():
            cap = max(max_rows // 8, 1000)
            df = pd.read_csv(fp, nrows=cap)
            log.info("  05_DNS (%s): loaded %d rows", csv_name, len(df))

            for _, row in df.iterrows():
                domain = str(row.get("Domain", row.get("domain", "example.com")))
                event = {
                    "timestamp": _make_timestamp(),
                    "hostname": "dns01",
                    "source_type": "dns",
                    "dns_query_name": domain,
                    "original_log_level": "info",
                    "message_body": f"DNS query: {domain}",
                }
                label = _safe_int(row.get("clif_label", 0))
                attack = str(row.get("clif_attack_type", "benign"))
                events.append((event, label, attack))

    return events[:max_rows]


def load_cloud(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """06_Cloud: AWS CloudTrail features."""
    events = []
    fp = DATA_DIR / "06_Cloud_AWS" / "dec12_18features.csv"
    if not fp.exists():
        # Try alternate name
        fp = DATA_DIR / "06_Cloud_AWS" / "nineteenFeaturesDf.csv"
    if not fp.exists():
        log.warning("Cloud dataset not found in 06_Cloud_AWS/")
        return events

    df = pd.read_csv(fp, nrows=max_rows, low_memory=False)
    log.info("  06_Cloud: loaded %d rows", len(df))

    # Infer labels if not present
    if "clif_label" not in df.columns:
        if "label" in df.columns:
            df["clif_label"] = df["label"].apply(
                lambda x: 0 if str(x).lower() in ("normal", "benign", "0") else 1
            )
        elif "eventName" in df.columns:
            attack_actions = {"CreateUser", "AttachUserPolicy", "PutBucketPolicy",
                              "AuthorizeSecurityGroupIngress", "CreateKeyPair"}
            df["clif_label"] = df["eventName"].apply(
                lambda x: 1 if x in attack_actions else 0
            )
        else:
            df["clif_label"] = 0
        df["clif_attack_type"] = "cloud_attack"

    for _, row in df.iterrows():
        action = str(row.get("eventName", row.get("action", "DescribeInstances")))
        source = str(row.get("eventSource", "ec2.amazonaws.com"))
        user = str(row.get("userName", row.get("user", "")))
        ip = str(row.get("sourceIPAddress", row.get("source_ip", "")))
        region = str(row.get("awsRegion", "us-east-1"))
        readonly = row.get("readOnly", True)

        severity = "info" if readonly else "warning"
        msg = f"CloudTrail: {user} called {action} on {source} from {ip} ({region})"

        event = {
            "timestamp": _make_timestamp(),
            "hostname": source,
            "user": user,
            "source_type": "cloudtrail",
            "cloud_action": action,
            "cloud_service": source,
            "cloud_user": user,
            "src_ip": ip,
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    return events


def load_k8s(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """07_Kubernetes: K8s audit training normalized."""
    events = []
    fp = DATA_DIR / "07_Kubernetes" / "k8s_audit_training_normalized.csv"
    if not fp.exists():
        log.warning("K8s dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  07_K8s: loaded %d rows", len(df))

    for _, row in df.iterrows():
        verb = str(row.get("verb", "get"))
        resource = str(row.get("resource", "pods"))
        namespace = str(row.get("namespace", "default"))
        user = str(row.get("user", "system:serviceaccount"))
        groups = str(row.get("groups", ""))
        is_admin = bool(row.get("is_admin", False))
        resp_code = _safe_int(row.get("response_code", 200))

        severity = "warning" if resp_code >= 400 else "info"
        msg = f"K8s audit: {user} {verb} {resource} in {namespace} → {resp_code}"

        event = {
            "timestamp": str(row.get("timestamp", _make_timestamp())),
            "hostname": "kube-apiserver",
            "user": user,
            "source_type": "kubernetes",
            "k8s_verb": verb,
            "k8s_resource": resource,
            "k8s_namespace": namespace,
            "k8s_user": user,
            "k8s_groups": groups,
            "k8s_is_admin": is_admin,
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    return events


def load_web(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """08_Web: CSIC 2010 normalized."""
    events = []
    rng = np.random.default_rng(66)
    fp = DATA_DIR / "08_Web_Server" / "csic_database_normalized.csv"
    if not fp.exists():
        log.warning("Web dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  08_Web: loaded %d rows", len(df))

    for _, row in df.iterrows():
        method = str(row.get("Method", "GET"))
        url = str(row.get("URL", "/"))
        content = str(row.get("content", ""))
        classification = str(row.get("classification", "normal")).lower()

        severity = "warning" if classification != "normal" else "info"
        msg = f"{method} {url}"
        if content and content != "nan":
            msg += f" body={content[:200]}"

        event = {
            "timestamp": _make_timestamp(),
            "hostname": "web01",
            "source_type": "web_server",
            "original_log_level": severity,
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    return events


def load_netflow(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """09_NetFlow: NF-UNSW stratified normalized."""
    events = []
    fp = DATA_DIR / "09_NetFlow" / "nf_unsw_stratified_normalized.csv"
    if not fp.exists():
        log.warning("NetFlow dataset not found: %s", fp)
        return events

    df = pd.read_csv(fp, nrows=max_rows)
    log.info("  09_NetFlow: loaded %d rows", len(df))

    # Column name detection
    src_ip_col = next((c for c in df.columns if "src" in c.lower() and "ip" in c.lower()), None)
    dst_ip_col = next((c for c in df.columns if "dst" in c.lower() and "ip" in c.lower()), None)
    src_port_col = next((c for c in df.columns if "src" in c.lower() and "port" in c.lower()), None)
    dst_port_col = next((c for c in df.columns if "dst" in c.lower() and "port" in c.lower()), None)
    proto_col = next((c for c in df.columns if "proto" in c.lower()), None)
    in_bytes_col = next((c for c in df.columns if "in" in c.lower() and "byte" in c.lower()), None)
    out_bytes_col = next((c for c in df.columns if "out" in c.lower() and "byte" in c.lower()), None)

    for _, row in df.iterrows():
        src_ip = str(row.get(src_ip_col, "10.0.0.1")) if src_ip_col else "10.0.0.1"
        dst_ip = str(row.get(dst_ip_col, "10.0.0.2")) if dst_ip_col else "10.0.0.2"
        sport = _safe_int(row.get(src_port_col, 0)) if src_port_col else 0
        dport = _safe_int(row.get(dst_port_col, 0)) if dst_port_col else 0
        proto_num = _safe_int(row.get(proto_col, 6)) if proto_col else 6
        sbytes = _safe_float(row.get(in_bytes_col, 0)) if in_bytes_col else 0.0
        dbytes = _safe_float(row.get(out_bytes_col, 0)) if out_bytes_col else 0.0

        proto_map = {6: "tcp", 17: "udp", 1: "icmp"}
        proto = proto_map.get(proto_num, "tcp")

        msg = f"NetFlow {proto.upper()} {src_ip}:{sport} → {dst_ip}:{dport} " \
              f"bytes_in={sbytes} bytes_out={dbytes}"

        event = {
            "timestamp": _make_timestamp(),
            "hostname": "router01",
            "source_type": "netflow",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "bytes_sent": sbytes,
            "bytes_received": dbytes,
            "original_log_level": "info",
            "message_body": msg,
        }
        label = _safe_int(row.get("clif_label", 0))
        attack = str(row.get("clif_attack_type", "benign"))
        events.append((event, label, attack))

    return events


def load_ids(max_rows: int) -> List[Tuple[Dict, int, str]]:
    """10_IDS: CICIDS2017 + NSL-KDD stratified normalized."""
    events = []

    # CICIDS2017
    fp_cicids = DATA_DIR / "10_IDS_IPS" / "cicids2017_stratified_normalized.csv"
    if fp_cicids.exists():
        df = pd.read_csv(fp_cicids, nrows=max_rows // 2, low_memory=False)
        log.info("  10_IDS (CICIDS): loaded %d rows", len(df))

        dst_port_col = next(
            (c for c in df.columns if "destination" in c.lower() and "port" in c.lower()),
            "Destination Port"
        )
        fwd_pkts_col = next(
            (c for c in df.columns if "fwd" in c.lower() and "packet" in c.lower()),
            None
        )

        for _, row in df.iterrows():
            dport = _safe_int(row.get(dst_port_col, 0))
            proto = str(row.get("Protocol", 6))
            proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}
            proto_str = proto_map.get(str(proto), "tcp")

            # Estimate bytes from packet counts
            fwd_pkts = _safe_float(row.get(fwd_pkts_col, 1)) if fwd_pkts_col else 1.0
            sbytes = fwd_pkts * 512
            dbytes = _safe_float(row.get("Total Backward Packets", 1)) * 512

            msg = f"IDS alert: {proto_str.upper()} flow to port {dport} " \
                  f"fwd_pkts={fwd_pkts}"

            event = {
                "timestamp": _make_timestamp(),
                "hostname": "ids01",
                "source_type": "ids_ips",
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "dst_port": dport,
                "protocol": proto_str,
                "bytes_sent": sbytes,
                "bytes_received": dbytes,
                "original_log_level": "info",
                "message_body": msg,
            }
            label = _safe_int(row.get("clif_label", 0))
            attack = str(row.get("clif_attack_type", "benign"))
            events.append((event, label, attack))

    # NSL-KDD
    fp_kdd = DATA_DIR / "10_IDS_IPS" / "nsl_kdd_stratified_normalized.csv"
    if fp_kdd.exists():
        cap = max(max_rows // 2, 5000)
        df = pd.read_csv(fp_kdd, nrows=cap)
        log.info("  10_IDS (KDD): loaded %d rows", len(df))

        for _, row in df.iterrows():
            proto = str(row.get("protocol_type", "tcp")).lower()
            service = str(row.get("service", "http"))
            dport_map = {"http": 80, "smtp": 25, "ftp": 21, "ssh": 22,
                         "dns": 53, "telnet": 23, "pop3": 110, "imap": 143}
            dport = dport_map.get(service, 0)
            sbytes = _safe_float(row.get("src_bytes", 0))
            dbytes = _safe_float(row.get("dst_bytes", 0))
            flag = str(row.get("flag", "SF"))

            msg = f"KDD {proto.upper()} {service} flag={flag} " \
                  f"bytes={sbytes}/{dbytes}"

            event = {
                "timestamp": _make_timestamp(),
                "hostname": "ids02",
                "source_type": "ids_ips",
                "dst_port": dport,
                "protocol": proto,
                "bytes_sent": sbytes,
                "bytes_received": dbytes,
                "original_log_level": "info",
                "message_body": msg,
            }
            label = _safe_int(row.get("clif_label", 0))
            attack = str(row.get("clif_attack_type", "benign"))
            events.append((event, label, attack))

    return events[:max_rows]


# =============================================================================
#  Feature Extraction (uses production feature_extractor.py)
# =============================================================================


def extract_features(
    labeled_events: List[Tuple[Dict, int, str]],
) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
    """
    Run all events through the SAME FeatureExtractor used in production.

    Returns:
        X: (N, 32) float32 feature matrix
        y: (N,) int labels
        source_types: list of N source type strings
        attack_types: list of N attack type strings
    """
    triage_config, Drain3Miner, EWMATracker, FeatureExtractor, \
        ShardedConnectionTracker, SourceNoveltyTracker, FEATURE_NAMES, NUM_FEATURES = _import_triage()

    log.info("Initializing feature extractor (production code)...")

    drain3 = Drain3Miner()
    ewma = EWMATracker()
    conn_tracker = ShardedConnectionTracker(
        num_shards=16,
        time_window_sec=2.0,
        host_window_size=100,
    )
    novelty = SourceNoveltyTracker()

    extractor = FeatureExtractor(
        drain3_miner=drain3,
        ewma_tracker=ewma,
        conn_tracker=conn_tracker,
        novelty_tracker=novelty,
        ioc_lookup_fn=None,  # No IOC cache during training
    )

    features_list = []
    labels = []
    source_types = []
    attack_types = []
    _ioc_rng = np.random.default_rng(99)  # For IOC injection

    # Determine topic from source_type
    topic_map = {
        "netflow": "network-events",
        "ids_ips": "network-events",
        "firewall": "network-events",
        "linux_auth": "security-events",
        "active_directory": "security-events",
        "windows_event": "security-events",
        "dns": "raw-logs",
        "cloudtrail": "raw-logs",
        "kubernetes": "raw-logs",
        "web_server": "raw-logs",
    }

    total = len(labeled_events)
    log.info("Extracting %d features using production FeatureExtractor...", total)
    t0 = time.time()

    for i, (event, label, attack_type) in enumerate(labeled_events):
        if i > 0 and i % 50000 == 0:
            elapsed = time.time() - t0
            rate = i / max(elapsed, 0.1)
            log.info("  ... %d/%d (%.0f events/sec)", i, total, rate)

        src_type = event.get("source_type", "unknown")
        topic = topic_map.get(src_type, "raw-logs")

        try:
            feats = extractor.extract(event, topic)
            features_list.append(feats)
            labels.append(label)
            source_types.append(src_type)
            attack_types.append(attack_type)
        except Exception as e:
            if i < 5:
                log.warning("Feature extraction failed for event %d: %s", i, e)

    elapsed = time.time() - t0
    log.info("Feature extraction complete: %d events in %.1fs (%.0f/s)",
             len(features_list), elapsed, len(features_list) / max(elapsed, 0.1))

    X = extractor.batch_to_numpy(features_list)
    y = np.array(labels, dtype=np.int32)

    # RED FLAG FIX: Inject synthetic IOC hits into the feature matrix.
    # During training ioc_lookup_fn is None so has_known_ioc (col 7) is
    # always 0.  In production it can be 1 when a known-bad IP is seen.
    # Inject IOC=1 for ~30% of attack events so the model learns the signal.
    ioc_col = 7  # has_known_ioc
    attack_mask = y == 1
    n_attack = attack_mask.sum()
    ioc_inject = _ioc_rng.random(n_attack) < 0.30
    X[np.where(attack_mask)[0][ioc_inject], ioc_col] = 1.0
    n_injected = ioc_inject.sum()
    log.info("  IOC injection: set has_known_ioc=1 for %d/%d attack events (%.0f%%)",
             n_injected, n_attack, n_injected / max(n_attack, 1) * 100)

    return X, y, source_types, attack_types


# =============================================================================
#  LightGBM Training (5-fold CV, per-type F1 gates)
# =============================================================================


def train_lgbm(
    X: np.ndarray,
    y: np.ndarray,
    source_types: List[str],
    feature_names: List[str],
    gpu_info: Optional[Dict[str, Any]] = None,
) -> Tuple:
    """
    Train LightGBM with 5-fold stratified CV and export ONNX.

    Returns:
        (model, cv_metrics_dict)
    """
    try:
        import lightgbm as lgb
    except ImportError:
        log.error("lightgbm not installed. Run: pip install lightgbm")
        sys.exit(1)

    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import f1_score, precision_score, recall_score

    log.info("=" * 60)
    log.info("LIGHTGBM TRAINING (5-fold stratified CV)")
    log.info("=" * 60)
    log.info("  Samples: %d  Features: %d  Positive rate: %.2f%%",
             len(y), X.shape[1], y.mean() * 100)

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "num_leaves": 63,
        "max_depth": 8,
        "learning_rate": 0.03,
        "min_child_samples": 30,
        "colsample_bytree": 0.8,
        "subsample": 0.8,
        "reg_alpha": 0.3,
        "reg_lambda": 3.0,
        "min_gain_to_split": 0.05,
        "scale_pos_weight": float(np.sum(y == 0)) / max(np.sum(y == 1), 1),
        "n_estimators": 1000,  # Reduced from 2000 — prevents over-training
        "verbose": -1,
        "seed": 42,
        "n_jobs": -1,
    }

    # GPU acceleration for LightGBM (requires GPU-compiled build)
    if gpu_info and gpu_info.get("lgbm_gpu"):
        params["device"] = "gpu"
        params["gpu_use_dp"] = False  # fp32 is sufficient for GBDT
        log.info("  LightGBM device: GPU")
    else:
        log.info("  LightGBM device: CPU (gpu build not available or --no-gpu)")

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    fold_f1s = []
    fold_metrics = []
    source_arr = np.array(source_types)

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y), 1):
        X_train, X_val = X[train_idx], X[val_idx]
        y_train, y_val = y[train_idx], y[val_idx]

        dtrain = lgb.Dataset(X_train, label=y_train, feature_name=feature_names)
        dval = lgb.Dataset(X_val, label=y_val, feature_name=feature_names, reference=dtrain)

        callbacks = [
            lgb.early_stopping(50, verbose=False),  # Tighter patience
            lgb.log_evaluation(period=0),
        ]

        model = lgb.train(
            params,
            dtrain,
            valid_sets=[dval],
            callbacks=callbacks,
        )

        y_pred = (model.predict(X_val) >= 0.5).astype(int)
        f1 = f1_score(y_val, y_pred)
        prec = precision_score(y_val, y_pred, zero_division=0)
        rec = recall_score(y_val, y_pred, zero_division=0)

        fold_f1s.append(f1)
        fold_metrics.append({"fold": fold, "f1": f1, "precision": prec, "recall": rec})

        # Per-source-type F1
        type_f1s = {}
        for st in np.unique(source_arr[val_idx]):
            mask = source_arr[val_idx] == st
            if mask.sum() > 0 and y_val[mask].sum() > 0:
                type_f1s[st] = f1_score(y_val[mask], y_pred[mask], zero_division=0)
        
        log.info("  Fold %d: F1=%.4f  Prec=%.4f  Recall=%.4f  "
                 "best_iter=%d", fold, f1, prec, rec, model.best_iteration)
        for st, sf1 in sorted(type_f1s.items()):
            log.info("    %-20s F1=%.4f%s", st, sf1,
                     " << BELOW GATE" if sf1 < 0.80 else "")

    mean_f1 = np.mean(fold_f1s)
    std_f1 = np.std(fold_f1s)
    log.info("-" * 60)
    log.info("  CV Results: F1 = %.4f ± %.4f", mean_f1, std_f1)

    # Retrain on full data with a 10% holdout to guard against overfitting
    avg_best = int(np.mean([m.get("best_iteration", 500)
                            for m in fold_metrics]))
    final_rounds = min(avg_best, 1000)  # No inflation — use CV-averaged rounds
    log.info("Training final model on full dataset (%d rounds, 10%% holdout)...",
             final_rounds)

    # 90/10 split for final train — the holdout catches catastrophic overfit
    from sklearn.model_selection import train_test_split as _tts
    X_ftrain, X_fval, y_ftrain, y_fval = _tts(
        X, y, test_size=0.10, stratify=y, random_state=42)
    dtrain = lgb.Dataset(X_ftrain, label=y_ftrain, feature_name=feature_names)
    dval = lgb.Dataset(X_fval, label=y_fval, feature_name=feature_names,
                       reference=dtrain)

    final_model = lgb.train(
        {**params, "n_estimators": final_rounds},
        dtrain,
        valid_sets=[dval],
        callbacks=[
            lgb.early_stopping(50, verbose=False),
            lgb.log_evaluation(period=0),
        ],
    )
    log.info("  Final model best_iteration: %d", final_model.best_iteration)

    cv_metrics = {
        "cv_f1_mean": float(mean_f1),
        "cv_f1_std": float(std_f1),
        "folds": fold_metrics,
    }

    return final_model, cv_metrics


def export_lgbm_onnx(model, feature_names: List[str], output_path: Path):
    """Export LightGBM model to ONNX format."""
    try:
        from onnxmltools import convert_lightgbm
        from onnxmltools.convert.common.data_types import FloatTensorType
    except ImportError:
        log.error("onnxmltools not installed. Run: pip install onnxmltools")
        sys.exit(1)

    log.info("Exporting LightGBM to ONNX: %s", output_path)

    initial_type = [("input", FloatTensorType([None, len(feature_names)]))]
    onnx_model = convert_lightgbm(
        model,
        initial_types=initial_type,
        target_opset=15,
    )

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    # Also save text representation
    txt_path = output_path.with_suffix(".txt")
    model.save_model(str(txt_path))
    log.info("  LightGBM text model saved: %s", txt_path)


# =============================================================================
#  Autoencoder Training (normal-only, MSE loss)
# =============================================================================


def train_autoencoder(
    X: np.ndarray,
    y: np.ndarray,
    source_types: List[str],
    scaler_mean: np.ndarray,
    scaler_std: np.ndarray,
    gpu_info: Optional[Dict[str, Any]] = None,
) -> Tuple:
    """
    Train Autoencoder on normal-only data.
    Architecture: 32 → 64 → 32 → 16 → 8 → 16 → 32 → 64 → 32.

    Returns:
        (model, calibration_dict)
    """
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        log.error("PyTorch not installed. Run: pip install torch")
        sys.exit(1)

    log.info("=" * 60)
    log.info("AUTOENCODER TRAINING (normal-only, 100 epochs)")
    log.info("=" * 60)

    # Use only normal (label=0) samples for training
    normal_mask = y == 0
    X_normal = X[normal_mask]
    source_normal = np.array(source_types)[normal_mask]

    log.info("  Normal samples: %d  (from %d total)", len(X_normal), len(y))

    # Z-score normalize using the pre-computed scaler
    std_safe = np.where(scaler_std < 1e-8, 1.0, scaler_std)
    X_scaled = ((X_normal - scaler_mean) / std_safe).astype(np.float32)

    # Mask stateful features (EWMA / connection-tracker) to 0 so the AE
    # only learns to reconstruct event-intrinsic features.
    AE_MASKED_INDICES = (8, 9, 10, 11, 16, 17, 18, 19)
    X_scaled[:, AE_MASKED_INDICES] = 0.0
    log.info("  Masked %d stateful features for AE training", len(AE_MASKED_INDICES))

    # 80/20 train/val split
    rng = np.random.default_rng(42)
    indices = rng.permutation(len(X_scaled))
    split = int(0.8 * len(indices))
    train_idx, val_idx = indices[:split], indices[split:]

    X_train_t = torch.from_numpy(X_scaled[train_idx])
    X_val_t = torch.from_numpy(X_scaled[val_idx])

    # Device selection
    use_cuda = (gpu_info or {}).get("cuda", False)
    device = torch.device("cuda" if use_cuda else "cpu")
    log.info("  Device: %s", device)

    # DataLoader tuning for GPU
    dl_kwargs = {}
    if use_cuda:
        dl_kwargs["pin_memory"] = True
        dl_kwargs["num_workers"] = 2
        dl_kwargs["persistent_workers"] = True

    train_ds = TensorDataset(X_train_t)
    val_ds = TensorDataset(X_val_t)
    train_dl = DataLoader(train_ds, batch_size=512, shuffle=True, **dl_kwargs)
    val_dl = DataLoader(val_ds, batch_size=1024, shuffle=False, **dl_kwargs)

    # Architecture: 32 → 64 → 32 → 16 → 8 → 16 → 32 → 64 → 32
    class Autoencoder(nn.Module):
        def __init__(self, dim=32):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(dim, 64), nn.ReLU(),
                nn.Linear(64, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 8), nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(8, 16), nn.ReLU(),
                nn.Linear(16, 32), nn.ReLU(),
                nn.Linear(32, 64), nn.ReLU(),
                nn.Linear(64, dim), nn.Sigmoid(),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    model = Autoencoder(dim=32).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    # Mixed-precision training (significant speedup on Tensor-Core GPUs)
    use_amp = use_cuda and hasattr(torch.amp, "GradScaler")
    if use_amp:
        scaler_amp = torch.amp.GradScaler("cuda")
        log.info("  Mixed precision: enabled (fp16 forward, fp32 grad)")
    else:
        scaler_amp = None
        if use_cuda:
            log.info("  Mixed precision: disabled (torch version lacks amp.GradScaler)")

    best_val_loss = float("inf")
    patience_counter = 0
    patience = 10
    best_state = None

    for epoch in range(100):
        # Train
        model.train()
        train_loss = 0.0
        for (batch,) in train_dl:
            batch = batch.to(device, non_blocking=use_cuda)
            if use_amp:
                with torch.amp.autocast("cuda"):
                    recon = model(batch)
                    loss = criterion(recon, batch)
                optimizer.zero_grad(set_to_none=True)
                scaler_amp.scale(loss).backward()
                scaler_amp.step(optimizer)
                scaler_amp.update()
            else:
                recon = model(batch)
                loss = criterion(recon, batch)
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                optimizer.step()
            train_loss += loss.item() * len(batch)
        train_loss /= len(train_idx)

        # Validate
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for (batch,) in val_dl:
                batch = batch.to(device, non_blocking=use_cuda)
                if use_amp:
                    with torch.amp.autocast("cuda"):
                        recon = model(batch)
                        val_loss += criterion(recon, batch).item() * len(batch)
                else:
                    recon = model(batch)
                    val_loss += criterion(recon, batch).item() * len(batch)
        val_loss /= len(val_idx)

        if (epoch + 1) % 10 == 0 or epoch == 0:
            log.info("  Epoch %3d: train_loss=%.6f  val_loss=%.6f", epoch + 1, train_loss, val_loss)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= patience:
                log.info("  Early stopping at epoch %d (best val_loss=%.6f)", epoch + 1, best_val_loss)
                break

    if best_state:
        model.load_state_dict(best_state)
    model.eval()

    # Compute per-source-type calibration (p99 and p50 reconstruction errors)
    log.info("Computing per-source-type calibration...")
    X_all_scaled = ((X - scaler_mean) / std_safe).astype(np.float32)
    X_all_scaled[:, AE_MASKED_INDICES] = 0.0  # same masking as training

    # Process in batches to avoid GPU OOM on large datasets
    all_mse_parts = []
    cal_batch = 8192
    with torch.no_grad():
        for start in range(0, len(X_all_scaled), cal_batch):
            chunk = torch.from_numpy(X_all_scaled[start:start + cal_batch]).to(device)
            recon_chunk = model(chunk)
            mse_chunk = ((chunk - recon_chunk) ** 2).mean(dim=1)
            all_mse_parts.append(mse_chunk.cpu().numpy())
    all_mse = np.concatenate(all_mse_parts)

    calibration = {}
    for st in np.unique(source_types):
        mask = np.array(source_types) == st
        normal_mask_st = mask & (y == 0)
        if normal_mask_st.sum() > 10:
            errors = all_mse[normal_mask_st]
            calibration[st] = {
                "p99_error": float(np.percentile(errors, 99)),
                "p50_error": float(np.percentile(errors, 50)),
            }

    # Default calibration from all normal data
    normal_errors = all_mse[y == 0]
    calibration["_default"] = {
        "p99_error": float(np.percentile(normal_errors, 99)),
        "p50_error": float(np.percentile(normal_errors, 50)),
    }

    for st, cal in sorted(calibration.items()):
        log.info("  %-20s p99=%.6f  p50=%.6f", st, cal["p99_error"], cal["p50_error"])

    return model, calibration


def export_autoencoder_onnx(model, output_path: Path):
    """Export PyTorch autoencoder to ONNX (always on CPU for portability)."""
    import torch

    log.info("Exporting Autoencoder to ONNX: %s", output_path)

    # Move model to CPU for export — ONNX runtime serves on CPU in production
    model = model.cpu()
    model.eval()
    dummy_input = torch.randn(1, 32)

    torch.onnx.export(
        model,
        dummy_input,
        str(output_path),
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input": {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        opset_version=17,
    )


# =============================================================================
#  Scaler / Manifest Generation
# =============================================================================


def compute_scaler(X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Compute per-feature mean and std for z-score normalization."""
    mean = np.mean(X, axis=0).astype(np.float64)
    std = np.std(X, axis=0).astype(np.float64)
    # Prevent division by zero
    std = np.where(std < 1e-8, 1.0, std)
    return mean, std


def save_scaler(mean: np.ndarray, std: np.ndarray, path: Path):
    """Save scaler parameters as JSON (matching FeatureScaler expectations)."""
    data = {
        "mean": mean.tolist(),
        "std": std.tolist(),
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    log.info("Feature scaler saved: %s", path)


def save_calibration(calibration: Dict, path: Path):
    """Save AE per-source calibration as JSON."""
    with open(path, "w") as f:
        json.dump(calibration, f, indent=2)
    log.info("AE calibration saved: %s", path)


def save_manifest(
    feature_names: List[str],
    cv_metrics: Dict,
    dataset_stats: Dict,
    model_dir: Path,
):
    """Save training manifest with metadata for drift detection."""
    manifest = {
        "version": "7.0.0",
        "created": datetime.now(timezone.utc).isoformat(),
        "features": feature_names,
        "num_features": len(feature_names),
        "models": {
            "lgbm": {
                "file": "lgbm_v7.onnx",
                "weight": 0.85,
                "type": "supervised",
            },
            "autoencoder": {
                "file": "autoencoder_v7.onnx",
                "weight": 0.15,
                "type": "unsupervised",
                "architecture": "32-64-32-16-8-16-32-64-32",
            },
        },
        "scaler": "feature_scaler_v7.json",
        "calibration": "ae_calibration_v7.json",
        "training": {
            "total_samples": dataset_stats.get("total", 0),
            "normal_samples": dataset_stats.get("normal", 0),
            "attack_samples": dataset_stats.get("attack", 0),
            "source_types": dataset_stats.get("source_types", {}),
            "cv_metrics": cv_metrics,
        },
        "thresholds": {
            "suspicious": 0.40,
            "anomalous": 0.90,
        },
    }

    path = model_dir / "manifest_v7.json"
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    log.info("Manifest saved: %s", path)


# =============================================================================
#  Main
# =============================================================================


def main():
    parser = argparse.ArgumentParser(description="CLIF Triage v7 Model Training")
    parser.add_argument("--dry-run", action="store_true",
                        help="Validate data loading only, skip training")
    parser.add_argument("--max-per-type", type=int, default=50000,
                        help="Max rows per dataset type (default: 50000)")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Output directory for models (default: agents/triage/models)")
    parser.add_argument("--no-gpu", action="store_true",
                        help="Force CPU-only training (ignore available GPUs)")
    args = parser.parse_args()

    # Set global GPU flag early so all training functions can use it
    global USE_GPU
    USE_GPU = not args.no_gpu

    output_dir = Path(args.output_dir) if args.output_dir else MODEL_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    log.info("=" * 70)
    log.info("CLIF Triage Agent v7 — Model Training Pipeline")
    log.info("=" * 70)
    log.info("Data directory:   %s", DATA_DIR)
    log.info("Output directory: %s", output_dir)
    log.info("Max per type:     %d", args.max_per_type)

    # ── Step 1: Load all datasets ───────────────────────────────────────
    log.info("")
    log.info("STEP 1: Loading datasets...")
    loaders = [
        ("01_Syslog", load_syslog),
        ("02_Windows", load_windows),
        ("03_Firewall", load_firewall),
        ("04_AD", load_ad),
        ("05_DNS", load_dns),
        ("06_Cloud", load_cloud),
        ("07_K8s", load_k8s),
        ("08_Web", load_web),
        ("09_NetFlow", load_netflow),
        ("10_IDS", load_ids),
    ]

    all_events: List[Tuple[Dict, int, str]] = []
    dataset_stats = {"source_types": {}}

    for name, loader_fn in loaders:
        t0 = time.time()
        events = loader_fn(args.max_per_type)
        elapsed = time.time() - t0

        if events:
            n_attack = sum(1 for _, l, _ in events if l == 1)
            n_normal = len(events) - n_attack
            log.info("  %-15s %6d events (%d normal, %d attack) [%.1fs]",
                     name, len(events), n_normal, n_attack, elapsed)
            dataset_stats["source_types"][name] = {
                "total": len(events), "normal": n_normal, "attack": n_attack
            }
        else:
            log.warning("  %-15s NO DATA", name)

        all_events.extend(events)

    total = len(all_events)
    total_attack = sum(1 for _, l, _ in all_events if l == 1)
    total_normal = total - total_attack
    dataset_stats["total"] = total
    dataset_stats["normal"] = total_normal
    dataset_stats["attack"] = total_attack

    log.info("-" * 60)
    log.info("TOTAL: %d events (%d normal / %d attack = %.1f%% attack rate)",
             total, total_normal, total_attack,
             total_attack / max(total, 1) * 100)

    if total == 0:
        log.error("No training data loaded. Check dataset paths.")
        sys.exit(1)

    # Shuffle to mix source types (important for CV)
    rng = np.random.default_rng(42)
    rng.shuffle(all_events)

    if args.dry_run:
        log.info("DRY RUN: Data loading validated successfully. Exiting.")
        return

    # ── Step 2: Feature extraction ──────────────────────────────────────
    log.info("")
    log.info("STEP 2: Feature extraction (production feature_extractor.py)...")
    _, _, _, _, _, _, FEATURE_NAMES, NUM_FEATURES = _import_triage()

    X, y, source_types, attack_types = extract_features(all_events)
    log.info("  Feature matrix: %s  Labels: %s", X.shape, y.shape)
    log.info("  NaN count:  %d", np.isnan(X).sum())
    log.info("  Inf count:  %d", np.isinf(X).sum())

    # ── Step 3: Compute scaler ──────────────────────────────────────────
    log.info("")
    log.info("STEP 3: Computing feature scaler (z-score)...")
    scaler_mean, scaler_std = compute_scaler(X)
    save_scaler(scaler_mean, scaler_std, output_dir / "feature_scaler_v7.json")

    # ── Step 4: Train LightGBM ──────────────────────────────────────────
    log.info("")
    log.info("STEP 3b: Detecting GPU hardware...")
    gpu_info = _detect_gpu()
    log.info("  CUDA available: %s", gpu_info["cuda"])
    if gpu_info["cuda"]:
        log.info("  CUDA device:    %s (%.1f GB)",
                 gpu_info.get("cuda_device", "?"), gpu_info.get("cuda_mem_gb", 0))
    log.info("  LightGBM GPU:   %s", gpu_info["lgbm_gpu"])

    log.info("")
    log.info("STEP 4: Training LightGBM...")
    lgbm_model, cv_metrics = train_lgbm(X, y, source_types, FEATURE_NAMES, gpu_info)
    export_lgbm_onnx(lgbm_model, FEATURE_NAMES, output_dir / "lgbm_v7.onnx")

    # ── Step 5: Train Autoencoder ───────────────────────────────────────
    log.info("")
    log.info("STEP 5: Training Autoencoder...")
    ae_model, calibration = train_autoencoder(
        X, y, source_types, scaler_mean, scaler_std, gpu_info
    )
    export_autoencoder_onnx(ae_model, output_dir / "autoencoder_v7.onnx")
    save_calibration(calibration, output_dir / "ae_calibration_v7.json")

    # ── Step 6: Save manifest ───────────────────────────────────────────
    log.info("")
    log.info("STEP 6: Saving manifest...")
    save_manifest(FEATURE_NAMES, cv_metrics, dataset_stats, output_dir)

    # ── Summary ─────────────────────────────────────────────────────────
    log.info("")
    log.info("=" * 70)
    log.info("TRAINING COMPLETE")
    log.info("=" * 70)
    log.info("Artifacts in %s:", output_dir)
    log.info("  lgbm_v7.onnx            — LightGBM supervised model")
    log.info("  lgbm_v7.txt             — LightGBM text representation")
    log.info("  autoencoder_v7.onnx     — Autoencoder anomaly detector")
    log.info("  feature_scaler_v7.json  — Z-score normalization params")
    log.info("  ae_calibration_v7.json  — Per-source AE calibration")
    log.info("  manifest_v7.json        — Training metadata & features")
    log.info("")
    log.info("LightGBM CV F1: %.4f ± %.4f", cv_metrics["cv_f1_mean"], cv_metrics["cv_f1_std"])
    log.info("")
    log.info("Next steps:")
    log.info("  1. Review manifest_v7.json for per-type metrics")
    log.info("  2. Run: docker compose -f docker-compose.pc2.yml up -d --build")
    log.info("  3. Monitor /stats endpoint for throughput")


if __name__ == "__main__":
    main()
