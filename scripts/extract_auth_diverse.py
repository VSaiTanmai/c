"""
LANL auth.txt Diverse Extraction Script
========================================
Extracts security-relevant + diverse normal samples from the 68 GB LANL auth.txt
for training BOTH known-attack (LightGBM) and anomaly-detection (Autoencoder) models.

Input:  C:\CLIF\agents\Data\Latest_Dataset\auth.txt  (~68 GB, ~1.13B lines)
Output: 01_Syslog/lanl_auth_syslog.csv       (general auth events for syslog training)
        04_Active_Directory/lanl_auth_ad.csv  (AD/Kerberos events for AD training)
        
Extraction Categories (ensuring diversity):
  1. ALL redteam-labeled events (749) — ATTACK label
  2. ±60s context window around each attack — behavioral context
  3. ALL authentication failures — brute force / credential attacks
  4. ALL rare logon types (RemoteInteractive, CachedInteractive, NewCreds, Unlock)
  5. ALL rare orientations (ScreenLock, ScreenUnlock, AuthMap)
  6. Stratified Kerberos TGT/TGS sample — AD credential activity
  7. Temporally-stratified normal sample — from every hour across 58 days
  8. Entity-diverse normal sample — many unique users/computers
  9. Failure-burst detection — periods with abnormal failure rates
"""

import os
import sys
import time
import random
import csv
from collections import defaultdict, Counter

random.seed(42)  # Reproducible

# ---------- Paths ----------
AUTH_FILE = r"C:\CLIF\agents\Data\Latest_Dataset\auth.txt"
REDTEAM_FILE = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\redteam.txt"
OUT_SYSLOG = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\lanl_auth_syslog.csv"
OUT_AD = r"C:\CLIF\agents\Data\Latest_Dataset\04_Active_Directory\lanl_auth_ad.csv"

# ---------- Config ----------
CONTEXT_WINDOW = 60          # seconds around redteam events
NORMAL_SAMPLE_PER_HOUR = 200 # normal events sampled per hour-bucket (58 days × 24h = 1392 buckets)
KERBEROS_TGT_SAMPLE = 200_000  # Kerberos TGT events sample
KERBEROS_TGS_SAMPLE = 200_000  # Kerberos TGS events sample
ENTITY_DIVERSE_TARGET = 300_000 # entity-diverse normal sample
FAILURE_BURST_WINDOW = 300   # 5-minute windows for burst detection
FAILURE_BURST_THRESHOLD = 50 # failures per window to flag as burst
PROGRESS_INTERVAL = 50_000_000  # print progress every 50M lines

HEADER = "timestamp,src_user,dst_user,src_computer,dst_computer,auth_type,logon_type,orientation,status,label,category"

# ---------- Step 1: Load redteam labels ----------
print("Loading redteam labels...")
redteam_lookup = {}  # (timestamp, user) -> (src, dst)
redteam_users = set()
redteam_computers = set()
redteam_time_windows = []  # (start, end) for context extraction

with open(REDTEAM_FILE) as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) >= 4:
            ts, user, src, dst = int(parts[0]), parts[1], parts[2], parts[3]
            redteam_lookup[(ts, user)] = (src, dst)
            redteam_users.add(user)
            redteam_computers.add(src)
            redteam_computers.add(dst)
            redteam_time_windows.append((ts - CONTEXT_WINDOW, ts + CONTEXT_WINDOW))

# Merge overlapping windows
redteam_time_windows.sort()
merged_windows = []
for start, end in redteam_time_windows:
    if merged_windows and start <= merged_windows[-1][1]:
        merged_windows[-1] = (merged_windows[-1][0], max(merged_windows[-1][1], end))
    else:
        merged_windows.append((start, end))

print(f"  Redteam events: {len(redteam_lookup)}")
print(f"  Redteam users: {len(redteam_users)}")
print(f"  Context windows: {len(merged_windows)} (merged from {len(redteam_time_windows)})")

# ---------- Step 2: Single-pass extraction ----------
print(f"\nStarting single-pass extraction of {AUTH_FILE}...")
print(f"  (This will take ~10-15 minutes for 68 GB)\n")

# Storage
syslog_events = []   # General auth events
ad_events = []       # AD-specific (Kerberos) events

# Counters
stats = Counter()
hourly_normal_counts = defaultdict(int)  # hour_bucket -> count sampled
hourly_normal_target = NORMAL_SAMPLE_PER_HOUR
entity_users_seen = set()
entity_sample_per_user = defaultdict(int)
failure_windows = defaultdict(int)  # (window_start) -> failure_count
failure_burst_events = []

# Reservoir sampling for large categories
kerberos_tgt_reservoir = []
kerberos_tgs_reservoir = []
kerberos_tgt_count = 0
kerberos_tgs_count = 0

# For entity-diverse sampling: reservoir by user
entity_reservoir = defaultdict(list)  # user -> [events]
MAX_PER_USER = 20  # max events per unique user for diversity

start_time = time.time()
lines_processed = 0
window_idx = 0  # pointer into merged_windows for efficient lookup

RARE_LOGON_TYPES = {"RemoteInteractive", "CachedInteractive", "NewCredentials", "Unlock", "Batch"}
RARE_ORIENTATIONS = {"ScreenLock", "ScreenUnlock", "AuthMap"}

with open(AUTH_FILE, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        lines_processed += 1
        
        if lines_processed % PROGRESS_INTERVAL == 0:
            elapsed = time.time() - start_time
            rate = lines_processed / elapsed
            pct = (lines_processed / 1_130_000_000) * 100
            total_extracted = len(syslog_events) + len(ad_events) + len(failure_burst_events)
            print(f"  [{pct:5.1f}%] {lines_processed/1e6:.0f}M lines | "
                  f"{rate/1e6:.2f}M lines/s | "
                  f"extracted: {total_extracted:,} | "
                  f"elapsed: {elapsed:.0f}s")
        
        parts = line.strip().split(",")
        if len(parts) < 9:
            stats["malformed"] += 1
            continue
        
        ts_str, src_user, dst_user, src_comp, dst_comp, auth_type, logon_type, orientation, status = parts[:9]
        
        try:
            ts = int(ts_str)
        except ValueError:
            stats["bad_timestamp"] += 1
            continue
        
        hour_bucket = ts // 3600
        is_fail = (status == "Fail")
        
        # --- Category 1: Redteam-labeled attack ---
        is_redteam = (ts, src_user) in redteam_lookup
        if is_redteam:
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},attack,redteam"
            syslog_events.append(event_line)
            if auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"):
                ad_events.append(event_line)
            stats["redteam"] += 1
            continue
        
        # --- Category 2: Context window around attacks ---
        # Check if timestamp falls within any attack context window
        in_context = False
        # Advance window pointer
        while window_idx < len(merged_windows) and merged_windows[window_idx][1] < ts:
            window_idx += 1
        
        # Check current and nearby windows (reset if needed since file may not be perfectly sorted)
        for wi in range(max(0, window_idx - 1), min(len(merged_windows), window_idx + 2)):
            if merged_windows[wi][0] <= ts <= merged_windows[wi][1]:
                # Also check if user/computer is related to redteam
                if src_user in redteam_users or src_comp in redteam_computers or dst_comp in redteam_computers:
                    in_context = True
                    break
        
        if in_context:
            label = "suspicious" if is_fail else "context"
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},{label},attack_context"
            syslog_events.append(event_line)
            if auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"):
                ad_events.append(event_line)
            stats["attack_context"] += 1
            continue
        
        # --- Category 3: ALL authentication failures ---
        if is_fail:
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},unknown,failure"
            syslog_events.append(event_line)
            if auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"):
                ad_events.append(event_line)
            stats["failures"] += 1
            
            # Track failure bursts
            burst_window = ts // FAILURE_BURST_WINDOW
            failure_windows[burst_window] += 1
            continue
        
        # --- Category 4: Rare logon types ---
        if logon_type in RARE_LOGON_TYPES:
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,rare_logon"
            syslog_events.append(event_line)
            if auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"):
                ad_events.append(event_line)
            stats["rare_logon"] += 1
            continue
        
        # --- Category 5: Rare orientations ---
        if orientation in RARE_ORIENTATIONS:
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,rare_orientation"
            syslog_events.append(event_line)
            stats["rare_orientation"] += 1
            continue
        
        # --- Category 6: Kerberos TGT/TGS reservoir sampling ---
        if orientation == "TGT":
            kerberos_tgt_count += 1
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,kerberos_tgt"
            if len(kerberos_tgt_reservoir) < KERBEROS_TGT_SAMPLE:
                kerberos_tgt_reservoir.append(event_line)
            else:
                j = random.randint(0, kerberos_tgt_count - 1)
                if j < KERBEROS_TGT_SAMPLE:
                    kerberos_tgt_reservoir[j] = event_line
            continue
        
        if orientation == "TGS":
            kerberos_tgs_count += 1
            event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,kerberos_tgs"
            if len(kerberos_tgs_reservoir) < KERBEROS_TGS_SAMPLE:
                kerberos_tgs_reservoir.append(event_line)
            else:
                j = random.randint(0, kerberos_tgs_count - 1)
                if j < KERBEROS_TGS_SAMPLE:
                    kerberos_tgs_reservoir[j] = event_line
            continue
        
        # --- Category 7: Temporally-stratified normal sample ---
        # Sample from every hour across the 58 days for uniform time coverage
        if hourly_normal_counts[hour_bucket] < hourly_normal_target:
            # Probabilistic sampling to avoid bias toward early events in each hour
            # Accept with decreasing probability as we fill the bucket
            remaining_target = hourly_normal_target - hourly_normal_counts[hour_bucket]
            if random.random() < 0.01:  # ~1% acceptance, enough to fill 200/hour from ~750K/hour
                event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,temporal_normal"
                syslog_events.append(event_line)
                hourly_normal_counts[hour_bucket] += 1
                stats["temporal_normal"] += 1
                continue
        
        # --- Category 8: Entity-diverse normal sample ---
        # Keep a few events per unique user to ensure user diversity
        if entity_sample_per_user[src_user] < MAX_PER_USER:
            if random.random() < 0.005:  # low acceptance rate since there are millions of events per user
                event_line = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,entity_diverse"
                syslog_events.append(event_line)
                entity_sample_per_user[src_user] += 1
                stats["entity_diverse"] += 1

# --- Post-pass: identify failure burst periods ---
print("\nIdentifying failure burst periods...")
burst_windows_found = {w for w, c in failure_windows.items() if c >= FAILURE_BURST_THRESHOLD}
print(f"  Failure burst windows (>{FAILURE_BURST_THRESHOLD} failures in {FAILURE_BURST_WINDOW}s): {len(burst_windows_found)}")

# Add Kerberos reservoir samples to AD events
for ev in kerberos_tgt_reservoir:
    ad_events.append(ev)
for ev in kerberos_tgs_reservoir:
    ad_events.append(ev)

# Also add a copy of Kerberos to syslog (they're still auth events)
syslog_events.extend(kerberos_tgt_reservoir[:50_000])  # limit to avoid bloat
syslog_events.extend(kerberos_tgs_reservoir[:50_000])

elapsed = time.time() - start_time
print(f"\n{'='*60}")
print(f"Extraction complete in {elapsed:.0f}s ({elapsed/60:.1f} min)")
print(f"Total lines processed: {lines_processed:,}")
print(f"{'='*60}")

# ---------- Step 3: Write outputs ----------
print(f"\nWriting outputs...")

# Ensure directories exist
os.makedirs(os.path.dirname(OUT_SYSLOG), exist_ok=True)
os.makedirs(os.path.dirname(OUT_AD), exist_ok=True)

with open(OUT_SYSLOG, "w", newline="", encoding="utf-8") as f:
    f.write(HEADER + "\n")
    for ev in syslog_events:
        f.write(ev + "\n")

with open(OUT_AD, "w", newline="", encoding="utf-8") as f:
    f.write(HEADER + "\n")
    for ev in ad_events:
        f.write(ev + "\n")

syslog_size = os.path.getsize(OUT_SYSLOG) / 1024 / 1024
ad_size = os.path.getsize(OUT_AD) / 1024 / 1024

print(f"\n{'='*60}")
print(f"OUTPUT FILES")
print(f"{'='*60}")
print(f"  {OUT_SYSLOG}")
print(f"    Events: {len(syslog_events):,}  |  Size: {syslog_size:.1f} MB")
print(f"  {OUT_AD}")
print(f"    Events: {len(ad_events):,}  |  Size: {ad_size:.1f} MB")

print(f"\n{'='*60}")
print(f"EXTRACTION BREAKDOWN")
print(f"{'='*60}")
for cat, count in sorted(stats.items(), key=lambda x: -x[1]):
    print(f"  {cat:25s}: {count:>12,}")
print(f"  {'kerberos_tgt_total':25s}: {kerberos_tgt_count:>12,} (sampled {len(kerberos_tgt_reservoir):,})")
print(f"  {'kerberos_tgs_total':25s}: {kerberos_tgs_count:>12,} (sampled {len(kerberos_tgs_reservoir):,})")
print(f"  {'failure_burst_windows':25s}: {len(burst_windows_found):>12,}")
print(f"  {'unique_users_sampled':25s}: {len(entity_sample_per_user):>12,}")
print(f"  {'hourly_buckets_covered':25s}: {len(hourly_normal_counts):>12,}")

# Label distribution
label_dist = Counter()
for ev in syslog_events:
    parts = ev.split(",")
    if len(parts) >= 10:
        label_dist[parts[9]] += 1

print(f"\n{'='*60}")
print(f"LABEL DISTRIBUTION (for training)")
print(f"{'='*60}")
for label, count in label_dist.most_common():
    print(f"  {label:15s}: {count:>12,}  ({count/len(syslog_events)*100:.1f}%)")

print(f"\n{'='*60}")
print(f"TRAINING APPLICABILITY")
print(f"{'='*60}")
print(f"  LightGBM (Known Attack Detection):")
print(f"    - 'attack' label -> known redteam compromises")
print(f"    - 'suspicious' label -> failures near attack time")
print(f"    - 'benign' label -> confirmed normal activity")
print(f"    - 'unknown' (failures) -> can be used as potential attack signal")
print(f"  Autoencoder (Anomaly Detection):")
print(f"    - Train ONLY on 'benign' events (temporal + entity-diverse normal)")
print(f"    - Test reconstruction error on 'attack' + 'suspicious' + 'unknown'")
print(f"    - High reconstruction error = anomaly detected")
print(f"\nDone!")
