"""
LANL auth.txt Diverse Extraction Script
Extracts security-relevant + diverse normal samples for training
both known-attack (LightGBM) and anomaly-detection (Autoencoder) models.
"""

import os
import sys
import time
import random
from collections import defaultdict, Counter

random.seed(42)

# Paths
AUTH_FILE = r"C:\CLIF\agents\Data\Latest_Dataset\auth.txt"
REDTEAM_FILE = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\redteam.txt"
OUT_SYSLOG = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\lanl_auth_syslog.csv"
OUT_AD = r"C:\CLIF\agents\Data\Latest_Dataset\04_Active_Directory\lanl_auth_ad.csv"

# Config
CONTEXT_WINDOW = 60
NORMAL_SAMPLE_PER_HOUR = 200
KERBEROS_TGT_SAMPLE = 200_000
KERBEROS_TGS_SAMPLE = 200_000
MAX_PER_USER = 20
PROGRESS_INTERVAL = 50_000_000

HEADER = "timestamp,src_user,dst_user,src_computer,dst_computer,auth_type,logon_type,orientation,status,label,category\n"

RARE_LOGON_TYPES = {"RemoteInteractive", "CachedInteractive", "NewCredentials", "Unlock", "Batch"}
RARE_ORIENTATIONS = {"ScreenLock", "ScreenUnlock", "AuthMap"}

# ---- Step 1: Load redteam labels ----
print("Loading redteam labels...", flush=True)
redteam_lookup = set()
redteam_users = set()
redteam_computers = set()
redteam_time_windows = []

with open(REDTEAM_FILE) as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) >= 4:
            ts, user, src, dst = int(parts[0]), parts[1], parts[2], parts[3]
            redteam_lookup.add((ts, user))
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

print(f"  Redteam events: {len(redteam_lookup)}", flush=True)
print(f"  Redteam users: {len(redteam_users)}", flush=True)
print(f"  Context windows: {len(merged_windows)}", flush=True)

# ---- Step 2: Single-pass extraction (write incrementally) ----
print(f"\nStarting single-pass extraction...", flush=True)
print(f"  File: {AUTH_FILE}", flush=True)
print(f"  (Estimated ~10-15 min for 68 GB)\n", flush=True)

os.makedirs(os.path.dirname(OUT_SYSLOG), exist_ok=True)
os.makedirs(os.path.dirname(OUT_AD), exist_ok=True)

stats = Counter()
hourly_normal_counts = defaultdict(int)
entity_sample_per_user = defaultdict(int)

# Reservoir sampling for Kerberos
kerberos_tgt_reservoir = []
kerberos_tgs_reservoir = []
kerberos_tgt_count = 0
kerberos_tgs_count = 0

start_time = time.time()
lines_processed = 0

f_syslog = open(OUT_SYSLOG, "w", encoding="utf-8")
f_ad = open(OUT_AD, "w", encoding="utf-8")
f_syslog.write(HEADER)
f_ad.write(HEADER)

syslog_count = 0
ad_count = 0

try:
    with open(AUTH_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            lines_processed += 1

            if lines_processed % PROGRESS_INTERVAL == 0:
                elapsed = time.time() - start_time
                rate = lines_processed / elapsed
                pct = (lines_processed / 1_130_000_000) * 100
                print(f"  [{pct:5.1f}%] {lines_processed/1e6:.0f}M lines | "
                      f"{rate/1e6:.2f}M lines/s | "
                      f"syslog: {syslog_count:,} | ad: {ad_count:,} | "
                      f"elapsed: {elapsed:.0f}s", flush=True)

            parts = line.strip().split(",")
            if len(parts) < 9:
                stats["malformed"] += 1
                continue

            ts_str = parts[0]
            src_user = parts[1]
            dst_user = parts[2]
            src_comp = parts[3]
            dst_comp = parts[4]
            auth_type = parts[5]
            logon_type = parts[6]
            orientation = parts[7]
            status = parts[8]

            try:
                ts = int(ts_str)
            except ValueError:
                stats["bad_timestamp"] += 1
                continue

            is_fail = (status == "Fail")
            is_ad = (auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"))

            # Cat 1: Redteam-labeled attack
            if (ts, src_user) in redteam_lookup:
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},attack,redteam\n"
                f_syslog.write(row); syslog_count += 1
                if is_ad: f_ad.write(row); ad_count += 1
                stats["redteam"] += 1
                continue

            # Cat 2: Context window around attacks
            in_context = False
            for wi in range(len(merged_windows)):
                ws, we = merged_windows[wi]
                if ts < ws:
                    break
                if ws <= ts <= we:
                    if (src_user in redteam_users or
                        src_comp in redteam_computers or
                        dst_comp in redteam_computers):
                        in_context = True
                    break

            if in_context:
                label = "suspicious" if is_fail else "context"
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},{label},attack_context\n"
                f_syslog.write(row); syslog_count += 1
                if is_ad: f_ad.write(row); ad_count += 1
                stats["attack_context"] += 1
                continue

            # Cat 3: ALL authentication failures
            if is_fail:
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},unknown,failure\n"
                f_syslog.write(row); syslog_count += 1
                if is_ad: f_ad.write(row); ad_count += 1
                stats["failures"] += 1
                continue

            # Cat 4: Rare logon types
            if logon_type in RARE_LOGON_TYPES:
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,rare_logon\n"
                f_syslog.write(row); syslog_count += 1
                if is_ad: f_ad.write(row); ad_count += 1
                stats["rare_logon"] += 1
                continue

            # Cat 5: Rare orientations
            if orientation in RARE_ORIENTATIONS:
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,rare_orientation\n"
                f_syslog.write(row); syslog_count += 1
                if is_ad: f_ad.write(row); ad_count += 1
                stats["rare_orientation"] += 1
                continue

            # Cat 6: Kerberos TGT/TGS (reservoir sampling - written at end)
            if orientation == "TGT":
                kerberos_tgt_count += 1
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,kerberos_tgt\n"
                if len(kerberos_tgt_reservoir) < KERBEROS_TGT_SAMPLE:
                    kerberos_tgt_reservoir.append(row)
                else:
                    j = random.randint(0, kerberos_tgt_count - 1)
                    if j < KERBEROS_TGT_SAMPLE:
                        kerberos_tgt_reservoir[j] = row
                continue

            if orientation == "TGS":
                kerberos_tgs_count += 1
                row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,kerberos_tgs\n"
                if len(kerberos_tgs_reservoir) < KERBEROS_TGS_SAMPLE:
                    kerberos_tgs_reservoir.append(row)
                else:
                    j = random.randint(0, kerberos_tgs_count - 1)
                    if j < KERBEROS_TGS_SAMPLE:
                        kerberos_tgs_reservoir[j] = row
                continue

            # Cat 7: Temporally-stratified normal sample
            hour_bucket = ts // 3600
            if hourly_normal_counts[hour_bucket] < NORMAL_SAMPLE_PER_HOUR:
                if random.random() < 0.01:
                    row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,temporal_normal\n"
                    f_syslog.write(row); syslog_count += 1
                    if is_ad: f_ad.write(row); ad_count += 1
                    hourly_normal_counts[hour_bucket] += 1
                    stats["temporal_normal"] += 1
                    continue

            # Cat 8: Entity-diverse normal sample
            if entity_sample_per_user[src_user] < MAX_PER_USER:
                if random.random() < 0.005:
                    row = f"{ts_str},{src_user},{dst_user},{src_comp},{dst_comp},{auth_type},{logon_type},{orientation},{status},benign,entity_diverse\n"
                    f_syslog.write(row); syslog_count += 1
                    if is_ad: f_ad.write(row); ad_count += 1
                    entity_sample_per_user[src_user] += 1
                    stats["entity_diverse"] += 1

    # Write kerberos reservoir samples
    print(f"\nWriting Kerberos reservoir samples...", flush=True)
    for row in kerberos_tgt_reservoir:
        f_syslog.write(row)
        f_ad.write(row)
        syslog_count += 1
        ad_count += 1
    for row in kerberos_tgs_reservoir:
        f_syslog.write(row)
        f_ad.write(row)
        syslog_count += 1
        ad_count += 1

finally:
    f_syslog.close()
    f_ad.close()

elapsed = time.time() - start_time

# ---- Step 3: Final report ----
syslog_size = os.path.getsize(OUT_SYSLOG) / 1024 / 1024
ad_size = os.path.getsize(OUT_AD) / 1024 / 1024

print(f"\n{'='*60}")
print(f"EXTRACTION COMPLETE in {elapsed:.0f}s ({elapsed/60:.1f} min)")
print(f"Lines processed: {lines_processed:,}")
print(f"{'='*60}")

print(f"\nOUTPUT FILES:")
print(f"  {OUT_SYSLOG}")
print(f"    Events: {syslog_count:,}  |  Size: {syslog_size:.1f} MB")
print(f"  {OUT_AD}")
print(f"    Events: {ad_count:,}  |  Size: {ad_size:.1f} MB")

print(f"\nEXTRACTION BREAKDOWN:")
for cat, count in sorted(stats.items(), key=lambda x: -x[1]):
    print(f"  {cat:25s}: {count:>12,}")
print(f"  {'kerberos_tgt_total':25s}: {kerberos_tgt_count:>12,} (sampled {len(kerberos_tgt_reservoir):,})")
print(f"  {'kerberos_tgs_total':25s}: {kerberos_tgs_count:>12,} (sampled {len(kerberos_tgs_reservoir):,})")
print(f"  {'unique_users_sampled':25s}: {len(entity_sample_per_user):>12,}")
print(f"  {'hourly_buckets_covered':25s}: {len(hourly_normal_counts):>12,}")

# Count label distribution from output file
print(f"\nLABEL DISTRIBUTION:")
label_dist = Counter()
with open(OUT_SYSLOG, "r") as f:
    next(f)  # skip header
    for line in f:
        parts = line.strip().split(",")
        if len(parts) >= 10:
            label_dist[parts[9]] += 1

for label, count in label_dist.most_common():
    print(f"  {label:15s}: {count:>12,}  ({count/syslog_count*100:.1f}%)")

print(f"\nTRAINING USAGE:")
print(f"  LightGBM (Known): attack + suspicious = positive, benign = negative")
print(f"  Autoencoder (Anomaly): Train on benign ONLY, anomaly = high recon error")
print(f"\nDone!", flush=True)
