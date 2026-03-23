"""Downsample the large extraction to a balanced training set."""
import random, os
from collections import Counter, defaultdict

random.seed(42)

SRC = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\lanl_auth_syslog.csv"
OUT_SYSLOG = r"C:\CLIF\agents\Data\Latest_Dataset\01_Syslog\lanl_auth_training.csv"
OUT_AD = r"C:\CLIF\agents\Data\Latest_Dataset\04_Active_Directory\lanl_auth_ad_training.csv"

TARGETS = {
    "redteam": 999999,
    "attack_context": 50000,
    "failure": 100000,
    "rare_logon": 50000,
    "rare_orientation": 30000,
    "temporal_normal": 999999,
    "entity_diverse": 100000,
    "kerberos_tgt": 50000,
    "kerberos_tgs": 50000,
}

print("Reading full extraction...", flush=True)
cat_counts = Counter()
total = 0
with open(SRC) as f:
    header = next(f)
    for line in f:
        total += 1
        parts = line.strip().split(",")
        if len(parts) >= 11:
            cat_counts[parts[10]] += 1

print(f"Total events: {total:,}")
for c, n in cat_counts.most_common():
    target = TARGETS.get(c, 10000)
    rate = min(1.0, target / max(n, 1))
    print(f"  {c:20s}: {n:>12,}  target={target:>8,}  rate={rate:.4f}")

# Calculate acceptance rates
acceptance = {}
for cat, count in cat_counts.items():
    target = TARGETS.get(cat, 10000)
    acceptance[cat] = min(1.0, target / max(count, 1))

print("\nDownsampling...", flush=True)
sampled = defaultdict(list)
with open(SRC) as f:
    next(f)
    for line in f:
        parts = line.strip().split(",")
        if len(parts) < 11:
            continue
        cat = parts[10]
        if random.random() < acceptance.get(cat, 0.01):
            sampled[cat].append(line)

print("Writing outputs...", flush=True)
syslog_count = 0
ad_count = 0

with open(OUT_SYSLOG, "w") as fs, open(OUT_AD, "w") as fa:
    fs.write(header)
    fa.write(header)
    for cat in sorted(sampled.keys()):
        for line in sampled[cat]:
            fs.write(line)
            syslog_count += 1
            parts = line.strip().split(",")
            if len(parts) >= 8:
                auth_type = parts[5]
                orientation = parts[7]
                if auth_type in ("Kerberos", "Negotiate") or orientation in ("TGT", "TGS"):
                    fa.write(line)
                    ad_count += 1

syslog_sz = os.path.getsize(OUT_SYSLOG) / 1024 / 1024
ad_sz = os.path.getsize(OUT_AD) / 1024 / 1024

print(f"\n{'='*60}")
print(f"TRAINING FILES CREATED")
print(f"{'='*60}")
print(f"  Syslog: {OUT_SYSLOG}")
print(f"    Events: {syslog_count:,}  |  Size: {syslog_sz:.1f} MB")
print(f"  AD: {OUT_AD}")
print(f"    Events: {ad_count:,}  |  Size: {ad_sz:.1f} MB")

label_dist = Counter()
cat_dist = Counter()
with open(OUT_SYSLOG) as f:
    next(f)
    for line in f:
        parts = line.strip().split(",")
        if len(parts) >= 11:
            label_dist[parts[9]] += 1
            cat_dist[parts[10]] += 1

print(f"\nLABEL DISTRIBUTION:")
for l, c in label_dist.most_common():
    print(f"  {l:15s}: {c:>10,}  ({c/syslog_count*100:.1f}%)")

print(f"\nCATEGORY DISTRIBUTION:")
for l, c in cat_dist.most_common():
    print(f"  {l:20s}: {c:>10,}  ({c/syslog_count*100:.1f}%)")

print(f"\nTRAINING USAGE:")
print(f"  LightGBM (Known Attack): attack+suspicious -> positive, benign -> negative")
print(f"  Autoencoder (Anomaly):   Train on benign ONLY, high recon error = anomaly")
print(f"\nDone!", flush=True)
