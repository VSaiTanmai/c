"""Full audit of all 10 dataset folders."""
import os
import csv

base = r"C:\CLIF\agents\Data\Latest_Dataset"
print("=" * 70)
print("LATEST_DATASET FULL AUDIT")
print("=" * 70)

total_size = 0
total_files = 0

for item in sorted(os.listdir(base)):
    full = os.path.join(base, item)
    if os.path.isdir(full):
        files = []
        sz = 0
        for r, d, fs in os.walk(full):
            for f in fs:
                fp = os.path.join(r, f)
                fsz = os.path.getsize(fp)
                sz += fsz
                rel = os.path.relpath(fp, full)
                files.append((rel, fsz))
        total_size += sz
        total_files += len(files)
        print(f"\n{'='*70}")
        print(f"{item}/ ({sz/1024/1024:.1f} MB, {len(files)} files)")
        print("-" * 70)
        for fn, fsz in sorted(files):
            print(f"  {fn}: {fsz/1024/1024:.2f} MB")
    else:
        fsz = os.path.getsize(full)
        total_size += fsz
        total_files += 1
        print(f"\n[ROOT FILE] {item}: {fsz/1024/1024:.2f} MB")

print(f"\n{'='*70}")
print(f"TOTAL: {total_size/1024/1024:.0f} MB ({total_size/1024/1024/1024:.1f} GB), {total_files} files")
print("=" * 70)
