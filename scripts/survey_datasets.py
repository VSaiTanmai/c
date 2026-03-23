"""
Deep survey of ALL datasets in datasets.zip — column names, value ranges, 
label columns, and sample rows. This gives us the exact mapping spec needed
for the unified feature extractor.
"""
import zipfile, io, csv, sys

zf = zipfile.ZipFile('agents/Data/datasets.zip')

# Gather all CSV files (skip .git stuff)
csvs = []
for n in zf.namelist():
    if n.endswith('.csv') and '.git' not in n:
        csvs.append(n)

# Deduplicate by filename (same file appears under multiple log-type folders)
seen = {}
for c in sorted(csvs):
    basename = c.split('/')[-1]
    size = zf.getinfo(c).file_size
    key = f"{basename}_{size}"
    if key not in seen:
        seen[key] = c

print(f"Unique CSV files: {len(seen)}")
print("=" * 80)

for key, path in sorted(seen.items(), key=lambda x: x[1]):
    info = zf.getinfo(path)
    size_mb = info.file_size / 1024 / 1024
    
    # Read first few rows
    try:
        raw = zf.read(path)
        text = raw.decode('utf-8', errors='replace')
        lines = text.split('\n')
        
        # Parse header
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        header = [h.strip().strip('\r') for h in header]
        
        # Count rows (approximate for large files)
        if size_mb > 50:
            # Estimate row count
            avg_line_len = sum(len(l) for l in lines[:100]) / min(100, len(lines))
            est_rows = int(info.file_size / avg_line_len) if avg_line_len > 0 else 0
            row_info = f"~{est_rows:,} (estimated)"
        else:
            row_info = f"{len(lines)-2:,}"
        
        # Find label/class columns
        label_cols = [h for h in header if any(k in h.lower() for k in 
                      ['label', 'class', 'attack', 'classification', 'anomaly', 'tactic', 'binary'])]
        
        # Find potentially useful columns
        print(f"\n--- {path} ({size_mb:.1f}MB, {row_info} rows) ---")
        print(f"  ALL COLUMNS ({len(header)}): {header}")
        print(f"  LABEL COLUMNS: {label_cols}")
        
        # Read first 3 data rows
        rows = []
        for i, row in enumerate(reader):
            if i >= 3:
                break
            rows.append(row)
        
        if rows and label_cols:
            for lc in label_cols:
                idx = header.index(lc) if lc in header else -1
                if idx >= 0:
                    vals = [r[idx] if idx < len(r) else 'N/A' for r in rows]
                    print(f"  {lc} sample values: {vals}")
        
        # Sample first row (truncated)
        if rows:
            sample = dict(zip(header, rows[0]))
            # Show key fields
            for show_key in ['Label', 'label', 'classification', 'Attack', 'EVTX_Tactic',
                           ' Label', 'binary_label', 'attack_type', 'class']:
                if show_key in sample:
                    print(f"  {show_key} = {sample[show_key]}")
            
    except Exception as e:
        print(f"\n--- {path} ({size_mb:.1f}MB) --- ERROR: {e}")

print("\n" + "=" * 80)
print("DONE")
