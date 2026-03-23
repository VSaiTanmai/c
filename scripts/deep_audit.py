"""Deep audit of each dataset folder: files, sizes, head samples, label distribution."""
import os, csv, json, sys

base = r"C:\CLIF\agents\Data\Latest_Dataset"

def list_files(folder):
    result = []
    for r, d, fs in os.walk(folder):
        for f in fs:
            fp = os.path.join(r, f)
            rel = os.path.relpath(fp, folder)
            result.append((rel, os.path.getsize(fp)))
    return sorted(result)

def head_lines(filepath, n=3):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= n:
                    break
                lines.append(line.rstrip('\n')[:200])
            return lines
    except:
        return ["[binary or unreadable]"]

def count_lines(filepath, max_count=None):
    try:
        count = 0
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                count += 1
                if max_count and count >= max_count:
                    return f">{max_count}"
        return count
    except:
        return "error"

def csv_info(filepath, max_rows=100000):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = 0
            for _ in reader:
                rows += 1
                if rows >= max_rows:
                    break
        return header, rows if rows < max_rows else f">{max_rows}"
    except:
        return None, "error"

# --- AUDIT EACH FOLDER ---
folders = [d for d in sorted(os.listdir(base)) if os.path.isdir(os.path.join(base, d))]

for folder in folders:
    fpath = os.path.join(base, folder)
    files = list_files(fpath)
    print("=" * 70)
    print(f"FOLDER: {folder}")
    print(f"  Files: {len(files)}")
    total_mb = sum(s for _, s in files) / 1024 / 1024
    print(f"  Total size: {total_mb:.1f} MB")
    print()
    
    for fname, fsize in files:
        full = os.path.join(fpath, fname)
        ext = os.path.splitext(fname)[1].lower()
        print(f"  [{fsize/1024/1024:.2f} MB] {fname}")
        
        if ext in ('.csv', '.tsv', '.txt', '.log'):
            if fsize < 500 * 1024 * 1024:  # < 500 MB
                lines = head_lines(full, 2)
                for l in lines:
                    print(f"    > {l[:150]}")
                
                if ext == '.csv':
                    header, rows = csv_info(full)
                    if header:
                        print(f"    Columns ({len(header)}): {', '.join(header[:15])}")
                        print(f"    Rows: {rows}")
        elif ext in ('.json', '.ndjson'):
            lines = head_lines(full, 1)
            for l in lines:
                print(f"    > {l[:150]}")
        elif ext in ('.zip', '.gz', '.tar', '.evtx', '.xml'):
            print(f"    [compressed/binary]")
    print()

print("=" * 70)
print("AUDIT COMPLETE")
