"""Audit folders 03_Firewall through 10_IDS_IPS."""
import os, csv

base = r"C:\CLIF\agents\Data\Latest_Dataset"

def head_lines(filepath, n=3):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= n: break
                lines.append(line.rstrip('\n')[:200])
            return lines
    except:
        return ["[binary or unreadable]"]

def csv_info(filepath, max_rows=5000000):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.reader(f)
            header = next(reader)
            rows = 0
            for _ in reader:
                rows += 1
        return header, rows
    except Exception as e:
        return None, str(e)

targets = ['03_Firewall', '04_Active_Directory', '05_DNS', '06_Cloud_AWS',
           '07_Kubernetes', '08_Web_Server', '09_NetFlow', '10_IDS_IPS']

for folder in targets:
    fpath = os.path.join(base, folder)
    if not os.path.isdir(fpath):
        print(f"\n{'='*60}\n{folder}: DOES NOT EXIST\n")
        continue
    
    files = []
    for r, d, fs in os.walk(fpath):
        for f in fs:
            fp = os.path.join(r, f)
            files.append((os.path.relpath(fp, fpath), os.path.getsize(fp)))
    files.sort()
    
    total = sum(s for _, s in files)
    print(f"\n{'='*60}")
    print(f"{folder}/ ({total/1024/1024:.1f} MB, {len(files)} files)")
    print("-" * 60)
    
    for fname, fsize in files:
        full = os.path.join(fpath, fname)
        ext = os.path.splitext(fname)[1].lower()
        print(f"  [{fsize/1024/1024:.2f} MB] {fname}")
        
        if ext == '.csv' and fsize < 2000*1024*1024:
            hdr, rows = csv_info(full)
            if hdr:
                print(f"    Cols ({len(hdr)}): {', '.join(hdr[:12])}")
                print(f"    Rows: {rows:,}")
            lines = head_lines(full, 2)
            for l in lines:
                print(f"    > {l[:160]}")
        elif ext in ('.txt', '.log') and fsize < 500*1024*1024:
            lines = head_lines(full, 2)
            for l in lines:
                print(f"    > {l[:160]}")
        elif ext in ('.zip', '.gz', '.evtx', '.json'):
            if ext == '.json' and fsize < 50*1024*1024:
                lines = head_lines(full, 1)
                for l in lines:
                    print(f"    > {l[:160]}")
            else:
                print(f"    [binary/compressed]")

print(f"\n{'='*60}")
print("DONE")
