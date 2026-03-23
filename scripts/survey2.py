"""Survey remaining key datasets: CIC, NSL-KDD, ToN-IoT, Linux auth logs."""
import zipfile, io, csv

zf = zipfile.ZipFile('agents/Data/datasets.zip')

targets = [
    'cicids2017_stratified.csv',
    'nsl_kdd_stratified.csv',
    'nf_ton_iot_temporal.csv',
    'Linux_2k.log_structured.csv',
    'Apache_2k.log_structured.csv',
]

seen = set()
for path in sorted(zf.namelist()):
    basename = path.split('/')[-1]
    if basename in targets and basename not in seen:
        seen.add(basename)
        info = zf.getinfo(path)
        raw = zf.read(path).decode('utf-8', errors='replace')
        lines = raw.split('\n')
        reader = csv.reader(io.StringIO(raw))
        header = [h.strip().strip('\r') for h in next(reader)]
        
        # Read 3 sample rows
        rows = []
        for i, row in enumerate(reader):
            if i >= 3: break
            rows.append(row)
        
        print(f"--- {basename} ({info.file_size/1024/1024:.1f}MB, ~{len(lines)-2} rows) ---")
        print(f"  PATH: {path}")
        print(f"  COLUMNS ({len(header)}): {header}")
        
        label_cols = [h for h in header if any(k in h.lower() for k in 
                      ['label', 'class', 'attack', 'anomaly', 'binary'])]
        print(f"  LABEL COLS: {label_cols}")
        
        if rows:
            sample = dict(zip(header, rows[0]))
            for lc in label_cols:
                if lc in sample:
                    # Show unique values in first 3 rows
                    vals = [r[header.index(lc)] if header.index(lc) < len(r) else 'N/A' for r in rows]
                    print(f"  {lc} values: {vals}")
            print(f"  SAMPLE ROW: {dict(list(zip(header, rows[0]))[:15])}")
        print()
