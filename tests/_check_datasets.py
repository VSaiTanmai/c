import zipfile
zf = zipfile.ZipFile('agents/Data/datasets.zip')
targets = [
    'evtx_data.csv',
    'csic_database.csv', 
    'CSV_malware.csv',
    'Linux_2k.log_structured.csv',
    'Apache_2k.log_structured.csv',
    'nf_ton_iot_temporal.csv',
]
seen = set()
for t in targets:
    for n in zf.namelist():
        if n.endswith(t) and t not in seen:
            seen.add(t)
            data = zf.read(n).decode('utf-8', errors='replace')[:3000]
            lines = data.split('\n')[:3]
            cols = lines[0].split(',') if lines else []
            print(f"--- {t} ({len(cols)} cols) ---")
            print(f"  Path: {n}")
            print(f"  Cols: {cols[:12]}")
            if len(cols) > 12:
                print(f"        {cols[12:]}")
            if len(lines) > 1:
                print(f"  Row1: {lines[1][:250]}")
            print()
            break
