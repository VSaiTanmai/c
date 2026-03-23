import zipfile, io, pandas as pd

zf = zipfile.ZipFile('agents/Data/datasets.zip')

# CSIC
for n in zf.namelist():
    if n.endswith('csic_database.csv') and '08_nginx' in n:
        data = zf.read(n).decode('utf-8', errors='replace')
        df = pd.read_csv(io.StringIO(data))
        print('CSIC classification dist:')
        print(df['classification'].value_counts())
        print('Methods:', df.iloc[:,1].value_counts().to_dict())
        print('Total:', len(df))
        break

print()
# EVTX
for n in zf.namelist():
    if n.endswith('evtx_data.csv') and '02_windows' in n:
        data = zf.read(n).decode('utf-8', errors='replace')
        df = pd.read_csv(io.StringIO(data), low_memory=False)
        print('EVTX Tactics:')
        print(df['EVTX_Tactic'].value_counts())
        print('Total:', len(df))
        break

print()
# ToN-IoT
for n in zf.namelist():
    if n.endswith('nf_ton_iot_temporal.csv'):
        data = zf.read(n).decode('utf-8', errors='replace')
        df = pd.read_csv(io.StringIO(data))
        print('ToN-IoT:')
        print(df['Attack'].value_counts())
        print('Total:', len(df))
        break

print()
# Linux Loghub - check for attack indicators
for n in zf.namelist():
    if n.endswith('Linux_2k.log_structured.csv') and 'path_a' in n:
        data = zf.read(n).decode('utf-8', errors='replace')
        df = pd.read_csv(io.StringIO(data))
        print('Linux Loghub:')
        print('Levels:', df['Level'].value_counts().to_dict())
        print('Components:', df['Component'].value_counts().head(10).to_dict())
        # Check for auth failures
        auth_fail = df[df['Content'].str.contains('failure|failed|invalid|error', case=False, na=False)]
        print(f'Auth failure lines: {len(auth_fail)} / {len(df)}')
        print('Sample failures:', auth_fail['Content'].head(3).tolist())
        break
