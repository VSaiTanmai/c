"""Inspect training data landscape for retraining plan."""
import pandas as pd, numpy as np, pickle, os

df = pd.read_csv('agents/Data/features_combined_features.csv')
print('=== TRAINING DATA ===')
print(f'Rows: {len(df):,}')
print(f'Columns: {list(df.columns)}')
print(f'Label dist: normal={int((df["label"]==0).sum())}, malicious={int((df["label"]==1).sum())}')

print('\n=== PER-DATASET BREAKDOWN ===')
for ds in df['source_dataset'].unique():
    sub = df[df['source_dataset']==ds]
    n_norm = int((sub['label']==0).sum())
    n_mal = int((sub['label']==1).sum())
    attacks = sub[sub['label']==1]['attack_type'].nunique()
    print(f'  {ds}: normal={n_norm}, malicious={n_mal}, attack_types={attacks}')

with open('agents/triage/models/feature_cols.pkl','rb') as f:
    cols = pickle.load(f)
print(f'\nFeature cols ({len(cols)}): {cols}')

print('\n=== DATA FILES ===')
for f in sorted(os.listdir('agents/Data')):
    size = os.path.getsize(f'agents/Data/{f}')
    print(f'  {f}: {size/1024/1024:.1f}MB')

print('\n=== MODEL FILES ===')
for f in sorted(os.listdir('agents/triage/models')):
    size = os.path.getsize(f'agents/triage/models/{f}')
    print(f'  {f}: {size/1024:.1f}KB')

# ARF stream
arf_df = pd.read_csv('agents/Data/features_arf_stream_features.csv')
print(f'\nARF stream: {len(arf_df)} rows')

# Feature statistics for normal data (what EIF SHOULD learn)
normal = df[df['label']==0][cols]
print('\n=== NORMAL DATA FEATURE STATS (for EIF) ===')
for c in cols:
    vals = normal[c].replace([np.inf, -np.inf], np.nan).dropna()
    print(f'  {c:25s}: mean={vals.mean():12.4f}  std={vals.std():12.4f}  min={vals.min():12.4f}  max={vals.max():12.4f}')

# Weak attack categories
print('\n=== WEAK ATTACK TYPES (detection rate < 60%) ===')
for at in ['Analysis','Backdoors','rootkit','DoS','Exploits','multihop','loadmodule','warezmaster']:
    mask = df['attack_type']==at
    if mask.sum()>0:
        sub = df[mask]
        print(f'  {at:20s}: n={mask.sum():5d}, dataset={sub["source_dataset"].iloc[0]}')

# Check which features have zero variance in normal data
print('\n=== ZERO/LOW VARIANCE FEATURES IN NORMAL ===')
for c in cols:
    v = normal[c].var()
    if v < 0.01:
        print(f'  {c}: var={v:.6f}')
