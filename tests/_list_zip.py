import zipfile
zf = zipfile.ZipFile('agents/Data/datasets.zip')
dirs = set()
csvs = []
for n in zf.namelist():
    parts = n.split('/')
    if len(parts) >= 2 and parts[0] == 'datasets':
        dirs.add(parts[1])
    if n.endswith('.csv') and 'git' not in n.lower():
        csvs.append(n)
print('Top-level folders:')
for d in sorted(dirs):
    if d:
        print(f'  {d}')
print(f'\nCSV files ({len(csvs)}):')
for c in sorted(csvs)[:50]:
    info = zf.getinfo(c)
    short = '/'.join(c.split('/')[2:])
    print(f'  {short}: {info.file_size/1024/1024:.1f}MB')
if len(csvs) > 50:
    print(f'  ... and {len(csvs)-50} more')
