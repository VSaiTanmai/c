import pathlib
p = pathlib.Path(r'C:\Users\saita\OneDrive\Desktop\CLIF-PC2\clif-log-investigation\docker-compose.pc2.yml')
t = p.read_text(encoding='utf-8')
t = t.replace('earliest\\', 'earliest')
p.write_text(t, encoding='utf-8')
print('Fixed. Verifying...')
for line in p.read_text(encoding='utf-8').splitlines():
    if 'OFFSET_RESET' in line:
        print(line.strip())
