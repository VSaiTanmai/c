import urllib.request

CH = "http://localhost:8123"
creds = "user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!"

# First list all tables
q = "SELECT name FROM system.tables WHERE database = 'clif_logs' ORDER BY name"
req = urllib.request.Request(f"{CH}/?{creds}", data=q.encode())
resp = urllib.request.urlopen(req)
all_tables = [x.strip() for x in resp.read().decode().strip().split('\n') if x.strip()]
print(f"Tables in clif_logs: {len(all_tables)}")

total = 0
for t in all_tables:
    q = f"SELECT count() FROM clif_logs.{t}"
    req = urllib.request.Request(f"{CH}/?{creds}", data=q.encode())
    try:
        resp = urllib.request.urlopen(req)
        c = int(resp.read().decode().strip())
    except Exception:
        c = 0
    if c > 0:
        total += c
        print(f"  {t:30s} {c:>12,}")
sep = "-" * 30
print(f"  {sep} {'':>12}")
print(f"  {'TOTAL':30s} {total:>12,}")
print(f"  Sent by script:              3,487,281")
pct = total / 3487281 * 100
print(f"  Ingestion ratio:             {pct:.1f}%")
