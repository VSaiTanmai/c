"""Quick ClickHouse verification script."""
import urllib.request, urllib.parse

def ch(q):
    url = 'http://localhost:8123/?' + urllib.parse.urlencode({
        'database': 'clif_logs',
        'user': 'clif_admin',
        'password': 'Cl1f_Ch@ngeM3_2026!'
    })
    return urllib.request.urlopen(
        urllib.request.Request(url, data=q.encode()), timeout=10
    ).read().decode().strip()

print("=" * 60)
print("CLICKHOUSE TABLE COUNTS")
print("=" * 60)
for t in ['raw_logs', 'security_events', 'process_events', 'network_events']:
    c = ch(f'SELECT count() FROM {t}')
    print(f"  {t:25s}: {int(c):>12,}")

print()
print("=" * 60)
print("SOURCE DISTRIBUTION (raw_logs)")
print("=" * 60)
print(ch('SELECT source, count() as cnt FROM raw_logs GROUP BY source ORDER BY cnt DESC LIMIT 15 FORMAT PrettyCompact'))

print()
print("=" * 60)
print("CATEGORY DISTRIBUTION (security_events)")
print("=" * 60)
print(ch('SELECT category, count() as cnt FROM security_events GROUP BY category ORDER BY cnt DESC LIMIT 15 FORMAT PrettyCompact'))

print()
print("=" * 60)
print("SAMPLE: Latest raw_logs")
print("=" * 60)
print(ch("SELECT source, level, substring(message,1,100) as msg FROM raw_logs ORDER BY received_at DESC LIMIT 10 FORMAT PrettyCompact"))

print()
print("=" * 60)
print("SAMPLE: Latest security_events")
print("=" * 60)
print(ch("SELECT category, source, severity, substring(description,1,100) as desc FROM security_events ORDER BY timestamp DESC LIMIT 10 FORMAT PrettyCompact"))

print()
print("=" * 60)
print("DATA SIZE ON DISK")
print("=" * 60)
for t in ['raw_logs', 'security_events', 'process_events', 'network_events']:
    size = ch(f"SELECT formatReadableSize(sum(bytes_on_disk)) FROM system.parts WHERE database='clif_logs' AND table='{t}' AND active=1")
    rows = ch(f"SELECT sum(rows) FROM system.parts WHERE database='clif_logs' AND table='{t}' AND active=1")
    print(f"  {t:25s}: {size:>12s}  ({int(rows):,} rows)")
