"""Quick check of hunter results in ClickHouse and Kafka."""
import subprocess, json

def ch(sql):
    r = subprocess.run(
        ["docker", "exec", "clif-clickhouse01", "clickhouse-client", "-q", sql],
        capture_output=True, text=True, timeout=10)
    return r.stdout.strip()

# 1. Count investigations
print("=== Hunter Investigations ===")
print(f"Total rows: {ch('SELECT count() FROM clif_logs.hunter_investigations')}")

# 2. All investigations with details
rows = ch("""SELECT hostname, round(trigger_score,4), finding_type,
       round(confidence,4), length(correlated_events), mitre_tactics
FROM clif_logs.hunter_investigations
ORDER BY started_at FORMAT TSVWithNames""")
print(rows)

# 3. Kafka hunter-results count
print("\n=== Kafka hunter-results ===")
r = subprocess.run(
    ["docker", "exec", "clif-redpanda01", "rpk", "topic", "consume",
     "hunter-results", "-o", "start", "--num", "30", "-f", "%v\n"],
    capture_output=True, text=True, timeout=15)
novel_hosts = {"dns-srv-01", "bastion-01", "internal-cache", "edge-router"}
known_hosts = {"db-srv-01", "dc-primary", "ws-finance-03", "rdp-gateway"}
for line in r.stdout.strip().split("\n"):
    if not line.strip():
        continue
    try:
        d = json.loads(line)
        h = d.get("hostname", "?")
        tag = "NOVEL" if h in novel_hosts else ("KNOWN" if h in known_hosts else "OTHER")
        print(f"  [{tag:5s}] {h:22s} triage={d.get('trigger_score',0):.4f}  "
              f"hunter={d.get('confidence',0):.4f}  finding={d.get('finding_type','?')}"
              f"  corr={len(d.get('correlated_events',[]))}  "
              f"mitre={d.get('mitre_tactics',[])}  status={d.get('status','?')}")
    except:
        pass

print(f"\nTotal messages in hunter-results: {len([l for l in r.stdout.strip().split(chr(10)) if l.strip()])}")
