"""Query triage_scores for validation of v6.0.0 with anomalous=0.89 threshold."""
import subprocess, sys

query = """
SELECT
  source_type,
  count() AS n,
  round(countIf(action='discard')*100.0/count(), 1) AS pct_benign,
  round(countIf(action='monitor')*100.0/count(), 1) AS pct_suspicious,
  round(countIf(action='escalate')*100.0/count(), 1) AS pct_anomalous,
  round(avg(lgbm_score), 4) AS avg_lgbm,
  round(min(lgbm_score), 4) AS min_lgbm,
  round(max(lgbm_score), 4) AS max_lgbm
FROM clif_logs.triage_scores
WHERE timestamp > now() - INTERVAL 15 MINUTE
  AND model_version = 'v6.0.0'
GROUP BY source_type
ORDER BY n DESC
FORMAT TSVWithNames
"""

cmd = [
    "docker", "exec", "clif-clickhouse01",
    "clickhouse-client",
    "--user", "clif_admin",
    "--password", "Cl1f_Ch@ngeM3_2026!",
    "-q", query.strip(),
]
result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
if result.returncode != 0:
    print("ERROR:", result.stderr, file=sys.stderr)
    sys.exit(1)

lines = result.stdout.strip().split("\n")
if len(lines) < 2:
    print("No data yet — triage may still be processing")
    sys.exit(0)

# Pretty-print as table
header = lines[0].split("\t")
rows = [line.split("\t") for line in lines[1:]]

# Column widths
widths = [max(len(h), max(len(r[i]) for r in rows)) for i, h in enumerate(header)]

fmt = "  ".join(f"{{:<{w}}}" for w in widths)
print(fmt.format(*header))
print("  ".join("-" * w for w in widths))
for row in rows:
    print(fmt.format(*row))

print()
# Summary
total = sum(int(r[1]) for r in rows)
print(f"Total scored: {total:,}")
