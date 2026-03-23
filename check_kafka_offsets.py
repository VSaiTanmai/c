#!/usr/bin/env python3
"""Sum high-water marks across Kafka partitions for ingestion topics."""
import subprocess

topics = ['raw-logs', 'security-events', 'network-events', 'process-events']
grand = 0
for t in topics:
    out = subprocess.check_output(
        ['docker', 'exec', 'clif-redpanda01', 'rpk', 'topic', 'describe', t, '-p'],
        text=True, stderr=subprocess.STDOUT
    )
    total = 0
    for line in out.strip().split('\n'):
        parts = line.split()
        if parts and parts[0].isdigit():
            total += int(parts[-1])
    print(f"  {t:20s}: {total:>10,}")
    grand += total

print(f"  {'─' * 34}")
print(f"  {'KAFKA TOTAL':20s}: {grand:>10,}")
