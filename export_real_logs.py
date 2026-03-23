#!/usr/bin/env python3
"""
Export all real-log datasets to a single NDJSON file for the Go TCP blaster.
Reuses the existing dataset loaders from test_real_logs.py.
"""
import json
import os
import sys
import time
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from test_real_logs import load_all_datasets

OUTPUT = "real_logs_payload.ndjson"
MAX_PER_DATASET = 50_000  # Load more events per dataset for a bigger payload
TARGET_EVENTS = 1_000_000  # Target 1M events by repeating datasets

def main():
    print(f"Loading real log datasets (max {MAX_PER_DATASET} per dataset)...")
    all_events = load_all_datasets(MAX_PER_DATASET)

    total_loaded = sum(len(v) for v in all_events.values())
    print(f"\nLoaded {total_loaded:,} unique events from {len(all_events)} datasets:")
    for name, events in sorted(all_events.items(), key=lambda x: -len(x[1])):
        print(f"  {name:25s}  {len(events):>8,}")

    # Interleave all events round-robin
    names = list(all_events.keys())
    iterators = {n: iter(all_events[n]) for n in names}
    interleaved = []
    done = set()
    while len(done) < len(names):
        for n in names:
            if n in done:
                continue
            try:
                ev = next(iterators[n])
                interleaved.append(ev)
            except StopIteration:
                done.add(n)

    # Repeat to reach target
    if len(interleaved) < TARGET_EVENTS:
        repeats = (TARGET_EVENTS // len(interleaved)) + 1
        print(f"\nRepeating {len(interleaved):,} events ×{repeats} to reach ~{TARGET_EVENTS:,}...")
        base = interleaved[:]
        for _ in range(repeats - 1):
            interleaved.extend(base)
        interleaved = interleaved[:TARGET_EVENTS]

    # Write NDJSON
    print(f"\nWriting {len(interleaved):,} events to {OUTPUT}...")
    start = time.time()
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for ev in interleaved:
            f.write(json.dumps(ev, separators=(",", ":")) + "\n")

    size_mb = os.path.getsize(OUTPUT) / (1024 * 1024)
    elapsed = time.time() - start
    print(f"Done: {size_mb:.1f} MB in {elapsed:.1f}s")
    print(f"Events: {len(interleaved):,}")

if __name__ == "__main__":
    main()
