"""Debug script: extract features from real Kafka events and print them."""
import json
import sys
sys.path.insert(0, "/app")

import config
from drain3_miner import Drain3Miner
from feature_extractor import FeatureExtractor, ConnectionTracker, FEATURE_NAMES

miner = Drain3Miner()
tracker = ConnectionTracker()
ext = FeatureExtractor(drain3_miner=miner, conn_tracker=tracker)

from confluent_kafka import Consumer
c = Consumer({
    "bootstrap.servers": "redpanda01:9092",
    "group.id": "debug-features-tmp",
    "auto.offset.reset": "earliest",
})
c.subscribe(["security-events", "network-events"])

found = 0
for _ in range(50):
    msg = c.poll(3.0)
    if msg is None or msg.error():
        continue
    topic = msg.topic()
    try:
        event = json.loads(msg.value().decode("utf-8"))
    except Exception:
        continue
    feats = ext.extract(event, topic)
    print(f"\n--- Event {found+1} from {topic} ---")
    print(f"  source_type: {feats.get('_source_type', '?')}")
    for name in FEATURE_NAMES:
        print(f"  {name:25s} = {feats[name]:.6f}")
    found += 1
    if found >= 3:
        break

c.close()
print(f"\nDone. Extracted {found} events.")
