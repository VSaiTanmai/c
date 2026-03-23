"""Debug: dump raw event JSON from security-events topic."""
import json, sys
sys.path.insert(0, "/app")

from confluent_kafka import Consumer
c = Consumer({
    "bootstrap.servers": "redpanda01:9092",
    "group.id": "debug-raw-event-tmp",
    "auto.offset.reset": "earliest",
})
c.subscribe(["security-events"])

found = 0
for _ in range(50):
    msg = c.poll(3.0)
    if msg is None or msg.error():
        continue
    try:
        event = json.loads(msg.value().decode("utf-8"))
    except Exception:
        continue
    print(f"--- Event {found+1} from {msg.topic()} ---")
    print(json.dumps(event, indent=2, default=str)[:2000])
    found += 1
    if found >= 2:
        break

c.close()
print(f"\nDone. {found} events.")
