import json, urllib.request
r = urllib.request.urlopen("http://localhost:9090/api/v1/targets", timeout=5)
d = json.loads(r.read())
targets = d["data"]["activeTargets"]
for t in targets:
    job = t["labels"].get("job", "?")
    health = t["health"]
    dur = t.get("lastScrapeDuration", "?")
    print(f"  {job:30s} {health:6s} {dur}")
print(f"\nTotal active targets: {len(targets)}")
