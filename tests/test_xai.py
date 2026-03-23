import json, urllib.request

data = json.dumps({
    "duration":0,"protocol":6,"src_bytes":0,"dst_bytes":0,
    "count":511,"srv_count":511,"serror_rate":1.0,"same_srv_rate":1.0,
    "diff_srv_rate":0,"dst_host_count":255,"dst_host_srv_count":255,
    "dst_host_same_srv_rate":1.0,"rerror_rate":0,"dst_host_diff_srv_rate":0,
    "dst_host_serror_rate":1.0,"dst_host_srv_serror_rate":1.0,
    "dst_host_rerror_rate":0,"dst_host_srv_rerror_rate":0,
    "hour_of_day":3,"is_weekend":0,"log_length":100
}).encode()
req = urllib.request.Request("http://10.180.247.241:8200/explain", data=data, headers={"Content-Type":"application/json"})
r = urllib.request.urlopen(req, timeout=10)
d = json.loads(r.read())
print(f"Attack: {d['is_attack']} | Severity: {d['severity']} | Confidence: {d['confidence']}")
print("Top features:")
for f in d["xai"]["top_features"][:5]:
    print(f"  {f['feature']:30s} delta={f['score_delta']:.4f}")
