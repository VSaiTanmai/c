"""Update docker-compose.yml model paths and thresholds (byte-safe)."""
path = r"C:\CLIF\docker-compose.yml"

with open(path, "rb") as f:
    data = f.read()

# Model paths: v3.0.0 -> v4.0.0
data = data.replace(b"lgbm_v3.0.0.onnx", b"lgbm_v4.0.0.onnx")
data = data.replace(b"eif_v3.0.0.pkl", b"eif_v4.0.0.pkl")
data = data.replace(b"arf_v3.0.0.pkl", b"arf_v4.0.0.pkl")

# Suspicious threshold: 0.19 -> 0.18
old = b'DEFAULT_SUSPICIOUS_THRESHOLD: "0.19"'
new = b'DEFAULT_SUSPICIOUS_THRESHOLD: "0.18"'
data = data.replace(old, new)

# Scoring comment update
data = data.replace(b"Scoring (v5", b"Scoring (v6")
data = data.replace(b"2026-03-05)", b"2026-03-06)")

with open(path, "wb") as f:
    f.write(data)

# Verify
with open(path, "rb") as f:
    content = f.read()

for pat in [b"lgbm_v4.0.0", b"eif_v4.0.0", b"arf_v4.0.0"]:
    print(f"  {pat.decode()}: {content.count(pat)} occurrences")
cnt_18 = content.count(b'"0.18"')
cnt_70 = content.count(b'"0.70"')
print(f"  suspicious 0.18: {cnt_18}")
print(f"  anomalous  0.70: {cnt_70}")
print("docker-compose.yml updated successfully")
