"""Update docker-compose.yml for v6.0.0 deployment."""
import pathlib

path = pathlib.Path(r"C:\CLIF\docker-compose.yml")
data = path.read_bytes()

replacements = [
    (b"lgbm_v4.0.0.onnx", b"lgbm_v6.0.0.onnx"),
    (b"eif_v4.0.0.pkl", b"eif_v6.0.0.pkl"),
    (b"arf_v4.0.0.pkl", b"arf_v6.0.0.pkl"),
    (b'DEFAULT_SUSPICIOUS_THRESHOLD: "0.18"', b'DEFAULT_SUSPICIOUS_THRESHOLD: "0.39"'),
]

for old, new in replacements:
    count = data.count(old)
    data = data.replace(old, new)
    print(f"  {old.decode()} -> {new.decode()}: {count} replacements")

path.write_bytes(data)
print("Done — docker-compose.yml updated for v6.0.0")
