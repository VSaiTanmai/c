"""Replace anomalous threshold 0.70 -> 0.89 in docker-compose.yml"""
import pathlib, re

p = pathlib.Path(r"C:\CLIF\docker-compose.yml")
text = p.read_text(encoding="utf-8")
text2, n = re.subn(
    r'DEFAULT_ANOMALOUS_THRESHOLD:\s*"0\.70"',
    'DEFAULT_ANOMALOUS_THRESHOLD: "0.89"',
    text,
)
p.write_text(text2, encoding="utf-8")
print(f"Replaced {n} occurrences")
