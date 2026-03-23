"""Replace KAFKA_OFFSET_RESET earliest -> latest in docker-compose.yml"""
import pathlib, re

p = pathlib.Path(r"C:\CLIF\docker-compose.yml")
text = p.read_text(encoding="utf-8")
text2, n = re.subn(
    r'KAFKA_OFFSET_RESET:\s*"earliest"',
    'KAFKA_OFFSET_RESET: "latest"',
    text,
)
p.write_text(text2, encoding="utf-8")
print(f"Replaced {n} occurrences")
