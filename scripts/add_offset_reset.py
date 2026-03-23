"""Add KAFKA_OFFSET_RESET=earliest to all triage agent env blocks."""
import re

path = r"C:\CLIF\docker-compose.yml"
with open(path, "rb") as f:
    data = f.read()

# Insert KAFKA_OFFSET_RESET after SCORE_WEIGHTS line in each triage block
old = b'SCORE_WEIGHTS: "lgbm=0.80,eif=0.12,arf=0.08"'
new = b'SCORE_WEIGHTS: "lgbm=0.80,eif=0.12,arf=0.08"\n      KAFKA_OFFSET_RESET: "earliest"'

count = data.count(old)
print(f"Found {count} occurrences of SCORE_WEIGHTS line")
data = data.replace(old, new)

with open(path, "wb") as f:
    f.write(data)

print(f"Added KAFKA_OFFSET_RESET=earliest to {count} blocks")
