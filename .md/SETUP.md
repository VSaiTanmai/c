# CLIF — Quick Setup Guide

> Get the full pipeline running from a fresh clone.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Docker Desktop** | v4.25+ (WSL2 backend on Windows) | Latest stable |
| **RAM allocated to Docker** | 12 GB | 16 GB |
| **Free disk** | 20 GB | 40 GB |
| **Node.js** (dashboard only) | v18+ | v20 LTS |

> **Resource note:** The full compose file defines ~22 services with generous limits.
> Docker Desktop → Settings → Resources → set Memory to at least **12 GB**.
> If your machine has < 16 GB total RAM, see [Lightweight Mode](#lightweight-mode) below.

---

## 1. Clone & Start (Single Machine)

```bash
git clone <repo-url> CLIF
cd CLIF

# Start the core pipeline (Redpanda, ClickHouse, Vector, Consumer, Triage Agent)
docker compose up -d
```

Docker Compose will:
1. Build consumer, triage-agent, vector, and merkle images
2. Start ClickHouse (2-node + Keeper) and Redpanda (3 brokers)
3. Run `redpanda-init` (creates 14 topics) and `clickhouse-init` (creates 24+ tables)
4. Start the consumer and triage agent pipelines

Check health:
```bash
docker compose ps          # All services should be "healthy" or "running"
docker compose logs -f --tail=50 clif-consumer       # Should show "Flushed" messages
docker compose logs -f --tail=50 clif-triage-agent-01 # Should show scoring events
```

### Dashboard (separate terminal)

```bash
cd dashboard
npm install
npm run dev
# → http://localhost:3000
```

---

## 2. Two-PC Cluster Mode (Advanced)

CLIF supports splitting across two machines:
- **PC1** (Data Tier): ClickHouse, Redpanda, MinIO, Consumer
- **PC2** (Compute Tier): Vector, Triage Agents, LanceDB, Dashboard

### PC1 — Data Node

```bash
docker compose -f docker-compose.yml up -d
```

### PC2 — Compute Node

1. Edit `cluster/.env` — set `DATA_IP` to PC1's LAN IP:
   ```bash
   # Find PC1's IP:  ipconfig | findstr IPv4   (Windows)
   #                  ip addr show              (Linux)
   DATA_IP=192.168.1.100   # ← replace with actual PC1 IP
   ```

2. Start PC2 services:
   ```bash
   docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster/.env up -d
   ```

---

## 3. Verify the Pipeline

### Send test events through the triage agent

```bash
# Known attack patterns (6 events — exfil, mimikatz, brute-force, etc.)
python scripts/test_triage_attacks.py

# Novel zero-day anomalies (5 events — never seen in training data)
python scripts/test_novel_anomalies.py
```

### Query ClickHouse for scored results

```bash
docker exec clif-clickhouse01 clickhouse-client --user clif_admin \
  --password "Cl1f_Ch@ngeM3_2026!" \
  --query "SELECT event_id, final_score, verdict FROM clif_logs.triage_scores ORDER BY scored_at DESC LIMIT 20"
```

---

## 4. Key Endpoints

| Service | URL | Notes |
|---------|-----|-------|
| ClickHouse HTTP | http://localhost:8123 | `clif_admin` / see `.env` |
| Redpanda Console | http://localhost:8080 | Topic browser |
| Prometheus | http://localhost:9090 | Metrics |
| Grafana | http://localhost:3002 | `admin` / see `.env` |
| Dashboard | http://localhost:3000 | `npm run dev` required |
| Triage Agent | http://localhost:8300 | `/health`, `/stats`, `/ready` |
| Vector API | http://localhost:8686 | Aggregator metrics |

---

## 5. Configuration Reference

All tunables are in `.env`. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `REDPANDA_REPLICATION_FACTOR` | 1 | Set to 3 if running all 3 Redpanda brokers |
| `REDPANDA_PARTITIONS` | 12 | Topic partition count |
| `CONSUMER_BATCH_SIZE` | 200000 | Events per ClickHouse flush batch |
| `CONSUMER_FLUSH_INTERVAL_SEC` | 0.5 | Max seconds between flushes |

---

## 6. Triage Agent Models

Pre-trained model artifacts are in `agents/triage/models/`:

| File | Description |
|------|-------------|
| `lgbm_v2.0.0.onnx` | LightGBM classifier (ONNX, weight 60%) |
| `eif_v2.0.0.pkl` | Extended Isolation Forest (pickle, weight 15%) |
| `arf_v2.0.0.pkl` | Adaptive Random Forest (pickle, weight 25%) |
| `manifest.json` | Active model versions and config |

These are git-tracked and mounted read-only into the container at `/models`.

Score thresholds: `suspicious >= 0.39`, `anomalous >= 0.89`

---

## Lightweight Mode

If your machine has limited resources, you can start only the essential services:

```bash
# Start just the data backbone
docker compose up -d redpanda01 clickhouse-keeper clickhouse01 clickhouse02

# Wait for health checks, then start the pipeline
docker compose up -d redpanda-init clif-consumer clif-triage-agent-01

# Start Vector for log ingestion
docker compose up -d vector
```

This skips: redpanda02/03, MinIO (3 nodes), extra consumers/triage agents, monitoring stack.

Minimum resources: **4 CPU cores, 8 GB RAM** allocated to Docker.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `redpanda-init` exits with topic errors | Redpanda not ready yet — it auto-retries. Check `docker compose logs redpanda-init` |
| ClickHouse schema errors on startup | Keeper must be healthy first. Run `docker compose restart clickhouse01 clickhouse02` |
| Triage agent "no brokers" | Redpanda not up. Check `docker compose ps redpanda01` |
| MinIO unhealthy | MinIO cluster needs all 3 nodes. Non-blocking — pipeline works without it (cold storage disabled) |
| Consumer `Code:60` errors | ClickHouse table missing. Tables auto-create on first start; if not, run schema manually: `docker exec clif-clickhouse01 clickhouse-client --multiquery < clickhouse/schema.sql` |
| Windows: `/var/log` mount warning | Expected — host log collection only works on Linux. Pipeline functions normally without it |
