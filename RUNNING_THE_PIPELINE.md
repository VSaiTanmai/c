# CLIF — Running the Full Pipeline

> **Two-machine setup**: Windows PC (data tier) + MacBook M1 (compute/AI tier)  
> Both machines must be on the same LAN.

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐   LAN (same network)   ┌────────────────────────────────┐
│          PC1 — Windows (Data Tier)          │◄──────────────────────►│    Mac M1 (Compute Tier)       │
│                                             │                        │                                │
│  Redpanda ×3  ──►  Go Consumer ×2           │                        │  Vector (log shipper)          │
│  ClickHouse ×2     MinIO ×2                 │                        │  Triage Agent  (port 8300)     │
│  ClickHouse Keeper Merkle Service           │                        │  Hunter Agent  (port 8400)     │
│  Redpanda Console  Prometheus / Grafana     │                        │  Verifier Agent(port 8500)     │
│  Next.js Dashboard (port 3002)              │                        │  XAI Service   (port 8200)     │
│                                             │                        │  LanceDB       (port 8100)     │
│                                             │                        │  Prometheus / Grafana          │
└─────────────────────────────────────────────┘                        └────────────────────────────────┘
```

---

## Prerequisites

| Machine | Requirements |
|---------|-------------|
| **PC1 (Windows)** | Docker Desktop ≥ 4.x, 16 GB RAM, 20 GB free disk, Git |
| **Mac M1** | Docker Desktop ≥ 4.x (Apple Silicon), 16 GB RAM, Git |

Both machines need:
- Docker Desktop **running** before any commands
- Both on the **same LAN/Wi-Fi** subnet
- Firewall ports open (see [Firewall Rules](#firewall-rules))

---

## Step 1 — Clone the Repository (both machines)

**PC1 — PowerShell:**
```powershell
git clone https://github.com/Nethrananda21/clif-log-investigation.git C:\CLIF
cd C:\CLIF
```

**Mac — Terminal:**
```bash
git clone https://github.com/Nethrananda21/clif-log-investigation.git ~/clif
cd ~/clif
```

---

## Step 2 — Configure Environment

### PC1 (Windows)

```powershell
# Copy the example env file
Copy-Item .env.example .env
```

Edit `.env` and change the credentials (at minimum):
```env
CLICKHOUSE_PASSWORD=Cl1f_Ch@ngeM3_2026!
MINIO_ROOT_PASSWORD=Cl1f_M1n10_2026!
GRAFANA_ADMIN_PASSWORD=Cl1f_Gr@f_2026!
```

Then run the interactive cluster setup — it auto-detects your LAN IP:
```powershell
.\cluster\setup.ps1 -Role pc1
```

This writes `cluster/.env` with `DATA_IP` set to PC1's LAN IP (e.g. `10.180.247.221`).

> To find PC1's LAN IP manually: `ipconfig | findstr IPv4`

### Mac

```bash
chmod +x cluster/setup-mac.sh
./cluster/setup-mac.sh
# When prompted, enter PC1's LAN IP (e.g. 10.180.247.221)
```

Or non-interactive:
```bash
./cluster/setup-mac.sh --data-ip 10.180.247.221
```

This writes `cluster/.env` with `DATA_IP=<PC1 IP>`.

---

## Step 3 — Start PC1 (Data Tier)

Run on PC1 in PowerShell from `C:\CLIF`:

```powershell
docker compose -f docker-compose.pc1.yml --env-file .env --env-file cluster/.env up -d
```

This starts the following containers:

| Container | Role | Port |
|-----------|------|------|
| `clif-keeper` | ClickHouse coordination | 12181 |
| `clickhouse01` | ClickHouse node 1 | 8123 (HTTP), 9000 (native) |
| `clickhouse02` | ClickHouse node 2 | — (internal) |
| `redpanda01/02/03` | Kafka-compatible event bus | 9092 (internal), 19092 (external) |
| `redpanda-init` | Creates all 14 topics (exits after) | — |
| `clif-console` | Redpanda web UI | 8080 |
| `minio1 / minio2` | S3-compatible object store | 9002 (data), 9003 (console) |
| `minio-mc` | Bucket initialiser (exits after) | — |
| `clif-consumer` | Go consumer: Redpanda → ClickHouse | — |
| `clif-consumer-2` | Go consumer #2 (horizontal scale) | — |
| `clif-merkle` | Merkle evidence anchoring service | 8600 |

Wait for ClickHouse and Redpanda to be healthy before proceeding (~60–90 seconds):

```powershell
docker compose -f docker-compose.pc1.yml ps
```

All services should show `healthy` or `running`.

---

## Step 4 — Start Mac (Compute Tier)

Run on the Mac from `~/clif`:

```bash
# Standard — Vector + Triage + Hunter + Verifier + XAI + Monitoring
docker compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env up -d

# Full — includes LanceDB semantic search (requires more RAM)
docker compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env --profile full up -d
```

This starts:

| Container | Role | Port |
|-----------|------|------|
| `clif-vector` | Log ingestion & shipper → Redpanda on PC1 | 8686 (API), 1514 (syslog) |
| `clif-triage-1..4` | ML triage agents (4 workers) | 8300–8303 |
| `clif-hunter` | Attack investigation agent | 8400 |
| `clif-verifier` | Evidence verification agent | 8500 |
| `clif-xai` | SHAP explainability service | 8200 |
| `clif-lancedb` *(full profile)* | Vector semantic search | 8100 |
| `prometheus` | Metrics collection | 9090 |
| `grafana` | Dashboards | 3002 |

---

## Step 5 — Start Dashboard (PC1)

```powershell
cd C:\CLIF\dashboard
Copy-Item .env.local.example .env.local   # if not already done
# Edit .env.local — set Mac's IP for AI service URLs:
# AI_SERVICE_URL=http://10.180.247.241:8200
# LANCEDB_URL=http://10.180.247.241:8100
# PROMETHEUS_URL=http://10.180.247.241:9090

npm install
npx next dev -p 3002
```

Open: **http://localhost:3002**

> For production use: `npm run build && npm start`

---

## Step 6 — Verify Everything is Running

### Health Check — PC1 (PowerShell)

```powershell
.\cluster\health-check.ps1 -Role pc1
```

### Health Check — Mac (Terminal)

```bash
./cluster/health-check-mac.sh
```

### Manual spot checks

**PC1:**
```powershell
# ClickHouse
curl http://localhost:8123/ping            # → "Ok."

# Redpanda
curl http://localhost:9644/v1/status/ready # → {"status":"ready"}

# Redpanda Console UI
start http://localhost:8080
```

**Mac:**
```bash
curl http://localhost:8300/health   # Triage Agent → {"status":"ok"}
curl http://localhost:8400/health   # Hunter Agent → {"status":"ok"}
curl http://localhost:8500/health   # Verifier Agent
curl http://localhost:8200/health   # XAI Service
curl http://localhost:8686/health   # Vector
```

---

## Service Port Reference

### PC1 — Windows

| Service | Port | URL |
|---------|------|-----|
| ClickHouse HTTP | 8123 | `http://localhost:8123` |
| ClickHouse Native | 9000 | — |
| Redpanda Kafka (external) | 19092 | — |
| Redpanda Admin | 9644 | `http://localhost:9644` |
| Redpanda Console | 8080 | `http://localhost:8080` |
| MinIO Console | 9003 | `http://localhost:9003` |
| MinIO Data | 9002 | — |
| Merkle Service | 8600 | `http://localhost:8600` |
| Dashboard (Next.js) | 3002 | `http://localhost:3002` |

### Mac

| Service | Port | URL |
|---------|------|-----|
| Triage Agent 1 | 8300 | `http://localhost:8300/health` |
| Triage Agent 2 | 8301 | `http://localhost:8301/health` |
| Triage Agent 3 | 8302 | `http://localhost:8302/health` |
| Triage Agent 4 | 8303 | `http://localhost:8303/health` |
| Hunter Agent | 8400 | `http://localhost:8400/health` |
| Verifier Agent | 8500 | `http://localhost:8500/health` |
| XAI / SHAP | 8200 | `http://localhost:8200/health` |
| LanceDB | 8100 | `http://localhost:8100/health` |
| Prometheus | 9090 | `http://localhost:9090` |
| Grafana | 3002 | `http://localhost:3002` |
| Vector API | 8686 | `http://localhost:8686/health` |
| Vector Syslog | 1514 | TCP (UDP) |

---

## Firewall Rules

PC1 must allow **inbound** connections from the Mac on these ports:

```powershell
# Run on PC1 as Administrator
$mac_ip = "10.180.247.241"   # replace with your Mac's actual IP

$ports = @(19092, 29092, 39092, 8123, 9000, 9002, 9003, 9363, 9364, 9644, 9645, 9646, 8080, 8600)

foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "CLIF-$port" `
        -Direction Inbound -Protocol TCP `
        -LocalPort $port `
        -RemoteAddress $mac_ip `
        -Action Allow -ErrorAction SilentlyContinue
}
```

Or use the provided helper:
```powershell
.\cluster\firewall-pc1.ps1
```

---

## Stopping the Stack

**PC1:**
```powershell
docker compose -f docker-compose.pc1.yml down
```

**Mac:**
```bash
docker compose -f docker-compose.mac.yml down
```

To also remove volumes (clears all data):
```powershell
# PC1
docker compose -f docker-compose.pc1.yml down -v

# Mac
docker compose -f docker-compose.mac.yml down -v
```

---

## Rebuilding After Code Changes

Agent code lives in `agents/`, consumer in `consumer-go/`. After editing:

**PC1:**
```powershell
docker compose -f docker-compose.pc1.yml --env-file .env --env-file cluster/.env up -d --build clif-consumer clif-consumer-2
```

**Mac:**
```bash
docker compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env up -d --build clif-triage clif-hunter clif-verifier clif-xai
```

---

## Single-Machine Mode (development only)

If you only have one machine, use the combined dev compose file:

```bash
# Both tiers on one machine (reduced resource limits)
docker compose -f docker-compose.yml up -d
```

> This is for development/testing only. Performance will be limited compared to the two-machine setup.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Mac agents can't reach Redpanda | Check `DATA_IP` in `cluster/.env`. Run `nc -z <PC1_IP> 19092` on Mac |
| ClickHouse not healthy | Keeper must start first. Check: `docker logs clif-keeper` |
| Topics not created | Check `redpanda-init` logs: `docker logs clif-redpanda-init` |
| Triage "model not found" | Ensure model files are in `agents/triage/` (check git LFS) |
| Dashboard shows no data | Check `dashboard/.env.local` has correct CH credentials and Mac IP for AI/LanceDB |
| Port already in use | Stop old containers: `docker ps -a` → `docker rm -f <id>` |
| Mac: "exec format error" | Rebuild with `--platform linux/arm64` flag or pull updated images |

---

## Data Flow Summary

```
Syslog/logs ──► Vector (Mac:1514)
                    │
                    ▼
              Redpanda (PC1:19092) ◄── external producers
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
   Go Consumer ×2         Triage Agents (Mac)
   (PC1 → ClickHouse)         │
          │              Anomaly Alerts
          ▼                    │
    ClickHouse ◄───────────────┘
     clif_logs DB        Hunter Agent (Mac)
          │                    │
          │              Evidence chain
          ▼                    │
     Merkle Service ◄──────────┘
     LanceDB (Mac)
          │
          ▼
     Dashboard (PC1:3002)
     XAI / SHAP (Mac:8200)
```
