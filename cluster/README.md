# CLIF Cluster — Multi-Machine Deployment Guide

Deploy CLIF services across two machines on the same LAN.
Supports three modes:

| Mode | Compose files | When to use |
|------|---------------|-------------|
| **Single-machine** | `docker-compose.yml` | Dev / small-scale |
| **PC1 + PC2** (Windows × 2) | `pc1.yml` + `pc2.yml` | Two identical Windows PCs |
| **PC1 + MacBook M1** | `pc1.yml` + `mac.yml` | Windows data tier + ARM compute |

---

## Option A — PC1 (Windows) + PC2 (Windows)

Right-sized for **6C/12T (12 logical CPUs), 16 GB RAM** per machine.

### Architecture

```
┌──────────────────────────────────────┐    LAN    ┌──────────────────────────────────────┐
│  PC1  —  DATA & MESSAGE TIER         │◄──────────►│  PC2  —  COMPUTE & PRESENTATION     │
│  (11.75 CPUs / 14.6G)               │           │  (11.5 CPUs / 10.3G)                │
│                                      │           │                                      │
│  Redpanda ×3   (19092/29092/39092)   │           │  Vector    ×1  (1514, 8687, 9514)   │
│  ClickHouse ×2 (8123, 9000)         │           │  Triage    ×2  (8300, 8301)          │
│  CH Keeper     (12181)               │           │  LanceDB   ×1  (8100) [--profile]   │
│  MinIO ×3      (9002)               │           │  Merkle    ×1  (internal)            │
│  Consumer ×2   (internal)           │           │  RP Console    (8080)                │
│                                      │           │  Prometheus    (9090)                │
│  12 services (2 one-shot)           │           │  Grafana       (3002)                │
│                                      │           │  Dashboard     (3001, native npm)   │
│  KEY WIN: Consumer → ClickHouse     │           │                                      │
│  runs with ZERO LAN hops!           │           │  7 services + Next.js dashboard      │
└──────────────────────────────────────┘           └──────────────────────────────────────┘
```

**Data flow:** Logs → Vector (PC2:1514) →LAN→ Redpanda (PC1) → Consumer (PC1) → ClickHouse (PC1)
**Only 1 LAN hop** on the ingestion hot path (Vector→Redpanda).

---

## Option B — PC1 (Windows) + MacBook M1

Right-sized for **PC1: 6C/12T, 16 GB** (Windows) + **MacBook: 8 CPU, 16 GB** (ARM64).
All Docker base images are multi-arch; custom Python images build natively on ARM.

### Architecture

```
┌──────────────────────────────────────┐    LAN    ┌──────────────────────────────────────┐
│  PC1  —  DATA & MESSAGE TIER         │◄──────────►│  MacBook M1 — COMPUTE & PRESENT.    │
│  Windows (11.75 CPUs / 14.6G)       │           │  macOS ARM64 (7.5 CPUs / 13.5G)     │
│                                      │           │                                      │
│  Redpanda ×3   (19092/29092/39092)   │           │  Vector    ×1  (1514, 8687, 9514)   │
│  ClickHouse ×2 (8123, 9000)         │           │  Triage    ×4  (8300–8303)           │
│  CH Keeper     (12181)               │           │  Hunter    ×1  (internal)            │
│  MinIO ×3      (9002)               │           │  LanceDB   ×1  (8100) [--profile]   │
│  Consumer ×2   (internal)           │           │  Merkle    ×1  (internal)            │
│                                      │           │  RP Console    (8080)                │
│  12 services (2 one-shot)           │           │  Prometheus    (9090)                │
│                                      │           │  Grafana       (3002)                │
│  KEY WIN: Consumer → ClickHouse     │           │                                      │
│  runs with ZERO LAN hops!           │           │  10 services (+ LanceDB optional)    │
└──────────────────────────────────────┘           └──────────────────────────────────────┘
```

**Data flow:** Logs → Vector (Mac:1514) →LAN→ Redpanda (PC1) → Consumer (PC1) → ClickHouse (PC1)
**Triage scores → Hunter:** Triage (Mac) → Redpanda (PC1) → Hunter (Mac)
**ARM64 advantage:** M1's unified memory + NEON SIMD gives efficient ONNX inference for 4 Triage agents.

### MacBook Memory Budget

| Service | CPU Limit | RAM Limit | Reservation |
|---------|-----------|-----------|-------------|
| Vector | 2.0 | 2 GB | 1 GB |
| Triage Agent ×4 | 1.5 each (6.0) | 2 GB each (8 GB) | 768 MB each |
| Hunter Agent | 1.5 | 1.5 GB | 512 MB |
| Merkle | 0.5 | 256 MB | 128 MB |
| Prometheus | 0.5 | 512 MB | 256 MB |
| Grafana | 0.25 | 256 MB | 128 MB |
| RP Console | 0.25 | 256 MB | — |
| LanceDB [full] | 1.0 | 2 GB | 768 MB |
| **Total (base)** | **7.5** | **12.8 GB** | **5.8 GB** |
| **Total (full)** | **8.5** | **14.8 GB** | **6.6 GB** |

> ~2.5 GB headroom for macOS kernel + Docker VM overhead (base profile).

---

## Prerequisites

### Option A — PC1 + PC2 (Windows × 2)

| Requirement | Both PCs |
|---|---|
| OS | Windows 10/11 |
| Docker Desktop | ≥ 4.25 (Compose v2) |
| RAM | ≥ 14 GB each |
| Network | Same LAN, can ping each other |
| Repo | CLIF repo cloned to same path |

### Option B — PC1 + MacBook M1

| Requirement | PC1 (Windows) | MacBook (M1) |
|---|---|---|
| OS | Windows 10/11 | macOS 13+ (Ventura) |
| Docker | Docker Desktop ≥ 4.25 | Docker Desktop for Mac ≥ 4.25 |
| CPU / RAM | 6C/12T, 16 GB | 8 cores, 16 GB |
| Network | Same LAN | Same LAN |
| Repo | CLIF repo cloned | CLIF repo cloned |

---

## Quick Start — Option A (PC1 + PC2)

### Step 1 — PC1 (Data Tier)

```powershell
cd C:\CLIF

# Auto-detect LAN IP and configure cluster
.\cluster\setup.ps1 -Role pc1

# Open firewall for PC2 (run as Administrator)
.\cluster\firewall-pc1.ps1

# Start data services
docker compose -f docker-compose.pc1.yml --env-file .env --env-file cluster\.env up -d

# Wait for healthy (all should show "healthy" in 60-90s)
docker compose -f docker-compose.pc1.yml ps
```

### Step 2 — PC2 (Compute Tier)

```powershell
cd C:\CLIF

# Configure with PC1's IP (e.g., 192.168.1.100)
.\cluster\setup.ps1 -Role pc2 -DataIP 192.168.1.100

# Start compute services
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d

# (Optional) Include Prometheus + Grafana:
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env --profile monitoring up -d

# Start the dashboard
cd dashboard
# Edit .env.local → set CH_HOST to PC1's IP (e.g., 192.168.1.100)
npm run dev
```

### Step 3 — Verify

```powershell
# Run from PC2 (tests both tiers + end-to-end pipeline)
.\cluster\health-check.ps1 -Role all -DataIP 192.168.1.100
```

---

## Quick Start — Option B (PC1 + MacBook M1)

### Step 1 — PC1 (Data Tier) — same as Option A

```powershell
cd C:\CLIF
.\cluster\setup.ps1 -Role pc1
.\cluster\firewall-pc1.ps1          # run as Administrator
docker compose -f docker-compose.pc1.yml --env-file .env --env-file cluster\.env up -d
```

### Step 2 — MacBook M1 (Compute Tier)

```bash
cd ~/CLIF          # or wherever you cloned the repo

# Setup: auto-detect LAN IP, test PC1 connectivity, write cluster/.env
chmod +x cluster/setup-mac.sh cluster/health-check-mac.sh
./cluster/setup-mac.sh --data-ip 192.168.1.100    # ← PC1's LAN IP

# Build & start compute services (first run builds ARM images ~5-10 min)
docker compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env up -d

# (Optional) Include LanceDB:
docker compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env --profile full up -d
```

### Step 3 — Verify (MacBook)

```bash
./cluster/health-check-mac.sh
```

### Adding Future Agents on MacBook

New agents follow a simple pattern — add to `docker-compose.mac.yml`:

```yaml
  new-agent:
    build: ./agents/new_agent
    <<: *pc1-hosts                    # resolves PC1 hostnames
    environment:
      KAFKA_BROKERS: "${DATA_IP}:19092,${DATA_IP}:29092,${DATA_IP}:39092"
      CLICKHOUSE_HOST: "${DATA_IP}"
    deploy:
      resources:
        limits: { cpus: '1.5', memory: 2G }
    restart: unless-stopped
```

---

## Dashboard Configuration

Edit `dashboard/.env.local` on PC2 or MacBook:

```env
CH_HOST=192.168.1.100    # ← PC1's LAN IP (was localhost)
CH_PORT=8123
CH_USER=clif_admin
CH_PASSWORD=Cl1f_Ch@ngeM3_2026!
LANCEDB_URL=http://localhost:8100
```

## Key Port Mappings (PC1 → LAN)

| Port | Service | Purpose |
|------|---------|---------|
| 19092 | Redpanda 01 | Kafka external |
| 29092 | Redpanda 02 | Kafka external |
| 39092 | Redpanda 03 | Kafka external |
| 8123 | ClickHouse 01 | HTTP API |
| 8124 | ClickHouse 02 | HTTP API |
| 9000 | ClickHouse 01 | Native protocol |
| 9001 | ClickHouse 02 | Native protocol |
| 9002 | MinIO 1 | S3 data |
| 9003 | MinIO 1 | Console |
| 9363 | ClickHouse 01 | Prometheus metrics |
| 9364 | ClickHouse 02 | Prometheus metrics |
| 9644 | Redpanda 01 | Admin API |
| 9645 | Redpanda 02 | Admin API |
| 9646 | Redpanda 03 | Admin API |

## Memory Budget

### PC1 — Data & Message Tier (12 CPUs / 16 GB)

| Service | CPU Limit | RAM Limit | Reservation |
|---------|-----------|-----------|-------------|
| ClickHouse Keeper | 0.5 | 512 MB | 256 MB |
| ClickHouse 01 | 2.0 | 3 GB | 1.5 GB |
| ClickHouse 02 | 1.0 | 2 GB | 1 GB |
| Redpanda ×3 | 1.5 each (4.5) | 2 GB each (6 GB) | 1.5 GB each |
| MinIO ×3 | 0.25 each (0.75) | 512 MB each (1.5 GB) | 128 MB each |
| Consumer ×2 | 1.5 each (3.0) | 768 MB each (1.5 GB) | 256 MB each |
| **Total** | **11.75** | **14.6 GB** | **6.6 GB** |

### PC2 — Compute & Presentation Tier (12 CPUs / 16 GB)

| Service | CPU Limit | RAM Limit | Reservation |
|---------|-----------|-----------|-------------|
| Vector | 5.0 | 3 GB | 1.5 GB |
| Triage Agent ×2 | 2.0 each (4.0) | 2 GB each (4 GB) | 768 MB each |
| LanceDB [full] | 1.0 | 2 GB | 768 MB |
| Merkle | 0.5 | 256 MB | 128 MB |
| Prometheus | 0.5 | 512 MB | 256 MB |
| Grafana | 0.25 | 256 MB | 128 MB |
| RP Console | 0.25 | 256 MB | — |
| Dashboard (npm) | ~1.0 | ~500 MB | — |
| **Total** | **11.5** | **10.3 GB** | **4.3 GB** |

## Running the Benchmark

```powershell
# Send logs to Vector on PC2 (from either PC)
# If running from PC1, target PC2's IP:
.\scripts\benchmark.ps1 -TargetHost <PC2_IP> -TargetPort 1514 -Duration 30

# If running from PC2 (localhost):
.\scripts\benchmark.ps1 -TargetHost localhost -TargetPort 1514 -Duration 30
```

## Troubleshooting

### PC2 services can't reach PC1
1. Check Windows Firewall: `Get-NetFirewallRule -DisplayName 'CLIF-*' | Format-Table`
2. Test connectivity: `Test-NetConnection -ComputerName <PC1_IP> -Port 19092`
3. Ensure both PCs are on same subnet (e.g., 192.168.1.x)

### MacBook can't reach PC1
1. Check Windows Firewall allows PC1 ports (run `firewall-pc1.ps1` as Admin)
2. Test from Mac terminal: `nc -z <PC1_IP> 19092 && echo OK`
3. Re-run setup: `./cluster/setup-mac.sh --data-ip <PC1_IP>`

### Redpanda Console shows no brokers
- The console uses hostnames `pc1-rp01:19092` etc. resolved via `extra_hosts`
- Verify `DATA_IP` in `cluster/.env` is correct
- Restart: `docker compose -f docker-compose.pc2.yml restart redpanda-console`
- On Mac: `docker compose -f docker-compose.mac.yml restart redpanda-console`

### Dashboard shows "connection refused"
- Edit `dashboard/.env.local` → `CH_HOST` must be PC1's LAN IP, not `localhost`
- Restart dashboard: `npm run dev`

### Falling back to single-machine mode
```bash
# Stop cluster (Windows)
docker compose -f docker-compose.pc1.yml down   # on PC1
docker compose -f docker-compose.pc2.yml down   # on PC2

# Stop cluster (MacBook)
docker compose -f docker-compose.mac.yml down    # on Mac

# Use original single-machine compose
docker compose up -d
```

## File Reference

```
CLIF/
├── docker-compose.yml          ← Original single-machine (unchanged)
├── docker-compose.pc1.yml      ← PC1 data tier (Windows)
├── docker-compose.pc2.yml      ← PC2 compute tier (Windows)
├── docker-compose.mac.yml      ← MacBook M1 compute tier (ARM64)
├── .env                        ← Shared credentials (all machines)
└── cluster/
    ├── .env                    ← Cluster-specific (DATA_IP, memory tuning)
    ├── setup.ps1               ← Windows interactive setup
    ├── setup-mac.sh            ← macOS setup (auto-detect IP, test connectivity)
    ├── health-check.ps1        ← Windows cross-cluster health check
    ├── health-check-mac.sh     ← macOS health check (local + remote)
    ├── firewall-pc1.ps1        ← Windows Firewall rules (run as Admin)
    ├── monitoring/
    │   ├── prometheus.yml      ← Prometheus config (cross-host targets)
    │   └── grafana-datasources.yml
    └── redpanda/
        └── console-config.yml  ← Console broker config (uses pc1-rpXX hosts)
```
