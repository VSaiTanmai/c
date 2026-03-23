# CLIF — Cognitive Log Investigation Framework

> **Agentic SIEM Platform** — Enterprise SOC with AI-powered threat detection, autonomous investigation & explainable verdicts  
> High-throughput log pipeline (ClickHouse + Redpanda + MinIO), Go-based Kafka consumers, AI agent pipeline (Triage → Hunter → Verifier) with SHAP-based XAI, Merkle evidence chain, 14-page SOC dashboard, 2-PC deployment (Windows + Mac M1), Prometheus/Grafana monitoring.  
> **Full pipeline validated: 3.88M triage scores, 7,476 investigations, 1,365 verified verdicts — 26,586 EPS sustained, 0% data loss**

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                         Log Producers                                 │
│   (Vector aggregator — syslog/HTTP/Docker/File sources)               │
└────────────────────────────┬──────────────────────────────────────────┘
                             │  Kafka protocol
                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Redpanda Cluster  (3 brokers, Kafka-compatible, C++ native)          │
│                                                                       │
│  Topics (14): raw-logs │ security-events │ process-events             │
│    network-events │ triage-scores │ hunter-tasks │ hunter-results     │
│    verifier-results │ evidence-events │ + 5 more                     │
│    6 partitions each, RF=3, 7-day retention, LZ4                     │
└──────────────┬─────────────────────────────────────┬─────────────────┘
               │                                     │
               ▼                                     ▼
┌──────────────────────────────┐  ┌────────────────────────────────────┐
│  Go Consumer ×2              │  │  Triage Agent ×4 (ML ensemble)     │
│  (Kafka→ClickHouse writer)   │  │                                    │
│                              │  │  LightGBM ONNX (80%) + EIF (12%)  │
│  • Multi-topic subscription  │  │  + River ARF+ADWIN (8%)            │
│  • Columnar batch inserts    │  │  • v6.0.0, F1=0.9469, 19 features │
│  • 0 errors, 0 parse drops   │  │  • SHAP explainability on escalate │
│  • Zero consumer lag          │  │  • Drain3 template mining          │
│  • Handles triage,hunter,     │  │  • Score fusion + CI bounds        │
│    verifier, raw, network,   │  │  • Port 8300                       │
│    security, evidence topics │  │                                    │
└──────────────┬───────────────┘  └──┬──────────────────────────┬──────┘
               │                     │ escalated (score≥0.95)    │
               │                     ▼                           │
               │  ┌──────────────────────────────────────┐       │
               │  │  Hunter Agent                         │      │
               │  │                                       │      │
               │  │  • Sigma rule matching                │      │
               │  │  • SPC anomaly detection              │      │
               │  │  • Entity graph correlation           │      │
               │  │  • Temporal pattern analysis          │      │
               │  │  • Fusion scoring → severity rating   │      │
               │  │  • 7,476 investigations to date       │      │
               │  │  • Port 8400                          │      │
               │  └──────────┬───────────────────────────┘      │
               │             │ hunter-results                    │
               │             ▼                                   │
               │  ┌──────────────────────────────────────┐       │
               │  │  Verifier Agent                       │      │
               │  │                                       │      │
               │  │  • Fact-checking & evidence assembly  │      │
               │  │  • Confidence scoring                │      │
               │  │  • Report narrative generation        │      │
               │  │  • Analyst summary + evidence JSON   │      │
               │  │  • 1,365 verdicts (100% XAI coverage)│      │
               │  │  • Port 8500                          │      │
               │  └──────────┬───────────────────────────┘      │
               │             │                                   │
               ▼             ▼                                   │
┌────────────────────────────────┐                               │
│  ClickHouse Cluster            │  ┌────────────────────────┐   │
│  (2-node replicated shard)     │  │  XAI Service           │◀──┘
│                                │  │  (SHAP Explanations)   │
│  26 Tables:                    │  │                        │
│  • raw_logs                    │  │  • /explain endpoint   │
│  • security_events             │  │  • Waterfall charts    │
│  • network_events              │  │  • Category attribution│
│  • triage_scores (3.88M)       │  │  • 19 features, v6.0.0│
│  • hunter_investigations (7.5K)│  │  • Port 8200           │
│  • verifier_results (1.4K)     │  └────────────────────────┘
│  • evidence_anchors (51)       │
│  • events_per_minute (MV)      │  ┌────────────────────────┐
│  • + 18 more tables            │  │  Merkle Agent          │
│                                │  │  (Evidence Chain)      │
│  Tiered storage:               │  │                        │
│  hot → warm → cold (S3/MinIO)  │  │  • SHA-256 trees       │
└────────────────┬───────────────┘  │  • Batch anchoring     │
                 │  S3 API          │  • S3 Object Lock      │
                 ▼                  │  • 51 anchors to date  │
┌───────────────────────────────┐   └────────────────────────┘
│  MinIO Cluster  (3 nodes)     │
│  Erasure coded                │   ┌────────────────────────┐
│  Buckets: clif-cold-logs      │   │  Monitoring            │
│    clif-backups               │   │  Prometheus (9090)     │
│    clif-evidence-archive      │   │  Grafana (3002)        │
└───────────────────────────────┘   │  11 targets, 9 UP     │
                                    └────────────────────────┘
```
```

---

## Implementation Status

| Layer | Component | Status | Details |
|-------|-----------|--------|---------|
| **Collection** | Vector (aggregator) | ✅ Live | Syslog/HTTP/Docker/File → Redpanda, dedup transforms |
| **Streaming** | Redpanda (3-node) | ✅ Live | 3 brokers, 14 topics, 6 partitions each, RF=3, 0 lag |
| **Ingestion** | Go Consumers (×2) | ✅ Live | Multi-topic subscription, columnar batch inserts, 0 errors/drops |
| **Storage** | ClickHouse (2-node) | ✅ Live | 26 tables, 2-node replicated cluster, 0 replication lag |
| **Cold Storage** | MinIO (3-node) | ✅ Live | S3-compatible, erasure coded |
| **Evidence** | Merkle Agent | ✅ Live | SHA-256 trees, batch anchoring, S3 Object Lock, 51 anchors |
| **Intelligence** | Triage Agent (×4) | ✅ Live | v6.0.0, F1=0.9469, 3-model ensemble (LightGBM 80% + EIF 12% + ARF 8%), 19 features, SHAP on escalate, 3.88M scores |
| **Intelligence** | Hunter Agent | ✅ Live | Sigma rules, SPC anomaly detection, entity graph, temporal analysis, fusion scoring, 7,476 investigations |
| **Intelligence** | Verifier Agent | ✅ Live | Fact-checking, confidence scoring, report narratives, analyst summaries, 1,365 verdicts |
| **Intelligence** | XAI Service | ✅ Live | SHAP explanations, waterfall charts, category attribution, /explain endpoint |
| **Monitoring** | Prometheus + Grafana | ✅ Live | 11 scrape targets (9 UP), alert rules, Grafana v11.1.4 |
| **Dashboard** | Next.js 14 (14 pages) | ✅ Live | 6 fully real, 3 partial, 5 mock |
| **Deployment** | 2-PC Docker Compose | ✅ Live | PC1 (12 svc data tier) + Mac M1 (11 svc AI compute), 23 containers |
| **Deployment** | Kubernetes (Kustomize) | ✅ Ready | 59+ resources, 3 overlays (dev/staging/prod) |

---

## Docker Services (23 containers across 2 machines)

CLIF uses a **2-PC split deployment** for maximum performance:
- **PC1 — Windows** (`docker-compose.yml`) — Data tier: ClickHouse, Redpanda, MinIO, Vector, Go Consumers (12 services)
- **Mac M1** (`docker-compose.mac.yml`) — AI compute: Triage ×4, Hunter, Verifier, XAI, Merkle, monitoring (11 services)

### PC1 — Data Tier (Windows, 12 containers)

| Service | Container | Port | CPU | Description |
|---------|-----------|------|-----|-------------|
| ClickHouse Keeper | `clif-keeper01` | 2181 | 0.3 | Consensus for replication |
| ClickHouse Node 1 | `clif-clickhouse01` | 8123, 9000 | 2.0 | Primary shard |
| ClickHouse Node 2 | `clif-clickhouse02` | 8124, 9001 | 0.5 | Replica shard |
| Redpanda Broker 1 | `clif-redpanda01` | 19092 | 1.0 | Kafka-compatible broker |
| Redpanda Broker 2 | `clif-redpanda02` | 29092 | 1.0 | Kafka-compatible broker |
| Redpanda Broker 3 | `clif-redpanda03` | 39092 | 1.0 | Kafka-compatible broker |
| MinIO Node 1 | `clif-minio01` | 9002 | 0.1 | S3-compatible storage |
| MinIO Node 2 | `clif-minio02` | — | 0.1 | MinIO cluster member |
| MinIO Node 3 | `clif-minio03` | — | 0.1 | MinIO cluster member |
| Vector | `clif-vector01` | 8686 | 3.0 | Log aggregator/shipper |
| Go Consumer 1 | `clif-consumer01` | — | 0.5 | Kafka → ClickHouse writer |
| Go Consumer 2 | `clif-consumer02` | — | 0.5 | Kafka → ClickHouse writer |

### Mac M1 — AI Compute (11 containers)

| Service | Container | Port | CPU | Description |
|---------|-----------|------|-----|-------------|
| Triage Agent 1-4 | `clif-triage-agent-{1-4}` | 8300 | 1.75 each | ML ensemble scoring (×4 replicas) |
| Hunter Agent | `clif-hunter-agent` | 8400 | 1.75 | Autonomous threat investigation |
| Verifier Agent | `clif-verifier-agent` | 8500 | 1.0 | Verdict validation & report generation |
| XAI Service | `clif-xai-service` | 8200 | 0.5 | SHAP explainability API |
| Merkle Agent | `clif-merkle-agent` | — | 0.5 | Evidence chain anchoring |
| Prometheus | `clif-prometheus` | 9090 | 0.5 | Metrics collection |
| Grafana | `clif-grafana` | 3002 | 0.25 | Monitoring dashboards |
| Redpanda Console | `clif-redpanda-console` | 8080 | 0.25 | Redpanda web UI |

---

## The Multi-Agent Intelligence Pipeline

CLIF's core differentiator: four specialized AI agents that autonomously detect, investigate, verify, and explain security threats. **All agents are fully integrated, deployed, and validated.**

```
                    ┌─────────────────────────────────────────────┐
                    │           Redpanda (14 topics)               │
                    └──┬──────────┬───────────┬───────────┬───────┘
                       │          │           │           │
                       ▼          │           │           │
              ┌────────────────┐  │           │           │
              │ Triage Agent×4 │  │           │           │
              │ v6.0.0         │  │           │           │
              │ F1=0.9469      │  │           │           │
              │ 19 features    │  │           │           │
              │ SHAP explain   │  │           │           │
              │ 3.88M scored   │  │           │           │
              └───┬────────────┘  │           │           │
                  │ escalated     │           │           │
                  │ (≥0.95)       │           │           │
                  ▼               │           │           │
              ┌────────────────┐  │           │           │
              │ Hunter Agent   │  │           │           │
              │ Sigma + SPC    │  │           │           │
              │ Graph + Tempo  │  │           │           │
              │ 7,476 invstgns │  │           │           │
              └───┬────────────┘  │           │           │
                  │ findings      │           │           │
                  ▼               │           │           │
              ┌────────────────┐  │           │           │
              │ Verifier Agent │  │           │           │
              │ Fact-check     │  │           │           │
              │ Narratives     │  │           │           │
              │ 1,365 verdicts │  │           │           │
              └───┬────────────┘  │           │           │
                  │               │           │           │
                  ▼               ▼           ▼           ▼
              ┌──────────────────────────────────────────────────┐
              │              Go Consumer → ClickHouse             │
              │  triage_scores │ hunter_investigations │ verifier │
              │  raw_logs │ network_events │ security_events      │
              └──────────────────────────────────────────────────┘
                  │
                  ▼
              ┌────────────────┐       ┌────────────────┐
              │ Merkle Agent   │       │ XAI Service    │
              │ SHA-256 anchor │       │ SHAP waterfall │
              │ → MinIO S3     │       │ /explain API   │
              │ 51 anchors     │       │ Port 8200      │
              └────────────────┘       └────────────────┘
```

### Triage Agent (×4 replicas)

| Component | Technology | Details |
|-----------|------------|----------|
| **Model Version** | v6.0.0 | F1=0.9469, 19 canonical features |
| **Model 1 (80%)** | LightGBM ONNX | Pre-trained gradient boosting, ONNX Runtime inference |
| **Model 2 (12%)** | Extended Isolation Forest | Unsupervised anomaly detection |
| **Model 3 (8%)** | River ARF + ADWIN | Online Adaptive Random Forest with warm restart |
| **Feature Extraction** | Custom | 19 features: token count, entropy, rarity, connection stats, fan-in/out, bytes stats, etc. |
| **Log Parsing** | Drain3 | Thread-safe template mining with rarity scoring |
| **Score Fusion** | Weighted ensemble | Anomalous threshold=0.95, disagreement floor=0.75, CI bounds |
| **SHAP** | TreeExplainer | Generates SHAP values for escalated events, stored in ClickHouse |
| **Throughput** | 3.88M scores | Actions: monitor=2.45M, escalate=1.09M, discard=348K |

### Hunter Agent

| Component | Technology | Details |
|-----------|------------|----------|
| **Sigma Engine** | Custom | Rule-based threat detection matching |
| **SPC Engine** | Statistical Process Control | Anomaly detection via control charts |
| **Entity Graph** | ClickHouse queries | ±15min entity expansion, correlation |
| **Temporal Analysis** | Time-series | Pattern detection across windows |
| **Fusion Scoring** | Multi-signal | Combines all signals into finding_type + severity |
| **Findings** | 7,476 total | BEHAVIOURAL_ANOMALY=4,205, CONFIRMED_ATTACK=2,962, ACTIVE_CAMPAIGN=308 |
| **Consume Loop** | aiokafka + snappy | Resilient loop with auto-restart on error |

### Verifier Agent

| Component | Technology | Details |
|-----------|------------|----------|
| **Fact-Checking** | Evidence assembly | Validates Hunter findings with additional context |
| **Confidence Scoring** | Probabilistic | true_positive=728 (avg=0.524), inconclusive=637 (avg=0.417) |
| **Report Generation** | Narrative engine | report_narrative + analyst_summary + evidence_json |
| **XAI Coverage** | 100% | All 1,365 verdicts have full narrative/summary/evidence |
| **Linkage** | alert_id JOIN | 2,092 Verifier→Hunter linked records |

### XAI Service (SHAP Explanations)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health + readiness |
| `/xai/status` | GET | Model version, F1 score, feature count |
| `/model/features` | GET | All 19 features with importance scores |
| `/explain` | POST | Full SHAP attribution: waterfall, category_attribution, prediction_drivers |

---

## Quick Start

### Prerequisites
- **Docker** ≥ 24.0 and **Docker Compose** v2
- **Go** ≥ 1.21 (for consumer build)
- **Python** ≥ 3.11 (for agents & test scripts)
- **2 machines** recommended (Windows PC + Mac/Linux for AI compute)
- `rpk` CLI (optional, for manual topic management)

### 1. Clone & configure

```bash
git clone https://github.com/Nethrananda21/clif-log-investigation.git
cd CLIF
cp .env.example .env        # edit passwords / ports as needed
```

### 2. Start the stack

**PC1 — Data tier (Windows):**
```bash
docker-compose up -d
```

**Mac M1 — AI compute:**
```bash
docker-compose -f docker-compose.mac.yml --env-file .env --env-file cluster/.env up -d
```

This brings up (in dependency order):
1. ClickHouse Keeper → ClickHouse nodes (schema auto-applied — 26 tables)
2. Redpanda brokers (3-node cluster, 14 topics)
3. MinIO nodes (3-node erasure coded)
4. Vector (log aggregator)
5. Go Consumers (×2 — multi-topic Kafka→ClickHouse writers)
6. **Triage Agent (×4 replicas — 3-model ML ensemble scoring with SHAP)**
7. **Hunter Agent (autonomous threat investigation — Sigma + SPC + graph)**
8. **Verifier Agent (verdict validation + report narratives)**
9. **XAI Service (SHAP explainability API)**
10. Merkle Agent (SHA-256 evidence chain anchoring)
11. Prometheus & Grafana (monitoring)
12. Redpanda Console (admin UI)

### 3. Verify everything is healthy

```bash
# All containers running
docker-compose ps                           # PC1
docker-compose -f docker-compose.mac.yml ps # Mac

# ClickHouse responding
curl "http://localhost:8123/?query=SELECT+version()"

# Redpanda healthy
rpk cluster health --brokers localhost:19092

# Triage Agent health
curl http://localhost:8300/health
curl http://localhost:8300/stats

# Hunter Agent health
curl http://localhost:8400/health
curl http://localhost:8400/stats

# Verifier Agent health
curl http://localhost:8500/health
curl http://localhost:8500/stats

# XAI Service
curl http://localhost:8200/health
curl -X POST http://localhost:8200/explain \
  -H "Content-Type: application/json" \
  -d '{"features": {"src_bytes": 999999, "serror_rate": 1.0}}'

# MinIO buckets
docker exec clif-minio01 mc ls clif/
```

### 4. Access web UIs

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://localhost:3002 | admin / (see .env) |
| Redpanda Console | http://localhost:8080 | (no auth) |
| MinIO Console | http://localhost:9002 | clif_minio_admin / (see .env) |
| Prometheus | http://localhost:9090 | (no auth) |
| ClickHouse HTTP | http://localhost:8123 | clif_admin / (see .env) |

---

## Running Tests

### Install test dependencies

```bash
pip install -r tests/requirements.txt
```

### Full test suite (pytest)

```bash
# Infrastructure, data integrity, performance, resilience tests
pytest tests/ -v --tb=short

# Run specific test categories
pytest tests/test_infrastructure.py -v    # Cluster health, schema, configs
pytest tests/test_data_integrity.py -v    # E2E pipeline validation
pytest tests/test_performance.py -v -s    # Throughput & query benchmarks
pytest tests/test_resilience.py -v -s     # Fault tolerance (destructive)
pytest tests/test_lancedb.py -v           # LanceDB semantic search tests
```

### Enterprise benchmark (Grade A)

```bash
# Full enterprise benchmark: 2M events, burst, latency probes, concurrent queries
python tests/enterprise_benchmark.py

# Results saved to tests/benchmark_results.json
```

### Realistic load test (LANL-format)

```bash
# Default: 1M events across 4 topics with LANL-realistic data
python tests/realistic_load_test.py

# Custom event count
python tests/realistic_load_test.py --events 500000
```

### Legacy performance test

```bash
python tests/performance_test.py --events 1000000 --rate 100000 --duration 60
```

---

## Benchmark Results

2-machine cluster benchmark: PC1 (i5-13420H) data tier + Mac M1 AI compute. Go consumers, 12 Redpanda partitions, 2-node ClickHouse.

| Metric | Result | Enterprise Target | Status |
|--------|--------|-------------------|--------|
| **Sustained Throughput** | **26,586 EPS** | ≥10,000 EPS | ✅ Pass |
| **Triage Scores Written** | **3,882,816** | — | ✅ |
| **Hunter Investigations** | **7,476** | — | ✅ |
| **Verifier Verdicts** | **1,365** | — | ✅ |
| **Evidence Anchors** | **51** | — | ✅ |
| **Data Loss** | **0.0%** | 0% | ✅ Pass |
| **Consumer Lag** | **0 messages** | <10,000 | ✅ Pass |
| **Query Avg Response** | **61.4ms** | <200ms | ✅ Pass |
| **Query P95 Response** | **87.4ms** | <500ms | ✅ Pass |
| **Zero Data Loss** | **2.5M/2.5M events** | Zero loss | ✅ Pass |

> Benchmark on 2-machine Docker cluster (Windows PC + Mac M1) with shared resources.

---

## Dashboard Pages

| Page | Route | Data Source | Status | Description |
|------|-------|-------------|--------|-------------|
| Overview | `/` | ClickHouse | ✅ Real | KPI cards, event trends, severity distribution |
| Dashboard | `/dashboard` | ClickHouse | ✅ Real | Aggregation charts, top sources |
| Live Feed | `/live-feed` | ClickHouse (2s poll) | ✅ Real | Real-time event stream with pause/filter/dedup |
| Search | `/search` | ClickHouse + LanceDB | ✅ Real | Keyword + AI semantic search, time/severity filters |
| Alerts | `/alerts` | ClickHouse | ⚠️ Partial | Real data, client-side workflow state |
| System Health | `/system` | Prometheus + Direct | ✅ Real | All infrastructure service status |
| Threat Intel | `/threat-intel` | ClickHouse + Mock | ⚠️ Partial | MITRE data real, IOC table mock |
| Evidence | `/evidence` | Merkle + Mock | ⚠️ Partial | Partial mock data |
| AI Agents | `/ai-agents` | Mock | 🔲 Mock | Agent cards & approval queue |
| Investigations | `/investigations` | Mock | 🔲 Mock | Case list with MITRE tags |
| Attack Graph | `/attack-graph` | Mock | 🔲 Mock | React Flow visualization |
| Reports | `/reports` | Mock | 🔲 Mock | Report templates |
| Settings | `/settings` | Mock | 🔲 Mock | User management |

### Dashboard API Routes (11)

| Route | Method | Description |
|-------|--------|-------------|
| `/api/metrics` | GET | ClickHouse aggregation queries for dashboard KPIs |
| `/api/events/stream` | GET | Live event polling (UNION ALL across 4 tables) |
| `/api/events/search` | GET | Full-text keyword search with filters |
| `/api/alerts` | GET | Alert data from security_events |
| `/api/system` | GET | Service health from Prometheus + direct checks |
| `/api/evidence` | GET | Merkle evidence chain data |
| `/api/threat-intel` | GET | MITRE ATT&CK + threat intelligence |
| `/api/lancedb` | GET | LanceDB health and stats proxy |
| `/api/semantic-search` | POST | AI semantic search via LanceDB embeddings |
| `/api/similar-events` | POST | Find similar events by event ID |

---

## Data Chain (Validated)

```
raw_logs (265,947)
    ↓ Vector parsing + routing
network_events (2,483,606) + security_events (1,550,206)
    ↓ Triage scoring (4 replicas, v6.0.0, F1=0.9469)
triage_scores (3,882,816) → escalated: 1,085,889 (score ≥ 0.95)
    ↓ Hunter investigation (Sigma + SPC + graph + temporal)
hunter_investigations (7,476) → BEHAVIOURAL_ANOMALY / CONFIRMED_ATTACK / ACTIVE_CAMPAIGN
    ↓ Verifier validation (fact-check + confidence + narratives)
verifier_results (1,365) → true_positive (728) / inconclusive (637)
    ↓ Merkle anchoring (SHA-256 batch trees)
evidence_anchors (51) → MinIO S3 Object Lock
```

---

## File Layout

```
CLIF/
├── docker-compose.yml              # PC1 data tier (12 services)
├── docker-compose.mac.yml          # Mac M1 AI compute (11 services)
├── docker-compose.prod.yml         # Production overrides
├── .env.example                    # Environment variable template
├── README.md                       # This file
├── PIPELINE_VALIDATION_REPORT.md   # Full 12-test pipeline validation
│
├── agents/                         # AI Agent Pipeline
│   ├── triage/                     # Triage Agent (x4 replicas)
│   │   ├── app.py                  # TriageProcessor + TriageAgent + FastAPI
│   │   ├── config.py               # Model weights, thresholds
│   │   ├── model_ensemble.py       # LightGBM + EIF + ARF ensemble
│   │   ├── feature_extractor.py    # 19-feature canonical extraction
│   │   ├── score_fusion.py         # Weighted fusion, CI, routing
│   │   ├── shap_explainer.py       # SHAP TreeExplainer
│   │   ├── drain3_miner.py         # Thread-safe Drain3 mining
│   │   ├── Dockerfile              # Python 3.11-slim, healthcheck
│   │   └── models/                 # Model artifacts (ONNX, joblib)
│   ├── hunter/                     # Hunter Agent
│   │   ├── app.py                  # FastAPI + resilient aiokafka loop
│   │   ├── config.py               # Score gate, concurrency settings
│   │   ├── investigation/          # Sigma, SPC, graph, temporal engines
│   │   ├── Dockerfile              # Python 3.11-slim, port 8400
│   │   └── requirements.txt        # aiokafka, python-snappy
│   ├── verifier/                   # Verifier Agent
│   │   ├── app.py                  # FastAPI + resilient aiokafka loop
│   │   ├── Dockerfile              # Python 3.11-slim, port 8500
│   │   └── requirements.txt        # aiokafka, python-snappy
│   └── xai-service/                # XAI Explainability Service
│       ├── app.py                  # /health /explain /model/features
│       └── Dockerfile              # Python 3.11-slim, port 8200
│
├── consumer-go/                    # Go Kafka→ClickHouse Consumer (x2)
│   ├── main.go                     # Multi-topic consumer
│   ├── schema.go                   # Table schemas + column mappings
│   └── Dockerfile                  # Go multi-stage build
│
├── merkle-service/                 # Merkle Evidence Agent
│   └── merkle_anchor.py            # SHA-256 batch anchoring
│
├── clickhouse/                     # ClickHouse configs
│   ├── schema.sql                  # 26 tables + materialized views
│   └── *.xml                       # Keeper, node, user configs
│
├── monitoring/                     # Prometheus + Grafana
│   ├── prometheus.yml              # 11 scrape targets
│   └── alert_rules.yml             # Alerting rules
│
├── tests/                          # Validation & test scripts
│   ├── pipeline_test.py            # 41-test comprehensive validation
│   └── inject_hunter_v2.py         # E2E test injector
│
├── k8s/                            # Kubernetes (Kustomize)
│   ├── base/                       # 59+ resources
│   └── overlays/                   # dev / staging / prod
│
└── dashboard/                      # SOC Dashboard (Next.js 14)
    └── src/app/                    # 14 pages + 11 API routes
```

---

## Architecture Decisions

### Why ClickHouse over Elasticsearch?
- **10–20x better compression** on structured log data (columnar + ZSTD)
- **Sub-second analytical queries** vs ES's multi-second aggregation
- **S3 tiering built-in** — 90% cost reduction for cold data
- **SQL interface** — no query DSL learning curve for analysts

### Why Redpanda over Kafka?
- **C++ native** — no JVM overhead, 10x lower tail latency
- **Kafka-compatible** — drop-in replacement, all client libraries work
- **Built-in Wasm** — enables in-stream PII scrubbing (future)
- **Simpler operations** — no ZooKeeper dependency

### Why LanceDB for vector search?
- **Embedded-first** — runs as a lightweight service, no cluster to manage
- **Fast ANN search** — IVF-PQ indexing on 494K+ embeddings
- **Auto-sync** — continuously indexes new ClickHouse events
- **Sentence-transformers** — `all-MiniLM-L6-v2` for 384-dim embeddings

### Why MinIO over AWS S3 directly?
- **Local development** — fully offline-capable, identical S3 API
- **Erasure coding** — data durability without cloud dependency
- **Swap for production** — change one endpoint URL to move to AWS S3

### Why ReplicatedMergeTree?
- **Async replication** — survives node loss with zero data loss
- **Built-in deduplication** — exactly-once semantics with idempotent inserts
- **Partition pruning** — daily partitions enable fast time-range queries

### Why Go consumer over ClickHouse Kafka engine?
- **Better error handling** — retries, dead letter logic, structured logging
- **Flexible batching** — tunable batch size + time-based flush + pipelined I/O
- **Offset control** — manual commit after confirmed ClickHouse insert
- **Horizontal scaling** — 2 instances consuming 12 Redpanda partitions
- **Performance** — Go binary with low memory footprint, zero GC pauses

---

## Troubleshooting

### ClickHouse won't start
```bash
# Check keeper is running first
docker logs clif-clickhouse-keeper
# Verify keeper health
echo ruok | nc localhost 2181   # should return "imok"
# Then check node logs
docker logs clif-clickhouse01
```

### Topics not created
```bash
# Run manually
rpk topic create raw-logs --brokers localhost:19092 --partitions 12 --replicas 2
# Or re-run the init container
docker-compose up redpanda-init
```

### Go consumer not ingesting
```bash
# Check logs
docker logs clif-go-consumer -f --tail 100
# Check consumer lag
rpk group describe clif-clickhouse-consumer --brokers localhost:19092
```

### Hunter/Verifier not consuming
```bash
# Check Hunter
curl http://10.180.247.241:8400/health
docker logs clif-hunter -f --tail 100
# Check Verifier
curl http://10.180.247.241:8500/health
docker logs clif-verifier -f --tail 100
```
### Triage Agent not scoring
```bash
# Check health (should return startup_ok + self-test_ok)
curl http://localhost:8300/health
# Check readiness
curl http://localhost:8300/ready
# Check stats (events_processed, arf_model_ready, etc.)
curl http://localhost:8300/stats
# Check logs for ClickHouse/Kafka health gate failures
docker logs clif-triage-agent -f --tail 100
```
### S3 tiering not working
```bash
# Verify MinIO is healthy
curl http://localhost:9002/minio/health/live
# Check ClickHouse storage policy
curl "http://localhost:8123/?query=SELECT+*+FROM+system.storage_policies+FORMAT+Pretty"
```

### Grafana shows no data
1. Check Prometheus targets: http://localhost:9090/targets
2. Verify data source in Grafana: Settings → Data Sources → Prometheus → Test
3. Redpanda metrics may take 1–2 minutes to appear after startup

---

## Tear Down

```bash
# Stop everything and remove volumes (fresh start)
docker-compose down -v

# Stop but keep data
docker-compose down
```

---

## Next Steps

See [implementation_plan.md](implementation_plan.md) for the full roadmap.

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 1: Foundation** | ClickHouse + Redpanda + MinIO + Go Consumers + Monitoring | ✅ Complete |
| **Phase 2: Triage Agent** | 3-model ensemble (LightGBM + EIF + ARF), warm restart, Drain3, score fusion, health gates | ✅ Complete |
| **Phase 3: 2-PC Cluster** | Split deployment (PC1 data / Mac M1 AI), 23 containers, Go consumers | ✅ Complete |
| **Phase 4: Hunter Agent** | Sigma rules, SPC anomaly, graph walk, temporal correlation, aiokafka consumer | ✅ Complete |
| **Phase 5: Verifier Agent** | HMAC integrity, confidence scoring, verdict generation, evidence chain | ✅ Complete |
| **Phase 6: XAI + Merkle** | SHAP explainability service, Merkle SHA-256 evidence anchoring, full E2E pipeline | ✅ Complete |

---

## Related Docs

| Document | Description |
|----------|-------------|
| [CLIF_PROJECT_REPORT.md](CLIF_PROJECT_REPORT.md) | Full layer-by-layer project report |
| [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) | Detailed enterprise benchmark analysis |
| [INDUSTRY_GAP_ANALYSIS.md](INDUSTRY_GAP_ANALYSIS.md) | 22-gap comparison vs Splunk/Elastic/Sentinel/CrowdStrike |
| [implementation_plan.md](implementation_plan.md) | Agentic SIEM transformation roadmap |
| [TRIAGE_AGENT_DOCUMENTATION.md](TRIAGE_AGENT_DOCUMENTATION.md) | Triage Agent deep dive & full agent pipeline data flow |
| [PIPELINE_READINESS_REPORT.md](PIPELINE_READINESS_REPORT.md) | Pipeline readiness audit for AI agent integration |

> **All agents are live and validated.** Triage (×4 replicas), Hunter, Verifier, XAI Service, and Merkle Evidence Agent are fully deployed across the 2-machine cluster. See [PIPELINE_VALIDATION_REPORT.md](PIPELINE_VALIDATION_REPORT.md) for the 12-test validation report.

---

*CLIF — Cognitive Log Investigation Framework — v6.0*
