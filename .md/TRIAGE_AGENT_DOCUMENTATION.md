# CLIF — Triage Agent & AI Pipeline Documentation

> **Cognitive Log Investigation Framework — SIH1733**
> Detailed documentation of the end-to-end data pipeline, the fully implemented Triage Agent,
> and the future AI agent architecture (Hunter, Verifier, Reporter).

---

## Table of Contents

1. [Pipeline Overview](#1-pipeline-overview)
2. [Complete Data Flow — Source to Dashboard](#2-complete-data-flow--source-to-dashboard)
3. [Kafka Topic Architecture](#3-kafka-topic-architecture)
4. [ClickHouse Table Map](#4-clickhouse-table-map)
5. [Triage Agent — Deep Dive](#5-triage-agent--deep-dive)
   - 5.1 [Architecture](#51-architecture)
   - 5.2 [Startup Sequence](#52-startup-sequence)
   - 5.3 [Drain3 Template Mining](#53-drain3-template-mining)
   - 5.4 [20-Feature Canonical Extraction](#54-20-feature-canonical-extraction)
   - 5.5 [3-Model Ensemble](#55-3-model-ensemble)
   - 5.6 [Score Fusion & Routing](#56-score-fusion--routing)
   - 5.7 [Online Learning Loop](#57-online-learning-loop)
   - 5.8 [Health & Observability](#58-health--observability)
6. [Hunter Agent — Future](#6-hunter-agent--future)
7. [Verifier Agent — Future](#7-verifier-agent--future)
8. [Reporter Agent — Future](#8-reporter-agent--future)
9. [Agent-to-Agent Data Flow](#9-agent-to-agent-data-flow)
10. [Deployment Topology](#10-deployment-topology)
11. [Model Artifacts](#11-model-artifacts)
12. [Configuration Reference](#12-configuration-reference)

---

## 1. Pipeline Overview

CLIF processes log events through four architectural planes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             DATA PLANE                                       │
│                                                                              │
│  Log Sources ──▶ Vector (CCS normalize) ──▶ Redpanda (3-broker cluster)     │
│                                               │                              │
│                    ┌──────────────────────────┘                              │
│                    ▼                                                          │
│             4 Kafka Topics (12 partitions each, RF=3, LZ4)                  │
│          ┌────────────┬────────────────┬──────────────┐                     │
│          │ raw-logs   │ security-events│ process-events│ network-events     │
│          └─────┬──────┴───────┬────────┴──────┬───────┴────┐               │
│                │              │               │            │                │
│       ┌────────┼──────────────┼───────────────┼────────────┤               │
│       ▼        ▼              ▼               ▼            ▼               │
│  Consumer ×3 (82K EPS)     Triage Agent (fan-out, own consumer group)      │
│       │                       │                                              │
│       ▼                       ▼                                              │
│  ClickHouse (2-node)     Score Fusion → triage-scores / anomaly-alerts     │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                         INTELLIGENCE PLANE                                   │
│                                                                              │
│  Triage Agent ──▶ Hunter Agent ──▶ Verifier Agent ──▶ Reporter Agent        │
│  (anomaly-alerts)  (hunter-tasks)  (verifier-tasks)   (verifier-results)    │
│                                                                              │
│  LanceDB (384-dim embeddings) ··········▶ Hunter (semantic similarity)      │
│  Threat Intel (VT / AbuseIPDB) ◀········▶ Verifier (IOC validation)        │
│  Merkle Service (SHA-256 proofs) ·······▶ Verifier (tamper detection)       │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                       PRESENTATION PLANE                                     │
│                                                                              │
│  Next.js 14 SOC Dashboard (14 pages, 11 API routes)                        │
│  ClickHouse queries │ LanceDB semantic search │ Prometheus metrics          │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                        OBSERVABILITY PLANE                                   │
│                                                                              │
│  Prometheus (scrapes all 22+ services) ──▶ Grafana (dashboards + alerts)    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Insight: Kafka Fan-Out

The Triage Agent does **NOT** read from ClickHouse for real-time scoring. It operates as an independent Kafka consumer in its own consumer group (`clif-triage-agent`), reading the same 4 raw topics that the ClickHouse consumers read. This is a Kafka fan-out pattern:

```
                         ┌── Consumer Group: clif-clickhouse-consumer ──▶ ClickHouse
Redpanda (4 topics) ─────┤
                         └── Consumer Group: clif-triage-agent ──────────▶ Triage Agent
```

**Why fan-out instead of reading from ClickHouse?**

| Approach | Latency | Hops | Bottleneck |
|----------|---------|------|------------|
| **Kafka fan-out (used)** | ~1ms | 1 | None — independent of storage |
| ClickHouse polling | 500ms–2s | 2 | Couples scoring to storage writes |

ClickHouse is only used by the Triage Agent for:
- **Startup:** ARF warm restart (replay buffer), IOC cache, threshold cache, allowlist, asset criticality
- **Runtime writes:** `arf_replay_buffer` (every scored event), `triage_scores` (via consumer on Kafka)

---

## 2. Complete Data Flow — Source to Dashboard

### Step-by-Step Event Journey

```
Step 1: SOURCE
    Syslog / HTTP / Docker / File / journald / eBPF Tetragon
        │
        ▼
Step 2: NORMALIZE
    Vector Aggregator (VRL transforms)
    • Parse raw log → CLIF Common Schema (CCS)
    • Auto-tag MITRE ATT&CK technique
    • Deduplication transforms
    • Route to correct topic by event type
        │
        ▼
Step 3: STREAM
    Redpanda (3 brokers, Kafka-compatible)
    • Event lands on 1 of 4 topics based on type
    • 12 partitions per topic, RF=3, LZ4 compression
    • 7-day retention (configurable)
        │
        ├─────────────────────────────────────┐
        ▼                                     ▼
Step 4a: STORE                          Step 4b: TRIAGE
    Consumer Pool (3× Python)               Triage Agent (own consumer group)
    • Batch 200K events or flush 0.5s       • Drain3 template mining
    • orjson parsing, WriterPool            • 20-feature extraction
    • 82K+ EPS sustained                    • 3-model ensemble inference
    • Manual offset commit                  • Score fusion + routing
        │                                       │
        ▼                                       ├──▶ triage-scores (Kafka)
    ClickHouse (2-node replicated)              ├──▶ anomaly-alerts (Kafka)
    • 24 tables (ReplicatedMergeTree)           └──▶ arf_replay_buffer (ClickHouse)
    • ZSTD 15-20× compression                      │
    • Hot → Warm → Cold tiered TTL                  │
        │                                           ▼
        ├──▶ MinIO (S3 cold storage)          Step 5: INVESTIGATE (future)
        ├──▶ Merkle Service (evidence hash)       Hunter → Verifier → Reporter
        └──▶ LanceDB (384-dim embeddings)
                                                    │
        ┌───────────────────────────────────────────┘
        ▼
Step 6: PRESENT
    SOC Dashboard (Next.js 14)
    • 14 pages: Overview, Live Feed, Search, Alerts, AI Agents, etc.
    • 11 API routes → ClickHouse + LanceDB + Prometheus + Redpanda
    • AI semantic search via LanceDB embeddings
```

---

## 3. Kafka Topic Architecture

All 14 topics are auto-created by the `redpanda-init` container on startup.

### Ingestion Topics (12 partitions, RF=3)

| Topic | Content | Producers | Consumers |
|-------|---------|-----------|-----------|
| `raw-logs` | Generic / unclassified log events | Vector | Consumer Pool, Triage Agent |
| `security-events` | Auth failures, access violations, IDS alerts | Vector | Consumer Pool, Triage Agent |
| `process-events` | Process exec/exit, eBPF Tetragon events | Vector | Consumer Pool, Triage Agent |
| `network-events` | Connection events, netflow, firewall logs | Vector | Consumer Pool, Triage Agent |

### Triage Agent Topics (12 partitions, RF=3)

| Topic | Content | Producers | Consumers |
|-------|---------|-----------|-----------|
| `templated-logs` | Drain3 template-mined events | Triage Agent | (observability) |
| `triage-scores` | All scored events with ensemble results | Triage Agent | Consumer Pool → ClickHouse |
| `anomaly-alerts` | Events with adjusted_score ≥ anomalous threshold | Triage Agent | Hunter Agent (future) |

### Agent Pipeline Topics (6 partitions, RF=3)

| Topic | Content | Producers | Consumers |
|-------|---------|-----------|-----------|
| `hunter-tasks` | Escalated anomalies for deep investigation | Triage Agent (mirror of anomaly-alerts) | Hunter Agent (future) |
| `hunter-results` | Investigation findings with entity graph | Hunter Agent (future) | Verifier Agent, Dashboard |
| `verifier-tasks` | Findings requiring IOC + evidence validation | Hunter Agent (future) | Verifier Agent (future) |
| `verifier-results` | Confirmed incidents or false positive verdicts | Verifier Agent (future) | Reporter Agent, Dashboard |

### Operational Topics (3 partitions, RF=3)

| Topic | Content | Producers | Consumers |
|-------|---------|-----------|-----------|
| `feedback-labels` | Analyst TP/FP feedback for model retraining | Verifier Agent, Dashboard | Model retraining pipeline |
| `dead-letter` | Failed events from any pipeline stage | All agents | Operations team |
| `pipeline-commands` | Control plane signals (pause, resume, retrain) | Dashboard / Admin | All agents |

---

## 4. ClickHouse Table Map

24 tables in the `clif_logs` database on the `clif_cluster` (2-node replicated shard).

### Core Event Tables

| Table | Engine | Purpose | Written By |
|-------|--------|---------|------------|
| `raw_logs` | ReplicatedMergeTree | Generic log events | Consumer Pool |
| `security_events` | ReplicatedMergeTree | Authentication, access, IDS events | Consumer Pool |
| `process_events` | ReplicatedMergeTree | Process execution and Tetragon events | Consumer Pool |
| `network_events` | ReplicatedMergeTree | Network connections and firewall events | Consumer Pool |

### Materialized Views (Auto-Aggregation)

| Table | Source | Purpose |
|-------|--------|---------|
| `events_per_minute` | 4 core tables | Real-time throughput monitoring |
| `security_severity_hourly` | security_events | Hourly severity distribution |
| `events_per_10s` | 4 core tables | High-resolution trend analysis |

### AI Agent Tables

| Table | Purpose | Read By | Written By |
|-------|---------|---------|------------|
| `triage_scores` | All scored events (28 columns) | Dashboard, Hunter, Analyst | Consumer Pool (from triage-scores topic) |
| `arf_replay_buffer` | 20 features + label for ARF warm restart | Triage Agent (startup) | Triage Agent (runtime) |
| `hunter_investigations` | Deep investigation results + entity graphs | Dashboard, Verifier | Hunter Agent (future) |
| `verifier_results` | Confirmed incidents / FP verdicts | Dashboard, Reporter | Verifier Agent (future) |
| `feedback_labels` | Analyst TP/FP labels for retraining | Model retraining pipeline | Verifier Agent, Dashboard |
| `dead_letter_events` | Failed events for debugging | Operations | All agents |

### Reference / Lookup Tables

| Table | Purpose | Seeded | Used By |
|-------|---------|--------|---------|
| `source_thresholds` | Per-source suspicious/anomalous thresholds | 10 rows (syslog through IDS/IPS) | Triage Agent (ScoreFusion) |
| `ioc_cache` | Cached IOC hashes, IPs, domains | External feeds | Triage Agent (IOCLookup), Verifier |
| `allowlist` | Known-benign patterns to bypass scoring | Admin | Triage Agent (AllowlistChecker) |
| `asset_criticality` | Hostname → criticality multiplier | Admin | Triage Agent (ScoreFusion) |
| `mitre_mapping_rules` | MITRE ATT&CK technique mappings | Static load | Hunter, Verifier, Reporter |
| `evidence_anchors` | Merkle tree roots + S3 pointers | Merkle Service | Verifier Agent |
| `pipeline_metrics` | Agent throughput / latency metrics | All agents | Prometheus, Dashboard |

### Feature Engineering Tables

| Table | Purpose |
|-------|---------|
| `features_entity_freq` | Entity (user/host/IP) access frequency baselines |
| `features_template_rarity` | Drain3 template frequency distributions |
| `features_entity_baseline` | Behavioral baselines for anomaly detection |
| `triage_score_rollup` | Hourly roll-up of triage scoring distributions |

---

## 5. Triage Agent — Deep Dive

### 5.1 Architecture

The Triage Agent is a high-throughput Python service that reads raw events directly from Kafka, scores them with a 3-model ML ensemble, and routes the results.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TRIAGE AGENT  (port 8300)                        │
│                                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────────────────┐   │
│  │  Kafka        │   │  Batch       │   │  Feature Extraction        │   │
│  │  Consumer     │──▶│  Collector   │──▶│                            │   │
│  │  (4 topics)   │   │  (1000 msgs) │   │  Drain3  ──▶ template_id  │   │
│  │  Group:       │   │              │   │               rarity score │   │
│  │  clif-triage  │   └──────────────┘   │                            │   │
│  │  -agent       │                      │  Connection ──▶ 8 KDD-     │   │
│  └──────────────┘                      │  Tracker        style feats │   │
│                                         │                            │   │
│                                         │  Event ──▶ 12 direct feats │   │
│                                         │  Parser    (time, severity,│   │
│                                         │             bytes, port…)  │   │
│                                         └──────────┬─────────────────┘   │
│                                                    │                     │
│         20 canonical float features                │                     │
│                                                    ▼                     │
│                                         ┌────────────────────────────┐   │
│                                         │   MODEL ENSEMBLE           │   │
│                                         │                            │   │
│                                         │  ┌────────────────────┐    │   │
│                                         │  │ LightGBM ONNX      │    │   │
│                                         │  │ (supervised, 50%)   │─┐  │   │
│                                         │  └────────────────────┘ │  │   │
│                                         │  ┌────────────────────┐ │  │   │
│                                         │  │ Ext. Isolation      │ │  │   │
│                                         │  │ Forest (unsup, 30%) │─┤  │   │
│                                         │  └────────────────────┘ │  │   │
│                                         │  ┌────────────────────┐ │  │   │
│                                         │  │ River ARF + ADWIN   │ │  │   │
│                                         │  │ (online, 20%)       │─┘  │   │
│                                         │  └────────────────────┘    │   │
│                                         └──────────┬─────────────────┘   │
│                                                    │                     │
│                                                    ▼                     │
│                                         ┌────────────────────────────┐   │
│                                         │   SCORE FUSION             │   │
│                                         │                            │   │
│                                         │  combined = Σ(wᵢ × scoreᵢ)│   │
│                                         │  CI = combined ± 1.96σ     │   │
│                                         │  adjusted = combined ×     │   │
│                                         │    asset_criticality       │   │
│                                         │                            │   │
│                                         │  IOC lookup + allowlist    │   │
│                                         │  Per-source thresholds     │   │
│                                         └──────────┬─────────────────┘   │
│                                                    │                     │
│         ┌──────────────────────────────────────────┼────────────────┐    │
│         ▼                    ▼                     ▼                │    │
│  ┌─────────────┐   ┌───────────────┐   ┌──────────────────┐       │    │
│  │ Kafka:       │   │ Kafka:         │   │ ClickHouse:       │      │    │
│  │ triage-      │   │ anomaly-       │   │ arf_replay_buffer │      │    │
│  │ scores       │   │ alerts         │   │ (20 feats + label)│      │    │
│  │ (all scored) │   │ (escalated)    │   │                   │      │    │
│  └─────────────┘   └───────────────┘   └──────────────────┘       │    │
│         │                    │                     │                │    │
│         │                    │                     │                │    │
│         │                    │                     └── ARF learn_one│    │
│         │                    │                         (online)     │    │
│         │                    │                                      │    │
└─────────┼────────────────────┼──────────────────────────────────────┘    │
          ▼                    ▼                                           │
  Consumer Pool ─▶     Hunter Agent (future)                              │
  ClickHouse             hunter-tasks topic                               │
  triage_scores table                                                     │
```

**Source Files:**

| File | Lines | Responsibility |
|------|-------|----------------|
| `agents/triage/app.py` | 837 | Main service: Kafka consumer, batch collector, Flask health endpoints |
| `agents/triage/config.py` | 189 | All environment variables, SOURCE_TYPE_MAP (30+ entries), SEVERITY_MAP, PROTOCOL_MAP |
| `agents/triage/model_ensemble.py` | 540 | LightGBM ONNX, Extended Isolation Forest, River ARF with warm restart |
| `agents/triage/feature_extractor.py` | 513 | ConnectionTracker, FeatureExtractor (20 canonical features) |
| `agents/triage/score_fusion.py` | 570 | TriageResult dataclass, SourceThresholdCache, ScoreFusion, IOCLookup, AllowlistChecker |
| `agents/triage/drain3_miner.py` | 188 | Thread-safe Drain3 template mining with rarity scoring |
| `agents/triage/drain3.ini` | — | 10 regex masking rules for IP, port, hex, timestamps, etc. |
| `agents/triage/Dockerfile` | 49 | Python 3.11-slim, librdkafka, healthcheck on 8300 |
| `agents/triage/requirements.txt` | — | onnxruntime, river, eif, drain3, orjson, confluent-kafka, flask, etc. |

### 5.2 Startup Sequence

The Triage Agent follows a strict startup protocol with health gates:

```
1. WAIT FOR INFRASTRUCTURE
   ├── ClickHouse connectivity check (retry up to 30× with 2s backoff)
   └── Kafka broker connectivity check (retry up to 30× with 2s backoff)
       │
       ▼
2. LOAD CACHES FROM CLICKHOUSE
   ├── SourceThresholdCache ← source_thresholds (10 rows)
   ├── IOCLookup            ← ioc_cache
   ├── AllowlistChecker     ← allowlist
   └── Asset criticality    ← asset_criticality
       │
       ▼
3. LOAD MODELS
   ├── LightGBM: load ONNX file → create InferenceSession (CPUExecutionProvider)
   ├── EIF: load joblib pickle + threshold array
   └── ARF: WARM RESTART (not pickle.load)
       ├── Create fresh ARFClassifier(n_models=10, seed=42)
       ├── Query arf_replay_buffer (last 24h, max 50K rows)
       ├── If rows found → replay via learn_one() to rebuild trees
       └── If empty → fallback to CSV cold-start file
           │
           ▼
4. SELF-TEST
   ├── Generate synthetic event (all fields populated)
   ├── Run through full pipeline: Drain3 → features → ensemble → fusion
   ├── Verify ARF produces VARYING probabilities (not constant)
   │   (constant = pickle bug; varying = warm restart successful)
   └── Log self-test scores for validation
       │
       ▼
5. START CONSUMING
   └── Subscribe to 4 raw topics, begin scoring loop
```

### 5.3 Drain3 Template Mining

Drain3 is an online log parsing algorithm that extracts structural templates from unstructured log messages. Every incoming event passes through Drain3 before feature extraction.

**What it does:**

```
Input:  "Failed password for admin from 192.168.1.50 port 22 ssh2"
Output: Template: "Failed password for <*> from <*> port <*> ssh2"
        Template ID: "t_00042"
        Template Count: 1,847 (how often this pattern was seen)
```

**Rarity scoring:**

```
template_rarity = 1.0 − (template_count / total_count)
```

- Common templates (e.g., heartbeat logs) → rarity ≈ 0.0 (benign)
- Rare templates (e.g., novel attack pattern) → rarity ≈ 1.0 (suspicious)

**Configuration:**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `DRAIN3_DEPTH` | 4 | Parse tree depth |
| `DRAIN3_SIM_TH` | 0.4 | Similarity threshold for template matching |
| `DRAIN3_MAX_CLUSTERS` | 1024 | Maximum number of unique templates |
| `DRAIN3_MAX_CHILDREN` | 100 | Max children per parse tree node |
| `drain3.ini` | 10 rules | Regex masking for IPs, ports, hex values, timestamps, paths |

### 5.4 20-Feature Canonical Extraction

All three models receive the **exact same 20 float features**. This is the unified feature contract.

| # | Feature Name | Source | Description |
|---|-------------|--------|-------------|
| 1 | `hour_of_day` | Timestamp | Hour (0–23), captures time-based patterns |
| 2 | `day_of_week` | Timestamp | Day (0=Mon – 6=Sun), weekday vs weekend |
| 3 | `severity_numeric` | Event field | Mapped via SEVERITY_MAP (info=0 → critical=4) |
| 4 | `source_type_numeric` | Event field | Mapped via SOURCE_TYPE_MAP (30+ aliases → 10 categories) |
| 5 | `src_bytes` | Event field | Bytes sent (0 for non-network events) |
| 6 | `dst_bytes` | Event field | Bytes received (0 for non-network events) |
| 7 | `event_freq_1m` | Sliding window | Events from this source in last 1 minute |
| 8 | `protocol` | Event field | Mapped via PROTOCOL_MAP (tcp=6, udp=17, icmp=1…) |
| 9 | `dst_port` | Event field | Destination port (0 for non-network) |
| 10 | `template_rarity` | Drain3 | Template rarity score (0.0–1.0) |
| 11 | `threat_intel_flag` | IOC cache | 1 if any IOC match found, else 0 |
| 12 | `duration` | Event field | Connection/session duration in seconds |
| 13 | `same_srv_rate` | ConnectionTracker | Ratio of connections to same service (KDD-style) |
| 14 | `diff_srv_rate` | ConnectionTracker | Ratio of connections to different services |
| 15 | `serror_rate` | ConnectionTracker | SYN error rate in sliding window |
| 16 | `rerror_rate` | ConnectionTracker | REJ error rate in sliding window |
| 17 | `count` | ConnectionTracker | Connection count in 2-second window |
| 18 | `srv_count` | ConnectionTracker | Same-service connection count |
| 19 | `dst_host_count` | ConnectionTracker | Unique hosts connecting to destination (last 100) |
| 20 | `dst_host_srv_count` | ConnectionTracker | Same-service count for destination host |

**Features 13–20** are KDD-style time-window aggregation features. For network events, they are computed in real-time from a sliding-window `ConnectionTracker`. For non-network events, they default to 0.

**Source type categories (10 with 30+ aliases):**

| Category | Numeric | Aliases |
|----------|---------|---------|
| Syslog | 1 | `syslog`, `linux_auth`, `sshd`, `sudo`, `pam`, `auditd`, `docker_logs`, `journald`, `http_json`, `file_logs`, `unknown` |
| Windows | 2 | `windows_event`, `winlogbeat`, `wineventlog`, `sysmon` |
| Firewall | 3 | `firewall`, `cef` |
| Active Directory | 4 | `active_directory`, `ldap` |
| DNS | 5 | `dns`, `dns_logs` |
| CloudTrail | 6 | `cloudtrail`, `aws_cloudtrail` |
| Kubernetes | 7 | `kubernetes`, `k8s_audit` |
| Web Server | 8 | `nginx`, `apache`, `web_server` |
| NetFlow | 9 | `netflow`, `ipfix` |
| IDS/IPS | 10 | `ids_ips`, `zeek`, `snort`, `suricata` |

### 5.5 3-Model Ensemble

The ensemble combines three fundamentally different ML approaches for robust anomaly detection:

```
20 features ──┬──▶ LightGBM ONNX ──▶ P(attack) ──── × 0.50 ─┐
              │                                                │
              ├──▶ Ext. Isolation Forest ──▶ anomaly_score ─ × 0.30 ─┤──▶ combined
              │                                                │
              └──▶ River ARF + ADWIN ──▶ P(attack) ──── × 0.20 ─┘
```

#### Model 1: LightGBM ONNX (50% weight)

| Property | Value |
|----------|-------|
| Type | Supervised gradient boosting classifier |
| Format | ONNX (deterministic, cross-platform) |
| Runtime | ONNX Runtime, CPUExecutionProvider |
| Training | Labeled dataset (attack/benign) |
| Output | `P(attack)` probability in [0, 1] |
| Path | `/models/lgbm_v1.0.0.onnx` |
| Strength | Best accuracy on known attack patterns |

#### Model 2: Extended Isolation Forest (30% weight)

| Property | Value |
|----------|-------|
| Type | Unsupervised anomaly detector |
| Format | joblib pickle (`.pkl`) |
| Training | Normal-only data (learns what "normal" looks like) |
| Output | Anomaly score normalized to [0, 1] |
| Threshold | Loaded from `eif_threshold.npy` |
| Path | `/models/eif_v1.0.0.pkl` |
| Strength | Detects novel/zero-day anomalies unseen in training |

#### Model 3: River ARF + ADWIN (20% weight)

| Property | Value |
|----------|-------|
| Type | Online Adaptive Random Forest with concept drift detection |
| Framework | River (Python streaming ML) |
| Training | Continuous online learning via `learn_one()` |
| Drift detection | ADWIN (Adaptive Windowing) — detects distribution shifts |
| Warm restart | Fresh model replays last 24h from `arf_replay_buffer` |
| Output | `P(attack)` probability in [0, 1] |
| Strength | Adapts to evolving threats in real-time |

**Why warm restart instead of pickle.load?**

River's ARF produces **constant probabilities** after `pickle.load()` — this is an upstream bug where the Hoeffding trees lose their splitting criteria. The production solution:

1. Create a fresh `ARFClassifier(n_models=10, seed=42)`
2. Query `arf_replay_buffer` from ClickHouse (last 24h, max 50K rows)
3. Replay each row via `learn_one(x, y)` to rebuild the internal trees
4. After replay, ARF produces varying, meaningful probabilities
5. Continue learning on every new scored event

**ARF Hyperparameters (must match training notebook):**

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `ARF_N_MODELS` | 10 | Number of trees in the forest |
| `ARF_ADWIN_DELTA` | 0.002 | ADWIN drift detection sensitivity |
| `ARF_ADWIN_WARNING_DELTA` | 0.01 | ADWIN warning level threshold |
| `ARF_SEED` | 42 | Reproducibility seed |
| `ARF_REPLAY_HOURS` | 24 | Hours of replay data to use |
| `ARF_REPLAY_MAX_ROWS` | 50,000 | Maximum rows to replay at startup |

### 5.6 Score Fusion & Routing

Score fusion combines the three model outputs into a single actionable decision.

**Formula:**

```
combined_score = lgbm_score × 0.50 + eif_score × 0.30 + arf_score × 0.20

std_dev   = std(lgbm_score, eif_score, arf_score)
agreement = 1.0 − std_dev
ci_lower  = max(0, combined_score − 1.96 × std_dev)
ci_upper  = min(1, combined_score + 1.96 × std_dev)

adjusted_score = combined_score × asset_multiplier
```

**Routing logic:**

```
IF allowlist match            → action = "discard" (bypass scoring)
IF ioc_match found            → action = "escalate" (immediate escalation)
IF adjusted_score ≥ anomalous → action = "escalate"
IF adjusted_score ≥ suspicious → action = "monitor"
ELSE                          → action = "discard"
```

**Per-source adaptive thresholds** (from `source_thresholds` table):

| Source Type | Suspicious | Anomalous |
|-------------|-----------|-----------|
| syslog | 0.70 | 0.90 |
| windows_event | 0.65 | 0.85 |
| firewall | 0.60 | 0.80 |
| active_directory | 0.55 | 0.75 |
| dns | 0.60 | 0.82 |
| cloudtrail | 0.58 | 0.80 |
| kubernetes | 0.62 | 0.83 |
| nginx | 0.68 | 0.88 |
| netflow | 0.65 | 0.85 |
| ids_ips | 0.50 | 0.70 |

**TriageResult output** (28 fields → `triage_scores` table):

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | String | Unique event identifier |
| `timestamp` | DateTime | Event timestamp |
| `source_type` | String | Log source category |
| `hostname` | String | Origin host |
| `source_ip` | String | Source IP address |
| `user_id` | String | Associated user |
| `template_id` | String | Drain3 template identifier |
| `template_rarity` | Float32 | Template rarity score (0–1) |
| `combined_score` | Float32 | Weighted ensemble score |
| `lgbm_score` | Float32 | LightGBM probability |
| `eif_score` | Float32 | EIF anomaly score |
| `arf_score` | Float32 | ARF probability |
| `score_std_dev` | Float32 | Model disagreement |
| `agreement` | Float32 | 1 − std_dev |
| `ci_lower` | Float32 | 95% CI lower bound |
| `ci_upper` | Float32 | 95% CI upper bound |
| `asset_multiplier` | Float32 | Host criticality boost |
| `adjusted_score` | Float32 | Final score after adjustments |
| `action` | String | discard / monitor / escalate |
| `ioc_match` | UInt8 | IOC found (0/1) |
| `ioc_confidence` | UInt8 | IOC confidence level |
| `mitre_tactic` | String | MITRE ATT&CK tactic |
| `mitre_technique` | String | MITRE ATT&CK technique ID |
| `features_stale` | UInt8 | Feature freshness flag |
| `model_version` | String | Ensemble model version string |
| `disagreement_flag` | UInt8 | Models disagreed significantly |

### 5.7 Online Learning Loop

The ARF model continuously learns from every scored event, creating a feedback loop:

```
┌──────────────────────────────────────────────────────────────┐
│                    ONLINE LEARNING LOOP                        │
│                                                                │
│  Event arrives                                                 │
│      │                                                         │
│      ▼                                                         │
│  Extract 20 features                                           │
│      │                                                         │
│      ├──▶ LightGBM + EIF + ARF → predict                     │
│      │                                                         │
│      ▼                                                         │
│  Score Fusion → TriageResult                                   │
│      │                                                         │
│      ├──▶ Kafka: triage-scores (all events)                   │
│      ├──▶ Kafka: anomaly-alerts (if escalated)                │
│      │                                                         │
│      ├──▶ ClickHouse: arf_replay_buffer                       │
│      │    (20 features + derived label for ARF replay)         │
│      │                                                         │
│      └──▶ ARF: learn_one(features, label)                     │
│           (incremental tree update + ADWIN drift check)        │
│                                                                │
│  On restart:                                                   │
│      Fresh ARF → replay arf_replay_buffer → rebuild trees     │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

The `arf_replay_buffer` table stores the 20 canonical features plus the derived label for every scored event. This serves two purposes:
1. **Runtime:** ARF learns incrementally via `learn_one()` after every prediction
2. **Restart:** A fresh ARF replays the buffer to rebuild its internal state (warm restart)

### 5.8 Health & Observability

**Health endpoints:**

| Endpoint | Port | Purpose |
|----------|------|---------|
| `GET /health` | 8300 | Full status: startup gates passed, model loaded, self-test result |
| `GET /ready` | 8300 | Kubernetes readiness: returns 200 only when ready to score |
| `GET /stats` | 8300 | Runtime statistics: events processed, ARF model state, error counts |

**Docker healthcheck:**

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=45s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8300/health')"
```

---

## 6. Hunter Agent — Future

> **Status:** Stub (Dockerfile-only placeholder, port 8400)

### Purpose

The Hunter Agent performs **deep investigation** of anomalies escalated by the Triage Agent. It assembles context around flagged entities (users, hosts, IPs) to reconstruct attack chains.

### Planned Data Flow

```
anomaly-alerts / hunter-tasks (Kafka)
    │
    ▼
Hunter Agent
    │
    ├── ClickHouse: temporal correlation queries (±15 min window)
    │   SELECT * FROM security_events
    │   WHERE user_id = '{flagged_user}'
    │     AND timestamp BETWEEN signal_time - 15m AND signal_time + 15m
    │
    ├── LanceDB: semantic similarity search
    │   Find similar historical incidents via 384-dim embedding cosine similarity
    │
    ├── ClickHouse: entity baseline comparison
    │   Check if observed behavior is normal for this user/host
    │   (features_entity_baseline, features_entity_freq tables)
    │
    └── Graph walk: multi-hop entity expansion
        User → Process → Network → IP → User (trace lateral movement)
    │
    ▼
Outputs:
    ├── hunter-results (Kafka) → Verifier Agent + Dashboard
    ├── verifier-tasks (Kafka) → Verifier Agent work queue
    └── hunter_investigations (ClickHouse table)
```

### Planned Configuration

| Variable | Value | Purpose |
|----------|-------|---------|
| `INPUT_TOPICS` | `hunter-tasks` | Work queue from Triage |
| `TOPIC_HUNTER_RESULTS` | `hunter-results` | Investigation findings |
| `TOPIC_VERIFIER_TASKS` | `verifier-tasks` | Handoff to Verifier |
| `CORRELATION_WINDOW_MINUTES` | 30 | Temporal expansion window |
| `MAX_CORRELATED_EVENTS` | 1000 | Max events per investigation |
| `INVESTIGATION_TIMEOUT_SEC` | 120 | Per-investigation timeout |

### Planned Capabilities

1. **Entity Expansion:** Given a flagged entity (user, host, IP), pull all activity ±15 minutes from ClickHouse
2. **Kill Chain Reconstruction:** Trace multi-hop paths through entity relationships
3. **Similarity Search:** Query LanceDB for historically similar attack patterns
4. **Behavioral Baseline:** Compare current behavior against statistical baselines in `features_entity_baseline`
5. **MITRE Mapping:** Map correlated events to ATT&CK tactics and techniques via `mitre_mapping_rules`

### Resource Allocation

| Resource | Limit | Reservation |
|----------|-------|-------------|
| CPU | 2 cores | 0.5 cores |
| Memory | 3 GB | 512 MB |

---

## 7. Verifier Agent — Future

> **Status:** Stub (Dockerfile-only placeholder, port 8500)

### Purpose

The Verifier Agent acts as the **judge** — it validates findings from the Hunter Agent by checking external threat intelligence, verifying log integrity via Merkle proofs, and eliminating false positives.

### Planned Data Flow

```
verifier-tasks (Kafka)
    │
    ▼
Verifier Agent
    │
    ├── ClickHouse: ioc_cache lookup
    │   Check if IPs, domains, file hashes are known-malicious
    │
    ├── External APIs: VirusTotal + AbuseIPDB
    │   Real-time IOC validation against threat intel feeds
    │
    ├── Merkle Service: proof verification
    │   Verify SHA-256 Merkle proofs to ensure source logs
    │   haven't been tampered with (evidence integrity)
    │
    ├── Historical FP analysis
    │   Compare against known false positive patterns
    │
    └── Priority assignment (P1–P4)
        Based on severity, asset criticality, IOC confidence
    │
    ▼
Outputs:
    ├── verifier-results (Kafka) → Reporter Agent + Dashboard
    │   Verdict: CONFIRMED_INCIDENT or FALSE_POSITIVE
    │
    ├── feedback-labels (Kafka) → Model retraining pipeline
    │   TP/FP labels flow back to improve Triage Agent models
    │
    └── verifier_results (ClickHouse table)
```

### Planned Configuration

| Variable | Value | Purpose |
|----------|-------|---------|
| `INPUT_TOPICS` | `verifier-tasks` | Work queue from Hunter |
| `TOPIC_VERIFIER_RESULTS` | `verifier-results` | Verified findings |
| `TOPIC_FEEDBACK_LABELS` | `feedback-labels` | Labels for retraining |
| `MERKLE_SERVICE_URL` | `http://clif-merkle:9400` | Evidence integrity API |
| `IOC_CACHE_TABLE` | `ioc_cache` | ClickHouse IOC lookup |
| `EVIDENCE_CHAIN_VERIFY` | `true` | Enable Merkle proof checks |

### Planned Capabilities

1. **IOC Validation:** Cross-reference IPs, domains, hashes against VirusTotal and AbuseIPDB
2. **Merkle Proof Verification:** Verify SHA-256 Merkle proofs from evidence anchors in S3 (WORM)
3. **False Positive Elimination:** Pattern matching against historical FP signatures
4. **Priority Assignment:** P1 (critical, immediate) through P4 (informational) based on compound scoring
5. **Feedback Labels:** Generate TP/FP labels that flow back to the model retraining pipeline via `feedback-labels` topic

### Feedback Loop to Triage Agent

The Verifier Agent closes the learning loop:

```
Verifier verdict (TP/FP)
    │
    ├──▶ feedback-labels (Kafka topic)
    │       │
    │       ▼
    │    feedback_labels (ClickHouse table)
    │       │
    │       ▼
    │    Model retraining pipeline
    │       • Retrain LightGBM with corrected labels
    │       • Update EIF normal-data distribution
    │       • ARF learns incrementally in real-time
    │
    └──▶ triage_scores table updated with ground truth
```

### Resource Allocation

| Resource | Limit | Reservation |
|----------|-------|-------------|
| CPU | 2 cores | 0.5 cores |
| Memory | 2 GB | 512 MB |

---

## 8. Reporter Agent — Future

> **Status:** Planned (no Dockerfile yet)

### Purpose

The Reporter Agent produces **human-readable incident reports**, maps attacks to the MITRE ATT&CK framework, and triggers automated SOAR (Security Orchestration, Automation, Response) actions.

### Planned Data Flow

```
verifier-results (Kafka)
    │
    ▼
Reporter Agent
    │
    ├── LLM narrative generation
    │   Generate executive summary from structured incident data
    │
    ├── MITRE ATT&CK kill chain mapping
    │   Map correlated events to tactics → techniques → sub-techniques
    │   using mitre_mapping_rules table
    │
    ├── Timeline reconstruction
    │   Chronological event sequence with evidence links
    │
    ├── Evidence references
    │   Link to Merkle-anchored S3 evidence archives
    │
    └── SOAR actions
        Automated response: isolate host, block IP, alert team
    │
    ▼
Outputs:
    ├── Markdown incident reports → Dashboard (API Gateway)
    ├── Slack / PagerDuty notifications
    ├── SOAR playbook execution
    └── Compliance report generation
```

### Report Structure

Each confirmed incident produces a report containing:

```
┌──────────────────────────────────────────────┐
│         INCIDENT REPORT: INV-2026-XXX         │
├──────────────────────────────────────────────┤
│ Executive Summary                             │
│ • What happened, impact, urgency              │
├──────────────────────────────────────────────┤
│ Kill Chain Analysis (MITRE ATT&CK)            │
│ • Tactic → Technique → Evidence               │
├──────────────────────────────────────────────┤
│ Timeline                                      │
│ • Chronological event sequence                │
├──────────────────────────────────────────────┤
│ Evidence (Merkle-Anchored)                    │
│ • Event IDs, Merkle roots, S3 archive links  │
├──────────────────────────────────────────────┤
│ Recommended Actions                           │
│ • Immediate / Short-term / Long-term          │
└──────────────────────────────────────────────┘
```

---

## 9. Agent-to-Agent Data Flow

### Complete Agent Pipeline

```
┌─────────┐    anomaly-alerts     ┌─────────┐    verifier-tasks    ┌──────────┐    verifier-results   ┌──────────┐
│ TRIAGE  │ ──────────────────▶   │ HUNTER  │ ──────────────────▶  │ VERIFIER │ ──────────────────▶   │ REPORTER │
│ AGENT   │    hunter-tasks       │ AGENT   │    hunter-results    │  AGENT   │    feedback-labels    │  AGENT   │
│         │                       │         │                      │          │                       │          │
│ Port    │                       │ Port    │                      │ Port     │                       │ Port     │
│ 8300    │                       │ 8400    │                      │ 8500     │                       │ 8600     │
└────┬────┘                       └────┬────┘                      └────┬─────┘                       └────┬─────┘
     │                                 │                                │                                  │
     │                                 │                                │                                  │
     ▼                                 ▼                                ▼                                  ▼
┌─────────┐                       ┌─────────┐                      ┌─────────┐                       ┌─────────┐
│ClickHouse│                      │ClickHouse│                     │ClickHouse│                      │ Dashboard│
│triage_   │                      │hunter_   │                     │verifier_ │                      │ API      │
│scores    │                      │investig- │                     │results   │                      │ Gateway  │
│arf_replay│                      │ations    │                     │feedback_ │                      │          │
│_buffer   │                      │          │                     │labels    │                      │          │
└──────────┘                      └──────────┘                     └──────────┘                      └──────────┘
                                       │
                                       ▼
                                  ┌──────────┐
                                  │ LanceDB  │
                                  │(semantic │
                                  │ search)  │
                                  └──────────┘
```

### Topic Flow Matrix

| From \ To | Triage | Hunter | Verifier | Reporter | Consumer | Dashboard |
|-----------|--------|--------|----------|----------|----------|-----------|
| **Vector** | raw-logs, security-events, process-events, network-events | — | — | — | same 4 topics | — |
| **Triage** | — | anomaly-alerts, hunter-tasks | — | — | triage-scores | — |
| **Hunter** | — | — | verifier-tasks | — | hunter-results | hunter-results |
| **Verifier** | feedback-labels | — | — | verifier-results | verifier-results, feedback-labels | verifier-results |
| **Reporter** | — | — | — | — | — | Reports via API |

### Data Store Access Matrix

| Store | Triage | Hunter | Verifier | Reporter | Consumer |
|-------|--------|--------|----------|----------|----------|
| **ClickHouse (read)** | source_thresholds, ioc_cache, allowlist, asset_criticality, arf_replay_buffer | security_events, process_events, network_events, features_entity_baseline, features_entity_freq | ioc_cache, evidence_anchors, verifier_results | mitre_mapping_rules, all event tables | — |
| **ClickHouse (write)** | arf_replay_buffer | hunter_investigations | verifier_results, feedback_labels | — | all tables (from Kafka) |
| **LanceDB** | — | Semantic similarity search | — | — | — |
| **Merkle Service** | — | — | Proof verification | Evidence links | — |
| **Threat Intel** | — | — | VT + AbuseIPDB queries | — | — |
| **MinIO (S3)** | — | — | Evidence archive | Report storage | — |

---

## 10. Deployment Topology

### Docker: 2-PC Split

```
┌──────────────────────────────────────────────────────────────┐
│  PC1 — DATA TIER  (docker-compose.pc1.yml, 14 services)      │
│                                                                │
│  ClickHouse Keeper → ClickHouse ×2 (replicated shard)        │
│  Redpanda ×3 (Kafka-compatible) + Console                     │
│  MinIO ×3 (erasure coded S3) + Init                           │
│  Prometheus + Grafana                                          │
│  Vector (log aggregator) + Merkle Service                     │
└──────────────────────┬───────────────────────────────────────┘
                       │ Cross-PC network (Kafka + CH Native TCP)
                       │
┌──────────────────────┴───────────────────────────────────────┐
│  PC2 — AI COMPUTE TIER  (docker-compose.pc2.yml, 10 services) │
│                                                                │
│  Consumer ×3 (Redpanda → ClickHouse, 82K EPS)                │
│  Triage Agent (3-model ensemble, port 8300)                   │
│  Hunter Agent (stub, port 8400)                                │
│  Verifier Agent (stub, port 8500)                              │
│  LanceDB (384-dim vector search, port 8100)                   │
│  SOC Dashboard (Next.js 14, port 3001)                        │
└───────────────────────────────────────────────────────────────┘
```

### Kubernetes: Kustomize with 3 Overlays

```
k8s/
├── base/                     # 59+ resources
│   ├── deployments/          # All services as Deployments
│   ├── services/             # ClusterIP + NodePort services
│   ├── pvcs/                 # PersistentVolumeClaims
│   │   └── triage-models.yaml   # 1Gi ReadOnlyMany for model artifacts
│   ├── configmaps/           # Configuration files
│   └── kustomization.yaml    # Base resource list
├── overlays/
│   ├── dev/                  # Single replica, relaxed limits
│   ├── staging/              # Scaled replicas, monitoring enabled
│   └── production/           # Full HA, strict resource limits
└── README.md
```

---

## 11. Model Artifacts

The Triage Agent requires 5 model files in the `/models` directory:

| File | Size (approx.) | Source | Description |
|------|-----------------|--------|-------------|
| `lgbm_v1.0.0.onnx` | ~2 MB | Training notebook (LightGBM → ONNX export) | Gradient boosting binary classifier |
| `eif_v1.0.0.pkl` | ~500 KB | Training notebook (joblib dump) | Extended Isolation Forest fitted model |
| `eif_threshold.npy` | ~128 B | Training notebook (numpy save) | EIF anomaly score threshold |
| `feature_cols.pkl` | ~1 KB | Training notebook (pickle dump) | Ordered feature column names (authority list) |
| `manifest.json` | ~500 B | Training notebook | Model versions, training date, metrics |

**Optional cold-start file:**

| File | Purpose |
|------|---------|
| `features_arf_stream_features.csv` | Offline CSV fallback for ARF warm restart when `arf_replay_buffer` is empty |

**Important:** ARF does NOT load from a pickle file at runtime. The pickle file (`arf_v1.0.0.pkl`) exists only as an offline reference. Production inference always uses warm restart (fresh model + replay buffer).

---

## 12. Configuration Reference

All configuration is via environment variables with sensible defaults.

### Kafka / Redpanda

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_BROKERS` | `redpanda01:9092` | Comma-separated broker list |
| `CONSUMER_GROUP_ID` | `clif-triage-agent` | Consumer group for triage |
| `INPUT_TOPICS` | `raw-logs,security-events,process-events,network-events` | Topics to consume |
| `TOPIC_TRIAGE_SCORES` | `triage-scores` | Output topic for all scores |
| `TOPIC_ANOMALY_ALERTS` | `anomaly-alerts` | Output topic for escalated events |
| `TOPIC_TEMPLATED_LOGS` | `templated-logs` | Output for Drain3 templates |
| `TOPIC_DEAD_LETTER` | `dead-letter` | Failed event parking |

### ClickHouse

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_HOST` | `clickhouse01` | ClickHouse native protocol host |
| `CLICKHOUSE_PORT` | `9000` | Native TCP port |
| `CLICKHOUSE_USER` | `clif_admin` | Database user |
| `CLICKHOUSE_PASSWORD` | `clif_secure_password_change_me` | Database password |
| `CLICKHOUSE_DB` | `clif_logs` | Target database |

### Models

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_DIR` | `/models` | Model artifact directory |
| `MODEL_LGBM_PATH` | `/models/lgbm_v1.0.0.onnx` | LightGBM ONNX model |
| `MODEL_EIF_PATH` | `/models/eif_v1.0.0.pkl` | EIF fitted model |
| `MODEL_EIF_THRESHOLD_PATH` | `/models/eif_threshold.npy` | EIF anomaly threshold |
| `FEATURE_COLS_PATH` | `/models/feature_cols.pkl` | Feature column order |
| `MANIFEST_PATH` | `/models/manifest.json` | Model version manifest |
| `SCORE_WEIGHTS` | `lgbm=0.50,eif=0.30,arf=0.20` | Ensemble weight distribution |

### Drain3

| Variable | Default | Description |
|----------|---------|-------------|
| `DRAIN3_DEPTH` | `4` | Parse tree depth |
| `DRAIN3_SIM_TH` | `0.4` | Template similarity threshold |
| `DRAIN3_MAX_CLUSTERS` | `1024` | Max template clusters |
| `DRAIN3_MAX_CHILDREN` | `100` | Max children per tree node |
| `DRAIN3_CONFIG_PATH` | `/app/drain3.ini` | Regex masking rules file |

### Thresholds

| Variable | Default | Description |
|----------|---------|-------------|
| `DEFAULT_SUSPICIOUS_THRESHOLD` | `0.70` | Global suspicious threshold |
| `DEFAULT_ANOMALOUS_THRESHOLD` | `0.90` | Global anomalous threshold |
| `DISAGREEMENT_THRESHOLD` | `0.35` | Model disagreement flag threshold |

### Connection Tracking

| Variable | Default | Description |
|----------|---------|-------------|
| `CONN_TIME_WINDOW_SEC` | `2.0` | Sliding window for KDD features |
| `CONN_HOST_WINDOW_SIZE` | `100` | Host connection history size |
| `CONN_CLEANUP_INTERVAL_SEC` | `10.0` | Stale connection cleanup period |

### ARF Warm Restart

| Variable | Default | Description |
|----------|---------|-------------|
| `ARF_WARM_RESTART` | `true` | Enable warm restart (recommended) |
| `ARF_REPLAY_HOURS` | `24` | Hours of history to replay |
| `ARF_REPLAY_MAX_ROWS` | `50000` | Max rows to replay |
| `ARF_STREAM_CSV_PATH` | `/models/features_arf_stream_features.csv` | Cold-start CSV fallback |
| `ARF_N_MODELS` | `10` | Number of trees |
| `ARF_ADWIN_DELTA` | `0.002` | Drift sensitivity |
| `ARF_ADWIN_WARNING_DELTA` | `0.01` | Warning sensitivity |
| `ARF_SEED` | `42` | Random seed |

### Operational

| Variable | Default | Description |
|----------|---------|-------------|
| `BATCH_SIZE` | `1000` | Events per inference batch |
| `INFERENCE_WORKERS` | `4` | Thread pool workers |
| `LOG_LEVEL` | `INFO` | Logging level |
| `TRIAGE_PORT` | `8300` | Health endpoint port |
| `SELFTEST_ENABLED` | `true` | Run self-test on startup |
| `STARTUP_HEALTH_RETRIES` | `30` | Max health gate retries |
| `STARTUP_HEALTH_DELAY_SEC` | `2.0` | Delay between retries |

---

*CLIF — Cognitive Log Investigation Framework — Triage Agent Documentation v1.0*
