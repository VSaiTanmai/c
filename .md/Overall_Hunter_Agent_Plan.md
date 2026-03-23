# CLIF Hunter Agent — Hybrid Implementation Plan

> **Project:** CLIF — Cognitive Log Investigation Framework (SIH1733)  
> **Agent:** Hunter Agent (Agent #2 in the 4-agent pipeline)  
> **Architecture:** Hybrid — Triple-Layer Detection + Parallel Investigation Pipeline  
> **Date:** March 4, 2026  
> **Status:** Planning Complete — Ready for Implementation  
> **Lineage:** Merger of Triple-Layer Plan (Sigma+SPC+ML) + V6 Implementation Spec (CatBoost+L1/L2 Parallel)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Position in the Agentic Pipeline](#2-position-in-the-agentic-pipeline)
3. [Data Contract: Triage → Hunter](#3-data-contract-triage--hunter)
4. [Hybrid Architecture Overview](#4-hybrid-architecture-overview)
5. [Fast Path — Sigma Rule Engine](#5-fast-path--sigma-rule-engine)
6. [L1 Parallel Investigation (4 Threads)](#6-l1-parallel-investigation-4-threads)
7. [L2 Parallel Investigation (2 Threads)](#7-l2-parallel-investigation-2-threads)
8. [RAG Narrative Builder](#8-rag-narrative-builder)
9. [Fusion Decision Engine](#9-fusion-decision-engine)
10. [Scoring Engine — 2-Phase (Heuristic → CatBoost)](#10-scoring-engine--2-phase-heuristic--catboost)
11. [Self-Supervised Training Pipeline](#11-self-supervised-training-pipeline)
12. [Drift Detection](#12-drift-detection)
13. [Novelty Paradox Solution (4-Layer)](#13-novelty-paradox-solution-4-layer)
14. [Attack Graph Construction](#14-attack-graph-construction)
15. [ClickHouse Schema & Tables](#15-clickhouse-schema--tables)
16. [LanceDB Integration](#16-lancedb-integration)
17. [Output Contract & Kafka Topics](#17-output-contract--kafka-topics)
18. [Infrastructure & Performance Budget](#18-infrastructure--performance-budget)
19. [Implementation Phases](#19-implementation-phases)
20. [File Structure](#20-file-structure)
21. [Testing Strategy](#21-testing-strategy)
22. [Risks & Mitigations](#22-risks--mitigations)

---

## 1. Executive Summary

The Hunter Agent is the **investigator** in CLIF's 4-agent pipeline (Triage → **Hunter** → Verifier → Reporter). This plan merges two complementary designs:

- **Triple-Layer Detection** (Sigma Rules + SPC Baselines + ML) — provides three fundamentally different detection paradigms for maximum coverage
- **V6 Parallel Investigation Pipeline** (Temporal + Similarity + Graph + MITRE + Campaign) — provides verified ClickHouse SQL, self-supervised training, and drift detection

### What Each Source Contributes

| Component | Source | Why |
|-----------|--------|-----|
| Sigma Rule Engine (fast-path) | Triple-Layer Plan | Deterministic known-attack detection in < 5ms; 52 community rules already in repo |
| SPC Behavioral Baselines | Triple-Layer Plan | Entity-level anomaly detection independent of ML; catches novel threats SPC can't classify |
| Fusion Decision Matrix | Triple-Layer Plan | 2-of-3 agreement paradigm; Sigma/SPC authority over ML |
| Novelty Paradox 4-Layer Solution | Triple-Layer Plan | Distance detection + Triage authority + multi-signal matrix + attack_embeddings |
| Temporal Correlator | V6 Plan | 3 verified CH queries, 4 output features |
| Similarity Searcher | V6 Plan | 3 LanceDB calls, multi-signal decision matrix, 7 features |
| Graph Builder | V6 Plan | 5 verified CH queries, 8 features, V6 noisy-IP cap |
| MITRE Mapper | V6 Plan | Rule matching with V6 trigger feature fix + startup validation |
| Campaign Detector | V6 Plan | Cross-table JOIN for coordinated attacks |
| 2-Phase Scoring | V6 Plan | Heuristic Day 0 → CatBoost at 100 samples, hot-reload |
| Self-Supervised Training | V6 Plan | Label hierarchy (analyst > verifier > pseudo), 6hr retraining |
| Drift Detection | V6 Plan | KL + PSI + Triage-anchored divergence (3 independent signals) |
| RAG Narrative Builder | V6 Plan | Structured assembly with severity/finding_type logic |

### Architecture Summary

| Tier | Components | Speed | Cold-Start |
|------|-----------|-------|------------|
| **Fast Path** | Sigma Rules → ClickHouse SQL | < 5 ms | Works from event #1 |
| **L1 Parallel** | Temporal + Similarity + Graph + SPC (4 threads) | ~50 ms | SPC needs ~24h; others immediate |
| **L2 Parallel** | MITRE Mapper + Campaign Detector (2 threads) | ~20 ms | Immediate |
| **Fusion** | Triple-Layer Decision Matrix + 2-Phase Scoring | < 5 ms | Heuristic Day 0; CatBoost at 100 samples |

**Why Hybrid?** Neither plan alone is sufficient:
- V6 has no Sigma rules → known attacks depend entirely on ML
- V6 has no SPC baselines → novel anomaly detection depends on EIF passthrough alone
- Triple-Layer lacks V6's verified SQL, training pipeline, drift detection, and campaign detection
- Combined: **deterministic + statistical + probabilistic** detection with production-grade ML lifecycle

**Performance target:** < 80 ms per investigation (p95), < 10 ms for Sigma fast-path hits  
**Feature vector:** 42 dimensions (V6's 36 + 4 Sigma/SPC + 2 SPC detail)  
**Output:** `hunter_investigations` table (17 fields) + `hunter-results` Kafka topic + `hunter_training_data` (direct CH write)

---

## 2. Position in the Agentic Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                        DATA PLANE                                │
│  Sources (7 types) → Vector VRL → Redpanda → Consumer → CH      │
│                                              → Triage Agent      │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │     TRIAGE AGENT        │
                    │  LGBM(0.60) + EIF(0.15) │
                    │  + ARF(0.25) ensemble   │
                    │  F1 = 0.9636            │
                    │                         │
                    │  action = escalate      │───── hunter-tasks topic
                    │  action = monitor       │───── triage-scores topic
                    │  action = discard       │───── triage-scores topic
                    └─────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   ★ HUNTER AGENT ★      │
                    │                         │
                    │  Fast Path: Sigma Rules │
                    │  L1: Temporal+Similarity │
                    │      +Graph+SPC (∥)     │
                    │  L2: MITRE+Campaign (∥) │
                    │  Fusion: Triple-Layer   │
                    │  Scoring: 2-Phase ML    │
                    │                         │
                    │  → Attack Graph         │
                    │  → RAG Narrative        │
                    │  → Evidence Assembly    │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    VERIFIER AGENT       │
                    │  IOC validation          │
                    │  Merkle proof check      │
                    │  TP/FP verdict           │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    REPORTER AGENT       │
                    │  Narrative generation    │
                    │  MITRE kill chain        │
                    │  Slack/PagerDuty notify  │
                    └─────────────────────────┘
```

---

## 3. Data Contract: Triage → Hunter

### Input: `hunter-tasks` Kafka Topic

Hunter consumes from `hunter-tasks` (6 partitions, created by `redpanda-init`). All messages are pre-filtered `action='escalate'` by Triage. Hunter applies a secondary gate: `adjusted_score > 0.65`.

**Source verification:** `agents/triage/app.py` lines 808-816 — escalated events published to `hunter-tasks`.

### TriageResult Payload (26 fields)

**Source verification:** `agents/triage/score_fusion.py` lines 42-68 (TriageResult dataclass)

| Field | Type | Hunter Usage |
|-------|------|-------------|
| `event_id` | UUID | → `alert_id` in hunter_investigations |
| `timestamp` | DateTime64(3) | Investigation time window anchor, off_hours derivation |
| `source_type` | String | Route to source-specific Sigma rules |
| `hostname` | String | Entity expansion + SPC baselines + Graph builder |
| `source_ip` | String | Entity expansion + Graph builder + SPC baselines |
| `user_id` | String | Entity expansion queries |
| `template_id` | String | SPC baseline key + MITRE trigger feature derivation |
| `template_rarity` | Float32 | Feature vector + novelty signal (≥ 0.8 = rare) |
| `combined_score` | Float32 | Reference (pre-adjustment score) |
| `lgbm_score` | Float32 | Feature vector |
| `eif_score` | Float32 | Feature vector + novelty signal (EIF ≥ 0.65 = strong anomaly) |
| `arf_score` | Float32 | Feature vector |
| `score_std_dev` | Float32 | Feature vector |
| `agreement` | Float32 | Feature vector |
| `ci_lower` | Float32 | Feature vector |
| `ci_upper` | Float32 | Feature vector |
| `asset_multiplier` | Float32 | Feature vector |
| `adjusted_score` | Float32 | → `trigger_score` + feature vector + Triage-anchored drift |
| `action` | String | Always 'escalate' on hunter-tasks (redundant check removed) |
| `ioc_match` | UInt8 | Feature vector + Sigma context |
| `ioc_confidence` | Float32 | Feature vector |
| `mitre_tactic` | String | MITRE mapper + Attack graph node |
| `mitre_technique` | String | MITRE mapper + Attack graph edge |
| `features_stale` | UInt8 | Quality gate |
| `model_version` | String | Audit trail |
| `disagreement_flag` | UInt8 | Feature vector + novelty signal |

### Field Alignment with Consumer Output

**Source verification:** `consumer/app.py` `_build_hunter_investigation_row()` method

| Hunter Output Field | Consumer Expected Key | Type |
|--------------------|-----------------------|------|
| `alert_id` | `msg.get("alert_id")` | String (UUID) |
| `source_event_id` | `msg.get("source_event_id")` | String (UUID) |
| `started_at` | `msg.get("started_at")` | DateTime64(3) |
| `completed_at` | `msg.get("completed_at")` | DateTime64(3) |
| `trigger_score` | `msg.get("trigger_score")` | Float32 |
| `confidence` | `msg.get("confidence")` | Float32 |
| `severity` | `msg.get("severity")` | Enum8 (0-4) |
| `finding_type` | `msg.get("finding_type")` | String |
| `summary` | `msg.get("summary")` | String |
| `evidence_json` | `msg.get("evidence_json")` | String (JSON) |
| `mitre_tactics` | `msg.get("mitre_tactics")` | Array(String) |
| `mitre_techniques` | `msg.get("mitre_techniques")` | Array(String) |
| `related_events` | `msg.get("related_events")` | Array(String) |
| `investigation_status` | `msg.get("investigation_status")` | Enum8 (0-4) |
| `assigned_to` | `msg.get("assigned_to")` | String |
| `hostname` | `msg.get("hostname")` | String |
| `source_type` | `msg.get("source_type")` | String |

### Triage Action Distribution (from live data)

| Action | Count | % |
|--------|-------|---|
| Escalate | 233,854 | 60.3% |
| Monitor | 117,772 | 30.4% |
| Discard | 36,158 | 9.3% |

> After `adjusted_score > 0.65` gate: estimated ~60-70% of escalated events pass → **~140K-164K events** enter the full pipeline per batch window.

### Escalation by Source Type

| Source Type | Escalation Rate | Volume |
|------------|----------------|--------|
| dns | 97.9% | Very High |
| ids_ips | 58.1% | High |
| netflow | 77.3% | High |
| windows_event | 100% | Medium |
| syslog_linux_auth | 100% | Medium |
| active_directory | 100% | Low |

---

## 4. Hybrid Architecture Overview

```
          ┌─────────────────────────────────────────┐
          │  HUNTER-TASKS  (adjusted_score > 0.65)   │
          └──────────────────┬──────────────────────┘
                             │
                    ┌────────▼────────┐
                    │   FAST PATH     │
                    │  Sigma Engine   │   < 5ms
                    │  52 YAML→SQL    │
                    └────┬───────┬────┘
                         │       │
              sigma_hit? │       │ sigma features
              ┌──────────┘       └──────────────────────┐
              │ YES                                      │ ALWAYS
              ▼                                          ▼
    ┌─────────────────┐               ┌─────────────────────────────────────┐
    │  CONFIRMED       │               │   L1 PARALLEL  (4 async threads)   │
    │  (known attack)  │               │                                     │
    │  Skip full pipe  │               │  T1: Temporal Correlator → 4 feat  │
    │  if confidence   │               │  T2: Similarity Searcher → 7 feat  │
    │  > 0.85          │               │  T3: Graph Builder       → 8 feat  │
    │                  │               │  T4: SPC Engine          → 4 feat  │
    │  Still writes    │               │                           ~50ms     │
    │  full evidence   │               └───────────────┬─────────────────────┘
    └────────┬────────┘                                │
             │                          ┌──────────────▼──────────────────────┐
             │                          │   L2 PARALLEL  (2 async threads)    │
             │                          │                                      │
             │                          │  T1: MITRE Mapper     → 2 features  │
             │                          │  T2: Campaign Detector → 2 features │
             │                          │                          ~20ms       │
             │                          └──────────────┬──────────────────────┘
             │                                         │
             │                          ┌──────────────▼──────────────────────┐
             │                          │      FUSION DECISION ENGINE         │
             │                          │                                      │
             │                          │  Triple-Layer Matrix:                │
             │                          │    Sigma + SPC + ML features         │
             │                          │    2-of-3 agreement = high conf      │
             │                          │                                      │
             │                          │  2-Phase Scoring:                    │
             │                          │    Day 0: Heuristic (42-dim)        │
             │                          │    100+ samples: CatBoost           │
             │                          └──────────────┬──────────────────────┘
             │                                         │
             │         ┌───────────────────────────────┤
             │         │                               │
             ▼         ▼                               ▼
    ┌──────────────────────┐    ┌──────────────┐   ┌────────────────┐
    │  RAG Narrative       │    │ Attack Graph │   │ Training Data  │
    │  Builder             │    │ Builder      │   │ Writer (CH)    │
    └──────────┬───────────┘    └──────┬───────┘   └────────────────┘
               │                       │
               ▼                       ▼
    ┌──────────────────────────────────────────┐
    │           OUTPUT                          │
    │  hunter_investigations (CH via consumer)  │
    │  hunter-results (Kafka topic)             │
    │  hunter_training_data (CH direct write)   │
    └──────────────────────────────────────────┘
```

### Why This Architecture

Six alternative architectures were evaluated against live ClickHouse data. Two were **eliminated by data constraints**:

- **Temporal Transformers / LSTM** — ELIMINATED: Data shows MITRE tactics occur **simultaneously** (all 3 in the same minute on MSEDGEWIN10), not sequentially. Also 300K events/window × per-token processing = infeasible on 6C CPU.
- **Graph Neural Networks** — ELIMINATED: 300K events per investigation window. O(n·k) graph construction. No graph-labeled training data. 16 GB RAM insufficient. Deferred to Phase 5 once Verifier provides 500+ verified samples.

The hybrid was chosen because:
1. **Sigma fast-path** removes ~15-30% of events from the full pipeline, reducing latency and load
2. **SPC baselines** provide entity-level anomaly detection that ML cannot replicate (novel zero-days)
3. **V6's parallel L1/L2 threads** give verified, production-ready investigation enrichment
4. **V6's training pipeline** solves the cold-start → warm model transition
5. **2-of-3 agreement** (Sigma+SPC+ML) gives confidence levels no single paradigm can achieve

---

## 5. Fast Path — Sigma Rule Engine

### What It Is

[Sigma](https://github.com/SigmaHQ/sigma) is a community-maintained, vendor-neutral detection rule format (YAML). CLIF has **52 Sigma rules** in `agents/Data/datasets/10_ids_ips_zeek/path_a_lightgbm/Sigma_IDS/`:

| Category | Rules | Example |
|----------|-------|---------|
| cisco | 8 | Cisco ASA threat detection |
| dns | 6 | Cobalt Strike DNS beaconing (`aaa.stage.*`) |
| firewall | 7 | Generic firewall anomalies |
| fortinet | 8 | FortiGate exploit detection |
| huawei | 7 | Huawei USG rules |
| juniper | 8 | Juniper SRX rules |
| zeek | 8 | Zeek connection anomalies |

### Why Fast Path Matters

Known attacks (Cobalt Strike C2, brute force, firewall bypass) should NOT wait 80ms for the full investigation pipeline. A Sigma rule fires in < 5ms with 100% precision. For these events, Hunter immediately classifies as `confirmed_attack`, writes full evidence, and skips the slower L1/L2 threads.

**Fast-path bypass condition:** `sigma_hit_count > 0 AND sigma_max_severity >= 'high'` AND no SPC/ML enrichment needed (confidence already > 0.85 from the Sigma match alone). Events that hit Sigma rules with `medium` or lower severity still enter the full pipeline for enrichment.

### How It Works

```
Sigma YAML  ──→  YAML→SQL Compiler  ──→  ClickHouse WHERE clause
                                          │
                                          ▼
                                    SELECT count() FROM security_events
                                    WHERE category = 'dns_query'
                                      AND description LIKE '%aaa.stage%'
                                      AND timestamp BETWEEN {t_start} AND {t_end}
```

Each Sigma rule compiles to a parameterized ClickHouse SQL query at startup. At investigation time, Hunter runs all applicable rules (filtered by `source_type`) against the ±15 min event window.

### Sigma Rule Structure (Example)

```yaml
title: Cobalt Strike DNS Beaconing
status: test
description: Detects DNS queries associated with Cobalt Strike C2 beaconing
logsource:
    category: dns
    product: zeek
detection:
    selection:
        query|contains:
            - 'aaa.stage.'
            - '.stage.123456.'
    condition: selection
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.004
```

### Implementation

```python
class SigmaEngine:
    """Compiles Sigma YAML rules → ClickHouse SQL and evaluates them.
    
    Runs as FAST PATH before L1/L2 threads.
    High-severity hits bypass the full pipeline.
    All hits contribute sigma_hit_count and sigma_max_severity to the 42-dim feature vector.
    """
    
    SEVERITY_MAP = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    
    def __init__(self, rules_dir: str, ch_client):
        self.rules = self._load_rules(rules_dir)
        self.compiled = {r.id: self._compile_to_sql(r) for r in self.rules}
        self.ch = ch_client
        self._validate_rules()  # V6-inspired startup check
    
    def _validate_rules(self):
        """Log WARNING for any rule referencing unknown columns/tables."""
        known_tables = {'security_events', 'dns_events', 'network_events', 'process_events'}
        for rule in self.rules:
            sql = self.compiled[rule.id]
            # Verify table references exist
            for table in known_tables:
                if table in sql:
                    break
            else:
                logger.warning(f"Sigma rule {rule.id} references unknown table: {sql[:100]}")
    
    def evaluate(self, hostname: str, source_type: str,
                 time_start: datetime, time_end: datetime) -> list[SigmaHit]:
        """Run applicable rules against the event window."""
        applicable = [r for r in self.rules if r.matches_source(source_type)]
        hits = []
        for rule in applicable:
            sql = self.compiled[rule.id].format(
                hostname=hostname, t_start=time_start, t_end=time_end
            )
            result = self.ch.execute(sql, settings={'max_execution_time': 3})
            if result and result[0][0] > 0:
                hits.append(SigmaHit(
                    rule_id=rule.id,
                    rule_name=rule.title,
                    mitre_tags=rule.tags,
                    severity=rule.level,
                    severity_numeric=self.SEVERITY_MAP.get(rule.level, 0),
                    matched_events=result[0][0]
                ))
        return hits
    
    def should_fast_path(self, hits: list[SigmaHit]) -> bool:
        """Determine if event can bypass full L1/L2 pipeline."""
        if not hits:
            return False
        max_sev = max(h.severity_numeric for h in hits)
        return max_sev >= 3  # high or critical → fast path
```

### Output → Feature Vector

| Feature | Description | Range |
|---------|-------------|-------|
| `sigma_hit_count` | Number of Sigma rules that fired | 0–52 |
| `sigma_max_severity` | Highest severity of matching rules (0=info, 4=critical) | 0–4 |

### Properties

| Property | Value |
|----------|-------|
| Detection type | Deterministic — same input always produces same output |
| Anomaly detection | **None** — only detects what rules explicitly define |
| Speed | < 5 ms per rule (pure SQL with `max_execution_time=3`) |
| Explainability | Rule name + MITRE tag directly in output |
| Cold-start | Works from event #1 |
| Maintenance | Community-updated; add new rules via YAML |

---

## 6. L1 Parallel Investigation (4 Threads)

All 4 threads run concurrently via `asyncio.gather()`. Combined wall-clock: ~50ms (dominated by ClickHouse/LanceDB I/O).

### Thread 1: Temporal Correlator

**Purpose:** Correlate the current alert with recent activity on the same host within a ±15-minute window.

**Verified SQL queries (all column names confirmed against `clickhouse/schema.sql`):**

#### Query 1 — Escalation Correlation (from `triage_scores`)

```sql
SELECT
    count()                              AS escalation_count,
    uniq(source_type)                    AS unique_categories,
    uniq(mitre_tactic)                   AS tactic_diversity,
    avg(adjusted_score)                  AS mean_score
FROM clif_logs.triage_scores
WHERE hostname = {hostname:String}
  AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
  AND action = 'escalate'
SETTINGS max_execution_time = 8
```

#### Query 2 — Process Chain Context (from `process_events`)

```sql
SELECT
    binary_path,
    arguments,
    pid,
    ppid,
    count() AS exec_count
FROM clif_logs.process_events
WHERE hostname = {hostname:String}
  AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
GROUP BY binary_path, arguments, pid, ppid
ORDER BY exec_count DESC
LIMIT 20
SETTINGS max_execution_time = 8
```

> **V3 fix:** Uses `binary_path`, `arguments`, `pid`, `ppid` — NOT the phantom `process_name`, `parent_process` from V2.

#### Query 3 — DNS Exfiltration Check (from `dns_events`)

```sql
SELECT
    query_name,
    count()       AS query_count,
    uniq(src_ip)  AS unique_sources
FROM clif_logs.dns_events
WHERE timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
  AND src_ip IN (
      SELECT source_ip FROM clif_logs.triage_scores
      WHERE hostname = {hostname:String}
        AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
  )
GROUP BY query_name
ORDER BY query_count DESC
LIMIT 10
SETTINGS max_execution_time = 8
```

#### Output → Feature Vector (4 features)

| Feature | Source | Range |
|---------|--------|-------|
| `temporal_escalation_count` | Query 1 `escalation_count` | 0–1000+ |
| `temporal_unique_categories` | Query 1 `unique_categories` | 0–38 |
| `temporal_tactic_diversity` | Query 1 `tactic_diversity` | 0–6 |
| `temporal_mean_score` | Query 1 `mean_score` | 0.0–1.0 |

**Fallback (query timeout):** `[0, 0, 0, 0.0]` (neutral — does not bias scoring).

---

### Thread 2: Similarity Searcher (V5 Architecture)

**Purpose:** Search LanceDB for similar confirmed attacks, historical incidents, and contextual log matches.

**Critical architectural rule (V5):**
> **LanceDB is a CONTEXT PROVIDER, never a DECISION MAKER.** Hunter uses LanceDB to classify *what kind* of attack (known, novel, evasion), not *whether* it's an attack. Triage's ML scores (especially EIF) are ground truth for anomaly detection.

#### Search 1 — Attack Verdict (`attack_embeddings` table)

```python
# Search confirmed attacks ONLY — this is the verdict search
response = await http_client.post("http://lancedb:8100/search", json={
    "query": f"{source_type} {hostname} {mitre_tactic} {template_id}",
    "table": "attack_embeddings",
    "limit": 5
}, timeout=3.0)
attack_results = response.json()["results"]
attack_distance = attack_results[0]["_distance"] if attack_results else 1.0
```

> **V5 fix:** `attack_embeddings` stores ONLY confirmed attacks (from `triage_scores WHERE action='escalate'`, `security_events WHERE severity >= 5`, `feedback_labels WHERE label='true_positive'`). This prevents the normal-neighbor contamination flaw where searching `log_embeddings` would find "normal" nearest neighbors for novel attacks.

#### Search 2 — Historical Context (`historical_incidents` table)

```python
# Historical incident context for RAG narrative
response = await http_client.post("http://lancedb:8100/search", json={
    "query": f"{source_type} {hostname} {mitre_tactic}",
    "table": "historical_incidents",
    "limit": 3
}, timeout=3.0)
incident_results = response.json()["results"]
incident_match = 1 if incident_results and incident_results[0]["_distance"] < 0.4 else 0
incident_severity = incident_results[0].get("severity", 0) if incident_match else 0
```

#### Search 3 — Log Context (`log_embeddings` table)

```python
# Context search only — NEVER used for verdict
response = await http_client.post("http://lancedb:8100/search", json={
    "query": f"{source_type} {hostname} {template_id}",
    "table": "log_embeddings",
    "limit": 5
}, timeout=3.0)
log_results = response.json()["results"]
log_min_distance = log_results[0]["_distance"] if log_results else 1.0
log_mean_distance = mean([r["_distance"] for r in log_results]) if log_results else 1.0
```

#### Multi-Signal Decision Matrix (Novelty + Evasion Detection)

```python
# Cross-reference LanceDB distances with Triage's statistical signals
eif_high       = triage_msg["eif_score"] >= 0.65
rarity_high    = triage_msg["template_rarity"] >= 0.8
no_attack_match = attack_distance > 0.45

# Novelty flag: No match in attack_embeddings + EIF says statistical outlier
novelty_flag = 1 if (no_attack_match and (eif_high or rarity_high)) else 0

# Evasion flag: Textually similar to normal logs BUT statistical outlier
# The conflict ITSELF is the strongest signal of stealth/evasion (MITRE T1036)
evasion_flag = 1 if (log_min_distance < 0.3 and eif_high and no_attack_match) else 0
```

#### Output → Feature Vector (7 features)

| Feature | Description | Range |
|---------|-------------|-------|
| `similarity_min_distance` | Nearest log_embeddings distance | 0.0–2.0 |
| `similarity_mean_distance` | Mean log_embeddings distance | 0.0–2.0 |
| `similarity_incident_match` | 1 if historical incident match | 0 or 1 |
| `similarity_incident_severity` | Matched incident severity | 0–4 |
| `similarity_attack_distance` | Distance to nearest confirmed attack | 0.0–2.0 |
| `similarity_novelty_flag` | 1 if novel anomaly detected | 0 or 1 |
| `similarity_evasion_flag` | 1 if stealth/evasion detected | 0 or 1 |

**Fallback (LanceDB unavailable):** `[1.0, 1.0, 0, 0, 1.0, 0, 0]` — neutral values. LanceDB requires `docker compose --profile full up`. Circuit breaker: 3s timeout, 60s backoff on failure.

---

### Thread 3: Graph Builder

**Purpose:** Build entity relationship graph from ClickHouse event data. Maps network connections, lateral movement paths, and C2 communication.

**Verified SQL queries (all column names confirmed against `clickhouse/schema.sql`):**

#### Query 1 — Host Network Connections

```sql
SELECT
    toString(src_ip)  AS src,
    toString(dst_ip)  AS dst,
    dst_port,
    count()           AS conn_count
FROM clif_logs.network_events
WHERE (toString(src_ip) = {ip:String} OR toString(dst_ip) = {ip:String})
  AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
GROUP BY src, dst, dst_port
ORDER BY conn_count DESC
LIMIT 50
SETTINGS max_execution_time = 8
```

#### Query 2 — Unique Hosts/IPs in Window

```sql
SELECT
    uniq(hostname)                       AS unique_hosts,
    uniq(source_ip)                      AS unique_ips,
    count()                              AS total_events
FROM clif_logs.triage_scores
WHERE timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
  AND action = 'escalate'
SETTINGS max_execution_time = 8
```

#### Query 3 — Max Fan-Out (Lateral Movement Indicator)

```sql
SELECT
    toString(src_ip)       AS source,
    uniq(toString(dst_ip)) AS fan_out
FROM clif_logs.network_events
WHERE toString(src_ip) = {ip:String}
  AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
GROUP BY source
SETTINGS max_execution_time = 8
```

#### Query 4 — Neighbor Escalation Rate (V6 Fix: Noisy IP Cap)

```sql
SELECT
    source_ip,
    count()                                            AS escalation_count,
    countIf(timestamp > now() - INTERVAL 6 HOUR)       AS recent_6h,
    countIf(timestamp > now() - INTERVAL 24 HOUR)      AS recent_24h,
    max(ioc_match)                                     AS has_ioc
FROM clif_logs.triage_scores
WHERE source_ip IN (
    SELECT DISTINCT toString(dst_ip)
    FROM clif_logs.network_events
    WHERE toString(src_ip) = {ip:String}
      AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
)
AND action = 'escalate'
AND timestamp > now() - INTERVAL 24 HOUR
GROUP BY source_ip
HAVING escalation_count <= 50 OR has_ioc = 1
SETTINGS max_execution_time = 8
```

> **V6 fix:** `HAVING escalation_count <= 50 OR has_ioc = 1` caps noisy scanner amplification. A scanner with 500+ escalations would otherwise inflate `graph_neighbor_escalate_rate` for every connected host. IOC-confirmed IPs bypass the cap.

#### Query 5 — C2 / IOC Neighbor Check

```sql
SELECT
    source_ip,
    max(ioc_match)   AS has_ioc,
    max(CASE WHEN mitre_tactic = 'command-and-control' THEN 1 ELSE 0 END) AS has_c2
FROM clif_logs.triage_scores
WHERE source_ip IN (
    SELECT DISTINCT toString(dst_ip)
    FROM clif_logs.network_events
    WHERE toString(src_ip) = {ip:String}
      AND timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
)
AND timestamp > now() - INTERVAL 24 HOUR
GROUP BY source_ip
SETTINGS max_execution_time = 8
```

#### Output → Feature Vector (8 features)

| Feature | Source | Range |
|---------|--------|-------|
| `graph_unique_hosts` | Query 2 | 0–22 |
| `graph_unique_ips` | Query 2 | 0–33 |
| `graph_total_edges` | Query 1 `sum(conn_count)` | 0–10000+ |
| `graph_max_fan_out` | Query 3 | 0–33 |
| `graph_has_lateral_movement` | 1 if fan_out > 3 | 0 or 1 |
| `graph_has_c2` | Query 5 | 0 or 1 |
| `graph_has_ioc_neighbor` | Query 5 | 0 or 1 |
| `graph_neighbor_escalate_rate` | Query 4 `recent_24h / escalation_count` (recency-weighted) | 0.0–1.0 |

**Fallback (query timeout):** `[0, 0, 0, 0, 0, 0, 0, 0.0]` (neutral).

---

### Thread 4: SPC Engine (Statistical Process Control)

**Purpose:** Per-entity behavioral baselines that detect **any deviation from normal**, regardless of whether the attack is known or novel. This closes the novelty gap that ML alone cannot cover.

**Why SPC is critical:** The **Novelty Paradox** — if a brand-new attack type appears that EIF doesn't flag (< 0.65), LightGBM/CatBoost misclassifies as benign, and LanceDB finds "close" normal neighbors — the attack passes undetected. **SPC catches it because the entity's behavior changed**, regardless of what the attack "looks like."

#### Baselines Tracked

Stored in ClickHouse `entity_baselines` table. Updated every 60s via materialized views.

| # | Baseline | Formula | Detection | What It Catches |
|---|----------|---------|-----------|----------------|
| 1 | Event rate | `count() / minute` per `(hostname)` | z-score > 3σ | DDoS, brute force, exfiltration |
| 2 | Score distribution | `avg(adjusted_score)` per `(hostname, category)` | EWMA shift | Gradual score escalation (APT) |
| 3 | Category frequency | `count per category` per `(hostname)` | Chi-squared | New attack types on host |
| 4 | Tactic diversity | `uniq(mitre_tactic)` per `(hostname, window)` | Count threshold | Kill chain progression |
| 5 | Connection fan-out | `uniq(ip_address)` per `(hostname, window)` | z-score > 3σ | Lateral movement, scanning |
| 6 | Template novelty | `uniq(template_id)` per `(hostname)` | New template never seen | Novel log patterns |

**Scale:** 22 unique hosts × 6 baselines = **132 baseline entries**. Fits entirely in memory.

#### Entity Profiling (from live data)

| Metric | Value |
|--------|-------|
| Unique hostnames | 22 |
| Unique source IPs | 33 |
| Unique categories | 38 |
| Unique MITRE tactics | 6 |
| Hosts with multi-category activity | 9 |
| Avg events per host | 93,978 |

#### Implementation

```python
class SPCEngine:
    """Statistical Process Control for per-entity behavioral baselines.
    
    Runs as L1 Thread 4 in parallel with Temporal/Similarity/Graph.
    Feeds 4 features into the 42-dim feature vector.
    Has AUTHORITY in the Fusion Decision Matrix — SPC anomaly always investigated.
    """
    
    def __init__(self, ch_client, baseline_window_hours: int = 24):
        self.ch = ch_client
        self.window = baseline_window_hours
        self.baselines = {}  # (hostname, metric) → (mean, std, last_updated)
    
    def refresh_baselines(self):
        """Pull aggregated baselines from ClickHouse. Called every 60s."""
        rows = self.ch.execute("""
            SELECT hostname,
                   'event_rate' AS metric,
                   avg(event_count) AS mean_val,
                   stddevPop(event_count) AS std_val,
                   count() AS samples
            FROM clif_logs.features_entity_freq
            WHERE window_start >= now() - INTERVAL {window} HOUR
            GROUP BY hostname
            HAVING samples >= 10
        """.format(window=self.window))
        for row in rows:
            self.baselines[(row['hostname'], row['metric'])] = (
                row['mean_val'], row['std_val']
            )
        # ... similar for other 5 baselines
    
    def evaluate(self, hostname: str, source_ip: str,
                 time_start: datetime, time_end: datetime) -> SPCResult:
        """Check if current behavior deviates from baseline."""
        current = self._get_current_metrics(hostname, time_start, time_end)
        deviations = []
        
        for metric_name, value in current.items():
            key = (hostname, metric_name)
            if key not in self.baselines:
                continue
            mean, std = self.baselines[key]
            if std == 0:
                continue
            z_score = abs(value - mean) / std
            if z_score > 3.0:
                deviations.append(SPCDeviation(
                    metric=metric_name,
                    expected=mean,
                    observed=value,
                    z_score=z_score,
                    explanation=f"{hostname} {metric_name}: expected {mean:.1f} "
                               f"(±{std:.1f}), observed {value:.1f} (z={z_score:.1f})"
                ))
        
        return SPCResult(
            is_anomaly=len(deviations) > 0,
            deviations=deviations,
            anomaly_score=min(max((d.z_score for d in deviations), default=0.0) / 10.0, 1.0),
            deviation_count=len(deviations),
            max_z_score=max((d.z_score for d in deviations), default=0.0)
        )
```

#### Output → Feature Vector (4 features)

| Feature | Description | Range |
|---------|-------------|-------|
| `spc_anomaly_flag` | 1 if any baseline deviation > 3σ | 0 or 1 |
| `spc_max_z_score` | Highest z-score across all baselines | 0.0–∞ (capped at 10.0 for ML) |
| `spc_deviation_count` | Number of baselines with deviation | 0–6 |
| `spc_anomaly_score` | Normalized score: `max_z / 10`, capped at 1.0 | 0.0–1.0 |

**Fallback (first 24h, no baselines yet):** `[0, 0.0, 0, 0.0]` — permissive (never blocks investigations during warm-up). Warm-start from historical ClickHouse data if available.

---

## 7. L2 Parallel Investigation (2 Threads)

L2 runs after L1 completes (depends on some L1 output features). Both L2 threads run in parallel.

### Thread 1: MITRE Mapper

**Purpose:** Match the current event against MITRE ATT&CK mapping rules stored in ClickHouse.

**Verified SQL query (against `clickhouse/schema.sql` `mitre_mapping_rules` table — 9 seeded rules):**

```sql
SELECT
    rule_id,
    rule_name,
    mitre_tactic,
    mitre_technique,
    severity,
    trigger_features,
    trigger_thresholds
FROM clif_logs.mitre_mapping_rules
WHERE source_type = {source_type:String}
   OR source_type = '*'
ORDER BY severity DESC
SETTINGS max_execution_time = 5
```

#### Rule Matching Logic

```python
def match_rules(self, rules: list, feature_context: dict) -> list[MITREMatch]:
    """Match MITRE rules against current event features."""
    matches = []
    for rule in rules:
        triggers = json.loads(rule['trigger_features'])   # e.g. {"off_hours": 1, "template_priv_escalation": 1}
        thresholds = json.loads(rule['trigger_thresholds'])
        
        all_match = True
        for feature, expected in triggers.items():
            actual = feature_context.get(feature, 0)
            threshold = thresholds.get(feature, expected)
            if actual < threshold:
                all_match = False
                break
        
        if all_match:
            matches.append(MITREMatch(
                rule_id=rule['rule_id'],
                rule_name=rule['rule_name'],
                tactic=rule['mitre_tactic'],
                technique=rule['mitre_technique'],
                severity=rule['severity']
            ))
    return matches
```

#### V6 Fix: Trigger Feature Derivation

Three features were hardcoded to 0 in earlier versions, silently disabling MITRE rules that depend on them:

```python
def build_feature_context(self, triage_msg: dict) -> dict:
    """Derive trigger features from TriageResult message."""
    ts = datetime.fromisoformat(triage_msg["timestamp"])
    hour_utc = ts.hour
    template = (triage_msg.get("template_id") or "").lower()
    
    return {
        "off_hours": 1 if (hour_utc < 7 or hour_utc >= 19) else 0,
        "template_user_created": 1 if any(
            kw in template for kw in ("useradd", "adduser", "net user", "new-localuser")
        ) else 0,
        "template_priv_escalation": 1 if any(
            kw in template for kw in ("sudo", "escalat", "runas", "privilege", "admin")
        ) else 0,
        "ioc_match": triage_msg.get("ioc_match", 0),
        "eif_score": triage_msg.get("eif_score", 0.0),
        "adjusted_score": triage_msg.get("adjusted_score", 0.0),
        # L1 thread outputs (available because L2 runs after L1)
        "temporal_tactic_diversity": l1_features.get("temporal_tactic_diversity", 0),
        "graph_has_lateral_movement": l1_features.get("graph_has_lateral_movement", 0),
        "spc_anomaly_flag": l1_features.get("spc_anomaly_flag", 0),
        "sigma_hit_count": sigma_features.get("sigma_hit_count", 0),
    }
```

#### V6 Addition: Startup Validation

```python
def validate_mitre_rules(self):
    """Startup check — warn about rules with unknown trigger features."""
    known = {"off_hours", "template_user_created", "template_priv_escalation",
             "ioc_match", "eif_score", "adjusted_score", "temporal_tactic_diversity",
             "graph_has_lateral_movement", "spc_anomaly_flag", "sigma_hit_count"}
    for rule in self.rules:
        triggers = json.loads(rule['trigger_features'])
        unknown = set(triggers.keys()) - known
        if unknown:
            logger.warning(f"MITRE rule {rule['rule_id']} has unknown trigger "
                          f"features: {unknown}. Rule may never fire.")
```

#### Output → Feature Vector (2 features)

| Feature | Description | Range |
|---------|-------------|-------|
| `mitre_rule_match_count` | Number of MITRE rules matched | 0–9 |
| `mitre_max_severity` | Highest matched rule severity | 0–4 |

---

### Thread 2: Campaign Detector

**Purpose:** Detect coordinated multi-host attack campaigns by correlating triage scores with network connections.

**Verified SQL query (cross-table JOIN):**

```sql
SELECT
    ts.hostname,
    ts.source_ip,
    ts.mitre_tactic,
    count()          AS event_count,
    avg(ts.adjusted_score) AS avg_score
FROM clif_logs.triage_scores ts
JOIN clif_logs.network_events ne
    ON ts.source_ip = toString(ne.src_ip)
WHERE ts.timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
  AND ts.action = 'escalate'
  AND ne.timestamp BETWEEN {t_start:DateTime64(3)} AND {t_end:DateTime64(3)}
GROUP BY ts.hostname, ts.source_ip, ts.mitre_tactic
HAVING event_count >= 3
ORDER BY event_count DESC
LIMIT 20
SETTINGS max_execution_time = 8
```

#### Campaign Detection Logic

```python
def detect_campaign(self, results: list) -> CampaignResult:
    """Determine if results indicate a coordinated campaign."""
    unique_hosts = set(r['hostname'] for r in results)
    unique_tactics = set(r['mitre_tactic'] for r in results if r['mitre_tactic'])
    total_events = sum(r['event_count'] for r in results)
    
    is_campaign = len(unique_hosts) >= 2 and len(unique_tactics) >= 2
    
    return CampaignResult(
        is_campaign=is_campaign,
        member_count=len(unique_hosts),
        unique_hosts=list(unique_hosts),
        unique_tactics=list(unique_tactics),
        total_events=total_events
    )
```

#### Output → Feature Vector (2 features)

| Feature | Description | Range |
|---------|-------------|-------|
| `campaign_member_count` | Number of hosts in campaign | 0–22 |
| `campaign_unique_hosts` | Count of unique hosts with coordinated escalations | 0–22 |

---

## 8. RAG Narrative Builder

**Purpose:** Assemble a structured investigation summary from all detection layers. This is deterministic string assembly, NOT AI-generated text.

### Severity Determination

```python
SEVERITY_MAP = {
    'confirmed_attack': 'critical',  # Sigma hit (any) + SPC + ML all agree
    'probable_attack': 'high',       # SPC anomaly + ML high, or Sigma + ML
    'novel_investigation': 'high',   # SPC anomaly + novel signals
    'evasion_technique': 'high',     # Stealth detection (T1036)
    'campaign': 'high',              # Multi-host coordinated activity
    'ml_alert': 'medium',            # ML-only signal
    'anomaly': 'medium',             # SPC-only signal
    'ioc_correlation': 'medium',     # IOC match enrichment
    'closed': 'info'                 # No signals
}
```

### Finding Type Priority Chain

```python
def determine_finding_type(self, sigma_hits, spc_result, ml_result, 
                            campaign, mitre_matches, similarity):
    """Determine finding_type in priority order."""
    if campaign and campaign.is_campaign:
        return 'campaign'
    if sigma_hits and spc_result.is_anomaly:
        return 'confirmed_attack'
    if sigma_hits:
        return 'confirmed_attack'
    if similarity.get('evasion_flag'):
        return 'evasion_technique'
    if similarity.get('novelty_flag'):
        return 'novel_anomaly'
    if spc_result.is_anomaly and ml_result.score > 0.5:
        return 'probable_attack'
    if spc_result.is_anomaly:
        return 'novel_investigation'
    if mitre_matches:
        return 'multi_vector'
    if ml_result.ioc_correlated:
        return 'ioc_correlation'
    if ml_result.score > 0.7:
        return 'ml_alert'
    return 'anomaly'
```

### Narrative Assembly

```python
def build_narrative(self, finding_type: str, sigma_hits: list, spc_result,
                    similarity: dict, campaign, graph_data: dict) -> str:
    """Build structured narrative string."""
    parts = []
    
    # Header
    parts.append(f"Hunter Investigation: {finding_type.upper()}")
    
    # Sigma findings
    if sigma_hits:
        rules = ", ".join(h.rule_name for h in sigma_hits)
        parts.append(f"Sigma Rules Matched: {rules}")
    
    # SPC findings
    if spc_result.is_anomaly:
        for d in spc_result.deviations:
            parts.append(f"SPC: {d.explanation}")
    
    # Similarity/novelty findings (V5)
    if similarity.get('evasion_flag'):
        parts.append(
            "STEALTH ALERT: Event is textually similar to normal operations "
            "but statistical features are anomalous. High probability of "
            "defense evasion (MITRE T1036 Masquerading)."
        )
    elif similarity.get('novelty_flag'):
        parts.append(
            "NOVEL PATTERN: No matching attack patterns found in attack_embeddings. "
            "EIF confirms statistical anomaly. Treat as potential zero-day."
        )
    elif similarity.get('incident_match'):
        parts.append(
            f"Historical Match: Similar pattern found in historical incidents "
            f"(distance={similarity.get('attack_distance', 'N/A'):.3f})."
        )
    
    # Campaign findings
    if campaign and campaign.is_campaign:
        parts.append(
            f"CAMPAIGN: {campaign.member_count} hosts involved: "
            f"{', '.join(campaign.unique_hosts)}"
        )
    
    # Graph context
    if graph_data.get('graph_has_lateral_movement'):
        parts.append(f"Lateral Movement: Fan-out to {graph_data['graph_max_fan_out']} destinations")
    if graph_data.get('graph_has_c2'):
        parts.append("C2 Communication: Detected in network neighbors")
    
    return " | ".join(parts)
```

---

## 9. Fusion Decision Engine

The Fusion Engine is the core of the hybrid architecture. It combines Sigma, SPC, and ML signals using a triple-layer agreement paradigm, then delegates to the 2-phase scoring engine for final confidence.

### Triple-Layer Decision Matrix

| Sigma Hit | SPC Anomaly | ML Score | Verdict | Severity | Min Confidence |
|-----------|-------------|----------|---------|----------|----------------|
| ✅ Yes | ✅ Yes | > 0.5 | **CONFIRMED** | Critical | 0.95 |
| ✅ Yes | ✅ Yes | < 0.5 | **CONFIRMED** | High | 0.85 |
| ✅ Yes | ❌ No | > 0.5 | **CONFIRMED** | High | 0.85 |
| ✅ Yes | ❌ No | < 0.5 | **CONFIRMED** | Medium | 0.70 |
| ❌ No | ✅ Yes | > 0.5 | **PROBABLE ATTACK** | High | 0.80 |
| ❌ No | ✅ Yes | < 0.5 | **NOVEL / INVESTIGATE** | Medium | 0.60 |
| ❌ No | ❌ No | > 0.7 | **ML ALERT** | Medium | 0.55 |
| ❌ No | ❌ No | 0.3–0.7 | **LOW CONFIDENCE** | Low | 0.30 |
| ❌ No | ❌ No | < 0.3 | **CLOSE** | Info | 0.10 |

### Key Principles

1. **Sigma hit = always escalate.** Deterministic rules are pre-validated by the community. A Cobalt Strike DNS beaconing match IS an attack.
2. **SPC anomaly = always investigate.** Behavioral deviation is a mathematical fact. The host IS behaving differently — that demands investigation even if ML says "normal."
3. **ML alone is advisory.** ML provides classification and enrichment but does NOT have veto power over Sigma or SPC.
4. **2-of-3 agreement = high confidence.** Three fundamentally different paradigms agreeing is extremely strong signal.
5. **Conflict is signal.** When ML says "normal" but SPC says "anomaly" → this IS a novel attack the ML hasn't seen. When LanceDB says "textually normal" but EIF says "statistical outlier" → this IS an evasion technique.
6. **Scoring engine refines confidence.** The matrix sets MINIMUM confidence; the 2-phase scorer (Section 10) computes the actual value from the full 42-dim feature vector.

### Implementation

```python
class FusionEngine:
    """Combines Sigma + SPC + ML signals with 2-phase scoring."""

    def __init__(self, scorer: Scorer):
        self.scorer = scorer  # Heuristic or CatBoost (auto-switched)

    def fuse(self, sigma_hits: list[SigmaHit], spc: SPCResult,
             features: dict, triage_msg: dict) -> HunterVerdict:
        
        sigma_hit = len(sigma_hits) > 0
        spc_anomaly = spc.is_anomaly
        
        # Build 42-dim feature vector
        feature_vector = self._build_feature_vector(
            triage_msg, features, sigma_hits, spc
        )
        
        # Get ML confidence from 2-phase scorer
        ml_confidence = self.scorer.score(feature_vector)
        
        # Apply triple-layer decision matrix
        agreeing = sum([sigma_hit, spc_anomaly, ml_confidence > 0.5])
        
        if sigma_hit:
            severity = 'critical' if agreeing == 3 else 'high' if agreeing >= 2 else 'medium'
            min_conf = 0.85 if agreeing >= 2 else 0.70
            finding = 'confirmed_attack'
        elif spc_anomaly and ml_confidence > 0.5:
            severity = 'high'
            min_conf = 0.80
            finding = 'probable_attack'
        elif spc_anomaly:
            severity = 'medium'
            min_conf = 0.60
            finding = 'novel_investigation'
        elif ml_confidence > 0.7:
            severity = 'medium'
            min_conf = 0.55
            finding = 'ml_alert'
        elif ml_confidence > 0.3:
            severity = 'low'
            min_conf = 0.30
            finding = 'low_confidence'
        else:
            severity = 'info'
            min_conf = 0.10
            finding = 'closed'
        
        # Final confidence = max(matrix minimum, scorer output)
        final_confidence = max(min_conf, ml_confidence)
        
        return HunterVerdict(
            finding_type=finding,
            severity=severity,
            confidence=final_confidence,
            sigma_hits=sigma_hits,
            spc_result=spc,
            ml_confidence=ml_confidence,
            agreeing_layers=agreeing,
            scorer_mode=self.scorer.mode  # 'heuristic' or 'catboost'
        )
```

---

## 10. Scoring Engine — 2-Phase (Heuristic → CatBoost)

### 42-Dimension Feature Vector

```python
FEATURE_ORDER = [
    # ── Triage passthrough (13) ── from TriageResult message
    "adjusted_score", "lgbm_score", "eif_score", "arf_score",
    "score_std_dev", "agreement", "ci_lower", "ci_upper",
    "template_rarity", "asset_multiplier", "ioc_match", "ioc_confidence",
    "disagreement_flag",

    # ── Graph (8) ── from L1 Thread 3
    "graph_unique_hosts", "graph_unique_ips", "graph_total_edges",
    "graph_max_fan_out", "graph_has_lateral_movement",
    "graph_has_c2", "graph_has_ioc_neighbor", "graph_neighbor_escalate_rate",

    # ── Temporal (4) ── from L1 Thread 1
    "temporal_escalation_count", "temporal_unique_categories",
    "temporal_tactic_diversity", "temporal_mean_score",

    # ── Similarity (7) ── from L1 Thread 2
    "similarity_min_distance", "similarity_mean_distance",
    "similarity_incident_match", "similarity_incident_severity",
    "similarity_attack_distance", "similarity_novelty_flag", "similarity_evasion_flag",

    # ── MITRE (2) ── from L2 Thread 1
    "mitre_rule_match_count", "mitre_max_severity",

    # ── Campaign (2) ── from L2 Thread 2
    "campaign_member_count", "campaign_unique_hosts",

    # ── Sigma (2) ── from Fast Path (NEW in hybrid)
    "sigma_hit_count", "sigma_max_severity",

    # ── SPC (4) ── from L1 Thread 4 (NEW in hybrid)
    "spc_anomaly_flag", "spc_max_z_score", "spc_deviation_count", "spc_anomaly_score",
]
assert len(FEATURE_ORDER) == 42
```

### Phase 1: Heuristic Scorer (Day 0 — before 100 labeled samples)

Weighted formula using the most informative features. Deterministic, interpretable, no model needed.

```python
HEURISTIC_WEIGHTS = {
    # ── Core triage signals ──
    "adjusted_score":              0.15,   # Triage's primary output
    "eif_score":                   0.08,   # Statistical isolation (EIF)
    "template_rarity":             0.04,   # Rare log pattern
    "ioc_match":                   0.05,   # Pre-checked IOC from Triage

    # ── NEW: Deterministic detection (Sigma + SPC) ──
    "sigma_hit_count":             0.14,   # Sigma rules fired (highest weight — deterministic)
    "spc_anomaly_score":           0.10,   # SPC behavioral deviation (normalized z-score)

    # ── Graph context ──
    "graph_neighbor_escalate_rate": 0.07,  # Network neighbor risk
    
    # ── Temporal context ──
    "temporal_escalation_count":    0.05,  # Correlated escalations in window
    "temporal_tactic_diversity":    0.06,  # Kill chain breadth

    # ── Similarity context ──
    "similarity_attack_distance":   0.04,  # Distance to known attacks (inverted: 1-dist)
    "similarity_novelty_flag":      0.04,  # Novel pattern (RAISES score)
    "similarity_evasion_flag":      0.03,  # Stealth detection (RAISES score)

    # ── MITRE + Campaign ──
    "mitre_rule_match_count":       0.07,  # MITRE rule matches
    "campaign_member_count":        0.04,  # Multi-host campaign size

    # ── Disagreement as uncertainty ──
    "disagreement_flag":            0.04,  # Model disagreement = investigate
}
# Sum: 0.15+0.08+0.04+0.05+0.14+0.10+0.07+0.05+0.06+0.04+0.04+0.03+0.07+0.04+0.04 = 1.00
```

```python
class HeuristicScorer:
    """Weighted formula scorer for Day 0 (no CatBoost model yet)."""
    
    mode = "heuristic"
    
    def score(self, features: list[float]) -> float:
        """Compute weighted confidence score."""
        feature_dict = dict(zip(FEATURE_ORDER, features))
        raw = 0.0
        for name, weight in HEURISTIC_WEIGHTS.items():
            value = feature_dict.get(name, 0.0)
            # Invert distance features (lower distance = higher score)
            if name == "similarity_attack_distance":
                value = max(0.0, 1.0 - value)
            # Normalize count features
            if name == "sigma_hit_count":
                value = min(value / 5.0, 1.0)  # Cap at 5 hits
            if name == "temporal_escalation_count":
                value = min(value / 20.0, 1.0)  # Cap at 20
            if name == "campaign_member_count":
                value = min(value / 5.0, 1.0)  # Cap at 5 hosts
            if name == "mitre_rule_match_count":
                value = min(value / 3.0, 1.0)  # Cap at 3 matches
            if name == "spc_max_z_score":
                value = min(value / 10.0, 1.0)  # Cap at z=10
            raw += weight * value
        return min(max(raw, 0.0), 1.0)
```

### Phase 2: CatBoost Scorer (after 100+ labeled samples)

```python
from catboost import CatBoostClassifier

class CatBoostScorer:
    """CatBoost binary classifier. Hot-reloads model from disk every 5 minutes."""
    
    mode = "catboost"
    
    def __init__(self, model_path: str = "/app/models/hunter_catboost.cbm"):
        self.model_path = model_path
        self.model = None
        self.last_loaded = 0
        self._try_load()
    
    def _try_load(self):
        """Load model with atomic save protection."""
        if not os.path.exists(self.model_path):
            return False
        try:
            m = CatBoostClassifier()
            m.load_model(self.model_path)
            if m.feature_count_ != 42:
                logger.error(f"Model has {m.feature_count_} features, expected 42")
                return False
            self.model = m
            self.last_loaded = time.time()
            return True
        except Exception as e:
            logger.error(f"CatBoost load failed: {e}")
            return False
    
    def score(self, features: list[float]) -> float:
        """Run CatBoost inference. Returns probability of positive class."""
        # Hot-reload check every 5 minutes
        if time.time() - self.last_loaded > 300:
            self._try_load()
        
        if self.model is None:
            raise ModelNotLoadedError()
        
        proba = self.model.predict_proba([features])[0][1]
        return float(proba)
```

### Auto-Switch Logic

```python
class Scorer:
    """Automatically switches from heuristic to CatBoost at 100 samples."""
    
    def __init__(self):
        self.heuristic = HeuristicScorer()
        self.catboost = CatBoostScorer()
    
    @property
    def mode(self) -> str:
        if self.catboost.model is not None:
            return "catboost"
        return "heuristic"
    
    def score(self, features: list[float]) -> float:
        if self.catboost.model is not None:
            try:
                return self.catboost.score(features)
            except Exception:
                logger.warning("CatBoost failed, falling back to heuristic")
        return self.heuristic.score(features)
```

---

## 11. Self-Supervised Training Pipeline

### The Problem

Hunter has no labeled training data at launch. Ground-truth labels come from:
1. **Analyst feedback** (best quality, lowest volume)
2. **Verifier Agent verdicts** (good quality, moderate volume — when Verifier exists)
3. **Pseudo-labels** from Hunter's own high-confidence investigations (available immediately)

### Label Hierarchy (Priority Order)

| Priority | Source | Trust Level | How Obtained |
|----------|--------|-------------|-------------|
| 1 | Analyst feedback | **Highest** | `feedback_labels` table (manual) |
| 2 | Verifier verdict | High | `verifier-results` topic (automated) |
| 3 | Pseudo-positive | Medium | Hunter `confidence >= 0.85 AND finding_type IN ('confirmed_attack', 'probable_attack')` |
| 4 | Pseudo-negative | Low | Hunter `confidence < 0.30 AND severity IN ('info', 'low') AND finding_type NOT IN ('novel_anomaly', 'evasion_technique')` |
| 5 | Triage-anchored negative | Lowest | `hunter_investigations WHERE severity = 'info' AND trigger_score < 0.70` |

> **V6 fix (Pseudo-Negative Label Void):** Earlier versions tried to source pseudo-negatives from `triage_scores WHERE action='discard'` — but Hunter only ever sees `action='escalate'` events. Discarded events never reach Hunter and never appear in `hunter_training_data`. The fix sources pseudo-negatives from Hunter's own low-confidence, low-severity investigations.

### Training Loop

```python
class SelfSupervisedTrainer:
    """6-hour background retraining loop for CatBoost."""
    
    MIN_SAMPLES = 100        # Minimum to train first model
    RETRAIN_INTERVAL = 21600 # 6 hours in seconds
    MIN_NEGATIVE_RATIO = 0.1 # At least 10% negative samples
    
    async def training_loop(self):
        """Background task — runs every 6 hours."""
        while True:
            await asyncio.sleep(self.RETRAIN_INTERVAL)
            try:
                dataset = self._build_training_set()
                if len(dataset) < self.MIN_SAMPLES:
                    logger.info(f"Only {len(dataset)} samples, need {self.MIN_SAMPLES}")
                    continue
                
                neg_count = sum(1 for r in dataset if r['label'] == 0)
                if neg_count == 0:
                    logger.warning("ZERO negative samples — pseudo-negative "
                                   "pipeline may be broken. Skipping retrain.")
                    continue
                
                self._train_and_save(dataset)
            except Exception as e:
                logger.error(f"Training loop failed: {e}")
    
    def _build_training_set(self) -> list[dict]:
        """Pull training data with label hierarchy."""
        rows = self.ch.execute("""
            SELECT
                feature_vector,
                label,
                label_source,
                label_confidence,
                created_at
            FROM clif_logs.hunter_training_data
            WHERE created_at > now() - INTERVAL 7 DAY
            ORDER BY
                CASE label_source
                    WHEN 'analyst'  THEN 1
                    WHEN 'verifier' THEN 2
                    WHEN 'pseudo_positive' THEN 3
                    WHEN 'pseudo_negative' THEN 4
                    WHEN 'triage_anchored' THEN 5
                END,
                label_confidence DESC
        """)
        
        # Deduplicate: keep highest-priority label per alert_id
        seen = set()
        dataset = []
        for row in rows:
            alert_id = row['alert_id']
            if alert_id in seen:
                continue
            seen.add(alert_id)
            dataset.append(row)
        
        return dataset
    
    def _train_and_save(self, dataset: list[dict]):
        """Train CatBoost and atomically save to disk."""
        X = [json.loads(r['feature_vector']) for r in dataset]
        y = [r['label'] for r in dataset]
        
        model = CatBoostClassifier(
            iterations=500,
            depth=6,
            learning_rate=0.05,
            loss_function='Logloss',
            eval_metric='F1',
            verbose=0,
            thread_count=2  # Leave cores for investigation pipeline
        )
        model.fit(X, y)
        
        # Atomic save: write to .tmp then os.replace
        tmp_path = self.model_path + ".tmp"
        model.save_model(tmp_path)
        os.replace(tmp_path, self.model_path)
        logger.info(f"CatBoost retrained: {len(dataset)} samples, "
                    f"{sum(y)}/{len(y)} positive")
```

### Training Data Schema

Written directly to ClickHouse (bypasses consumer):

```sql
CREATE TABLE IF NOT EXISTS clif_logs.hunter_training_data ON CLUSTER 'clif_cluster'
(
    alert_id          String                                       CODEC(ZSTD(1)),
    feature_vector    String                                       CODEC(ZSTD(3)),
    label             UInt8          DEFAULT 0                     CODEC(ZSTD(1)),
    label_source      LowCardinality(String)                      CODEC(ZSTD(1)),
    label_confidence  Float32        DEFAULT 0.0                  CODEC(ZSTD(1)),
    created_at        DateTime64(3)  DEFAULT now64()              CODEC(Delta, ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_training_data',
    '{replica}'
)
ORDER BY (alert_id, created_at)
TTL toDateTime(created_at) + INTERVAL 30 DAY DELETE;
```

---

## 12. Drift Detection

### Three Independent Drift Signals

A single drift metric can be fooled. Three independent signals provide robust detection.

#### Signal 1: KL Divergence on Confidence Distribution

```python
def kl_divergence(self):
    """Compare score distribution: 7-day baseline vs last 24h."""
    baseline = self.ch.execute("""
        SELECT confidence FROM clif_logs.hunter_investigations
        WHERE started_at BETWEEN now() - INTERVAL 7 DAY AND now() - INTERVAL 1 DAY
    """)
    current = self.ch.execute("""
        SELECT confidence FROM clif_logs.hunter_investigations
        WHERE started_at > now() - INTERVAL 1 DAY
    """)
    if len(baseline) < 50 or len(current) < 50:
        return None  # Insufficient data
    
    # Histogram into 20 bins
    b_hist, _ = np.histogram([r[0] for r in baseline], bins=20, range=(0, 1), density=True)
    c_hist, _ = np.histogram([r[0] for r in current], bins=20, range=(0, 1), density=True)
    
    # Add epsilon to avoid log(0)
    b_hist = b_hist + 1e-10
    c_hist = c_hist + 1e-10
    
    kl = float(np.sum(c_hist * np.log(c_hist / b_hist)))
    return kl  # Threshold: 0.15
```

> **V6 fix (Drift Baseline Self-Contamination):** Earlier versions compared last-1h vs last-24h. Both windows contain Hunter's own output and drift together during gradual degradation → KL stays low → alarm never fires. The fix uses a **7-day-to-1-day baseline** that predates any recent drift.

#### Signal 2: PSI (Population Stability Index) on Feature Distribution

```python
def psi(self, feature_idx: int):
    """PSI on a single feature across baseline vs current."""
    baseline = self._get_feature_values(feature_idx, days_ago=7, days_span=6)
    current = self._get_feature_values(feature_idx, days_ago=0, days_span=1)
    
    if len(baseline) < 50 or len(current) < 50:
        return None
    
    # 10-bin histogram comparison
    bins = np.linspace(min(baseline), max(baseline), 11)
    b_pct = np.histogram(baseline, bins=bins)[0] / len(baseline) + 1e-10
    c_pct = np.histogram(current, bins=bins)[0] / len(current) + 1e-10
    
    psi_val = float(np.sum((c_pct - b_pct) * np.log(c_pct / b_pct)))
    return psi_val  # Threshold: 0.20
```

#### Signal 3: Triage-Anchored Divergence

```python
def triage_anchored_divergence(self):
    """Compare Hunter confidence against Triage's trigger_score.
    
    trigger_score is Triage's adjusted_score — computed BEFORE Hunter ran.
    It's an independent anchor that doesn't drift with Hunter.
    """
    rows = self.ch.execute("""
        SELECT
            avg(abs(confidence - trigger_score)) AS mean_divergence,
            avg(confidence - trigger_score)       AS bias
        FROM clif_logs.hunter_investigations
        WHERE started_at > now() - INTERVAL 24 HOUR
          AND trigger_score > 0
    """)
    if not rows:
        return None, None
    
    divergence = rows[0]['mean_divergence']
    bias = rows[0]['bias']
    # divergence threshold: 0.25
    # bias > 0 → Hunter over-alerting, bias < 0 → Hunter under-alerting
    return divergence, bias
```

#### Combined Drift Check

```python
async def check_drift(self) -> DriftReport:
    """Run all 3 drift signals. Write to hunter_model_health."""
    kl = self.kl_divergence()
    psi_vals = [self.psi(i) for i in [0, 2, 13, 24]]  # Key features
    triage_div, triage_bias = self.triage_anchored_divergence()
    
    alerts = []
    if kl is not None and kl > 0.15:
        alerts.append(f"KL divergence: {kl:.3f} (threshold: 0.15)")
    if any(p is not None and p > 0.20 for p in psi_vals):
        alerts.append(f"PSI drift detected on feature distribution")
    if triage_div is not None and triage_div > 0.25:
        direction = "over-alerting" if triage_bias > 0 else "under-alerting"
        alerts.append(f"Triage-anchored divergence: {triage_div:.3f} ({direction})")
    
    report = DriftReport(
        kl_divergence=kl,
        psi_values=psi_vals,
        triage_divergence=triage_div,
        triage_bias=triage_bias,
        is_drifting=len(alerts) > 0,
        alerts=alerts
    )
    
    # Write to health table
    self._write_health_record(report)
    return report
```

### Model Health Table

```sql
CREATE TABLE IF NOT EXISTS clif_logs.hunter_model_health ON CLUSTER 'clif_cluster'
(
    check_time        DateTime64(3)  DEFAULT now64()              CODEC(Delta, ZSTD(3)),
    scorer_mode       LowCardinality(String)                      CODEC(ZSTD(1)),
    kl_divergence     Float32        DEFAULT 0.0                  CODEC(ZSTD(1)),
    psi_max           Float32        DEFAULT 0.0                  CODEC(ZSTD(1)),
    triage_divergence Float32        DEFAULT 0.0                  CODEC(ZSTD(1)),
    triage_bias       Float32        DEFAULT 0.0                  CODEC(ZSTD(1)),
    is_drifting       UInt8          DEFAULT 0                    CODEC(ZSTD(1)),
    sample_count      UInt32         DEFAULT 0                    CODEC(ZSTD(1)),
    alerts            String         DEFAULT ''                   CODEC(ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/hunter_model_health',
    '{replica}'
)
ORDER BY check_time
TTL toDateTime(check_time) + INTERVAL 90 DAY DELETE;
```

---

## 13. Novelty Paradox Solution (4-Layer)

### The Problem

LanceDB similarity search has a critical flaw for anomaly detection: novel/zero-day attacks have no historical matches, so nearest neighbors are **normal events** → LanceDB would label the attack as "similar to normal" → **novel attacks marked as benign**.

### The Solution: 4 Defensive Layers

#### Layer A: Distance-Based Novelty Detection

| avg_distance | Interpretation | Action |
|-------------|---------------|--------|
| < 0.20 | Known pattern (close match) | Trust LanceDB classification |
| 0.20 – 0.45 | Uncertain (moderate distance) | Blend with other signals |
| > 0.45 | Novel (far from all known patterns) | **Flag as novel — DO NOT trust neighbor labels** |

#### Layer B: Triage Score Is Authoritative

Hunter **NEVER** overrides Triage's escalation decision based on LanceDB results. If Triage said `action=escalate`, the event IS investigated regardless of LanceDB similarity scores. When textual similarity and statistical anomaly conflict, the conflict ITSELF is the strongest signal of a stealth/evasion attack.

#### Layer C: Multi-Signal Decision Matrix

| Scenario | Signals | Verdict |
|----------|---------|---------|
| Novel zero-day | EIF ≥ 0.65 + template_rarity ≥ 0.8 + attack_distance > 0.45 | `novel_anomaly` — zero-day treatment |
| Stealth/evasion | log_distance < 0.3 + EIF ≥ 0.65 + attack_distance > 0.45 | `evasion_technique` — MITRE T1036 |
| Known attack variant | attack_distance < 0.3 + Sigma hit | `confirmed_attack` — classify and close |
| True false positive | EIF < 0.65 + no disagreement + attack_distance < 0.3 | `likely_false_positive` — close |
| SPC-detected novel | SPC anomaly + no Sigma + no attack match | `novel_investigation` — SPC authority |

#### Layer D: Separate Attack Embeddings Table

LanceDB maintains a dedicated `attack_embeddings` table populated **only** from confirmed attacks:
- Events confirmed as True Positives by the Verifier Agent
- Events with `severity >= high` from Hunter investigations
- Entries from `feedback_labels WHERE label='true_positive'`

```
┌─────────────────────┐     ┌──────────────────────┐
│  log_embeddings     │     │  attack_embeddings   │
│  (all logs — noisy) │     │  (confirmed attacks) │
│                     │     │                      │
│  ❌ Novel attacks   │     │  ✅ Novel attacks    │
│  look "normal" here │     │  have no close match │
│                     │     │  → high distance     │
│                     │     │  → CORRECTLY flagged  │
└─────────────────────┘     └──────────────────────┘
```

---

## 14. Attack Graph Construction

### Feasibility (Proven from Live Data)

| Data Point | Value | Source |
|-----------|-------|--------|
| MITRE tactics observed | 6 (defense-evasion, lateral-movement, privilege-escalation, credential-access, initial-access, discovery) | security_events |
| Hosts with multi-stage kill chains | 7 (MSEDGEWIN10, IEWIN7, fw-01, etc.) | security_events |
| Cross-host entity resolution | MSEDGEWIN10→10.0.2.17, IEWIN7→10.0.2.15/16 | network_events |
| DNS C2 indicators | steam.zombieden.cn (1,406 queries), tinyurl.com (1,998) | dns_events |

### Graph Structure (stored in `evidence_json`)

```json
{
  "attack_graph": {
    "nodes": [
      {"id": "MSEDGEWIN10", "type": "host", "tactics": ["defense-evasion", "lateral-movement", "privilege-escalation"]},
      {"id": "10.0.2.17", "type": "ip", "role": "source"},
      {"id": "10.0.2.15", "type": "ip", "role": "target"},
      {"id": "steam.zombieden.cn", "type": "domain", "role": "c2"}
    ],
    "edges": [
      {"from": "MSEDGEWIN10", "to": "10.0.2.15", "type": "lateral_movement", "technique": "T1021", "event_count": 921},
      {"from": "MSEDGEWIN10", "to": "steam.zombieden.cn", "type": "c2_communication", "technique": "T1071.004", "event_count": 1406}
    ],
    "kill_chain": [
      {"stage": 1, "tactic": "initial-access", "host": "host-syslog", "technique": "T1078"},
      {"stage": 2, "tactic": "privilege-escalation", "host": "MSEDGEWIN10", "technique": "T1548"},
      {"stage": 3, "tactic": "lateral-movement", "host": "MSEDGEWIN10→IEWIN7", "technique": "T1021"},
      {"stage": 4, "tactic": "defense-evasion", "host": "fw-01", "technique": "T1562"}
    ]
  }
}
```

### How It's Built

Uses Graph Builder's 5 verified SQL queries (Section 6, Thread 3) plus additional entity expansion:

1. **Entity Expansion**: L1 Thread 3 queries provide network connections, fan-out, and neighbor escalation data
2. **Relationship Extraction**: Map host→IP, IP→IP, host→domain from Query 1 + DNS query (L1 Thread 1)
3. **Tactic Ordering**: Sort by earliest `timestamp` per tactic to reconstruct kill chain
4. **Graph Assembly**: Build node/edge graph with event counts as edge weights
5. **MITRE Mapping**: Label edges with ATT&CK techniques from `mitre_mapping_rules` (L2 Thread 1)

### GNN Future Path (Phase 5 — Deferred)

SQL graph construction is sufficient for current scale. GNN migration requires:
- Verifier Agent providing 500+ verified TP/FP samples
- GPU or dedicated compute (infeasible on current 6C/16GB hardware)
- Graph-labeled training data (does not exist yet)

**GNN is blocked until Phase 5. No exceptions.**

---

## 15. ClickHouse Schema & Tables

### Existing Tables Used by Hunter

| Table | Purpose | Relevant Columns | Status |
|-------|---------|-------------------|--------|
| `triage_scores` | Source data | 28 columns (`hostname`, `source_ip` String, `adjusted_score`, `mitre_tactic`, etc.) | ✅ Active |
| `security_events` | Event context | `hostname`, `category` LowCardinality, `severity` UInt8, `description` String | ✅ Active |
| `network_events` | Attack graph | `src_ip` IPv4, `dst_ip` IPv4, `dst_port` UInt16, `bytes_sent` UInt64, `bytes_received` UInt64 | ✅ Active |
| `dns_events` | C2 detection | `query_name` String, `src_ip` IPv4, `query_type` String | ✅ Active |
| `process_events` | Process chains | `binary_path` String, `arguments` String, `pid` UInt32, `ppid` UInt32 | ✅ Active |
| `raw_logs` | Full evidence | `message` String | ✅ Active |
| `hunter_investigations` | Hunter output | 17 fields (see Output Contract) | ✅ Schema exists, empty |
| `ioc_cache` | Threat intel | `indicator`, `indicator_type`, `confidence` | ⚠️ Empty |
| `asset_criticality` | Asset weights | `hostname`, `criticality_score` | ⚠️ Empty |
| `allowlist` | FP suppression | `pattern`, `source_type` | ⚠️ Empty |
| `mitre_mapping_rules` | ATT&CK rules | `rule_id`, `trigger_features`, `trigger_thresholds`, `severity` | ✅ 9 seeded rules |
| `features_entity_freq` | Entity frequency | `hostname`, `event_count`, `window_start` | ⚠️ **TABLE MISSING (P0)** |

> **Column verification:** All column names above confirmed against `clickhouse/schema.sql`. Note: `network_events` stores IPs as `IPv4` type — Graph Builder uses `toString(src_ip)` for string comparison with `triage_scores.source_ip` (String type).

### New Tables (4 total)

#### 1. `entity_baselines` (SPC)

```sql
CREATE TABLE IF NOT EXISTS clif_logs.entity_baselines ON CLUSTER 'clif_cluster'
(
    hostname          String                                       CODEC(ZSTD(1)),
    metric_name       LowCardinality(String)                       CODEC(ZSTD(1)),
    window_start      DateTime64(3)                               CODEC(Delta, ZSTD(3)),
    mean_value        Float64        DEFAULT 0.0                  CODEC(ZSTD(1)),
    std_value         Float64        DEFAULT 0.0                  CODEC(ZSTD(1)),
    sample_count      UInt32         DEFAULT 0                    CODEC(ZSTD(1)),
    last_updated      DateTime64(3)  DEFAULT now64()              CODEC(ZSTD(3))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/entity_baselines',
    '{replica}'
)
ORDER BY (hostname, metric_name, window_start)
TTL toDateTime(window_start) + INTERVAL 7 DAY DELETE;
```

#### 2. `sigma_rule_hits` (Audit log)

```sql
CREATE TABLE IF NOT EXISTS clif_logs.sigma_rule_hits ON CLUSTER 'clif_cluster'
(
    hit_time          DateTime64(3)  DEFAULT now64()              CODEC(Delta, ZSTD(3)),
    alert_id          String                                       CODEC(ZSTD(1)),
    rule_id           String                                       CODEC(ZSTD(1)),
    rule_name         String                                       CODEC(ZSTD(1)),
    source_type       LowCardinality(String)                      CODEC(ZSTD(1)),
    hostname          String                                       CODEC(ZSTD(1)),
    severity          LowCardinality(String)                      CODEC(ZSTD(1)),
    mitre_tactic      String         DEFAULT ''                   CODEC(ZSTD(1)),
    mitre_technique   String         DEFAULT ''                   CODEC(ZSTD(1)),
    matched_events    UInt32         DEFAULT 0                    CODEC(ZSTD(1))
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sigma_rule_hits',
    '{replica}'
)
ORDER BY (hit_time, rule_id)
TTL toDateTime(hit_time) + INTERVAL 90 DAY DELETE;
```

#### 3. `hunter_training_data` (Self-supervised — see Section 11)

#### 4. `hunter_model_health` (Drift detection — see Section 12)

### Tables Requiring Population

| Table | What To Populate | Priority |
|-------|-----------------|----------|
| `features_entity_freq` | Create missing table in ClickHouse | **P0** — SPC depends on it |
| `ioc_cache` | Seed with open-source threat feeds (abuse.ch, malware bazaar) | P1 |
| `asset_criticality` | Define importance for 22 known hosts | P1 |
| `allowlist` | Add known false-positive patterns after first run | P2 |
| `attack_embeddings` | Add to LanceDB service + populate from historical high-severity events | P1 |

---

## 16. LanceDB Integration

### Architecture

| Component | Value |
|-----------|-------|
| Service | FastAPI (`lancedb-service/app.py`, 875 lines) |
| Embedding model | all-MiniLM-L6-v2 (384 dimensions) |
| Existing tables | `log_embeddings`, `threat_intel`, `historical_incidents` |
| New table needed | **`attack_embeddings`** (confirmed attacks only — V5 addition) |
| Sync | ClickHouse → LanceDB every 30s (watermark-based) |
| Docker profile | `full` (requires `docker compose --profile full up`) |
| Port | 8100 |

### Tables Searched per Investigation

| Table | Search Purpose | Used For |
|-------|---------------|----------|
| `attack_embeddings` | **Verdict** — "Is this a known attack?" | `similarity_attack_distance`, `similarity_novelty_flag`, `similarity_evasion_flag` |
| `historical_incidents` | **Context** — similar past incidents for RAG narrative | `similarity_incident_match`, `similarity_incident_severity` |
| `log_embeddings` | **Context only** — NEVER for verdict | `similarity_min_distance`, `similarity_mean_distance` |

### Critical Rule

> **LanceDB is a CONTEXT PROVIDER, never a DECISION MAKER.** Hunter uses LanceDB to classify WHAT KIND of attack (known, novel, evasion), not WHETHER it's an attack. Hunter NEVER downgrades a Triage escalation based solely on LanceDB similarity to normal events.

### Circuit Breaker (LanceDB is profile-gated)

```python
class LanceDBClient:
    """HTTP client with circuit breaker for profile-gated LanceDB."""
    
    CONNECT_TIMEOUT = 3.0    # seconds
    BACKOFF_DURATION = 60.0  # seconds
    
    def __init__(self):
        self.available = True
        self.last_failure = 0
    
    async def search(self, table: str, query: str, limit: int = 5) -> list:
        if not self.available:
            if time.time() - self.last_failure < self.BACKOFF_DURATION:
                return []  # Circuit open — return empty
            self.available = True  # Try again
        
        try:
            resp = await self.http.post(
                "http://lancedb:8100/search",
                json={"query": query, "table": table, "limit": limit},
                timeout=self.CONNECT_TIMEOUT
            )
            return resp.json()["results"]
        except Exception:
            self.available = False
            self.last_failure = time.time()
            logger.warning(f"LanceDB unavailable — circuit breaker open for {self.BACKOFF_DURATION}s")
            return []
```

---

## 17. Output Contract & Kafka Topics

### Hunter → Kafka: `hunter-results` topic

Published for every investigation. Consumer reads this and writes to `hunter_investigations` table.

```python
output = {
    "alert_id":              str(uuid4()),           # Unique investigation ID
    "source_event_id":       triage_msg["event_id"], # Original event UUID
    "started_at":            started_at.isoformat(),
    "completed_at":          completed_at.isoformat(),
    "trigger_score":         triage_msg["adjusted_score"],
    "confidence":            verdict.confidence,
    "severity":              verdict.severity,        # Enum: info/low/medium/high/critical
    "finding_type":          verdict.finding_type,    # String
    "summary":               narrative,               # Field name matches consumer's msg.get("summary")
    "evidence_json":         json.dumps({
        "sigma_hits":        [asdict(h) for h in sigma_hits],
        "spc_deviations":    [asdict(d) for d in spc.deviations],
        "graph_features":    graph_data,
        "temporal_features": temporal_data,
        "similarity":        similarity_data,
        "mitre_matches":     mitre_data,
        "campaign":          campaign_data,
        "attack_graph":      attack_graph,
        "scorer_mode":       verdict.scorer_mode,
        "feature_vector":    feature_vector,
        "investigation_ms":  int((completed_at - started_at).total_seconds() * 1000)
    }),
    "mitre_tactics":         list(set(t.tactic for t in mitre_matches)),
    "mitre_techniques":      list(set(t.technique for t in mitre_matches)),
    "related_events":        related_event_ids[:50],
    "investigation_status":  "completed",
    "assigned_to":           "hunter-agent",
    "hostname":              triage_msg["hostname"],
    "source_type":           triage_msg["source_type"],
}
await producer.send("hunter-results", json.dumps(output).encode())
```

> **V4 fix:** Hunter publishes the narrative as `summary` (not `narrative`). Consumer's `msg.get("summary")` matches perfectly. Zero consumer code changes needed.

### Hunter → ClickHouse Direct: `hunter_training_data`

Written directly (bypasses consumer) after every investigation for self-supervised training:

```python
self.ch.execute("""
    INSERT INTO clif_logs.hunter_training_data
    (alert_id, feature_vector, label, label_source, label_confidence)
    VALUES
""", [{
    "alert_id": output["alert_id"],
    "feature_vector": json.dumps(feature_vector),
    "label": 1 if verdict.confidence >= 0.85 else 0,
    "label_source": "pseudo_positive" if verdict.confidence >= 0.85 else "pseudo_negative",
    "label_confidence": verdict.confidence
}])
```

---

## 18. Infrastructure & Performance Budget

### Machine Specifications

| Spec | Value |
|------|-------|
| CPU | 6 cores / 12 threads |
| RAM | 16 GB (shared with all containers) |
| OS | Windows 11 + Docker Desktop (WSL2) |
| Storage | SSD (ClickHouse tiered storage) |

### Docker Container

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8400
CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8400"]
```

**Port:** 8400 (avoids conflict with Triage 8300-8303, LanceDB 8100)  
**RAM limit:** 4 GB (Docker resource constraint)  
**Health check:** `GET /health` → `{"status": "healthy", "scorer_mode": "heuristic|catboost", "sigma_rules": 52, "spc_baselines": 132}`

### Investigation Workload (from live data)

| Host | Events per ±15 min Window | Complexity |
|------|--------------------------|------------|
| ids-sensor-01 | 349,284 | Very Heavy |
| fw-01 | 325,719 | Very Heavy |
| ids-01 | 229,582 | Heavy |
| PC01.example.corp | 15,283 | Medium |
| MSEDGEWIN10 | 5,773 | Light |
| IEWIN7 | 1,877 | Light |
| LAPTOP-JU4M3I0E | 288 | Minimal |

### Latency Budget

| Component | Budget | Expected |
|-----------|--------|----------|
| **Sigma Fast Path** | < 10 ms | < 5 ms |
| L1 Thread 1: Temporal (3 CH queries) | < 30 ms | ~15 ms |
| L1 Thread 2: Similarity (3 LanceDB) | < 40 ms | ~25 ms |
| L1 Thread 3: Graph (5 CH queries) | < 50 ms | ~30 ms |
| L1 Thread 4: SPC (in-memory) | < 5 ms | < 2 ms |
| **L1 wall-clock (parallel)** | < 50 ms | ~30 ms |
| L2 Thread 1: MITRE Mapper | < 15 ms | ~10 ms |
| L2 Thread 2: Campaign Detector | < 25 ms | ~15 ms |
| **L2 wall-clock (parallel)** | < 25 ms | ~15 ms |
| Fusion + Scoring | < 5 ms | < 2 ms |
| Narrative + Graph Assembly | < 10 ms | ~5 ms |
| DB write + Kafka publish | < 10 ms | ~5 ms |
| **Total (full pipeline)** | **< 100 ms** | **~60-80 ms** |
| **Sigma fast-path (bypass)** | **< 15 ms** | **~8 ms** |

### Throughput Analysis

```
233,854 escalated events per batch window
  × ~65% pass adjusted_score > 0.65 gate
  = ~152,000 events enter Hunter

Of those:
  ~15-30% hit Sigma fast-path → ~8ms each → ~23K-46K fast
  ~70-85% enter full pipeline → ~70ms each → ~106K-129K full

Single instance: ~70ms/event → ~14,000 events/sec (full pipeline)
With Sigma fast-path: effective ~10,000-14,000 mixed events/sec

For 152K events: ~11-15 seconds processing time (single instance)
```

### Horizontal Scaling

For production load: 3 Hunter instances sharing same Kafka consumer group on `hunter-tasks` (6 partitions):
- 2 partitions per instance
- ~50K events per instance
- ~4-5 seconds per batch window

```yaml
# docker-compose.yml additions
clif-hunter-agent:
  build: ./agents/hunter
  ports: ["8400:8400"]
  deploy:
    resources:
      limits:
        memory: 4G
  environment:
    KAFKA_BOOTSTRAP: redpanda01:9092
    KAFKA_GROUP: hunter-agent-group
    KAFKA_TOPIC: hunter-tasks
    CH_HOST: clickhouse01
    LANCEDB_URL: http://lancedb:8100
    SCORER_MODEL_PATH: /app/models/hunter_catboost.cbm
```

### What This Eliminates

| Approach | Why Eliminated |
|----------|---------------|
| GNN (Graph Neural Networks) | 300K node graph = O(n·k), > 16 GB RAM, no training data |
| LSTM / Transformers | Per-token processing × 300K events = infeasible on 6C CPU |
| Deep Learning ensemble | GPU required; CPU inference > 500 ms per event |

---

## 19. Implementation Phases

### Phase 4A: Foundation + Sigma Fast Path (Days 1-5)

| Task | Description | Dependencies |
|------|-------------|-------------|
| Create `agents/hunter/` directory | Full structure per Section 20 | None |
| Create `features_entity_freq` table | **P0** — table missing from ClickHouse | None |
| Create `entity_baselines` table | SPC storage | None |
| Create `sigma_rule_hits` table | Audit log | None |
| Create `hunter_training_data` table | Training pipeline | None |
| Create `hunter_model_health` table | Drift detection | None |
| Sigma YAML→SQL compiler | Parse 52 rules into ClickHouse SQL | Sigma rules in dataset |
| SigmaEngine class | Fast-path evaluation | SQL compiler |
| Docker service + Kafka consumer | `hunter-tasks` consumer, health endpoint | None |
| Heuristic Scorer | 42-dim weighted formula | Feature vector definition |

### Phase 4B: L1/L2 Investigation Pipeline (Days 6-10)

| Task | Description | Dependencies |
|------|-------------|-------------|
| L1 Thread 1: Temporal Correlator | 3 CH queries, 4 features | CH access |
| L1 Thread 2: Similarity Searcher | LanceDB client + circuit breaker + multi-signal matrix | LanceDB service |
| L1 Thread 3: Graph Builder | 5 CH queries, 8 features, noisy-IP cap | CH access |
| L1 Thread 4: SPC Engine | 6 baselines, z-score evaluation, 4 features | entity_baselines + features_entity_freq |
| L2 Thread 1: MITRE Mapper | Rule matching + trigger feature derivation + startup validation | L1 complete |
| L2 Thread 2: Campaign Detector | Cross-table JOIN | CH access |
| Fusion Decision Engine | Triple-layer matrix + scorer integration | All threads |
| RAG Narrative Builder | Structured summary assembly | All threads |
| Attack Graph Builder | Entity expansion + graph construction | Graph Builder + MITRE Mapper |
| Output writer + Kafka producer | `hunter-results` topic + training data | Fusion Engine |

### Phase 4C: Training + Drift + Tuning (Days 11-15)

| Task | Description | Dependencies |
|------|-------------|-------------|
| Self-Supervised Trainer | 6hr retraining loop, label hierarchy | hunter_training_data |
| CatBoost Scorer | Model loading, hot-reload, auto-switch | Training data |
| Drift Detector | KL + PSI + Triage-anchored (3 signals) | hunter_model_health |
| `attack_embeddings` table | Add to LanceDB service + populate | LanceDB service |
| Populate `ioc_cache` | Seed with open-source threat feeds | None |
| Populate `asset_criticality` | Define importance for 22 hosts | None |
| SPC baseline warm-up | 24h of data for initial baselines | SPC Engine |
| End-to-end testing | Full pipeline: Triage → Hunter → hunter_investigations | All components |
| Threshold tuning | z-score limits, ML boundaries, drift thresholds | Running system |
| Performance benchmark | Verify < 100ms p95, Sigma fast-path < 15ms | All components |

---

## 20. File Structure

```
agents/hunter/
├── app.py                    # Main entry: FastAPI + Kafka consumer + orchestrator
├── config.py                 # Configuration (thresholds, timeouts, endpoints)
├── models.py                 # Dataclasses (HunterVerdict, SigmaHit, SPCResult, etc.)
├── detection/
│   ├── __init__.py
│   ├── sigma_engine.py       # Fast Path: Sigma YAML→SQL compiler + evaluator
│   └── spc_engine.py         # L1 Thread 4: SPC behavioral baselines
├── investigation/
│   ├── __init__.py
│   ├── temporal_correlator.py  # L1 Thread 1: 3 CH queries, 4 features
│   ├── similarity_searcher.py  # L1 Thread 2: 3 LanceDB calls, 7 features
│   ├── graph_builder.py        # L1 Thread 3: 5 CH queries, 8 features
│   ├── mitre_mapper.py         # L2 Thread 1: MITRE rule matching
│   ├── campaign_detector.py    # L2 Thread 2: Cross-table JOIN
│   └── rag_narrative.py        # Narrative assembly + severity + finding_type
├── scoring/
│   ├── __init__.py
│   ├── heuristic_scorer.py   # Phase 1: 42-dim weighted formula
│   ├── catboost_scorer.py    # Phase 2: CatBoost inference + hot-reload
│   └── scorer.py             # Mode switcher (heuristic → catboost at 100 samples)
├── training/
│   ├── __init__.py
│   ├── self_supervised_trainer.py  # 6hr background retraining loop
│   ├── label_builder.py           # Priority hierarchy (analyst > verifier > pseudo)
│   └── feature_store.py           # hunter_training_data R/W
├── monitoring/
│   ├── __init__.py
│   └── drift_detector.py    # KL divergence + PSI + Triage-anchored
├── fusion.py                 # Fusion Decision Engine (triple-layer matrix)
├── graph_constructor.py      # Attack graph assembly (evidence_json)
├── entity_expander.py        # ClickHouse ±15 min window queries
├── output_writer.py          # Kafka producer + training data writer
├── sigma_rules/              # Compiled Sigma rules (YAML + generated SQL)
│   ├── cisco/
│   ├── dns/
│   ├── firewall/
│   ├── fortinet/
│   ├── huawei/
│   ├── juniper/
│   └── zeek/
├── models/                   # CatBoost model files (hot-reloaded)
│   └── .gitkeep
├── tests/
│   ├── test_sigma_engine.py
│   ├── test_spc_engine.py
│   ├── test_temporal_correlator.py
│   ├── test_similarity_searcher.py
│   ├── test_graph_builder.py
│   ├── test_mitre_mapper.py
│   ├── test_campaign_detector.py
│   ├── test_fusion.py
│   ├── test_heuristic_scorer.py
│   ├── test_catboost_scorer.py
│   ├── test_drift_detector.py
│   └── test_integration.py
├── Dockerfile
└── requirements.txt
```

### `requirements.txt`

```
fastapi==0.109.0
uvicorn==0.27.0
aiokafka==0.10.0
clickhouse-connect==0.7.0
httpx==0.27.0
catboost==1.2.2
numpy==1.26.4
pyyaml==6.0.1
pydantic==2.5.3
```

---

## 21. Testing Strategy

### Unit Tests

| Test | What It Verifies |
|------|-----------------|
| `test_sigma_engine.py` | YAML→SQL compilation, rule matching, fast-path bypass logic, startup validation |
| `test_spc_engine.py` | z-score calculation, EWMA shift detection, baseline refresh, warm-start behavior |
| `test_temporal_correlator.py` | 3 CH queries return correct features, timeout fallback to `[0,0,0,0.0]` |
| `test_similarity_searcher.py` | 3 LanceDB calls, multi-signal matrix, novelty/evasion flag logic, circuit breaker |
| `test_graph_builder.py` | 5 CH queries, noisy-IP cap, fan-out calculation, fallback behavior |
| `test_mitre_mapper.py` | Rule matching, trigger feature derivation (off_hours, template_*), startup validation |
| `test_campaign_detector.py` | Cross-table JOIN, campaign threshold (≥2 hosts, ≥2 tactics) |
| `test_fusion.py` | All 9 decision matrix rows produce correct verdicts |
| `test_heuristic_scorer.py` | Weight sum = 1.00, normalization, edge cases (all zeros, all max) |
| `test_catboost_scorer.py` | Model loading, hot-reload, fallback to heuristic on failure |
| `test_drift_detector.py` | KL divergence, PSI, Triage-anchored divergence, alerting thresholds |

### Integration Tests

| Test | What It Verifies |
|------|-----------------|
| Cobalt Strike DNS | Sigma rule fires → fast-path CONFIRMED → correct MITRE T1071.004 |
| Known brute force | Sigma + SPC + ML all agree → severity=critical, confidence > 0.95 |
| Novel zero-day | SPC flags deviation + no Sigma + no attack_embeddings match → `novel_investigation` |
| Evasion technique | Low LanceDB distance + high EIF → `evasion_technique` (T1036) |
| Multi-host campaign | Campaign detector finds ≥2 hosts → `campaign` finding |
| Legitimate admin traffic | All layers clear → CLOSE → severity=info, confidence < 0.15 |
| High-volume host (ids-sensor-01) | Investigation completes in < 500ms despite 349K event window |
| LanceDB unavailable | Circuit breaker activates, neutral fallback features, investigation still completes |
| CatBoost model swap | Hot-reload mid-pipeline → next investigation uses new model |

### Performance Tests

| Metric | Target |
|--------|--------|
| Per-investigation latency (p95) | < 100 ms (full pipeline) |
| Sigma fast-path latency (p95) | < 15 ms |
| Throughput | > 10,000 investigations/sec (mixed fast-path + full) |
| Memory usage | < 4 GB (Docker container limit) |
| Cold-start time | < 30 sec (model load + baseline pull + Sigma compile) |
| CatBoost inference | < 5 ms per event |
| SPC evaluation | < 2 ms per event |

---

## 22. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|-----------|
| **features_entity_freq table missing** | **Certain** | High | **P0 fix**: Create table before Hunter implementation starts. SPC cannot function without it. |
| ClickHouse graph queries timeout under load | Medium | High | `max_execution_time=8` on all queries, zero-vector fallback, LIMIT clauses on all queries |
| LanceDB HTTP unavailable (profile-gated) | **High** | Medium | 3s connection timeout, 60s circuit breaker, fallback to neutral similarity features (7 features all neutral). Document that `--profile full` required for full capability. |
| SPC false positives during first 24h | High | Medium | Warm-start from historical ClickHouse data; permissive thresholds during baseline build |
| Pseudo-negative label void | ~~High~~ **Eliminated** | ~~Critical~~ | V6 fix: Source from Hunter's own low-confidence investigations, not non-existent discarded events |
| Drift baseline self-contamination | ~~Medium~~ **Eliminated** | ~~High~~ | V6 fix: 7-day-to-1-day baseline + Triage-anchored divergence (independent anchor) |
| Graph amplification from noisy scanners | ~~Medium~~ **Eliminated** | ~~High~~ | V6 fix: `HAVING escalation_count <= 50 OR has_ioc = 1` caps noisy IPs |
| MITRE trigger features hardcoded to 0 | ~~Medium~~ **Eliminated** | ~~Medium~~ | V6 fix: Derived from TriageResult (off_hours, template_user_created, template_priv_escalation) |
| CatBoost model corrupted on disk | Low | Low | Atomic save (.tmp → os.replace), fallback to heuristic on load failure |
| Label quality too low for CatBoost | High | High | Label hierarchy (analyst > verifier > pseudo), min 10% negative ratio guard |
| Escalation rate spike overloads Hunter | Medium | High | Horizontal scaling (3 instances, 6 partitions), `adjusted_score > 0.65` gate, Sigma fast-path bypass |
| 4GB RAM tight under concurrent load | Medium | Medium | CatBoost (~200MB) + feature vectors + HTTP clients. Monitor via `/health` endpoint. |
| Campaign detector JOIN expensive under load | Medium | Medium | `max_execution_time=8`, LIMIT 20, benchmark before production |
| Sigma rules don't cover all source types | Medium | Low | 52 rules cover 7 categories; ML + SPC cover gaps. Add custom rules for new source types. |
| All support tables (ioc_cache, asset_criticality) empty | High | Medium | Phase 4C population task; Hunter works without them (degraded but functional) |
| GNN added prematurely | Medium | High | **GNN blocked until Phase 5. No exceptions.** Requires 500+ verified samples + GPU. |
| `attack_embeddings` table doesn't exist in LanceDB | **Certain** | High | Must be added to `lancedb-service/app.py` `_ensure_tables()`. Hard dependency for 7 similarity features. |

---

## Appendix A: Data Inventory

### ClickHouse Data Summary

| Metric | Value |
|--------|-------|
| Total events (security_events) | 2,067,513 |
| Unique hostnames | 22 |
| Unique source IPs | 33 |
| Unique categories | 38 |
| Unique MITRE tactics | 6 |
| Hosts with multi-category activity | 9 |
| Triage escalated events | 233,854 (60.3%) |
| Sigma rules available | 52 (7 vendor categories) |
| MITRE mapping rules seeded | 9 |

### Triage Score Columns Available (28 fields in triage_scores table)

```
score_id, event_id, timestamp, source_type, hostname, source_ip, user_id,
template_id, template_rarity, combined_score, lgbm_score, eif_score, arf_score,
score_std_dev, agreement, ci_lower, ci_upper, asset_multiplier, adjusted_score,
action, ioc_match, ioc_confidence, mitre_tactic, mitre_technique,
shap_top_features, shap_summary, features_stale, model_version, disagreement_flag
```

> Note: `shap_top_features` and `shap_summary` exist in schema but are NOT currently populated by Triage.

### Cross-Host Attack Chain Evidence

| Host | IP | Tactics | Events | Techniques |
|------|----|---------|--------|------------|
| MSEDGEWIN10 | 10.0.2.17 | defense-evasion, lateral-movement, privilege-escalation | 12,733 | T1562, T1021, T1548 |
| IEWIN7 | 10.0.2.15/16 | lateral-movement, privilege-escalation | 4,097 | T1021, T1548 |
| DESKTOP-NTSSLJD | — | privilege-escalation | 19,389 | T1548 |
| fw-01 | — | defense-evasion | 354,593 | T1562 |
| host-syslog | — | credential-access, initial-access | 22,603 | T1078 |
| dns-resolver-01 | — | discovery | 36 | T1046 |

### DNS C2 Indicators

| Domain | Query Count | Suspicion |
|--------|-------------|-----------|
| steam.zombieden.cn | 1,406 | High — known C2 pattern |
| tinyurl.com | 1,998 | Medium — URL shortener abuse |

---

## Appendix B: Existing Triage Agent Reference

| Component | Detail |
|-----------|--------|
| Models | LGBM v2.0.0 (weight=0.60), EIF v2.0.0 (0.15), ARF v2.0.0 (0.25) |
| Training F1 | 0.9636 (LGBM) |
| Thresholds | suspicious=0.39, anomalous=0.89 |
| EIF override | Floor score = 0.45 when EIF ≥ 0.65 |
| Online learning | River ARF with ADWIN drift detection (delta=0.002) |
| Replay buffer | arf_replay_buffer (24h, 50K rows max) |
| Output topics | triage-scores (all), anomaly-alerts (escalated), hunter-tasks (escalated) |
| Source code | `agents/triage/app.py` (892 lines), `agents/triage/score_fusion.py` (626 lines) |

---

## Appendix C: LanceDB Service Reference

| Component | Detail |
|-----------|--------|
| Source | `lancedb-service/app.py` (875 lines) |
| Framework | FastAPI |
| Embedding | all-MiniLM-L6-v2 (384 dimensions, thread-safe) |
| Tables | log_embeddings, threat_intel, historical_incidents |
| Required addition | **attack_embeddings** (confirmed attacks only — add to `_ensure_tables()`) |
| ClickHouse sync | 4 source tables (raw_logs, security_events, process_events, network_events) |
| Sync interval | Every 30 seconds (watermark-based) |
| Docker profile | `full` (currently disabled) |
| Port | 8100 |
| Seeded data | 5 historical incidents (ransomware, APT, insider, supply-chain, cryptominer) |

---

## Appendix D: V6 Corrections Applied to This Plan

This hybrid plan incorporates all 30 corrections from the V6 implementation spec (V2→V3: 10 fixes, V3→V4: 9 fixes, V4→V5: 7 fixes, V5→V6: 4 fixes). Key corrections reflected:

| Fix | What Was Wrong | What This Plan Does |
|-----|---------------|-------------------|
| Phantom input fields | V2 assumed `dst_ip`, `dst_bytes`, `midas_burst_score` etc. in TriageResult | All 26 TriageResult fields verified against `score_fusion.py` lines 42-68 |
| triage_scores columns | V2 queried `dst_ip`/`dst_port` from triage_scores | Network queries use `network_events` table (confirmed `src_ip IPv4`, `dst_ip IPv4`) |
| hunter-tasks topic | V3 consumed `triage-scores` (all events) | Consumes `hunter-tasks` (escalated-only, 6 partitions) |
| Process event columns | V2 used `process_name`, `parent_process` | Uses `binary_path`, `arguments`, `pid`, `ppid` (confirmed) |
| Port 8200 conflict | V2 used port 8200 | Uses port 8400 (8200 free but 8400 for clarity) |
| `summary` vs `narrative` | V3 published `narrative`, consumer reads `summary` | Publishes as `summary` — consumer match |
| LanceDB profile-gated | V3 assumed always available | Circuit breaker: 3s timeout, 60s backoff, neutral fallback |
| `attack_embeddings` table | V4 referenced non-existent `security_embeddings` | Uses `attack_embeddings` (must be added to LanceDB service) |
| Normal-neighbor contamination | V4 searched `log_embeddings` for verdict | `attack_embeddings` for verdict, `log_embeddings` for context only |
| Pseudo-negative void | V6: earlier versions queried non-existent discarded events | Sources from low-confidence Hunter investigations |
| Drift self-contamination | V6: 1h vs 24h both contain Hunter output | 7-day-to-1-day baseline + Triage-anchored divergence |
| Graph amplification | V6: noisy scanners inflated neighbor rates | `HAVING escalation_count <= 50 OR has_ioc = 1` |
| MITRE blind spots | V6: trigger features hardcoded to 0 | Derived from TriageResult + `validate_mitre_rules()` startup check |

---

*Hybrid plan merging Triple-Layer Detection (Sigma+SPC+ML fusion) with V6 Parallel Investigation Pipeline (verified SQL, CatBoost scoring, self-supervised training, drift detection). All field names, column types, port assignments, and topic routing verified against live CLIF pipeline as of March 4, 2026.*
