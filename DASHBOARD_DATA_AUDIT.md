# CLIF Dashboard — Data Feasibility Audit

> **Generated:** 2026-03-13  
> **Scope:** All 7 dashboard pages mapped against ClickHouse schema, API routes, and live agent endpoints  
> **Database:** `clif_logs` (26 tables including materialized views)  
> **Methodology:** Every widget traced to its actual SQL query or HTTP endpoint in the codebase

---

## Table of Contents

1. [Dashboard (Main)](#1-dashboard-main)
2. [Explainability](#2-explainability)
3. [Threat Intelligence](#3-threat-intelligence)
4. [Investigation Detail](#4-investigation-detail)
5. [AI Agents](#5-ai-agents)
6. [Chain of Custody](#6-chain-of-custody)
7. [Reports](#7-reports)
8. [Summary Matrix](#8-summary-matrix)

---

## 1. Dashboard (Main)

**Page:** `/dashboard`  
**API:** `/api/metrics`  
**Coverage:** 100%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Total Events (Global Ingestion) | `raw_logs`, `security_events`, `process_events`, `network_events` | `SUM(count())` across all 4 tables |
| Ingestion Rate (EPS) | `events_per_minute` MV → `events_per_10s` MV → `pipeline_metrics` | 3-tier cascade: per-minute MV (primary), per-10s MV (fallback), `pipeline_metrics.metric='producer_eps'` (tertiary) |
| Active Alerts | `security_severity_hourly` MV | `SUM(event_count) WHERE severity >= 2 AND hour >= now() - INTERVAL {range}` |
| Active Incidents | `hunter_investigations` | `countIf(status = 'completed')` from live agent probe |
| Risk Score | `security_severity_hourly` MV | Derived: weighted formula `(crit×40 + high×20 + med×8 + low×2) / total × 2.5`, capped at 100 |
| MTTR (Mean Time to Respond) | `security_events` | `AVG(dateDiff('second', min(timestamp), max(timestamp)))` grouped by category, severity >= 3 |
| SLA Uptime | Prometheus | `avg_over_time(up{job=~"clickhouse.*\|redpanda"}[24h]) * 100` |
| Event Volume Timeline (area chart) | `events_per_10s` MV → `events_per_minute` MV | Time-series query with fallback |
| Alert Severity Breakdown (bar chart) | `security_severity_hourly` MV | Group by `severity` (UInt8: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical) |
| Live Alerts (scrollable list) | `security_events` JOIN `triage_scores` | `LEFT JOIN` on `event_id`, severity >= 2, ordered by timestamp DESC |
| MITRE ATT&CK Heatmap | `security_events` | `GROUP BY mitre_tactic` → `uniqExact(mitre_technique)` + `count()` per tactic |
| Risky Entities (user/host table) | `security_events` | `GROUP BY user_id` (type=user) and `hostname` (type=host), weighted severity sum |
| Top Log Sources (progress bars) | `events_per_minute` MV | `GROUP BY source ORDER BY SUM(event_count) DESC LIMIT 10` |
| Recent Investigations (table) | `hunter_investigations` via `/api/ai/agents` | Last 20 investigations with severity, status, finding_type |
| Previous Period Trend (% delta) | `security_severity_hourly` MV | Same query on `[now-2×range, now-range]` interval for comparison |

### Gaps

**None.** All dashboard widgets are fully backed by real data.

#### Minor Note

- **Top Log Sources labels:** The dashboard spec mentions "AWS CloudTrail", "CrowdStrike EDR", etc. The pipeline shows real dataset source names (`ssh-zenodo`, `loghub-linux`, `cicids2017`). To display branded names, add a display-name mapping in `events_per_minute` source field or in the frontend.

---

## 2. Explainability

**Page:** `/explainability`  
**API:** `/api/ai/xai` (GET status + POST explain), `/api/ai/leaderboard`  
**Coverage:** ~80%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Pipeline XAI Integration Banner (3 agent badges) | Agent health probes | HTTP GET `:8300/health`, `:8400/health`, `:8500/health` → status check |
| SHAP Explainer (type + version) | XAI service `:8200/xai/status` | Returns `explainer_type` ("Perturbation-based") + `model_version` |
| ARF Confidence (online learning ramp) | `triage_scores` | `AVG(arf_score)` — ARF score stored per event as Float32 |
| Per-Agent XAI: Triage (explainer, top feature, stability) | XAI `:8200/xai/status` + `:8200/model/features` + `triage_scores` | `model_types.binary`, top feature by importance, `shap_top_features` consistency |
| Per-Agent XAI: Hunter (L1 modules, meta-model) | `hunter_investigations.evidence_json` + Hunter `:8400/health` | JSON contains module breakdown + scoring components |
| Per-Agent XAI: Verifier (formula, thresholds) | `verifier_results` + Verifier `:8500/stats` | `verdict` enum (true_positive/false_positive/inconclusive) + `confidence` |
| Live Event Explainer (3 sample → SHAP) | `triage_scores` + XAI `:8200/explain` POST | Fetch recent events, POST feature vector → returns per-feature SHAP bars |
| Per-Investigation Explanations (6 cards) | `hunter_investigations` | `severity`, `finding_type`, `correlated_events` count, ordered by `started_at DESC` |
| Tab 1: Feature Importance (global SHAP bars) | XAI `:8200/model/features` | Returns all features sorted by importance with display names + categories |
| Tab 3: Cohort Analysis (4 event types) | `triage_scores` + `feedback_labels` | `GROUP BY source_type` → accuracy/F1 per cohort from `feedback_labels.label` |
| Tab 4: Model Cards — Triage LightGBM | XAI `:8200/xai/status` → `metrics` | F1, Precision, Recall, AUC from model manifest |

### Gaps

| Gap | What's Missing | Real Implementation |
|---|---|---|
| **PSI Drift Score** | PSI (Population Stability Index) not computed or stored | **Add to triage training pipeline:** After model training, compute PSI between training distribution and current inference distribution. Store result in `pipeline_metrics` table: `INSERT INTO pipeline_metrics (metric, value) VALUES ('psi_drift', <computed_psi>)`. The triage agent's `score_fusion.py` already has access to feature distributions — add a periodic PSI computation (e.g., every 1000 batches) comparing `feature_extractor.py` current stats vs. training baseline stored in the model manifest. |
| **Model Freshness** (days since retrain) | Training date not in model manifest | **Add `trained_at` field to model manifest JSON** (`agents/triage/models/manifest.json`). When training completes, write `"trained_at": "2026-03-13T00:00:00Z"`. The XAI `/xai/status` endpoint already returns the manifest — just include this field. Dashboard computes `days_since = now() - trained_at`. |
| **Radar Chart** (6 dimensions × 3 agents) | No single API returns all 6 dimensions per agent | **Add `/api/ai/xai/radar` API route** that aggregates: (1) SHAP Stability = `SELECT countIf(shap_top_features LIKE '%event_frequency%') / count() FROM triage_scores` (consistency of top feature), (2) Confidence = `AVG(confidence)` from each agent's results table, (3) F1 Score = from XAI `/xai/status` metrics, (4) Fairness = `SELECT countIf(label='true_positive') / count() FROM feedback_labels` per agent, (5) Drift Resistance = inverse of PSI (see above), (6) Interpretability = static per-agent value (Triage=high, Hunter=medium, Verifier=medium). All from real tables. |
| **Feature Interaction Strengths** (5 pairs) | Pairwise SHAP interactions not computed | **Add interaction computation to XAI service:** In `agents/xai-service/app.py`, add a `/model/interactions` endpoint. Compute from `triage_scores.shap_top_features`: parse the JSON strings, count co-occurrence of feature pairs across all scored events. Query: `SELECT shap_top_features FROM triage_scores ORDER BY timestamp DESC LIMIT 10000`, parse JSON, build co-occurrence matrix of top feature pairs, return top-5 by frequency × combined importance. This is real statistical analysis, not mock. |
| **Tab 2: Decision Boundary** (scatter plot) | 2D feature projection not pre-computed | **Add `/api/ai/xai/boundary` endpoint** that queries: `SELECT combined_score, lgbm_score, eif_score FROM triage_scores ORDER BY timestamp DESC LIMIT 5000`. Return the two most discriminative score pairs (e.g., `lgbm_score` vs `eif_score`) with `combined_score > threshold` as the color axis. The frontend plots these as a scatter. No PCA needed — the model scores themselves ARE the 2D representation. |
| **Tab 4: Model Cards — Hunter & Verifier** | No model manifest for Hunter/Verifier | **Expose metrics from Hunter/Verifier `/stats` endpoints.** Hunter's `/stats` already returns processing stats. Add `accuracy` and `f1` fields computed from: `SELECT countIf(verdict='true_positive') / count() FROM verifier_results WHERE investigation_id IN (SELECT investigation_id FROM hunter_investigations)`. Verifier calibration metrics: `SELECT AVG(confidence) as avg_conf, countIf(verdict='true_positive')/count() as precision FROM verifier_results`. |
| **Tab 4: Fairness Metrics** (Equalized Odds, Demographic Parity) | Fairness metrics not computed | **Add fairness computation query:** `SELECT source_type, countIf(fl.label = 'true_positive') / count() AS tp_rate FROM triage_scores ts JOIN feedback_labels fl ON ts.event_id = fl.event_id GROUP BY source_type`. Demographic Parity = max(tp_rate) - min(tp_rate) across source_types. Equalized Odds = same but conditional on actual label. Both tables exist (`triage_scores` + `feedback_labels`). |

---

## 3. Threat Intelligence

**Page:** `/threat-intel`  
**API:** `/api/threat-intel`  
**Coverage:** 100%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Total IOCs | `ioc_cache` | `count()` — table has `ioc_type` enum (ip/domain/hash/url/email), `ioc_value`, `confidence` (UInt8), `source`, `threat_type` |
| Active Threats | `security_events` | `count() WHERE severity >= 3 AND timestamp >= now() - INTERVAL 24 HOUR` |
| MITRE Techniques count | `security_events` | `uniqExact(mitre_technique) WHERE mitre_technique != ''` |
| Last Updated | `ioc_cache` | `MAX(last_seen)` |
| AI-Driven IOC Enrichment Banner | Agent health probes + static | Live status from `:8300/health`, `:8400/health`, `:8500/health` |
| Attack Timeline 24h (stacked area) | `security_severity_hourly` MV | `GROUP BY hour, severity` WHERE severity IN (2,3,4) → three series: Medium, High, Critical |
| IOC Type Distribution (5 bars) | `ioc_cache` | `GROUP BY ioc_type` → maps to enum: ip=1→Server, domain=2→Domain, hash=3→SHA256, url=4→URL, email=5→Email |
| MITRE ATT&CK Coverage Bubble Chart | `security_events` | `GROUP BY mitre_tactic` → `count()` (size), `uniqExact(mitre_technique)` (position). Already in threat-intel API. |
| Cyber Kill Chain (6 bars) | `security_events.mitre_tactic` | Map tactic values → kill chain phases. `initial_access`→Delivery, `execution`→Exploitation, `persistence`→Installation, etc. |
| Threat Feed Status (4 feeds) | `ioc_cache` | `GROUP BY source` → feed name, `MAX(last_seen)` → last sync, `count()` → IOCs pulled, `AVG(confidence) > 50` → Health |
| High-Risk Entities (4 rows) | `security_events` | Weighted severity by `user_id`/`hostname` — same query as dashboard risky entities |
| Recent Critical Alerts (2 cards) | `security_events` | `WHERE severity >= 3 ORDER BY timestamp DESC LIMIT 2` with `mitre_technique` badge |
| Investigation Matches (4 links) | `hunter_investigations` | `ORDER BY started_at DESC LIMIT 4` |
| Tab 1: IOC Table (Type, Value, Confidence, Source, MITRE, Last Seen) | `ioc_cache` + `security_events` JOIN | `ioc_type`, `ioc_value`, `confidence`, `source`, MITRE from joined security events, `last_seen`. Already in API. |
| Tab 2: Threat Patterns (cards) | `security_events` | `GROUP BY mitre_technique, mitre_tactic` with counts + max severity |
| Tab 3: Reports | Placeholder | No data needed |

### Gaps

**None.** All widgets are fully backed by real data from `ioc_cache`, `security_events`, `security_severity_hourly`, and `hunter_investigations`.

#### Minor Note

- **Threat Feed Source names:** The spec lists "AlienVault OTX", "MISP Community", "Abuse.ch", "ThreatFox". The actual `ioc_cache.source` values depend on what feeds populate the table. If the triage agent fetches from those specific feeds, the names match automatically. Otherwise, the table shows whatever real feed sources are configured.

---

## 4. Investigation Detail

**Page:** `/investigations/[id]`  
**API:** `/api/investigations/[id]`  
**Coverage:** 100%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Page Header (title, severity, ID, date, assignee, events, status, confidence) | `hunter_investigations` | `investigation_id` (UUID), `severity` (enum), `started_at` (DateTime64), `user_id`, `correlated_events` (Array UUID → length = event count), `status` (enum), `confidence` (Float32) |
| Action Bar Tags (lateral-movement, T1021) | `hunter_investigations` | `mitre_tactics` (Array String) + `mitre_techniques` (Array String) |
| Incident Narrative (4 paragraphs + entities + classification) | `verifier_results` + `hunter_investigations` | `report_narrative` (full text), `analyst_summary`, `summary`, `recommended_action` — all String fields written by AI agents |
| Attack Graph (ReactFlow — nodes + edges) | `hunter_investigations.evidence_json` + `verifier_results.evidence_json` | Parsed JSON: `evidence_json.attack_graph.nodes[]` + `.edges[]`. API also extracts Mermaid diagram as fallback. |
| MITRE ATT&CK Mapping Table | `hunter_investigations` | `mitre_tactics[]` + `mitre_techniques[]` arrays, cross-referenced with severity |
| AI Analysis Pipeline (Triage → Hunter → Verifier) | `triage_scores` + `hunter_investigations` + `verifier_results` | API JOINs all 3 tables by `alert_id`/`event_id`/`investigation_id` chain. Each has `status`, timestamps, confidence. |
| Triage Agent Card (confidence, severity, SHAP bars) | `triage_scores` | All 29 columns: `combined_score`, `lgbm_score`, `eif_score`, `arf_score`, `adjusted_score`, `action`, `shap_top_features` (JSON), `shap_summary`, `asset_multiplier`, `ioc_match` |
| Hunter Agent Card (events, IOCs, queries) | `hunter_investigations` | `correlated_events` (Array UUID, length = events count), `evidence_json` (contains IOC correlations) |
| Verifier Agent Card (score, checks, FP score) | `verifier_results` | `confidence` (Float32), `evidence_verified` (UInt8), `verdict` (enum) |
| Merkle Integrity (verify button + output log) | `evidence_anchors` + source tables | Full cryptographic re-verification: API re-hashes events from source table (SHA256), rebuilds Merkle tree, compares stored root. Returns PASS/FAIL/TAMPERING with event counts. Uses `prev_merkle_root` for chain linking. |
| Raw Log Evidence (3 accordion entries with JSON) | `raw_logs` + `security_events` + `triage_scores` | API follows FK chain: `hunter_investigations.alert_id` → `security_events.event_id` → `security_events.raw_log_event_id` → `raw_logs.event_id`. Returns full payloads with `metadata` Map. |
| Timeline (chronological event sequence) | `verifier_results.timeline_json` | Verifier builds timeline during investigation — raw logs, triage scores, hunter findings, verifier verdict — all with real timestamps. API parses and groups by second. |

### Gaps

**None.** Every element is sourced from real ClickHouse data. The API at `/api/investigations/[id]` performs 5-table JOINs (hunter_investigations, verifier_results, security_events, raw_logs, triage_scores) plus evidence_anchors for Merkle verification.

---

## 5. AI Agents

**Page:** `/ai-agents`  
**API:** `/api/ai/agents`, `/api/ai/leaderboard`, `/api/ai/xai`  
**Coverage:** ~95%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Agent Pipeline Architecture (5-stage flow) | Static + agent health probes | Static visualization with live status dots from `/health` endpoints |
| Score Fusion Engine — 3 Models | `triage_scores` | `lgbm_score` (LightGBM), `eif_score` (Extended IF), `arf_score` (ARF/Autoencoder) — all Float32 per event |
| Score Fusion Engine — 4 Modifiers | `triage_scores` | `asset_multiplier` (Float32), `ioc_match` + `ioc_confidence` (UInt8), `template_rarity` (Float32), `allowlist` table check |
| Agent Confidence (3 donut charts) | Agent `/health` + CH tables | Triage: XAI `/xai/status` → `metrics.accuracy`. Hunter: `AVG(confidence) FROM hunter_investigations`. Verifier: `AVG(confidence) FROM verifier_results`. |
| Total Processed | `triage_scores` or Triage `/stats` | `count() FROM triage_scores` or `/stats` → `events_processed` |
| Avg Latency | Triage `:8300/health` | `avg_batch_time_ms` returned by health endpoint |
| HMAC Status | `evidence_anchors` | `countIf(status = 'Verified') / count()` — verification rate |
| Kafka Topics + Lag | Redpanda Admin API | `/v1/partitions` (topic count), consumer group lag from `/v1/groups` |
| Agent Performance Trends 24h (bar chart) | `triage_scores` + `hunter_investigations` | `SELECT toStartOfHour(timestamp) AS hour, count() FROM triage_scores GROUP BY hour` (same for hunter) |
| XAI Global Feature Importance (4 bars) | XAI `:8200/model/features` | Returns all features sorted by importance with display names |
| Recent Pipeline Activity (4 log entries) | `hunter_investigations` + `verifier_results` | `ORDER BY started_at DESC LIMIT 4` from each — agent name derived from table |

### Gaps

| Gap | What's Missing | Real Implementation |
|---|---|---|
| **Model Leaderboard — 3 models** | Only LightGBM has metrics via XAI. XGBoost and RF rows would be empty. | **Option A:** If you only use LightGBM (which is the case), show only that one model — this is the real state. **Option B:** Add multi-model support. In `agents/triage/model_ensemble.py`, the ensemble currently uses LightGBM + EIF + ARF. Expose each model's individual metrics by adding a `/model/metrics` endpoint to the triage agent that returns per-model accuracy computed from `feedback_labels`: `SELECT ts.model_version, countIf(fl.label = 'true_positive' AND ts.lgbm_score > 0.5) / countIf(ts.lgbm_score > 0.5) AS lgbm_precision FROM triage_scores ts JOIN feedback_labels fl ON ts.event_id = fl.event_id`. |

---

## 6. Chain of Custody

**Page:** `/chain-of-custody`  
**API:** `/api/evidence/chain`, `/api/evidence/verify`  
**Coverage:** 100%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| Verifier Agent Status Bar | Verifier `:8500/health` + `evidence_anchors` | Live health probe + aggregate stats |
| Total Batches | `evidence_anchors` | `count()` |
| Total Anchored (events) | `evidence_anchors` | `SUM(event_count)` |
| Verification Rate (%) | `evidence_anchors` | `countIf(status = 'Verified') / count() × 100` |
| Chain Length | `evidence_anchors` | `count()` — each batch is a chain link via `prev_merkle_root` |
| Evidence-Backed Investigations (5 rows) | `hunter_investigations` + `verifier_results.merkle_batch_ids` | JOIN investigations with evidence batches via merkle_batch_ids array or time-window overlap |
| Live Evidence Batches (6 rows, expandable) | `evidence_anchors` | All columns: `batch_id`, `table_name`, `event_count`, `created_at`, `merkle_root`, `merkle_depth`, `time_from`/`time_to`, `s3_key`, `status`, `prev_merkle_root` |
| VERIFY Button (per batch) | `/api/evidence/verify?batchId=X` | Full Merkle re-computation: fetches events from source table by time window, re-hashes each row (SHA256 of concatenated fields), rebuilds tree, applies chain hash with `prev_merkle_root`, compares stored root. Returns PASS/FAIL/TAMPERING with detailed diagnostics. |
| Footer (Last Updated, System Integrity) | `evidence_anchors` | `MAX(created_at)` for timestamp, aggregate verified/total for integrity |

### Gaps

**None.** This page is 100% backed by real cryptographic operations against live ClickHouse data. The verify endpoint performs actual SHA256 hashing and Merkle tree reconstruction — no mock verification.

---

## 7. Reports

**Page:** `/reports`  
**API:** `/api/reports`, `/api/reports/download`  
**Coverage:** ~85%

### Available Data

| Widget | Source Table / Endpoint | Query / Mechanism |
|---|---|---|
| **Tab 1: Reports** | | |
| Download Templates (5 cards) | Static | Template definitions — no dynamic data needed |
| Generate by Investigation table | `hunter_investigations` + `verifier_results` | JOIN on `investigation_id` → verdict, confidence, finding_type, severity, hostname, correlated counts |
| Download (Incident/Technical/Executive) | `/api/reports/download` | Fetches real data from `security_events` (alerts), `evidence_anchors` (evidence), per-table counts, MITRE techniques — formats as CSV/JSON/Markdown |
| **Tab 2: Investigations** | | |
| Investigation Table (filtered, paginated) | `hunter_investigations` + `verifier_results` | Full filter support: status, severity, search text, score range, time range. All via `/api/investigations` |
| Bottom Stats: High Risk Findings | `hunter_investigations` | `countIf(trigger_score >= 0.8)` |
| Bottom Stats: System Health | Agent `/health` endpoints + Prometheus `up` | Live probes |
| **Tab 3: Sigma Rules** | | |
| Total Alerts (with trend) | `security_events` | `count() WHERE timestamp >= now() - INTERVAL 24 HOUR` vs previous 24h |
| Top 10 Firing Rules (bars) | `security_events` | `GROUP BY category ORDER BY count() DESC LIMIT 10` — category = detection rule proxy |
| Severity Distribution (donut chart) | `security_severity_hourly` MV | `GROUP BY severity` with counts |
| Rules by MITRE Tactic (bars) | `security_events` | `GROUP BY mitre_tactic` with counts |
| **Tab 4: ML Model** | | |
| TP/FP Classification Ratio (donut) | `verifier_results` or `feedback_labels` | `countIf(verdict = 'true_positive')` vs `countIf(verdict = 'false_positive')` from `verifier_results` |
| Hunter Score Distribution (bar chart) | `triage_scores` | `SELECT intDiv(toUInt16(combined_score * 100), 10) * 10 AS bucket, count() FROM triage_scores GROUP BY bucket` |
| Feature Importance (table) | XAI `:8200/model/features` | Feature names + importance values |
| **Tab 5: Evidence Chain** | | |
| Stat Cards (Batches, Verified, Rate, Gaps) | `evidence_anchors` | `count()`, `countIf(status='Verified')`, verification rate, `countIf(prev_merkle_root = '')` for continuity gaps |
| Evidence Batch Table (paginated) | `evidence_anchors` | All columns: `batch_id`, `event_count`, `status`, `prev_merkle_root` (continuity check), `merkle_root`, `created_at` |
| Integrity Summary Chart (stacked bar) | `evidence_anchors` | `GROUP BY status` → Anchored/Verified/Pending series |

### Gaps

| Gap | What's Missing | Real Implementation |
|---|---|---|
| **Report History Table** (Tab 1) | No storage table for previously generated reports. Currently reports are generated on-the-fly for download. | **Create a `report_history` table in ClickHouse:** `CREATE TABLE clif_logs.report_history (report_id UUID DEFAULT generateUUIDv4(), title String, template LowCardinality(String), investigation_id Nullable(UUID), created_at DateTime64(3) DEFAULT now64(), format LowCardinality(String), size_bytes UInt32 DEFAULT 0, page_count UInt16 DEFAULT 0, s3_key String DEFAULT '', created_by String DEFAULT 'system') ENGINE = MergeTree() ORDER BY (created_at, report_id)`. Then in `/api/reports/download/route.ts`, after generating a report, INSERT a row into this table with the report metadata. The `/api/reports` endpoint adds a query: `SELECT * FROM report_history ORDER BY created_at DESC LIMIT 100`. |
| **Reports Generated count** (Tab 2 bottom stat) | Depends on report_history table above | **Same table:** `SELECT count() FROM report_history` |
| **Sigma Rules Metadata** (Tab 3: Coverage Score, TP Rate, Active Rules count) | No dedicated sigma rule catalog table. Vector VRL applies rules during parsing but doesn't store rule definitions. | **Create a `sigma_rules` table in ClickHouse:** `CREATE TABLE clif_logs.sigma_rules (rule_id String, rule_name String, severity LowCardinality(String), mitre_tactic LowCardinality(String), mitre_technique LowCardinality(String), description String, status LowCardinality(String) DEFAULT 'active', created_at DateTime64(3) DEFAULT now64(), last_fired Nullable(DateTime64(3)), fire_count UInt64 DEFAULT 0) ENGINE = ReplacingMergeTree() ORDER BY rule_id`. Populate from Vector VRL rule definitions by parsing `vector.yaml` transforms. Add a column `detection_rule` to `security_events` (already exists as String) and populate with `rule_id` during VRL classification. Then: Coverage = `uniqExact(mitre_technique) FROM sigma_rules` / total MITRE techniques. TP Rate = `countIf(label='true_positive') / count() FROM feedback_labels fl JOIN security_events se ON fl.event_id = se.event_id WHERE se.detection_rule != ''`. Active Rules = `countIf(status = 'active') FROM sigma_rules`. |
| **KL Divergence & PSI Max** (Tab 4) | Model drift metrics not computed or stored | **Add drift computation to triage agent:** In `agents/triage/score_fusion.py`, add a periodic task (every N batches) that computes KL divergence and PSI between the current feature distribution (from the last 1000 events) and the training baseline (stored in model manifest). Store results: `INSERT INTO pipeline_metrics (metric, value) VALUES ('kl_divergence', {kl}), ('psi_max', {psi})`. Query: `SELECT value FROM pipeline_metrics WHERE metric = 'kl_divergence' ORDER BY ts DESC LIMIT 1`. The `pipeline_metrics` table already exists with `ts`, `metric`, `value` columns. |
| **Per-Feature Drift PSI** (Tab 4 table) | Individual feature PSI not stored | **Extend the drift computation above:** For each feature, compute individual PSI and store: `INSERT INTO pipeline_metrics (metric, value) VALUES ('psi_feature_event_frequency', {psi}), ('psi_feature_sigma_match', {psi})`. Query: `SELECT metric, value FROM pipeline_metrics WHERE metric LIKE 'psi_feature_%' ORDER BY ts DESC LIMIT 1 BY metric`. |
| **Model Health** (Tab 4) | No model uptime tracking | **Use agent health probe data:** Model Health = `(time_since_last_successful_health_check < 60s)`. Compute uptime % from Prometheus: `avg_over_time(up{job="triage"}[24h]) * 100`. Sample Count = `count() FROM triage_scores WHERE timestamp >= now() - INTERVAL 24 HOUR`. |

---

## 8. Summary Matrix

| Page | Coverage | Gaps Count | Gap Severity |
|---|---|---|---|
| **Dashboard** | 100% | 0 | — |
| **Explainability** | ~80% | 6 | Medium — all solvable with aggregation queries + XAI endpoint additions |
| **Threat Intelligence** | 100% | 0 | — |
| **Investigation Detail** | 100% | 0 | — |
| **AI Agents** | ~95% | 1 | Low — only multi-model leaderboard |
| **Chain of Custody** | 100% | 0 | — |
| **Reports** | ~85% | 5 | Medium — report history table, sigma rules catalog, drift metrics |

### Total Gaps: 12

### Implementation Priority

**Priority 1 — Quick Wins (add queries/endpoints only, no schema changes):**

1. Explainability Radar Chart — aggregate existing metrics from 3 tables
2. Explainability Decision Boundary — query existing `triage_scores` columns
3. AI Agents Model Leaderboard — show single real model, not 3 blank rows
4. Reports Tab 4: TP/FP Ratio — query `verifier_results.verdict`
5. Reports Tab 4: Model Health — use Prometheus uptime

**Priority 2 — New Table + Insert Logic:**

6. Reports: `report_history` table — simple CREATE TABLE + INSERT on download
7. Reports: `sigma_rules` table — populate from Vector VRL rule definitions

**Priority 3 — Computation Pipeline Additions:**

8. Explainability: PSI Drift Score — add drift computation to triage training pipeline
9. Explainability: Feature Interactions — add co-occurrence analysis to XAI service
10. Explainability: Model Freshness — add `trained_at` to model manifest
11. Reports Tab 4: KL/PSI drift — periodic drift computation in triage agent
12. Explainability: Fairness Metrics — cross-tabulate `feedback_labels` with predictions

### What's NOT a Gap

Everything marked "REAL" above uses **actual pipeline data** — no mock objects, no hardcoded values, no fake generators. The data flows are:

```
Real Logs → Vector (parse/classify/enrich) → Redpanda (11 topics)
  → Go Consumer → ClickHouse (12 base tables + 14 MVs)
  → Triage Agent (score → triage_scores)
  → Hunter Agent (investigate → hunter_investigations)
  → Verifier Agent (verify → verifier_results)
  → Merkle Anchor (hash → evidence_anchors)
  → XAI Service (explain → live SHAP values)
  → Dashboard API → Real queries → Real charts
```
