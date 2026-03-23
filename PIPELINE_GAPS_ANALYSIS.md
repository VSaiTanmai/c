# CLIF Pipeline — Gaps & Limitations Analysis

> Generated: March 14, 2026  
> Based on: Code review + live pipeline data (534,826 real events)

---

## Gap 1: Log-Only Events Have Minimal Discriminative Features

**Severity**: HIGH  
**Component**: Triage Agent — Feature Extractor

The 19-feature vector is KDD/CICIDS-derived. For non-network events (pure syslog text logs without embedded IPs/ports), 8 out of 19 features (`count`, `srv_count`, `same_srv_rate`, `diff_srv_rate`, `serror_rate`, `rerror_rate`, `dst_host_count`, `dst_host_srv_count`) are hardcoded to **0.0**. Two more (`src_bytes` = message length, `dst_bytes` = 0) carry weak signal.

This leaves only **3 truly discriminative features** for log-only events: `severity_numeric`, `hour_of_day`, `day_of_week`. The model is essentially guessing for text-only logs without network metadata.

**Evidence**: Socket events (JSON logs) have a 1.2% escalation rate vs 32.0% for syslog — a 27x disparity suggesting systematic under-scoring of one log format.

**Recommendation**: Add NLP-derived features (TF-IDF of message tokens, log template cluster distance, semantic embedding similarity) or a separate text-classification model for non-network logs.

---

## Gap 2: 2-Second Time Window Misses Slow/Low Attacks

**Severity**: HIGH  
**Component**: Triage Agent — ConnectionTracker

The `ConnectionTracker` uses a fixed 2-second sliding window per (src_ip → dst_ip) pair. An attacker sending 1 connection every 3 seconds will always have `count=1` and `serror_rate=0.0` in each window — indistinguishable from normal traffic.

Slow brute force (1 attempt/minute), low-and-slow port scans, and patient lateral movement are invisible to this window.

**Evidence**: The 100-connection host window (`dst_host_count`) provides some long-term visibility, but it only tracks per `dst_ip`, not per (src→dst) pair, and has no time decay.

**Recommendation**: Add multi-scale windows (2s, 60s, 300s, 3600s) and compute features at each scale. Alternatively, maintain exponentially-weighted moving averages that naturally capture both fast and slow patterns.

---

## Gap 3: No Content/Payload Inspection

**Severity**: MEDIUM  
**Component**: Vector + Triage Agent

The pipeline operates purely on metadata features (byte counts, ports, timing, error rates). It never inspects the actual payload content of network connections or the semantic content of log messages beyond keyword regex in Vector.

Encrypted C2 channels, DNS tunneling with valid-looking queries, and data exfiltration within normal-looking HTTPS traffic are undetectable by the current feature set.

**Evidence**: Vector's regex only catches literal keywords like "dns tunnel" or "reverse shell" — it can't detect actual DNS tunneling behavior (high entropy in DNS query names, unusually long DNS records, high query frequency to a single domain).

**Recommendation**: Add entropy-based features for DNS query names, JA3/JA3S TLS fingerprinting correlation, and payload-length distribution anomaly metrics.

---

## Gap 4: Template Rarity Removed from Model but Not Replaced

**Severity**: MEDIUM  
**Component**: Triage Agent — Feature Extractor / Config

`template_rarity` was the #1 LightGBM feature by importance (947K gain) in v5, but was **removed from v6 model features** because it was "unreliable in production." The post-model boost is also disabled (`TEMPLATE_RARITY_BOOST_MAX = 0.0`).

This means Drain3 template mining runs on every event, consuming CPU, but its output contributes **zero signal** to the scoring decision.

**Evidence**: 
- `config.py`: `TEMPLATE_RARITY_BOOST_MAX = 0.0` (disabled)  
- `feature_extractor.py` comment: "v6: template_rarity REMOVED from model features (unreliable in production)"  
- Drain3 still runs for every event in `extract()` → wasted computation

**Recommendation**: Either fix the production reliability issue (likely Drain3 cold-start instability — the warmup guard exists but may not be sufficient) and re-enable the feature, or remove the Drain3 processing entirely to save CPU.

---

## Gap 5: Triage Throughput Bottleneck (~1-2 EPS)

**Severity**: HIGH  
**Component**: Triage Agent — Processing Pipeline

Measured sustained throughput is **~1.3-2.2 events/second** across 4 replicas. For a SIEM expected to handle thousands of EPS, this is orders of magnitude too slow.

Bottlenecks:
1. **SHAP attribution**: For each escalated event, runs 5 extra model inferences (one per zeroed-out feature). With 19.5% escalation rate, ~1 in 5 events triggers this.
2. **ARF `predict_proba_one()`**: River's ARF processes events one-at-a-time; it cannot batch.
3. **ConnectionTracker lock contention**: Single mutex for all src/dst IP lookups.
4. **ClickHouse writes per batch**: Each triage batch writes to `arf_replay_buffer`.

**Evidence**: Pipeline data shows 534,826 events with timestamps spanning months, and per-minute throughput of 45-133 events/minute (0.8-2.2 EPS).

**Recommendation**: 
- Defer SHAP to an async post-processing queue (don't block the scoring pipeline)
- Batch ARF predictions using River's batch utilities or replace with a batched online model
- Shard ConnectionTracker by src_ip hash (one lock per shard)
- Scale to 8-16 triage replicas or move to GPU inference for LightGBM

---

## Gap 6: Socket vs Syslog Scoring Disparity

**Severity**: HIGH  
**Component**: Triage Agent — Source Type Encoding

Socket-source events have a dramatically different score distribution from syslog events:

| Source | Events | Escalated | Rate | Avg Score (escalated) |
|--------|--------|-----------|------|----------------------|
| syslog | 318K | 101,750 | 32.0% | 0.979 |
| socket | 217K | 2,571 | 1.2% | 0.896 |

The `source_type_numeric` mapping may be encoding training-time biases. The LightGBM model may have learned that `source_type=1` (syslog) correlates with attacks while `source_type=9` or other socket mappings correlate with normal traffic — a spurious correlation from the training dataset composition, not a real pattern.

**Evidence**: Even when socket events ARE escalated, their average combined score (0.896) is lower than syslog (0.979), suggesting the model is systematically less confident about socket events.

**Recommendation**: Audit the training dataset for source-type balance. If syslog was overrepresented in malicious samples, either balance the training data or remove `source_type_numeric` as a feature (let the model rely on behavioral features only).

---

## Gap 7: No Feedback Loop — Models Don't Learn from Analyst Decisions

**Severity**: HIGH  
**Component**: Triage Agent — ARF Learning / Score Fusion

The `feedback_labels` table exists in the schema but contained **0 real analyst labels** (had to be seeded with heuristic pseudo-labels). The ARF online learner uses LightGBM pseudo-labels (`>0.80 → malicious, <0.20 → normal`), not human feedback.

This means:
- The supervised model (LightGBM) never improves from production experience
- The online learner (ARF) learns from another model's opinions, not ground truth
- False positives/negatives are never corrected
- The pipeline has no mechanism to adapt to the specific organization's threat landscape

**Evidence**: 
- `config.py`: `ARF_LABEL_SOURCE = "lgbm_pseudo"` — labels come from the model itself
- `feedback_labels` table was empty until artificially seeded
- No UI or API endpoint for analysts to submit labels

**Recommendation**: Build a feedback UI in the dashboard where analysts can label escalated events as true positive, false positive, or false negative. Use these labels for periodic LightGBM retraining and real-time ARF learning.

---

## Gap 8: EIF Score Discrimination is Narrow

**Severity**: MEDIUM  
**Component**: Triage Agent — Extended Isolation Forest

The EIF model has a narrow effective score range:

| Class | Avg EIF Score |
|-------|---------------|
| Discarded (normal) | 0.430 |
| Monitored | 0.463 |
| Escalated (attack) | 0.949 |

The gap between normal (0.43) and monitored (0.46) is only **0.033** — virtually no discrimination in the critical middle range. Most of the EIF's discrimination comes from the extreme tails.

Combined with its 12% weight, the EIF contributes only ~0.004-0.006 score difference between normal and monitored events. Its primary value is the anomaly override (EIF ≥ 0.85 → floor=0.42), not continuous scoring.

**Evidence**: Training data shows `EIF: normal=0.4853, mal=0.6478` — the model was score-flipped because normal scored higher than malicious. This suggests the EIF struggles with the heterogeneous multi-log feature space.

**Recommendation**: Retrain EIF on normal-only data from a single, clean feature distribution. Or replace with an autoencoder that can learn a more nuanced normality model across heterogeneous log types.

---

## Gap 9: Vector Classification Leaks into Model Input

**Severity**: MEDIUM  
**Component**: Vector → Triage Agent Feature Interaction

Although v6 added `original_log_level` to break the circular dependency (Vector's classification → severity → model feature → score), the fallback chain in the feature extractor still uses `.severity` as a third fallback:

```python
severity_raw = event.get(
    "original_log_level",
    event.get("level", event.get("severity", "info"))
)
```

If `original_log_level` is missing (e.g., older events, pre-classified events), the model receives Vector's classification-inflated severity — events Vector tagged as `security` get `severity=3-4`, while unrecognized events get `severity=0`. This creates a self-reinforcing loop where novel threats (no regex match → low severity → low model score → discarded).

**Evidence**: Feature extractor code explicitly documents this risk in comments. The `_skip_classify` path for pre-classified events does NOT set `original_log_level`.

**Recommendation**: Make `original_log_level` mandatory in the Vector output schema. Remove the fallback to `.severity` in the feature extractor.

---

## Gap 10: No Lateral Movement or Kill-Chain Correlation

**Severity**: HIGH  
**Component**: Pipeline Architecture

Each event is scored **independently**. There is no mechanism to correlate a sequence of events into an attack chain:

1. Brute force login (auth failure × 100) → scored individually
2. Successful login after brute force → scored as benign auth success (severity=1)
3. New process spawn → scored independently, likely low score
4. Outbound data transfer → scored independently

A human analyst would see steps 1→2→3→4 as a single intrusion. The pipeline sees 4 unrelated events and may only escalate step 1.

**Evidence**: The ConnectionTracker tracks per-IP activity within 2 seconds, but there is no session-level, user-level, or host-level correlation across event types or time scales.

**Recommendation**: Add a session/kill-chain correlator that tracks per-host state machines (reconnaissance → initial access → execution → persistence → exfiltration) and escalates when multiple stages are observed within a time window.

---

## Gap 11: Threat Intel (IOC) is Boosted but Not in Training Data

**Severity**: MEDIUM  
**Component**: Triage Agent — Score Fusion

The `threat_intel_flag` feature is always 0 in training data (`config.py` comment: "threat_intel_flag remains 0 in training"). The model never learned to use IOC matches as a feature. Instead, IOC hits are handled via:
- Post-model score boost: `+0.15`
- Asset multiplier floor: `max(multiplier, 1.5)`

This is a crude heuristic. A normal event from an IOC-matched IP gets boosted by +0.15 and ×1.5, potentially escalating benign traffic from a recently-flagged IP that was already cleaned up.

**Evidence**: `config.py`: `IOC_MATCH_SCORE_BOOST = 0.15`; training data has `threat_intel_flag=0` for all samples.

**Recommendation**: Include IOC matches in the training data with realistic ratios. This lets the model learn the _context_ where IOC matches matter (suspicious behavior + IOC = high score) vs. don't (normal behavior + IOC = moderate score).

---

## Gap 12: No Encrypted Traffic Analysis

**Severity**: MEDIUM  
**Component**: Pipeline Architecture

The pipeline has no JA3/JA3S TLS fingerprinting, no certificate analysis, no encrypted traffic metadata features. Modern attacks primarily use HTTPS/TLS for C2, data exfiltration, and lateral movement.

Features like `dst_port=443`, `bytes_sent`, `bytes_received` capture basic connection characteristics but miss TLS-specific indicators:
- Unusual cipher suites (JA3 hash)
- Self-signed or recently-issued certificates
- Certificate pinning anomalies
- TLS version downgrade attacks

**Recommendation**: If the log sources include TLS metadata (e.g., from a TLS-terminating proxy, Zeek/Suricata logs), add JA3 hash matching and certificate anomaly features. If not, this requires infrastructure changes (deploying a network tap with TLS inspection).

---

## Gap 13: Single Hostname Source — No Network Diversity

**Severity**: LOW (data-specific)  
**Component**: Training/Ingestion Data

All 534K events in the current pipeline originate from hostname `LabSZ` with source IP `172.18.0.1`. This is a lab environment, not a production network with diverse hosts.

The `asset_criticality` multiplier and `hostname`-based features have no variance, and the ConnectionTracker's per-dst_ip windowing has limited diversity.

**Evidence**: All sample escalated events show `hostname=LabSZ`, `source_ip=172.18.0.1`.

**Recommendation**: Ingest logs from multiple production hosts, network segments, and user populations to validate the pipeline under realistic conditions.

---

## Gap 14: ARF Cold-Start and Pickle Bug Workaround

**Severity**: MEDIUM  
**Component**: Triage Agent — Adaptive Random Forest

River's ARF has a known bug where pickled models return **constant probabilities** after deserialization. The workaround (warm restart from ClickHouse replay buffer) adds:
- 50K-row ClickHouse query at startup
- Sequential `learn_one()` calls for each replayed event
- Startup delay proportional to replay buffer size
- Dependency on ClickHouse being available at Triage startup

If ClickHouse is down at startup and no CSV fallback exists, ARF starts with **uninformed prior (0.5)** — its 8% weight adds a constant 0.04 to all scores. With the confidence ramp (10K events before full weight), this is mitigated but not eliminated.

**Evidence**: `model_ensemble.py` comment: "After pickle.load(), River ARF models return CONSTANT probabilities (upstream River bug). The pickle file is retained as an offline reference but is NEVER loaded for production inference."

**Recommendation**: Monitor the River project for a pickle fix. Consider replacing ARF with a different online learner (e.g., Mondrian Forest, Online Gradient Boosting) that serializes correctly.

---

## Gap 15: No User/Entity Behavior Analytics (UEBA)

**Severity**: HIGH  
**Component**: Pipeline Architecture

The pipeline has no concept of user or entity behavior baselines. It doesn't track:
- Normal working hours per user
- Typical access patterns per user
- Usual data transfer volumes per host
- Expected network connections per service

An insider threat using their legitimate credentials during normal hours, accessing systems they normally access, but exfiltrating slightly more data than usual, is invisible to this pipeline.

**Evidence**: While `user_id` is extracted and stored, it's never used as a feature. `hour_of_day` and `day_of_week` are global features, not per-user baselines.

**Recommendation**: Build per-user and per-host behavior profiles (rolling statistics over 7-30 days) and add deviation-from-baseline features to the model.

---

## Summary Table

| # | Gap | Severity | Component | Status |
|---|-----|----------|-----------|--------|
| 1 | Log-only events have minimal features (8/19 = zero) | HIGH | Feature Extractor | Open |
| 2 | 2-second window misses slow/low attacks | HIGH | ConnectionTracker | Open |
| 3 | No payload/content inspection | MEDIUM | Vector + Triage | Open |
| 4 | Template rarity disabled but Drain3 still running | MEDIUM | Feature Extractor | Open |
| 5 | Triage throughput ~1-2 EPS (too slow for production) | HIGH | Triage Pipeline | Open |
| 6 | Socket vs Syslog scoring disparity (1.2% vs 32%) | HIGH | Source Type Encoding | Open |
| 7 | No analyst feedback loop — models don't learn from humans | HIGH | Score Fusion / ARF | Open |
| 8 | EIF score discrimination is narrow (0.43 vs 0.46) | MEDIUM | EIF Model | Open |
| 9 | Vector classification leaks into model via severity fallback | MEDIUM | Feature Extractor | Partially Fixed |
| 10 | No lateral movement or kill-chain correlation | HIGH | Architecture | Open |
| 11 | IOC boost is heuristic, not model-learned | MEDIUM | Score Fusion | Open |
| 12 | No encrypted traffic analysis (JA3, certs) | MEDIUM | Architecture | Open |
| 13 | Single hostname source — no network diversity | LOW | Data | Open |
| 14 | ARF pickle bug workaround adds startup fragility | MEDIUM | Model Ensemble | Open |
| 15 | No UEBA — no per-user/entity baselines | HIGH | Architecture | Open |

**HIGH severity gaps**: 1, 2, 5, 6, 7, 10, 15 (7 gaps)  
**MEDIUM severity gaps**: 3, 4, 8, 9, 11, 12, 14 (7 gaps)  
**LOW severity gaps**: 13 (1 gap)
