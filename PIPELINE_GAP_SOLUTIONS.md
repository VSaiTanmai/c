# CLIF Pipeline — Gap Solutions Design

> Generated: March 14, 2026  
> Goal: Process ANY type of raw log at high throughput while accurately detecting known and anomalous attacks  
> Based on: Deep code review of all pipeline components + live data analysis (534K events)

---

## Solution 1: Log-Only Events Have Minimal Discriminative Features

**Gap**: 8 of 19 features are zero for non-network logs → model has only 3 useful features for text-only events.

### Solution: Dual-Track Feature Extraction

Split the feature extractor into two parallel tracks that merge before model inference:

**Track A — Network Features (existing)**: The current 19 features for events with network metadata. No changes needed.

**Track B — Text Features (new, for all events)**: Add 5 text-derived features computed from the log message body:

| # | Feature | How to Compute | Why |
|---|---------|----------------|-----|
| 1 | `template_cluster_size` | Drain3 cluster size (already computed but unused) | Rare templates = unusual events |
| 2 | `message_entropy` | Shannon entropy of message bytes: $H = -\sum p_i \log_2 p_i$ | Encoded/obfuscated payloads have high entropy |
| 3 | `token_count` | Number of whitespace-delimited tokens | Log verbosity correlates with event complexity |
| 4 | `numeric_ratio` | Count of digit characters / message length | IP addresses, ports, error codes increase this |
| 5 | `special_char_ratio` | Count of non-alphanumeric / message length | Injection attacks, encoded payloads, base64 |

**Implementation in `feature_extractor.py`**:

```python
# Add to extract() after _msg_body assignment:
msg_str = str(message_body) if message_body else ""
msg_len = max(len(msg_str), 1)

# Feature: Shannon entropy
from collections import Counter
byte_counts = Counter(msg_str.encode('utf-8', errors='replace'))
total = sum(byte_counts.values())
message_entropy = -sum((c/total) * math.log2(c/total) for c in byte_counts.values() if c > 0)

# Feature: Token count  
token_count = float(len(msg_str.split()))

# Feature: Numeric ratio
numeric_ratio = sum(c.isdigit() for c in msg_str) / msg_len

# Feature: Special character ratio  
special_char_ratio = sum(not c.isalnum() and not c.isspace() for c in msg_str) / msg_len
```

These features are **O(n)** on message length (fast), require **no external models**, and work for ALL log types — syslog, JSON, Windows events, CEF, anything.

**Model Impact**: Expand `FEATURE_NAMES` from 19 → 24 features. Retrain LightGBM with the new features using the existing training pipeline (`scripts/retrain_all.py`). The text features give log-only events 8 useful features instead of 3.

**Why not embeddings/TF-IDF**: They require a trained tokenizer or vocab, add latency, and increase model complexity. Pure statistical features (entropy, ratios, counts) are language/format agnostic and compute in microseconds — matching the "any raw log" goal.

---

## Solution 2: 2-Second Time Window Misses Slow/Low Attacks

**Gap**: Fixed 2s window means attackers with >3s interval always see `count=1`.

### Solution: Multi-Scale Exponential Decay Counters

Replace the single 2-second window with **3 decay scales** using exponentially weighted moving averages (EWMA). No sliding window needed — just a counter per IP pair that decays over time.

**Design**:

```
Per (src_ip → dst_ip) pair, maintain 3 EWMA counters:
  fast_rate   (half-life = 2s)   — catches bursts (port scans, DDoS)
  medium_rate (half-life = 60s)  — catches moderate attacks (brute force)
  slow_rate   (half-life = 600s) — catches slow/low (patient reconnaissance)

On each event:
  elapsed = now - last_seen
  decay = exp(-elapsed * ln(2) / half_life)
  rate = rate * decay + 1.0
```

**New features** (replace existing 8 KDD features with 9 multi-scale features):

| Feature | Description |
|---------|-------------|
| `conn_rate_fast` | EWMA rate at 2s half-life (replaces `count`) |
| `conn_rate_medium` | EWMA rate at 60s half-life |
| `conn_rate_slow` | EWMA rate at 600s half-life |
| `srv_rate_fast` | Same-service rate at 2s |
| `error_rate_fast` | Error rate at 2s |
| `error_rate_medium` | Error rate at 60s |
| `dst_host_diversity` | Unique src_ips per dst_ip (last 100 connections, unchanged) |
| `dst_host_srv_count` | Same-service count on dst_ip (unchanged) |
| `rate_acceleration` | `conn_rate_fast / max(conn_rate_slow, 0.01)` — spikes relative to baseline |

**Why EWMA**: No sliding window to maintain (O(1) memory per pair), no lock contention for window cleanup, naturally captures multi-timescale patterns. The `rate_acceleration` feature specifically catches the pattern where a slow baseline suddenly spikes — classic attack onset.

**Memory**: Each (src_ip→dst_ip) pair stores 7 floats + timestamp = ~64 bytes. With 100K active pairs: ~6.4 MB. The existing `ConnectionTracker` already tracks `Dict[str, Deque[ConnectionRecord]]` with up to 10K records per IP — the EWMA approach uses **less memory**.

---

## Solution 3: No Content/Payload Inspection

**Gap**: Pipeline operates on metadata only; can't detect encrypted C2, DNS tunneling, etc.

### Solution: Lightweight Protocol Anomaly Features (No Deep Inspection)

True DPI is infeasible without infrastructure changes. Instead, add **protocol-behavioral features** that detect anomalous usage patterns without inspecting payload content:

| Feature | Detects | Computation |
|---------|---------|-------------|
| `dns_query_entropy` | DNS tunneling (high entropy in query names) | Shannon entropy of DNS query string if `dst_port=53` or `dns_query` field exists |
| `dns_query_length` | DNS tunneling (unusually long queries) | `len(dns_query)` — legitimate queries average ~15 chars, tunneling >50 |
| `bytes_ratio` | Data exfiltration asymmetry | `src_bytes / max(src_bytes + dst_bytes, 1)` — normal browsing ≈0.1, exfil ≈0.9 |
| `port_novelty` | Unusual service access | `1.0` if `dst_port` not in top-100 common ports, else `0.0` |
| `duration_anomaly` | C2 beaconing (regular intervals) | Standard deviation of inter-connection timing from same src_ip in last 100 connections |

These are computed from **existing fields** the pipeline already extracts (`dst_port`, `dns_query`, `bytes_sent`, `bytes_received`, `duration_ms`) — no new log sources needed.

**Where to add**: In `feature_extractor.py` → `extract()`, after the existing KDD features are computed. These features are O(1) per event (except `duration_anomaly` which needs the ConnectionTracker's existing per-IP history).

---

## Solution 4: Template Rarity Disabled but Drain3 Still Running

**Gap**: Drain3 runs on every event consuming CPU but contributing zero signal (boost disabled, feature removed from model).

### Solution: Re-enable Template Rarity as a Feature with Stability Fix

The instability reason was cold start — Drain3 has too few templates early on, producing unreliable rarity scores. The warmup guard (returns 0.5 until 10K events) already mitigates this, but there are two remaining issues:

1. **Cross-restart instability**: Drain3 state file may not persist correctly across container restarts (new model, new state)
2. **Cluster count drift**: With `max_clusters=1024`, old clusters accumulate and aren't pruned

**Fix**:

```python
# In drain3_miner.py, add cluster pruning:
def _prune_stale_clusters(self):
    """Remove clusters not seen in the last 100K events."""
    if self._total_events % 100_000 != 0:
        return
    active_threshold = self._total_events - 100_000
    # Keep only clusters with recent matches
    ...
```

Then **re-add `template_rarity` to `FEATURE_NAMES`** (position 20), making it a 20-feature model. The warmup guard + cluster pruning together prevent the instability that caused it to be removed.

**Alternatively** — if template rarity is not worth the complexity, remove Drain3 entirely to save CPU:
- Delete `drain3_miner.py` references from `feature_extractor.py` and `app.py`
- Remove `template_id`, `template_str`, `template_rarity` from the output
- Saves the `threading.Lock` + tree traversal + linear cluster scan per event

**Recommended approach**: Keep Drain3 but don't feed `template_rarity` to the model. Instead, use it as a **post-model boost multiplier** — set `TEMPLATE_RARITY_BOOST_MAX = 0.05` so that extremely rare templates (rarity < 0.15) get a small scoring nudge. This avoids retraining while extracting some value from the computation. The boost is capped at 0.05 to prevent false escalations.

---

## Solution 5: Triage Throughput Bottleneck (~1-2 EPS)

**Gap**: Pipeline processes ~1-2 EPS. A production SIEM needs 1,000-10,000+ EPS.

### Solution: 4-Part Throughput Optimization

The bottleneck is the Python triage agent. Based on the profiling, here are the fixes in priority order:

#### 5A. Defer SHAP to Async Post-Processing (Biggest Win)

SHAP runs **21 extra ONNX inferences per escalated event** synchronously inside `process_batch()`. SHAP results are NOT used for routing — they're stored for the dashboard.

**Fix**: Move SHAP to a background thread pool:

```python
# In app.py, replace synchronous SHAP call:
# OLD (blocking):
shap_results = self._shap.explain_batch_escalated(X, model_scores, actions)

# NEW (non-blocking):
self._shap_executor.submit(
    self._deferred_shap, event_ids, X, model_scores, actions
)

def _deferred_shap(self, event_ids, X, model_scores, actions):
    """Runs in background thread, updates ClickHouse directly."""
    results = self._shap.explain_batch_escalated(X, model_scores, actions)
    # UPDATE triage_scores SET shap_top_features=..., shap_summary=... 
    # WHERE event_id IN (...)
```

**Impact**: At 19.5% escalation rate with batch=500, this removes ~525 ONNX inferences from the critical path per batch. Even though ONNX is fast (~0.1ms each), this still saves ~50ms/batch and more importantly unblocks the consumer loop.

#### 5B. Batch ARF via Pre-computed Fallback

River's `predict_proba_one()` cannot be vectorized. With 8% weight and the confidence ramp, ARF adds minimal value during the first 10K events anyway.

**Fix**: Pre-compute ARF scores for the batch using a ThreadPoolExecutor and timeout:

```python
# In model_ensemble.py predict_batch():
with ThreadPoolExecutor(max_workers=4) as pool:
    arf_futures = [pool.submit(self._arf.predict_one, row) for row in rows]
    arf_scores = []
    for f in arf_futures:
        try:
            arf_scores.append(f.result(timeout=0.01))  # 10ms timeout per event
        except TimeoutError:
            arf_scores.append(0.5)  # uninformed prior on timeout
```

**Alternative (simpler)**: If ARF throughput remains a bottleneck, reduce its weight to 0% and give EIF+LGBM the full 100%. ARF's value is marginal — it has narrow-band outputs (~0.074 cold, ~0.7-1.0 warm) and only 8% weight. Removing it eliminates the row-by-row Python loop entirely.

#### 5C. Parallelize Feature Extraction

Currently sequential (`for event in events: extract(event, topic)`). Feature extraction is CPU-bound (regex, ConnectionTracker lookup, Drain3).

**Fix**: Use multi-processing for feature extraction batches:

```python
# In app.py process_batch():
from concurrent.futures import ProcessPoolExecutor
# BUT: ConnectionTracker is stateful & shared → cannot use ProcessPool

# Better: Split batch into chunks, extract in thread pool
# (GIL is released during regex operations)
with ThreadPoolExecutor(max_workers=4) as pool:
    chunks = [events[i::4] for i in range(4)]
    results = list(pool.map(
        lambda chunk: [self._extractor.extract(e, topic) for e in chunk],
        chunks
    ))
    features_list = [f for chunk_result in results for f in chunk_result]
```

Note: The `ConnectionTracker` uses a single `threading.Lock`, which serializes under contention. Replace with a **sharded lock** (lock per `hash(src_ip) % 16`) for 16x reduction in lock contention.

#### 5D. Scale Replicas + Increase Batch Size

Current: 4 replicas × 500 batch × 1.75 CPU.

**Immediate fix** (no code changes):
- Increase `BATCH_SIZE` from 500 → 2000 (ONNX Runtime is more efficient with larger batches)
- Increase triage replicas from 4 → 8 (requires more PC2 resources or a third machine)
- Increase Redpanda partitions from 12 → 24 per topic (enables more parallel consumers)

**Expected throughput gain**: 5A (defer SHAP) + 5D (8 replicas, batch=2000) should yield **50-100x improvement** → 100-200 EPS. Combined with 5B (batch ARF), closer to **200-500 EPS**.

For 10,000+ EPS: Replace the Python triage agent with a **Go reimplementation** using ONNX Runtime Go bindings, eliminating GIL, Python overhead, and River dependency. The Go consumer already demonstrates this architecture can handle 500K event batches.

---

## Solution 6: Socket vs Syslog Scoring Disparity

**Gap**: Socket events escalate at 1.2% vs syslog at 32% — 27x disparity.

### Solution: Source-Blind Model + Per-Source Threshold Calibration

**Root Cause Investigation**: The disparity has two possible causes:
1. **Training data bias**: syslog-format datasets (NSL-KDD, CICIDS) dominate the training set; socket-format events were underrepresented in malicious samples
2. **Feature leakage**: `source_type_numeric` encodes the log format, and the model learned that syslog=1 correlates with attacks

**Fix (two-pronged)**:

**A. Remove `source_type_numeric` from model features**  

This feature encodes the *transport format*, not threat behavior. A port scan looks the same whether it arrives via syslog UDP or JSON TCP socket. Removing it forces the model to rely on behavioral features only.

```python
# In FEATURE_NAMES, remove "source_type_numeric"
# Retrain with scripts/retrain_all.py
```

**B. Calibrate per-source thresholds using the existing `source_thresholds` table**

The `SourceThresholdCache` already supports per-source thresholds. Populate the table with calibrated values:

```sql
INSERT INTO source_thresholds VALUES
  ('syslog', 0.45, 0.95),    -- higher suspicious for syslog (high baseline)
  ('socket', 0.30, 0.90);    -- lower thresholds for socket (currently under-detected)
```

This compensates for any remaining model bias by setting source-appropriate thresholds.

---

## Solution 7: No Analyst Feedback Loop

**Gap**: Models never learn from human decisions. ARF learns from LightGBM pseudo-labels only.

### Solution: Feedback API + Periodic Retraining Pipeline

**A. Dashboard Feedback Endpoint** (add to existing dashboard API):

```typescript
// POST /api/feedback
// Body: { event_id: string, label: "true_positive" | "false_positive" | "false_negative", notes: string }
```

This writes to the existing `feedback_labels` ClickHouse table (already in schema with `Enum8('true_positive'=1, 'false_positive'=2, 'unknown'=3)` — extend enum to include `'false_negative'=4`).

**B. Change ARF label source to prefer human labels**:

```python
# In app.py _write_replay_buffer(), change label resolution:
# Priority: 1) Human label from feedback_labels (if exists)
#           2) LightGBM pseudo-label (current fallback)

# Periodically (every 5 minutes), refresh a cache of event_id → human_label
# from ClickHouse: SELECT event_id, label FROM feedback_labels WHERE created_at > now() - INTERVAL 24 HOUR
```

**C. Scheduled LightGBM Retraining** (weekly cron job):

```bash
# Weekly: Pull last 7 days of human-labeled events from feedback_labels
# Combine with original training data (weighted: human labels 3x)
# Retrain LightGBM → new ONNX file
# Validate F1 > 0.90 on holdout → auto-deploy if pass, alert if fail
```

The existing `scripts/retrain_all.py` already handles the retraining pipeline. Add a `--feedback-labels` flag that pulls from ClickHouse.

**D. Feedback Volume Requirements**: Need at least ~500 labeled events to meaningfully influence retraining. Display a "labels needed" counter in the dashboard to encourage analyst participation.

---

## Solution 8: EIF Score Discrimination is Narrow

**Gap**: EIF scores 0.43 (normal) vs 0.46 (monitored) — only 0.03 gap in the critical middle range.

### Solution: Replace EIF with Autoencoder Anomaly Detector

The Extended Isolation Forest struggles with heterogeneous multi-log feature spaces because it uses random hyperplane splits that don't align with the data's natural boundaries. With the `score_flip=True` already required, the model is fundamentally misaligned.

**Replacement**: A simple feedforward autoencoder trained on normal-only data:

```
Architecture: 24 → 16 → 8 → 16 → 24 (encoder-decoder)
Loss: MSE reconstruction error
Anomaly score: reconstruction_error / training_99th_percentile_error
```

**Why autoencoder over EIF**:
- Learns the **actual manifold** of normal data (not random splits)
- Produces a continuous, well-spread anomaly score (reconstruction error)
- Handles heterogeneous features naturally (the bottleneck layer learns a compressed normal representation)
- Can be exported to ONNX for batch inference (same as LightGBM — no API change)
- Training on normal-only data means it doesn't need attack labels

**Implementation**:
```python
# Train offline with PyTorch/scikit-learn:
# 1. Collect 100K normal events (action=discard in triage_scores)
# 2. Train autoencoder, save to ONNX
# 3. Compute 99th percentile reconstruction error on normal data → threshold
# 4. Replace ExtendedIsolationForest class with AutoencoderAnomaly class
#    that loads ONNX and computes normalized reconstruction error
```

**Score spread improvement**: Autoencoders typically produce reconstruction errors ranging from 0.01 (perfectly normal) to 10+ (completely anomalous), giving much better discrimination than EIF's 0.43-0.95 range.

**Deployment**: Drop-in replacement — the `ModelEnsemble.predict_batch()` already treats EIF as a black box that returns `scores: np.ndarray`. The autoencoder would implement the same interface.

---

## Solution 9: Vector Classification Leaks into Model Input

**Gap**: Severity fallback chain uses Vector's classification-inflated `.severity` when `original_log_level` is missing.

### Solution: Strict Original-Only Severity + Default Neutral Value

**Fix in `feature_extractor.py`** — Remove the `.severity` fallback entirely:

```python
# CURRENT (leaks Vector classification):
severity_raw = event.get(
    "original_log_level",
    event.get("level", event.get("severity", "info"))
)

# FIXED (strict — original source severity only):
severity_raw = event.get("original_log_level", 0)
# If the source system didn't provide a severity, default to 0 (unknown)
# NOT to Vector's classification-inflated severity
```

**Fix in `vector.yaml`** — Ensure `original_log_level` is ALWAYS set, including for pre-classified events:

```yaml
# In the _skip_classify=true branch, add:
} else {
  # Pre-classified: safe defaults
  # ALWAYS compute original_log_level from raw fields
  .original_log_level = 0
  if exists(.level) {
    _oll = upcase(to_string!(.level))
    # ... same mapping as Section B
  }
}
```

**Impact**: Novel attacks that don't match Vector's regex patterns (the exact events the ML models should catch) will no longer be penalized with `severity=0`. They'll get a neutral `original_log_level` and the model will score them based on behavioral features.

---

## Solution 10: No Lateral Movement or Kill-Chain Correlation

**Gap**: Each event scored independently. Multi-stage attacks spanning minutes/hours are invisible.

### Solution: Host-Level Session State Machine in Score Fusion

Add a lightweight **per-host state tracker** in the Triage agent that maintains kill-chain progression:

```
State Machine per hostname (via ClickHouse table or in-memory cache):
  RECONNAISSANCE → INITIAL_ACCESS → EXECUTION → PERSISTENCE → EXFILTRATION
```

**Implementation**:

```python
class KillChainTracker:
    """Tracks per-host attack stage progression."""
    
    STAGES = {
        "reconnaissance": 1,   # port scan, service enumeration
        "initial_access": 2,   # brute force success, exploit
        "execution": 3,        # new process, script execution
        "persistence": 4,      # cron job, service creation
        "exfiltration": 5,     # large outbound transfer
    }
    
    def update(self, hostname: str, event_category: str, score: float) -> float:
        """Returns a boost multiplier based on kill-chain progression."""
        current_stage = self._get_stage(hostname)
        new_stage = self._classify_stage(event_category, score)
        
        if new_stage > current_stage:
            # Kill-chain progressed! Each stage transition doubles the boost
            boost = 1.0 + (new_stage - 1) * 0.15  # max boost at stage 5: 1.60
            self._set_stage(hostname, new_stage, ttl=3600)
            return boost
        return 1.0
```

**How it maps event categories to stages**:

| Vector Category | Kill-Chain Stage |
|----------------|-----------------|
| `network-attack` (port scan) | RECONNAISSANCE |
| `auth` (failed → success) | INITIAL_ACCESS |
| Process spawn after auth | EXECUTION |
| `privilege-escalation`, cron | PERSISTENCE |
| Large `bytes_sent` outbound | EXFILTRATION |

**Integration point**: In `score_fusion.py` → `fuse_batch()`, after computing `adjusted` score:

```python
chain_boost = self._kill_chain.update(hostname, event.get("category", ""), adjusted)
adjusted = min(1.0, adjusted * chain_boost)
```

**State storage**: In-memory `Dict[str, (stage, expiry_time)]` with 1-hour TTL. At 100K unique hostnames: ~10 MB. Cleared automatically when TTL expires. No ClickHouse writes needed for this (it's purely a session-level acceleration, not a permanent record).

**Why this works**: A lone failed login (stage 1) gets its normal score. But if the same host later shows a successful login + process spawn + large upload, each subsequent event gets a progressively higher multiplier because the kill-chain is advancing. This makes the pipeline escalate multi-stage attacks that would individually score as `monitor`.

---

## Solution 11: IOC Boost is Heuristic, Not Model-Learned

**Gap**: `threat_intel_flag` is always 0 in training; IOC hits use crude +0.15 boost.

### Solution: Context-Aware IOC Scoring

Instead of a flat +0.15 boost, make the IOC boost **proportional to the behavioral score**:

```python
# CURRENT (flat boost):
if ioc_match:
    score_boost += 0.15

# NEW (context-aware):
if ioc_match:
    # Scale boost by behavioral suspicion:
    # High behavior score + IOC = very likely threat → large boost
    # Low behavior score + IOC = likely stale/cleaned IOC → small boost
    behavior_factor = float(combined[i])  # 0.0-1.0
    ioc_boost = 0.05 + (0.20 * behavior_factor)  # range: 0.05-0.25
    score_boost += ioc_boost
```

**Logic**: An IOC-matched IP doing normal traffic (combined=0.1) gets a modest +0.07 boost (stays in monitor). The same IP doing suspicious activity (combined=0.7) gets +0.19 boost (pushed toward escalation). This prevents stale IOC entries from flooding Hunter with false positives.

**Long-term**: When retraining (Solution 7), include `threat_intel_flag` as a real training feature by enriching 5-10% of training data with synthetic IOC matches (randomly flag known-malicious IPs in the training set as IOC hits). This lets the model learn the IOC-behavior interaction natively.

---

## Solution 12: No Encrypted Traffic Analysis

**Gap**: No JA3/JA3S, no certificate analysis, no TLS metadata features.

### Solution: TLS Metadata Features from Existing Log Enrichment

This requires **log sources that emit TLS metadata** (Zeek, Suricata, or a TLS-terminating proxy). If such sources exist, add features in Vector's mega_transform:

```yaml
# In Vector, for events with TLS metadata:
if exists(.ja3_hash) {
  .tls_ja3 = to_string!(.ja3_hash)
}
if exists(.certificate_issuer) {
  .cert_self_signed = if match(to_string!(.certificate_issuer), r'(?i)self.signed|let.s.encrypt') { 1 } else { 0 }
}
if exists(.tls_version) {
  .tls_downgrade = if to_string!(.tls_version) == "TLSv1.0" || to_string!(.tls_version) == "SSLv3" { 1 } else { 0 }
}
```

In `feature_extractor.py`, add 3 features:
| Feature | Value | Detects |
|---------|-------|---------|
| `tls_downgrade` | 1 if TLSv1.0/SSLv3 | Protocol downgrade attacks |
| `cert_self_signed` | 1 if self-signed/LE | C2 with quick certificates |
| `ja3_novelty` | 1 if JA3 hash not in top-100 common hashes | Unusual TLS clients (malware) |

**If no TLS log sources exist**: This gap cannot be solved at the application layer. It requires deploying **Zeek/Suricata on a network tap** or a **TLS-intercepting proxy** to generate the metadata. Add this to the infrastructure roadmap, not the application roadmap.

**Interim mitigation**: Use `bytes_ratio` and `duration_anomaly` from Solution 3 — these catch some encrypted attack patterns (beaconing, exfiltration) based on size/timing without inspecting content.

---

## Solution 13: Single Hostname Source — No Network Diversity

**Gap**: All data from hostname `LabSZ` / IP `172.18.0.1` — lab, not production.

### Solution: Multi-Source Ingestion Configuration

This is a deployment gap, not a code gap. Enable the commented-out Vector sources to ingest from real production systems:

**A. Enable additional Vector sources** in `vector.yaml`:

```yaml
# Uncomment and configure:
syslog_udp:
  type: syslog
  address: "0.0.0.0:1514"
  mode: udp  # Many network devices use UDP syslog

docker_logs:
  type: docker_logs
  docker_host: "unix:///var/run/docker.sock"  # Container runtime logs

file_logs:
  type: file
  include:
    - "/var/log/auth.log"
    - "/var/log/syslog"
    - "/var/log/audit/audit.log"
```

**B. Configure external log forwarding** — Point production systems' syslog to Vector:

```bash
# On each production server (rsyslog.conf):
*.* @@<VECTOR_HOST>:1514    # TCP syslog to Vector

# Windows Event Forwarding:
# Use Winlogbeat or NXLog → Vector's tcp_json:9514

# Network devices (firewalls, switches):
# Configure syslog destination → Vector:1514
```

**C. Validate per-source model performance** — After ingesting production logs, run:

```sql
-- Check per-hostname score distributions
SELECT hostname, count(*), avg(combined_score), countIf(action='escalate') AS esc
FROM triage_scores
GROUP BY hostname
ORDER BY esc DESC;
```

If any hostname shows extreme bias (all escalated or all discarded), add per-source thresholds to `source_thresholds`.

---

## Solution 14: ARF Pickle Bug Workaround

**Gap**: River ARF can't be pickled correctly → requires warm restart from ClickHouse on every container restart.

### Solution: Replace ARF with Online Gradient Boosted Trees

The ARF's value proposition (online learning, drift detection) can be achieved with a more robust library:

**Option A — River's `HoeffdingAdaptiveTreeClassifier`** (simplest):
```python
from river.tree import HoeffdingAdaptiveTreeClassifier
# Single tree, no ARF forest → simpler pickle, faster predict_proba_one()
# Still has ADWIN drift detection
model = HoeffdingAdaptiveTreeClassifier(
    grace_period=200,
    delta=0.002,
    leaf_prediction="adaptive",
)
```
Test if pickling this model produces consistent probabilities. If yes, eliminate the warm restart dependency entirely.

**Option B — Vowpal Wabbit** (production-grade):
```python
from vowpalwabbit import pyvw
# VW's online learning is battle-tested at massive scale
# Native binary serialization works correctly
# Can process 100K+ events/second
model = pyvw.Workspace("--loss_function logistic --adaptive --invariant")
```
VW's model can be saved/loaded reliably and is orders of magnitude faster than River's per-event processing.

**Option C — Remove online learning entirely** (simplest, least risk):
- Set `SCORE_WEIGHTS` to `lgbm=0.88,eif=0.12,arf=0.00`
- The ARF with 8% weight, shallow confidence ramp, and pseudo-labels contributes marginal value
- LightGBM periodic retraining (Solution 7) handles concept drift at a weekly cadence
- Eliminates the row-by-row Python loop bottleneck (Solution 5B)
- Eliminates the warm restart dependency (this gap)
- Eliminates the replay buffer writes (saves ClickHouse I/O)

**Recommended**: Option C in the short term (remove ARF, solve 3 gaps at once), Option B long term if real-time adaptation is needed.

---

## Solution 15: No UEBA — No Per-User/Entity Baselines

**Gap**: No per-user/host behavior profiles. Insider threats using normal credentials are invisible.

### Solution: Rolling Baseline Statistics in ClickHouse Materialized Views

Use ClickHouse's **AggregatingMergeTree** to maintain per-entity rolling baselines without any Python computation:

**A. Create materialized view for host baselines**:

```sql
CREATE MATERIALIZED VIEW host_baselines_mv
ENGINE = AggregatingMergeTree()
ORDER BY (hostname, hour_slot)
AS SELECT
    hostname,
    toStartOfHour(timestamp) AS hour_slot,
    avgState(combined_score) AS avg_score,
    stddevPopState(combined_score) AS std_score,
    countState() AS event_count,
    avgState(toFloat64(JSONExtractUInt(shap_top_features, 'count', 'value'))) AS avg_conn_count,
    uniqState(source_ip) AS unique_src_ips
FROM triage_scores
GROUP BY hostname, hour_slot;
```

**B. Add deviation-from-baseline features** in the Triage agent:

```python
# In feature_extractor.py or score_fusion.py:
# Periodically (every 5 min) fetch baselines from ClickHouse:
baselines = ch_client.execute("""
    SELECT hostname,
           avgMerge(avg_score) AS baseline_score,
           stddevPopMerge(std_score) AS baseline_std,
           avgMerge(avg_conn_count) AS baseline_conn_count
    FROM host_baselines_mv
    WHERE hour_slot >= now() - INTERVAL 7 DAY
    GROUP BY hostname
""")

# Per event, compute z-scores:
host_baseline = baselines.get(hostname, default_baseline)
score_deviation = (current_score - host_baseline.avg) / max(host_baseline.std, 0.01)
conn_deviation = (current_count - host_baseline.conn_count) / max(host_baseline.conn_std, 1.0)
```

**New features**:

| Feature | Description | Detects |
|---------|-------------|---------|
| `host_score_zscore` | Z-score of current event score vs host's 7-day baseline | Anomalous behavior from a normally-quiet host |
| `host_conn_zscore` | Z-score of connection count vs host's baseline | Sudden increase in network activity |
| `host_hour_novelty` | 1 if this host has never been active at this hour in 7 days | Unusual working hours (insider threat, compromised account) |

**Why materialized views**: ClickHouse computes them incrementally as new data arrives — zero additional CPU on the Triage agent. The feature extractor just reads pre-computed baselines every few minutes. No per-event ClickHouse queries.

---

## Implementation Priority Matrix

| Priority | Solution | Effort | Impact | Dependencies |
|----------|----------|--------|--------|-------------|
| **P0** | 5A: Defer SHAP async | 2 hours | +50% throughput | None |
| **P0** | 5D: Scale replicas + batch size | 30 min | +2-4x throughput | Docker config only |
| **P0** | 14/5B: Remove ARF (set weight=0) | 1 hour | +30% throughput, removes 3 gaps | Config change only |
| **P1** | 9: Fix severity leakage | 1 hour | Fixes false negatives | Vector + triage code |
| **P1** | 1: Add text features | 4 hours | Fixes log-only blind spot | Retrain model |
| **P1** | 6: Remove source_type_numeric | 2 hours | Fixes scoring bias | Retrain model |
| **P1** | 7: Feedback API | 8 hours | Enables model improvement | Dashboard + triage |
| **P2** | 2: Multi-scale EWMA | 6 hours | Catches slow attacks | Retrain model |
| **P2** | 10: Kill-chain tracker | 8 hours | Catches multi-stage attacks | Score fusion code |
| **P2** | 11: Context-aware IOC | 1 hour | Better IOC scoring | Score fusion code |
| **P2** | 4: Re-enable template rarity boost | 1 hour | Minor accuracy gain | Config change |
| **P3** | 15: UEBA baselines | 12 hours | Catches insider threats | CH materialized views |
| **P3** | 8: Replace EIF with autoencoder | 16 hours | Better anomaly detection | Retrain + new model |
| **P3** | 3: Protocol anomaly features | 4 hours | Detects DNS tunneling etc | Retrain model |
| **P3** | 12: TLS metadata features | 16+ hours | Encrypted traffic analysis | Infrastructure change |
| **P3** | 13: Multi-source ingestion | 4 hours | Production validation | Deployment config |

### Quick Wins (P0 — achievable in a single day, no retraining):
1. Remove ARF (config change) → solves Gaps 5B, 14
2. Defer SHAP async (small code change) → solves Gap 5A  
3. Increase batch size to 2000 + add 4 more triage replicas → solves Gap 5D

**Expected result**: Throughput jumps from ~2 EPS to ~50-100 EPS with just config and minor code changes.

### Medium-Term (P1-P2 — requires model retraining):
4. Add text features + remove source_type_numeric → solves Gaps 1, 6
5. Multi-scale EWMA → solves Gap 2
6. Kill-chain tracker → solves Gap 10
7. Feedback API → solves Gap 7

**Expected result**: Catches slow attacks, log-only attacks, multi-stage attacks, and models improve over time from analyst feedback.

### Long-Term (P3 — architecture changes):
8. Replace EIF with autoencoder → solves Gap 8
9. UEBA baselines → solves Gap 15
10. TLS metadata → solves Gap 12
11. Multi-source production deployment → solves Gap 13

---

## Architecture After All Solutions Applied

```
Raw logs (ANY format) ──► Vector (:1514 syslog, :9514 JSON, file, docker)
                              │
                    mega_transform + TLS metadata extraction
                              │
                    ┌─────────┼─────────┬─────────┐
                    ▼         ▼         ▼         ▼
              security   process   network     raw     ──► Redpanda (24 partitions)
                    │         │         │         │
                    └─────────┼─────────┘─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼                               ▼
    Go Consumer (storage)          Triage Agent ×8 (scoring)
    Redpanda → ClickHouse          │
                                   ├─ Text Features (entropy, ratios) ← Solution 1
                                   ├─ Multi-Scale EWMA (2s/60s/600s)  ← Solution 2
                                   ├─ Protocol Features (DNS entropy)  ← Solution 3
                                   ├─ Template Rarity (re-enabled)     ← Solution 4
                                   │
                                   ├─ LightGBM ONNX (88% weight)      ← Solutions 6,14
                                   ├─ Autoencoder ONNX (12% weight)   ← Solution 8
                                   │  (ARF removed)
                                   │
                                   ├─ Kill-Chain Tracker (per-host)    ← Solution 10
                                   ├─ Context-Aware IOC Boost          ← Solution 11
                                   ├─ UEBA Z-Scores (from CH MVs)     ← Solution 15
                                   ├─ Original-Only Severity           ← Solution 9
                                   │
                                   ├─ SHAP (async, non-blocking)       ← Solution 5A
                                   │
                                   └─► triage-scores / anomaly-alerts / hunter-tasks
                                                    │
                              ┌─────────────────────┘
                              ▼
                    Hunter Agent (deep investigation)
                              │
                    Verifier Agent (forensic validation)
                              │
                    Dashboard + Feedback API              ← Solution 7
                              │
                    Periodic LightGBM Retraining          ← Solution 7
```
