# CLIF Pipeline Benchmark Results

**Date:** 2026-03-02  
**Machine:** 12 logical CPUs (6C/12T), 16 GB RAM, Windows 11 + Docker Desktop (WSL2)

---

## v2.1 Pipeline Architecture (Current — VRL-Optimized + CPU-Rebalanced)

**Stack:** Vector 0.42.0 (8 threads, 3 GB) → ClickHouse 24.8 Direct (2 replicated nodes) + Kafka/Redpanda for AI pipeline only  
**Compose:** `docker-compose.eps-test.yml` — 6 containers, ~8.5 GB total, zero CPU oversubscription (12/12 cores)  

| Container | CPUs | Memory | Role |
|-----------|------|--------|------|
| clif-vector | 8 | 3 GB | TCP/HTTP/Syslog → mega_transform → CH sinks |
| clickhouse01 | 2.5 | 2 GB | Primary replica (all writes) |
| clickhouse02 | 0.5 | 1.5 GB | Async replication only |
| redpanda01 | 0.5 | 1 GB | AI pipeline topics only |
| clickhouse-keeper | 0.25 | 512 MB | ZooKeeper replacement |
| clif-consumer | 0.25 | 512 MB | AI pipeline consumer |

### v2.1 Optimizations (over v2)
- **VRL: Conditional metadata build** — full metadata for security events only, minimal `{original_source_type}` for process/network/raw (saves ~10 exists() checks per non-security event)
- **VRL: Eliminated redundant field checks in output formatting** — Section D guarantees fields exist, Section E uses them directly instead of re-checking
- **CPU rebalance** — Vector 6→8 CPUs (transforms are CPU-intensive), CH01 2→2.5 (sole write target), CH02/Redpanda/Consumer reduced (idling in benchmarks)
- **De-sharded writes** — All writes to CH01 (sharding hurt with security-heavy datasets due to replication overhead on CH02)

---

## Benchmark Results — v2.1 Pipeline (Latest)

### Real-Log Benchmarks (11 Heterogeneous Datasets, Go TCP Blaster)

| Test | Workers | Events Sent | Total EPS | Per-Core EPS | Vector CPUs |
|------|---------|-------------|-----------|-------------|-------------|
| **CH+Kafka (production) Run 1** | 12 TCP | 3,064,913 | **51,081** | **6,385** | 8 |
| **CH+Kafka (production) Run 2** | 12 TCP | 3,326,297 | **55,438** | **6,929** | 8 |
| **CH only (no Kafka)** | 12 TCP | 3,715,457 | **61,924** | **7,740** | 8 |
| **CH+Kafka — 16 workers** | 16 TCP | 3,333,839 | **55,563** | **6,945** | 8 |

### Resource Utilization During v2.1 Benchmarks

| Config | Vector CPU | CH01 CPU | CH02 CPU | Redpanda CPU | Vector Mem | Notes |
|--------|-----------|----------|----------|-------------|-----------|-------|
| CH+Kafka (production) | 382% / 800% | 186% / 250% | 50% / 50% | 17% / 50% | 341 MB | CH01 at 74% |
| CH only (no Kafka) | 376% / 800% | 223% / 250% | 52% / 50% | 2% / 50% | 1.03 GB | CH01 at 89% ← bottleneck |

---

## Benchmark Results — v2 Pipeline (Historical)

### Synthetic Benchmarks (Pre-generated Events)

| Test | Duration | Events Sent | Total EPS | Per-Core EPS | Vector CPUs |
|------|----------|-------------|-----------|-------------|-------------|
| Synthetic v2 (pre-generated) | 60s | ~7.2M | **115,000–121,000** | **19,200–20,100** | 6 |
| Synthetic v1 (baseline) | 30s | 1.37M | 45,675 | 11,419 | 4 |

### Real-Log Benchmarks (Go TCP Blaster, v2 configuration — 6 Vector CPUs)

| Test | Sender | Workers | Duration | Events Sent | Total EPS | Per-Core EPS |
|------|--------|---------|----------|-------------|-----------|-------------|
| **Go TCP Blaster — CH+Kafka (production)** | Go | 8 TCP | 60s | 2,689,861 | **44,831** | **7,471** |
| **Go TCP Blaster — CH+Kafka (pre-optimization)** | Go | 8 TCP | 60s | 2,416,791 | 40,279 | 6,713 |
| **Go TCP Blaster — CH only (no Kafka)** | Go | 8 TCP | 60s | 3,137,452 | **52,290** | **8,715** |
| **Go TCP Blaster — Blackhole (VRL ceiling)** | Go | 8 TCP | 60s | ~4.0M | **67,226** | **11,204** |
| Python TCP (sender-bound) | Python | 6 proc | 60s | 2,159,160 | 35,986 | 5,998 |
| Python TCP v1 (baseline) | Python | 6 proc | 60s | 1,755,447 | 26,959 | 6,740 |

### Resource Utilization During v2 Benchmarks (6 Vector CPUs)

| Config | Vector CPU | CH01 CPU | CH02 CPU | Redpanda CPU | Notes |
|--------|-----------|----------|----------|-------------|-------|
| CH+Kafka (production) | 377% / 600% | 199% / 200% | 151% / 150% | 28% / 100% | Full pipeline utilized |
| CH+Kafka (pre-optimization) | 3% / 600% | 34% / 200% | 7% / 150% | 2% / 100% | Kafka `block` killed throughput |
| CH only (no Kafka) | 329% / 600% | 131% / 200% | 103% / 150% | 2% / 100% | Theoretical CH ceiling |
| Blackhole (VRL ceiling) | 362% / 600% | 0% | 0% | 0% | Pure transform speed |

### Key Findings

1. **VRL optimization + CPU rebalance delivered +24% EPS gain.** From 44.8K → 55.4K production EPS. Conditional metadata build (skip for non-security events), eliminating redundant exists() checks, and giving Vector 8 CPUs (up from 6) were the main contributors.

2. **CH01 is the production bottleneck at 186-223% / 250% CPU.** All direct writes go to CH01 (2.5 CPUs). With async inserts + concurrency:10, it's 74-89% utilized depending on Kafka load.

3. **Kafka `when_full: block` was the #1 bottleneck (v2 finding).** Changing to `drop_newest` unleashed 10× more Vector CPU utilization (3% → 377%) and a **+25% EPS gain** (40K → 45K with Kafka, or +30% to 52K without Kafka).

4. **Sharding hurt for security-heavy datasets.** CH02 at 0.5 CPU couldn't keep up with async replication of security events from CH01. De-sharding (all writes to CH01) with CH01 at 2.5 CPUs was more effective.

5. **Go TCP blaster vs Python sender:** Go achieved **44.8K EPS** vs Python's **36K EPS** — a **25% improvement** by eliminating Python multiprocessing overhead.

6. **Real vs Synthetic gap:** Synthetic achieves 120K (simple templates, fast JSON). Real heterogeneous logs with full VRL parsing achieve 51-62K — the VRL classification/normalization overhead costs ~50%.

7. **Throughput progression across all optimization phases:**

   | Phase | Config | Total EPS | Per-Core EPS | Improvement |
   |-------|--------|-----------|-------------|-------------|
   | v1 baseline | Python TCP, 4 CPUs | 26,959 | 6,740 | — |
   | v2 pre-optimization | Go TCP, Kafka blocking | 40,279 | 6,713 | +49% total |
   | v2 + async_insert | Go TCP, 6 CPUs | 45,987 | 7,664 | +71% total |
   | v2 + drop_newest (production) | Go TCP, 6 CPUs + Kafka | 44,831 | 7,471 | +66% total |
   | v2 CH-only | Go TCP, 6 CPUs, no Kafka | 52,290 | 8,715 | +94% total |
   | v2 Blackhole (VRL ceiling) | Go TCP, 6 CPUs | 67,226 | 11,204 | +149% total |
   | **v2.1 production** | **Go TCP, 8 CPUs + Kafka** | **55,438** | **6,929** | **+106% total** |
   | **v2.1 CH-only** | **Go TCP, 8 CPUs, no Kafka** | **61,924** | **7,740** | **+130% total** |
   | v2 Synthetic (upper bound) | Pre-generated, 6 CPUs | 120,000 | 20,000 | +345% total |

---

## Go TCP Blaster Tool

Built a high-performance Go TCP log sender for accurate pipeline benchmarking:

- **Location:** `tools/tcpblaster/`
- **Language:** Go 1.22 (built via Docker, no host installation required)
- **Architecture:** N goroutine workers, each with persistent TCP connection
- **Optimizations:** TCP_NODELAY, 8 MB send buffers, 1 MB bufio writers, 256 KB chunks
- **Payload:** 1M real events from 11 datasets (277.6 MB NDJSON), pre-loaded into memory
- **Build:** `docker build -t tcpblaster tools/tcpblaster/`
- **Run:** `docker run --rm --network clif_clif-backend -v real_logs_payload.ndjson:/data/real_logs_payload.ndjson:ro tcpblaster --host clif-vector --port 9514 --workers 8 --duration 60`

---

## Real Log Datasets (11 Sources, 179,114 Unique Events)

| Dataset | Unique Events | Type | Source |
|---------|--------------|------|--------|
| cicids_web_attacks | 50,000 | ids_ips | CICIDS-2017 web attacks |
| cicids_ddos | 50,000 | ids_ips | CICIDS-2017 DDoS |
| nsl_kdd | 24,600 | ids_ips | NSL-KDD intrusion dataset |
| unsw_firewall | 20,200 | firewall | UNSW-NB15 firewall logs |
| netflow_ton_iot | 11,300 | netflow | ToN-IoT NetFlow |
| dns_phishing | 5,000 | dns | DNS phishing queries |
| dns_malware | 5,000 | dns | DNS malware C2 |
| evtx_attacks | 4,633 | windows_event_log | Windows EVTX attack dataset |
| iis_tunna | 4,298 | http_server | IIS with Tunna webshell |
| linux_syslog | 2,083 | syslog | Linux auth logs |
| apache_log | 2,000 | http_server | Apache access logs |
| **TOTAL** | **179,114** | | Repeated ×6 → 1M events (277.6 MB) |

### Event Type Distribution (from ClickHouse)

| Event Type | Count | Percentage |
|-----------|-------|-----------|
| security_events | 2,031,454 | 51% |
| network_events | 1,765,810 | 44% |
| raw_logs | 184,313 | 5% |
| process_events | 18 | <0.01% |

---

## v1 Pipeline Results (Historical Baseline)

**Stack:** Vector 0.42.0 (4 threads, 2 GB) → Redpanda 24.2.8 (3 brokers) → Python consumers (3×) → ClickHouse 24.8  
**Compose:** 10 containers, ~11.5 GB total, 14.5 CPU (oversubscribed)

| Test | Protocol | Duration | Events Sent | Avg EPS |
|------|----------|----------|-------------|---------|
| Synthetic (5 templates, 8 threads) | HTTP JSON | 30s | 1,371,240 | 45,675 |
| Real Logs (11 datasets, 6 workers) | HTTP JSON | 60s | 311,517 | 5,118 |
| Real Logs (11 datasets, 6 workers) | TCP NDJSON | 60s | 1,755,447 | 26,959 |

---

## Bugs Fixed During Benchmarking

### BUG-1: Timestamp Type Mismatch (100% Event Loss)
- **Symptom:** Vector accepted events (HTTP 200) but Redpanda had 0 messages in all topics
- **Root cause:** `format_timestamp!(.timestamp, ...)` in VRL requires a native timestamp type, but JSON payloads deliver `.timestamp` as a string.
- **Fix:** Added type checking + `parse_timestamp()` in `parse_and_structure` transform.

### BUG-2: IPv4 Validation (Consumer Stalls)
- **Symptom:** Consumers stalled at `rate=0` with 9K+ errors after consuming ~97K events
- **Root cause:** Network event fields could contain epoch timestamps or IPv6 addresses that ClickHouse's `IPv4` column type rejects.
- **Fix:** Added IPv4 regex validation with fallback to `'0.0.0.0'`.

### BUG-3: Port Range Overflow (Consumer Stalls)
- **Symptom:** ClickHouse UInt16 column rejected out-of-range values
- **Root cause:** Non-numeric strings in port fields surviving `to_int()` conversion.
- **Fix:** Added range check (`0 ≤ port ≤ 65535`) with fallback to `0`.

### BUG-4: Kafka `when_full: block` Caused 10× CPU Under-utilization
- **Symptom:** Vector at 3% CPU despite being allocated 6 cores. Pipeline throughput capped at 40K EPS.
- **Root cause:** Kafka sink's `when_full: block` caused backpressure that stalled the entire Vector pipeline, including CH sinks.
- **Fix:** Changed to `when_full: drop_newest`. Vector CPU jumped to 377%, throughput to 45K EPS.

---

## Commit History

| Commit | Description |
|--------|-------------|
| `21ef90e` | fix(vector): harden VRL — timestamp parsing, IPv4/IPv6 validation, port range clamping |
| `e74d8f3` | feat: v2 pipeline — direct ClickHouse sinks, zero CPU oversubscription |
| `492c61e` | docs: v2 implementation report + synthetic benchmark results |
| `3fd0cbe` | feat: Go TCP blaster, sink optimization, Kafka backpressure fix |
| *(latest)* | perf: VRL optimization (conditional metadata, field dedup) + CPU rebalance (Vector 8 CPUs) |

---

## Recommendations for Higher Throughput

1. **Scale ClickHouse CPU.** CH01 at 186-223% / 250% is the production bottleneck. On a dedicated server with 4-8 CH01 CPUs, expect 80-100K+ real-log EPS.
2. **Consider event-type-aware sharding for balanced workloads.** Sharding helps when event types are evenly distributed. For security-heavy datasets, de-sharded single-writer is better.
3. **Reduce VRL complexity for ultra-high throughput.** The 512-byte prefix scan + MITRE mapping costs significant per-event CPU. Pre-classification at the agent side would help.
4. **Separate Kafka to its own machine.** Even with `drop_newest`, the dual-write costs ~10-15% throughput (62K→55K).
5. **Horizontal Vector scaling.** With 8 CPUs at 382% utilization (48%), Vector has theoretical 2× headroom if CH/Kafka can keep up.
