 # CLIF AI Agents — Complete Reimplementation Plan

> Date: March 14, 2026  
> Scope: End-to-end from raw log collection → processing → training → inference → detection  
> Goals: (1) Process the top-10 enterprise log types, (2) Detect known + anomaly attacks, (3) High throughput (1,000+ EPS)

---

## Table of Contents

1. [What's Wrong with the Current System](#1-whats-wrong-with-the-current-system)
2. [The Top 10 Enterprise Log Types](#2-the-top-10-enterprise-log-types)
3. [Phase 1 — Unified Log Normalization (Vector)](#3-phase-1--unified-log-normalization-vector)
4. [Phase 2 — Feature Engineering (New 32-Feature Vector)](#4-phase-2--feature-engineering-new-32-feature-vector)
5. [Phase 3 — Training Data Strategy](#5-phase-3--training-data-strategy)
6. [Phase 4 — Model Architecture (New 2-Model Ensemble)](#6-phase-4--model-architecture-new-2-model-ensemble)
7. [Phase 5 — Score Fusion & Correlation Engine](#7-phase-5--score-fusion--correlation-engine)
8. [Phase 6 — Triage Agent Reimplementation](#8-phase-6--triage-agent-reimplementation)
9. [Phase 7 — Hunter Agent Improvements](#9-phase-7--hunter-agent-improvements)
10. [Phase 8 — Feedback Loop & Continuous Learning](#10-phase-8--feedback-loop--continuous-learning)
11. [Phase 9 — Performance Architecture](#11-phase-9--performance-architecture)
12. [Full Pipeline Diagram](#12-full-pipeline-diagram)
13. [Implementation Roadmap](#13-implementation-roadmap)

---

## 1. What's Wrong with the Current System

### Fundamental Design Problems

| # | Problem | Root Cause | Impact |
|---|---------|------------|--------|
| 1 | **Log-only events are invisible** | 8 of 19 features are zero for non-network events. Log events (syslog, Windows, K8s) have only 3 discriminative features: `severity`, `hour`, `day_of_week` | Insider threats, privilege escalation, account abuse via syslog/Windows Event Logs are undetectable |
| 2 | **Model is network-centric** | 12 of 19 features (63%) come from network flow metadata (bytes, ports, KDD). Training data is 70% network datasets (CICIDS, NSL-KDD, UNSW-NB15) | The model learned "port scan + high connection count = attack" but cannot recognize "suspicious Windows EventID sequence = attack" |
| 3 | **Training data doesn't match production** | Training uses CICIDS2017 flows, NSL-KDD 1999 features, synthetic severity values. Production receives raw syslog text and JSON socket events | 534K real events showed 27× scoring bias between socket (1.2% escalation) and syslog (32% escalation) sources |
| 4 | **Too slow for production** | Python single-threaded consumer, synchronous SHAP (21 ONNX calls per escalated event), row-by-row ARF, Drain3 with threading.Lock | ~1.3–2.2 EPS. Enterprise requires 1,000–10,000 EPS minimum |
| 5 | **No temporal correlation** | Each event scored independently. No tracking of attack progression across time or hosts | Multi-stage attacks (recon → access → lateral → exfil) spanning hours are invisible |
| 6 | **4 unused dataset directories** | `04_active_directory_ldap/`, `05_dns_logs/`, `06_aws_cloudtrail/`, `07_kubernetes_audit/` contain zero training data (only Git repos of tools cloned) | The pipeline claims 10-source-type coverage but only has real training data for 6 |
| 7 | **EIF is nearly useless** | Score discrimination: normal=0.43 vs monitored=0.46 (only Δ0.03). Required `score_flip=true`. Only 12% weight | Essentially adds noise — a random number between 0.40–0.50 for most events |
| 8 | **ARF contributes ≈0** | Pickle bug → constant probabilities → warm restart from CH → cold start gives 0.50 everywhere. 8% weight × 0.50 = always +0.04 | Removing ARF changes scores by <0.04. Three layers of complexity for zero value |

### What Actually Works Well

- **Vector's VRL mega_transform**: Robust multi-format parser. Handles syslog, JSON, CEF. Fast (Rust native)
- **Go Consumer (consumer-go)**: Highly optimized ClickHouse writer. 500K event batches, goroutine pool. NOT a bottleneck
- **Hunter's investigation architecture**: 42-feature vector, parallel L1/L2 investigation, CatBoost scoring, narrative builder. Conceptually sound
- **Verifier's evidence chain**: Merkle anchoring, IOC correlation, FP analysis, timeline reconstruction. Unique forensic capability
- **LanceDB similarity search**: 384-dim embeddings for attack pattern matching. Useful for Hunter's similarity analysis
- **ClickHouse schema**: Well-designed tiered storage with TTLs, materialized views, entity baselines. Production-ready

### Design Principle for the New System

> **Every feature the AI model uses must be computable from ANY log format** —  
> whether it's a raw syslog line, a Windows Event XML, a Kubernetes audit JSON, or a CEF firewall entry.  
> No feature should require "network flow" metadata that only exists in PCAP/NetFlow data.

---

## 2. The Top 10 Enterprise Log Types

These are the log sources every enterprise SOC processes, ordered by volume and security value:

| # | Log Type | Format | Volume | Security Value | Example Sources |
|---|----------|--------|--------|----------------|-----------------|
| 1 | **Syslog (Linux/Unix)** | RFC 3164/5424 text | Very High | Auth, process, service events | auth.log, syslog, daemon.log, cron.log |
| 2 | **Windows Event Logs** | XML/EVTX | Very High | Logon, policy, process, PowerShell | Security.evtx (4624/4625/4688/4697/4720) |
| 3 | **Firewall/UTM** | CEF, LEEF, syslog | High | Allow/deny decisions, connection tracking | Palo Alto, Fortinet, pfSense, iptables |
| 4 | **Active Directory/LDAP** | Windows Event + syslog | High | Auth, group changes, privilege abuse | DC Security logs (4768/4769/4771/4776) |
| 5 | **DNS** | Query logs, passive DNS | High | Tunneling, DGA, C2 beaconing | BIND query log, Windows DNS, Zeek dns.log |
| 6 | **Cloud Audit (AWS/Azure/GCP)** | JSON (CloudTrail/Activity/Audit) | High | IAM changes, resource access, data exfil | CloudTrail, Azure Activity Log, GCP Audit |
| 7 | **Kubernetes Audit** | JSON | Medium | RBAC abuse, container escape, secrets access | kube-apiserver audit log |
| 8 | **Web Server/WAF** | Combined/JSON access log | Medium-High | SQLi, XSS, path traversal, credential stuffing | nginx, Apache, IIS, Cloudflare, ModSecurity |
| 9 | **Network Flow (NetFlow/IPFIX)** | Binary → JSON | Medium | Lateral movement, exfil, C2 by volume | NetFlow v5/v9, IPFIX, sFlow |
| 10 | **IDS/IPS (Zeek/Suricata)** | JSON/EVE | Medium | Signature matches, protocol anomalies | Zeek conn.log, Suricata eve.json |

### Current Coverage Assessment

| Log Type | Training Data? | Real Data? | Feature Coverage | Verdict |
|----------|---------------|------------|-----------------|---------|
| 1. Syslog | ✅ 2K Loghub Linux + 2K OpenSSH (tiny) | ✅ 534K events | ❌ Only 3/19 features work | **Broken** |
| 2. Windows Events | ✅ 4.6K EVTX (attacks only, synth normals) | ❌ None | ❌ Only 3/19 features work | **Broken** |
| 3. Firewall | ✅ 20K UNSW-NB15 (network flows, not CEF) | ❌ None | ⚠️ Network features work, log features don't | **Partial** |
| 4. Active Directory | ❌ Empty directory, zero training data | ❌ None | ❌ Not represented at all | **Missing** |
| 5. DNS | ✅ 20K CIC-Bell (DNS exfil pcap stats) | ❌ None | ❌ KDD features forced to zero | **Broken** |
| 6. Cloud Audit | ❌ Empty directory, zero training data | ❌ None | ❌ Not represented at all | **Missing** |
| 7. Kubernetes | ❌ Empty directory, zero training data | ❌ None | ❌ Not represented at all | **Missing** |
| 8. Web Server | ✅ 20K CSIC 2010 + 2K Apache Loghub | ❌ None | ⚠️ HTTP-specific features (URL length) not captured | **Partial** |
| 9. NetFlow | ✅ 12K NF-UNSW + 11K NF-ToN-IoT | ❌ None | ✅ Network features work | **OK** |
| 10. IDS/IPS | ✅ 30K CICIDS + 24K NSL-KDD | ❌ None | ✅ Network features work | **OK** |

**Only 2 of 10 log types have adequate coverage. 3 have zero training data. 5 have broken features.**

---

## 3. Phase 1 — Unified Log Normalization (Vector)

### Current State
Vector's `mega_transform` already handles syslog and JSON socket input. It extracts `original_log_level`, `source_ip`, `dst_ip`, ports, protocols, and classifies via regex.

### What to Change

**Add structured field extraction for enterprise-specific log types** in the VRL mega_transform:

#### 3A. Windows Event Log Fields
```yaml
# After JSON parsing, detect Windows Event structure:
if exists(.EventID) || exists(.event_id) || exists(.System.EventID) {
  .clif_log_type = "windows_event"
  .windows_event_id = to_int!(.EventID ?? .event_id ?? .System.EventID."#text" ?? 0)
  .windows_channel = to_string!(.Channel ?? .System.Channel ?? "")
  .windows_logon_type = to_int!(.LogonType ?? .EventData.LogonType ?? 0)
  .windows_task_category = to_string!(.TaskCategory ?? .System.Task ?? "")
  .windows_keywords = to_string!(.Keywords ?? "")
  .windows_target_user = to_string!(.TargetUserName ?? .EventData.TargetUserName ?? "")
  .windows_source_user = to_string!(.SubjectUserName ?? .EventData.SubjectUserName ?? "")
  .windows_process_name = to_string!(.NewProcessName ?? .EventData.NewProcessName ?? "")
  .windows_parent_process = to_string!(.ParentProcessName ?? .EventData.ParentProcessName ?? "")
  .windows_command_line = to_string!(.CommandLine ?? .EventData.CommandLine ?? "")
}
```

#### 3B. Cloud Audit Fields
```yaml
# AWS CloudTrail / Azure Activity Log detection:
if exists(.eventSource) && exists(.eventName) && exists(.awsRegion) {
  .clif_log_type = "cloudtrail"
  .cloud_action = to_string!(.eventName)
  .cloud_service = to_string!(.eventSource)
  .cloud_user = to_string!(.userIdentity.userName ?? .userIdentity.arn ?? "")
  .cloud_region = to_string!(.awsRegion)
  .cloud_error = to_string!(.errorCode ?? "")
  .cloud_source_ip = to_string!(.sourceIPAddress ?? "")
  .cloud_readonly = to_bool!(.readOnly ?? true)
}
```

#### 3C. Kubernetes Audit Fields
```yaml
# K8s audit log detection:
if exists(.apiVersion) && exists(.kind) && .kind == "Event" {
  .clif_log_type = "k8s_audit"
  .k8s_verb = to_string!(.verb ?? "")
  .k8s_resource = to_string!(.objectRef.resource ?? "")
  .k8s_namespace = to_string!(.objectRef.namespace ?? "")
  .k8s_user = to_string!(.user.username ?? "")
  .k8s_groups = to_string!(.user.groups ?? "")
  .k8s_response_code = to_int!(.responseStatus.code ?? 0)
  .k8s_is_admin = contains(to_string!(.user.groups ?? ""), "system:masters")
}
```

#### 3D. DNS Query Fields
```yaml
# DNS log detection (Zeek dns.log, BIND query log, Windows DNS):
if exists(.query) && exists(.qtype) || exists(.dns_query) {
  .clif_log_type = "dns"
  .dns_query_name = to_string!(.query ?? .dns_query ?? "")
  .dns_query_type = to_string!(.qtype ?? .query_type ?? "A")
  .dns_response_code = to_string!(.rcode ?? .response_code ?? "")
  .dns_answer_count = to_int!(.answers ?? length!(.answers ?? []))
}
```

#### 3E. Output: Unified Normalized Event

After all extraction, every event has this guaranteed structure:

```json
{
  "event_id": "uuid5(...)",
  "timestamp": "2026-03-14T...",
  "hostname": "...",
  "source_ip": "...",
  "source_type": "syslog|windows|firewall|dns|cloud|k8s|webapp|netflow|ids",
  "clif_log_type": "syslog|windows_event|cloudtrail|k8s_audit|dns|cef|...",
  "original_log_level": "info|warning|error|critical",
  "severity": "...",
  "message_body": "...",
  
  // — Network fields (null for log-only events) —
  "dst_ip": null, "src_port": null, "dst_port": null,
  "protocol": null, "bytes_sent": null, "bytes_received": null,
  
  // — Log-type-specific fields (null for non-matching types) —
  "windows_event_id": null, "windows_logon_type": null,
  "cloud_action": null, "cloud_service": null,
  "k8s_verb": null, "k8s_resource": null,
  "dns_query_name": null, "dns_query_type": null,
  
  // — Original raw message —
  "raw_log": "..."
}
```

**Key principle**: Every field is nullable. The feature extractor handles null → 0.0 or null → default for each feature independently. No feature assumes the presence of another field.

---

## 4. Phase 2 — Feature Engineering (New 32-Feature Vector)

### Design Philosophy

The current 19-feature vector has 16 features that require network flow data. The new design splits features into 4 tracks:

| Track | Features | Works For | Current Coverage |
|-------|----------|-----------|-----------------|
| **Universal** (works for ALL logs) | 12 | All 10 log types | NEW |
| **Network** (needs flow data) | 8 | NetFlow, IDS, Firewall | Existing (refined) |
| **Text** (needs message body) | 6 | Syslog, Windows, K8s, Cloud, Web | NEW |
| **Behavioral** (needs temporal context) | 6 | All 10 log types | NEW |

### The 32 Features

#### Track A — Universal Features (12) — Every log event has these

| # | Feature | Computation | Why |
|---|---------|-------------|-----|
| 0 | `hour_of_day` | `timestamp.hour` (0–23) | Off-hours activity indicates compromise |
| 1 | `day_of_week` | `timestamp.weekday()` (0–6) | Weekend anomalies |
| 2 | `is_off_hours` | 1 if hour ∈ {0..5, 22, 23} or weekend | Binary off-hours flag (stronger signal than raw hour) |
| 3 | `severity_numeric` | Map from `original_log_level` ONLY: debug=0, info=1, warning=2, error=3, critical=4 | Source-system severity (NOT Vector classification) |
| 4 | `event_id_risk_score` | Lookup table: Windows EventID → risk score (4625=0.7, 4688=0.3, 4720=0.9, ...), CEF severity → score, syslog keyword → score | Pre-computed risk score based on event type identifier |
| 5 | `action_type` | Categorical: 0=info, 1=auth_attempt, 2=auth_success, 3=auth_fail, 4=process_create, 5=process_terminate, 6=network_connect, 7=network_deny, 8=policy_change, 9=privilege_use, 10=data_access, 11=config_change | Normalized action across ALL log types |
| 6 | `is_admin_action` | 1 if: Windows LogonType=10 (RemoteInteractive), K8s groups contain "system:masters", Cloud action modifies IAM, syslog "sudo" or "root" | Cross-source admin indicator |
| 7 | `has_known_ioc` | IOC cache lookup (existing, from `ioc_cache` table) | Threat intelligence flag |
| 8 | `entity_event_rate` | EWMA of events per minute for this (hostname, user) pair, 60s half-life | Sudden burst = suspicious |
| 9 | `entity_error_rate` | EWMA of error/warning events for this entity, 300s half-life | Error spike = attack or misconfiguration |
| 10 | `entity_unique_actions` | Count of distinct `action_type` values from this entity in last 300s | Diverse actions = lateral movement or automated attack |
| 11 | `source_novelty` | 1 if (hostname, source_type) pair not seen in last 24h baseline | New source appearing = possible rogue device |

#### Track B — Network Features (8) — Only for events with network flow data

| # | Feature | Computation | Current Equivalent |
|---|---------|-------------|-------------------|
| 12 | `dst_port` | Destination port (0 for non-network) | Same |
| 13 | `protocol_numeric` | TCP=6, UDP=17, ICMP=1, other=0 | Same |
| 14 | `byte_ratio` | `src_bytes / max(src_bytes + dst_bytes, 1)` | NEW — detects exfiltration asymmetry |
| 15 | `total_bytes_log` | `log10(1 + src_bytes + dst_bytes)` | Replaces raw bytes (log scale for better discrimination) |
| 16 | `conn_rate_fast` | EWMA connection rate at 2s half-life (replaces fixed window `count`) | Improved |
| 17 | `conn_rate_slow` | EWMA connection rate at 600s half-life | NEW — catches slow scans |
| 18 | `rate_acceleration` | `conn_rate_fast / max(conn_rate_slow, 0.01)` | NEW — spike detection |
| 19 | `port_entropy` | Shannon entropy of destination ports from this src_ip in last 100 connections | NEW — port scans have high entropy |

#### Track C — Text Features (6) — For events with a message body

| # | Feature | Computation | Why |
|---|---------|-------------|-----|
| 20 | `message_entropy` | Shannon entropy of message bytes: $H = -\sum p_i \log_2 p_i$ | Obfuscated/encoded payloads have high entropy |
| 21 | `message_length_log` | `log10(1 + len(message))` | Unusually long/short messages can indicate attacks |
| 22 | `numeric_ratio` | Count of digit chars / message length | IPs, hex values, error codes increase this |
| 23 | `special_char_ratio` | Count of non-alphanumeric, non-space / message length | Injection attacks, encoded payloads |
| 24 | `keyword_threat_score` | Log-linear count of security keywords: `fail|denied|error|attack|exploit|malicious|unauthorized|violation|brute|inject|overflow|escalat` | Direct textual threat signal |
| 25 | `template_novelty` | `1.0 - log(1 + cluster_size) / log(1 + total_events)` from Drain3 | Rare log patterns may indicate novel attacks |

#### Track D — Behavioral/Contextual Features (6) — Computed from temporal state

| # | Feature | Computation | Why |
|---|---------|-------------|-----|
| 26 | `host_score_baseline_z` | Z-score of this event's score vs host's 7-day baseline (from ClickHouse MV) | Behavioral anomaly relative to host's normal |
| 27 | `user_score_baseline_z` | Z-score of this event vs user's 7-day baseline | Compromised account detection |
| 28 | `kill_chain_stage` | Current attack stage for this host: 0=none, 1=recon, 2=access, 3=execution, 4=persistence, 5=exfil | Multi-stage attack tracking |
| 29 | `kill_chain_velocity` | Time between stage transitions (0 if no progression) | Rapid progression = automated attack |
| 30 | `cross_host_correlation` | Count of other hosts showing similar anomalies in last 15 min | Campaign/worm detection |
| 31 | `dns_query_entropy` | Shannon entropy of DNS query string (0 if not DNS) | DNS tunneling/DGA detection |

### Feature Availability Matrix

| Feature Track | Syslog | Windows | Firewall | AD | DNS | Cloud | K8s | Web | NetFlow | IDS |
|---------------|--------|---------|----------|----|-----|-------|-----|-----|---------|-----|
| **Universal (0-11)** | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 | ✅ 12/12 |
| **Network (12-19)** | ❌ 0/8 | ❌ 0/8 | ✅ 8/8 | ❌ 0/8 | ⚠️ 2/8 | ❌ 0/8 | ❌ 0/8 | ⚠️ 2/8 | ✅ 8/8 | ✅ 8/8 |
| **Text (20-25)** | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ❌ 0/6 | ✅ 6/6 |
| **Behavioral (26-31)** | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 | ✅ 6/6 |
| **Total usable** | **24/32** | **24/32** | **32/32** | **24/32** | **26/32** | **24/32** | **24/32** | **26/32** | **26/32** | **32/32** |

**Current system**: Syslog gets 3/19 useful features. New system: 24/32. That's an **8× improvement in feature coverage for log-only sources**.

---

## 5. Phase 3 — Training Data Strategy

### Problem Statement

The current training pipeline has:
- **175K samples** from 12 datasets
- **70% network-dominated** (CICIDS, NSL-KDD, UNSW, NetFlow = ~118K of 175K)
- **Tiny log samples** (2K Linux syslog, 2K Apache, 2K OpenSSH, 4.6K EVTX = only 10.6K)
- **Zero training data** for: Active Directory, Cloud Audit, Kubernetes
- **Synthetic KDD features** that partially approximate but don't match production behavior
- **Random severity values** (`rng.normal(1.0, 0.5)`) — no semantic relationship to actual attack patterns

### New Training Data Design: 2-Layer Approach

#### Layer 1 — Public Security Datasets (Supervised, Known Attacks)

**For each of the 10 log types**, source real-world labeled datasets:

| # | Log Type | Dataset | Samples | Attack Types | Source |
|---|----------|---------|---------|-------------|--------|
| 1 | **Syslog** | Loghub Linux + OpenSSH (existing) + **LANL auth.txt.gz** (30M+ auth events, 749 compromised users) | 30K stratified | Failed auth, brute force, lateral movement, privilege escalation | [LANL Comprehensive Dataset](https://csr.lanl.gov/data/cyber1/) |
| 2 | **Windows** | EVTX-ATTACK-SAMPLES (existing) + **EVTX-ATTACK-SAMPLES-v2** + **Mordor datasets** (MITRE ATT&CK evaluations recorded as EVTX) | 20K | Mimikatz, PowerShell empire, lateral movement, persistence | [OTRF Security Datasets](https://securitydatasets.com/) |
| 3 | **Firewall** | UNSW-NB15 (existing) + **generate synthetic CEF** from UNSW flows | 20K | Port scans, DoS, exploits, fuzzing, backdoors, shellcode | UNSW-NB15 with CEF wrapper |
| 4 | **Active Directory** | **LANL auth dataset** (AD auth events) + **Mordor AD attacks** (DCSync, Kerberoasting, Golden Ticket) | 15K | Kerberoasting (T1558), DCSync (T1003.006), Pass-the-Hash, Golden Ticket | LANL + OTRF |
| 5 | **DNS** | CIC-Bell-DNS-EXFil (existing) + **DGTA benchmark** (DGA domain dataset) + **DNS tunneling captures** | 20K | DNS tunneling/exfil, DGA, DNS rebinding, cache poisoning | CIC-Bell + DGArchive |
| 6 | **Cloud Audit** | **Stratus Red Team** (AWS attack simulation → CloudTrail JSON) + **CloudGoat** attack scenarios | 15K | IAM privilege escalation, S3 exfil, Lambda backdoor, EC2 SSRF | [Stratus Red Team](https://stratus-red-team.cloud/) |
| 7 | **Kubernetes** | **Falco generated events** + **MITRE ATT&CK for Containers** attack simulations + **Kubernetes Goat** | 10K | Container escape, RBAC abuse, secrets theft, cryptomining, reverse shell | Falco + K8s Goat |
| 8 | **Web Server** | CSIC 2010 (existing) + **ModSecurity audit log** + **OWASP WebGoat** traffic captures | 20K | SQLi, XSS, path traversal, command injection, SSRF, credential stuffing | CSIC + ModSecurity |
| 9 | **NetFlow** | NF-UNSW + NF-ToN-IoT (existing) | 20K | Network scans, DDoS, botnets, C2 beaconing | Existing |
| 10 | **IDS/IPS** | CICIDS2017 + NSL-KDD (existing) + **CIC-IDS2018** (updated, more attack types) | 30K | All CICIDS attack types + infiltration, web attacks, botnet | Existing + CIC-IDS2018 |

**Total Layer 1: ~200K labeled samples, balanced across all 10 log types** (20K each)

#### Layer 2 — Synthetic Normal Baseline + Anomaly Injection

For each log type, generate a **"normal day" synthetic dataset** that represents typical enterprise activity:

| Log Type | Normal Simulation | Anomaly Injection |
|----------|-------------------|-------------------|
| Syslog | 10K events: cron jobs, service starts, normal logins, log rotation, NTP sync | Inject 2K: 500 brute force sequences, 500 privilege escalation chains, 500 unusual process spawns, 500 after-hours root access |
| Windows | 10K events: workstation logon/logoff (4624/4634), scheduled tasks, Windows Update, LSASS normal | Inject 2K: 500 failed+success logon sequences, 500 new service installations, 500 PowerShell encoded commands, 500 credential dumping |
| Firewall | 10K events: allow HTTP/HTTPS outbound, deny inbound scans (normal FW noise), VPN connections | Inject 2K: 500 port scan sequences, 500 unusual outbound ports, 500 data exfil (high bytes out), 500 C2 beaconing patterns |
| AD | 10K events: normal Kerberos TGT/TGS (4768/4769), LDAP binds, password changes | Inject 2K: 500 Kerberoasting (many TGS for SPNs), 500 pass-the-hash, 500 DC replication (DCSync), 500 account lockout storms |
| DNS | 10K events: normal A/AAAA queries, CNAME, MX records for known domains | Inject 2K: 500 DGA domains (high entropy), 500 DNS tunneling (long subdomains), 500 fast-flux, 500 NXDOMAIN storms |
| Cloud | 10K events: console logins, S3 reads, EC2 describe calls, CloudWatch metrics | Inject 2K: 500 IAM policy changes, 500 S3 bucket public access, 500 unusual region access, 500 API key creation |
| K8s | 10K events: pod list/get, deployment scale, configmap reads, health checks | Inject 2K: 500 exec into pod, 500 secrets access, 500 privileged container, 500 namespace-wide list (recon) |
| Web | 10K events: normal HTTP 200/301/304 responses, static assets, API calls | Inject 2K: 500 SQLi patterns in URLs, 500 XSS payloads, 500 path traversal (../), 500 credential stuffing (many POST /login) |
| NetFlow | Covered by Layer 1 datasets | — |
| IDS | Covered by Layer 1 datasets | — |

**Total Layer 2: 80K normal + 16K injected anomalies = 96K**

#### Combined Training Corpus: ~296K samples

| Source | Samples | Purpose |
|--------|---------|---------|
| Layer 1: Public labeled datasets | ~200K | Known attack detection (supervised) |
| Layer 2: Synthetic normal baselines | ~80K | Normal behavior modeling (for anomaly detection) |
| Layer 2: Injected anomalies | ~16K | Anomaly pattern recognition |
| **Total** | **~296K** | **Balanced known + anomaly detection** |

#### Balance Guarantees

- **Per-log-type**: Each log type contributes 20K–30K samples (no single type dominates)
- **Normal/attack ratio**: ~50/50 overall, but each log type individually balanced
- **Attack diversity**: Minimum 4 distinct attack categories per log type
- **Temporal diversity**: Events spread across all 24 hours and 7 days (not clustered in business hours)

### Feature Engineering for Training (Critical Fix)

The current system computes features differently during training vs production. This causes **train/serve skew**. The new plan:

**Principle**: Use the EXACT SAME `feature_extractor.py` code for training AND production.

```python
# NEW training pipeline:
def build_training_dataset():
    for dataset in ALL_DATASETS:
        raw_events = load_dataset_as_normalized_events(dataset)
        # ↑ Convert each dataset row into the EXACT same JSON format 
        #   that Vector produces in production
        
        for event in raw_events:
            features = feature_extractor.extract(event)
            # ↑ SAME function used in production triage agent
            #   No simulation, no approximation, no synthetic values
            training_rows.append((features, label))
```

This means:
- **No more `_sim_conn_tracker()`** — train on the ACTUAL ConnectionTracker/EWMA output
- **No more `rng.normal(1.0, 0.5)` for severity** — use the ACTUAL severity from the log
- **No more random hour/day** — use ACTUAL timestamps from the dataset
- **No more `event_freq_1m = 60/duration`** — use the ACTUAL EWMA rate from the entity tracker

The training script will:
1. Feed each dataset event through Vector's VRL transform (or a Python equivalent) to normalize it
2. Feed normalized events through `feature_extractor.extract()` in chronological order (so EWMA/ConnectionTracker state builds naturally)
3. Collect the 32-feature vector + label
4. Output: `features_combined_v7.csv`

---

## 6. Phase 4 — Model Architecture (New 2-Model Ensemble)

### Why 2 Models Instead of 3

| Current | New | Reason |
|---------|-----|--------|
| LightGBM (0.80) | **LightGBM (0.85)** | Primary, proven, fast |
| EIF (0.12) | **Autoencoder (0.15)** | Better anomaly discrimination |
| ARF (0.08) | **Removed** | Near-zero contribution, pickle bugs, throughput bottleneck |

Removing ARF eliminates:
- Row-by-row Python loop (throughput bottleneck)
- Pickle serialization bug
- ClickHouse warm-restart dependency
- Replay buffer writes
- The `confidence_ramp` complexity

### Model 1 — LightGBM v7 (Supervised, Known Attack Detection)

**Role**: Detect known attack patterns across all 10 log types.

```python
params = {
    "objective": "binary",
    "metric": "binary_logloss",
    "boosting_type": "gbdt",
    "num_leaves": 63,           # Up from 31 — more capacity for 32 features
    "max_depth": 8,             # Up from 6 — deeper trees for complex interactions
    "learning_rate": 0.03,      # Slightly lower — more trees, better generalization  
    "min_child_samples": 30,    # Down from 50 — don't over-regularize
    "colsample_bytree": 0.8,    # Up from 0.7 — 32 features, can use more
    "subsample": 0.8,           # Up from 0.7
    "reg_alpha": 0.3,           # Down from 0.5 — less L1
    "reg_lambda": 3.0,          # Down from 5.0 — less L2
    "min_gain_to_split": 0.05,  # Down from 0.1
    "scale_pos_weight": "auto", # Auto-balance
    "n_estimators": 2000,       # Up from 1000 — more trees for more features
    "early_stopping_rounds": 100,
    "categorical_feature": [5],  # action_type is categorical
    "seed": 42,
}
```

**Validation**: 5-fold stratified cross-validation (NOT single 80/20 split). Report mean ± std for each metric.

**Quality gates**:
- Per-log-type F1 must exceed **0.80** (not just aggregate)
- Overall F1 must exceed **0.90**
- False positive rate must be below **5%** per log type

**Export**: ONNX with opset 17 for batch inference.

### Model 2 — Autoencoder (Unsupervised, Novel Anomaly Detection)

**Role**: Detect events that look "unusual" compared to learned normal patterns — catches zero-day attacks, novel TTPs, and insider threats.

**Architecture**:

```
Input (32 features) → Dense(64, ReLU) → Dense(32, ReLU) → Dense(16, ReLU)
                       → Dense(8, ReLU)  ← Bottleneck (latent space)
                       → Dense(16, ReLU) → Dense(32, ReLU) → Dense(64, ReLU)
                       → Dense(32, Sigmoid)  ← Reconstruction
```

- **Parameters**: ~10K (tiny — fast inference)
- **Training**: On normal-only data (all Layer 2 normal baselines = ~80K events)
- **Loss**: MSE reconstruction error
- **Anomaly score**: `reconstruction_error / p99_training_error`
  - Score 1.0 = as anomalous as the worst 1% of training data
  - Score >1.0 = more anomalous than anything seen in training
  - Clip to [0.0, 1.0] via `min(score, 1.0)` for fusion

**Why autoencoder over EIF**:
1. **Better score spread**: EIF gave Δ0.03 between normal and suspicious. Autoencoders typically give Δ0.3+ because reconstruction error is proportional to how "weird" the input is
2. **Learns the data manifold**: EIF uses random hyperplane splits. The autoencoder learns the actual structure of "normal" through the bottleneck compression
3. **Handles heterogeneous features**: The 32-feature vector has different scales and semantics per track. The autoencoder's hidden layers learn useful transformations automatically
4. **ONNX compatible**: Export to ONNX for batch inference at ~1μs/event

**Training procedure**:
1. Collect all normal-labeled events across all 10 log types
2. Standardize features (z-score normalization, save mean/std for production)
3. Train autoencoder for 100 epochs with early stopping (patience=10) on 80/20 split
4. Compute reconstruction error on training set → store 99th percentile as threshold
5. Export encoder+decoder to ONNX

**Per-log-type calibration**: Each log type may have different "normal" reconstruction error distributions. Store per-source-type normalizing constants:

```python
calibration = {
    "syslog": {"p99_error": 0.032, "p50_error": 0.008},
    "windows": {"p99_error": 0.041, "p50_error": 0.012},
    "firewall": {"p99_error": 0.028, "p50_error": 0.007},
    ...
}
# At inference: anomaly_score = recon_error / calibration[source_type]["p99_error"]
```

---

## 7. Phase 5 — Score Fusion & Correlation Engine

### New Fusion Formula

```python
combined = lgbm_score × 0.85 + autoencoder_score × 0.15

# Post-model adjusters (applied to combined):
adjusted = combined

# 1. Kill-chain progression boost
if kill_chain_stage >= 2:
    adjusted *= (1.0 + kill_chain_stage * 0.10)  # max 1.5× at stage 5

# 2. Cross-host correlation boost
if cross_host_correlation >= 3:
    adjusted *= 1.20  # 3+ hosts showing similar anomalies = likely campaign

# 3. IOC correlation (context-aware, not flat)
if has_known_ioc:
    ioc_boost = 0.05 + 0.15 * combined  # range: 0.05-0.20
    adjusted += ioc_boost

# 4. Disagreement escalation (preserved from current system)
disagreement = abs(lgbm_score - autoencoder_score)
if disagreement > 0.40 and max(lgbm_score, autoencoder_score) > 0.70:
    adjusted = max(adjusted, 0.95)  # Force escalate when models strongly disagree

# Clamp
adjusted = min(adjusted, 1.0)
```

### Routing Thresholds

| Score Range | Action | Destination |
|-------------|--------|-------------|
| `adjusted ≥ 0.90` | **ESCALATE** | → `anomaly-alerts` + `hunter-tasks` |
| `adjusted ≥ 0.40` | **MONITOR** | → `triage-scores` (dashboard visible) |
| `adjusted < 0.40` | **DISCARD** | → `triage-scores` (audit log only) |

**Why 0.90 instead of 0.95**: With better features and a properly trained model, we can afford a lower escalation threshold. The current 0.95 was raised specifically because the model was generating too many false escalations due to training/production skew. With the new feature vector, that skew is eliminated.

### Kill-Chain State Machine (In-Memory)

```python
class KillChainTracker:
    """Per-host attack stage progression with decay."""
    
    STAGE_MAP = {
        # action_type → kill chain stage
        "network_connect": 0,       # Normal
        "auth_fail": 1,             # RECONNAISSANCE (enum probing)
        "auth_success": 2,          # INITIAL ACCESS (after failures)
        "process_create": 3,        # EXECUTION
        "config_change": 4,         # PERSISTENCE  
        "data_access": 5,           # EXFILTRATION
        "privilege_use": 3,         # EXECUTION (elevated)
        "policy_change": 4,         # PERSISTENCE
    }
    
    def __init__(self):
        self._hosts: Dict[str, HostState] = {}
        # HostState = {stage: int, last_update: float, score_history: deque}
    
    def update(self, hostname: str, action_type: int, score: float) -> Tuple[int, float]:
        """Returns (current_stage, stage_velocity)."""
        state = self._hosts.get(hostname)
        if state is None:
            state = HostState(stage=0, last_update=time.time(), transitions=[])
            self._hosts[hostname] = state
        
        new_stage = self.STAGE_MAP.get(ACTION_NAMES[action_type], 0)
        
        # Only advance if new stage > current AND event is suspicious (score > 0.3)
        if new_stage > state.stage and score > 0.30:
            elapsed = time.time() - state.last_update
            state.transitions.append(elapsed)
            state.stage = new_stage
            state.last_update = time.time()
        
        # Decay: reset to 0 if no activity for 1 hour
        if time.time() - state.last_update > 3600:
            state.stage = 0
            state.transitions.clear()
        
        velocity = 0.0
        if len(state.transitions) >= 2:
            velocity = 1.0 / max(np.mean(state.transitions), 1.0)
        
        return state.stage, velocity
```

**Memory**: ~100 bytes per host. 100K hosts = 10 MB. Trivial.

---

## 8. Phase 6 — Triage Agent Reimplementation

### Architecture: Multi-Process Python + ONNX Batch

The current single-threaded Python consumer processes events one-batch-at-a-time. The new design:

```
Kafka Consumer Thread (confluent_kafka)
   │
   ├── Poll batch (2000 events)
   │
   ├── Feature Extraction (ThreadPoolExecutor, 4 workers)  ← PARALLEL
   │   ├── worker-0: events[0:500]
   │   ├── worker-1: events[500:1000]
   │   ├── worker-2: events[1000:1500]
   │   └── worker-3: events[1500:2000]
   │
   ├── Model Inference (single call, batched)  ← FAST
   │   ├── LightGBM ONNX: (2000, 32) → (2000,) scores  ← ~2ms
   │   └── Autoencoder ONNX: (2000, 32) → (2000,) errors ← ~0.5ms
   │
   ├── Score Fusion (vectorized numpy)  ← FAST
   │   ├── combined = lgbm * 0.85 + ae * 0.15
   │   ├── kill_chain_updates (in-memory, O(1) per event)
   │   └── routing: escalate / monitor / discard
   │
   ├── Kafka Produce (lz4, batch, async)  ← NON-BLOCKING
   │
   └── SHAP (background thread, async)  ← NON-BLOCKING
       └── Only for escalated events, written to CH directly
```

### Key Performance Changes

| Component | Current | New | Speedup |
|-----------|---------|-----|---------|
| Batch size | 500 | 2000 | 4× |
| Feature extraction | Sequential, 1 thread | Parallel, 4 threads | ~3× |
| SHAP | Synchronous, 21 ONNX calls per escalation | Async background thread | ∞ (removed from critical path) |
| ARF inference | Row-by-row Python, 500 events | Removed | ∞ (eliminated) |
| Model count | 3 (LGBM + EIF + ARF) | 2 (LGBM + AE) | Fewer calls |
| ONNX batch inference | (500, 19) × 3 models | (2000, 32) × 2 models | ~2× larger batch, 1 fewer model |
| Replicas | 4 | 8 | 2× |
| Kafka partitions | 12 | 24 | 2× parallelism |

**Expected throughput per replica**: ~100-200 EPS  
**Expected total throughput (8 replicas)**: ~800-1600 EPS  
**With 12 replicas (future)**: ~1200-2400 EPS

### Sharded ConnectionTracker (Eliminate Lock Contention)

The current `ConnectionTracker` uses a single `threading.Lock()` that serializes all feature extraction threads.

```python
class ShardedConnectionTracker:
    """16 independent shards, each with its own lock."""
    
    NUM_SHARDS = 16
    
    def __init__(self):
        self._shards = [
            {"lock": threading.Lock(), "connections": defaultdict(deque)}
            for _ in range(self.NUM_SHARDS)
        ]
    
    def _shard_for(self, src_ip: str) -> int:
        return hash(src_ip) % self.NUM_SHARDS
    
    def update(self, src_ip, dst_ip, service, flag, timestamp):
        shard = self._shards[self._shard_for(src_ip)]
        with shard["lock"]:
            # Only this shard is locked — other IPs proceed in parallel
            ...
```

With 4 feature extraction threads and 16 shards, the probability of lock contention drops from ~75% (single lock) to ~6% (sharded).

### EWMA Rate Tracker (Replace Fixed Windows)

```python
class EWMATracker:
    """Per-entity exponentially weighted rates. O(1) memory per entity."""
    
    def __init__(self, half_lives: List[float] = [2.0, 60.0, 600.0]):
        self._half_lives = half_lives
        self._decay_constants = [math.log(2) / hl for hl in half_lives]
        self._entities: Dict[str, EntityState] = {}
    
    def update(self, entity_key: str, timestamp: float, is_error: bool = False) -> Dict:
        state = self._entities.get(entity_key)
        if state is None:
            state = EntityState(
                rates=[0.0] * len(self._half_lives),
                error_rates=[0.0] * len(self._half_lives),
                last_ts=timestamp,
                unique_actions=set()
            )
            self._entities[entity_key] = state
        
        elapsed = max(timestamp - state.last_ts, 0.001)
        for i, dc in enumerate(self._decay_constants):
            decay = math.exp(-elapsed * dc)
            state.rates[i] = state.rates[i] * decay + 1.0
            if is_error:
                state.error_rates[i] = state.error_rates[i] * decay + 1.0
            else:
                state.error_rates[i] = state.error_rates[i] * decay
        
        state.last_ts = timestamp
        
        return {
            "rate_fast": state.rates[0],    # 2s half-life
            "rate_slow": state.rates[2],    # 600s half-life
            "error_rate": state.error_rates[1],  # 60s half-life
            "rate_acceleration": state.rates[0] / max(state.rates[2], 0.01),
        }
```

---

## 9. Phase 7 — Hunter Agent Improvements

### Current Issues
- Processes ~1-2 events/second (downstream bottleneck)
- 42-feature vector with many zero-value features
- CatBoost cold-start requires lowered confidence threshold

### Changes

#### 7A. Increase Score Gate Precision

The current `HUNTER_SCORE_GATE = 0.70` filters input. With the new triage model producing better-calibrated scores:

```python
HUNTER_SCORE_GATE = 0.80  # Higher gate — only investigate events triage is confident about
```

This reduces Hunter's input volume by ~50% (based on current score distribution), doubling its effective throughput.

#### 7B. Add Kill-Chain Context to Hunter Investigations

Pass the kill-chain state from Triage to Hunter via the `hunter-tasks` Kafka message:

```python
# In hunter-tasks message, add:
{
    "kill_chain_stage": 3,          # From Triage's KillChainTracker
    "kill_chain_velocity": 0.5,     # Transitions/minute
    "kill_chain_history": [         # Stage progression timeline
        {"stage": 1, "timestamp": "...", "event_id": "..."},
        {"stage": 2, "timestamp": "...", "event_id": "..."},
        {"stage": 3, "timestamp": "...", "event_id": "..."},
    ]
}
```

Hunter uses this to:
1. Prioritize events at advanced kill-chain stages (stage 4-5 get investigated first)
2. Include the entire kill-chain timeline in the narrative
3. Query ClickHouse for all events from earlier stages for the same host

#### 7C. Parallel Investigation Scaling

Current: 1 Hunter instance, `HUNTER_CONCURRENCY=8`.
New: 2 Hunter instances with `HUNTER_CONCURRENCY=12` each = 24 parallel investigations.

Split `hunter-tasks` topic to 4 partitions → 2 consumer groups.

#### 7D. Hunter CatBoost Feature Update

Update the 42-dim feature vector to include the new triage features:

| Removed | Added |
|---------|-------|
| `arf_score` (removed from triage) | `autoencoder_score` |
| — | `kill_chain_stage` |
| — | `kill_chain_velocity` |
| — | `entity_event_rate` (from triage) |
| — | `entity_error_rate` (from triage) |

New Hunter feature vector: 46 dimensions.

---

## 10. Phase 8 — Feedback Loop & Continuous Learning

### The Missing Feedback Cycle

Currently: Models are trained once → deployed → never updated from production data.
Goal: Models continuously improve from analyst decisions.

### 8A. Analyst Feedback API

```
Dashboard → POST /api/feedback
{
    "event_id": "...",
    "label": "true_positive" | "false_positive" | "false_negative",
    "attack_type": "brute_force",      // Optional
    "mitre_technique": "T1110.001",    // Optional  
    "notes": "Confirmed brute force from external IP",
    "analyst_id": "analyst_01"
}
    → INSERT INTO feedback_labels (event_id, label, attack_type, ...)
```

### 8B. Feedback Integration Points

```
                 feedback_labels
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    Weekly LGBM   Daily AE     Immediate
    Retraining    Recalib.     Allowlist
          │           │           │
          ▼           ▼           ▼
    New ONNX      New p99    AllowlistChecker
    model file    thresholds    cache update
```

#### Weekly LightGBM Retraining:
1. Pull last 7 days of feedback_labels from ClickHouse
2. Match feedback events to their 32-feature vectors (from `triage_scores`)
3. Combine with original 296K training set (human labels weighted 3×)
4. Retrain LightGBM v7 with same hyperparameters
5. Validate: per-log-type F1 ≥ 0.80, overall F1 ≥ 0.90
6. If pass → atomic swap ONNX file → Triage agent hot-reloads within 60s
7. If fail → alert, keep current model

#### Daily Autoencoder Recalibration:
1. Pull last 24h of confirmed-normal events (feedback label = "false_positive")
2. Compute reconstruction error distribution
3. If p99_error shifted by >20% → retrain autoencoder on expanded normal set
4. If <20% shift → update only the per-source calibration constants

#### Immediate Allowlist Updates:
1. If analyst marks 3+ events from same (source_ip, source_type) as false_positive within 7 days
2. Auto-suggest allowlist entry (require analyst approval via dashboard)
3. On approval → INSERT into `allowlist` table → `AllowlistChecker` picks up within 5 minutes

### 8C. Minimum Feedback Volume Targets

| Metric | Target | Current |
|--------|--------|---------|
| Labels per day | 20+ | 0 |
| Labels per week | 100+ | 0 |
| Labels needed for first retrain | 500 | 0 |
| FP labels for reliable allowlist | 50 per source | 0 |

Display a **"Feedback Dashboard"** widget showing:
- Total labels this week
- Labels by type (TP/FP/FN)
- "Labels needed for next retrain: X"
- Per-analyst leaderboard (gamification)

---

## 11. Phase 9 — Performance Architecture

### Resource Allocation (PC2 Redesign)

| Service | Replicas | CPU | RAM | Role |
|---------|----------|-----|-----|------|
| Triage Agent | 8 | 1.5 each (12 total) | 1.5G each (12G total) | Primary scoring |
| Hunter Agent | 2 | 1.5 each (3 total) | 1.5G each (3G total) | Deep investigation |
| Verifier | 1 | 0.5 | 512M | Forensic validation |
| XAI Service | 1 | 0.25 | 256M | Explainability |
| LanceDB | 1 | 1.0 | 2G | Similarity search |
| Merkle | 1 | 0.25 | 128M | Evidence anchoring |
| Prometheus | 1 | 0.25 | 256M | Metrics |
| Grafana | 1 | 0.25 | 256M | Dashboards |
| **Total** | **16** | **~18 CPU** | **~20G RAM** | |

**Hardware requirement**: PC2 needs 18+ logical CPU cores and 24+ GB RAM. If the current PC2 only has 12 cores / 16 GB, either:
- Add a **PC3** for 4 additional triage replicas + 1 additional hunter
- Or upgrade PC2

### Kafka Partition Strategy

| Topic | Current Partitions | New Partitions | Reason |
|-------|-------------------|----------------|--------|
| raw-logs | 12 | 24 | 8 triage replicas need balanced distribution |
| security-events | 12 | 24 | Same |
| process-events | 12 | 24 | Same |
| network-events | 12 | 24 | Same |
| triage-scores | 3 | 6 | Higher write throughput |
| hunter-tasks | 3 | 4 | 2 hunter replicas |
| anomaly-alerts | 1 | 3 | Dashboard fan-out |

### Throughput Targets

| Stage | Target | How |
|-------|--------|-----|
| **Vector ingestion** | 50,000 EPS | Already Rust-native, handles this |
| **Redpanda throughput** | 100,000 EPS | 3 brokers, 24 partitions, lz4 compression |
| **Go Consumer → CH** | 50,000 EPS | Already handles 500K batch inserts |
| **Triage scoring** | 1,600 EPS | 8 replicas × 200 EPS each |
| **Hunter investigation** | 10 events/s | 2 replicas × 5 events/s |
| **Overall pipeline** | **1,600 EPS** | Bottleneck = Triage (but 10× better than current 1-2 EPS) |

### Monitoring & Alerting

```yaml
# New Prometheus alerts for pipeline health:
groups:
  - name: clif_pipeline
    rules:
      - alert: TriageThroughputLow
        expr: rate(clif_triage_events_processed_total[5m]) < 100
        for: 10m
        labels: { severity: warning }
        
      - alert: TriageLatencyHigh
        expr: histogram_quantile(0.99, clif_triage_batch_duration_seconds) > 10
        for: 5m
        labels: { severity: critical }
        
      - alert: KafkaConsumerLag
        expr: clif_triage_consumer_lag > 10000
        for: 5m
        labels: { severity: warning }
        
      - alert: ModelDriftDetected
        expr: clif_triage_kl_divergence > 0.15
        for: 1h
        labels: { severity: warning }
        
      - alert: EscalationRateAnomaly
        expr: |
          abs(rate(clif_triage_escalations_total[1h]) / rate(clif_triage_events_processed_total[1h]) - 0.05) > 0.03
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "Escalation rate deviated >3% from 5% target"
```

---

## 12. Full Pipeline Diagram

```
                              ┌──────────────────────────────────────────────┐
                              │           ENTERPRISE LOG SOURCES             │
                              │                                              │
                              │  Syslog ─────────── :1514 TCP ──────────┐    │
                              │  Windows (NXLog) ─── :9514 JSON ────────┤    │
                              │  Firewall (CEF) ──── :1514 UDP ─────────┤    │
                              │  Cloud (Fluentd) ─── :9514 JSON ────────┤    │
                              │  K8s (Fluentbit) ─── :9514 JSON ────────┤    │
                              │  DNS (named) ──────── :1514 TCP ────────┤    │
                              │  Web (nginx) ──────── :1514 TCP ────────┤    │
                              │  NetFlow (softflowd)─ :9514 JSON ───────┤    │
                              │  IDS (Suricata) ───── :9514 JSON ───────┤    │
                              │  AD (DC WEF) ──────── :9514 JSON ───────┤    │
                              └────────────────────────────┬─────────────┘    │
                                                           │
                              ┌─────────────────────────────────────────────┐
                              │         VECTOR (Rust, PC1)                  │
                              │                                             │
                              │  mega_transform:                            │
                              │    A. Timestamp normalization               │
                              │    B. Parse + field extraction by log type  │
                              │       - Windows EventID, LogonType          │
                              │       - Cloud action, service, user         │
                              │       - K8s verb, resource, namespace       │
                              │       - DNS query name, type                │
                              │       - CEF severity, action                │
                              │    C. Security classification (regex+MITRE) │
                              │    D. Normalize to unified schema           │
                              │    E. Route → 4 Kafka topics                │
                              └────────────┬──────────────┬─────────────────┘
                                           │              │
                     ┌─────────────────────┘              └──────────────────┐
                     ▼                                                       ▼
         ┌───────────────────────┐                            ┌──────────────────────┐
         │   Redpanda (3 nodes)  │                            │   Redpanda (3 nodes)  │
         │   24 partitions/topic │                            │   24 partitions/topic │
         │                       │                            │                       │
         │  raw-logs             │                            │  raw-logs             │
         │  security-events      │                            │  security-events      │
         │  process-events       │                            │  process-events       │
         │  network-events       │                            │  network-events       │
         └───────┬───────────────┘                            └──────────┬────────────┘
                 │                                                       │
                 ▼                                                       ▼
    ┌─────────────────────┐                         ┌──────────────────────────────────┐
    │   Go Consumer ×2    │                         │   TRIAGE AGENT ×8  (Python)      │
    │   (PC1)             │                         │   (PC2 + PC3)                    │
    │                     │                         │                                  │
    │   Kafka → ClickHouse│                         │   ┌─ Feature Extraction ──────┐  │
    │   500K batch inserts│                         │   │  Universal (12 features)  │  │
    │   async_insert=1    │                         │   │  Network (8 features)     │  │
    │   50,000+ EPS       │                         │   │  Text (6 features)        │  │
    │                     │                         │   │  Behavioral (6 features)  │  │
    └─────────┬───────────┘                         │   └───────────┬───────────────┘  │
              │                                     │               │                  │
              ▼                                     │   ┌───────────▼───────────────┐  │
    ┌─────────────────────┐                         │   │  LightGBM ONNX (0.85)    │  │
    │   ClickHouse ×2     │                         │   │  Autoencoder ONNX (0.15) │  │
    │   (PC1)             │                         │   │  Batch: (2000, 32)        │  │
    │                     │                         │   │  Latency: ~3ms/batch      │  │
    │   raw_logs          │                         │   └───────────┬───────────────┘  │
    │   security_events   │◄─── MV baselines ──────►│               │                  │
    │   triage_scores     │                         │   ┌───────────▼───────────────┐  │
    │   hunter_*          │                         │   │  Score Fusion             │  │
    │   verifier_*        │                         │   │  Kill-Chain Tracker       │  │
    │   feedback_labels   │                         │   │  Cross-Host Correlation   │  │
    │                     │                         │   │  IOC Lookup               │  │
    │   host_baselines MV │                         │   │  Allowlist Check          │  │
    │   entity_freq MV    │                         │   └───────────┬───────────────┘  │
    └─────────────────────┘                         │               │                  │
                                                    │      ┌────────┼────────┐         │
                                                    │      ▼        ▼        ▼         │
                                                    │   escalate  monitor  discard     │
                                                    │      │        │        │          │
                                                    │      ▼        └────┬───┘          │
                                                    │  hunter-tasks     │              │
                                                    │  anomaly-alerts   │              │
                                                    │      │      triage-scores        │
                                                    │      │            │               │
                                                    │  SHAP (async)    │               │
                                                    └──────┼────────────┼───────────────┘
                                                           │            │
                                                           ▼            ▼
                                              ┌─────────────────┐    (Go Consumer
                                              │  HUNTER ×2      │     writes to CH)
                                              │                 │
                                              │  Score Gate≥0.80│
                                              │  L1: Sigma,SPC, │
                                              │      Graph,     │
                                              │      Temporal,  │
                                              │      Similarity │
                                              │  L2: MITRE,     │
                                              │      Campaign,  │
                                              │      KillChain  │
                                              │  CatBoost (46d) │
                                              │  NarrativeBuilder│
                                              └────────┬────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  VERIFIER ×1    │
                                              │                 │
                                              │  Evidence       │
                                              │  IOC Correlation│
                                              │  Timeline       │
                                              │  FP Analysis    │
                                              │  Merkle Verify  │
                                              └────────┬────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  DASHBOARD      │
                                              │  (Next.js)      │
                                              │                 │
                                              │  Alert Triage   │
                                              │  Investigation  │
                                              │  Feedback API ──┼──► feedback_labels
                                              │  Kill-Chain View│       │
                                              │  UEBA View      │       ▼
                                              └─────────────────┘  Weekly Retrain
                                                                   ┌─────────────┐
                                                                   │ retrain_v7  │
                                                                   │ LightGBM    │
                                                                   │ Autoencoder │
                                                                   │ Calibration │
                                                                   └─────────────┘
```

---

## 13. Implementation Roadmap

### Sprint 1 (Week 1–2): Quick Throughput Wins — No Retraining

| Task | Effort | Impact |
|------|--------|--------|
| Remove ARF from ensemble (set weight=0) | 2h | +30% throughput, eliminates 3 bugs |
| Defer SHAP to async background thread | 4h | +50% throughput |
| Increase BATCH_SIZE from 500 → 2000 | 30min | +2× throughput |
| Add 4 more triage replicas (4→8) | 1h | +2× throughput |
| Increase Kafka partitions to 24 | 1h | Enables 8 replicas |
| **Sprint 1 Result** | ~1 day | **~2 EPS → ~100-200 EPS** |

### Sprint 2 (Week 3–4): New Feature Vector

| Task | Effort | Impact |
|------|--------|--------|
| Implement 12 universal features in feature_extractor.py | 3d | All log types get 12 usable features |
| Implement 6 text features | 1d | Syslog/Windows/K8s get 6 more features |
| Implement 6 behavioral features (EWMA, kill-chain) | 2d | Temporal correlation enabled |
| Refine 8 network features (EWMA, port entropy) | 1d | Better network detection |
| Update Vector VRL for Windows/Cloud/K8s field extraction | 2d | New log type parsing |
| Implement ShardedConnectionTracker | 1d | Eliminate lock contention |
| **Sprint 2 Result** | ~2 weeks | **32 features, all 10 log types covered** |

### Sprint 3 (Week 5–6): Training Data Collection

| Task | Effort | Impact |
|------|--------|--------|
| Download LANL auth dataset + preprocess | 2d | 30K labeled syslog/AD events |
| Download Mordor/OTRF datasets + preprocess | 2d | 20K labeled Windows events |
| Download Stratus Red Team CloudTrail + preprocess | 1d | 15K labeled cloud events |
| Generate Falco/K8s attack simulations | 2d | 10K labeled K8s events |
| Download CIC-IDS2018 + preprocess | 1d | 30K updated IDS events |
| Build Layer 2 synthetic normal baselines | 3d | 80K normal events |
| Build Layer 2 anomaly injections | 2d | 16K injected anomalies |
| Implement production-aligned feature extractor for training | 2d | Eliminate train/serve skew |
| **Sprint 3 Result** | ~2 weeks | **~296K training samples, 10 log types** |

### Sprint 4 (Week 7–8): Model Training & Validation

| Task | Effort | Impact |
|------|--------|--------|
| Train LightGBM v7 with 32 features, 5-fold CV | 2d | New supervised model |
| Train Autoencoder on normal-only data | 2d | New anomaly model |
| Per-log-type F1 validation (must pass ≥0.80 each) | 1d | Quality assurance |
| Calibrate per-source-type autoencoder thresholds | 1d | Correct anomaly scoring |
| Calibrate fusion thresholds (suspicious/anomalous) | 1d | Correct routing |
| Export both models to ONNX + verification | 1d | Deployment ready |
| End-to-end test: feed 10K events through full pipeline | 2d | Integration validation |
| **Sprint 4 Result** | ~2 weeks | **Validated 2-model ensemble** |

### Sprint 5 (Week 9–10): Feedback Loop + Hunter Updates

| Task | Effort | Impact |
|------|--------|--------|
| Implement feedback API endpoint in dashboard | 2d | Analyst labels flow in |
| Implement weekly LightGBM retraining cron | 2d | Models improve over time |
| Implement daily autoencoder recalibration | 1d | Anomaly thresholds stay current |
| Update Hunter 42→46 feature vector | 1d | Kill-chain context in investigations |
| Add 2nd Hunter instance | 2h | Double investigation throughput |
| Implement kill-chain visualization in dashboard | 3d | Analysts see attack progression |
| **Sprint 5 Result** | ~2 weeks | **Continuous learning pipeline** |

### Sprint 6 (Week 11–12): Production Hardening

| Task | Effort | Impact |
|------|--------|--------|
| Load test at 1,000 EPS sustained for 24h | 2d | Verify throughput target |
| Per-log-type accuracy audit with synthetic attacks | 2d | Verify all 10 types work |
| Prometheus alerts for pipeline health | 1d | Operational monitoring |
| Grafana dashboards for model metrics | 1d | Model health visibility |
| Documentation update | 2d | Operational runbook |
| **Sprint 6 Result** | ~2 weeks | **Production-ready pipeline** |

---

## Summary: Current → New Comparison

| Dimension | Current | New | Improvement |
|-----------|---------|-----|-------------|
| **Feature count** | 19 | 32 | +68% features |
| **Features for log-only events** | 3 usable | 24 usable | **8× improvement** |
| **Training data** | 175K (70% network) | 296K (balanced 10 types) | +69% data, 100% type coverage |
| **Log types with real training data** | 6 of 10 | 10 of 10 | **Full coverage** |
| **Models** | 3 (LGBM+EIF+ARF) | 2 (LGBM+AE) | Simpler, faster, no bugs |
| **Anomaly detection** | EIF (Δ0.03 spread) | Autoencoder (Δ0.3+ spread) | **10× better discrimination** |
| **Temporal correlation** | None | Kill-chain + EWMA + cross-host | **New capability** |
| **Throughput** | ~2 EPS | ~1,600 EPS | **800× improvement** |
| **Feedback loop** | None | Weekly retrain from analyst labels | **New capability** |
| **Known attack detection** | Good for network, blind for logs | Good for ALL log types | **Full coverage** |
| **Anomaly detection** | Broken (EIF+ARF useless) | Autoencoder + behavioral baselines | **Real anomaly detection** |
| **Train/serve skew** | Significant (simulated features) | Eliminated (same extractor) | **No skew** |
| **Detection latency** | ~500ms–1s per event | ~1.5ms per event (batch) | **300× faster** |
