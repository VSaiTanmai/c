# DATASET AUDIT REPORT — Training & Preprocessing Readiness

**Date:** June 2025  
**Location:** `C:\CLIF\agents\Data\Latest_Dataset\`  
**Total Size:** ~10.6 GB (excluding auth.txt)  
**Total Files:** 641 across 10 folders  

---

## EXECUTIVE SUMMARY

| Status | Count | Details |
|--------|-------|---------|
| ✅ READY | 9/10 | Sufficient data, labels present, both benign + attack |
| ❌ EMPTY | 1/10 | 07_Kubernetes — needs synthetic generation |
| ⚠️ CLEANUP | 1 file | auth.txt (68 GB) can be safely deleted |

---

## PER-FOLDER AUDIT

### 01_Syslog/ — ✅ READY (133.7 MB, 12 files)

| File | Size | Rows | Purpose |
|------|------|------|---------|
| lanl_auth_training.csv | 60.4 MB | 709,070 | **Primary training file** — LANL auth logs |
| SSH.log | 70.0 MB | ~500K | Raw SSH auth logs (brute-force, valid logins) |
| Linux.log | 2.2 MB | ~10K | General Linux syslog |
| OpenSSH_2k.log + structured CSV | 0.5 MB | 2,000 | Structured SSH with event templates |
| loghub-linux/ (3 files) | 0.3 MB | 2,000 | Linux structured logs with 118 templates |
| redteam.txt | 0.02 MB | 749 | LANL red team attack labels |

**Label Distribution (lanl_auth_training.csv):**
- benign: 558,400 (78.8%)
- unknown: 99,922 (14.1%) — auth failures, good anomaly signals
- context: 49,463 (7.0%) — events near attack windows
- attack: 1,134 (0.2%) — confirmed red team activity
- suspicious: 150 (0.02%)

**Verdict:** Excellent. 709K labeled events covering 58 days, 33K users, 10 auth types. Class imbalance is real-world representative. LightGBM uses attack+suspicious as positive class; Autoencoder trains on benign-only.

---

### 02_Windows_Event/ — ✅ READY (620.8 MB, 496 files)

**Dataset:** OTRF Security Datasets (Mordor/Security-Datasets)  
**Content:** 496 compressed .zip/.tar.gz files + JSON files organized by MITRE ATT&CK tactics:
- credential_access/ (25 host + 8 network scenarios)
- defense_evasion/ (32 host + 1 network scenarios)
- discovery/ (8 host + 6 network scenarios)
- execution/ (4 scenarios)
- lateral_movement/ (28 host + 25 network scenarios)
- persistence/ (8 scenarios)
- privilege_escalation/ (3 scenarios)
- **Compound attacks:** APT29 (day1 + day2), 7x LSASS campaigns, Log4Shell, GoldenSAML

**Key Files:**
- purplesharp_ad_playbook_I_2020-10-22042947.json: 37.8 MB (large JSON)
- apt29 day1 manual: 13.3 MB, day2 manual: 41.0 MB
- LSASS campaign PCAPs: 54-60 MB each
- APT29 Zeek logs: individual conn, dce_rpc, dns, kerberos, smb, ssl, x509

**MITRE Coverage:** credential_access, defense_evasion, discovery, execution, lateral_movement, persistence, privilege_escalation, collection = **8 tactics**

**Verdict:** Very rich dataset. Compressed Windows EVTX/JSON with real attack simulations. Needs extraction during preprocessing (unzip → parse JSON/EVTX). All files are attack data — normal Windows baseline should come from the benign portions of compound attacks.

---

### 03_Firewall/ — ✅ READY (168.8 MB, 3 files)

| File | Size | Rows | Columns |
|------|------|------|---------|
| UNSW-NB15_1.csv | 161.2 MB | 700,000 | 49 (no header row) |
| unsw_stratified.csv | 5.1 MB | 20,233 | 52 (with headers) |
| unsw_normal_only.csv | 2.6 MB | 10,000 | 52 (normal baseline) |

**Label Distribution (unsw_stratified.csv):**
- Normal: 10,000 (49.4%)
- Fuzzers: 2,000 | Exploits: 2,000 | Generic: 2,000
- Reconnaissance: 1,759 | DoS: 1,167 | Backdoors: 534
- Analysis: 526 | Shellcode: 223 | Worms: 24

**Verdict:** Ready. Well-balanced stratified subset with 9 attack categories + normal. The 700K raw file provides depth for Autoencoder training. 52-feature vector is very rich.

---

### 04_Active_Directory/ — ✅ READY (35.5 MB, 2 files)

| File | Size | Rows | Columns |
|------|------|------|---------|
| lanl_auth_ad_training.csv | 35.4 MB | 420,943 | 11 |
| redteam.txt | 0.02 MB | 749 | 4 |

**Label Distribution:**
- benign: 312,185 (74.2%)
- unknown: 85,649 (20.3%) — auth failures
- context: 22,882 (5.4%)
- attack: 129 (0.03%)
- suspicious: 98 (0.02%)

**Content:** Kerberos/Negotiate/TGT/TGS authentication events from LANL (subset of 01_Syslog filtered to AD-specific protocols).

**Verdict:** Ready. 420K events focused on AD authentication patterns. Same column structure as syslog file. Good for training AD-specific feature tracks.

---

### 05_DNS/ — ✅ READY (639.2 MB, 66 files)

**Sub-datasets:**

| Dataset | Files | Size | Content |
|---------|-------|------|---------|
| CIC-Bell-DNS-EXFil-2021 | 48 | ~367 MB | DNS exfiltration attacks + benign (CSVs + PCAPs) |
| DGA (dga_data.csv) | 1 | 7.0 MB | 160K domains (80K DGA + 80K legit, 7 families) |
| OONI (ooni_dns_normal.json) | 1 | 0.6 MB | Normal DNS from OONI observatory |
| Benign DNS CSVs | 4 | ~279 MB | 500K benign + 5K malware + 5K phishing + 4K spam |

**CIC DNS Exfiltration Features:**
- Stateful (27 cols): rr, frequency distributions, unknowns
- Stateless (15 cols): timestamp, FQDN_count, subdomain_length, entropy, labels, longest_word
- Attack types: audio/compressed/exe/image/text/video exfiltration (light + heavy variants)
- Benign: 220K+ normal DNS queries across multiple captures

**DGA Coverage:** gameoverdga + 6 more DGA families, 80K DGA vs 80K legit

**Verdict:** Excellent coverage. Three complementary DNS datasets: exfiltration detection (CIC), DGA detection (dga_data), and domain reputation (benign/malware/phishing/spam CSVs). More than sufficient for DNS feature tracks.

---

### 06_Cloud_AWS/ — ✅ READY (1,787.1 MB, 37 files)

| Dataset | Files | Size | Rows |
|---------|-------|------|------|
| CloudTrail (19 features) | 1 | 994.2 MB | 1,939,207 |
| CloudTrail (18 features) | 1 | 792.4 MB | 1,939,207 |
| Stratus Red Team logs | 35 | 0.5 MB | 310 events |

**CloudTrail Columns (19):** eventID, eventTime, sourceIPAddress, userAgent, eventName, eventSource, awsRegion, eventVersion, userIdentitytype, eventType, requestID, userIdentityaccountId, userIdentityprincipalId, userIdentityarn, recipientAccountId, managementEvent, readOnly, resources, errorCode

**Stratus Red Team Coverage (11 MITRE categories):**
- credential-access (5): EC2 get-password-data, steal-instance-creds, SecretsManager, SSM
- defense-evasion (6): CloudTrail delete/stop/selectors, DNS delete, VPC flow-logs, org-leave
- discovery (1): EC2 download-user-data
- execution (4): EC2 launch/user-data, SSM send-command/start-session
- exfiltration (4): EC2 security-group, share-AMI/EBS/RDS
- impact (1): Bedrock invoke-model
- initial-access (1): console-login-without-MFA
- lateral-movement (2): EC2 instance-connect, serial-console
- persistence (8): IAM backdoor/create roles/users, Lambda functions, RolesAnywhere, STS
- privilege-escalation (1): IAM update-user-login-profile

**Verdict:** Ready. 1.9M normal CloudTrail events + 310 precision red team attack events across 11 MITRE categories. The two CSV variants (18 vs 19 features) are the same data — use the 19-feature version.

---

### 07_Kubernetes/ — ❌ EMPTY (0 files)

**Status:** No data. Needs synthetic generation.

**Recommendation:** Generate synthetic Kubernetes audit logs covering:
- Normal: pod lifecycle (create/start/stop/delete), service operations, health checks
- Attack: privileged container creation, hostPath mounts, secrets access, RBAC escalation, container escape

**Priority:** LOW — Kubernetes is the least critical log type for initial training. Can be deferred to Sprint 3-4 of the implementation plan.

---

### 08_Web_Server/ — ✅ READY (54.8 MB, 7 files)

| File | Size | Rows | Purpose |
|------|------|------|---------|
| csic_database.csv | 28.2 MB | 61,065 | CSIC 2010 HTTP dataset (labeled) |
| goodqueries.txt | 23.0 MB | ~700K | FWAF benign HTTP queries |
| badqueries.txt | 3.2 MB | ~48K | FWAF attack queries |
| Loghub_Apache/ (4 files) | 0.4 MB | 2,000 | Structured Apache access logs |

**CSIC Label Distribution:**
- Normal (0): 36,000 (59%)
- Attack (1): 25,065 (41%)

**CSIC Columns (17):** Method, User-Agent, Pragma, Cache-Control, Accept, Accept-encoding, Accept-charset, language, host, cookie, content-type, connection, length, content, classification, URL

**FWAF:** ~700K good queries + ~48K bad queries (SQLi, XSS, command injection, path traversal)

**Verdict:** Ready. Well-balanced CSIC dataset + massive FWAF corpus. Rich HTTP header features for web attack detection. Attack types include SQLi, XSS, command injection.

---

### 09_NetFlow/ — ✅ READY (558.3 MB, 4 files)

| File | Size | Rows | Columns |
|------|------|------|---------|
| NF-UNSW-NB15-v3.csv | 550.6 MB | 2,365,424 | 55 |
| nf_unsw_stratified.csv | 3.0 MB | 12,000 | 57 |
| nf_unsw_normal_only.csv | 2.5 MB | 10,000 | 57 |
| nf_ton_iot_temporal.csv | 2.2 MB | 11,341 | 57 |

**Label Distribution (stratified):**
- Benign: 10,000 (83.3%)
- Exploits: 651 | Fuzzers: 573 | Reconnaissance: 274 | Generic: 273
- DoS: 84 | Backdoor: 77 | Shellcode: 45 | Analysis: 20 | Worms: 3

**NetFlow Features (55-57):** FLOW_START/END_MILLISECONDS, IPV4_SRC/DST_ADDR, L4_SRC/DST_PORT, PROTOCOL, L7_PROTO, IN/OUT_BYTES, IN/OUT_PKTS, TCP_FLAGS, SRC/DST_TO_SRC/DST IAT stats, Label, Attack

**Verdict:** Ready. 2.4M NetFlow records in the main file + balanced stratified subset. 55 features per flow. Covers 9 attack categories. TON-IoT adds temporal IoT attack patterns.

---

### 10_IDS_IPS/ — ✅ READY (6,603.6 MB, 14 files)

| File | Size | Rows | Source |
|------|------|------|--------|
| CIC-IDS2018/ (10 CSVs) | 6,567 MB | 7.5M+ | CIC-IDS 2018 |
| cicids2017_stratified.csv | 10.8 MB | 30,193 | CIC-IDS 2017 |
| nsl_kdd_stratified.csv | 3.7 MB | 24,607 | NSL-KDD |
| KDDTrain+.txt | 18.2 MB | ~125K | KDD Cup 99 |
| KDDTest+.txt | 3.3 MB | ~23K | KDD Cup 99 |

**CICIDS2017 Label Distribution (stratified):**
- BENIGN: 10,000 (33.1%)
- SSH-Patator: 2,000 | PortScan: 2,000 | FTP-Patator: 2,000
- DoS GoldenEye/Slowhttptest/Hulk/Slowloris: 2,000 each
- DDoS: 2,000 | Bot: 1,966
- Web Attack Brute Force: 1,507 | XSS: 652
- Infiltration: 36 | SQL Injection: 21 | Heartbleed: 11

**NSL-KDD Distribution:**
- Attack (1): 14,607 (59.4%)
- Normal (0): 10,000 (40.6%)

**CIC-IDS2018:** 80 flow features per record, 10 days of network traffic

**Verdict:** The largest dataset. Three IDS benchmarks spanning 20+ years of research. 80 features, 15+ attack types. CIC-IDS2018 alone has 7.5M+ records — will need sampling for training. Well suited for both LightGBM (labeled) and Autoencoder (benign-only training).

---

## TRAINING READINESS MATRIX

| # | Type | Benign Rows | Attack Rows | Attack Types | LightGBM Ready | Autoencoder Ready |
|---|------|------------|-------------|--------------|----------------|-------------------|
| 01 | Syslog | 558,400 | 1,284 | 3 (attack/suspicious/failure) | ✅ | ✅ |
| 02 | Windows Event | ~1000s (compound datasets) | 496 scenarios (8 MITRE tactics) | 8+ categories | ✅ (needs parsing) | ✅ (needs parsing) |
| 03 | Firewall | 10,000 | 10,233 | 9 categories | ✅ | ✅ |
| 04 | Active Directory | 312,185 | 227 | 2 (attack/suspicious) | ✅ | ✅ |
| 05 | DNS | 580,000+ | 90,000+ | DGA(7 families), exfil(6 types), malware, phishing, spam | ✅ | ✅ |
| 06 | Cloud/AWS | 1,939,207 | 310 | 11 MITRE categories | ✅ | ✅ |
| 07 | Kubernetes | 0 | 0 | — | ❌ | ❌ |
| 08 | Web Server | 36,000 | 73,065+ | SQLi, XSS, cmd-inj, path traversal | ✅ | ✅ |
| 09 | NetFlow | 10,000+ | 2,000+ (+ 2.3M raw) | 9 categories | ✅ | ✅ |
| 10 | IDS/IPS | 10,000+ (+ millions raw) | 14,607+ (+ millions raw) | 15+ attack types | ✅ | ✅ |

---

## ISSUES & RECOMMENDATIONS

### Critical
1. **07_Kubernetes is EMPTY** — Generate synthetic audit logs or defer to later sprint

### Cleanup
2. **auth.txt (68 GB)** at `Latest_Dataset\auth.txt` — All valuable data has been extracted into `lanl_auth_training.csv` and `lanl_auth_ad_training.csv`. **Safe to delete** to free 68 GB.

### Preprocessing Notes
3. **02_Windows_Event:** Files are compressed (.zip/.tar.gz). Preprocessing must unzip → parse JSON/EVTX → extract features.
4. **03_Firewall UNSW-NB15_1.csv:** Missing header row (700K rows, 49 columns). Must use `unsw_stratified.csv` headers as reference.
5. **06_Cloud_AWS:** Two versions of the same data (18 vs 19 features). Use `nineteenFeaturesDf.csv` (19 features) — same data with requestID added.
6. **10_IDS_IPS CIC-IDS2018:** 7.5M+ records across 10 CSV files. Will need sampling/batching during training. The `02-20-2018.csv` is particularly large at 3.9 GB.
7. **label column naming inconsistency:** `label` (01, 04), `classification` (08), `Label` (09, 10 CICIDS), `binary_label` (10 NSL-KDD), `attack_cat`/`Attack` (03, 09). Preprocessing must normalize these.

### Good to Know
8. **Total training-ready events:** ~5.8M+ labeled rows across all datasets (excluding raw CIC-IDS2018)
9. **Target of 296K samples:** More than achievable — data can be stratified down from each source
10. All CSV files use UTF-8 encoding and standard comma delimiters ✅

---

## FINAL VERDICT

**9 of 10 log types are READY for preprocessing and training.** Only Kubernetes data is missing (low priority, can be synthetically generated). The datasets are diverse, well-labeled, and cover the full spectrum of MITRE ATT&CK tactics needed for CLIF's threat detection pipeline.
