# CLIF — Data Collection & Download Guide

> **Goal**: Acquire sufficient, labeled training data across all **10 enterprise log types** to train models for **both known attack detection AND anomaly detection**.
>
> **Target**: ~296K samples (200K labeled Layer 1 + 96K synthetic Layer 2)

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Current Data Inventory (What You Already Have)](#2-current-data-inventory)
3. [Per-Type Download Instructions](#3-per-type-download-instructions)
   - [Type 01 — Syslog / Linux Auth](#type-01--syslog--linux-auth)
   - [Type 02 — Windows Event Log](#type-02--windows-event-log)
   - [Type 03 — Firewall / CEF](#type-03--firewall--cef)
   - [Type 04 — Active Directory / LDAP](#type-04--active-directory--ldap)
   - [Type 05 — DNS Logs](#type-05--dns-logs)
   - [Type 06 — AWS CloudTrail / Cloud Audit](#type-06--aws-cloudtrail--cloud-audit)
   - [Type 07 — Kubernetes Audit](#type-07--kubernetes-audit)
   - [Type 08 — Web Server (Nginx/Apache)](#type-08--web-server-nginxapache)
   - [Type 09 — NetFlow / IPFIX](#type-09--netflow--ipfix)
   - [Type 10 — IDS/IPS / Zeek](#type-10--idsips--zeek)
4. [Layer 2 — Synthetic Normal + Anomaly Injection](#4-layer-2--synthetic-normal--anomaly-injection)
5. [Post-Download Verification Checklist](#5-post-download-verification-checklist)
6. [Final Dataset Assembly](#6-final-dataset-assembly)

---

## 1. Prerequisites

### Tools to Install

```powershell
# Python packages for dataset downloading and processing
pip install kaggle pandas pyarrow gdown requests tqdm

# Kaggle API setup (needed for several datasets)
# 1. Go to https://www.kaggle.com → Your Profile → Account → Create New API Token
# 2. Save kaggle.json to C:\Users\<you>\.kaggle\kaggle.json
# 3. Verify:
kaggle datasets list -s "cicids"
```

### Directory Structure

```powershell
# Create download directory structure
$base = "C:\CLIF\agents\Data\datasets"
@(
    "$base\01_syslog_linux_auth\downloads",
    "$base\02_windows_event_log\downloads",
    "$base\03_firewall_cef\downloads",
    "$base\04_active_directory_ldap\downloads",
    "$base\05_dns_logs\downloads",
    "$base\06_aws_cloudtrail\downloads",
    "$base\07_kubernetes_audit\downloads",
    "$base\08_nginx_web_server\downloads",
    "$base\09_netflow_ipfix\downloads",
    "$base\10_ids_ips_zeek\downloads"
) | ForEach-Object { New-Item -ItemType Directory -Force -Path $_ }
```

---

## 2. Current Data Inventory

### What You Already Have (Sufficient ✅ vs. Insufficient ⚠️ vs. Missing ❌)

| # | Log Type | Have (Rows) | Key Datasets Available | Status | Need |
|---|----------|------------|----------------------|--------|------|
| 1 | Syslog/Linux Auth | ~34K | CICIDS2017 stratified (30K), Loghub Linux (2K), OpenSSH (2K) | ⚠️ Syslog-specific data is only 4K | LANL auth dataset |
| 2 | Windows Event Log | ~10K | EVTX-ATTACK-SAMPLES CSV (9.8K) | ⚠️ Only attack samples, no normal baseline | Mordor/OTRF + normal baselines |
| 3 | Firewall/CEF | ~20K | UNSW-NB15 stratified (20K), UNSW full (700K+) | ✅ Sufficient | Minor: add CEF formatting |
| 4 | Active Directory | 0 | ❌ Nothing (only reused EVTX) | ❌ EMPTY | LANL auth + Mordor AD attacks |
| 5 | DNS | ~295K+ | CIC-Bell DNS-EXFil (265MB benign + 15K attacks), CIC-Bell-2021 (~28 CSVs) | ✅ Sufficient | Minor: add DGA domains |
| 6 | Cloud Audit (AWS) | 0 | ❌ Nothing (only Sigma YAML rules) | ❌ EMPTY | Full dataset needed |
| 7 | Kubernetes Audit | 0 | ❌ Nothing (only Falco/kube-hunter source code) | ❌ EMPTY | Full dataset needed |
| 8 | Web Server | ~63K | CSIC 2010 (61K), Apache Loghub (2K) | ✅ Sufficient | Minor: more normal samples |
| 9 | NetFlow/IPFIX | ~43K+ | NF-UNSW stratified (12K), NF-ToN-IoT (11K), NF-UNSW-v3 full (550MB), NF-ToN-IoT-v3 full (5GB) | ✅ Sufficient | None |
| 10 | IDS/IPS/Zeek | ~55K+ | CICIDS2017 stratified (30K), NSL-KDD (24.6K), CICIDS2017 full (~2.8M) | ✅ Sufficient | Minor: CIC-IDS2018 for more attack types |

### Priority Download Order
1. **🔴 CRITICAL** (empty directories): Types 04, 06, 07
2. **🟡 IMPORTANT** (insufficient data): Types 01, 02
3. **🟢 OPTIONAL** (already sufficient, but improvements available): Types 03, 05, 08, 10

---

## 3. Per-Type Download Instructions

---

### Type 01 — Syslog / Linux Auth

#### What You Have
- `CICIDS2017/cicids2017_stratified.csv` — 30,193 rows (network-focused, not syslog-native)
- `Loghub/Linux_2k.log_structured.csv` — 2,000 rows (parsed syslog, unlabeled)
- `New_Dataset/OPEN_SSH/SSH.log` — 655,147 raw SSH log lines (unlabeled)
- `New_Dataset/OPEN_SSH/OpenSSH_2k.log_structured.csv` — 2,000 rows (parsed, unlabeled)

#### What You Need
Real syslog/auth log data with attack labels. Current syslog-specific data is only ~4K rows and unlabeled.

#### Dataset 1: LANL Comprehensive Cybersecurity Dataset (★ PRIMARY)
- **Source**: Los Alamos National Laboratory
- **URL**: https://csr.lanl.gov/data/cyber1/
- **Size**: ~12 GB compressed (auth.txt.gz = 1.2 GB, the key file)
- **Rows**: 1,051,430,459 auth events over 58 days + 749 compromised users (redteam.txt.gz)
- **Labels**: Red team events explicitly labeled in `redteam.txt.gz` — user@computer compromises
- **Attack Types**: Lateral movement, credential compromise, privilege escalation, brute force
- **Normal Baseline**: 1 billion+ normal authentication events (perfect for anomaly detection)

```powershell
cd C:\CLIF\agents\Data\datasets\01_syslog_linux_auth\downloads

# Download auth events (~1.2 GB)
Invoke-WebRequest -Uri "https://csr.lanl.gov/data/cyber1/auth.txt.gz" -OutFile "auth.txt.gz"

# Download red team labels
Invoke-WebRequest -Uri "https://csr.lanl.gov/data/cyber1/redteam.txt.gz" -OutFile "redteam.txt.gz"
```

**Process into training data:**
```python
import pandas as pd
import gzip

# Auth format: time,src_user@src_domain,dst_user@dst_domain,src_computer,dst_computer,auth_type,logon_type,auth_orientation,success/failure
with gzip.open('auth.txt.gz', 'rt') as f:
    # Read first 2M lines (manageable sample)
    lines = [next(f) for _ in range(2_000_000)]

auth_df = pd.DataFrame(
    [line.strip().split(',') for line in lines],
    columns=['time', 'src_user_domain', 'dst_user_domain', 'src_computer', 'dst_computer',
             'auth_type', 'logon_type', 'auth_orientation', 'success']
)

# Load red team labels
redteam = pd.read_csv('redteam.txt.gz', compression='gzip',
                       names=['time', 'user_domain', 'src_computer', 'dst_computer'])
redteam['is_attack'] = 1

# Merge to label attacks
auth_df['label'] = 0  # default normal
# Match red team events by time + computers
# ... (join logic depends on your feature extractor)

# Stratified sample: 15K normal + 15K attack-adjacent windows
auth_stratified = ...  # balance and save
auth_stratified.to_csv('../lanl_auth_stratified.csv', index=False)
print(f"Saved {len(auth_stratified)} rows")
```

#### Dataset 2: Loghub Full Linux Syslog (★ SUPPLEMENT)
- **Source**: LogPAI / Loghub (already partially in your workspace)
- **URL**: https://zenodo.org/records/8196385
- **Description**: Full 25K+ Linux syslog entries (you already have 2K subset) with structured parsing
- **Status**: ✅ You already have the full 25,567-line Linux.log in `New_Dataset/Loghub/`

**Use the full dataset instead of the 2K sample:**
```python
import pandas as pd

# Parse the full raw syslog (already downloaded)
# At: C:\CLIF\agents\Data\New_Dataset\Loghub\Linux.log
with open(r'C:\CLIF\agents\Data\New_Dataset\Loghub\Linux.log') as f:
    lines = f.readlines()
print(f"Full Linux syslog: {len(lines)} lines")  # ~25,567
```

#### Dataset 3: Kaggle SSH Brute Force Logs
- **Source**: Kaggle
- **URL**: https://www.kaggle.com/datasets/joebeachcapital/ssh-brute-force-logs
- **Rows**: ~50K+ SSH auth events with brute force labels

```powershell
cd C:\CLIF\agents\Data\datasets\01_syslog_linux_auth\downloads
kaggle datasets download -d joebeachcapital/ssh-brute-force-logs
Expand-Archive ssh-brute-force-logs.zip -DestinationPath ssh-brute-force
```

#### Target After Download
| Source | Rows | Known Attacks | Anomaly Baseline |
|--------|------|--------------|-----------------|
| LANL auth (stratified) | 30,000 | Lateral movement, credential theft, priv-esc | ✅ 1B+ normal auth events |
| Full Linux syslog (Loghub) | 25,567 | Unlabeled (use for normal baseline) | ✅ Normal syslog |
| SSH brute force | ~50,000 | SSH brute force, unauthorized access | ✅ Normal SSH |
| OpenSSH 655K (already have) | 655,147 | Auth failures, break-in attempts | ✅ Normal SSH |
| **Total usable** | **30,000 stratified** | ✅ 5+ attack types | ✅ Massive normal baseline |

---

### Type 02 — Windows Event Log

#### What You Have
- `EVTX-ATTACK-SAMPLES/evtx_data.csv` — 9,886 rows covering 8 MITRE ATT&CK tactics
- `New_Dataset/Windows/baseline_security.evtx` — Normal baseline (binary, needs conversion)
- `New_Dataset/Windows/baseline_system.evtx` — Normal baseline (binary, needs conversion)

#### What You Need
More attack variety + normal baselines in CSV format.

#### Dataset 1: OTRF Security Datasets / Mordor (★ PRIMARY)
- **Source**: Open Threat Research Forge
- **URL**: https://securitydatasets.com/
- **GitHub**: https://github.com/OTRF/Security-Datasets
- **Size**: ~2 GB (full collection of JSON event logs from ATT&CK evaluations)
- **Attack Types**: 100+ techniques across all 14 MITRE ATT&CK tactics
- **Format**: JSON (Windows Event Log format, one event per line)

```powershell
cd C:\CLIF\agents\Data\datasets\02_windows_event_log\downloads

# Clone the dataset metadata
git clone --depth 1 https://github.com/OTRF/Security-Datasets.git

# The actual event data is in the releases / hosted files
# Download specific ATT&CK evaluation datasets
$datasets = @(
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_wmi_remote_event_subscription.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/covenant_installutil.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/covenant_powershell_execution.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/persistence/host/covenant_schtask_creation.zip"
)

foreach ($url in $datasets) {
    $filename = Split-Path $url -Leaf
    Invoke-WebRequest -Uri $url -OutFile $filename
    Expand-Archive $filename -DestinationPath "mordor_events" -Force
}
```

**Better approach — use the pre-compiled OTRF dataset:**
```powershell
# Download OTRF's pre-compiled large dataset (APT simulations)
# APT29 evaluation (used in MITRE ATT&CK evaluations)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip" -OutFile "apt29_day1.zip"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip" -OutFile "apt29_day2.zip"

Expand-Archive apt29_day1.zip -DestinationPath apt29_day1
Expand-Archive apt29_day2.zip -DestinationPath apt29_day2
```

#### Dataset 2: Kaggle Windows Event Logs (★ SUPPLEMENT — large normal baseline)
- **Source**: Kaggle
- **URL**: https://www.kaggle.com/datasets/joebeachcapital/windows-event-logs
- **Size**: ~500 MB
- **Rows**: 100K+ normal Windows events
- **Purpose**: Normal baseline for anomaly detection

```powershell
cd C:\CLIF\agents\Data\datasets\02_windows_event_log\downloads
kaggle datasets download -d joebeachcapital/windows-event-logs
Expand-Archive windows-event-logs.zip -DestinationPath windows-normal-baseline
```

#### Dataset 3: Convert Your Existing EVTX Baselines
```python
# Install evtx parser
# pip install python-evtx lxml

import Evtx.Evtx as evtx
import json
import csv

def evtx_to_csv(evtx_path, output_csv):
    rows = []
    with evtx.Evtx(evtx_path) as log:
        for record in log.records():
            try:
                xml = record.xml()
                # Parse XML to extract fields
                rows.append({
                    'timestamp': record.timestamp(),
                    'event_id': ...,  # parse from XML
                    'raw_xml': xml,
                    'label': 'normal'  # baseline files are normal
                })
            except:
                continue
    pd.DataFrame(rows).to_csv(output_csv, index=False)

evtx_to_csv(r'C:\CLIF\agents\Data\New_Dataset\Windows\baseline_security.evtx', 'baseline_security.csv')
evtx_to_csv(r'C:\CLIF\agents\Data\New_Dataset\Windows\baseline_system.evtx', 'baseline_system.csv')
```

#### Target After Download
| Source | Rows | Known Attacks | Anomaly Baseline |
|--------|------|--------------|-----------------|
| EVTX-ATTACK-SAMPLES (have) | 9,886 | 8 MITRE tactics | ❌ Attacks only |
| OTRF/Mordor APT29 | ~10,000 | Mimikatz, PowerShell, lateral movement, persistence, C2 | Mixed |
| Windows normal baseline (Kaggle) | ~100,000 | — | ✅ Normal operations |
| Converted EVTX baselines (have) | ~5,000 | — | ✅ Normal baselines |
| **Total usable** | **20,000+ stratified** | ✅ 14 MITRE tactics | ✅ Large normal baseline |

---

### Type 03 — Firewall / CEF

#### What You Have — ✅ SUFFICIENT
- `UNSW-NB15/unsw_stratified.csv` — 20,233 rows (balanced: 10K normal + 10K attacks)
- `UNSW-NB15/UNSW-NB15_1.csv` — 700K+ rows (full dataset)
- 10 attack categories: Fuzzers, Exploits, Generic, Reconnaissance, DoS, Backdoors, Analysis, Shellcode, Worms

#### Optional Enhancement: CIC-IDS2018 for Additional Firewall-Relevant Attacks
- **URL**: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
- **New Attacks**: Infiltration, DDoS-LOIC, Botnet, Heartbleed (more variety)

```powershell
cd C:\CLIF\agents\Data\datasets\03_firewall_cef\downloads
kaggle datasets download -d solarmainframe/ids-intrusion-csv
Expand-Archive ids-intrusion-csv.zip -DestinationPath cicids2018
```

#### Action Needed: CEF Formatting Wrapper
Your existing UNSW-NB15 data is in raw packet format. For firewall training, you'll want to add CEF-like field mapping during feature extraction. This is a **preprocessing step**, not a download step.

#### Target: 20,000 stratified rows ✅ (already have)

---

### Type 04 — Active Directory / LDAP

#### What You Have — ❌ NOTHING
- Only reused EVTX-ATTACK-SAMPLES (attacks against Windows, not AD-specific)
- No AD authentication logs, no Kerberos events, no LDAP events

#### Dataset 1: LANL Comprehensive Dataset — Auth Events (★ PRIMARY)
- **Source**: Los Alamos National Laboratory (same download as Type 01)
- **URL**: https://csr.lanl.gov/data/cyber1/
- **Key Files**: `auth.txt.gz` (1.2 GB) — contains Windows AD authentication events
- **Rows**: 1,051,430,459 authentication events (Kerberos, NTLM)
- **Labels**: `redteam.txt.gz` — 749 compromised user accounts with timestamps
- **AD Events Captured**: Logon/logoff, Kerberos TGT/TGS requests, authentication failures, network logons

> **Note**: This is the SAME download as Type 01. You only need to download it once and extract different features for AD vs Syslog training.

```powershell
# If not already downloaded for Type 01:
cd C:\CLIF\agents\Data\datasets\04_active_directory_ldap\downloads

Invoke-WebRequest -Uri "https://csr.lanl.gov/data/cyber1/auth.txt.gz" -OutFile "auth.txt.gz"
Invoke-WebRequest -Uri "https://csr.lanl.gov/data/cyber1/redteam.txt.gz" -OutFile "redteam.txt.gz"
```

**Extract AD-specific features:**
```python
import pandas as pd
import gzip

# Auth events have: time, src_user@domain, dst_user@domain, src_computer, dst_computer, auth_type, logon_type, auth_orientation, success/fail
# AD-relevant features to extract:
# - auth_type: Kerberos vs NTLM vs Negotiate
# - logon_type: Network (3), Interactive (2), Service (5), Batch (4), RemoteInteractive (10)
# - auth_orientation: LogOn vs TGS vs TGT vs AuthMap
# - Cross-computer authentication patterns (lateral movement indicator)
# - TGS request frequency per user (Kerberoasting indicator)
# - Failed auth bursts (password spraying)

with gzip.open('auth.txt.gz', 'rt') as f:
    # Read 5M lines for AD feature extraction
    lines = [next(f) for _ in range(5_000_000)]

df = pd.DataFrame(
    [l.strip().split(',') for l in lines],
    columns=['time','src_user_domain','dst_user_domain','src_computer','dst_computer',
             'auth_type','logon_type','auth_orientation','success']
)

# Filter for Kerberos events (AD-specific)
kerberos = df[df['auth_orientation'].isin(['TGS', 'TGT', 'LogOn'])]
print(f"Kerberos events: {len(kerberos)}")
```

#### Dataset 2: OTRF Mordor — AD Attack Simulations
- **Source**: OTRF Security Datasets
- **GitHub**: https://github.com/OTRF/Security-Datasets
- **Specific AD Attacks Available**:
  - DCSync (T1003.006) — `credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges`
  - Kerberoasting (T1558.003) — `credential_access/host/empire_rubeus_asktgs_createnetonly`
  - Pass-the-Hash (T1550.002) — `lateral_movement/host/`
  - Golden Ticket (T1558.001) — `credential_access/host/`
  - LDAP reconnaissance — `discovery/host/`

```powershell
cd C:\CLIF\agents\Data\datasets\04_active_directory_ldap\downloads

# Download AD-specific attack datasets from OTRF
$ad_attacks = @(
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_rubeus_asktgs_createnetonly.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/covenant_psexec_service_creation.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/discovery/host/cmd_service_query.zip",
    "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip"
)

foreach ($url in $ad_attacks) {
    $filename = Split-Path $url -Leaf
    Invoke-WebRequest -Uri $url -OutFile $filename
    Expand-Archive $filename -DestinationPath "mordor_ad_attacks" -Force
}
```

#### Dataset 3: Azure AD Sign-In Logs (Kaggle)
- **URL**: https://www.kaggle.com/datasets/joebeachcapital/azure-ad-sign-in-logs
- **Rows**: ~50K+ Azure AD authentication events
- **Contains**: Normal sign-ins, conditional access failures, risky sign-ins

```powershell
kaggle datasets download -d joebeachcapital/azure-ad-sign-in-logs
Expand-Archive azure-ad-sign-in-logs.zip -DestinationPath azure-ad-logs
```

#### Target After Download
| Source | Rows | Known Attacks | Anomaly Baseline |
|--------|------|--------------|-----------------|
| LANL auth (AD-focused stratified) | 15,000 | Lateral movement, credential theft | ✅ Massive normal auth |
| OTRF Mordor AD attacks | ~3,000 | DCSync, Kerberoasting, Pass-the-Hash, Golden Ticket | Mixed |
| Azure AD logs | ~50,000 | Risky sign-ins, conditional access failures | ✅ Normal sign-ins |
| **Total usable** | **20,000 stratified** | ✅ 6+ AD attack types | ✅ Large normal baseline |

---

### Type 05 — DNS Logs

#### What You Have — ✅ MOSTLY SUFFICIENT
- `CIC-Bell-DNS-EXFil/CSV_benign.csv` — 265 MB (massive benign DNS dataset)
- `CIC-Bell-DNS-EXFil/CSV_malware.csv` — 5,001 rows (malware C2 domains)
- `CIC-Bell-DNS-EXFil/CSV_phishing.csv` — 5,001 rows (phishing domains)
- `CIC-Bell-DNS-EXFil/CSV_spam.csv` — 4,337 rows (spam domains)
- `New_Dataset/CIC-Bell-DNS-EXFil-2021/` — 28 more CSVs with stateful/stateless features
- Total existing: ~280 MB of DNS data with labels

#### Optional Enhancement: DGA Domain Dataset
For better coverage of DGA (Domain Generation Algorithm) attacks:

- **Source**: DGTA / Kaggle DGA Dataset
- **URL**: https://www.kaggle.com/datasets/aryashah2k/domain-generation-algorithm-dga-dataset
- **Rows**: ~70K domains with DGA family labels (bamital, conficker, cryptolocker, matsnu, etc.)
- **Purpose**: Detect C2 communication using algorithmically generated domains

```powershell
cd C:\CLIF\agents\Data\datasets\05_dns_logs\downloads
kaggle datasets download -d aryashah2k/domain-generation-algorithm-dga-dataset
Expand-Archive domain-generation-algorithm-dga-dataset.zip -DestinationPath dga-domains
```

#### Optional Enhancement: DNS Tunneling Dataset
- **URL**: https://www.kaggle.com/datasets/brantley67/dns-tunnel-dataset
- **Rows**: Labeled DNS tunneling traffic (iodine, dnscat2, dns2tcp)

```powershell
kaggle datasets download -d brantley67/dns-tunnel-dataset
Expand-Archive dns-tunnel-dataset.zip -DestinationPath dns-tunneling
```

#### Target: 20,000+ stratified rows ✅ (already have sufficient, DGA adds diversity)

---

### Type 06 — AWS CloudTrail / Cloud Audit

#### What You Have — ❌ NOTHING
- Only Sigma YAML detection rules in the directory

#### Dataset 1: Stratus Red Team CloudTrail Logs (★ PRIMARY)
- **Source**: DataDog Stratus Red Team
- **GitHub**: https://github.com/DataDog/stratus-red-team
- **What It Is**: A tool that executes real AWS attacks and captures CloudTrail JSON logs
- **Attack Types**: 25+ cloud attack techniques mapped to MITRE ATT&CK:
  - Privilege Escalation: CreateAdminUser, AddUserToGroup, AttachAdminPolicy
  - Credential Access: StealEC2InstanceCredentials, InstanceProfileExfil
  - Defense Evasion: StopCloudTrailLogging, DeleteTrailLogging
  - Discovery: EnumerateRoles, ListSecrets
  - Collection: S3Exfiltration, SSMRetrieveDocuments
  - Exfiltration: EBSSnapshotSharing, AMISharing
  - Impact: S3ObjectDeletion
- **Format**: CloudTrail JSON events

**Option A: Use Pre-Generated CloudTrail Logs (no AWS account needed)**

```powershell
cd C:\CLIF\agents\Data\datasets\06_aws_cloudtrail\downloads

# Clone stratus-red-team (has example detonation logs)
git clone --depth 1 https://github.com/DataDog/stratus-red-team.git
```

**Option B: Generate Your Own (requires AWS account)**
```powershell
# Install stratus-red-team
Invoke-WebRequest -Uri "https://github.com/DataDog/stratus-red-team/releases/latest/download/stratus-red-team_Windows_x86_64.zip" -OutFile stratus.zip
Expand-Archive stratus.zip -DestinationPath stratus

# List available attack techniques
.\stratus\stratus.exe list

# Detonate and capture CloudTrail logs (each creates ~50-200 events)
.\stratus\stratus.exe detonate aws.credential-access.ec2-get-credentials
.\stratus\stratus.exe detonate aws.defense-evasion.cloudtrail-stop
.\stratus\stratus.exe detonate aws.exfiltration.s3-backdoor-bucket-policy
# ... run all 25+ techniques
```

#### Dataset 2: CloudTrail Attack Dataset (Kaggle)
- **URL**: https://www.kaggle.com/datasets/yangzhanghungry/realistic-cloudtrail-security-dataset
- **Rows**: 50K+ synthetic but realistic CloudTrail events
- **Labels**: Normal operations + attack events (privilege escalation, data exfiltration)
- **Includes**: Normal API calls (EC2/S3/IAM describe, list, get) + attack patterns

```powershell
kaggle datasets download -d yangzhanghungry/realistic-cloudtrail-security-dataset
Expand-Archive realistic-cloudtrail-security-dataset.zip -DestinationPath cloudtrail-dataset
```

#### Dataset 3: Generate Synthetic Normal CloudTrail
Since CloudTrail has a predictable format, generate normal baselines:

```python
import json
import random
from datetime import datetime, timedelta

normal_events = []
base_time = datetime(2024, 1, 15, 8, 0, 0)

# Normal API calls pattern for a typical day
normal_api_calls = [
    ("DescribeInstances", "ec2.amazonaws.com", "us-east-1"),
    ("ListBuckets", "s3.amazonaws.com", "us-east-1"),
    ("GetObject", "s3.amazonaws.com", "us-east-1"),
    ("PutObject", "s3.amazonaws.com", "us-east-1"),
    ("DescribeLogGroups", "logs.amazonaws.com", "us-east-1"),
    ("GetMetricData", "monitoring.amazonaws.com", "us-east-1"),
    ("ListFunctions20150331", "lambda.amazonaws.com", "us-east-1"),
    ("AssumeRole", "sts.amazonaws.com", "us-east-1"),
    ("GetCallerIdentity", "sts.amazonaws.com", "us-east-1"),
]

for i in range(10000):
    api, source, region = random.choice(normal_api_calls)
    event = {
        "eventTime": (base_time + timedelta(seconds=i*3)).isoformat() + "Z",
        "eventName": api,
        "eventSource": source,
        "awsRegion": region,
        "sourceIPAddress": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
        "userAgent": "aws-cli/2.x Python/3.x",
        "userIdentity": {"type": "IAMUser", "userName": f"user-{random.randint(1,20)}"},
        "errorCode": None,
        "readOnly": api.startswith(("Describe", "List", "Get")),
        "label": "normal"
    }
    normal_events.append(event)

# Save
import pandas as pd
pd.DataFrame(normal_events).to_csv('cloudtrail_normal_baseline.csv', index=False)
```

#### Target After Download
| Source | Rows | Known Attacks | Anomaly Baseline |
|--------|------|--------------|-----------------|
| Stratus Red Team detonations | ~3,000 | 25+ MITRE cloud techniques | Mixed |
| Kaggle CloudTrail dataset | ~50,000 | Priv-esc, data exfil, defense evasion | ✅ Normal API calls |
| Synthetic normal baseline | 10,000 | — | ✅ Normal operations |
| **Total usable** | **15,000+ stratified** | ✅ 6+ cloud attack categories | ✅ Large normal baseline |

---

### Type 07 — Kubernetes Audit

#### What You Have — ❌ NOTHING
- Only Falco source code and kube-hunter source code (tools, not data)

#### Dataset 1: Kubernetes Audit Log Dataset (★ PRIMARY)
- **Source**: There is no single large public K8s audit dataset. The best approach is a combination:

**Option A: Falco-Generated Events (Recommended)**

Falco can generate labeled K8s security events. Use the Falco test framework:

```powershell
cd C:\CLIF\agents\Data\datasets\07_kubernetes_audit\downloads

# Download Falco's event-generator (creates real K8s audit-style events)
Invoke-WebRequest -Uri "https://github.com/falcosecurity/event-generator/releases/latest/download/event-generator_windows_amd64.tar.gz" -OutFile event-generator.tar.gz
```

**Option B: Kubernetes Goat Audit Logs**
- **URL**: https://github.com/madhuakula/kubernetes-goat
- **Description**: Vulnerable K8s environment that generates labeled audit logs
- **Attack types**: Container escape, RBAC abuse, secrets theft, cryptomining, reverse shell

```powershell
git clone --depth 1 https://github.com/madhuakula/kubernetes-goat.git
```

#### Dataset 2: Generate K8s Audit Logs from Minikube/Kind

The most practical approach for K8s audit data is to **generate it yourself** using a local cluster:

```powershell
# Install Kind (Kubernetes in Docker)
Invoke-WebRequest -Uri "https://kind.sigs.k8s.io/dl/v0.20.0/kind-windows-amd64" -OutFile kind.exe

# Create cluster with audit logging enabled
# (Requires a kind config YAML enabling audit policy)
```

```python
# generate_k8s_audit_training_data.py
import json
import random
from datetime import datetime, timedelta

# K8s audit event template
normal_verbs = ["get", "list", "watch"]
attack_verbs = ["create", "delete", "patch", "exec"]
normal_resources = ["pods", "services", "deployments", "configmaps", "namespaces"]
sensitive_resources = ["secrets", "clusterroles", "clusterrolebindings", "serviceaccounts"]

events = []
base_time = datetime(2024, 1, 15, 8, 0, 0)

# Normal events (80%)
for i in range(8000):
    events.append({
        "timestamp": (base_time + timedelta(seconds=i*5)).isoformat() + "Z",
        "verb": random.choice(normal_verbs),
        "resource": random.choice(normal_resources),
        "namespace": random.choice(["default", "kube-system", "monitoring"]),
        "user": f"system:serviceaccount:kube-system:kube-{random.choice(['scheduler','controller-manager','proxy'])}",
        "source_ip": f"10.244.{random.randint(0,3)}.{random.randint(1,254)}",
        "response_code": 200,
        "label": "normal"
    })

# Attack events (20%) — mapped to real K8s attack patterns
attack_patterns = [
    {"verb": "create", "resource": "pods", "namespace": "default",
     "user": "attacker", "annotation": "privileged_container", "label": "container_escape"},
    {"verb": "get", "resource": "secrets", "namespace": "kube-system",
     "user": "compromised-sa", "annotation": "secrets_access", "label": "secrets_theft"},
    {"verb": "exec", "resource": "pods", "namespace": "default",
     "user": "attacker", "annotation": "exec_into_pod", "label": "remote_execution"},
    {"verb": "create", "resource": "clusterrolebindings", "namespace": "",
     "user": "attacker", "annotation": "rbac_escalation", "label": "privilege_escalation"},
    {"verb": "create", "resource": "deployments", "namespace": "default",
     "user": "attacker", "annotation": "cryptominer_deployment", "label": "cryptomining"},
    {"verb": "delete", "resource": "pods", "namespace": "kube-system",
     "user": "attacker", "annotation": "disruption", "label": "denial_of_service"},
]

for i in range(2000):
    pattern = random.choice(attack_patterns)
    events.append({
        "timestamp": (base_time + timedelta(seconds=i*10 + random.randint(0,5))).isoformat() + "Z",
        "verb": pattern["verb"],
        "resource": pattern["resource"],
        "namespace": pattern["namespace"],
        "user": pattern["user"],
        "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        "response_code": random.choice([200, 201, 403]),
        "label": pattern["label"]
    })

import pandas as pd
df = pd.DataFrame(events).sample(frac=1).reset_index(drop=True)
df.to_csv('k8s_audit_training.csv', index=False)
print(f"Generated {len(df)} K8s audit events ({df['label'].value_counts().to_dict()})")
```

#### Dataset 3: DARPA Transparent Computing (TC) Dataset
- **Source**: DARPA TC Engagement
- **URL**: https://github.com/darpa-i2o/Transparent-Computing
- **Contains**: Host audit logs including container events, provenance graphs
- **Rows**: Millions of system events across multi-host exercises

```powershell
git clone --depth 1 https://github.com/darpa-i2o/Transparent-Computing.git
```

#### Target After Download
| Source | Rows | Known Attacks | Anomaly Baseline |
|--------|------|--------------|-----------------|
| Synthetic K8s audit events | 10,000 | Container escape, secrets theft, RBAC abuse, cryptomining | ✅ Normal K8s ops |
| Falco event-generator | ~2,000 | Falcosecurity rule-based events | Mixed |
| DARPA TC dataset | ~5,000 (stratified) | Host/container compromise | ✅ Normal system calls |
| **Total usable** | **10,000+ stratified** | ✅ 6+ K8s attack types | ✅ Normal K8s operations |

---

### Type 08 — Web Server (Nginx/Apache)

#### What You Have — ✅ SUFFICIENT
- `CSIC_2010/csic_database.csv` — 61,065 rows (SQLi, XSS, path traversal, param tampering)
- `Loghub Apache/Apache_2k.log_structured.csv` — 2,000 rows (normal Apache logs)

#### Optional Enhancement: FWAF Dataset
- **Source**: Kaggle
- **URL**: https://www.kaggle.com/datasets/ispangler/fwaf-dataset
- **Rows**: 100K+ HTTP requests labeled as normal/attack
- **Attack Types**: SQL injection, XSS, command injection, path traversal, LDAP injection

```powershell
cd C:\CLIF\agents\Data\datasets\08_nginx_web_server\downloads
kaggle datasets download -d ispangler/fwaf-dataset
Expand-Archive fwaf-dataset.zip -DestinationPath fwaf
```

#### Optional Enhancement: HTTP CSIC 2010 Extended + Normal Web Traffic
```python
# Use existing CSIC 2010 (already ~61K) + generate normal web traffic

import pandas as pd
import random

normal_urls = [
    "/index.html", "/api/v1/users", "/api/v1/products", "/static/css/main.css",
    "/static/js/app.js", "/images/logo.png", "/api/health", "/favicon.ico",
    "/api/v1/search?q=laptop", "/dashboard", "/login", "/api/v1/orders",
]

normal_events = []
for i in range(10000):
    normal_events.append({
        "method": random.choice(["GET", "GET", "GET", "POST", "PUT"]),
        "url": random.choice(normal_urls),
        "status": random.choice([200, 200, 200, 200, 301, 304, 404]),
        "body": "",
        "label": "normal"
    })

pd.DataFrame(normal_events).to_csv('web_normal_baseline.csv', index=False)
```

#### Target: 20,000+ stratified rows ✅ (already have 61K CSIC + 2K Apache)

---

### Type 09 — NetFlow / IPFIX

#### What You Have — ✅ FULLY SUFFICIENT
- `NF-UNSW-NB15-v3/nf_unsw_stratified.csv` — 12,000 rows (balanced)
- `NF-UNSW-NB15-v3/NF-UNSW-NB15-v3.csv` — 550 MB (full dataset)
- `nf_ton_iot_temporal.csv` — 11,341 rows
- `NF-ToN-IoT-v3.csv` — 5,057 MB (massive full dataset)
- Normal-only subsets already extracted (10K each)

#### No Downloads Needed ✅

Your NetFlow data covers:
- **Known attacks**: DDoS, port scan, reconnaissance, exploits, fuzzers, backdoors, botnets
- **Normal baseline**: 10K+ normal flow records
- **Anomaly capability**: Both stratified labeled + massive full datasets

---

### Type 10 — IDS/IPS / Zeek

#### What You Have — ✅ MOSTLY SUFFICIENT
- `NSL-KDD/nsl_kdd_stratified.csv` — 24,607 rows (23 attack types)
- `CICIDS2017/cicids2017_stratified.csv` — 30,193 rows (12 attack types)
- `CICIDS2017/` full day CSVs — ~2.8M rows total

#### Optional Enhancement: CIC-IDS2018
- **Source**: Canadian Institute for Cybersecurity
- **URL**: https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv
- **Rows**: 6M+ events
- **New Attack Types Beyond CICIDS2017**: Infiltration (more samples), SQL injection, DDoS attacks (LOIC/HOIC variants), Botnet (Ares)

```powershell
cd C:\CLIF\agents\Data\datasets\10_ids_ips_zeek\downloads
kaggle datasets download -d solarmainframe/ids-intrusion-csv
Expand-Archive ids-intrusion-csv.zip -DestinationPath cicids2018
```

#### Target: 30,000+ stratified rows ✅ (already have 54K combined)

---

## 4. Layer 2 — Synthetic Normal + Anomaly Injection

After downloading all Layer 1 datasets, you need Layer 2: synthetic normal baselines + injected anomalies for log types that lack pure normal data.

### Generation Script

```python
# generate_layer2_data.py
"""
Generates Layer 2 training data:
- 10K normal events per log type (8 types that need it)
- 2K injected anomalies per log type
Total: 80K normal + 16K anomalies = 96K events
"""

import pandas as pd
import numpy as np
import random
import json
from datetime import datetime, timedelta

rng = np.random.default_rng(42)


def generate_syslog_normal(n=10000):
    """Normal Linux syslog events"""
    templates = [
        "CRON[{pid}]: (root) CMD ({cmd})",
        "systemd[1]: Started {service}.",
        "sshd[{pid}]: Accepted publickey for {user} from {ip} port {port} ssh2",
        "kernel: [{time}] audit: type=1100 audit({epoch}): pid={pid} uid={uid} auid={auid}",
        "sudo: {user} : TTY=pts/{tty} ; PWD={pwd} ; USER=root ; COMMAND={cmd}",
        "systemd[1]: Starting {service}...",
        "rsyslogd: [origin software=\"rsyslogd\"] start",
        "ntpd[{pid}]: adjusting local clock by {drift}s",
    ]
    events = []
    base = datetime(2024, 3, 15, 0, 0, 0)
    for i in range(n):
        t = base + timedelta(seconds=rng.integers(0, 86400))
        events.append({
            "timestamp": t.isoformat(),
            "facility": random.choice(["auth", "kern", "daemon", "cron", "syslog"]),
            "severity": random.choice(["info", "notice", "warning"]),
            "hostname": f"srv-{rng.integers(1, 50):03d}",
            "message": random.choice(templates).format(
                pid=rng.integers(1000, 65535), cmd=random.choice(["/usr/bin/logrotate", "/bin/sh -c run-parts", "certbot renew"]),
                service=random.choice(["nginx", "postgresql", "docker", "cron"]),
                user=random.choice(["admin", "deploy", "monitor"]),
                ip=f"10.0.{rng.integers(1,254)}.{rng.integers(1,254)}", port=rng.integers(40000, 65535),
                time=f"{rng.integers(100,999)}.{rng.integers(100,999)}", epoch=f"{int(t.timestamp())}",
                uid=rng.integers(0, 1000), auid=rng.integers(0, 65535), tty=rng.integers(0, 5),
                pwd=random.choice(["/root", "/home/admin", "/var/log"]),
                drift=f"{rng.uniform(-0.01, 0.01):.6f}"
            ),
            "label": "normal",
            "attack_type": "normal"
        })
    return pd.DataFrame(events)


def inject_syslog_anomalies(n=2000):
    """Inject syslog attack patterns"""
    events = []
    base = datetime(2024, 3, 15, 2, 0, 0)  # attacks often at odd hours

    # 500 brute force sequences
    for i in range(500):
        t = base + timedelta(seconds=i * 2)
        events.append({
            "timestamp": t.isoformat(),
            "facility": "auth", "severity": "warning",
            "hostname": f"srv-{rng.integers(1, 5):03d}",
            "message": f"sshd[{rng.integers(1000,9999)}]: Failed password for {'root' if i%3==0 else 'admin'} from {rng.integers(50,200)}.{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)} port {rng.integers(40000,65535)} ssh2",
            "label": "attack", "attack_type": "brute_force"
        })

    # 500 privilege escalation
    for i in range(500):
        t = base + timedelta(hours=1, seconds=i * 5)
        events.append({
            "timestamp": t.isoformat(),
            "facility": "auth", "severity": "error",
            "hostname": f"srv-{rng.integers(1, 5):03d}",
            "message": f"sudo: unknown_user : user NOT in sudoers ; TTY=pts/{rng.integers(0,5)} ; COMMAND=/bin/bash",
            "label": "attack", "attack_type": "privilege_escalation"
        })

    # 500 unusual process spawns
    for i in range(500):
        t = base + timedelta(hours=2, seconds=i * 3)
        events.append({
            "timestamp": t.isoformat(),
            "facility": "kern", "severity": "alert",
            "hostname": f"srv-{rng.integers(1, 5):03d}",
            "message": f"audit: type=1400 msg=audit({int(t.timestamp())}): apparmor=\"DENIED\" operation=\"exec\" name=\"/tmp/.{rng.integers(1000,9999)}\"",
            "label": "attack", "attack_type": "suspicious_process"
        })

    # 500 after-hours root access
    for i in range(500):
        night_hour = rng.integers(1, 5)
        t = base.replace(hour=night_hour) + timedelta(seconds=i * 10)
        events.append({
            "timestamp": t.isoformat(),
            "facility": "auth", "severity": "info",
            "hostname": f"srv-{rng.integers(1, 50):03d}",
            "message": f"sshd[{rng.integers(1000,9999)}]: Accepted password for root from {rng.integers(50,200)}.{rng.integers(1,254)}.{rng.integers(1,254)}.{rng.integers(1,254)} port {rng.integers(40000,65535)} ssh2",
            "label": "attack", "attack_type": "after_hours_access"
        })

    return pd.DataFrame(events)


# Generate for all 8 log types that need Layer 2
# (NetFlow and IDS are covered by Layer 1)

print("Generating Layer 2 data...")

syslog_normal = generate_syslog_normal(10000)
syslog_attacks = inject_syslog_anomalies(2000)
syslog_l2 = pd.concat([syslog_normal, syslog_attacks], ignore_index=True).sample(frac=1, random_state=42)
syslog_l2.to_csv('layer2_syslog.csv', index=False)
print(f"Syslog Layer 2: {len(syslog_l2)} rows ({syslog_l2['label'].value_counts().to_dict()})")

# Similar functions for: windows, firewall, ad, dns, cloud, k8s, web
# (Following the same pattern as above, with domain-specific templates)
# Each generates 10K normal + 2K attacks = 12K per type

print("\\nLayer 2 generation complete!")
print("Total: 8 types × 12K = 96K events")
```

> **NOTE**: The full Layer 2 generation script should be built during Sprint 3 of the implementation plan. The key templates for each log type are defined in `AI_AGENTS_IMPLEMENTATION_PLAN.md` Section 5 (Layer 2 table). The script above shows the pattern for syslog — replicate it for all 8 types.

---

## 5. Post-Download Verification Checklist

Run this script after all downloads to verify data completeness:

```python
# verify_downloads.py
import os
import pandas as pd
import glob

base = r"C:\CLIF\agents\Data\datasets"
results = []

requirements = {
    "01_syslog_linux_auth": {"min_rows": 20000, "needs": ["normal", "attack"]},
    "02_windows_event_log": {"min_rows": 15000, "needs": ["normal", "attack"]},
    "03_firewall_cef": {"min_rows": 20000, "needs": ["normal", "attack"]},
    "04_active_directory_ldap": {"min_rows": 15000, "needs": ["normal", "attack"]},
    "05_dns_logs": {"min_rows": 20000, "needs": ["normal", "attack"]},
    "06_aws_cloudtrail": {"min_rows": 10000, "needs": ["normal", "attack"]},
    "07_kubernetes_audit": {"min_rows": 10000, "needs": ["normal", "attack"]},
    "08_nginx_web_server": {"min_rows": 20000, "needs": ["normal", "attack"]},
    "09_netflow_ipfix": {"min_rows": 20000, "needs": ["normal", "attack"]},
    "10_ids_ips_zeek": {"min_rows": 20000, "needs": ["normal", "attack"]},
}

for dir_name, req in requirements.items():
    dir_path = os.path.join(base, dir_name)
    csv_files = glob.glob(os.path.join(dir_path, "**/*.csv"), recursive=True)

    total_rows = 0
    has_normal = False
    has_attack = False
    file_count = 0

    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file, nrows=5)
            row_count = sum(1 for _ in open(csv_file)) - 1  # fast line count
            total_rows += row_count
            file_count += 1

            # Check for label columns
            label_cols = [c for c in df.columns if c.lower() in ['label', 'class', 'attack_type', 'is_attack', 'Label', 'attack_cat']]
            if label_cols:
                sample = pd.read_csv(csv_file, usecols=label_cols, nrows=1000)
                values = sample.iloc[:, 0].astype(str).str.lower().unique()
                if any(v in ['normal', 'benign', '0', 'false', 'legitimate'] for v in values):
                    has_normal = True
                if any(v not in ['normal', 'benign', '0', 'false', 'legitimate', 'nan'] for v in values):
                    has_attack = True
        except:
            continue

    status = "✅ PASS" if total_rows >= req["min_rows"] and has_normal and has_attack else "❌ FAIL"

    results.append({
        "Directory": dir_name,
        "CSV Files": file_count,
        "Total Rows": total_rows,
        f"Min Required ({req['min_rows']})": "✅" if total_rows >= req['min_rows'] else f"❌ ({total_rows}/{req['min_rows']})",
        "Has Normal": "✅" if has_normal else "❌",
        "Has Attack": "✅" if has_attack else "❌",
        "Overall": status
    })

results_df = pd.DataFrame(results)
print(results_df.to_string(index=False))

# Summary
passed = sum(1 for r in results if r["Overall"] == "✅ PASS")
print(f"\n{'='*50}")
print(f"PASSED: {passed}/10 log types")
print(f"TOTAL ROWS AVAILABLE: {sum(r['Total Rows'] for r in results):,}")
if passed < 10:
    print("\n⚠️ ACTION NEEDED:")
    for r in results:
        if r["Overall"] == "❌ FAIL":
            print(f"  - {r['Directory']}: {r['Total Rows']} rows, Normal={'✅' if r['Has Normal']=='✅' else '❌'}, Attack={'✅' if r['Has Attack']=='✅' else '❌'}")
```

---

## 6. Final Dataset Assembly

After all downloads are verified, assemble into the unified training file:

### Step 1: Per-Type Stratified Sampling
```python
# For each of the 10 log types, create a balanced stratified sample:
# - 50% normal events
# - 50% attack events (balanced across attack categories)
# - Target 20K-30K rows per type

# Use the existing stratification pattern from retrain_v4.py:
# Example for syslog:
from sklearn.model_selection import train_test_split

df = pd.read_csv('lanl_auth_stratified.csv')
# Balance: undersample majority class
normal = df[df['label'] == 'normal'].sample(n=15000, random_state=42)
attack = df[df['label'] != 'normal'].sample(n=min(15000, len(df[df['label']!='normal'])), random_state=42)
balanced = pd.concat([normal, attack])
```

### Step 2: Feature Extraction
```
# Run through the NEW feature_extractor.py (32 features, 4 tracks)
# As defined in AI_AGENTS_IMPLEMENTATION_PLAN.md Phase 2
# Universal(12) + Network(8) + Text(6) + Behavioral(6) = 32 features
```

### Step 3: Merge into features_combined_v5.csv
```python
# Merge all 10 types + Layer 2 into one file
all_dfs = []
for log_type in range(1, 11):
    df = pd.read_csv(f'features_type_{log_type:02d}.csv')
    df['source_type'] = log_type
    all_dfs.append(df)

# Add Layer 2 synthetic data
for log_type in ['syslog', 'windows', 'firewall', 'ad', 'dns', 'cloud', 'k8s', 'web']:
    df = pd.read_csv(f'layer2_{log_type}.csv')
    all_dfs.append(df)

combined = pd.concat(all_dfs, ignore_index=True).sample(frac=1, random_state=42)
combined.to_csv('features_combined_v5.csv', index=False)
print(f"Final training file: {len(combined)} rows, {combined['label'].value_counts()}")
# Expected: ~296K rows
```

---

## Quick Reference: Download Priority Order

### 🔴 Step 1 — Download These FIRST (Critical Missing Data)

| Priority | Log Type | Dataset | Command | Size |
|----------|----------|---------|---------|------|
| P0 | **04 AD** | LANL auth.txt.gz | `Invoke-WebRequest "https://csr.lanl.gov/data/cyber1/auth.txt.gz"` | 1.2 GB |
| P0 | **04 AD** | LANL redteam.txt.gz | `Invoke-WebRequest "https://csr.lanl.gov/data/cyber1/redteam.txt.gz"` | 1 MB |
| P0 | **06 Cloud** | Kaggle CloudTrail Security | `kaggle datasets download -d yangzhanghungry/realistic-cloudtrail-security-dataset` | ~100 MB |
| P0 | **06 Cloud** | Stratus Red Team | `git clone https://github.com/DataDog/stratus-red-team.git` | ~50 MB |
| P0 | **07 K8s** | DARPA TC dataset | `git clone https://github.com/darpa-i2o/Transparent-Computing.git` | ~200 MB |

### 🟡 Step 2 — Download These NEXT (Insufficient / Weak Diversity)

| Priority | Log Type | Dataset | Why Needed | Command | Size |
|----------|----------|---------|-----------|---------|------|
| P1 | **01 Syslog** | LANL auth.txt.gz | Only 4K syslog-specific data | (Same as P0 — reuse for syslog features) | (already downloaded) |
| P1 | **02 Windows** | OTRF Mordor APT29 | Only attack samples, no normal baseline | `Invoke-WebRequest "...apt29_evals_day1_manual.zip"` | ~500 MB |
| P1 | **02 Windows** | Kaggle Windows Events | Need normal baseline for anomaly detection | `kaggle datasets download -d joebeachcapital/windows-event-logs` | ~500 MB |
| P1 | **05 DNS** | DGA Domain Dataset | Existing DNS has only 3 attack types — need DGA families | `kaggle datasets download -d aryashah2k/domain-generation-algorithm-dga-dataset` | ~10 MB |
| P1 | **08 Web** | FWAF Dataset | CSIC has NO attack sub-types (all labeled "Anomalous") — FWAF adds SQLi/XSS/cmd-injection labels | `kaggle datasets download -d ispangler/fwaf-dataset` | ~50 MB |

### 🟢 Step 3 — Optional Enhancements

| Priority | Log Type | Dataset | Command | Size |
|----------|----------|---------|---------|------|
| P2 | **05 DNS** | DNS Tunnel Dataset | `kaggle datasets download -d brantley67/dns-tunnel-dataset` | ~20 MB |
| P2 | **10 IDS** | CIC-IDS2018 | `kaggle datasets download -d solarmainframe/ids-intrusion-csv` | ~2 GB |

---

## Disk Space Requirements

| Category | Size Estimate |
|----------|---------------|
| Already on disk | ~10 GB (heavily duplicated CICIDS2017, UNSW, NF-ToN-IoT) |
| New downloads (P0) | ~1.6 GB |
| New downloads (P1) | ~1.1 GB |
| New downloads (P2) | ~2.0 GB |
| Layer 2 synthetic | ~50 MB (generated, not downloaded) |
| **Total new disk space** | **~4.8 GB** |

---

## Important Notes

1. **LANL is your most valuable single download** — it covers both Type 01 (Syslog) and Type 04 (AD) from one 1.2 GB file. Download it first.

2. **Kaggle API is required** for 5 of the downloads. Set it up before starting (see Prerequisites).

3. **Types 03 and 09 need NO new downloads** — they already have sufficient labeled data with both normal and attack samples. Types 05 (DNS) and 08 (Web) have enough volume but lack attack-type diversity — the P1 downloads fix this.

4. **Type 07 (K8s) is the hardest** — no large public labeled K8s audit dataset exists. You'll rely on synthetic generation + DARPA TC data. This is acceptable because K8s audit logs have a very structured format and synthetic data closely matches real patterns.

5. **Deduplication**: Before building features_combined_v5.csv, deduplicate the CICIDS2017 data that's currently copied across 4 directories (01, 02, 03, 10). Use only one copy.

6. **All datasets listed above are free and publicly available.** No paid datasets or restricted-access data is required.

7. **Both known AND anomaly detection coverage** is ensured by:
   - **Known attacks**: Each dataset has labeled attack categories (supervised training for LightGBM)
   - **Anomaly detection**: Each dataset has labeled normal baselines (unsupervised training for Autoencoder) + Layer 2 provides additional synthetic normal data and rare anomaly injections
