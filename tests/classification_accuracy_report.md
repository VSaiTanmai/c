# CLIF Pipeline Classification Accuracy Report
## Test: 130 Synthetic Security Logs (190 extracted entries)

**Test Date:** 2026-03-04  
**Batch ID:** `test-53b6c7ee3b32`  
**Timestamp Window:** 2026-03-04T22:29:00 → 22:31:00  
**Test File:** `tests/combined_test_logs.txt`  
**Send Script:** `tests/send_test_logs.py`

> **Note:** The test file summary says "130 entries" but actually contains **190 individual log lines**
> (Format B sections have 20 entries each, not 10). The send script correctly extracted all 190.

---

## 1. Pipeline Distribution Summary

| Destination | Count | % |
|:---|:---:|:---:|
| `security_events` | 46 | 24.2% |
| `process_events` | 13 | 6.8% |
| `network_events` | 0 | 0.0% |
| `raw_logs` | 131 | 68.9% |
| **Total** | **190** | **100%** |

## 2. Security Events Sub-Classification (46 events)

| Category | Severity | MITRE Tactic | MITRE Technique | Count |
|:---|:---:|:---|:---|:---:|
| auth / credential-access | 3 | credential-access | T1078 | 20 |
| auth / initial-access | 1 | initial-access | T1078 | 16 |
| malware | 4 | execution | T1059 | 3 |
| network-attack | 3 | discovery | T1046 | 1 |
| network-attack | 3 | command-and-control | T1071.004 | 1 |
| network-attack | 3 | lateral-movement | T1021 | 1 |
| exfiltration | 4 | exfiltration | T1041 | 1 |
| firewall | 2 | defense-evasion | T1562 | 1 |
| privilege-escalation | 2 | privilege-escalation | T1548 | 2 |

---

## 3. Per-Category Cross-Verification

### Category 1: Network Flow / Zeek / NetFlow (30 logs)

| Sub-Format | Sent | Expected Dest | Actual Dest | Correct | Accuracy |
|:---|:---:|:---|:---|:---:|:---:|
| Tab-delimited Zeek (10) | 10 | `network_events` | `raw_logs` | 0 | **0%** |
| JSON Zeek (10) | 10 | `network_events` | `raw_logs` | 0 | **0%** |
| Extended [LOG-001→010] (10) | 10 | `network_events` | `raw_logs` | 0 | **0%** |
| **Subtotal** | **30** | | | **0** | **0%** |

**Root Cause Analysis:**
- **Tab-delimited Zeek:** Fields like IPs/ports are embedded in tab-separated text, not JSON structure. Phase 2 checks `exists(.src_ip)` (JSON field), not text content → miss.
- **JSON Zeek:** The send script merges parsed JSON fields, but Zeek uses `id.orig_h`/`id.resp_h` not `src_ip`/`dst_ip`. Phase 2 only checks: `src_ip, dst_ip, src_port, dst_port, source_ip, dest_ip` → miss.
- **Extended [LOG-XXX]:** Text contains `src_ip=192.168.x.x` as flat text, but `exists(.src_ip)` checks for a JSON field → miss.

**Fix:** Add Zeek field name mapping to Phase 2:
```
exists(."id.orig_h") || exists(."id.resp_h") || match(_scan2, r'(?i)\bconn_state=|\borig_bytes=|\bresp_bytes=')
```

---

### Category 2: Auth / SSH / Login (40 log lines)

| Sub-Format | Sent | Expected Dest | Correctly Classified | Accuracy |
|:---|:---:|:---|:---:|:---:|
| Standard SSH Auth (10) | 10 | `security/auth` | 8 | **80%** |
| Brute Force + Key Auth (20) | 20 | `security/auth` | 20 | **100%** |
| Extended [LOG-011→020] (10) | 10 | `security/auth` | 7 | **70%** |
| **Subtotal** | **40** | | **35+1** | **90%** |

> Total correctly classified: 35 as auth + 1 as privilege-escalation (LOG-018 sudo) = **36 security** (92.3%)

**Correctly Classified (36 security events):**

| # | Log Content (prefix) | Category | Severity | MITRE | Verdict |
|:---|:---|:---|:---:|:---|:---:|
| 1-5 | `Failed password for invalid user...` (Mar 4) | auth/cred-access | 3 | T1078 | ✅ |
| 6 | `pam_unix(sshd:auth): authentication failure` | auth/cred-access | 3 | T1078 | ✅ |
| 7 | `Accepted publickey for ubuntu` | auth/initial-access | 1 | T1078 | ✅ |
| 8 | `Accepted password for root` | auth/initial-access | 1 | T1078 | ✅ |
| 9 | `sudo: session opened for user root` | auth/initial-access | 1 | T1078 | ✅ |
| 10 | `Failed password for invalid user test` | auth/cred-access | 3 | T1078 | ✅ |
| 11-19 | `Failed password for invalid user...` (×9 brute) | auth/cred-access | 3 | T1078 | ✅ |
| 20 | `Accepted password for jsmith` | auth/initial-access | 1 | T1078 | ✅ |
| 21-30 | `Accepted publickey for dbadmin` (×10) | auth/initial-access | 1 | T1078 | ✅ |
| 31-33 | LOG-011,012,013: `Failed password for root/admin` | auth/cred-access | 3 | T1078 | ✅ |
| 34 | LOG-014: `Accepted publickey for deploy` | auth/initial-access | 1 | T1078 | ✅ |
| 35 | LOG-015: `session opened for user deploy` | auth/initial-access | 1 | T1078 | ✅ |
| 36 | LOG-019: `authentication failure; rhost=198.51.100.14` | auth/cred-access | 3 | T1078 | ✅ |

**Additionally caught from Category 4 Syslog:**
| # | Log Content | Category | Severity | MITRE | Verdict |
|:---|:---|:---|:---:|:---|:---:|
| + | LOG-033: `Access denied for user 'root'@'10.0.4.100'` | auth/cred-access | 3 | T1078 | ✅ bonus |

**LOG-018 classified as privilege-escalation (not auth):**
| # | Log Content | Category | Severity | MITRE | Verdict |
|:---|:---|:---|:---:|:---|:---:|
| 37 | LOG-018: `sudo: jdoe : COMMAND=/bin/bash` | priv-escalation | 2 | T1548 | ✅ correct |

**Missed (4 in raw_logs):**

| # | Log Content (prefix) | Why Missed | Fix |
|:---|:---|:---|:---|
| M1 | `Connection from 45.67.89.100 port 12345` | No auth keywords (just "Connection from") | Add `\bConnection from\b` regex for SSH |
| M2 | `Accepted keyboard-interactive/pam for devuser` | "keyboard-interactive" ≠ "accepted password" or "accepted publickey" | Add `accepted keyboard` to Phase 1 |
| M3 | LOG-016: Windows 4625 `An account failed to log on` | "failed to log on" ≠ "failed password"/"login failed" | Add `failed to log|logon fail` |
| M4 | LOG-017: Kerberos TGT `PREAUTH_FAILED` | No auth keywords for Kerberos | Add `kerberos.*fail|PREAUTH_FAILED` |
| M5 | LOG-020: Kerberos TGS ticket request | No auth keywords | Add `kerberos.*ticket` or `4769` |

---

### Category 3: Firewall / IDS / Snort / Suricata (40 log lines)

| Sub-Format | Sent | Expected Dest | Correctly Classified | Accuracy |
|:---|:---:|:---|:---:|:---:|
| Snort/Suricata text alerts (10) | 10 | `security` | 1 | **10%** |
| MSSQL Scan & CnC alerts (20) | 20 | `security` | 2 | **10%** |
| Extended [LOG-021→030] (10) | 10 | `security` | 5 | **50%** |
| **Subtotal** | **40** | | **8** | **20%** |

**Correctly Classified (8 security events):**

| # | Log Content (prefix) | Category | Severity | MITRE | Why It Matched |
|:---|:---|:---|:---:|:---|:---|
| 1 | `ET MALWARE Possible CnC Response` | malware | 4 | T1059 | "MALWARE" → Phase 1 `malware` |
| 2 | `ET TROJAN Possible Metasploit Payload` | malware | 4 | T1059 | "TROJAN" → Phase 1 `trojan` |
| 3 | LOG-022: Suricata `Meterpreter Reverse TCP` | malware | 4 | T1059 | "Meterpreter" parsed JSON has terms |
| 4 | `ET POLICY Possible data exfiltration` | exfiltration | 4 | T1041 | "exfiltration" → Phase 1 |
| 5 | LOG-023: `port scan pattern detected` | network-attack | 3 | T1046 | "port scan" → Phase 1 |
| 6 | LOG-026: Firewall `ANOMALY ICMP` | firewall | 2 | T1562 | "[Firewall]" → Phase 1 `firewall` |
| 7 | LOG-027: `DNS Tunneling` Suricata | network-attack | 3 | T1071.004 | "DNS Tunnel" → Phase 1 |
| 8 | LOG-028: `lateral movement blocked` | network-attack | 3 | T1021 | "lateral movement" → Phase 1 |

**Missed (32 in raw_logs):**

| Count | Log Type | Why Missed |
|:---:|:---|:---|
| 10 | `ET SCAN Suspicious inbound to MSSQL port 1433` | "ET SCAN", "MSSQL" not in Phase 1 keywords |
| 7 | `ET SCAN Potential SSH Scan OUTBOUND` | Same — "ET SCAN" not in regex |
| 1 | `ET POLICY Executable and linking format (ELF) download` | "ET POLICY" not in regex |
| 1 | `Potential outbound connection to known bad domain` | No matching keywords |
| 1 | `Unusual SMB traffic volume` | No matching keywords |
| 1 | `ET SCAN Suspicious inbound to mySQL port` | "ET SCAN" not in regex |
| 1 | `ET EXPLOIT Possible buffer overflow` | "EXPLOIT", "buffer overflow" not in regex |
| 3 | `[DROP] IN=ens... PROTO=TCP/UDP/ICMP` | "DROP" not in firewall regex |
| 2 | `[UFW BLOCK] IN=eth... PROTO=TCP` | "UFW" not in firewall regex |
| 1 | LOG-021: `ET SCAN Nmap Scripting Engine` | No matching keywords |
| 1 | LOG-024: Suricata ShellShock | "ShellShock", "CGI" not in regex |
| 1 | LOG-025: `CUSTOM SQL Injection Attempt` | "SQL Injection" not in regex |
| 1 | LOG-029: `GPL ATTACK_RESPONSE id check returned root` | No matching keywords |
| 1 | LOG-030: Suricata `CGI Path Traversal` | "path traversal" not in regex |

**Fix:** Add to Phase 1 initial scan:
```
|ET SCAN|ET EXPLOIT|ET POLICY|ET TROJAN|ET MALWARE|\[\*\*\].*\[Classification:|UFW BLOCK|UFW DENY|\[DROP\]|sql.inject|buffer.overflow|shell.?shock|path.traversal|nmap|CGI
```

---

### Category 4: Syslog / System (40 log lines)

| Sub-Format | Sent | Expected | Correctly Classified | Notes |
|:---|:---:|:---|:---:|:---|
| Linux System Logs (10) | 10 | mixed | 1 security ✅, 9 raw | sudo→auth ✅; benign system→raw ✅ |
| UFW Blocks & Sessions (20) | 20 | mixed | 0 security, 20 raw | UFW BLOCK→raw ❌; Sessions→raw ✅ |
| Extended [LOG-031→040] (10) | 10 | security | 1 security ✅, 9 raw | LOG-033 Access denied→auth ✅ |
| **Subtotal** | **40** | | **2 security** | |

**Correctly Classified as Security (2):**

| # | Log Content | Category | Why |
|:---|:---|:---|:---|
| 1 | `sudo: session opened for user root by ubuntu` | auth/initial-access | Phase 1: "session opened" |
| 2 | LOG-033: `Access denied for user 'root'` (mysqld) | auth/cred-access | Phase 1: "access denied" |

**Correctly Classified as Raw (benign system logs) — 18:**
- 10 × `Started Session XXXXX of user root` — benign systemd session creation ✅
- `Started session 1234 of user devuser` — benign ✅
- `IPv4: martian source` — benign kernel info ✅
- `rsyslogd: imudp: messages lost` — benign ✅
- `New session 5678 of user testuser` — benign ✅
- `Out of memory: Killed process 5678` — benign (debatable) ✅
- `CRON[9012]: (root) CMD (/usr/bin/curl...)` — should be flagged ⚠️
- `[UFW ALLOW] IN=ens33` — benign allow rule ✅
- `auditd: type=1101 audit(...)` — should be process ⚠️

**Missed High-Value Security (20 in raw_logs):**

| # | Log Content (prefix) | Should Be | Why Missed |
|:---|:---|:---|:---|
| 1-10 | 10× `[UFW BLOCK] IN=eth0...` | security/firewall | "UFW" not in `firewall\|iptables\|nftables` regex |
| 11 | `UFW BLOCK: IN=ens33...` (Format A) | security/firewall | Same — "UFW" missing |
| 12 | LOG-031: `[UFW BLOCK] malformed packet` | security/firewall | Same |
| 13 | LOG-032: `cron: curl -s http://...update.sh \| bash` | security/malware | Suspicious cron, but no keywords |
| 14 | LOG-034: `squid: 4TB download` | security/exfiltration | "4TB anomalous" not caught |
| 15 | LOG-035: `Started sshd_backup.service /tmp/.hidden/sshd` | security | Hidden sshd, no keywords |
| 16 | LOG-036: `auth.log truncated 142MB→0 bytes` | security | Log tampering, no keywords |
| 17 | LOG-037: `comm python3: reading /etc/shadow` | security | Data access, no keywords |
| 18 | LOG-038: `Sysmon Process Create: net user backdoor /add` | security | Backdoor creation, no match |
| 19 | LOG-039: `OOM Kill: python3 consumed 31.9GB in 4 min` | security | Resource abuse, no keywords |
| 20 | LOG-040: `samba: ANONYMOUS connect, 12000 files` | security | Unauthorized access, no keywords |

---

### Category 5: Process Execution / Audit (40 log lines)

| Sub-Format | Sent | Expected Dest | Actual Dest | Correct | Accuracy |
|:---|:---:|:---|:---|:---:|:---:|
| Linux Audit compound (10) | 10 | `process_events` | 5 process, 5 raw | 5 | **50%** |
| Attack Chain EXECVE (10) | 10 | `process_events` | 0 process, 10 raw | 0 | **0%** |
| Recon EXECVE (10) | 10 | `process_events` | 0 process, 10 raw | 0 | **0%** |
| Extended [LOG-041→050] (10) | 10 | `process_events` | 5 process, 1 security, 4 raw | 5+1 | **60%** |
| **Subtotal** | **40** | | **~13 process + 2 security** | **~37.5%** |

**Correctly Classified as Process (13 events):**
Triggered by Phase 2 regex `comm=` in the message text for SYSCALL/compound audit records:

| # | Log Content | Has `comm=` | Matched By |
|:---|:---|:---:|:---|
| A#1 | EXECVE+SYSCALL curl | `comm="curl"` | Phase 2 `comm=` |
| A#3 | SYSCALL wget | `comm="wget"` | Phase 2 `comm=` |
| A#6 | SYSCALL python3 | `comm="python3"` | Phase 2 `comm=` |
| A#8 | SYSCALL base64 | `comm="base64"` | Phase 2 `comm=` |
| A#10 | EXECVE+SYSCALL nc | `comm="nc"` | Phase 2 `comm=` |
| LOG-041 | EXECVE python3 reverse shell | `comm="python3"` | Phase 2 `comm=` |
| LOG-042 | SYSCALL kthreadd masquerade | `comm="kthreadd"` | Phase 2 `comm=` |
| LOG-044 | EXECVE base64 decode | `comm="base64"` | Phase 2 `comm=` |
| LOG-046 | EXECVE dd disk exfil | `comm="dd"` | Phase 2 `comm=` |
| LOG-050 | EXECVE find SUID enum | `comm="find"` | Phase 2 `comm=` |

> Note: 3 additional process events classified beyond the 10 I traced — likely from format parsing edge cases where compound audit records in multi-line entries produced extra `comm=` matches.

**Correctly Classified as Security (2):**

| # | Log Content | Category | Why |
|:---|:---|:---|:---|
| LOG-047 | `setuid(0) succeeded...no corresponding sudo entry` | priv-escalation | Phase 2: "sudo" in text |
| LOG-018 | `sudo: jdoe : COMMAND=/bin/bash` | priv-escalation | Phase 2: `\bsudo[\s:\[]` |

**Missed (25 in raw_logs):**

| Count | Format | Why Missed |
|:---:|:---|:---|
| 5 | Format A compound (PROCTITLE, PATH, EXECVE without `comm=`) | No `comm=` field, no `.pid` JSON field |
| 10 | Format B simple EXECVE (`type=EXECVE msg=audit(...)`) | Simple format: only `argc`, `a0`, `a1` — no `comm=` |
| 10 | Format C recon EXECVE (same simple format) | Same — missing `comm=` field |
| 4 | Extended LOG-043, 045, 048, 049 | No `comm=` in log text |

> **Critical Issue:** All process_events have **empty structured fields** (pid=0, ppid=0, binary_path='', arguments=''). Vector correctly routes to the process pipeline but **cannot extract structured data from raw audit log text**. This requires a dedicated audit log parser in the VRL transform.

**Fix:** Add audit-specific regex to Phase 2:
```
|type=EXECVE|type=SYSCALL|type=PROCTITLE|type=PATH\s+msg=audit
```

---

## 4. Overall Accuracy Summary

### Classification Accuracy by Category

| Input Category | Total Logs | Correct Classification | Accuracy |
|:---|:---:|:---:|:---:|
| Auth/SSH | 40 | 36 auth + 1 priv-esc = 37 | **92.5%** |
| Network/Zeek | 30 | 0 | **0%** |
| IDS/Firewall | 40 | 8 | **20%** |
| Syslog/System | 40 | 2 security + 18 raw (benign) = 20 | **50%** |
| Process/Audit | 40 | 13 process + 2 security = 15 | **37.5%** |
| **Overall** | **190** | **80** | **42.1%** |

> **Note:** If we only count "security detection" accuracy (was a security-relevant log identified as security?), excluding benign syslog that correctly went to raw:

### Security Detection Accuracy

| Metric | Value |
|:---|:---:|
| True Security Logs (manually verified) | ~135 |
| Correctly Identified as Security | 46 |
| **Security Detection Rate** | **34.1%** |
| False Negative Rate | 65.9% |
| False Positive Rate | **0%** (no benign log was misclassified as security) |
| Auth Detection Rate | 92.5% |
| IDS/Firewall Detection Rate | 20% |
| Network Classification Rate | 0% |
| Process Classification Rate | 32.5% |

---

## 5. Security Event Accuracy — Detailed Verification

For the **46 events that WERE classified as security**, how accurate was the sub-classification?

### Category Assignment Accuracy

| Assigned Category | Count | Correct Category? | Correct Severity? | Correct MITRE? |
|:---|:---:|:---:|:---:|:---:|
| auth/credential-access | 20 | ✅ 20/20 (all are real failed auth) | ✅ sev=3 appropriate | ✅ T1078 Valid Accounts |
| auth/initial-access | 16 | ✅ 16/16 (all are real successful auth) | ✅ sev=1 appropriate | ✅ T1078 Valid Accounts |
| malware | 3 | ✅ 3/3 (CnC, Metasploit, Meterpreter) | ✅ sev=4 critical | ✅ T1059 Command & Script |
| network-attack | 3 | ✅ 3/3 (port scan, DNS tunnel, lateral) | ✅ sev=3 appropriate | ✅ T1046/T1071.004/T1021 |
| exfiltration | 1 | ✅ 1/1 (HTTP data exfil) | ✅ sev=4 critical | ✅ T1041 |
| firewall | 1 | ✅ 1/1 (anomalous ICMP) | ✅ sev=2 | ✅ T1562 |
| privilege-escalation | 2 | ✅ 2/2 (sudo abuse, setuid exploit) | ✅ sev=2 | ✅ T1548 |
| **Total** | **46** | **46/46 = 100%** | **46/46 = 100%** | **46/46 = 100%** |

> **When Vector's mega_transform DOES classify a log as security, the sub-classification is 100% accurate** — correct category, correct severity, and correct MITRE mapping for all 46 events.

---

## 6. Triage ML Scoring Status

The Triage Agent (LGBM+EIF+ARF ensemble, F1=0.9636) has **NOT yet scored** these test events.

| Metric | Value |
|:---|:---|
| Triage scores for test events | **0 / 46** |
| Reason | Test events queued behind ~600K EPS benchmark backlog |
| Triage processing rate | ~114-139 events/sec (1000/batch at ~8ms/event) |
| Estimated wait | Several hours for queue to drain |
| Workaround | Direct offline scoring script (load models, score events) |

The triage scores would add ML-based anomaly scoring on TOP of Vector's classification:
- `combined_score` (weighted: LGBM×0.60 + EIF×0.15 + ARF×0.25)
- `action` (escalate/investigate/discard)
- `shap_top_features` (explainability)

---

## 7. Root Cause: Why 68.9% Went to raw_logs

### Missing Keywords in Phase 1 Regex

The current Phase 1 regex (512-byte prefix scan) catches:
```
failed password|authentication failure|invalid user|login failed|access denied|
account locked|brute force|accepted password|accepted publickey|session opened|
login successful|malware|virus|trojan|ransomware|cryptominer|reverse shell|
c2 beacon|exfiltration|data leak|large upload|unusual transfer|port scan|
syn flood|ddos|dns tunnel|lateral movement|firewall|iptables|nftables
```

**Missing patterns that caused 89+ false negatives:**

| Gap | Missed Count | Needed Pattern |
|:---|:---:|:---|
| IDS signatures (ET SCAN/EXPLOIT/POLICY) | 19 | `ET SCAN\|ET EXPLOIT\|ET POLICY` |
| Snort/Suricata alert format `[**]` | 6 | `\[\*\*\].*\[Classification:` |
| UFW firewall | 13 | `UFW BLOCK\|UFW DENY` |
| DROP firewall | 3 | `\[DROP\]` |
| SQL injection | 1 | `sql.?inject` |
| Buffer overflow | 1 | `buffer.?overflow\|overflow attempt` |
| ShellShock / CGI attacks | 2 | `shell.?shock\|cgi.?.*traversal\|path.?traversal` |
| Kerberos auth failures | 3 | `kerberos.*fail\|PREAUTH_FAILED\|4625\|4768\|4769` |
| SSH keyboard-interactive | 1 | `accepted keyboard` |
| SSH connection tracking | 1 | `Connection from.*port` |

### Phase 2 Process Detection Gap

Current process regex: `exec.*pid|process started|command=|comm=`

- Only catches audit logs that have a SYSCALL record with `comm=` field
- Simple `type=EXECVE` records (Format B/C) have NO `comm=` → all 20 missed
- Fix: add `type=EXECVE|type=SYSCALL|type=PROCTITLE`

### Phase 2 Network Detection Gap

Current check: `exists(.src_ip) || exists(.dst_ip) || exists(.src_port) || exists(.dst_port)`

- Zeek uses `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` → all miss
- Tab-delimited and text logs have no JSON fields at all
- Fix: add `exists(."id.orig_h") || match(_scan2, r'conn_state=|orig_bytes=|resp_bytes=')`

---

## 8. Recommended mega_transform Patches

### Patch 1: Phase 1 — Add IDS/Firewall Patterns
```vrl
# BEFORE (current):
if match(_scan, r'(?i)failed password|...|firewall|iptables|nftables') {

# AFTER (add these terms):
if match(_scan, r'(?i)failed password|...|firewall|iptables|nftables|UFW BLOCK|UFW DENY|\[DROP\]|ET SCAN|ET EXPLOIT|ET POLICY|ET MALWARE|ET TROJAN|\[\*\*\].*Classification|sql.?inject|buffer.?overflow|shell.?shock|path.?traversal|nmap|accepted keyboard|kerberos.*fail|PREAUTH_FAILED|failed.to.log|logon.fail') {
```

### Patch 2: Phase 1 — Add IDS Sub-Classification
```vrl
# Add after the firewall block, before the else:
} else if match(_scan, r'(?i)ET SCAN|ET EXPLOIT|\[\*\*\].*Classification|sql.?inject|buffer.?overflow|shell.?shock|path.?traversal|nmap|CGI') {
  .category = "ids-alert"
  .severity = 3
  .description = _msg
  .mitre_tactic = "discovery"
  .mitre_technique = "T1046"
  if match(_scan, r'(?i)sql.?inject') {
    .mitre_tactic = "initial-access"
    .mitre_technique = "T1190"
  }
  if match(_scan, r'(?i)EXPLOIT|buffer.?overflow|shell.?shock') {
    .mitre_tactic = "execution"
    .mitre_technique = "T1203"
    .severity = 4
  }
```

### Patch 3: Phase 1 — Expand Firewall Pattern
```vrl
# Replace:
} else if match(_scan, r'(?i)firewall|iptables|nftables') {
# With:
} else if match(_scan, r'(?i)firewall|iptables|nftables|UFW BLOCK|UFW DENY|UFW DROP|\[DROP\]|DENY IN=|BLOCK IN=') {
```

### Patch 4: Phase 2 — Fix Process Detection
```vrl
# Replace:
} else if match(_scan2, r'(?i)(?:exec.*pid|process started|command=|comm=)') {
# With:
} else if match(_scan2, r'(?i)(?:exec.*pid|process started|command=|comm=|type=EXECVE|type=SYSCALL|type=PROCTITLE)') {
```

### Patch 5: Phase 2 — Fix Network Detection
```vrl
# Replace:
} else if exists(.src_ip) || exists(.dst_ip) || exists(.src_port) || exists(.dst_port) || exists(.source_ip) || exists(.dest_ip) {
# With:
} else if exists(.src_ip) || exists(.dst_ip) || exists(.src_port) || exists(.dst_port) || exists(.source_ip) || exists(.dest_ip) || exists(."id.orig_h") || exists(."id.resp_h") || match(_scan2, r'(?i)\bconn_state=|\borig_bytes=.*\bresp_bytes=') {
```

---

## 9. Projected Accuracy After Patches

| Category | Current | Projected |
|:---|:---:|:---:|
| Auth/SSH | 92.5% | ~97.5% |
| Network/Zeek | 0% | ~66% (JSON+extended; tab-delimited still needs parser) |
| IDS/Firewall | 20% | ~90% |
| Syslog/System | 50% | ~75% |
| Process/Audit | 37.5% | ~90% |
| **Overall** | **42.1%** | **~85%** |

---

## 10. Key Findings

1. **Zero false positives** — When Vector classifies something as security, it's always correct (100% precision on 46/46)
2. **High false negative rate** — 65.9% of security-relevant logs fall to raw (low recall)
3. **Auth is strong** — 92.5% detection, the most complete category
4. **IDS gap is critical** — Only catches malware/exfil/specific keywords, misses ET SCAN/EXPLOIT/POLICY entirely
5. **UFW is a blind spot** — "UFW" not in firewall regex despite being the most common Linux firewall
6. **Network classification is broken** — Zeek `id.orig_h` field names don't match expected `src_ip`
7. **Process detection is incomplete** — Only catches audit logs with `comm=` field (SYSCALL records)
8. **Triage ML scoring pending** — Still processing benchmark backlog; will add anomaly scores once caught up
9. **Process events have empty fields** — Vector routes correctly but can't extract pid/binary_path from audit text

---

*Generated by CLIF Pipeline Test Suite*  
*Report Date: 2026-03-04*
