# CLIF Sysmon Integration — Windows Endpoint Telemetry

Production-grade Sysmon + Vector agent deployment for the CLIF (Cognitive Log Investigation Framework) pipeline. Provides deep Windows endpoint visibility covering process execution, network connections, registry modifications, credential access, and more.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Endpoint                              │
│  ┌───────────┐  ┌──────────────────┐  ┌───────────────────────┐ │
│  │  Sysmon   │  │ Windows Security │  │  PowerShell Logging   │ │
│  │ (26 EIDs) │  │  (4624/4625/..)  │  │   (ScriptBlock 4104) │ │
│  └─────┬─────┘  └────────┬─────────┘  └──────────┬────────────┘ │
│        │                  │                        │              │
│        └──────────┬───────┴────────────────────────┘              │
│                   ▼                                               │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │        Vector Agent (vector-agent-windows.yaml)              │ │
│  │  • Parse Sysmon EIDs → CLIF Common Schema (CCS)             │ │
│  │  • LOLBin detection, credential dump detection               │ │
│  │  • MITRE ATT&CK mapping per event                            │ │
│  │  • Disk-buffered HTTP sink (gzip compressed)                 │ │
│  └──────────────────────┬───────────────────────────────────────┘ │
└─────────────────────────┼───────────────────────────────────────┘
                          │ HTTP POST (JSON, gzip)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│               Central CLIF Pipeline (Docker)                     │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ Vector Aggregator (vector.yaml) — port 8687                  │ │
│  │  route_http_source ──→ route_windows_events ──→ dedup ──→──│ │
│  └────────────────────────────────────────────────────────┬─────┘ │
│                                                          ▼       │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐ │
│  │ raw-logs │   │ security │   │ process  │   │   network    │ │
│  │  topic   │   │  events  │   │  events  │   │   events     │ │
│  └────┬─────┘   └─────┬────┘   └────┬─────┘   └──────┬───────┘ │
│       └───────────┬────┴─────────────┴────────────────┘         │
│                   ▼                                              │
│        ┌──────────────────┐    ┌──────────────┐                  │
│        │   ClickHouse     │    │   LanceDB    │                  │
│        │ (4 tables, CCS)  │    │ (Semantic)   │                  │
│        └──────────────────┘    └──────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `sysmonconfig-clif.xml` | Sysmon XML configuration — 26 event IDs with noise exclusions |
| `vector-agent-windows.yaml` | Vector agent config for Windows endpoints |
| `Install-ClifSysmon.ps1` | Production installer (Sysmon + Vector + audit policies) |
| `Uninstall-ClifSysmon.ps1` | Clean removal script |
| `Get-ClifSysmonStatus.ps1` | Diagnostic/status report tool |

## Quick Start

### 1. Deploy on Windows Endpoint

```powershell
# From an elevated PowerShell prompt:
.\Install-ClifSysmon.ps1 -ClifVectorUrl "http://<CLIF_SERVER_IP>:8687"
```

### 2. Verify Deployment

```powershell
.\Get-ClifSysmonStatus.ps1
```

### 3. Unattended Mass Deployment

```powershell
# For domain-joined machines via GPO/SCCM/Intune:
.\Install-ClifSysmon.ps1 -Unattended -ClifVectorUrl "http://siem.corp.local:8687"
```

## Sysmon Event Coverage

### Process Events → `process_events` table

| EID | Event | Detection |
|-----|-------|-----------|
| 1 | Process Create | LOLBins, encoded PowerShell, Office macro spawns, recon commands, credential dumpers, suspicious paths |
| 5 | Process Terminate | Process lifecycle tracking |
| 7 | Image Loaded (DLL) | Unsigned DLL sideloading, attack DLLs (clr.dll, amsi.dll, dbghelp.dll) |

### Network Events → `network_events` table

| EID | Event | Detection |
|-----|-------|-----------|
| 3 | Network Connection | Source/dest IP:port, protocol, initiating process |
| 22 | DNS Query | Domain resolution with process context |

### Security Events → `security_events` table

| EID | Event | MITRE Technique |
|-----|-------|-----------------|
| 6 | Driver Loaded | T1547.006 — Kernel Module / Driver |
| 8 | CreateRemoteThread | T1055 — Process Injection |
| 9 | RawAccessRead | T1003 — OS Credential Dumping |
| 10 | Process Access | T1003.001 — LSASS Memory |
| 12-14 | Registry Events | T1547.001 — Registry Run Keys, T1543.003 — Windows Service, T1053.005 — Scheduled Task |
| 15 | FileCreateStreamHash | T1564.004 — NTFS Alternate Data Streams |
| 24 | Clipboard Change | T1115 — Clipboard Data |
| 25 | Process Tampering | T1055.012 — Process Hollowing |

**Windows Security Log:**

| EID | Event | MITRE Technique |
|-----|-------|-----------------|
| 4624 | Logon Success | T1078 — Valid Accounts |
| 4625 | Logon Failure | T1110 — Brute Force |
| 4648 | Explicit Credential | T1078.002 — Domain Accounts |
| 4672 | Special Privileges | T1134 — Access Token Manipulation |
| 4688 | Process Creation | (fallback when Sysmon unavailable) |
| 4720/4726 | Account Create/Delete | T1136.001 — Local Account |
| 4732/4733 | Group Membership | T1098 — Account Manipulation |
| 1102 | Audit Log Cleared | T1070.001 — Clear Windows Event Logs |

**PowerShell:**

| EID | Event | Detection |
|-----|-------|-----------|
| 4104 | Script Block | Invoke-Mimikatz, IEX, DownloadString, encoded commands, bypass, shellcode |
| 4103 | Module Logging | Module execution tracking |

### Raw Logs → `raw_logs` table

| EID | Event |
|-----|-------|
| 2 | File Creation Time Changed (timestomping) |
| 11 | File Create (executables, scripts, startup locations) |
| 17-18 | Named Pipe Create/Connect (known malicious pipes → security) |
| 23 | File Delete (archived) |
| 26 | File Delete (logged) |

## Detection Rules

The Vector agent includes built-in detection rules that set `is_suspicious=1` and `detection_rule` fields:

| Rule | Description | Severity |
|------|-------------|----------|
| `lolbin_*` | Living Off The Land binary execution (certutil, mshta, regsvr32, etc.) | High |
| `suspicious_powershell` | Encoded commands, hidden window, bypass flags | High |
| `recon_*` | Reconnaissance commands (whoami, net user, systeminfo, etc.) | Medium |
| `credential_dumping` | Mimikatz, procdump, comsvcs MiniDump | Critical |
| `office_macro_spawn` | Office app spawning cmd/powershell/script host | Critical |
| `exec_from_suspicious_path` | Execution from temp/downloads/public dirs | Medium |
| `unsigned_dll_load` | Unsigned DLL loaded into process | Medium |

## Resource Impact

### Sysmon
- **CPU:** < 2% average on modern hardware (noise-filtered config)
- **Memory:** ~15-30 MB working set
- **Disk:** Archive directory grows with file-delete captures; health monitor warns at 1 GB

### Vector Agent
- **CPU:** < 1% average (batched HTTP forwarding)
- **Memory:** ~50-100 MB (disk buffering, not memory)
- **Network:** Gzip-compressed JSON, batched (5000-10000 events/batch)
- **Disk Buffer:** Up to 512 MB security, 1 GB each for process/network/raw — survives central Vector outages

### Event Log Sizes (configured by installer)
- Sysmon: 256 MB
- Security: 512 MB
- PowerShell: 128 MB

## Health Monitoring

The installer creates a scheduled task `CLIF-Sysmon-HealthMonitor` that runs every 5 minutes:

- Auto-restarts Sysmon if stopped
- Auto-restarts Vector agent if stopped
- Checks event flow (warns if no events in 5 min)
- Monitors archive directory size
- Logs to `C:\CLIF\Logs\health_monitor.log`

## Customization

### Tuning Sysmon Noise

Edit `sysmonconfig-clif.xml` to exclude additional noisy processes:

```xml
<!-- Add to ProcessCreate exclusions -->
<Image condition="is">C:\Path\To\TrustedApp.exe</Image>
```

Then update the running config:

```powershell
Sysmon64.exe -c C:\CLIF\Sysmon\sysmonconfig-clif.xml
```

### Adding Custom Detection Rules

Edit `vector-agent-windows.yaml`, in the `detect_suspicious_processes` transform:

```yaml
# Add custom detection
if contains(bp_lower, "custom_malware.exe") {
  .is_suspicious = 1
  .detection_rule = "custom_malware_detected"
}
```

### Changing Central Vector URL

```powershell
# Update environment variable
[System.Environment]::SetEnvironmentVariable("CLIF_VECTOR_URL", "http://new-server:8687", "Machine")
# Restart service
Restart-Service "clif-vector-agent"
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No Sysmon events | Run `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5` |
| Vector not forwarding | Check `C:\CLIF\Logs\health_monitor.log`; verify network to central Vector |
| High CPU from Sysmon | Add exclusions to `sysmonconfig-clif.xml` for noisy processes |
| Disk buffer growing | Central Vector unreachable; check network/firewall |
| Events not in ClickHouse | Verify central Vector routes: check `route_http_source` and `route_windows_events` in central `vector.yaml` |
