#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CLIF Sysmon Status Report — Diagnostic Tool

.DESCRIPTION
    Generates a comprehensive status report for the CLIF Sysmon deployment:
      - Service status (Sysmon, Vector agent)
      - Event generation rates
      - Resource usage (CPU, memory, disk)
      - Configuration validation
      - Recent alerts summary

.PARAMETER OutputFormat
    Output format: Console (default), JSON, or HTML.

.EXAMPLE
    .\Get-ClifSysmonStatus.ps1
    .\Get-ClifSysmonStatus.ps1 -OutputFormat JSON
#>

[CmdletBinding()]
param(
    [ValidateSet("Console", "JSON", "HTML")]
    [string]$OutputFormat = "Console"
)

$ErrorActionPreference = "Continue"
$report = [ordered]@{}

# ═══════════════════════════════════════════════════════════════════════════════
# Service Status
# ═══════════════════════════════════════════════════════════════════════════════

$sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
$vectorSvc = Get-Service -Name "clif-vector-agent" -ErrorAction SilentlyContinue
$sysmonDrv = Get-Service -Name "SysmonDrv" -ErrorAction SilentlyContinue

$report["Services"] = @{
    Sysmon = @{
        Status = if ($sysmonSvc) { $sysmonSvc.Status.ToString() } else { "NOT_INSTALLED" }
        StartType = if ($sysmonSvc) { $sysmonSvc.StartType.ToString() } else { "N/A" }
    }
    SysmonDriver = @{
        Status = if ($sysmonDrv) { $sysmonDrv.Status.ToString() } else { "NOT_INSTALLED" }
    }
    VectorAgent = @{
        Status = if ($vectorSvc) { $vectorSvc.Status.ToString() } else { "NOT_INSTALLED" }
        StartType = if ($vectorSvc) { $vectorSvc.StartType.ToString() } else { "N/A" }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Event Statistics (last 1 hour)
# ═══════════════════════════════════════════════════════════════════════════════

$cutoff = (Get-Date).AddHours(-1)
$eventStats = @{}

try {
    $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $cutoff }

    if ($sysmonEvents) {
        $byEventId = $sysmonEvents | Group-Object -Property Id | Sort-Object -Property Count -Descending
        foreach ($group in $byEventId) {
            $eidName = switch ($group.Name) {
                "1"  { "ProcessCreate" }
                "2"  { "FileCreateTimeChange" }
                "3"  { "NetworkConnect" }
                "5"  { "ProcessTerminate" }
                "6"  { "DriverLoad" }
                "7"  { "ImageLoad" }
                "8"  { "CreateRemoteThread" }
                "9"  { "RawAccessRead" }
                "10" { "ProcessAccess" }
                "11" { "FileCreate" }
                "12" { "RegistryAddOrDelete" }
                "13" { "RegistryValueSet" }
                "14" { "RegistryRename" }
                "15" { "FileStreamHash" }
                "17" { "PipeCreated" }
                "18" { "PipeConnected" }
                "22" { "DNSQuery" }
                "23" { "FileDelete" }
                "24" { "ClipboardChange" }
                "25" { "ProcessTampering" }
                "26" { "FileDeleteLogged" }
                default { "EID_$($group.Name)" }
            }
            $eventStats["EID$($group.Name)_$eidName"] = $group.Count
        }
        $eventStats["TotalEvents_1h"] = $sysmonEvents.Count
        $eventStats["EventsPerMinute"] = [math]::Round($sysmonEvents.Count / 60, 1)
    } else {
        $eventStats["TotalEvents_1h"] = 0
        $eventStats["EventsPerMinute"] = 0
    }
} catch {
    $eventStats["Error"] = $_.Exception.Message
}

$report["EventStatistics"] = $eventStats

# ═══════════════════════════════════════════════════════════════════════════════
# Log File Sizes
# ═══════════════════════════════════════════════════════════════════════════════

$logSizes = @{}

$logNames = @(
    "Microsoft-Windows-Sysmon/Operational",
    "Security",
    "Microsoft-Windows-PowerShell/Operational"
)

foreach ($logName in $logNames) {
    try {
        $logInfo = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($logInfo) {
            $logSizes[$logName] = @{
                CurrentSizeMB = [math]::Round($logInfo.FileSize / 1MB, 1)
                MaxSizeMB = [math]::Round($logInfo.MaximumSizeInBytes / 1MB, 1)
                UsagePercent = [math]::Round(($logInfo.FileSize / $logInfo.MaximumSizeInBytes) * 100, 1)
                RecordCount = $logInfo.RecordCount
                IsEnabled = $logInfo.IsEnabled
            }
        }
    } catch {
        $logSizes[$logName] = @{ Error = $_.Exception.Message }
    }
}

$report["EventLogSizes"] = $logSizes

# ═══════════════════════════════════════════════════════════════════════════════
# Resource Usage
# ═══════════════════════════════════════════════════════════════════════════════

$resources = @{}

# Sysmon process
$sysmonProc = Get-Process -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($sysmonProc) {
    $resources["Sysmon"] = @{
        PID = $sysmonProc.Id
        CPU_Seconds = [math]::Round($sysmonProc.CPU, 2)
        WorkingSetMB = [math]::Round($sysmonProc.WorkingSet64 / 1MB, 1)
        PrivateMemMB = [math]::Round($sysmonProc.PrivateMemorySize64 / 1MB, 1)
        ThreadCount = $sysmonProc.Threads.Count
        HandleCount = $sysmonProc.HandleCount
        StartTime = $sysmonProc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
        Uptime = ((Get-Date) - $sysmonProc.StartTime).ToString("dd\.hh\:mm\:ss")
    }
}

# Vector process
$vectorProc = Get-Process -Name "vector" -ErrorAction SilentlyContinue
if ($vectorProc) {
    $resources["VectorAgent"] = @{
        PID = $vectorProc.Id
        CPU_Seconds = [math]::Round($vectorProc.CPU, 2)
        WorkingSetMB = [math]::Round($vectorProc.WorkingSet64 / 1MB, 1)
        PrivateMemMB = [math]::Round($vectorProc.PrivateMemorySize64 / 1MB, 1)
        ThreadCount = $vectorProc.Threads.Count
        HandleCount = $vectorProc.HandleCount
        StartTime = $vectorProc.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
        Uptime = ((Get-Date) - $vectorProc.StartTime).ToString("dd\.hh\:mm\:ss")
    }
}

# SysmonArchive directory size
$archiveDir = "C:\CLIF\SysmonArchive"
if (Test-Path $archiveDir) {
    $archiveFiles = Get-ChildItem $archiveDir -Recurse -ErrorAction SilentlyContinue
    $resources["SysmonArchive"] = @{
        SizeMB = [math]::Round(($archiveFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
        FileCount = $archiveFiles.Count
    }
}

$report["Resources"] = $resources

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration Validation
# ═══════════════════════════════════════════════════════════════════════════════

$config = @{}

# Sysmon config
$configPath = "C:\CLIF\Sysmon\sysmonconfig-clif.xml"
if (Test-Path $configPath) {
    $hash = (Get-FileHash -Path $configPath -Algorithm SHA256).Hash
    $config["SysmonConfig"] = @{
        Path = $configPath
        SHA256 = $hash
        LastModified = (Get-Item $configPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
} else {
    $config["SysmonConfig"] = @{ Status = "NOT_FOUND" }
}

# Vector config
$vectorConfig = "C:\CLIF\Vector\config\vector.yaml"
if (Test-Path $vectorConfig) {
    $hash = (Get-FileHash -Path $vectorConfig -Algorithm SHA256).Hash
    $config["VectorConfig"] = @{
        Path = $vectorConfig
        SHA256 = $hash
        LastModified = (Get-Item $vectorConfig).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
} else {
    $config["VectorConfig"] = @{ Status = "NOT_FOUND" }
}

# PowerShell logging
$psReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psVal = Get-ItemProperty -Path $psReg -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
$config["PowerShellLogging"] = @{
    ScriptBlockLogging = if ($psVal -and $psVal.EnableScriptBlockLogging -eq 1) { "Enabled" } else { "Disabled" }
}

# Audit policies
$auditRaw = auditpol /get /category:* 2>&1 | Out-String
$config["AuditPolicySnapshot"] = "Run 'auditpol /get /category:*' for full details"

$report["Configuration"] = $config

# ═══════════════════════════════════════════════════════════════════════════════
# Recent High-Severity Events (last 15 min)
# ═══════════════════════════════════════════════════════════════════════════════

$recentAlerts = @()
$alertCutoff = (Get-Date).AddMinutes(-15)

try {
    # Suspicious Sysmon events
    $highSev = @(8, 9, 10, 25)  # CreateRemoteThread, RawAccessRead, ProcessAccess, ProcessTampering
    foreach ($eid in $highSev) {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = $eid
            StartTime = $alertCutoff
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        foreach ($evt in $events) {
            $recentAlerts += @{
                Time = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                EventID = $eid
                Message = $evt.Message.Substring(0, [Math]::Min(200, $evt.Message.Length))
            }
        }
    }
} catch {}

$report["RecentAlerts"] = $recentAlerts

# ═══════════════════════════════════════════════════════════════════════════════
# Output
# ═══════════════════════════════════════════════════════════════════════════════

$report["GeneratedAt"] = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$report["Hostname"] = $env:COMPUTERNAME
$report["OS"] = (Get-CimInstance Win32_OperatingSystem).Caption

switch ($OutputFormat) {
    "JSON" {
        $report | ConvertTo-Json -Depth 5
    }
    "HTML" {
        $htmlPath = "C:\CLIF\Logs\status_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $html = "<html><head><title>CLIF Sysmon Status</title><style>body{font-family:monospace;background:#1a1a2e;color:#e0e0e0}h1{color:#00d4ff}h2{color:#00ff88;border-bottom:1px solid #333}table{border-collapse:collapse;width:100%;margin:10px 0}td,th{border:1px solid #333;padding:6px 12px;text-align:left}th{background:#0f3460;color:#fff}.ok{color:#00ff88}.warn{color:#ffd700}.error{color:#ff4757}</style></head><body>"
        $html += "<h1>CLIF Sysmon Status Report</h1>"
        $html += "<p>Generated: $($report.GeneratedAt) | Host: $($report.Hostname) | OS: $($report.OS)</p>"
        $html += "<pre>" + ($report | ConvertTo-Json -Depth 5) + "</pre>"
        $html += "</body></html>"
        Set-Content -Path $htmlPath -Value $html
        Write-Host "Report saved to: $htmlPath" -ForegroundColor Green
    }
    default {
        # Console output
        Write-Host ""
        Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
        Write-Host "  ║            CLIF Sysmon Status Report                     ║" -ForegroundColor Cyan
        Write-Host "  ║  $($report.Hostname) | $($report.GeneratedAt)              ║" -ForegroundColor Cyan
        Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
        Write-Host ""

        # Services
        Write-Host "  SERVICES" -ForegroundColor Yellow
        Write-Host "  ────────────────────────────────────────"
        foreach ($svc in $report.Services.GetEnumerator()) {
            $status = $svc.Value.Status
            $color = if ($status -eq "Running") { "Green" } elseif ($status -eq "NOT_INSTALLED") { "Red" } else { "Yellow" }
            Write-Host "    $($svc.Key): " -NoNewline
            Write-Host $status -ForegroundColor $color
        }
        Write-Host ""

        # Event Stats
        Write-Host "  EVENT STATISTICS (Last 1 Hour)" -ForegroundColor Yellow
        Write-Host "  ────────────────────────────────────────"
        foreach ($stat in $report.EventStatistics.GetEnumerator()) {
            Write-Host "    $($stat.Key): $($stat.Value)"
        }
        Write-Host ""

        # Resources
        Write-Host "  RESOURCE USAGE" -ForegroundColor Yellow
        Write-Host "  ────────────────────────────────────────"
        foreach ($res in $report.Resources.GetEnumerator()) {
            Write-Host "    $($res.Key):" -ForegroundColor Cyan
            foreach ($prop in $res.Value.GetEnumerator()) {
                Write-Host "      $($prop.Key): $($prop.Value)"
            }
        }
        Write-Host ""

        # Log Sizes
        Write-Host "  EVENT LOG SIZES" -ForegroundColor Yellow
        Write-Host "  ────────────────────────────────────────"
        foreach ($log in $report.EventLogSizes.GetEnumerator()) {
            $usage = $log.Value.UsagePercent
            $color = if ($usage -gt 90) { "Red" } elseif ($usage -gt 70) { "Yellow" } else { "Green" }
            Write-Host "    $($log.Key): " -NoNewline
            Write-Host "$($log.Value.CurrentSizeMB)/$($log.Value.MaxSizeMB) MB ($usage%)" -ForegroundColor $color
        }
        Write-Host ""

        # Recent Alerts
        if ($report.RecentAlerts.Count -gt 0) {
            Write-Host "  RECENT HIGH-SEVERITY EVENTS (Last 15 min)" -ForegroundColor Red
            Write-Host "  ────────────────────────────────────────"
            foreach ($alert in $report.RecentAlerts) {
                Write-Host "    [$($alert.Time)] EID $($alert.EventID): $($alert.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  No high-severity events in the last 15 minutes" -ForegroundColor Green
        }
        Write-Host ""
    }
}
