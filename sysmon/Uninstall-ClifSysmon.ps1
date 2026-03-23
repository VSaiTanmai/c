#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CLIF Sysmon Uninstall Script

.DESCRIPTION
    Cleanly removes Sysmon, Vector agent, scheduled tasks, and CLIF config.
    Optionally preserves log data.

.PARAMETER KeepLogs
    Preserve the C:\CLIF\Logs directory after uninstall.

.PARAMETER KeepArchive
    Preserve the C:\CLIF\SysmonArchive directory after uninstall.

.EXAMPLE
    .\Uninstall-ClifSysmon.ps1
    .\Uninstall-ClifSysmon.ps1 -KeepLogs -KeepArchive
#>

[CmdletBinding()]
param(
    [switch]$KeepLogs,
    [switch]$KeepArchive
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "OK"      { Write-Host "[$ts] [OK]    $Message" -ForegroundColor Green }
        "WARN"    { Write-Host "[$ts] [WARN]  $Message" -ForegroundColor Yellow }
        "ERROR"   { Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red }
        default   { Write-Host "[$ts] [INFO]  $Message" -ForegroundColor Cyan }
    }
}

Write-Host ""
Write-Host "  CLIF Sysmon Uninstaller" -ForegroundColor Red
Write-Host "  ═══════════════════════" -ForegroundColor Red
Write-Host ""

# ── Stop & remove Vector agent ──────────────────────────────────────────────
$vectorSvc = Get-Service -Name "clif-vector-agent" -ErrorAction SilentlyContinue
if ($vectorSvc) {
    Stop-Service -Name "clif-vector-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & sc.exe delete "clif-vector-agent" 2>&1 | Out-Null
    Write-Status "Vector agent service removed" "OK"
} else {
    Write-Status "Vector agent service not found (skipping)" "WARN"
}

# ── Uninstall Sysmon ─────────────────────────────────────────────────────────
$sysmonExe = "C:\CLIF\Sysmon\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Write-Status "Uninstalling Sysmon..."
    & $sysmonExe -u force 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    Write-Status "Sysmon uninstalled" "OK"
} else {
    # Try system-wide Sysmon
    $sysmon = Get-Command Sysmon64.exe -ErrorAction SilentlyContinue
    if ($sysmon) {
        & $sysmon.Source -u force 2>&1 | Out-Null
        Write-Status "Sysmon uninstalled (system)" "OK"
    } else {
        Write-Status "Sysmon executable not found (skipping)" "WARN"
    }
}

# ── Remove scheduled task ────────────────────────────────────────────────────
$task = Get-ScheduledTask -TaskName "CLIF-Sysmon-HealthMonitor" -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName "CLIF-Sysmon-HealthMonitor" -Confirm:$false
    Write-Status "Health monitor task removed" "OK"
} else {
    Write-Status "Health monitor task not found (skipping)" "WARN"
}

# ── Remove firewall rules ────────────────────────────────────────────────────
$rule = Get-NetFirewallRule -DisplayName "CLIF-Vector-Agent-Outbound" -ErrorAction SilentlyContinue
if ($rule) {
    Remove-NetFirewallRule -DisplayName "CLIF-Vector-Agent-Outbound"
    Write-Status "Firewall rule removed" "OK"
}

# ── Remove environment variables ──────────────────────────────────────────────
[System.Environment]::SetEnvironmentVariable("CLIF_VECTOR_URL", $null, "Machine")
[System.Environment]::SetEnvironmentVariable("VECTOR_CONFIG", $null, "Machine")
[System.Environment]::SetEnvironmentVariable("VECTOR_DATA_DIR", $null, "Machine")
Write-Status "Environment variables cleaned" "OK"

# ── Remove directories ───────────────────────────────────────────────────────
$installDir = "C:\CLIF"

if ($KeepLogs) {
    Write-Status "Preserving logs directory" "INFO"
}
if ($KeepArchive) {
    Write-Status "Preserving archive directory" "INFO"
}

$dirsToRemove = @("Sysmon", "Vector", "Scripts")
if (-not $KeepLogs) { $dirsToRemove += "Logs" }
if (-not $KeepArchive) { $dirsToRemove += "SysmonArchive" }

foreach ($dir in $dirsToRemove) {
    $path = Join-Path $installDir $dir
    if (Test-Path $path) {
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed: $path" "OK"
    }
}

# Remove install root if empty
$remaining = Get-ChildItem -Path $installDir -ErrorAction SilentlyContinue
if (-not $remaining) {
    Remove-Item -Path $installDir -Force -ErrorAction SilentlyContinue
    Write-Status "Removed: $installDir" "OK"
}

# ── Revert PowerShell logging (optional — leave enabled for security) ──────
Write-Status "PowerShell logging registry keys left intact (security best practice)" "INFO"

Write-Host ""
Write-Status "CLIF Sysmon uninstall complete" "OK"
Write-Host ""
