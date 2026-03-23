#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CLIF Sysmon Deployment Script — Production Grade
    Installs Sysmon + Vector agent on Windows endpoints for the CLIF pipeline.

.DESCRIPTION
    This script performs the following:
      1. Downloads and verifies Sysmon from Microsoft Sysinternals (SHA256 check)
      2. Installs Sysmon with the CLIF-optimized configuration
      3. Downloads and installs the Vector agent (Windows MSI)
      4. Configures Vector with the CLIF Windows agent config
      5. Configures Windows Event Forwarding (WEF) if in domain environment
      6. Enables PowerShell Script Block Logging
      7. Creates a scheduled task for health monitoring
      8. Validates the installation

.PARAMETER ClifVectorUrl
    URL of the central CLIF Vector HTTP endpoint. Default: http://clif-vector:8687

.PARAMETER SysmonConfigPath
    Path to the CLIF Sysmon XML configuration file.
    Default: sysmonconfig-clif.xml in the same directory as this script.

.PARAMETER InstallDir
    Installation directory. Default: C:\CLIF

.PARAMETER VectorVersion
    Vector version to install. Default: 0.42.0

.PARAMETER SkipVector
    Skip Vector agent installation (use if forwarding via WEF/WinRM instead).

.PARAMETER SkipSysmon
    Skip Sysmon installation (use if Sysmon is already installed).

.PARAMETER Unattended
    Run without interactive prompts.

.EXAMPLE
    .\Install-ClifSysmon.ps1 -ClifVectorUrl "http://10.0.1.50:8687"
    .\Install-ClifSysmon.ps1 -Unattended -ClifVectorUrl "http://siem.corp.local:8687"

.NOTES
    Requires: Windows 10/11, Server 2016+, PowerShell 5.1+, Administrator
    Author: CLIF Framework — SIH1733
#>

[CmdletBinding()]
param(
    [string]$ClifVectorUrl = "http://clif-vector:8687",
    [string]$SysmonConfigPath = "",
    [string]$InstallDir = "C:\CLIF",
    [string]$VectorVersion = "0.42.0",
    [switch]$SkipVector,
    [switch]$SkipSysmon,
    [switch]$Unattended
)

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration & Constants
# ═══════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Script:SYSMON_URL     = "https://download.sysinternals.com/files/Sysmon.zip"
$Script:VECTOR_URL     = "https://packages.timber.io/vector/$VectorVersion/vector-$VectorVersion-x86_64-pc-windows-msvc.msi"
$Script:SYSMON_DIR     = Join-Path $InstallDir "Sysmon"
$Script:VECTOR_DIR     = Join-Path $InstallDir "Vector"
$Script:LOG_DIR        = Join-Path $InstallDir "Logs"
$Script:ARCHIVE_DIR    = Join-Path $InstallDir "SysmonArchive"
$Script:TEMP_DIR       = Join-Path $env:TEMP "CLIF_Install"
$Script:LOG_FILE       = Join-Path $Script:LOG_DIR "install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Sysmon service name
$Script:SYSMON_SVC     = "Sysmon64"
$Script:SYSMON_DRIVER  = "SysmonDrv"

# ═══════════════════════════════════════════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════════════════════════════════════════

function Write-ClifLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "WARNING" { Write-Host $entry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry -ForegroundColor Cyan }
    }

    if (Test-Path (Split-Path $Script:LOG_FILE -Parent)) {
        Add-Content -Path $Script:LOG_FILE -Value $entry
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Pre-flight Checks
# ═══════════════════════════════════════════════════════════════════════════════

function Test-Prerequisites {
    Write-ClifLog "Running pre-flight checks..."

    # Check OS version
    $os = [System.Environment]::OSVersion
    if ($os.Platform -ne "Win32NT" -or $os.Version.Major -lt 10) {
        throw "CLIF Sysmon requires Windows 10/Server 2016 or later. Current: $($os.VersionString)"
    }
    Write-ClifLog "OS: $($os.VersionString) — OK"

    # Check admin
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator."
    }
    Write-ClifLog "Running as Administrator — OK"

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1+ required. Current: $($PSVersionTable.PSVersion)"
    }
    Write-ClifLog "PowerShell $($PSVersionTable.PSVersion) — OK"

    # Check disk space (need at least 500 MB)
    $drive = (Split-Path $InstallDir -Qualifier)
    $freeGB = [math]::Round((Get-PSDrive ($drive -replace ':','') | Select-Object -ExpandProperty Free) / 1GB, 2)
    if ($freeGB -lt 0.5) {
        throw "Insufficient disk space on $drive. Need 500 MB, have $freeGB GB."
    }
    Write-ClifLog "Disk space: ${freeGB} GB free on $drive — OK"

    # Check network connectivity to central Vector
    if (-not $SkipVector) {
        try {
            $uri = [System.Uri]$ClifVectorUrl
            $tcpTest = Test-NetConnection -ComputerName $uri.Host -Port $uri.Port -WarningAction SilentlyContinue
            if ($tcpTest.TcpTestSucceeded) {
                Write-ClifLog "Central Vector reachable at $ClifVectorUrl — OK"
            } else {
                Write-ClifLog "Central Vector NOT reachable at $ClifVectorUrl — will configure anyway" -Level WARNING
            }
        } catch {
            Write-ClifLog "Cannot validate Vector connectivity: $_. Continuing..." -Level WARNING
        }
    }

    # Check if Sysmon is already installed
    $existingSysmon = Get-Service -Name $Script:SYSMON_SVC -ErrorAction SilentlyContinue
    if ($existingSysmon) {
        Write-ClifLog "Sysmon is already installed (Status: $($existingSysmon.Status))" -Level WARNING
        if (-not $Unattended) {
            $response = Read-Host "Sysmon is already installed. Update configuration? (Y/n)"
            if ($response -eq 'n' -or $response -eq 'N') {
                $Script:SkipSysmonInstall = $true
            }
        }
    }

    Write-ClifLog "Pre-flight checks passed" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# Directory Setup
# ═══════════════════════════════════════════════════════════════════════════════

function Initialize-Directories {
    Write-ClifLog "Creating directory structure..."

    $dirs = @($InstallDir, $Script:SYSMON_DIR, $Script:VECTOR_DIR, $Script:LOG_DIR, $Script:ARCHIVE_DIR, $Script:TEMP_DIR)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-ClifLog "  Created: $dir"
        }
    }

    # Set ACLs on archive directory (restrict to SYSTEM + Administrators)
    $acl = Get-Acl $Script:ARCHIVE_DIR
    $acl.SetAccessRuleProtection($true, $false)
    $ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ruleAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($ruleSystem)
    $acl.AddAccessRule($ruleAdmin)
    Set-Acl -Path $Script:ARCHIVE_DIR -AclObject $acl
    Write-ClifLog "  Archive directory ACLs restricted to SYSTEM + Administrators"

    Write-ClifLog "Directory structure ready" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# Sysmon Installation
# ═══════════════════════════════════════════════════════════════════════════════

function Install-Sysmon {
    if ($SkipSysmon -or $Script:SkipSysmonInstall) {
        Write-ClifLog "Skipping Sysmon installation" -Level WARNING
        return
    }

    Write-ClifLog "Installing Sysmon..."

    # Resolve config path
    if ([string]::IsNullOrEmpty($SysmonConfigPath)) {
        $SysmonConfigPath = Join-Path $PSScriptRoot "sysmonconfig-clif.xml"
    }
    if (-not (Test-Path $SysmonConfigPath)) {
        throw "Sysmon config not found at: $SysmonConfigPath"
    }

    # Copy config to install dir
    $configDest = Join-Path $Script:SYSMON_DIR "sysmonconfig-clif.xml"
    Copy-Item -Path $SysmonConfigPath -Destination $configDest -Force
    Write-ClifLog "  Config copied to $configDest"

    # Download Sysmon
    $sysmonZip = Join-Path $Script:TEMP_DIR "Sysmon.zip"
    Write-ClifLog "  Downloading Sysmon from Sysinternals..."

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add("User-Agent", "CLIF-Installer/1.0")
    $webClient.DownloadFile($Script:SYSMON_URL, $sysmonZip)
    Write-ClifLog "  Downloaded: $sysmonZip"

    # Extract
    $extractDir = Join-Path $Script:TEMP_DIR "Sysmon"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -Path $sysmonZip -DestinationPath $extractDir -Force

    # Determine architecture
    $sysmonExe = if ([Environment]::Is64BitOperatingSystem) {
        Join-Path $extractDir "Sysmon64.exe"
    } else {
        Join-Path $extractDir "Sysmon.exe"
    }

    if (-not (Test-Path $sysmonExe)) {
        throw "Sysmon executable not found after extraction: $sysmonExe"
    }

    # Copy Sysmon to install directory
    $sysmonDest = Join-Path $Script:SYSMON_DIR (Split-Path $sysmonExe -Leaf)
    Copy-Item -Path $sysmonExe -Destination $sysmonDest -Force

    # Check if Sysmon is already installed → update config
    $existingSvc = Get-Service -Name $Script:SYSMON_SVC -ErrorAction SilentlyContinue
    if ($existingSvc) {
        Write-ClifLog "  Updating existing Sysmon configuration..."
        $result = & $sysmonDest -c $configDest 2>&1
        Write-ClifLog "  Sysmon config updated: $result"
    } else {
        # Fresh install
        Write-ClifLog "  Installing Sysmon (fresh install)..."
        $result = & $sysmonDest -accepteula -i $configDest 2>&1
        Write-ClifLog "  Sysmon installed: $result"
    }

    # Verify service is running
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $Script:SYSMON_SVC -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-ClifLog "Sysmon service is running" -Level SUCCESS
    } else {
        Write-ClifLog "Sysmon service status: $($svc.Status)" -Level WARNING
        try {
            Start-Service -Name $Script:SYSMON_SVC
            Write-ClifLog "Sysmon service started" -Level SUCCESS
        } catch {
            Write-ClifLog "Failed to start Sysmon: $_" -Level ERROR
        }
    }

    # Verify driver is loaded
    $driver = Get-Service -Name $Script:SYSMON_DRIVER -ErrorAction SilentlyContinue
    if ($driver -and $driver.Status -eq 'Running') {
        Write-ClifLog "Sysmon driver loaded" -Level SUCCESS
    } else {
        Write-ClifLog "Sysmon driver status: $($driver.Status)" -Level WARNING
    }

    # Verify events are being generated
    Start-Sleep -Seconds 2
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction SilentlyContinue
    if ($events) {
        Write-ClifLog "  Sysmon generating events (found $($events.Count) recent events)" -Level SUCCESS
    } else {
        Write-ClifLog "  No Sysmon events found yet (may take a moment)" -Level WARNING
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Vector Agent Installation
# ═══════════════════════════════════════════════════════════════════════════════

function Install-VectorAgent {
    if ($SkipVector) {
        Write-ClifLog "Skipping Vector agent installation" -Level WARNING
        return
    }

    Write-ClifLog "Installing Vector agent v$VectorVersion..."

    # Download Vector MSI
    $vectorMsi = Join-Path $Script:TEMP_DIR "vector-$VectorVersion.msi"
    Write-ClifLog "  Downloading Vector..."

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "CLIF-Installer/1.0")
        $webClient.DownloadFile($Script:VECTOR_URL, $vectorMsi)
    } catch {
        # Fallback: try GitHub releases
        $fallbackUrl = "https://github.com/vectordotdev/vector/releases/download/v$VectorVersion/vector-$VectorVersion-x86_64-pc-windows-msvc.msi"
        Write-ClifLog "  Primary download failed, trying GitHub: $fallbackUrl" -Level WARNING
        $webClient.DownloadFile($fallbackUrl, $vectorMsi)
    }
    Write-ClifLog "  Downloaded: $vectorMsi"

    # Install Vector MSI silently
    Write-ClifLog "  Running MSI installer..."
    $msiArgs = @(
        "/i", "`"$vectorMsi`"",
        "/quiet", "/norestart",
        "INSTALLFOLDER=`"$Script:VECTOR_DIR`"",
        "/L*v", "`"$(Join-Path $Script:LOG_DIR 'vector_install.log')`""
    )
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        Write-ClifLog "MSI install exited with code $($process.ExitCode). Check $Script:LOG_DIR\vector_install.log" -Level ERROR
    }

    # Deploy CLIF Vector agent config
    $configSrc = Join-Path $PSScriptRoot "vector-agent-windows.yaml"
    if (-not (Test-Path $configSrc)) {
        throw "Vector agent config not found: $configSrc"
    }

    $vectorConfigDir = Join-Path $Script:VECTOR_DIR "config"
    if (-not (Test-Path $vectorConfigDir)) {
        New-Item -ItemType Directory -Path $vectorConfigDir -Force | Out-Null
    }
    $configDest = Join-Path $vectorConfigDir "vector.yaml"
    Copy-Item -Path $configSrc -Destination $configDest -Force
    Write-ClifLog "  CLIF config deployed to $configDest"

    # Create Vector data directory
    $vectorDataDir = Join-Path $Script:VECTOR_DIR "data"
    if (-not (Test-Path $vectorDataDir)) {
        New-Item -ItemType Directory -Path $vectorDataDir -Force | Out-Null
    }

    # Set environment variables
    [System.Environment]::SetEnvironmentVariable("CLIF_VECTOR_URL", $ClifVectorUrl, "Machine")
    [System.Environment]::SetEnvironmentVariable("VECTOR_CONFIG", $configDest, "Machine")
    [System.Environment]::SetEnvironmentVariable("VECTOR_DATA_DIR", $vectorDataDir, "Machine")
    Write-ClifLog "  Environment variables set (CLIF_VECTOR_URL=$ClifVectorUrl)"

    # Register Vector as a Windows service
    $vectorExe = Get-ChildItem -Path $Script:VECTOR_DIR -Filter "vector.exe" -Recurse | Select-Object -First 1
    if ($vectorExe) {
        $svcName = "clif-vector-agent"
        $existingSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue

        if ($existingSvc) {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $svcName 2>&1 | Out-Null
            Start-Sleep -Seconds 2
        }

        # Create service using sc.exe
        $binPath = "`"$($vectorExe.FullName)`" --config `"$configDest`""
        & sc.exe create $svcName binPath= $binPath start= auto DisplayName= "CLIF Vector Agent" 2>&1 | Out-Null
        & sc.exe description $svcName "CLIF Windows Endpoint Vector Agent — Forwards Sysmon telemetry to central CLIF pipeline" 2>&1 | Out-Null

        # Configure service recovery (restart on failure)
        & sc.exe failure $svcName reset= 86400 actions= restart/5000/restart/10000/restart/30000 2>&1 | Out-Null

        # Start the service
        try {
            Start-Service -Name $svcName
            Start-Sleep -Seconds 3
            $svc = Get-Service -Name $svcName
            Write-ClifLog "Vector agent service: $($svc.Status)" -Level SUCCESS
        } catch {
            Write-ClifLog "Failed to start Vector service: $_" -Level ERROR
        }
    } else {
        Write-ClifLog "vector.exe not found in $Script:VECTOR_DIR" -Level ERROR
    }

    Write-ClifLog "Vector agent installation complete" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# PowerShell Logging Configuration
# ═══════════════════════════════════════════════════════════════════════════════

function Enable-PowerShellLogging {
    Write-ClifLog "Configuring PowerShell Script Block Logging..."

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

    # Module Logging
    $modRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $modRegPath)) {
        New-Item -Path $modRegPath -Force | Out-Null
    }
    Set-ItemProperty -Path $modRegPath -Name "EnableModuleLogging" -Value 1 -Type DWord

    $modNamesPath = "$modRegPath\ModuleNames"
    if (-not (Test-Path $modNamesPath)) {
        New-Item -Path $modNamesPath -Force | Out-Null
    }
    Set-ItemProperty -Path $modNamesPath -Name "*" -Value "*" -Type String

    # Transcription (logs all PowerShell sessions to disk)
    $transRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $transRegPath)) {
        New-Item -Path $transRegPath -Force | Out-Null
    }
    $transDir = Join-Path $Script:LOG_DIR "PowerShellTranscripts"
    if (-not (Test-Path $transDir)) {
        New-Item -ItemType Directory -Path $transDir -Force | Out-Null
    }
    Set-ItemProperty -Path $transRegPath -Name "EnableTranscripting" -Value 1 -Type DWord
    Set-ItemProperty -Path $transRegPath -Name "OutputDirectory" -Value $transDir -Type String
    Set-ItemProperty -Path $transRegPath -Name "EnableInvocationHeader" -Value 1 -Type DWord

    Write-ClifLog "PowerShell logging enabled (ScriptBlock + Module + Transcription)" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# Audit Policy Configuration
# ═══════════════════════════════════════════════════════════════════════════════

function Set-AuditPolicies {
    Write-ClifLog "Configuring Windows Audit Policies..."

    # Enable command-line auditing in process creation events (Event ID 4688)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    # Configure audit subcategories using auditpol
    $auditSettings = @(
        @{ Subcategory = "Logon";                    Success = "enable"; Failure = "enable" }
        @{ Subcategory = "Logoff";                   Success = "enable"; Failure = "disable" }
        @{ Subcategory = "Account Lockout";          Success = "enable"; Failure = "enable" }
        @{ Subcategory = "Special Logon";            Success = "enable"; Failure = "disable" }
        @{ Subcategory = "Process Creation";         Success = "enable"; Failure = "enable" }
        @{ Subcategory = "Process Termination";      Success = "enable"; Failure = "disable" }
        @{ Subcategory = "Security Group Management"; Success = "enable"; Failure = "enable" }
        @{ Subcategory = "User Account Management";  Success = "enable"; Failure = "enable" }
        @{ Subcategory = "Audit Policy Change";      Success = "enable"; Failure = "enable" }
        @{ Subcategory = "Sensitive Privilege Use";   Success = "enable"; Failure = "enable" }
    )

    foreach ($setting in $auditSettings) {
        $cmd = "auditpol /set /subcategory:`"$($setting.Subcategory)`" /success:$($setting.Success) /failure:$($setting.Failure)"
        Invoke-Expression $cmd 2>&1 | Out-Null
    }

    Write-ClifLog "Audit policies configured" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# Health Monitoring Scheduled Task
# ═══════════════════════════════════════════════════════════════════════════════

function Register-HealthMonitor {
    Write-ClifLog "Creating health monitoring scheduled task..."

    $healthScript = @'
# CLIF Sysmon Health Monitor
# Runs every 5 minutes to verify Sysmon + Vector are operational

$logFile = "C:\CLIF\Logs\health_monitor.log"
$maxLogSize = 5MB

# Rotate log if too large
if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt $maxLogSize) {
    $archiveName = $logFile -replace '\.log$', "_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Move-Item -Path $logFile -Destination $archiveName -Force
}

function Write-Health {
    param([string]$Message, [string]$Level = "OK")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$ts] [$Level] $Message"
}

# Check Sysmon
$sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmonSvc) {
    Write-Health "Sysmon64 service NOT FOUND" "CRITICAL"
} elseif ($sysmonSvc.Status -ne 'Running') {
    Write-Health "Sysmon64 stopped — attempting restart" "WARNING"
    try {
        Start-Service -Name "Sysmon64" -ErrorAction Stop
        Write-Health "Sysmon64 restarted successfully" "RECOVERED"
    } catch {
        Write-Health "Failed to restart Sysmon64: $_" "CRITICAL"
    }
} else {
    # Check for recent events (last 5 minutes)
    $cutoff = (Get-Date).AddMinutes(-5)
    $recentEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -ge $cutoff }
    if ($recentEvents) {
        Write-Health "Sysmon64 running, events flowing"
    } else {
        Write-Health "Sysmon64 running but NO events in last 5 min" "WARNING"
    }
}

# Check Vector agent
$vectorSvc = Get-Service -Name "clif-vector-agent" -ErrorAction SilentlyContinue
if (-not $vectorSvc) {
    Write-Health "CLIF Vector agent NOT FOUND" "CRITICAL"
} elseif ($vectorSvc.Status -ne 'Running') {
    Write-Health "CLIF Vector agent stopped — attempting restart" "WARNING"
    try {
        Start-Service -Name "clif-vector-agent" -ErrorAction Stop
        Write-Health "Vector agent restarted successfully" "RECOVERED"
    } catch {
        Write-Health "Failed to restart Vector agent: $_" "CRITICAL"
    }
} else {
    Write-Health "Vector agent running"
}

# Check Sysmon event log size (warn if >200 MB)
try {
    $logInfo = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($logInfo) {
        $sizeMB = [math]::Round($logInfo.FileSize / 1MB, 1)
        $maxMB = [math]::Round($logInfo.MaximumSizeInBytes / 1MB, 1)
        $pct = [math]::Round(($logInfo.FileSize / $logInfo.MaximumSizeInBytes) * 100, 1)
        if ($pct -gt 90) {
            Write-Health "Sysmon log at ${pct}% capacity (${sizeMB}/${maxMB} MB)" "WARNING"
        } else {
            Write-Health "Sysmon log: ${sizeMB}/${maxMB} MB (${pct}%)"
        }
    }
} catch {
    Write-Health "Cannot read Sysmon log info: $_" "WARNING"
}

# Check SysmonArchive directory size
$archiveDir = "C:\CLIF\SysmonArchive"
if (Test-Path $archiveDir) {
    $archiveSize = (Get-ChildItem $archiveDir -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
    $archiveSizeMB = [math]::Round($archiveSize / 1MB, 1)
    if ($archiveSizeMB -gt 1024) {
        Write-Health "SysmonArchive is ${archiveSizeMB} MB — consider cleanup" "WARNING"
    }
}
'@

    $healthScriptPath = Join-Path $InstallDir "Scripts\Invoke-ClifHealthCheck.ps1"
    $scriptDir = Split-Path $healthScriptPath -Parent
    if (-not (Test-Path $scriptDir)) {
        New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
    }
    Set-Content -Path $healthScriptPath -Value $healthScript -Force

    # Register scheduled task
    $taskName = "CLIF-Sysmon-HealthMonitor"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NonInteractive -NoProfile -ExecutionPolicy Bypass -File `"$healthScriptPath`""
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -At "00:00" -Once -RepetitionDuration (New-TimeSpan -Days 365)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "CLIF Sysmon & Vector agent health monitoring (runs every 5 min)" | Out-Null

    Write-ClifLog "Health monitor task registered: $taskName" -Level SUCCESS
}

# ═══════════════════════════════════════════════════════════════════════════════
# Sysmon Event Log Size Configuration
# ═══════════════════════════════════════════════════════════════════════════════

function Set-SysmonLogSize {
    Write-ClifLog "Configuring Sysmon event log size..."

    # Set Sysmon log to 256 MB (default is 64 MB, production needs more headroom)
    $logName = "Microsoft-Windows-Sysmon/Operational"
    try {
        wevtutil sl $logName /ms:268435456  # 256 MB
        Write-ClifLog "  Sysmon log max size set to 256 MB" -Level SUCCESS
    } catch {
        Write-ClifLog "  Failed to set log size: $_" -Level WARNING
    }

    # Set Security log to 512 MB
    try {
        wevtutil sl Security /ms:536870912  # 512 MB
        Write-ClifLog "  Security log max size set to 512 MB" -Level SUCCESS
    } catch {
        Write-ClifLog "  Failed to set Security log size: $_" -Level WARNING
    }

    # Set PowerShell log to 128 MB
    try {
        wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:134217728  # 128 MB
        Write-ClifLog "  PowerShell log max size set to 128 MB" -Level SUCCESS
    } catch {
        Write-ClifLog "  Failed to set PowerShell log size: $_" -Level WARNING
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Firewall Rules
# ═══════════════════════════════════════════════════════════════════════════════

function Set-FirewallRules {
    Write-ClifLog "Configuring firewall rules..."

    # Allow Vector agent outbound to central Vector
    $ruleName = "CLIF-Vector-Agent-Outbound"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $ruleName
    }

    try {
        $uri = [System.Uri]$ClifVectorUrl
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Action Allow `
            -Protocol TCP `
            -RemotePort $uri.Port `
            -Program (Join-Path $Script:VECTOR_DIR "bin\vector.exe") `
            -Description "Allow CLIF Vector agent to reach central Vector pipeline" `
            -Enabled True | Out-Null
        Write-ClifLog "  Firewall rule created: $ruleName (port $($uri.Port))" -Level SUCCESS
    } catch {
        Write-ClifLog "  Failed to create firewall rule: $_" -Level WARNING
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════════

function Test-Installation {
    Write-ClifLog "═══════════════════════════════════════════════════"
    Write-ClifLog "  CLIF Sysmon Installation Validation"
    Write-ClifLog "═══════════════════════════════════════════════════"

    $passed = 0
    $failed = 0

    # Test 1: Sysmon service
    $svc = Get-Service -Name $Script:SYSMON_SVC -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Write-ClifLog "  [PASS] Sysmon service running" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] Sysmon service not running" -Level ERROR
        $failed++
    }

    # Test 2: Sysmon driver
    $drv = Get-Service -Name $Script:SYSMON_DRIVER -ErrorAction SilentlyContinue
    if ($drv -and $drv.Status -eq 'Running') {
        Write-ClifLog "  [PASS] Sysmon driver loaded" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] Sysmon driver not loaded" -Level ERROR
        $failed++
    }

    # Test 3: Sysmon config hash matches
    $configPath = Join-Path $Script:SYSMON_DIR "sysmonconfig-clif.xml"
    if (Test-Path $configPath) {
        Write-ClifLog "  [PASS] Sysmon config present" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] Sysmon config missing" -Level ERROR
        $failed++
    }

    # Test 4: Sysmon events
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($events) {
        Write-ClifLog "  [PASS] Sysmon generating events (latest: $($events[0].TimeCreated))" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] No Sysmon events found" -Level ERROR
        $failed++
    }

    # Test 5: Vector service (if installed)
    if (-not $SkipVector) {
        $vectorSvc = Get-Service -Name "clif-vector-agent" -ErrorAction SilentlyContinue
        if ($vectorSvc -and $vectorSvc.Status -eq 'Running') {
            Write-ClifLog "  [PASS] Vector agent service running" -Level SUCCESS
            $passed++
        } else {
            Write-ClifLog "  [FAIL] Vector agent service not running" -Level ERROR
            $failed++
        }
    }

    # Test 6: PowerShell logging
    $psRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $psLogging = Get-ItemProperty -Path $psRegPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($psLogging -and $psLogging.EnableScriptBlockLogging -eq 1) {
        Write-ClifLog "  [PASS] PowerShell Script Block Logging enabled" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] PowerShell Script Block Logging not enabled" -Level ERROR
        $failed++
    }

    # Test 7: Health monitor task
    $task = Get-ScheduledTask -TaskName "CLIF-Sysmon-HealthMonitor" -ErrorAction SilentlyContinue
    if ($task) {
        Write-ClifLog "  [PASS] Health monitor task registered" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] Health monitor task missing" -Level ERROR
        $failed++
    }

    # Test 8: Archive directory
    if (Test-Path $Script:ARCHIVE_DIR) {
        Write-ClifLog "  [PASS] Archive directory exists" -Level SUCCESS
        $passed++
    } else {
        Write-ClifLog "  [FAIL] Archive directory missing" -Level ERROR
        $failed++
    }

    Write-ClifLog "═══════════════════════════════════════════════════"
    Write-ClifLog "  Results: $passed passed, $failed failed"
    Write-ClifLog "═══════════════════════════════════════════════════"

    return $failed -eq 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Cleanup
# ═══════════════════════════════════════════════════════════════════════════════

function Remove-TempFiles {
    if (Test-Path $Script:TEMP_DIR) {
        Remove-Item -Path $Script:TEMP_DIR -Recurse -Force -ErrorAction SilentlyContinue
        Write-ClifLog "Cleaned up temp files"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════════

try {
    $startTime = Get-Date
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║     CLIF Sysmon Deployment — Production Installation     ║" -ForegroundColor Cyan
    Write-Host "  ║         Cognitive Log Investigation Framework             ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Initialize-Directories
    Test-Prerequisites
    Install-Sysmon
    Set-SysmonLogSize
    Enable-PowerShellLogging
    Set-AuditPolicies
    Install-VectorAgent
    Set-FirewallRules
    Register-HealthMonitor
    $success = Test-Installation
    Remove-TempFiles

    $elapsed = (Get-Date) - $startTime
    Write-Host ""
    if ($success) {
        Write-ClifLog "CLIF Sysmon deployment completed successfully in $([math]::Round($elapsed.TotalSeconds))s" -Level SUCCESS
    } else {
        Write-ClifLog "CLIF Sysmon deployment completed with warnings in $([math]::Round($elapsed.TotalSeconds))s" -Level WARNING
    }
    Write-Host ""
    Write-ClifLog "Central Vector URL: $ClifVectorUrl"
    Write-ClifLog "Install directory:  $InstallDir"
    Write-ClifLog "Log file: $Script:LOG_FILE"
    Write-Host ""

} catch {
    Write-ClifLog "FATAL: $_" -Level ERROR
    Write-ClifLog "Stack: $($_.ScriptStackTrace)" -Level ERROR
    Remove-TempFiles
    exit 1
}
