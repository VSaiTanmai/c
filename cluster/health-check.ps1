# =============================================================================
# CLIF Cluster — Health Check Script
# =============================================================================
# Run on either PC to verify the cluster is operational.
# =============================================================================

param(
    [ValidateSet("pc1","pc2","all")]
    [string]$Role = "all",

    [string]$DataIP
)

$ErrorActionPreference = "SilentlyContinue"

# Read DATA_IP from cluster/.env if not provided
if (-not $DataIP) {
    $envFile = Join-Path $PSScriptRoot ".env"
    if (Test-Path $envFile) {
        $DataIP = (Get-Content $envFile | Where-Object { $_ -match "^DATA_IP=" }) -replace "DATA_IP=", ""
    }
    if (-not $DataIP -or $DataIP -eq "CHANGE_ME") {
        Write-Host "ERROR: DATA_IP not set. Run setup.ps1 first or pass -DataIP." -ForegroundColor Red
        exit 1
    }
}

$pass = 0; $fail = 0; $warn = 0

function Test-Endpoint {
    param([string]$Name, [string]$Host, [int]$Port, [string]$HttpPath)

    if ($HttpPath) {
        try {
            $resp = Invoke-WebRequest -Uri "http://${Host}:${Port}${HttpPath}" -TimeoutSec 3 -UseBasicParsing 2>$null
            if ($resp.StatusCode -eq 200) {
                Write-Host "  OK    $Name" -ForegroundColor Green
                $script:pass++
                return
            }
        } catch {}
        Write-Host "  FAIL  $Name (http://${Host}:${Port}${HttpPath})" -ForegroundColor Red
        $script:fail++
    } else {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ConnectAsync($Host, $Port).Wait(2000) | Out-Null
            if ($tcp.Connected) {
                Write-Host "  OK    $Name ($Port)" -ForegroundColor Green
                $tcp.Close()
                $script:pass++
                return
            }
            $tcp.Close()
        } catch {}
        Write-Host "  FAIL  $Name ($Host`:$Port)" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  CLIF Cluster Health Check" -ForegroundColor Cyan
Write-Host "  DATA_IP = $DataIP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ── PC1 Data Tier ──────────────────────────────────────────────────────────
if ($Role -in "pc1","all") {
    Write-Host "`n── PC1 Data Tier ($DataIP) ──" -ForegroundColor Yellow

    Test-Endpoint "Redpanda 01 (Kafka)"    $DataIP 19092
    Test-Endpoint "Redpanda 02 (Kafka)"    $DataIP 29092
    Test-Endpoint "Redpanda 03 (Kafka)"    $DataIP 39092
    Test-Endpoint "Redpanda Admin"         $DataIP 9644  "/v1/status/ready"
    Test-Endpoint "ClickHouse 01 (HTTP)"   $DataIP 8123  "/ping"
    Test-Endpoint "ClickHouse 02 (HTTP)"   $DataIP 8124  "/ping"
    Test-Endpoint "ClickHouse 01 (Native)" $DataIP 9000
    Test-Endpoint "MinIO (Data)"           $DataIP 9002  "/minio/health/live"
    Test-Endpoint "MinIO (Console)"        $DataIP 9003

    # Quick ClickHouse query
    try {
        $chUser = "clif_admin"
        $body = "SELECT count() FROM clif_logs.raw_events"
        $resp = Invoke-WebRequest -Uri "http://${DataIP}:8123/?user=$chUser&password=Cl1f_Ch%40ngeM3_2026!" `
            -Method POST -Body $body -TimeoutSec 5 -UseBasicParsing 2>$null
        $count = $resp.Content.Trim()
        Write-Host "  OK    ClickHouse query: $count events in raw_events" -ForegroundColor Green
        $pass++
    } catch {
        Write-Host "  WARN  ClickHouse query failed (may need credentials)" -ForegroundColor Yellow
        $warn++
    }

    # Redpanda topic check
    try {
        $rpkOut = docker exec clif-redpanda01 rpk topic list --no-header 2>$null
        $topicCount = ($rpkOut | Measure-Object -Line).Lines
        if ($topicCount -ge 14) {
            Write-Host "  OK    Redpanda topics: $topicCount" -ForegroundColor Green
            $pass++
        } else {
            Write-Host "  WARN  Redpanda topics: $topicCount (expected 14)" -ForegroundColor Yellow
            $warn++
        }
    } catch {
        Write-Host "  SKIP  Redpanda topic check (not running locally)" -ForegroundColor Gray
    }
}

# ── PC2 Compute Tier ──────────────────────────────────────────────────────
if ($Role -in "pc2","all") {
    Write-Host "`n── PC2 Compute Tier (localhost) ──" -ForegroundColor Yellow

    Test-Endpoint "Vector API"         "localhost" 8686  "/health"
    Test-Endpoint "Vector Syslog"      "localhost" 1514
    Test-Endpoint "LanceDB"            "localhost" 8100  "/health"
    Test-Endpoint "AI Classifier"      "localhost" 8200  "/health"
    Test-Endpoint "Redpanda Console"   "localhost" 8080  "/admin/health"
    Test-Endpoint "Prometheus"         "localhost" 9090  "/-/healthy"
    Test-Endpoint "Grafana"            "localhost" 3002  "/api/health"
    Test-Endpoint "Dashboard"          "localhost" 3001

    # Check agent health (placeholders may not be running yet)
    foreach ($agent in @(@{N="Triage";P=8300},@{N="Hunter";P=8400},@{N="Verifier";P=8500})) {
        Test-Endpoint "$($agent.N) Agent" "localhost" $agent.P "/health"
    }
}

# ── Cross-Host Pipeline Test ──────────────────────────────────────────────
if ($Role -eq "all") {
    Write-Host "`n── Cross-Host Pipeline Test ──" -ForegroundColor Yellow

    # Send a test log via Vector HTTP → Redpanda → ClickHouse
    $testPayload = @{
        message  = "CLIF cluster health check test $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')"
        hostname = "health-check"
        severity = "info"
    } | ConvertTo-Json

    try {
        Invoke-WebRequest -Uri "http://localhost:8687" -Method POST `
            -Body $testPayload -ContentType "application/json" `
            -TimeoutSec 5 -UseBasicParsing | Out-Null
        Write-Host "  OK    Sent test event to Vector (port 8687)" -ForegroundColor Green
        $pass++

        Write-Host "  ...   Waiting 5s for pipeline propagation" -ForegroundColor Gray
        Start-Sleep -Seconds 5

        $body = "SELECT count() FROM clif_logs.raw_events WHERE host_name = 'health-check' AND event_time > now() - INTERVAL 30 SECOND"
        $resp = Invoke-WebRequest -Uri "http://${DataIP}:8123/?user=clif_admin&password=Cl1f_Ch%40ngeM3_2026!" `
            -Method POST -Body $body -TimeoutSec 5 -UseBasicParsing 2>$null
        $hitCount = [int]$resp.Content.Trim()
        if ($hitCount -gt 0) {
            Write-Host "  OK    End-to-end pipeline verified ($hitCount events reached ClickHouse)" -ForegroundColor Green
            $pass++
        } else {
            Write-Host "  WARN  Test event not yet in ClickHouse (pipeline may be slow)" -ForegroundColor Yellow
            $warn++
        }
    } catch {
        Write-Host "  FAIL  Pipeline test failed: $_" -ForegroundColor Red
        $fail++
    }
}

# ── Summary ────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
$total = $pass + $fail + $warn
$color = if ($fail -eq 0) { "Green" } elseif ($fail -le 2) { "Yellow" } else { "Red" }
Write-Host "  Results: $pass passed, $fail failed, $warn warnings ($total total)" -ForegroundColor $color
Write-Host "========================================`n" -ForegroundColor Cyan

exit $fail
