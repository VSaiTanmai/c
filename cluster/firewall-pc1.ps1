# =============================================================================
# CLIF Cluster — Firewall Configuration for PC1 (Data Tier)
# =============================================================================
# Run as Administrator on PC1 to open required ports for PC2 access.
# =============================================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "`nConfiguring Windows Firewall for CLIF Cluster..." -ForegroundColor Cyan

$rules = @(
    @{Name="CLIF-Redpanda-Kafka";     Port="19092,29092,39092"; Desc="Redpanda Kafka external listeners"}
    @{Name="CLIF-Redpanda-Proxy";     Port="18082,28082,38082"; Desc="Redpanda Pandaproxy"}
    @{Name="CLIF-Redpanda-Admin";     Port="9644,9645,9646";    Desc="Redpanda Admin API / metrics"}
    @{Name="CLIF-ClickHouse-HTTP";    Port="8123,8124";         Desc="ClickHouse HTTP API"}
    @{Name="CLIF-ClickHouse-Native";  Port="9000,9001";         Desc="ClickHouse Native protocol"}
    @{Name="CLIF-ClickHouse-Metrics"; Port="9363,9364";         Desc="ClickHouse Prometheus metrics"}
    @{Name="CLIF-MinIO";              Port="9002,9003";         Desc="MinIO data + console"}
    @{Name="CLIF-CH-Keeper";          Port="12181";             Desc="ClickHouse Keeper"}
)

foreach ($r in $rules) {
    $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  UPDATE $($r.Name) → $($r.Port)" -ForegroundColor Yellow
        $existing | Remove-NetFirewallRule
    } else {
        Write-Host "  ADD    $($r.Name) → $($r.Port)" -ForegroundColor Green
    }

    New-NetFirewallRule -DisplayName $r.Name `
        -Direction Inbound -Action Allow -Protocol TCP `
        -LocalPort ($r.Port -split ',') `
        -Description $r.Desc `
        -Profile Private,Domain | Out-Null
}

Write-Host "`nFirewall rules configured. PC2 can now reach data services." -ForegroundColor Green
Write-Host "To remove rules later:  Get-NetFirewallRule -DisplayName 'CLIF-*' | Remove-NetFirewallRule`n" -ForegroundColor Gray
