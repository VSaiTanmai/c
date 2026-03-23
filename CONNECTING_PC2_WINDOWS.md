# Connecting PC2 (Windows) — SSH Setup & Docker Compose

> Replaces the MacBook with a second Windows PC running the same cores/RAM.  
> PC2 runs the compute/AI tier (`docker-compose.pc2.yml`).

---

## 1 — Enable SSH on PC2

Run these on **PC2** in PowerShell **as Administrator**:

```powershell
# Install OpenSSH Server (built-in on Windows 10 1809+ / Windows 11)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start it now and set it to auto-start on boot
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Confirm it's running
Get-Service sshd
```

> If `Add-WindowsCapability` fails (no internet on PC2), install via:  
> **Settings → Apps → Optional features → Add a feature → OpenSSH Server**

---

## 2 — Find PC2's LAN IP

Run on **PC2**:

```powershell
ipconfig | findstr /i "IPv4"
# Example output:  IPv4 Address. . . . . : 10.180.247.242
```

---

## 3 — Allow SSH Through PC2's Firewall

PowerShell as **Administrator on PC2**:

```powershell
New-NetFirewallRule -Name "OpenSSH-Server-In" `
    -DisplayName "OpenSSH Server (port 22)" `
    -Protocol TCP -LocalPort 22 `
    -Direction Inbound -Action Allow
```

---

## 4 — SSH from PC1 into PC2

On **PC1** (PowerShell — no admin needed):

```powershell
ssh <PC2_username>@<PC2_IP>
# Example:
ssh reddy@10.180.247.242
```

First connection will show a fingerprint prompt — type `yes` to trust it.

### Set up passwordless SSH (recommended for repeated use)

On **PC1**:

```powershell
# Generate a key pair if you don't have one yet
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\clif_pc2" -N ""

# Copy the public key to PC2
type "$env:USERPROFILE\.ssh\clif_pc2.pub" | ssh reddy@10.180.247.242 "powershell -Command `"New-Item -Force -ItemType Directory $HOME\.ssh; Add-Content $HOME\.ssh\authorized_keys ([Console]::In.ReadToEnd())`""
```

Then connect without a password:

```powershell
ssh -i "$env:USERPROFILE\.ssh\clif_pc2" reddy@10.180.247.242
```

---

## 5 — Clone the Repo on PC2 (via SSH session)

After SSHing into PC2:

```powershell
# On PC2 (inside SSH session)
git clone https://github.com/Nethrananda21/clif-log-investigation.git C:\CLIF
cd C:\CLIF
```

---

## 6 — Configure PC2 for the CLIF Stack

Still on **PC2** (via SSH or directly), run the setup script:

```powershell
cd C:\CLIF
.\cluster\setup.ps1 -Role pc2 -DataIP 10.180.247.221   # PC1's LAN IP
```

This writes `cluster\.env` with `DATA_IP=10.180.247.221` so containers know where PC1's Redpanda + ClickHouse live.

Copy and fill in the main env:

```powershell
Copy-Item .env.example .env
# Edit .env — match the same credentials you used on PC1
notepad .env
```

---

## 7 — Start Docker Compose on PC2 (from PC1 via SSH)

You can trigger PC2's stack directly from PC1 in one line:

```powershell
ssh reddy@10.180.247.242 "cd C:\CLIF && docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d"
```

Or SSH in interactively and run:

```powershell
cd C:\CLIF
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d
```

### What PC2 runs

| Container | Role | Port |
|-----------|------|------|
| `clif-vector` | Log ingestion → PC1 Redpanda | 8686 (API), 1514 (syslog) |
| `clif-triage-1 / 2` | ML triage agents (2 workers) | 8300 / 8301 |
| `clif-hunter` | Attack investigation agent | 8400 |
| `clif-verifier` | Evidence verification agent | 8500 |
| `clif-xai` | SHAP explainability service | 8200 |
| `clif-lancedb` *(--profile full)* | Vector semantic search | 8100 |
| `clif-merkle` | Merkle evidence anchoring | 8600 |
| `prometheus` | Metrics | 9090 |
| `grafana` | Dashboards | 3002 |

With LanceDB (full profile):

```powershell
docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env --profile full up -d
```

---

## 8 — Update Dashboard `.env.local` on PC1

Edit `C:\CLIF\dashboard\.env.local` on PC1 to point AI services at PC2:

```env
AI_SERVICE_URL=http://10.180.247.242:8200
LANCEDB_URL=http://10.180.247.242:8100
PROMETHEUS_URL=http://10.180.247.242:9090
```

Then restart the dashboard:

```powershell
cd C:\CLIF\dashboard
npx next dev -p 3002
```

---

## 9 — Firewall Rules on PC1 (allow PC2 in)

On **PC1** as Administrator — same rules as before, just add PC2's IP:

```powershell
$pc2_ip = "10.180.247.242"   # PC2's LAN IP

$ports = @(19092, 29092, 39092, 8123, 9000, 9002, 9003, 9644, 9645, 9646, 8080, 8600)

foreach ($port in $ports) {
    New-NetFirewallRule -DisplayName "CLIF-PC2-$port" `
        -Direction Inbound -Protocol TCP `
        -LocalPort $port `
        -RemoteAddress $pc2_ip `
        -Action Allow -ErrorAction SilentlyContinue
}
```

Or with the helper (already handles this):

```powershell
.\cluster\firewall-pc1.ps1
```

---

## 10 — Verify

**From PC1, check PC2 services via SSH:**

```powershell
ssh reddy@10.180.247.242 "docker compose -f C:\CLIF\docker-compose.pc2.yml ps"
```

**Or hit the health endpoints from PC1:**

```powershell
$pc2 = "10.180.247.242"
curl "http://${pc2}:8300/health"   # Triage Agent
curl "http://${pc2}:8400/health"   # Hunter Agent
curl "http://${pc2}:8500/health"   # Verifier Agent
curl "http://${pc2}:8200/health"   # XAI Service
curl "http://${pc2}:8686/health"   # Vector
```

---

## Quick Reference

| Task | Command (run on PC1) |
|------|----------------------|
| Open SSH session to PC2 | `ssh reddy@10.180.247.242` |
| Start PC2 stack remotely | `ssh reddy@10.180.247.242 "cd C:\CLIF && docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d"` |
| Stop PC2 stack remotely | `ssh reddy@10.180.247.242 "cd C:\CLIF && docker compose -f docker-compose.pc2.yml down"` |
| View PC2 container status | `ssh reddy@10.180.247.242 "docker compose -f C:\CLIF\docker-compose.pc2.yml ps"` |
| View PC2 container logs | `ssh reddy@10.180.247.242 "docker logs clif-triage-1 --tail 50"` |
| Pull latest code on PC2 | `ssh reddy@10.180.247.242 "cd C:\CLIF && git pull"` |
| Rebuild agents on PC2 | `ssh reddy@10.180.247.242 "cd C:\CLIF && docker compose -f docker-compose.pc2.yml --env-file .env --env-file cluster\.env up -d --build"` |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ssh: connect to host ... port 22` | Check `Get-Service sshd` on PC2 — must be `Running` |
| Permission denied (publickey) | Use password auth first: `ssh reddy@<ip>` — or re-copy the key |
| Docker not found in SSH session | Docker Desktop adds Docker to `$PATH` for interactive sessions. In SSH, prepend path: `& "C:\Program Files\Docker\Docker\resources\bin\docker.exe"` or install Docker Engine directly (no Desktop) |
| Containers can't reach PC1 | Run `.\cluster\setup.ps1 -Role pc2 -DataIP <PC1_IP>` again — checks connectivity |
| Port 22 blocked by corporate network | Use VPN or set SSH to port 443: in `C:\ProgramData\ssh\sshd_config`, change `#Port 22` → `Port 443` and restart `sshd` |
