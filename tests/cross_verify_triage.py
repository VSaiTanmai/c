#!/usr/bin/env python3
"""
CLIF — Ground-Truth Cross-Verification of Triage Scores (v5)
==============================================================
Systematically labels every test event with a human-audited ground truth
(malicious / suspicious / benign), then compares against the triage agent's
predicted action (escalate / monitor / discard).

Run INSIDE the triage container:
    docker cp tests/cross_verify_triage.py clif-triage-agent:/app/cross_verify_triage.py
    docker exec -e SCORE_WEIGHTS="lgbm=0.80,eif=0.12,arf=0.08" \
                -e DEFAULT_SUSPICIOUS_THRESHOLD=0.35 \
                -e DEFAULT_ANOMALOUS_THRESHOLD=0.78 \
                clif-triage-agent python /app/cross_verify_triage.py
"""

from __future__ import annotations
import re, sys, json
from datetime import datetime, timezone
from collections import defaultdict

sys.path.insert(0, "/app")
import config
from clickhouse_driver import Client


# ═══════════════════════════════════════════════════════════════════════════════
# GROUND-TRUTH RULES — applied in priority order to the message body
# ═══════════════════════════════════════════════════════════════════════════════
# Each rule: (compiled_regex_pattern, ground_truth_label, short_reason)
#   ground_truth: "malicious" | "suspicious" | "benign"
#   Expected triage action mapping:
#     malicious  → escalate
#     suspicious → monitor
#     benign     → discard

GROUND_TRUTH_RULES = [
    # ── MALICIOUS patterns (definitive attacks) ────────────────────────────

    # Reverse shells / bind shells
    (re.compile(r"nc\s+-[el].*(/bin/(ba)?sh|/bin/sh)", re.I),
     "malicious", "reverse/bind shell via netcat"),
    (re.compile(r"os\.dup2.*subprocess.*call.*bin/(ba)?sh", re.I),
     "malicious", "Python reverse shell"),
    (re.compile(r"socket\.connect.*dup2.*subprocess", re.I),
     "malicious", "Python reverse shell (variant)"),
    (re.compile(r"Meterpreter|Metasploit", re.I),
     "malicious", "Meterpreter/Metasploit detected"),
    (re.compile(r"CnC Response|CnC\s", re.I),
     "malicious", "C2/CnC communication"),
    (re.compile(r"Reverse TCP Shell", re.I),
     "malicious", "Reverse TCP shell"),

    # Exploits
    (re.compile(r"ShellShock", re.I),
     "malicious", "ShellShock exploit"),
    (re.compile(r"EternalBlue", re.I),
     "malicious", "EternalBlue exploit"),
    (re.compile(r"buffer overflow attempt", re.I),
     "malicious", "Buffer overflow exploit"),
    (re.compile(r"Path Traversal Attempt|/\.\./\.\./\.\./etc/passwd|cgi-bin/\.\./\.\./", re.I),
     "malicious", "Path traversal attack"),
    (re.compile(r"SQL.Injection", re.I),
     "malicious", "SQL injection"),
    (re.compile(r"EncodedCommand|IEX.*DownloadString|powershell.*-[eE]nc", re.I),
     "malicious", "Encoded PowerShell execution"),

    # Privilege escalation
    (re.compile(r"setuid\(0\) succeeded for unprivileged|euid=0.*uid=\d{4}", re.I),
     "malicious", "Privilege escalation (setuid)"),
    (re.compile(r"net user.*backdoor.*(/add|/add.*administrators)", re.I),
     "malicious", "Backdoor account creation"),
    (re.compile(r"chmod\s+4755\s+/bin/bash", re.I),
     "malicious", "SUID bash escalation"),
    (re.compile(r"setuid bit detected.*vim", re.I),
     "malicious", "SUID vim privilege escalation"),

    # Data exfiltration / theft
    (re.compile(r"dd\s+if=/dev/sda.*nc\s+", re.I),
     "malicious", "Disk exfiltration via dd+nc"),
    (re.compile(r"scp.*exfil|scp.*/etc/passwd.*backup@", re.I),
     "malicious", "Data exfiltration via scp"),
    (re.compile(r"data exfiltration", re.I),
     "malicious", "Data exfiltration alert"),
    (re.compile(r"cat.*/etc/shadow", re.I),
     "malicious", "Credential theft (/etc/shadow)"),
    (re.compile(r"reading directory.*reading /etc/shadow|840MB/s.*/dev/null", re.I),
     "malicious", "Mass data read from /etc/shadow"),

    # Malware download & execution
    (re.compile(r"curl.*\|\s*bash|wget.*\|\s*bash|curl -s http.*setup\.sh", re.I),
     "malicious", "Download-and-execute (curl|bash)"),
    (re.compile(r"pastebin\.io/raw|pastebin.*wget.*apache", re.I),
     "malicious", "Web shell pastebin download"),
    (re.compile(r"/tmp/\.hidden/(update|sshd)|/tmp/\.hidden\.sh|/dev/shm/\.x", re.I),
     "malicious", "Hidden malware path"),
    (re.compile(r"gcc.*-o.*/tmp/backdoor", re.I),
     "malicious", "Compiling backdoor"),
    (re.compile(r"ELF file download", re.I),
     "malicious", "Malware binary download"),
    (re.compile(r"chmod\s+\+x.*/tmp/\.hidden", re.I),
     "malicious", "Making malware executable"),
    (re.compile(r"a0=\"/tmp/\.hidden/update\"", re.I),
     "malicious", "Executing hidden malware"),

    # Backdoor / persistence
    (re.compile(r"crontab.*heartbeat.*bash|echo.*crontab", re.I),
     "malicious", "Cron persistence mechanism"),
    (re.compile(r"Hidden.*sshd.*port 2222|/tmp/\.hidden/sshd", re.I),
     "malicious", "Backdoor SSH daemon"),
    (re.compile(r"kthreadd.*masquerad|binary masquerades as kernel", re.I),
     "malicious", "Process masquerading"),

    # Log tampering
    (re.compile(r"auth\.log was truncated|truncated from.*to 0 bytes", re.I),
     "malicious", "Log tampering"),

    # Brute force (high confidence)
    (re.compile(r"count=847 in 60s|count=2100 failures in 180s", re.I),
     "malicious", "Massive brute force"),
    (re.compile(r"id check returned root|uid=0\(root\) gid=0\(root\)", re.I),
     "malicious", "Successful exploitation (returned root)"),

    # Network attack patterns
    (re.compile(r"Nmap Scripting Engine", re.I),
     "malicious", "Nmap scanning"),
    (re.compile(r"DNS.*Tunnel|DNS Long TXT|exfil-domain", re.I),
     "malicious", "DNS tunneling"),
    (re.compile(r"port scan pattern detected|1024 ports in 30s", re.I),
     "malicious", "Port scanning"),
    (re.compile(r"lateral movement blocked|DMZ.*LAN.*lateral", re.I),
     "malicious", "Lateral movement attempt"),
    (re.compile(r"ANOMALY.*840Mbps.*ICMP|does not exist in DHCP", re.I),
     "malicious", "ICMP amplification/DoS"),

    # Anonymous/unauthorized access
    (re.compile(r"ANONYMOUS.*12000 files|samba.*ANONYMOUS", re.I),
     "malicious", "Unauthorized anonymous SMB access"),
    (re.compile(r"4TB anomalous|4398046511104.*GET.*application/octet-stream", re.I),
     "malicious", "Anomalous massive download"),

    # base64 decode + execute
    (re.compile(r"base64.*-d.*/tmp/.*\.cache.*piped to /bin/sh", re.I),
     "malicious", "Encoded payload execution"),

    # SSH brute force from external IPs
    (re.compile(r"Failed password.*from (45\.|93\.|185\.|198\.51|203\.0\.113)", re.I),
     "malicious", "SSH brute force from external IP"),

    # Brute force rapid sequence from single internal IP (the 192.168.1.100 series)
    (re.compile(r"Failed password for invalid user.*(admin|root|test|guest|oracle|postgres|mysql|tomcat|apache).*192\.168\.1\.100", re.I),
     "malicious", "SSH brute force from internal (compromised host)"),
    # Login success AFTER brute force from same IP
    (re.compile(r"Accepted password for jsmith.*192\.168\.1\.100.*54330", re.I),
     "malicious", "Successful brute force (account compromised)"),

    # Kerberos attacks
    (re.compile(r"Kerberos.*PREAUTH_FAILED|4768.*PREAUTH_FAILED", re.I),
     "malicious", "Kerberos brute force"),
    (re.compile(r"krbtgt.*non-DC host|4769.*krbtgt.*non-DC", re.I),
     "malicious", "Kerberoasting / Golden Ticket"),

    # Windows failed logon (from brute force context)
    (re.compile(r"4625.*An account failed to log on.*Administrator", re.I),
     "malicious", "Windows brute force"),

    # Privilege escalation via sudo (anomalous)
    (re.compile(r"sudo.*USER=root.*COMMAND=/bin/bash.*not used sudo in \d+ days", re.I),
     "malicious", "Anomalous sudo to root shell"),

    # Auth failure targeting service accounts
    (re.compile(r"authentication failure.*rhost=198\.51\.100.*www-data", re.I),
     "malicious", "Brute force on service account"),

    # Tor/C2 long connections
    (re.compile(r"185\.220\.101\.\d+.*9001|dst_port=9001.*185\.220", re.I),
     "malicious", "Tor C2 connection"),
    (re.compile(r"beacon_score=0\.9[0-9]|beacon_score=1\.0", re.I),
     "malicious", "C2 beacon (high score)"),

    # ADMIN$ share access
    (re.compile(r"ADMIN\$|smb_share=.*ADMIN", re.I),
     "malicious", "ADMIN$ lateral movement"),

    # Successful path traversal
    (re.compile(r"%2e%2e.*etc.*passwd.*status_code=200", re.I),
     "malicious", "Successful path traversal (200 OK)"),

    # Unencrypted RDP with high volume
    (re.compile(r"rdp.*encryption=none|3389.*encryption=none", re.I),
     "malicious", "Unencrypted RDP lateral movement"),

    # Invalid cert to suspicious IP
    (re.compile(r"Invalid_Server_Cert.*185\.220|185\.220.*Invalid_Server_Cert", re.I),
     "malicious", "TLS to C2 with invalid cert"),
    (re.compile(r"SSL::Invalid_Server_Cert", re.I),
     "malicious", "Invalid SSL certificate"),

    # SQL injection from Zeek notice
    (re.compile(r"HTTP::SQL_Injection_Attacker", re.I),
     "malicious", "SQL injection (Zeek notice)"),

    # SCAN MSSQL series
    (re.compile(r"ET SCAN.*inbound.*MSSQL|ET SCAN.*port 1433", re.I),
     "malicious", "MSSQL port scan"),
    # SSH scan outbound
    (re.compile(r"ET SCAN.*SSH Scan OUTBOUND|Potential SSH Scan OUTBOUND", re.I),
     "malicious", "SSH scan outbound (lateral recon)"),

    # cron curl suspicious external
    (re.compile(r"curl -s http.*198\.51\.100|curl.*update\.sh.*bash", re.I),
     "malicious", "Malicious cron curl|bash"),

    # at job with privilege escalation
    (re.compile(r"at.*chmod.*4755.*bash|at job.*chmod.*bash", re.I),
     "malicious", "Scheduled privilege escalation"),

    # ── SUSPICIOUS patterns ────────────────────────────────────────────────

    # Failed password for named users from internal IPs (single failures)
    (re.compile(r"Failed password for", re.I),
     "suspicious", "SSH failed password (residual)"),

    # SUID enumeration from new geo
    (re.compile(r"find.*-perm.*-4000|SUID.*enum", re.I),
     "suspicious", "SUID binary enumeration"),

    # Recon commands
    (re.compile(r"grep.*-i.*password.*/var/log", re.I),
     "suspicious", "Password hunting in logs"),
    (re.compile(r"base64.*/tmp/archive", re.I),
     "suspicious", "Encoding archive for exfiltration"),
    (re.compile(r"tar.*-czf.*archive.*www", re.I),
     "suspicious", "Staging web content for exfil"),
    (re.compile(r"a0=\"/usr/bin/last\"", re.I),
     "suspicious", "User activity enumeration (last)"),
    (re.compile(r"cat.*/var/log/auth\.log", re.I),
     "suspicious", "Auth log review (recon)"),
    (re.compile(r"netstat.*-tulpn", re.I),
     "suspicious", "Network enumeration (netstat)"),
    (re.compile(r"a0=\"/usr/bin/ps\".*aux", re.I),
     "suspicious", "Process enumeration (ps aux)"),
    (re.compile(r"find.*/.*-name.*\.conf", re.I),
     "suspicious", "Config file enumeration"),
    (re.compile(r"cat.*/etc/sudoers", re.I),
     "suspicious", "Sudoers enumeration"),
    (re.compile(r"ls.*/root|-la /root", re.I),
     "suspicious", "Root directory enumeration"),
    (re.compile(r"sudo.*whoami|-S.*whoami", re.I),
     "suspicious", "Privilege check (sudo whoami)"),
    (re.compile(r"curl.*-I.*http://45\.|curl.*http://185\.", re.I),
     "suspicious", "Curl to suspicious external IP"),

    # Anomalous RDP / SMB / SSH
    (re.compile(r"smb.*REJ|445.*conn_state.*REJ", re.I),
     "suspicious", "Rejected SMB connection"),
    (re.compile(r"rdp.*REJ|3389.*REJ", re.I),
     "suspicious", "Rejected RDP connection"),
    (re.compile(r"conn_state.*RSTR|RSTR.*ssh", re.I),
     "suspicious", "Reset SSH connection"),
    (re.compile(r"conn_state.*S0.*ssh|ssh.*S0", re.I),
     "suspicious", "SSH no-reply (scanning)"),
    (re.compile(r"service.*snmp.*S0|snmp.*conn_state.*S0", re.I),
     "suspicious", "SNMP scan (no reply)"),

    # Long-duration connections (beaconing indicators)
    (re.compile(r"duration.*1[28]00\.|duration.*86401", re.I),
     "suspicious", "Long-duration connection (beaconing)"),

    # Scan-related alerts
    (re.compile(r"ET SCAN Suspicious inbound.*mySQL|ET SCAN.*to mySQL", re.I),
     "suspicious", "MySQL inbound scan alert"),
    (re.compile(r"broadcast sweep|256 hosts in 4s", re.I),
     "suspicious", "ICMP broadcast sweep"),

    # UFW BLOCK repeated from same source (internal)
    (re.compile(r"\[UFW BLOCK\].*192\.168\.1\.200.*DPT=22", re.I),
     "suspicious", "Repeated blocked SSH from internal host"),
    (re.compile(r"UFW BLOCK.*SRC=203\.0\.113", re.I),
     "suspicious", "Blocked external traffic"),
    (re.compile(r"UFW BLOCK.*SRC=45\.67\.89", re.I),
     "suspicious", "Blocked traffic from suspicious IP"),
    (re.compile(r"UFW BLOCK.*SRC=198\.51\.100", re.I),
     "suspicious", "Blocked traffic from suspicious IP"),

    # Other blocked/dropped packets
    (re.compile(r"\[DROP\].*SRC=10\.0\.0\.55.*DPT=445", re.I),
     "suspicious", "Blocked internal SMB attempt"),
    (re.compile(r"\[DROP\].*172\.20\.0\.30.*198\.51\.100", re.I),
     "suspicious", "Blocked DNS to suspicious IP"),
    (re.compile(r"Potential outbound.*known bad domain", re.I),
     "suspicious", "Connection to suspicious domain"),
    (re.compile(r"Unusual SMB traffic volume", re.I),
     "suspicious", "Anomalous SMB traffic volume"),

    # OOM killed
    (re.compile(r"Out of memory.*Kill process|OOM.*Kill", re.I),
     "suspicious", "OOM kill (possible resource abuse)"),
    # Martian source
    (re.compile(r"martian source", re.I),
     "suspicious", "Martian source packet"),
    # rsyslogd overflow
    (re.compile(r"rsyslogd.*messages lost|queue overflow", re.I),
     "suspicious", "Log message loss"),
    # Ext4 error with python
    (re.compile(r"EXT4-fs error.*python3", re.I),
     "suspicious", "Filesystem error from suspicious process"),

    # ET POLICY ELF / Executable
    (re.compile(r"ET POLICY Exe.*linking format", re.I),
     "suspicious", "Potentially bad ELF traffic"),

    # Snort/IDS attack response
    (re.compile(r"ATTACK_RESPONSE", re.I),
     "suspicious", "Attack response detected"),

    # SMB with large data to external
    (re.compile(r"smb.*198\.51\.100|445.*198\.51\.100|12345678.*smb", re.I),
     "suspicious", "Large SMB to external IP"),

    # First-time login from new IP
    (re.compile(r"never logged in from.*before|first login", re.I),
     "suspicious", "First login from unknown IP"),

    # Accepted keyboard-interactive
    (re.compile(r"Accepted keyboard-interactive", re.I),
     "suspicious", "Interactive auth session"),

    # Connection from suspicious IP without auth result
    (re.compile(r"Connection from 45\.67\.89", re.I),
     "suspicious", "Connection from suspicious IP"),

    # Multiple rapid publickey sessions (automation)
    (re.compile(r"Accepted publickey for dbadmin.*10\.0\.0\.25", re.I),
     "suspicious", "Rapid repeated publickey sessions"),

    # CRON external curl (not download-and-execute, just -I)
    (re.compile(r"CRON.*curl.*185\.199", re.I),
     "suspicious", "Suspicious cron curling external IP"),

    # Root password login
    (re.compile(r"Accepted password for root", re.I),
     "suspicious", "Root password login"),

    # MySQL to external IP
    (re.compile(r"3306.*203\.0\.113|mysql.*external", re.I),
     "suspicious", "MySQL connection to external"),

    # ICMP to external (recon)
    (re.compile(r"icmp.*198\.51\.100|icmp.*external", re.I),
     "suspicious", "ICMP to external (recon)"),

    # Source port 4444 (Metasploit default)
    (re.compile(r"src.*port.*4444|SPT=4444|orig_p.*4444", re.I),
     "suspicious", "Source port 4444 (Metasploit)"),

    # Publickey deploy from new IP
    (re.compile(r"Accepted publickey for deploy.*203\.0\.113", re.I),
     "suspicious", "Deploy login from external IP"),

    # DNS large response / anomalous
    (re.compile(r"dns.*response_ttl=0|dns.*query_count.*response.*4096", re.I),
     "suspicious", "Anomalous DNS response"),

    # REJ SSH
    (re.compile(r"ssh.*REJ|22.*conn_state.*REJ", re.I),
     "suspicious", "Rejected SSH connection"),

    # wget (alone, without pipe to bash)
    (re.compile(r"wget.*payload|wget.*http://185", re.I),
     "suspicious", "Downloading from suspicious URL"),

    # Malformed packet
    (re.compile(r"SPT=0 DPT=0.*malformed|malformed packet", re.I),
     "suspicious", "Malformed packet"),

    # Large file transfer on conn
    (re.compile(r"resp_bytes.*52428800|orig_bytes.*10485760", re.I),
     "suspicious", "Large file transfer"),

    # JA3 fingerprint (C2-like)
    (re.compile(r"ja3=.*ja3s=|ssl.*ja3", re.I),
     "suspicious", "TLS with JA3 fingerprint (C2 indicator)"),

    # ── BENIGN patterns ────────────────────────────────────────────────────

    # Normal systemd sessions
    (re.compile(r"Started [Ss]ession \d+ of user", re.I),
     "benign", "Normal systemd session start"),
    # Normal publickey auth (generic)
    (re.compile(r"Accepted publickey for", re.I),
     "benign", "Normal publickey authentication"),
    # Normal sudo session
    (re.compile(r"pam_unix\(sudo:session\): session opened", re.I),
     "benign", "Normal sudo session open"),
    # UFW ALLOW
    (re.compile(r"UFW ALLOW", re.I),
     "benign", "Normal UFW allow"),
    # Normal DNS (small, < 200 bytes)
    (re.compile(r"dns.*duration.*0\.0[0-2]\d", re.I),
     "benign", "Normal DNS query"),
    # Normal HTTP (small)
    (re.compile(r"http.*duration.*0\.0[0-8]\d.*orig_bytes.*\d{1,3}\b", re.I),
     "benign", "Normal HTTP connection"),
    # Localhost traffic
    (re.compile(r"SRC=127\.0\.0\.1.*DST=127\.0\.0\.1", re.I),
     "benign", "Localhost traffic (benign)"),
    # Audit PAM accounting
    (re.compile(r"audit.*PAM:accounting.*res=success", re.I),
     "benign", "Normal PAM accounting"),
    # systemd-logind new session
    (re.compile(r"systemd-logind.*New session", re.I),
     "benign", "Normal session login"),
    # Normal process execution (ls, cat generic files, etc.)
    (re.compile(r"a0=\"/usr/bin/ls\"", re.I),
     "benign", "Normal ls command"),
    (re.compile(r"a0=\"/usr/bin/cat\".*a1=\"/etc/sudoers\"", re.I),
     "suspicious", "Reading sudoers"),
    # Process events that are empty / generic
    (re.compile(r"^$|^\s*$", re.I),
     "benign", "Empty/unclassified event"),
]

# Fallback for unmatched events
FALLBACK_LABEL = "suspicious"  # Default to monitor if nothing matched


def classify_ground_truth(message: str) -> tuple:
    """Apply ground-truth rules to message body, return (label, reason)."""
    if not message or not message.strip():
        return ("benign", "Empty message body")
    for pattern, label, reason in GROUND_TRUTH_RULES:
        if pattern.search(message):
            return (label, reason)
    return (FALLBACK_LABEL, f"No rule matched (fallback={FALLBACK_LABEL})")


def expected_action(ground_truth: str) -> str:
    """Map ground-truth label to expected triage action."""
    return {
        "malicious": "escalate",
        "suspicious": "monitor",
        "benign": "discard",
    }[ground_truth]


def main():
    print("=" * 80)
    print("CLIF — Ground-Truth Cross-Verification Report (Triage v5)")
    print("=" * 80)
    print(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"Config: weights={config.SCORE_WEIGHTS}")
    print(f"Thresholds: suspicious={config.DEFAULT_SUSPICIOUS_THRESHOLD}, "
          f"anomalous={config.DEFAULT_ANOMALOUS_THRESHOLD}")
    print()

    # ── Connect to ClickHouse ──────────────────────────────────────────────
    ch = Client(
        host=config.CLICKHOUSE_HOST,
        port=config.CLICKHOUSE_PORT,
        user=config.CLICKHOUSE_USER,
        password=config.CLICKHOUSE_PASSWORD,
        database=config.CLICKHOUSE_DB,
    )

    # ── Query scored events with original messages ─────────────────────────
    # Join triage_scores with all source tables to get original message

    query = """
    -- Step 1: Build a message lookup from all source tables
    WITH msg_lookup AS (
        SELECT event_id, description as message, 'security-events' as source_table
        FROM clif_logs.security_events
        WHERE timestamp >= '2026-03-04T22:29:00' AND timestamp <= '2026-03-04T22:31:00'
        UNION ALL
        SELECT event_id, concat(binary_path, ' ', arguments) as message, 'process-events' as source_table
        FROM clif_logs.process_events
        WHERE timestamp >= '2026-03-04T22:29:00' AND timestamp <= '2026-03-04T22:31:00'
        UNION ALL
        SELECT event_id, message, 'raw-logs' as source_table
        FROM clif_logs.raw_logs
        WHERE timestamp >= '2026-03-04T22:29:00' AND timestamp <= '2026-03-04T22:31:00'
    )
    SELECT
        t.event_id,
        t.combined_score,
        t.adjusted_score,
        t.lgbm_score,
        t.eif_score,
        t.arf_score,
        t.action,
        t.source_type,
        t.hostname,
        t.source_ip,
        t.disagreement_flag,
        t.template_rarity,
        coalesce(m.message, '') as message,
        coalesce(m.source_table, 'unknown') as source_table
    FROM clif_logs.triage_scores t
    LEFT JOIN msg_lookup m ON t.event_id = m.event_id
    WHERE t.timestamp >= '2026-03-04T22:29:00'
      AND t.timestamp <= '2026-03-04T22:31:00'
    ORDER BY t.adjusted_score DESC
    """
    rows = ch.execute(query)
    print(f"Fetched {len(rows)} scored events from ClickHouse\n")

    if not rows:
        print("ERROR: No scored events found!")
        sys.exit(1)

    # ── Classify and compare ───────────────────────────────────────────────
    results = []
    for row in rows:
        (event_id, combined, adjusted, lgbm, eif, arf, action,
         source_type, hostname, source_ip, disagree, rarity,
         message, source_table) = row

        gt_label, gt_reason = classify_ground_truth(str(message))
        exp_action = expected_action(gt_label)
        correct = (action == exp_action)

        results.append({
            "event_id": str(event_id),
            "message": str(message)[:120],
            "source_table": source_table,
            "adjusted_score": float(adjusted),
            "lgbm": float(lgbm),
            "eif": float(eif),
            "arf": float(arf),
            "predicted_action": action,
            "ground_truth": gt_label,
            "expected_action": exp_action,
            "correct": correct,
            "gt_reason": gt_reason,
            "disagree_flag": disagree,
            "rarity": float(rarity),
        })

    total = len(results)
    correct_count = sum(1 for r in results if r["correct"])
    accuracy = correct_count / total * 100 if total else 0

    # ── Confusion matrix ───────────────────────────────────────────────────
    actions = ["escalate", "monitor", "discard"]
    gt_labels = ["malicious", "suspicious", "benign"]

    # Count matrix: rows = ground truth, cols = predicted action
    confusion = defaultdict(lambda: defaultdict(int))
    for r in results:
        confusion[r["ground_truth"]][r["predicted_action"]] += 1

    # Per-class counts
    gt_counts = defaultdict(int)
    pred_counts = defaultdict(int)
    for r in results:
        gt_counts[r["ground_truth"]] += 1
        pred_counts[r["predicted_action"]] += 1

    # ═══════════════════════════════════════════════════════════════════════
    # REPORT
    # ═══════════════════════════════════════════════════════════════════════

    print("=" * 80)
    print(f"OVERALL ACCURACY: {correct_count}/{total} = {accuracy:.1f}%")
    print("=" * 80)

    # Distribution
    print(f"\n{'GROUND TRUTH DISTRIBUTION':─^80}")
    for gt in gt_labels:
        print(f"  {gt:12s}: {gt_counts[gt]:3d}  ({gt_counts[gt]/total*100:.1f}%)")

    print(f"\n{'PREDICTED ACTION DISTRIBUTION':─^80}")
    for a in actions:
        print(f"  {a:12s}: {pred_counts[a]:3d}  ({pred_counts[a]/total*100:.1f}%)")

    # Confusion matrix
    print(f"\n{'CONFUSION MATRIX':─^80}")
    print(f"{'':>15s} {'escalate':>10s} {'monitor':>10s} {'discard':>10s} │ {'Total':>6s}")
    print(f"  {'─' * 60}")
    for gt in gt_labels:
        row_total = sum(confusion[gt][a] for a in actions)
        cells = "".join(f"{confusion[gt][a]:10d}" for a in actions)
        print(f"  {gt:>12s} {cells} │ {row_total:6d}")
    print(f"  {'─' * 60}")
    col_totals = "".join(f"{sum(confusion[gt][a] for gt in gt_labels):10d}" for a in actions)
    print(f"  {'Total':>12s} {col_totals} │ {total:6d}")

    # Per-class metrics
    print(f"\n{'PER-CLASS METRICS':─^80}")
    print(f"  {'Class':>12s} │ {'TP':>4s} {'FP':>4s} {'FN':>4s} │ {'Precision':>9s} {'Recall':>8s} {'F1':>8s}")
    print(f"  {'─' * 62}")

    class_map = {"malicious": "escalate", "suspicious": "monitor", "benign": "discard"}
    f1_scores = []

    for gt, act in class_map.items():
        tp = confusion[gt][act]
        fp = sum(confusion[other_gt][act] for other_gt in gt_labels if other_gt != gt)
        fn = sum(confusion[gt][other_act] for other_act in actions if other_act != act)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        f1_scores.append(f1)
        print(f"  {gt:>12s} │ {tp:4d} {fp:4d} {fn:4d} │ {precision:9.3f} {recall:8.3f} {f1:8.3f}")

    macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0
    print(f"\n  Macro F1: {macro_f1:.3f}")

    # ── Security-specific metrics ──────────────────────────────────────────
    print(f"\n{'SECURITY-CRITICAL METRICS':─^80}")

    # Malicious missed (false negatives for malicious)
    malicious_total = gt_counts["malicious"]
    malicious_escalated = confusion["malicious"]["escalate"]
    malicious_monitored = confusion["malicious"]["monitor"]
    malicious_discarded = confusion["malicious"]["discard"]

    print(f"  Malicious events: {malicious_total}")
    print(f"    Correctly escalated: {malicious_escalated} ({malicious_escalated/malicious_total*100:.1f}%)" if malicious_total else "")
    print(f"    Downgraded to monitor: {malicious_monitored} ({malicious_monitored/malicious_total*100:.1f}%)" if malicious_total else "")
    print(f"    Missed (discard): {malicious_discarded} ({malicious_discarded/malicious_total*100:.1f}%)" if malicious_total else "")

    benign_total = gt_counts["benign"]
    benign_escalated = confusion["benign"]["escalate"]
    print(f"\n  Benign events: {benign_total}")
    print(f"    False escalations: {benign_escalated} ({benign_escalated/benign_total*100:.1f}%)" if benign_total else "")

    # False negative rate (most critical for SIEM)
    fn_rate = malicious_discarded / malicious_total * 100 if malicious_total else 0
    print(f"\n  ** FALSE NEGATIVE RATE (malicious→discard): {fn_rate:.1f}% **")
    fp_rate = benign_escalated / benign_total * 100 if benign_total else 0
    print(f"  ** FALSE POSITIVE RATE (benign→escalate): {fp_rate:.1f}% **")

    # ── Detailed misclassifications ────────────────────────────────────────
    misclassified = [r for r in results if not r["correct"]]
    print(f"\n{'MISCLASSIFIED EVENTS (' + str(len(misclassified)) + ')':─^80}")

    # Critical misclassifications first (malicious → discard)
    critical_miss = [r for r in misclassified
                     if r["ground_truth"] == "malicious" and r["predicted_action"] == "discard"]
    if critical_miss:
        print(f"\n  *** CRITICAL: {len(critical_miss)} MALICIOUS events DISCARDED ***")
        for r in critical_miss:
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # Malicious → monitor (concerning but less critical)
    downgraded = [r for r in misclassified
                  if r["ground_truth"] == "malicious" and r["predicted_action"] == "monitor"]
    if downgraded:
        print(f"\n  WARNING: {len(downgraded)} MALICIOUS events only MONITORED (not escalated):")
        for r in sorted(downgraded, key=lambda x: x["adjusted_score"], reverse=True):
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # Benign → escalate (false positives)
    false_pos = [r for r in misclassified
                 if r["ground_truth"] == "benign" and r["predicted_action"] == "escalate"]
    if false_pos:
        print(f"\n  FALSE POSITIVES: {len(false_pos)} BENIGN events ESCALATED:")
        for r in false_pos:
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # Suspicious → escalate (over-triaged)
    over_triaged = [r for r in misclassified
                    if r["ground_truth"] == "suspicious" and r["predicted_action"] == "escalate"]
    if over_triaged:
        print(f"\n  OVER-TRIAGED: {len(over_triaged)} SUSPICIOUS events ESCALATED:")
        for r in sorted(over_triaged, key=lambda x: x["adjusted_score"], reverse=True):
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # Suspicious → discard (under-triaged)
    under_triaged = [r for r in misclassified
                     if r["ground_truth"] == "suspicious" and r["predicted_action"] == "discard"]
    if under_triaged:
        print(f"\n  UNDER-TRIAGED: {len(under_triaged)} SUSPICIOUS events DISCARDED:")
        for r in under_triaged:
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # Benign → monitor (minor concern)
    benign_monitor = [r for r in misclassified
                      if r["ground_truth"] == "benign" and r["predicted_action"] == "monitor"]
    if benign_monitor:
        print(f"\n  NOISE: {len(benign_monitor)} BENIGN events MONITORED (could be discarded):")
        for r in benign_monitor:
            print(f"    [{r['adjusted_score']:.4f}] lgbm={r['lgbm']:.3f} "
                  f"| {r['source_table']:16s} | {r['gt_reason']}")
            print(f"      MSG: {r['message'][:100]}")

    # ── Score distribution by ground truth ─────────────────────────────────
    print(f"\n{'SCORE RANGES BY GROUND TRUTH':─^80}")
    for gt in gt_labels:
        gt_results = [r for r in results if r["ground_truth"] == gt]
        if not gt_results:
            continue
        scores = [r["adjusted_score"] for r in gt_results]
        lgbm_scores = [r["lgbm"] for r in gt_results]
        print(f"\n  {gt} ({len(gt_results)} events):")
        print(f"    adjusted: min={min(scores):.4f}  max={max(scores):.4f}  "
              f"mean={sum(scores)/len(scores):.4f}")
        print(f"    lgbm:     min={min(lgbm_scores):.4f}  max={max(lgbm_scores):.4f}  "
              f"mean={sum(lgbm_scores)/len(lgbm_scores):.4f}")

    # ── Full event table ───────────────────────────────────────────────────
    print(f"\n{'FULL EVENT TABLE (sorted by adjusted_score desc)':─^80}")
    print(f"{'#':>4s} {'Action':>8s} {'GT':>11s} {'Match':>5s} {'AdjScore':>8s} "
          f"{'LGBM':>6s} {'Table':>16s} │ Reason / Message")
    print(f"  {'─' * 95}")

    for i, r in enumerate(results):
        mark = " OK " if r["correct"] else "MISS"
        msg_short = r["message"][:55]
        print(f"{i+1:4d} {r['predicted_action']:>8s} {r['ground_truth']:>11s} "
              f"{mark:>5s} {r['adjusted_score']:8.4f} {r['lgbm']:6.3f} "
              f"{r['source_table']:>16s} │ {r['gt_reason'][:35]:35s} {msg_short}")

    print(f"\n{'=' * 80}")
    print(f"SUMMARY: {correct_count}/{total} correct ({accuracy:.1f}% accuracy)  "
          f"Macro-F1={macro_f1:.3f}  "
          f"FN-rate={fn_rate:.1f}%  FP-rate={fp_rate:.1f}%")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
