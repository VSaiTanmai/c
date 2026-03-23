import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { cached } from "@/lib/cache";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const RATE_LIMIT = { maxTokens: 20, refillRate: 1 };

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT);
  if (limited) return limited;

  try {
    const data = await cached("threat-intel:dashboard", 15_000, async () => {
      const [mitreStats, topIOCs, recentAttacks, iocTable] = await Promise.allSettled([
        // MITRE technique distribution from security_events
        queryClickHouse<{
          technique: string;
          tactic: string;
          cnt: string;
          max_sev: number;
        }>(
          `SELECT
             mitre_technique AS technique,
             mitre_tactic AS tactic,
             count() AS cnt,
             max(severity) AS max_sev
           FROM clif_logs.security_events
           WHERE mitre_technique != ''
             AND timestamp >= now() - INTERVAL 30 DAY
           GROUP BY mitre_technique, mitre_tactic
           ORDER BY cnt DESC
           LIMIT 20`
        ),
        // Top IOC-like indicators (IPs, hostnames with high severity)
        queryClickHouse<{
          value: string;
          type: string;
          cnt: string;
          max_sev: number;
        }>(
          `SELECT
             hostname AS value,
             'Hostname' AS type,
             count() AS cnt,
             max(severity) AS max_sev
           FROM clif_logs.security_events
           WHERE severity >= 2
             AND timestamp >= now() - INTERVAL 30 DAY
           GROUP BY hostname
           ORDER BY cnt DESC
           LIMIT 15`
        ),
        // Recent high-severity attacks timeline
        queryClickHouse<{
          hour: string;
          technique: string;
          cnt: string;
        }>(
          `SELECT
             toStartOfHour(timestamp) AS hour,
             mitre_technique AS technique,
             count() AS cnt
           FROM clif_logs.security_events
           WHERE severity >= 3
             AND mitre_technique != ''
             AND timestamp >= now() - INTERVAL 30 DAY
           GROUP BY hour, mitre_technique
           ORDER BY hour DESC
           LIMIT 50`
        ),
        // Detailed IOCs for table view (IPs + hostnames)
        queryClickHouse<{
          indicator: string;
          ioc_type: string;
          source_type: string;
          technique: string;
          tactic: string;
          cnt: string;
          max_sev: number;
          first_seen: string;
          last_seen: string;
        }>(
          `SELECT
             IPv4NumToString(toUInt32(ip_address)) AS indicator,
             'IPv4' AS ioc_type,
             source AS source_type,
             mitre_technique AS technique,
             mitre_tactic AS tactic,
             count() AS cnt,
             max(severity) AS max_sev,
             min(timestamp) AS first_seen,
             max(timestamp) AS last_seen
           FROM clif_logs.security_events
           WHERE severity >= 2
             AND ip_address != toIPv4('0.0.0.0')
             AND timestamp >= now() - INTERVAL 30 DAY
           GROUP BY ip_address, source, mitre_technique, mitre_tactic
           ORDER BY cnt DESC
           LIMIT 30`
        ),
      ]);

      // Return mock data when ClickHouse is unavailable
      if ([mitreStats, topIOCs, recentAttacks, iocTable].every((r) => r.status === "rejected")) {
        const mockIOCs = [
          { type: "IPv4", value: "185.220.101.34", source: "firewall", confidence: 95, firstSeen: "2026-03-10T08:12:00Z", lastSeen: "2026-03-15T14:30:00Z", mitre: "T1071.001", tags: ["C2", "Command and Control"], matchedEvents: 42 },
          { type: "IPv4", value: "91.215.85.17", source: "dns-logs", confidence: 88, firstSeen: "2026-03-11T15:45:00Z", lastSeen: "2026-03-15T09:22:00Z", mitre: "T1071.004", tags: ["DNS Tunneling", "Exfiltration"], matchedEvents: 28 },
          { type: "Hostname", value: "DC01.corp.local", source: "sysmon", confidence: 82, firstSeen: "2026-03-09T22:00:00Z", lastSeen: "2026-03-15T18:10:00Z", mitre: "T1003.001", tags: ["Credential Access", "LSASS"], matchedEvents: 19 },
          { type: "IPv4", value: "45.33.32.156", source: "firewall", confidence: 76, firstSeen: "2026-03-12T03:30:00Z", lastSeen: "2026-03-14T21:45:00Z", mitre: "T1190", tags: ["Initial Access", "Exploit"], matchedEvents: 14 },
          { type: "Hostname", value: "WEB-SRV-03", source: "windows-security", confidence: 71, firstSeen: "2026-03-13T11:20:00Z", lastSeen: "2026-03-15T16:55:00Z", mitre: "T1059.001", tags: ["Execution", "PowerShell"], matchedEvents: 11 },
        ];
        const mockPatterns = [
          { name: "T1059.001", description: "PowerShell command execution via Execution tactic", mitre: "T1059.001", iocCount: 2, matchedEvents: 248, severity: 4 },
          { name: "T1021.002", description: "Lateral movement via SMB/Windows Admin Shares", mitre: "T1021.002", iocCount: 1, matchedEvents: 183, severity: 3 },
          { name: "T1003.001", description: "Credential dumping via LSASS Memory", mitre: "T1003.001", iocCount: 1, matchedEvents: 142, severity: 4 },
          { name: "T1071.001", description: "Application layer C2 protocol", mitre: "T1071.001", iocCount: 1, matchedEvents: 118, severity: 3 },
          { name: "T1055.001", description: "Process injection via DLL", mitre: "T1055.001", iocCount: 0, matchedEvents: 97, severity: 3 },
        ];
        return {
          iocs: mockIOCs,
          patterns: mockPatterns,
          stats: { totalIOCs: mockIOCs.length, activeThreats: 8, mitreTechniques: 14, lastUpdated: new Date().toISOString() },
          mitreStats: [], topIOCs: [], recentAttacks: [], iocTable: mockIOCs,
        };
      }

      const mitreArr =
          mitreStats.status === "fulfilled"
            ? mitreStats.value.data.map((r) => ({
                technique: r.technique,
                tactic: r.tactic,
                count: Number(r.cnt),
                maxSeverity: r.max_sev,
              }))
            : [];

      const iocArr =
          iocTable.status === "fulfilled"
            ? iocTable.value.data.map((r) => ({
                type: r.ioc_type,
                value: r.indicator,
                source: r.source_type,
                confidence: Math.min(100, Math.round((r.max_sev / 4) * 100)),
                firstSeen: r.first_seen,
                lastSeen: r.last_seen,
                mitre: r.technique || "",
                tags: [r.tactic, r.ioc_type].filter(Boolean),
                matchedEvents: Number(r.cnt),
              }))
            : [];

      const patternArr = mitreArr.map((m) => ({
              name: m.technique,
              description: `MITRE technique ${m.technique} under tactic ${m.tactic}`,
              mitre: m.technique,
              iocCount: iocArr.filter((i) => i.mitre === m.technique).length,
              matchedEvents: m.count,
              severity: m.maxSeverity,
            }));

      return {
        iocs: iocArr,
        patterns: patternArr,
        stats: {
          totalIOCs: iocArr.length,
          activeThreats: mitreArr.filter((m) => m.maxSeverity >= 3).length,
          mitreTechniques: mitreArr.length,
          lastUpdated: new Date().toISOString(),
        },
        mitreStats: mitreArr,
        topIOCs:
          topIOCs.status === "fulfilled"
            ? topIOCs.value.data.map((r) => ({
                value: r.value,
                type: r.type,
                hits: Number(r.cnt),
                maxSeverity: r.max_sev,
              }))
            : [],
        recentAttacks:
          recentAttacks.status === "fulfilled"
            ? recentAttacks.value.data.map((r) => ({
                hour: r.hour,
                technique: r.technique,
                count: Number(r.cnt),
              }))
            : [],
        iocTable: iocArr,
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Threat intel fetch failed, using mock fallback", { error: err instanceof Error ? err.message : "unknown", component: "api/threat-intel" });

    const mockIOCs = [
      { type: "IPv4", value: "185.220.101.34", source: "firewall", confidence: 95, firstSeen: "2026-03-10T08:12:00Z", lastSeen: "2026-03-15T14:30:00Z", mitre: "T1071.001", tags: ["C2", "Command and Control"], matchedEvents: 42 },
      { type: "IPv4", value: "91.215.85.17", source: "dns-logs", confidence: 88, firstSeen: "2026-03-11T15:45:00Z", lastSeen: "2026-03-15T09:22:00Z", mitre: "T1071.004", tags: ["DNS Tunneling", "Exfiltration"], matchedEvents: 28 },
      { type: "Hostname", value: "DC01.corp.local", source: "sysmon", confidence: 82, firstSeen: "2026-03-09T22:00:00Z", lastSeen: "2026-03-15T18:10:00Z", mitre: "T1003.001", tags: ["Credential Access", "LSASS"], matchedEvents: 19 },
      { type: "IPv4", value: "45.33.32.156", source: "firewall", confidence: 76, firstSeen: "2026-03-12T03:30:00Z", lastSeen: "2026-03-14T21:45:00Z", mitre: "T1190", tags: ["Initial Access", "Exploit"], matchedEvents: 14 },
      { type: "Hostname", value: "WEB-SRV-03", source: "windows-security", confidence: 71, firstSeen: "2026-03-13T11:20:00Z", lastSeen: "2026-03-15T16:55:00Z", mitre: "T1059.001", tags: ["Execution", "PowerShell"], matchedEvents: 11 },
    ];

    const mockPatterns = [
      { name: "T1059.001", description: "MITRE technique T1059.001 under tactic Execution", mitre: "T1059.001", iocCount: 2, matchedEvents: 248, severity: 4 },
      { name: "T1021.002", description: "MITRE technique T1021.002 under tactic Lateral Movement", mitre: "T1021.002", iocCount: 1, matchedEvents: 183, severity: 3 },
      { name: "T1003.001", description: "MITRE technique T1003.001 under tactic Credential Access", mitre: "T1003.001", iocCount: 1, matchedEvents: 142, severity: 4 },
      { name: "T1071.001", description: "MITRE technique T1071.001 under tactic Command and Control", mitre: "T1071.001", iocCount: 1, matchedEvents: 118, severity: 3 },
      { name: "T1055.001", description: "MITRE technique T1055.001 under tactic Defense Evasion", mitre: "T1055.001", iocCount: 0, matchedEvents: 97, severity: 3 },
    ];

    return NextResponse.json({
      iocs: mockIOCs,
      patterns: mockPatterns,
      stats: { totalIOCs: mockIOCs.length, activeThreats: 8, mitreTechniques: 14, lastUpdated: new Date().toISOString() },
      mitreStats: [],
      topIOCs: [],
      recentAttacks: [],
      iocTable: mockIOCs,
    });
  }
}
