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

      return {
        mitreStats:
          mitreStats.status === "fulfilled"
            ? mitreStats.value.data.map((r) => ({
                technique: r.technique,
                tactic: r.tactic,
                count: Number(r.cnt),
                maxSeverity: r.max_sev,
              }))
            : [],
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
        iocTable:
          iocTable.status === "fulfilled"
            ? iocTable.value.data.map((r) => ({
                indicator: r.indicator,
                type: r.ioc_type,
                source: r.source_type,
                technique: r.technique,
                tactic: r.tactic,
                hits: Number(r.cnt),
                maxSeverity: r.max_sev,
                firstSeen: r.first_seen,
                lastSeen: r.last_seen,
              }))
            : [],
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Threat intel fetch failed", { error: err instanceof Error ? err.message : "unknown", component: "api/threat-intel" });
    return NextResponse.json(
      { error: "Failed to fetch threat intel" },
      { status: 500 }
    );
  }
}
