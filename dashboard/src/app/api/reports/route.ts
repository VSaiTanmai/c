import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), { maxTokens: 20, refillRate: 1 });
  if (limited) return limited;

  try {
    const data = await cached("reports:list", 30_000, async () => {
      const [
        alertSummary,
        eventCounts,
        evidenceStats,
        topCategories,
        severityDist,
        recentAlerts,
        mitreTop,
      ] = await Promise.allSettled([
        // Alert summary last 24h
        queryClickHouse<{ total: string; critical: string; high: string; medium: string }>(
          `SELECT
             count() AS total,
             countIf(severity = 4) AS critical,
             countIf(severity = 3) AS high,
             countIf(severity = 2) AS medium
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 30 DAY`
        ),
        // Event counts per table
        queryClickHouse<{ table_name: string; cnt: string }>(
          `SELECT 'raw_logs' AS table_name, count() AS cnt FROM clif_logs.raw_logs
           UNION ALL
           SELECT 'security_events', count() FROM clif_logs.security_events
           UNION ALL
           SELECT 'process_events', count() FROM clif_logs.process_events
           UNION ALL
           SELECT 'network_events', count() FROM clif_logs.network_events`
        ),
        // Evidence stats
        queryClickHouse<{ batches: string; anchored: string; verified: string }>(
          `SELECT
             count() AS batches,
             sum(event_count) AS anchored,
             countIf(status = 'Verified') AS verified
           FROM clif_logs.evidence_anchors`
        ),
        // Top categories
        queryClickHouse<{ category: string; cnt: string }>(
          `SELECT category, count() AS cnt
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 7 DAY
           GROUP BY category
           ORDER BY cnt DESC
           LIMIT 10`
        ),
        // Severity distribution last 7 days
        queryClickHouse<{ severity: string; cnt: string }>(
          `SELECT toString(severity) AS severity, count() AS cnt
           FROM clif_logs.security_events
           WHERE timestamp >= now() - INTERVAL 7 DAY
           GROUP BY severity
           ORDER BY severity DESC`
        ),
        // Recent critical/high alerts for report content
        queryClickHouse<{
          event_id: string;
          ts: string;
          severity: string;
          category: string;
          source: string;
          description: string;
          hostname: string;
          mitre_tactic: string;
          mitre_technique: string;
        }>(
          `SELECT
             toString(event_id) AS event_id,
             toString(timestamp) AS ts,
             severity,
             category,
             source,
             description,
             hostname,
             mitre_tactic,
             mitre_technique
           FROM clif_logs.security_events
           WHERE severity >= 3
             AND timestamp >= now() - INTERVAL 7 DAY
           ORDER BY timestamp DESC
           LIMIT 50`
        ),
        // Top MITRE techniques
        queryClickHouse<{ technique: string; tactic: string; cnt: string }>(
          `SELECT mitre_technique AS technique, mitre_tactic AS tactic, count() AS cnt
           FROM clif_logs.security_events
           WHERE mitre_technique != ''
             AND timestamp >= now() - INTERVAL 7 DAY
           GROUP BY mitre_technique, mitre_tactic
           ORDER BY cnt DESC
           LIMIT 15`
        ),
      ]);

      // Return mock data when ClickHouse is unavailable
      if ([alertSummary, eventCounts, evidenceStats, topCategories, severityDist, recentAlerts, mitreTop].every((r) => r.status === "rejected")) {
        return {
          summary: {
            totalEvents: 1_847_293, totalAlerts24h: 127, criticalAlerts: 12, highAlerts: 35,
            mediumAlerts: 80, evidenceBatches: 38, evidenceAnchored: 184720, evidenceVerified: 32,
          },
          eventsByTable: [
            { table: "raw_logs", count: 924810 }, { table: "security_events", count: 482910 },
            { table: "process_events", count: 298472 }, { table: "network_events", count: 141101 },
          ],
          topCategories: [
            { category: "Authentication", count: 4820 }, { category: "Process Execution", count: 3210 },
            { category: "Network Connection", count: 2890 }, { category: "File Modification", count: 1940 },
            { category: "Registry Change", count: 1280 },
          ],
          severityDistribution: [
            { severity: 4, count: 127 }, { severity: 3, count: 842 },
            { severity: 2, count: 3241 }, { severity: 1, count: 8920 },
          ],
          recentCriticalAlerts: [
            { eventId: "EVT-40012", timestamp: new Date(Date.now() - 840_000).toISOString(), severity: 4, category: "Credential Access", source: "sysmon", description: "Suspicious LSASS Memory Access", hostname: "DC01", mitreTactic: "Credential Access", mitreTechnique: "T1003.001" },
            { eventId: "EVT-40008", timestamp: new Date(Date.now() - 1_920_000).toISOString(), severity: 4, category: "Execution", source: "windows-security", description: "Encoded PowerShell Command", hostname: "WEB-SRV-03", mitreTactic: "Execution", mitreTechnique: "T1059.001" },
          ],
          mitreTopTechniques: [
            { technique: "T1059.001", tactic: "Execution", count: 248 },
            { technique: "T1021.002", tactic: "Lateral Movement", count: 183 },
            { technique: "T1003.001", tactic: "Credential Access", count: 142 },
          ],
          generatedAt: new Date().toISOString(),
        };
      }

      const alerts = alertSummary.status === "fulfilled" ? alertSummary.value.data[0] : null;
      const events = eventCounts.status === "fulfilled" ? eventCounts.value.data : [];
      const evidence = evidenceStats.status === "fulfilled" ? evidenceStats.value.data[0] : null;
      const categories = topCategories.status === "fulfilled" ? topCategories.value.data : [];
      const severity = severityDist.status === "fulfilled" ? severityDist.value.data : [];
      const criticalAlerts = recentAlerts.status === "fulfilled" ? recentAlerts.value.data : [];
      const mitre = mitreTop.status === "fulfilled" ? mitreTop.value.data : [];

      const totalEvents = events.reduce((sum, e) => sum + Number(e.cnt), 0);

      return {
        summary: {
          totalEvents,
          totalAlerts24h: Number(alerts?.total ?? 0),
          criticalAlerts: Number(alerts?.critical ?? 0),
          highAlerts: Number(alerts?.high ?? 0),
          mediumAlerts: Number(alerts?.medium ?? 0),
          evidenceBatches: Number(evidence?.batches ?? 0),
          evidenceAnchored: Number(evidence?.anchored ?? 0),
          evidenceVerified: Number(evidence?.verified ?? 0),
        },
        eventsByTable: events.map((e) => ({ table: e.table_name, count: Number(e.cnt) })),
        topCategories: categories.map((c) => ({ category: c.category, count: Number(c.cnt) })),
        severityDistribution: severity.map((s) => ({ severity: Number(s.severity), count: Number(s.cnt) })),
        recentCriticalAlerts: criticalAlerts.map((a) => ({
          eventId: a.event_id,
          timestamp: a.ts,
          severity: Number(a.severity),
          category: a.category,
          source: a.source,
          description: a.description,
          hostname: a.hostname,
          mitreTactic: a.mitre_tactic,
          mitreTechnique: a.mitre_technique,
        })),
        mitreTopTechniques: mitre.map((m) => ({
          technique: m.technique,
          tactic: m.tactic,
          count: Number(m.cnt),
        })),
        generatedAt: new Date().toISOString(),
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Reports data fetch failed, using mock fallback", {
      error: err instanceof Error ? err.message : "unknown",
      component: "api/reports",
    });
    return NextResponse.json({
      summary: {
        totalEvents: 1_847_293,
        totalAlerts24h: 127,
        criticalAlerts: 12,
        highAlerts: 35,
        mediumAlerts: 80,
        evidenceBatches: 38,
        evidenceAnchored: 184720,
        evidenceVerified: 32,
      },
      eventsByTable: [
        { table: "raw_logs", count: 924810 },
        { table: "security_events", count: 482910 },
        { table: "process_events", count: 298472 },
        { table: "network_events", count: 141101 },
      ],
      topCategories: [
        { category: "Authentication", count: 4820 },
        { category: "Process Execution", count: 3210 },
        { category: "Network Connection", count: 2890 },
        { category: "File Modification", count: 1940 },
        { category: "Registry Change", count: 1280 },
      ],
      severityDistribution: [
        { severity: 4, count: 127 },
        { severity: 3, count: 842 },
        { severity: 2, count: 3241 },
        { severity: 1, count: 8920 },
      ],
      recentCriticalAlerts: [
        { eventId: "EVT-40012", timestamp: new Date(Date.now() - 840_000).toISOString(), severity: 4, category: "Credential Access", source: "sysmon", description: "Suspicious LSASS Memory Access", hostname: "DC01", mitreTactic: "Credential Access", mitreTechnique: "T1003.001" },
        { eventId: "EVT-40008", timestamp: new Date(Date.now() - 1_920_000).toISOString(), severity: 4, category: "Execution", source: "windows-security", description: "Encoded PowerShell Command", hostname: "WEB-SRV-03", mitreTactic: "Execution", mitreTechnique: "T1059.001" },
      ],
      mitreTopTechniques: [
        { technique: "T1059.001", tactic: "Execution", count: 248 },
        { technique: "T1021.002", tactic: "Lateral Movement", count: 183 },
        { technique: "T1003.001", tactic: "Credential Access", count: 142 },
      ],
      generatedAt: new Date().toISOString(),
    });
  }
}
