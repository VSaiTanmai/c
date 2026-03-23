import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

/** Explicit columns — never SELECT * in production */
const ALERT_COLUMNS = [
  "toString(se.event_id) AS event_id",
  "se.timestamp",
  "se.severity",
  "se.category",
  "se.source AS log_source",
  "se.description AS event_type",
  "se.hostname",
  "se.user_id",
  "se.mitre_tactic",
  "se.mitre_technique",
  "coalesce(ts.adjusted_score, 0) AS confidence",
].join(", ");

export async function GET(request: Request) {
  const rateLimited = checkRateLimit(getClientId(request), { maxTokens: 30, refillRate: 2 }, "/api/alerts");
  if (rateLimited) return rateLimited;

  try {
    const data = await cached("alerts:recent", 8_000, async () => {
      const [result, alerts] = await Promise.allSettled([
        queryClickHouse<{ severity: number; cnt: string }>(
          `SELECT severity, count() AS cnt
           FROM clif_logs.security_events
           WHERE severity >= 2
             AND timestamp >= now() - INTERVAL 30 DAY
           GROUP BY severity
           ORDER BY severity DESC`
        ),
        queryClickHouse(
          `SELECT ${ALERT_COLUMNS}
           FROM clif_logs.security_events AS se
           LEFT JOIN (
             SELECT event_id, argMax(adjusted_score, timestamp) AS adjusted_score
             FROM clif_logs.triage_scores
             WHERE timestamp >= now() - INTERVAL 30 DAY
             GROUP BY event_id
           ) AS ts ON ts.event_id = se.event_id
           WHERE se.severity >= 2
             AND se.timestamp >= now() - INTERVAL 30 DAY
           ORDER BY se.timestamp DESC
           LIMIT 100`
        ),
      ]);

      return {
        summary:
          result.status === "fulfilled"
            ? result.value.data.map((r) => ({
                severity: r.severity,
                count: Number(r.cnt),
              }))
            : [],
        alerts: alerts.status === "fulfilled" ? alerts.value.data : [],
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Alerts API failed", {
      component: "api/alerts",
      error: err instanceof Error ? err.message : "unknown",
    });
    return NextResponse.json(
      { error: "Failed to fetch alerts" },
      { status: 500 }
    );
  }
}
