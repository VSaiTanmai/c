import { NextRequest, NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { log } from "@/lib/logger";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";

/**
 * GET /api/investigations — Fetch investigations from ClickHouse
 *
 * Joins hunter_investigations with verifier_results to build a full
 * investigation timeline. Returns real data — no mock fallback.
 *
 * Query params:
 *   - status: "open" | "completed" | "all" (default: "all")
 *   - severity: "critical" | "high" | "medium" | "low" | "all" (default: "all")
 *   - q: search text (hostname, IP, summary)
 *   - limit: max results (default: 100, max: 500)
 *   - offset: pagination offset (default: 0)
 */
export async function GET(req: NextRequest) {
  const rateLimited = checkRateLimit(getClientId(req), { maxTokens: 30, refillRate: 2 }, "/api/investigations");
  if (rateLimited) return rateLimited;

  const url = req.nextUrl;
  const status = url.searchParams.get("status") || "all";
  const severity = url.searchParams.get("severity") || "all";
  const q = url.searchParams.get("q") || "";
  const limit = Math.min(Number(url.searchParams.get("limit")) || 100, 500);
  const offset = Math.max(Number(url.searchParams.get("offset")) || 0, 0);

  const cacheKey = `investigations:${status}:${severity}:${q}:${limit}:${offset}`;

  try {
    const data = await cached(cacheKey, 8_000, async () => {
      // Build WHERE clauses
      const conditions: string[] = [];

      if (status === "open") {
        conditions.push("h.status IN ('pending', 'running')");
      } else if (status === "completed") {
        conditions.push("h.status = 'completed'");
      }

      const severityMap: Record<string, string> = {
        critical: "'critical'",
        high: "'high'",
        medium: "'medium'",
        low: "'low'",
        info: "'info'",
      };
      if (severity !== "all" && severityMap[severity]) {
        conditions.push(`h.severity = ${severityMap[severity]}`);
      }

      if (q) {
        conditions.push(
          `(h.hostname ILIKE {q:String} OR h.source_ip ILIKE {q:String} OR h.summary ILIKE {q:String} OR h.finding_type ILIKE {q:String})`
        );
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

      // Main query: hunter investigations LEFT JOIN verifier results
      const sql = `
        SELECT
          h.investigation_id,
          h.alert_id,
          h.started_at,
          h.completed_at,
          h.status AS hunt_status,
          h.hostname,
          h.source_ip,
          h.user_id,
          h.trigger_score,
          h.severity,
          h.finding_type,
          h.summary,
          h.mitre_tactics,
          h.mitre_techniques,
          h.recommended_action,
          h.confidence AS hunt_confidence,
          length(h.correlated_events) AS correlated_count,
          v.verdict,
          v.confidence AS verify_confidence,
          v.priority,
          v.analyst_summary,
          v.evidence_verified
        FROM hunter_investigations h
        LEFT JOIN (
          SELECT investigation_id,
                 verdict, confidence, priority, analyst_summary, evidence_verified,
                 ROW_NUMBER() OVER (PARTITION BY investigation_id ORDER BY started_at DESC) AS rn
          FROM verifier_results
        ) v ON v.investigation_id = h.investigation_id AND v.rn = 1
        ${whereClause}
        ORDER BY h.started_at DESC
        LIMIT {limit:UInt32}
        OFFSET {offset:UInt32}
      `;

      const params: Record<string, string | number> = { limit, offset };
      if (q) params.q = `%${q}%`;

      const result = await queryClickHouse(sql, params);

      // Total count for pagination
      const countSql = `
        SELECT count() AS total
        FROM hunter_investigations h
        ${whereClause}
      `;
      const countResult = await queryClickHouse<{ total: number }>(countSql, q ? { q: `%${q}%` } : {});
      const total = countResult.data[0]?.total || 0;

      // Summary stats
      const statsSql = `
        SELECT
          countIf(status IN ('pending', 'running')) AS open_count,
          countIf(status = 'completed') AS completed_count,
          countIf(severity = 'critical') AS critical_count,
          countIf(severity = 'high') AS high_count
        FROM hunter_investigations
      `;
      const stats = await queryClickHouse(statsSql);

      return {
        investigations: result.data,
        total,
        stats: stats.data[0] || {},
      };
    });

    return NextResponse.json(data);
  } catch (e: any) {
    log.error("Investigations API error", { error: e.message, component: "api.investigations" });
    return NextResponse.json({ error: e.message || "Failed to fetch investigations" }, { status: 500 });
  }
}
