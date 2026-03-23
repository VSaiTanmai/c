import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";
import investigationsMock from "@/lib/mock/investigations.json";

export const dynamic = "force-dynamic";

const CACHE_TTL_MS = 10_000;

/* Map ClickHouse severity enum ordinal to numeric value */
const SEVERITY_MAP: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/* Map ClickHouse status enum to frontend label */
const STATUS_MAP: Record<string, string> = {
  pending: "Open",
  running: "In Progress",
  completed: "Closed",
  failed: "Closed",
  timeout: "Closed",
};

interface CHInvestigation {
  investigation_id: string;
  alert_id: string;
  started_at: string;
  completed_at: string | null;
  status: string;
  hostname: string;
  source_ip: string;
  user_id: string;
  trigger_score: number;
  severity: string;
  finding_type: string;
  summary: string;
  correlated_events: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  recommended_action: string;
  confidence: number;
}

export async function GET(request: Request) {
  const rateLimited = checkRateLimit(getClientId(request), { maxTokens: 20, refillRate: 2 }, "/api/ai/investigations/list");
  if (rateLimited) return rateLimited;

  const { searchParams } = new URL(request.url);
  const limit = Math.min(Math.max(Number(searchParams.get("limit")) || 50, 1), 200);

  try {
    const data = await cached(`investigations:list:${limit}`, CACHE_TTL_MS, async () => {
      const result = await queryClickHouse<CHInvestigation>(
        `SELECT
           toString(investigation_id) AS investigation_id,
           toString(alert_id) AS alert_id,
           started_at,
           completed_at,
           status,
           hostname,
           source_ip,
           user_id,
           trigger_score,
           severity,
           finding_type,
           summary,
           correlated_events,
           mitre_tactics,
           mitre_techniques,
           recommended_action,
           confidence
         FROM clif_logs.hunter_investigations
         ORDER BY started_at DESC
         LIMIT {limit:UInt32}`,
        { limit },
      );

      return {
        investigations: result.data.map((row) => ({
          id: row.investigation_id,
          title: row.summary || `${row.finding_type || "Investigation"} on ${row.hostname || "unknown host"}`,
          status: STATUS_MAP[row.status] ?? row.status,
          severity: SEVERITY_MAP[String(row.severity).toLowerCase()] ?? 0,
          created: row.started_at,
          updated: row.completed_at ?? row.started_at,
          assignee: row.user_id ? `Hunter (${row.user_id})` : "AI Hunter",
          eventCount: Array.isArray(row.correlated_events) ? row.correlated_events.length : 0,
          description: row.recommended_action || row.summary || "",
          tags: [
            ...(row.mitre_tactics ?? []),
            ...(row.finding_type ? [row.finding_type] : []),
          ],
          hosts: row.hostname ? [row.hostname] : [],
          users: row.user_id ? [row.user_id] : [],
        })),
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.warn("Investigations list query failed, using mock fallback", {
      component: "api/ai/investigations/list",
      error: err instanceof Error ? err.message : "unknown",
    });

    // Fallback to mock data when ClickHouse is unavailable
    return NextResponse.json({ investigations: investigationsMock.cases });
  }
}
