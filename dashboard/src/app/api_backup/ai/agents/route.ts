import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

const MAC_IP = process.env.AI_SERVICE_URL?.replace(/^https?:\/\//, "").replace(/:\d+$/, "") || "localhost";

/** Agent definitions – name, port, role */
const AGENTS = [
  { name: "triage",   port: 8300, role: "Risk scoring & classification" },
  { name: "hunter",   port: 8400, role: "Threat hunting & correlation" },
  { name: "verifier", port: 8500, role: "Verdict verification" },
  { name: "xai",      port: 8200, role: "Explainability (SHAP)" },
] as const;

async function probeAgent(agent: typeof AGENTS[number]) {
  const base = `http://${MAC_IP}:${agent.port}`;
  try {
    const hRes = await fetch(`${base}/health`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    if (!hRes.ok) return { name: agent.name, role: agent.role, status: "unhealthy", cases_handled: 0, avg_response_time: 0, error_count: 0 };
    const health = await hRes.json();

    let stats: Record<string, unknown> = {};
    try {
      const sRes = await fetch(`${base}/stats`, { cache: "no-store", signal: AbortSignal.timeout(3000) });
      if (sRes.ok) stats = await sRes.json();
    } catch { /* /stats not available on all agents */ }

    return {
      name: agent.name,
      role: agent.role,
      status: health.status === "healthy" || health.status === "ok" ? "active" : health.status,
      cases_handled: Number(stats.messages_processed ?? health.batches_processed ?? health.events_processed ?? 0),
      avg_response_time: Number(health.avg_batch_time_ms ?? 0),
      error_count: Number(stats.errors ?? 0),
    };
  } catch {
    return { name: agent.name, role: agent.role, status: "unreachable", cases_handled: 0, avg_response_time: 0, error_count: 0 };
  }
}

/**
 * GET /api/ai/agents — Get status of all AI agents + recent investigations
 */
export async function GET() {
  try {
    const data = await cached("ai:agents", 10_000, async () => {
      const agents = await Promise.all(AGENTS.map(probeAgent));

      // Recent investigations from ClickHouse
      let investigations: unknown[] = [];
      try {
        const invRes = await queryClickHouse<{
          investigation_id: string; finding_type: string; severity: string;
          status: string; confidence: string; started_at: string;
        }>(
          `SELECT toString(investigation_id) AS investigation_id, finding_type, severity,
                  status, toString(confidence) AS confidence, started_at
           FROM clif_logs.hunter_investigations
           ORDER BY started_at DESC LIMIT 20`
        );
        investigations = invRes.data.map((r) => ({
          id: r.investigation_id,
          event_type: r.finding_type,
          verdict: r.status,
          confidence: Number(r.confidence),
          severity: r.severity,
          timestamp: r.started_at,
          duration: 0,
        }));
      } catch { /* no investigations table or empty */ }

      return {
        agents,
        total_agents: agents.length,
        active_agents: agents.filter((a) => a.status === "active").length,
        investigations,
      };
    });

    return NextResponse.json(data);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "unknown";
    return NextResponse.json(
      { agents: [], total_agents: 0, investigations: [], error: msg },
      { status: 503 },
    );
  }
}
