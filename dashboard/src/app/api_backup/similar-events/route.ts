import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const LANCEDB_URL = process.env.LANCEDB_URL || "http://localhost:8100";
const RATE_LIMIT = { maxTokens: 20, refillRate: 2 };

/** Find events similar to a given event_id using LanceDB vector similarity */
export async function POST(req: NextRequest) {
  const limited = checkRateLimit(getClientId(req), RATE_LIMIT);
  if (limited) return limited;

  try {
    const body = await req.json();
    const { event_id, table, limit } = body;

    if (!event_id) {
      return NextResponse.json({ error: "Missing event_id" }, { status: 400 });
    }

    const res = await fetch(`${LANCEDB_URL}/similar`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        event_id,
        table: table || "log_embeddings",
        limit: limit || 10,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const text = await res.text();
      return NextResponse.json({ error: text }, { status: res.status });
    }

    return NextResponse.json(await res.json());
  } catch (err) {
    log.error("Similar events error", { error: err instanceof Error ? err.message : "unknown", component: "api/similar-events" });
    return NextResponse.json({ error: "Similar events service unavailable" }, { status: 503 });
  }
}
