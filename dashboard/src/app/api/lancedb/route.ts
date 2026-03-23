import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const LANCEDB_URL = process.env.LANCEDB_URL || "http://localhost:8100";
const RATE_LIMIT = { maxTokens: 10, refillRate: 1 };

/** Query LanceDB service stats and table counts */
export async function GET(req: NextRequest) {
  const limited = checkRateLimit(getClientId(req), RATE_LIMIT);
  if (limited) return limited;

  try {
    const [statsRes, tablesRes] = await Promise.all([
      fetch(`${LANCEDB_URL}/stats`, { signal: AbortSignal.timeout(5_000) }),
      fetch(`${LANCEDB_URL}/tables`, { signal: AbortSignal.timeout(5_000) }),
    ]);

    if (!statsRes.ok || !tablesRes.ok) {
      return NextResponse.json({ error: "LanceDB service error" }, { status: 502 });
    }

    const [stats, tables] = await Promise.all([statsRes.json(), tablesRes.json()]);

    return NextResponse.json({
      status: "connected",
      ...stats,
      ...tables,
    });
  } catch (err) {
    log.error("LanceDB stats error", { error: err instanceof Error ? err.message : "unknown", component: "api/lancedb" });
    return NextResponse.json(
      { status: "disconnected", error: "LanceDB service unavailable" },
      { status: 503 }
    );
  }
}
