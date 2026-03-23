import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const LANCEDB_URL = process.env.LANCEDB_URL || "http://localhost:8100";
const RATE_LIMIT = { maxTokens: 30, refillRate: 3 };

/** Proxy semantic search requests to the LanceDB service */
export async function GET(req: NextRequest) {
  const limited = checkRateLimit(getClientId(req), RATE_LIMIT);
  if (limited) return limited;

  const { searchParams } = req.nextUrl;
  const q = searchParams.get("q");
  const table = searchParams.get("table") || "log_embeddings";
  const limitParam = searchParams.get("limit") || "20";
  const filter = searchParams.get("filter");

  if (!q || q.trim().length === 0) {
    return NextResponse.json({ error: "Missing 'q' parameter" }, { status: 400 });
  }

  try {
    const params = new URLSearchParams({ q, table, limit: limitParam });
    if (filter) params.set("filter", filter);

    // Retry once on transient failures (cold start, connection reset)
    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const res = await fetch(`${LANCEDB_URL}/search?${params}`, {
          signal: AbortSignal.timeout(15_000),
        });

        if (!res.ok) {
          const body = await res.text();
          log.error("LanceDB search failed", { status: res.status, body, component: "api/semantic-search" });
          return NextResponse.json({ error: "Semantic search failed" }, { status: res.status });
        }

        const data = await res.json();
        return NextResponse.json(data);
      } catch (err) {
        lastErr = err;
        if (attempt < 2) await new Promise((r) => setTimeout(r, 800));
      }
    }

    const errMsg = lastErr instanceof Error ? lastErr.message : "unknown";
    log.error("Semantic search error after retries", { error: errMsg, url: `${LANCEDB_URL}/search`, component: "api/semantic-search" });
    return NextResponse.json({ error: `AI search service unavailable: ${errMsg}` }, { status: 503 });
  } catch (err) {
    log.error("Semantic search unexpected error", { error: err instanceof Error ? err.message : "unknown", component: "api/semantic-search" });
    return NextResponse.json({ error: "AI search service unavailable" }, { status: 503 });
  }
}

export async function POST(req: NextRequest) {
  const limited = checkRateLimit(getClientId(req), RATE_LIMIT);
  if (limited) return limited;

  try {
    const body = await req.json();
    const res = await fetch(`${LANCEDB_URL}/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });

    if (!res.ok) {
      const text = await res.text();
      return NextResponse.json({ error: text }, { status: res.status });
    }

    return NextResponse.json(await res.json());
  } catch (err) {
    log.error("Semantic search POST error", { error: err instanceof Error ? err.message : "unknown", component: "api/semantic-search" });
    return NextResponse.json({ error: "Semantic search service unavailable" }, { status: 503 });
  }
}
