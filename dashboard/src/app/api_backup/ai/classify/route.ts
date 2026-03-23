import { NextRequest, NextResponse } from "next/server";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/**
 * GET /api/ai/classify — Get AI model info from XAI status
 * POST /api/ai/classify — Classify via Triage model (SHAP explain)
 */
export async function GET() {
  try {
    const res = await fetch(`${AI_SERVICE_URL}/xai/status`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`AI service returned ${res.status}`);
    const data = await res.json();
    return NextResponse.json({
      status: "online",
      binary_model: data.model_types?.binary ?? "unknown",
      multiclass_model: data.model_types?.multiclass ?? "N/A",
      version: data.model_version ?? "unknown",
      feature_count: data.feature_count ?? 0,
      metrics: data.metrics ?? {},
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "AI service unreachable";
    return NextResponse.json({
      status: "offline",
      error: msg,
    }, { status: 503 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const event = Array.isArray(body.events) ? body.events[0] : body.events;

    // Use XAI /explain endpoint with the event features
    const res = await fetch(`${AI_SERVICE_URL}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`AI service error: ${res.status} - ${errText}`);
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (e: any) {
    return NextResponse.json({
      error: e.message || "Classification failed",
    }, { status: 500 });
  }
}
