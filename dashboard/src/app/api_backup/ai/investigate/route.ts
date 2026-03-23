import { NextRequest, NextResponse } from "next/server";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/**
 * POST /api/ai/investigate — Run SHAP explanation via XAI service
 *
 * The full 4-agent pipeline runs through Redpanda (event-driven).
 * This endpoint provides per-event SHAP explanations via the XAI service.
 */
export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { event } = body;

    const res = await fetch(`${AI_SERVICE_URL}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`XAI explain error: ${res.status} - ${errText}`);
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Investigation failed";
    return NextResponse.json(
      { error: msg },
      { status: 500 },
    );
  }
}
