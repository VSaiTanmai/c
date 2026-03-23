import { NextResponse } from "next/server";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/** GET — XAI/SHAP status + global feature importance */
export async function GET() {
  try {
    const [statusRes, featuresRes] = await Promise.all([
      fetch(`${AI_SERVICE_URL}/xai/status`, {
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      }),
      fetch(`${AI_SERVICE_URL}/model/features`, {
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      }),
    ]);

    const status = statusRes.ok ? await statusRes.json() : { available: false };
    const features = featuresRes.ok ? await featuresRes.json() : { features: [] };

    return NextResponse.json({ ...status, ...features });
  } catch (err) {
    return NextResponse.json(
      {
        available: false,
        features: [],
        error: err instanceof Error ? err.message : "XAI service unavailable",
      },
      { status: 200 } // Degrade gracefully
    );
  }
}

/** POST — Explain a single event with SHAP */
export async function POST(req: Request) {
  try {
    const body = await req.json();

    const res = await fetch(`${AI_SERVICE_URL}/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const detail = await res.text();
      return NextResponse.json(
        { error: detail },
        { status: res.status }
      );
    }

    return NextResponse.json(await res.json());
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "XAI request failed" },
      { status: 500 }
    );
  }
}
