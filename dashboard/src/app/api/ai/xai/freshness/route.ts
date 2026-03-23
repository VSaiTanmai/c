import { NextResponse } from "next/server";
import { cached } from "@/lib/cache";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/**
 * GET /api/ai/xai/freshness — Model freshness (days since last training).
 *
 * Reads trained_at from XAI /xai/status and computes the age.
 */
export async function GET() {
  try {
    const data = await cached("xai:freshness", 60_000, async () => {
      const res = await fetch(`${AI_SERVICE_URL}/xai/status`, {
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) throw new Error(`XAI service returned ${res.status}`);
      const xai = await res.json();

      const trainedAt = xai.trained_at ?? null;
      let daysSinceTraining: number | null = null;
      let freshness: string = "unknown";

      if (trainedAt) {
        const trainedDate = new Date(trainedAt);
        const now = new Date();
        daysSinceTraining = Math.floor(
          (now.getTime() - trainedDate.getTime()) / (1000 * 60 * 60 * 24)
        );

        if (daysSinceTraining <= 7) freshness = "fresh";
        else if (daysSinceTraining <= 30) freshness = "acceptable";
        else if (daysSinceTraining <= 90) freshness = "stale";
        else freshness = "outdated";
      }

      return {
        trainedAt,
        daysSinceTraining,
        freshness,
        modelVersion: xai.model_version ?? null,
        featureCount: xai.feature_count ?? null,
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      {
        error: err instanceof Error ? err.message : "Freshness data unavailable",
        trainedAt: null,
        daysSinceTraining: null,
        freshness: "unknown",
      },
      { status: 200 }
    );
  }
}
