import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/ai/xai/boundary — Decision boundary scatter plot data.
 *
 * Returns the two most discriminative score dimensions (lgbm_score vs eif_score)
 * with combined_score as the color axis for recent events.
 * The threshold line separates discard/monitor/escalate zones.
 */
export async function GET() {
  try {
    const data = await cached("xai:boundary", 30_000, async () => {
      const result = await queryClickHouse<{
        lgbm: string;
        eif: string;
        combined: string;
        action: string;
      }>(
        `SELECT
           lgbm_score AS lgbm,
           eif_score AS eif,
           combined_score AS combined,
           action
         FROM clif_logs.triage_scores
         WHERE timestamp >= now() - INTERVAL 24 HOUR
         ORDER BY rand()
         LIMIT 5000`
      );

      const points = result.data.map((r) => ({
        x: Number(r.lgbm),
        y: Number(r.eif),
        score: Number(r.combined),
        action: r.action,
      }));

      // Compute threshold lines from the data
      const escalated = points.filter((p) => p.action === "escalate");
      const monitored = points.filter((p) => p.action === "monitor");
      const discarded = points.filter((p) => p.action === "discard");

      return {
        points,
        axes: { x: "LightGBM Score", y: "EIF Anomaly Score" },
        colorAxis: "Combined Score",
        summary: {
          escalated: escalated.length,
          monitored: monitored.length,
          discarded: discarded.length,
          total: points.length,
        },
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Boundary data unavailable", points: [] },
      { status: 200 }
    );
  }
}
