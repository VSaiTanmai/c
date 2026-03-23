import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/ai/xai/drift — Model drift metrics (PSI + KL divergence).
 *
 * Reads PSI and KL divergence values written by the triage agent's
 * DriftMonitor into the pipeline_metrics table.
 *
 * Returns:
 * - Latest aggregate PSI, KL, and PSI max values
 * - Per-feature PSI for the top drifting features
 * - Historical 24h trend of PSI values
 */
export async function GET() {
  try {
    const data = await cached("xai:drift", 30_000, async () => {
      const [latestRes, perFeatureRes, trendRes] = await Promise.allSettled([
        // Latest aggregate metrics
        queryClickHouse<{ metric: string; value: string; ts: string }>(
          `SELECT metric, value, toString(ts) AS ts
           FROM clif_logs.pipeline_metrics
           WHERE metric IN ('psi_drift', 'kl_divergence', 'psi_max')
           ORDER BY ts DESC
           LIMIT 1 BY metric`
        ),

        // Per-feature PSI (latest values)
        queryClickHouse<{ metric: string; value: string }>(
          `SELECT metric, value
           FROM clif_logs.pipeline_metrics
           WHERE metric LIKE 'psi_feature_%'
           ORDER BY ts DESC
           LIMIT 1 BY metric`
        ),

        // PSI trend over last 24h
        queryClickHouse<{ ts: string; value: string }>(
          `SELECT toString(ts) AS ts, value
           FROM clif_logs.pipeline_metrics
           WHERE metric = 'psi_drift'
             AND ts >= now() - INTERVAL 24 HOUR
           ORDER BY ts ASC`
        ),
      ]);

      // Parse latest aggregates
      const latest =
        latestRes.status === "fulfilled" ? latestRes.value.data : [];
      const metrics: Record<string, { value: number; timestamp: string }> = {};
      for (const row of latest) {
        metrics[row.metric] = {
          value: Number(row.value),
          timestamp: row.ts,
        };
      }

      // Parse per-feature PSI
      const featureRows =
        perFeatureRes.status === "fulfilled" ? perFeatureRes.value.data : [];
      const perFeature = featureRows.map((r) => ({
        feature: r.metric.replace("psi_feature_", ""),
        psi: Number(r.value),
      })).sort((a, b) => b.psi - a.psi);

      // Parse trend
      const trendRows =
        trendRes.status === "fulfilled" ? trendRes.value.data : [];
      const trend = trendRows.map((r) => ({
        timestamp: r.ts,
        psi: Number(r.value),
      }));

      const psiValue = metrics["psi_drift"]?.value ?? null;
      let driftStatus: string;
      if (psiValue === null) driftStatus = "unknown";
      else if (psiValue >= 0.25) driftStatus = "critical";
      else if (psiValue >= 0.1) driftStatus = "moderate";
      else driftStatus = "stable";

      return {
        psi: metrics["psi_drift"] ?? null,
        klDivergence: metrics["kl_divergence"] ?? null,
        psiMax: metrics["psi_max"] ?? null,
        driftStatus,
        perFeaturePsi: perFeature,
        trend,
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Drift data unavailable", driftStatus: "unknown" },
      { status: 200 }
    );
  }
}
