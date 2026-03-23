import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

const PROMETHEUS_URL = process.env.PROMETHEUS_URL || "http://prometheus:9090";

/**
 * GET /api/reports/ml — ML model metrics for Reports Tab 4.
 *
 * Returns TP/FP ratio, model health (uptime + sample count),
 * hunter score distribution, and feature importance.
 */
export async function GET() {
  try {
    const data = await cached("reports:ml", 30_000, async () => {
      const [verdictRes, scoreDistRes, sampleCountRes, uptimeRes] =
        await Promise.allSettled([
          // TP/FP classification ratio from verifier verdicts
          queryClickHouse<{
            verdict: string;
            cnt: string;
          }>(
            `SELECT verdict, count() AS cnt
             FROM clif_logs.verifier_results
             GROUP BY verdict`
          ),

          // Hunter score distribution (10 buckets)
          queryClickHouse<{ bucket: string; cnt: string }>(
            `SELECT
               intDiv(toUInt16(combined_score * 100), 10) * 10 AS bucket,
               count() AS cnt
             FROM clif_logs.triage_scores
             WHERE timestamp >= now() - INTERVAL 7 DAY
             GROUP BY bucket
             ORDER BY bucket`
          ),

          // Sample count last 24h
          queryClickHouse<{ cnt: string }>(
            `SELECT count() AS cnt
             FROM clif_logs.triage_scores
             WHERE timestamp >= now() - INTERVAL 24 HOUR`
          ),

          // Prometheus uptime (best-effort)
          fetch(
            `${PROMETHEUS_URL}/api/v1/query?query=avg_over_time(up{job=~"triage.*"}[24h])*100`,
            { signal: AbortSignal.timeout(3000), cache: "no-store" }
          )
            .then((r) => (r.ok ? r.json() : null))
            .catch(() => null),
        ]);

      // TP/FP ratio
      const verdicts =
        verdictRes.status === "fulfilled" ? verdictRes.value.data : [];
      const verdictMap: Record<string, number> = {};
      for (const v of verdicts) {
        verdictMap[v.verdict] = Number(v.cnt);
      }
      const tp = verdictMap["true_positive"] ?? 0;
      const fp = verdictMap["false_positive"] ?? 0;
      const inconclusive = verdictMap["inconclusive"] ?? 0;
      const totalVerdicts = tp + fp + inconclusive;

      // Score distribution
      const scoreDist =
        scoreDistRes.status === "fulfilled"
          ? scoreDistRes.value.data.map((d) => ({
              bucket: `${d.bucket}-${Number(d.bucket) + 9}`,
              count: Number(d.cnt),
            }))
          : [];

      // Model health
      const sampleCount =
        sampleCountRes.status === "fulfilled"
          ? Number(sampleCountRes.value.data[0]?.cnt ?? 0)
          : 0;

      let uptimePct = null;
      if (uptimeRes.status === "fulfilled" && uptimeRes.value) {
        const promResult = uptimeRes.value?.data?.result?.[0]?.value?.[1];
        if (promResult != null) uptimePct = Number(Number(promResult).toFixed(2));
      }

      return {
        tpFpRatio: {
          truePositive: tp,
          falsePositive: fp,
          inconclusive,
          total: totalVerdicts,
          precision: totalVerdicts > 0 ? Number((tp / (tp + fp || 1)).toFixed(4)) : null,
        },
        scoreDistribution: scoreDist,
        modelHealth: {
          uptimePercent: uptimePct,
          samplesLast24h: sampleCount,
          status: sampleCount > 0 ? "healthy" : "no_data",
        },
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "ML metrics unavailable" },
      { status: 500 }
    );
  }
}
