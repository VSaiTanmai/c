import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:8200";

/**
 * GET /api/ai/leaderboard — Build leaderboard from all 3 ensemble models.
 *
 * Shows LightGBM (primary binary), EIF (anomaly), and ARF (online learning)
 * with per-model metrics derived from live triage_scores data.
 */
export async function GET() {
  try {
    const data = await cached("ai:leaderboard", 30_000, async () => {
      // Fetch XAI status for LightGBM manifest metrics (ground truth from training)
      const xaiPromise = fetch(`${AI_SERVICE_URL}/xai/status`, {
        cache: "no-store",
        signal: AbortSignal.timeout(5000),
      }).then(r => r.ok ? r.json() : null).catch(() => null);

      // Fetch per-model score distributions from live triage data
      const statsPromise = queryClickHouse<{
        total: string;
        lgbm_avg: string;
        lgbm_std: string;
        lgbm_gt50: string;
        eif_avg: string;
        eif_std: string;
        eif_gt50: string;
        arf_avg: string;
        arf_std: string;
        arf_gt50: string;
        escalate_count: string;
        discard_count: string;
      }>(
        `SELECT
           count() AS total,
           avg(lgbm_score) AS lgbm_avg,
           stddevPop(lgbm_score) AS lgbm_std,
           countIf(lgbm_score > 0.5) AS lgbm_gt50,
           avg(eif_score) AS eif_avg,
           stddevPop(eif_score) AS eif_std,
           countIf(eif_score > 0.5) AS eif_gt50,
           avg(arf_score) AS arf_avg,
           stddevPop(arf_score) AS arf_std,
           countIf(arf_score > 0.5) AS arf_gt50,
           countIf(action = 'escalate') AS escalate_count,
           countIf(action = 'discard') AS discard_count
         FROM clif_logs.triage_scores
         WHERE timestamp >= now() - INTERVAL 24 HOUR`
      ).catch(() => null);

      const [xai, stats] = await Promise.all([xaiPromise, statsPromise]);
      const m = xai?.metrics ?? {};
      const s = stats?.data?.[0];
      const total = Number(s?.total ?? 0) || 1;

      return {
        binary: [
          {
            name: xai?.model_types?.binary ?? "LightGBM",
            role: "Primary binary classifier",
            weight: 0.80,
            accuracy: m.accuracy ?? 0,
            precision: m.precision ?? 0,
            recall: m.recall ?? 0,
            f1: m.f1 ?? 0,
            roc_auc: m.roc_auc ?? m.f1 ?? 0,
            avgScore: Number(Number(s?.lgbm_avg ?? 0).toFixed(4)),
            stdScore: Number(Number(s?.lgbm_std ?? 0).toFixed(4)),
            alertRate: Number((Number(s?.lgbm_gt50 ?? 0) / total).toFixed(4)),
            samplesLast24h: total,
          },
          {
            name: "Extended Isolation Forest",
            role: "Anomaly detector (unsupervised)",
            weight: 0.12,
            accuracy: null,
            precision: null,
            recall: null,
            f1: null,
            roc_auc: null,
            avgScore: Number(Number(s?.eif_avg ?? 0).toFixed(4)),
            stdScore: Number(Number(s?.eif_std ?? 0).toFixed(4)),
            alertRate: Number((Number(s?.eif_gt50 ?? 0) / total).toFixed(4)),
            samplesLast24h: total,
          },
          {
            name: "Adaptive Random Forest",
            role: "Online learning (concept drift)",
            weight: 0.08,
            accuracy: null,
            precision: null,
            recall: null,
            f1: null,
            roc_auc: null,
            avgScore: Number(Number(s?.arf_avg ?? 0).toFixed(4)),
            stdScore: Number(Number(s?.arf_std ?? 0).toFixed(4)),
            alertRate: Number((Number(s?.arf_gt50 ?? 0) / total).toFixed(4)),
            samplesLast24h: total,
          },
        ],
        ensemble: {
          escalateRate: Number((Number(s?.escalate_count ?? 0) / total).toFixed(4)),
          discardRate: Number((Number(s?.discard_count ?? 0) / total).toFixed(4)),
          totalProcessed: total,
        },
        multiclass: [],
      };
    });
    return NextResponse.json(data);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "AI service unreachable";
    return NextResponse.json({ error: msg }, { status: 503 });
  }
}
