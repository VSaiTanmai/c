import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/ai/xai/fairness — Fairness metrics across source types.
 *
 * Cross-tabulates feedback_labels with triage_scores predictions to compute:
 *   - Demographic parity: escalation rate per source_type
 *   - Equalized odds: TP rate per source_type (conditional on actual label)
 *   - Selection rate ratio: min/max escalation rate ratio
 */
export async function GET() {
  try {
    const data = await cached("xai:fairness", 120_000, async () => {
      // 1. Demographic parity — escalation rate per source_type (no labels needed)
      const dpRows = await queryClickHouse<{
        source_type: string;
        total: string;
        escalated: string;
        escalation_rate: string;
      }>(`
        SELECT
          source_type,
          count()                                           AS total,
          countIf(action = 'escalate')                      AS escalated,
          round(countIf(action = 'escalate') / count(), 4)  AS escalation_rate
        FROM clif_logs.triage_scores
        WHERE source_type != ''
        GROUP BY source_type
        HAVING total >= 20
        ORDER BY total DESC
        LIMIT 20
      `);

      const demographic = dpRows.data.map((r) => ({
        sourceType: r.source_type,
        total: Number(r.total),
        escalated: Number(r.escalated),
        escalationRate: Number(r.escalation_rate),
      }));

      // Selection rate ratio (min / max escalation rate)
      const rates = demographic.map((d) => d.escalationRate).filter((r) => r > 0);
      const selectionRateRatio =
        rates.length >= 2 ? Math.min(...rates) / Math.max(...rates) : null;

      // 2. Equalized odds — requires feedback labels
      const eoRows = await queryClickHouse<{
        source_type: string;
        tp: string;
        fp: string;
        fn: string;
        tn: string;
      }>(`
        SELECT
          t.source_type,
          countIf(t.action = 'escalate' AND f.label = 'true_positive')    AS tp,
          countIf(t.action = 'escalate' AND f.label = 'false_positive')   AS fp,
          countIf(t.action != 'escalate' AND f.label = 'true_positive')   AS fn,
          countIf(t.action != 'escalate' AND f.label = 'false_positive')  AS tn
        FROM clif_logs.triage_scores AS t
        INNER JOIN clif_logs.feedback_labels AS f ON t.event_id = f.event_id
        WHERE t.source_type != ''
        GROUP BY t.source_type
        HAVING (tp + fp + fn + tn) >= 5
        ORDER BY (tp + fp + fn + tn) DESC
        LIMIT 20
      `);

      const equalizedOdds = eoRows.data.map((r) => {
        const tp = Number(r.tp);
        const fp = Number(r.fp);
        const fn = Number(r.fn);
        const tn = Number(r.tn);
        const tpr = tp + fn > 0 ? tp / (tp + fn) : null;
        const fpr = fp + tn > 0 ? fp / (fp + tn) : null;
        return {
          sourceType: r.source_type,
          tp,
          fp,
          fn,
          tn,
          tpr: tpr !== null ? Math.round(tpr * 10000) / 10000 : null,
          fpr: fpr !== null ? Math.round(fpr * 10000) / 10000 : null,
        };
      });

      // Compute disparity (max - min TPR across groups)
      const tprs = equalizedOdds.map((e) => e.tpr).filter((v): v is number => v !== null);
      const tprDisparity =
        tprs.length >= 2
          ? Math.round((Math.max(...tprs) - Math.min(...tprs)) * 10000) / 10000
          : null;

      return {
        demographic,
        selectionRateRatio:
          selectionRateRatio !== null
            ? Math.round(selectionRateRatio * 10000) / 10000
            : null,
        equalizedOdds,
        tprDisparity,
        labelsAvailable: eoRows.data.length > 0,
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Fairness data unavailable" },
      { status: 500 }
    );
  }
}
