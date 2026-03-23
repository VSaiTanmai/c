import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/reports/history — List previously generated reports.
 *
 * Returns the most recent 100 reports from report_history table,
 * plus aggregate counts.
 */
export async function GET() {
  try {
    const data = await cached("reports:history", 15_000, async () => {
      const [historyRes, countsRes] = await Promise.allSettled([
        queryClickHouse<{
          report_id: string;
          title: string;
          template: string;
          investigation_id: string;
          created_at: string;
          format: string;
          size_bytes: string;
          created_by: string;
        }>(
          `SELECT
             toString(report_id) AS report_id,
             title,
             template,
             toString(investigation_id) AS investigation_id,
             toString(created_at) AS created_at,
             format,
             size_bytes,
             created_by
           FROM clif_logs.report_history
           ORDER BY created_at DESC
           LIMIT 100`
        ),
        queryClickHouse<{ total: string; last_7d: string }>(
          `SELECT
             count() AS total,
             countIf(created_at >= now() - INTERVAL 7 DAY) AS last_7d
           FROM clif_logs.report_history`
        ),
      ]);

      const history =
        historyRes.status === "fulfilled"
          ? historyRes.value.data.map((r) => ({
              reportId: r.report_id,
              title: r.title,
              template: r.template,
              investigationId: r.investigation_id || null,
              createdAt: r.created_at,
              format: r.format,
              sizeBytes: Number(r.size_bytes),
              createdBy: r.created_by,
            }))
          : [];

      const counts =
        countsRes.status === "fulfilled" ? countsRes.value.data[0] : null;

      return {
        reports: history,
        totalGenerated: Number(counts?.total ?? 0),
        generatedLast7d: Number(counts?.last_7d ?? 0),
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Report history unavailable" },
      { status: 500 }
    );
  }
}
