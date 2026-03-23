import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { cached } from "@/lib/cache";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const RATE_LIMIT = { maxTokens: 20, refillRate: 1 };

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT);
  if (limited) return limited;

  try {
    const data = await cached("evidence:chain", 15_000, async () => {
      const [batches, summary] = await Promise.all([
        // Fetch anchor batches with pagination safety
        queryClickHouse<{
          batch_id: string;
          created_at: string;
          table_name: string;
          time_from: string;
          time_to: string;
          event_count: string;
          merkle_root: string;
          merkle_depth: string;
          s3_key: string;
          status: string;
          prev_merkle_root: string;
        }>(
          `SELECT
             batch_id,
             toString(created_at) AS created_at,
             table_name,
             toString(time_from) AS time_from,
             toString(time_to) AS time_to,
             event_count,
             merkle_root,
             merkle_depth,
             s3_key,
             status,
             prev_merkle_root
           FROM clif_logs.evidence_anchors
           ORDER BY created_at DESC
           LIMIT 1000`
        ),
        // Aggregate summary stats
        queryClickHouse<{
          total_anchored: string;
          total_batches: string;
          avg_batch_size: string;
          verified_count: string;
        }>(
          `SELECT
             sum(event_count) AS total_anchored,
             count() AS total_batches,
             avg(event_count) AS avg_batch_size,
             countIf(status = 'Verified') AS verified_count
           FROM clif_logs.evidence_anchors`
        ),
      ]);

      const summaryRow = summary.data[0];
      const totalBatches = Number(summaryRow?.total_batches ?? 0);
      const verifiedCount = Number(summaryRow?.verified_count ?? 0);

      return {
        batches: batches.data.map((b) => ({
          id: b.batch_id,
          timestamp: b.created_at,
          tableName: b.table_name,
          timeFrom: b.time_from,
          timeTo: b.time_to,
          eventCount: Number(b.event_count),
          merkleRoot: b.merkle_root,
          merkleDepth: Number(b.merkle_depth),
          // Only expose filename, not full S3 key path (security)
          s3Key: b.s3_key ? b.s3_key.split("/").pop() || "" : "",
          status: b.status,
          prevMerkleRoot: b.prev_merkle_root,
        })),
        summary: {
          totalAnchored: Number(summaryRow?.total_anchored ?? 0),
          totalBatches,
          verificationRate: totalBatches > 0
            ? Math.round((verifiedCount / totalBatches) * 100)
            : 0,
          avgBatchSize: Math.round(Number(summaryRow?.avg_batch_size ?? 0)),
          chainLength: totalBatches,
        },
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("Evidence chain fetch failed", { error: err instanceof Error ? err.message : "unknown", component: "api/evidence/chain" });
    return NextResponse.json(
      { error: "Failed to fetch evidence chain" },
      { status: 500 }
    );
  }
}
