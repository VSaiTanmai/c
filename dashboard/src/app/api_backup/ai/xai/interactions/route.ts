import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/ai/xai/interactions — Top-5 feature interaction strengths.
 *
 * Computes pairwise co-occurrence of top SHAP features from triage_scores.
 * Features that frequently appear together in shap_top_features JSON
 * indicate interaction effects in the model.
 */
export async function GET() {
  try {
    const data = await cached("xai:interactions", 60_000, async () => {
      const result = await queryClickHouse<{ features: string }>(
        `SELECT shap_top_features AS features
         FROM clif_logs.triage_scores
         WHERE timestamp >= now() - INTERVAL 24 HOUR
           AND shap_top_features != ''
         ORDER BY timestamp DESC
         LIMIT 10000`
      );

      // Parse SHAP top features and build co-occurrence matrix
      const pairCounts = new Map<string, { count: number; totalImportance: number }>();
      let totalEvents = 0;

      for (const row of result.data) {
        try {
          // shap_top_features may be:
          //   Object: {"feat": {"contribution": 0.45, "value": 3}, ...}
          //   Array:  [{"feature":"x","shap":0.3}, ...]
          const parsed = JSON.parse(row.features);
          if (parsed === null || typeof parsed !== "object") continue;

          totalEvents++;

          // Normalize to array of { name, importance }
          let entries: { name: string; importance: number }[];
          if (Array.isArray(parsed)) {
            entries = parsed
              .slice(0, 5)
              .map((f: Record<string, unknown>) => ({
                name: String(f.feature ?? f.name ?? ""),
                importance: Math.abs(Number(f.shap ?? f.contribution ?? f.value ?? 0)),
              }))
              .filter((e) => e.name);
          } else {
            entries = Object.entries(parsed as Record<string, Record<string, number>>)
              .slice(0, 5)
              .map(([name, data]) => ({
                name,
                importance: Math.abs(data?.contribution ?? data?.value ?? 0),
              }));
          }

          // Build all pairs
          for (let i = 0; i < entries.length; i++) {
            for (let j = i + 1; j < entries.length; j++) {
              const pair = [entries[i].name, entries[j].name].sort().join(" × ");
              const existing = pairCounts.get(pair) ?? { count: 0, totalImportance: 0 };
              existing.count++;
              existing.totalImportance += entries[i].importance + entries[j].importance;
              pairCounts.set(pair, existing);
            }
          }
        } catch {
          // Skip malformed JSON
        }
      }

      // Sort by frequency × average importance
      const interactions = Array.from(pairCounts.entries())
        .map(([pair, data]) => ({
          pair,
          features: pair.split(" × "),
          coOccurrence: data.count,
          coOccurrenceRate: totalEvents > 0 ? data.count / totalEvents : 0,
          avgImportance: data.count > 0 ? data.totalImportance / data.count : 0,
          strength: totalEvents > 0
            ? (data.count / totalEvents) * (data.totalImportance / data.count)
            : 0,
        }))
        .sort((a, b) => b.strength - a.strength)
        .slice(0, 5);

      return {
        interactions,
        totalEventsAnalyzed: totalEvents,
        analysisWindow: "24h",
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Interaction data unavailable", interactions: [] },
      { status: 200 }
    );
  }
}
