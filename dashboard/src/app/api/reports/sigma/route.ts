import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";

/**
 * GET /api/reports/sigma — Sigma rule catalog, coverage score, and TP rate.
 *
 * Returns:
 * - Active rules list with fire counts and MITRE mapping
 * - Coverage = unique MITRE techniques covered / total known techniques
 * - TP rate derived from verified investigations
 * - Top firing rules (from security_events categories)
 */
export async function GET() {
  try {
    const data = await cached("reports:sigma", 60_000, async () => {
      const [rulesRes, firingRes, coverageRes, severityDistRes] =
        await Promise.allSettled([
          // Sigma rule catalog
          queryClickHouse<{
            rule_id: string;
            rule_name: string;
            severity: string;
            mitre_tactic: string;
            mitre_technique: string;
            description: string;
            status: string;
            fire_count: string;
          }>(
            `SELECT rule_id, rule_name, severity, mitre_tactic, mitre_technique,
                    description, status, fire_count
             FROM clif_logs.sigma_rules
             ORDER BY fire_count DESC`
          ),

          // Top firing rules from actual security_events (category acts as rule proxy)
          queryClickHouse<{ category: string; cnt: string }>(
            `SELECT category, count() AS cnt
             FROM clif_logs.security_events
             WHERE timestamp >= now() - INTERVAL 24 HOUR
               AND category != ''
             GROUP BY category
             ORDER BY cnt DESC
             LIMIT 10`
          ),

          // MITRE coverage: unique techniques in sigma_rules vs techniques seen in events
          queryClickHouse<{
            rule_techniques: string;
            seen_techniques: string;
          }>(
            `SELECT
               (SELECT uniqExact(mitre_technique) FROM clif_logs.sigma_rules
                WHERE mitre_technique != '' AND status = 'active') AS rule_techniques,
               (SELECT uniqExact(mitre_technique) FROM clif_logs.security_events
                WHERE mitre_technique != '') AS seen_techniques`
          ),

          // Severity distribution from sigma rules
          queryClickHouse<{ severity: string; cnt: string }>(
            `SELECT severity, count() AS cnt
             FROM clif_logs.sigma_rules
             WHERE status = 'active'
             GROUP BY severity
             ORDER BY cnt DESC`
          ),
        ]);

      const rules =
        rulesRes.status === "fulfilled"
          ? rulesRes.value.data.map((r) => ({
              ruleId: r.rule_id,
              ruleName: r.rule_name,
              severity: r.severity,
              mitreTactic: r.mitre_tactic,
              mitreTechnique: r.mitre_technique,
              description: r.description,
              status: r.status,
              fireCount: Number(r.fire_count),
            }))
          : [];

      const topFiring =
        firingRes.status === "fulfilled"
          ? firingRes.value.data.map((r) => ({
              category: r.category,
              count: Number(r.cnt),
            }))
          : [];

      const coverage =
        coverageRes.status === "fulfilled"
          ? coverageRes.value.data[0]
          : null;
      const ruleTechniques = Number(coverage?.rule_techniques ?? 0);
      const seenTechniques = Number(coverage?.seen_techniques ?? 0);

      const severityDist =
        severityDistRes.status === "fulfilled"
          ? severityDistRes.value.data.map((s) => ({
              severity: s.severity,
              count: Number(s.cnt),
            }))
          : [];

      return {
        rules,
        activeRules: rules.filter((r) => r.status === "active").length,
        totalRules: rules.length,
        coverageScore:
          seenTechniques > 0
            ? Number((ruleTechniques / seenTechniques).toFixed(4))
            : null,
        ruleTechniques,
        seenTechniques,
        topFiringRules: topFiring,
        severityDistribution: severityDist,
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : "Sigma rules unavailable" },
      { status: 500 }
    );
  }
}
