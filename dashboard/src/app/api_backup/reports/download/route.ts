import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

/* ── Helpers ── */
function escapeCSV(val: string): string {
  if (val.includes(",") || val.includes('"') || val.includes("\n")) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}

const SEV_LABEL: Record<number, string> = {
  0: "Info",
  1: "Low",
  2: "Medium",
  3: "High",
  4: "Critical",
};

/* ── GET /api/reports/download?type=incident|executive|technical|compliance|threat-intel&format=pdf|csv|json|markdown ── */
export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), { maxTokens: 5, refillRate: 0.2 });
  if (limited) return limited;

  const { searchParams } = new URL(request.url);
  const reportType = searchParams.get("type") ?? "incident";
  const format = searchParams.get("format") ?? "json";

  const validTypes = ["incident", "executive", "technical", "compliance", "threat-intel"];
  const validFormats = ["pdf", "csv", "json", "markdown"];

  if (!validTypes.includes(reportType)) {
    return NextResponse.json({ error: `Invalid type. Valid: ${validTypes.join(", ")}` }, { status: 400 });
  }
  if (!validFormats.includes(format)) {
    return NextResponse.json({ error: `Invalid format. Valid: ${validFormats.join(", ")}` }, { status: 400 });
  }

  try {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    let alerts: any[], evidence: any[], events: any[], mitre: any[], categories: any[];

    // Pull real data from ClickHouse
    const [alertsRes, evidenceRes, eventsRes, mitreRes, categoriesRes] = await Promise.allSettled([
      queryClickHouse<{
        event_id: string;
        ts: string;
        severity: string;
        category: string;
        source: string;
        description: string;
        hostname: string;
        user_id: string;
        mitre_tactic: string;
        mitre_technique: string;
      }>(
        `SELECT
           toString(event_id) AS event_id,
           toString(timestamp) AS ts,
           severity,
           category,
           source,
           description,
           hostname,
           user_id,
           mitre_tactic,
           mitre_technique
         FROM clif_logs.security_events
         WHERE severity >= 2
           AND timestamp >= now() - INTERVAL 7 DAY
         ORDER BY timestamp DESC
         LIMIT 200`
      ),
      queryClickHouse<{
        batch_id: string;
        created_at: string;
        table_name: string;
        event_count: string;
        merkle_root: string;
        merkle_depth: string;
        status: string;
      }>(
        `SELECT
           batch_id,
           toString(created_at) AS created_at,
           table_name,
           event_count,
           merkle_root,
           merkle_depth,
           status
         FROM clif_logs.evidence_anchors
         ORDER BY created_at DESC
         LIMIT 100`
      ),
      queryClickHouse<{ table_name: string; cnt: string }>(
        `SELECT 'raw_logs' AS table_name, count() AS cnt FROM clif_logs.raw_logs
         UNION ALL
         SELECT 'security_events', count() FROM clif_logs.security_events
         UNION ALL
         SELECT 'process_events', count() FROM clif_logs.process_events
         UNION ALL
         SELECT 'network_events', count() FROM clif_logs.network_events`
      ),
      queryClickHouse<{ technique: string; tactic: string; cnt: string }>(
        `SELECT mitre_technique AS technique, mitre_tactic AS tactic, count() AS cnt
         FROM clif_logs.security_events
         WHERE mitre_technique != ''
           AND timestamp >= now() - INTERVAL 7 DAY
         GROUP BY mitre_technique, mitre_tactic
         ORDER BY cnt DESC
         LIMIT 20`
      ),
      queryClickHouse<{ category: string; cnt: string }>(
        `SELECT category, count() AS cnt
         FROM clif_logs.security_events
         WHERE timestamp >= now() - INTERVAL 7 DAY
         GROUP BY category
         ORDER BY cnt DESC
         LIMIT 10`
      ),
    ]);

    const alerts2 = alertsRes.status === "fulfilled" ? alertsRes.value.data : [];
    const evidence2 = evidenceRes.status === "fulfilled" ? evidenceRes.value.data : [];
    const events2 = eventsRes.status === "fulfilled" ? eventsRes.value.data : [];
    const mitre2 = mitreRes.status === "fulfilled" ? mitreRes.value.data : [];
    const categories2 = categoriesRes.status === "fulfilled" ? categoriesRes.value.data : [];
    alerts = alerts2;
    evidence = evidence2;
    events = events2;
    mitre = mitre2;
    categories = categories2;

    const now = new Date().toISOString();
    const totalEvents = events.reduce((s, e) => s + Number(e.cnt), 0);
    const criticalCount = alerts.filter((a) => Number(a.severity) === 4).length;
    const highCount = alerts.filter((a) => Number(a.severity) === 3).length;

    const REPORT_TITLES: Record<string, string> = {
      incident: "Incident Report",
      executive: "Executive Summary",
      technical: "Technical Analysis Report",
      compliance: "Compliance & Audit Report",
      "threat-intel": "Threat Intelligence Report",
    };
    const title = REPORT_TITLES[reportType] ?? "Report";

    // Helper: record report generation in history table (fire-and-forget)
    // Values are all server-controlled constants (title from REPORT_TITLES, template from validTypes, format from validFormats)
    const recordHistory = (sizeBytes: number) => {
      const safeTitle = title.replace(/'/g, "''");
      queryClickHouse(
        `INSERT INTO clif_logs.report_history (title, template, format, size_bytes, created_by)
         VALUES ('${safeTitle}', '${reportType}', '${format}', ${Math.floor(sizeBytes)}, 'dashboard')`
      ).catch(() => { /* best-effort */ });
    };

    // ── JSON format ──
    if (format === "json") {
      const jsonReport = buildJsonReport(reportType, title, now, alerts, evidence, events, mitre, categories, totalEvents, criticalCount, highCount);
      const body = JSON.stringify(jsonReport, null, 2);
      recordHistory(new TextEncoder().encode(body).length);
      return new NextResponse(body, {
        headers: {
          "Content-Type": "application/json",
          "Content-Disposition": `attachment; filename="CLIF-${title.replace(/\s+/g, "-")}-${now.slice(0, 10)}.json"`,
        },
      });
    }

    // ── CSV format ──
    if (format === "csv") {
      const csv = buildCsvReport(reportType, alerts, evidence, mitre);
      recordHistory(new TextEncoder().encode(csv).length);
      return new NextResponse(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="CLIF-${title.replace(/\s+/g, "-")}-${now.slice(0, 10)}.csv"`,
        },
      });
    }

    // ── Markdown format ──
    if (format === "markdown") {
      const md = buildMarkdownReport(reportType, title, now, alerts, evidence, events, mitre, categories, totalEvents, criticalCount, highCount);
      recordHistory(new TextEncoder().encode(md).length);
      return new NextResponse(md, {
        headers: {
          "Content-Type": "text/markdown; charset=utf-8",
          "Content-Disposition": `attachment; filename="CLIF-${title.replace(/\s+/g, "-")}-${now.slice(0, 10)}.md"`,
        },
      });
    }

    // ── PDF format (HTML-based for browser rendering / print-to-pdf) ──
    if (format === "pdf") {
      const html = buildHtmlReport(reportType, title, now, alerts, evidence, events, mitre, categories, totalEvents, criticalCount, highCount);
      recordHistory(new TextEncoder().encode(html).length);
      return new NextResponse(html, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Disposition": `inline; filename="CLIF-${title.replace(/\s+/g, "-")}-${now.slice(0, 10)}.html"`,
        },
      });
    }

    return NextResponse.json({ error: "Unknown format" }, { status: 400 });
  } catch (err) {
    log.error("Report download failed", {
      error: err instanceof Error ? err.message : "unknown",
      component: "api/reports/download",
    });
    return NextResponse.json({ error: "Report generation failed" }, { status: 500 });
  }
}

/* ═══════════════════════════════════ JSON Builder ═══════════════════════════════════ */
function buildJsonReport(
  type: string, title: string, now: string,
  alerts: Array<Record<string, string>>,
  evidence: Array<Record<string, string>>,
  events: Array<Record<string, string>>,
  mitre: Array<Record<string, string>>,
  categories: Array<Record<string, string>>,
  totalEvents: number, criticalCount: number, highCount: number,
) {
  return {
    report: {
      title,
      type,
      generatedAt: now,
      generatedBy: "CLIF — Cognitive Log Investigation Framework",
      classification: "CONFIDENTIAL",
    },
    summary: {
      totalEvents,
      alertsLast7Days: alerts.length,
      criticalAlerts: criticalCount,
      highAlerts: highCount,
      evidenceBatches: evidence.length,
      topCategories: categories.slice(0, 5).map((c) => ({ category: c.category, count: Number(c.cnt) })),
      mitreTopTechniques: mitre.slice(0, 10).map((m) => ({
        technique: m.technique,
        tactic: m.tactic,
        count: Number(m.cnt),
      })),
    },
    alerts: alerts.map((a) => ({
      eventId: a.event_id,
      timestamp: a.ts,
      severity: SEV_LABEL[Number(a.severity)] ?? a.severity,
      category: a.category,
      source: a.source,
      description: a.description,
      hostname: a.hostname,
      userId: a.user_id,
      mitreTactic: a.mitre_tactic,
      mitreTechnique: a.mitre_technique,
    })),
    evidenceChain: evidence.map((e) => ({
      batchId: e.batch_id,
      createdAt: e.created_at,
      table: e.table_name,
      eventCount: Number(e.event_count),
      merkleRoot: e.merkle_root,
      depth: Number(e.merkle_depth),
      status: e.status,
    })),
  };
}

/* ═══════════════════════════════════ CSV Builder ═══════════════════════════════════ */
function buildCsvReport(
  type: string,
  alerts: Array<Record<string, string>>,
  evidence: Array<Record<string, string>>,
  mitre: Array<Record<string, string>>,
) {
  const lines: string[] = [];

  if (type === "compliance" || type === "incident") {
    // Evidence chain data
    lines.push("## Evidence Chain of Custody");
    lines.push("Batch ID,Created At,Table,Event Count,Merkle Root,Depth,Status");
    for (const e of evidence) {
      lines.push([
        escapeCSV(e.batch_id), escapeCSV(e.created_at), escapeCSV(e.table_name),
        e.event_count, escapeCSV(e.merkle_root), e.merkle_depth, escapeCSV(e.status),
      ].join(","));
    }
    lines.push("");
  }

  if (type === "threat-intel") {
    lines.push("## MITRE ATT&CK Techniques");
    lines.push("Technique,Tactic,Count");
    for (const m of mitre) {
      lines.push([escapeCSV(m.technique), escapeCSV(m.tactic), m.cnt].join(","));
    }
    lines.push("");
  }

  // Always include alerts
  lines.push("## Security Alerts (Last 7 Days)");
  lines.push("Event ID,Timestamp,Severity,Category,Source,Description,Hostname,User ID,MITRE Tactic,MITRE Technique");
  for (const a of alerts) {
    lines.push([
      escapeCSV(a.event_id), escapeCSV(a.ts), SEV_LABEL[Number(a.severity)] ?? a.severity,
      escapeCSV(a.category), escapeCSV(a.source), escapeCSV(a.description),
      escapeCSV(a.hostname), escapeCSV(a.user_id),
      escapeCSV(a.mitre_tactic), escapeCSV(a.mitre_technique),
    ].join(","));
  }

  return lines.join("\n");
}

/* ═══════════════════════════════════ Markdown Builder ═══════════════════════════════════ */
function buildMarkdownReport(
  type: string, title: string, now: string,
  alerts: Array<Record<string, string>>,
  evidence: Array<Record<string, string>>,
  events: Array<Record<string, string>>,
  mitre: Array<Record<string, string>>,
  categories: Array<Record<string, string>>,
  totalEvents: number, criticalCount: number, highCount: number,
) {
  const lines: string[] = [];
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`**Generated:** ${new Date(now).toLocaleString()}`);
  lines.push(`**Classification:** CONFIDENTIAL`);
  lines.push(`**Generator:** CLIF — Cognitive Log Investigation Framework`);
  lines.push("");

  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Events Ingested | ${totalEvents.toLocaleString()} |`);
  lines.push(`| Security Alerts (7d) | ${alerts.length} |`);
  lines.push(`| Critical Alerts | ${criticalCount} |`);
  lines.push(`| High Alerts | ${highCount} |`);
  lines.push(`| Evidence Batches | ${evidence.length} |`);
  lines.push("");

  if (type !== "executive") {
    lines.push("## Event Distribution");
    lines.push("");
    lines.push("| Table | Count |");
    lines.push("|-------|-------|");
    for (const e of events) {
      lines.push(`| ${e.table_name} | ${Number(e.cnt).toLocaleString()} |`);
    }
    lines.push("");
  }

  lines.push("## Top Alert Categories");
  lines.push("");
  lines.push("| Category | Count |");
  lines.push("|----------|-------|");
  for (const c of categories.slice(0, 10)) {
    lines.push(`| ${c.category} | ${Number(c.cnt).toLocaleString()} |`);
  }
  lines.push("");

  if (type === "threat-intel" || type === "technical") {
    lines.push("## MITRE ATT&CK Mapping");
    lines.push("");
    lines.push("| Technique | Tactic | Occurrences |");
    lines.push("|-----------|--------|-------------|");
    for (const m of mitre) {
      lines.push(`| ${m.technique} | ${m.tactic} | ${Number(m.cnt).toLocaleString()} |`);
    }
    lines.push("");
  }

  if (type === "incident" || type === "technical") {
    lines.push("## Critical/High Alerts Detail");
    lines.push("");
    for (const a of alerts.slice(0, 20)) {
      const sev = SEV_LABEL[Number(a.severity)] ?? a.severity;
      lines.push(`### [${sev}] ${a.category} — ${a.source}`);
      lines.push(`- **Time:** ${a.ts}`);
      lines.push(`- **Host:** ${a.hostname}`);
      lines.push(`- **User:** ${a.user_id || "N/A"}`);
      lines.push(`- **Description:** ${a.description}`);
      if (a.mitre_technique) lines.push(`- **MITRE:** ${a.mitre_tactic} / ${a.mitre_technique}`);
      lines.push("");
    }
  }

  if (type === "compliance" || type === "incident") {
    lines.push("## Evidence Chain of Custody");
    lines.push("");
    lines.push("| Batch ID | Table | Events | Merkle Root | Status |");
    lines.push("|----------|-------|--------|-------------|--------|");
    for (const e of evidence.slice(0, 30)) {
      lines.push(`| ${e.batch_id} | ${e.table_name} | ${Number(e.event_count).toLocaleString()} | \`${e.merkle_root.slice(0, 16)}…\` | ${e.status} |`);
    }
    lines.push("");
  }

  lines.push("---");
  lines.push(`*Report generated by CLIF at ${now}*`);

  return lines.join("\n");
}

/* ═══════════════════════════════════ HTML Builder (for PDF) ═══════════════════════════════════ */
function buildHtmlReport(
  type: string, title: string, now: string,
  alerts: Array<Record<string, string>>,
  evidence: Array<Record<string, string>>,
  events: Array<Record<string, string>>,
  mitre: Array<Record<string, string>>,
  categories: Array<Record<string, string>>,
  totalEvents: number, criticalCount: number, highCount: number,
) {
  const sevColor = (s: string) => {
    const n = Number(s);
    if (n === 4) return "#dc2626";
    if (n === 3) return "#f97316";
    if (n === 2) return "#f59e0b";
    return "#64748b";
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${title} — CLIF</title>
<style>
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1e293b; line-height: 1.5; padding: 40px; max-width: 1000px; margin: 0 auto; }
  .header { border-bottom: 3px solid #2563eb; padding-bottom: 16px; margin-bottom: 24px; }
  .header h1 { font-size: 28px; color: #0f172a; }
  .header .meta { font-size: 12px; color: #64748b; margin-top: 4px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-confidential { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
  .section { margin: 24px 0; }
  .section h2 { font-size: 18px; color: #0f172a; border-left: 4px solid #2563eb; padding-left: 12px; margin-bottom: 12px; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
  .kpi { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }
  .kpi .value { font-size: 28px; font-weight: 700; color: #0f172a; }
  .kpi .label { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  .kpi.critical .value { color: #dc2626; }
  .kpi.high .value { color: #f97316; }
  .kpi.green .value { color: #16a34a; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 8px 0; }
  thead { background: #f8fafc; }
  th { text-align: left; padding: 8px 12px; font-weight: 600; color: #475569; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }
  tr:hover { background: #f8fafc; }
  .sev { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; color: white; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }
  @media print { .no-print { display: none; } }
  .print-btn { position: fixed; top: 16px; right: 16px; background: #2563eb; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
  .print-btn:hover { background: #1d4ed8; }
</style>
</head>
<body>
<button class="print-btn no-print" onclick="window.print()">🖨 Print / Save as PDF</button>

<div class="header">
  <h1>${title}</h1>
  <div class="meta">
    Generated: ${new Date(now).toLocaleString()} · <span class="badge badge-confidential">CONFIDENTIAL</span> · CLIF — Cognitive Log Investigation Framework
  </div>
</div>

<div class="kpi-grid">
  <div class="kpi"><div class="value">${totalEvents.toLocaleString()}</div><div class="label">Total Events</div></div>
  <div class="kpi"><div class="value">${alerts.length}</div><div class="label">Alerts (7d)</div></div>
  <div class="kpi critical"><div class="value">${criticalCount}</div><div class="label">Critical</div></div>
  <div class="kpi high"><div class="value">${highCount}</div><div class="label">High</div></div>
</div>

${type !== "executive" ? `
<div class="section">
  <h2>Event Distribution</h2>
  <table>
    <thead><tr><th>Table</th><th>Count</th></tr></thead>
    <tbody>
      ${events.map((e) => `<tr><td>${e.table_name}</td><td>${Number(e.cnt).toLocaleString()}</td></tr>`).join("")}
    </tbody>
  </table>
</div>` : ""}

<div class="section">
  <h2>Top Alert Categories</h2>
  <table>
    <thead><tr><th>Category</th><th>Count</th></tr></thead>
    <tbody>
      ${categories.slice(0, 10).map((c) => `<tr><td>${c.category}</td><td>${Number(c.cnt).toLocaleString()}</td></tr>`).join("")}
    </tbody>
  </table>
</div>

${type === "threat-intel" || type === "technical" ? `
<div class="section">
  <h2>MITRE ATT&CK Mapping</h2>
  <table>
    <thead><tr><th>Technique</th><th>Tactic</th><th>Occurrences</th></tr></thead>
    <tbody>
      ${mitre.map((m) => `<tr><td>${m.technique}</td><td>${m.tactic}</td><td>${Number(m.cnt).toLocaleString()}</td></tr>`).join("")}
    </tbody>
  </table>
</div>` : ""}

<div class="section">
  <h2>Security Alerts</h2>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Category</th><th>Source</th><th>Host</th><th>Description</th></tr></thead>
    <tbody>
      ${alerts.slice(0, type === "executive" ? 10 : 50).map((a) => `
        <tr>
          <td class="mono" style="white-space:nowrap">${a.ts.replace("T", " ").slice(0, 19)}</td>
          <td><span class="sev" style="background:${sevColor(a.severity)}">${SEV_LABEL[Number(a.severity)] ?? a.severity}</span></td>
          <td>${a.category}</td>
          <td>${a.source}</td>
          <td class="mono">${a.hostname}</td>
          <td>${a.description.slice(0, 100)}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>
</div>

${type === "compliance" || type === "incident" ? `
<div class="section">
  <h2>Evidence Chain of Custody</h2>
  <table>
    <thead><tr><th>Batch ID</th><th>Table</th><th>Events</th><th>Merkle Root</th><th>Status</th></tr></thead>
    <tbody>
      ${evidence.slice(0, 30).map((e) => `
        <tr>
          <td class="mono">${e.batch_id}</td>
          <td>${e.table_name}</td>
          <td>${Number(e.event_count).toLocaleString()}</td>
          <td class="mono">${e.merkle_root.slice(0, 16)}…</td>
          <td>${e.status}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>
</div>` : ""}

<div class="footer">
  Report generated by CLIF — Cognitive Log Investigation Framework · ${now}
</div>

</body>
</html>`;
}
