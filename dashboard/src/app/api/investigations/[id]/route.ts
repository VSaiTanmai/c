import { NextRequest, NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { log } from "@/lib/logger";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";

export const dynamic = "force-dynamic";

/**
 * GET /api/investigations/[id] — Full investigation detail from ClickHouse
 *
 * Returns hunter investigation + verifier result + attack graph + timeline.
 * All data is real — sourced from ClickHouse.
 */
export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  const rateLimited = checkRateLimit(getClientId(req), { maxTokens: 30, refillRate: 2 }, "/api/investigations/id");
  if (rateLimited) return rateLimited;

  const id = params.id;

  // Validate UUID format
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return NextResponse.json({ error: "Invalid investigation ID" }, { status: 400 });
  }

  try {
    // Fetch hunter investigation
    const hunterSql = `
      SELECT *
      FROM hunter_investigations
      WHERE investigation_id = {id:UUID}
      LIMIT 1
    `;
    const hunter = await queryClickHouse(hunterSql, { id });

    if (hunter.data.length === 0) {
      return NextResponse.json({ error: "Investigation not found" }, { status: 404 });
    }

    const inv = hunter.data[0] as Record<string, unknown>;

    const alertId = String(inv.alert_id);

    // Fetch verifier result — try by investigation_id first, then by alert_id
    let ver: Record<string, unknown> | null = null;
    const verByInv = await queryClickHouse(
      `SELECT * FROM verifier_results WHERE investigation_id = {id:UUID} ORDER BY started_at DESC LIMIT 1`,
      { id },
    );
    if (verByInv.data.length > 0) {
      ver = verByInv.data[0] as Record<string, unknown>;
    } else {
      const verByAlert = await queryClickHouse(
        `SELECT * FROM verifier_results WHERE alert_id = {alert_id:UUID} ORDER BY started_at DESC LIMIT 1`,
        { alert_id: alertId },
      );
      ver = verByAlert.data.length > 0 ? verByAlert.data[0] as Record<string, unknown> : null;
    }

    // Fetch security_event enrichment — alert_id IS the security_events.event_id
    const secEvent = await queryClickHouse(
      `SELECT * FROM security_events WHERE event_id = {alert_id:UUID} LIMIT 1`,
      { alert_id: alertId },
    );
    const sec = secEvent.data.length > 0 ? secEvent.data[0] as Record<string, unknown> : null;

    // Fetch the original raw log event — use raw_log_event_id from security event
    let raw: Record<string, unknown> | null = null;
    if (sec && sec.raw_log_event_id) {
      const rawLog = await queryClickHouse(
        `SELECT * FROM raw_logs WHERE event_id = {eid:UUID} LIMIT 1`,
        { eid: String(sec.raw_log_event_id) },
      );
      raw = rawLog.data.length > 0 ? rawLog.data[0] as Record<string, unknown> : null;
    }

    // Fetch the original triage score — event_id matches security_events.event_id
    const triage = await queryClickHouse(
      `SELECT * FROM triage_scores WHERE event_id = {alert_id:UUID} LIMIT 1`,
      { alert_id: alertId },
    );
    let tri = triage.data.length > 0 ? triage.data[0] as Record<string, unknown> : null;

    // Fallback: look for triage by hostname + closest adjusted_score to trigger_score
    if (!tri && inv.hostname && inv.trigger_score) {
      const triFallback = await queryClickHouse(
        `SELECT * FROM triage_scores
         WHERE hostname = {host:String}
           AND abs(adjusted_score - {score:Float32}) < 0.01
         ORDER BY abs(adjusted_score - {score2:Float32}) ASC
         LIMIT 1`,
        { host: String(inv.hostname), score: Number(inv.trigger_score), score2: Number(inv.trigger_score) },
      );
      tri = triFallback.data.length > 0 ? triFallback.data[0] as Record<string, unknown> : null;
    }

    // Parse JSON fields safely
    const parseJson = (val: unknown) => {
      if (!val || val === "") return null;
      try { return JSON.parse(String(val)); } catch { return null; }
    };

    // Build timeline from verifier's timeline_json or construct from available data
    let rawTimeline = ver ? parseJson(ver.timeline_json) : null;
    let timeline: Array<{ source: string; timestamp: string; label: string }>;

    if (rawTimeline && Array.isArray(rawTimeline) && rawTimeline.length > 0) {
      // Transform verifier's raw timeline entries into labeled events
      const mapped = (rawTimeline as Array<Record<string, unknown>>).map((evt) => {
        const src = String(evt.source || "unknown");
        const ts = String(evt.timestamp || "");

        // Normalize source names and create meaningful labels
        if (src === "raw_logs") {
          const lvl = String(evt.log_level || "INFO");
          const msg = String(evt.message || "");
          return { source: "raw_log", timestamp: ts, label: `[${lvl}] ${msg.length > 120 ? msg.slice(0, 120) + "…" : msg}` };
        }
        if (src === "triage_scores") {
          const score = Number(evt.adjusted_score || evt.combined_score || 0);
          const action = String(evt.action || "unknown");
          const srcType = String(evt.source_type || "");
          return { source: "triage", timestamp: ts, label: `Score: ${(score * 100).toFixed(1)}% → ${action.toUpperCase()}${srcType ? ` (${srcType})` : ""}` };
        }
        if (src === "hunter_investigations") {
          const fType = String(evt.finding_type || "");
          const conf = Number(evt.confidence || 0);
          return { source: "hunter", timestamp: ts, label: `${fType} (confidence: ${(conf * 100).toFixed(0)}%)` };
        }
        return { source: src, timestamp: ts, label: String(evt.summary || evt.message || evt.label || "") };
      });

      // Group raw_logs by second and keep a sample — too many raw logs flood the page
      const rawLogs = mapped.filter(e => e.source === "raw_log");
      const others = mapped.filter(e => e.source !== "raw_log");

      let condensedRawLogs: typeof mapped;
      if (rawLogs.length > 10) {
        // Group by rounded timestamp (second-level)
        const groups = new Map<string, typeof mapped>();
        for (const r of rawLogs) {
          const key = r.timestamp.slice(0, 19); // YYYY-MM-DD HH:MM:SS
          if (!groups.has(key)) groups.set(key, []);
          groups.get(key)!.push(r);
        }

        condensedRawLogs = [];
        for (const entry of Array.from(groups.entries())) {
          const [ts, group] = entry;
          // Keep first 3 representative events per second, add a summary entry
          condensedRawLogs.push(...group.slice(0, 3));
          if (group.length > 3) {
            condensedRawLogs.push({
              source: "raw_log",
              timestamp: ts,
              label: `... and ${group.length - 3} more raw log events in this second`,
            });
          }
        }
      } else {
        condensedRawLogs = rawLogs;
      }

      // Balanced allocation: hunter/verifier up to 15, triage up to 25, raw up to 10
      const hunterVerifier = others.filter(e => e.source === "hunter" || e.source === "verifier");
      const triageEvents = others.filter(e => e.source === "triage");
      const hvSlice = hunterVerifier.slice(0, 15);
      const triSlice = triageEvents.slice(0, 25);
      const rawSlice = condensedRawLogs.slice(0, 10);

      timeline = [...hvSlice, ...triSlice, ...rawSlice]
        .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    } else {
      // Construct basic timeline from available data
      const events: Array<{ source: string; timestamp: string; label: string }> = [];
      if (tri) {
        events.push({
          source: "triage",
          timestamp: String(tri.timestamp),
          label: `Triage: score=${tri.adjusted_score} action=${tri.action}`,
        });
      }
      events.push({
        source: "hunter",
        timestamp: String(inv.started_at),
        label: `Hunter: ${inv.finding_type} (confidence=${inv.confidence})`,
      });
      if (ver) {
        events.push({
          source: "verifier",
          timestamp: String(ver.started_at),
          label: `Verifier: ${ver.verdict} (confidence=${ver.confidence})`,
        });
      }
      timeline = events;
    }

    // Parse attack graphs
    const hunterEvidence = parseJson(inv.evidence_json);
    const verifierEvidence = ver ? parseJson(ver.evidence_json) : null;
    const iocCorrelations = ver ? parseJson(ver.ioc_correlations) : null;

    // Find relevant Merkle batches for this event's time window
    // Only look for verifiable tables (raw_logs, security_events)
    let merkleBatchIds: string[] = ver?.merkle_batch_ids as string[] || [];
    if (!merkleBatchIds || merkleBatchIds.length === 0) {
      const eventTimestamp = sec ? String(sec.timestamp) : String(inv.started_at);
      const merkleBatches = await queryClickHouse<{ batch_id: string }>(
        `SELECT batch_id FROM evidence_anchors
         WHERE table_name IN ('raw_logs', 'security_events')
           AND time_from <= {ts:String} AND time_to >= {ts2:String}
         ORDER BY created_at DESC LIMIT 5`,
        { ts: eventTimestamp, ts2: eventTimestamp },
      );
      if (merkleBatches.data.length > 0) {
        merkleBatchIds = merkleBatches.data.map(b => b.batch_id);
      }
    }

    return NextResponse.json({
      investigation: {
        investigation_id: inv.investigation_id,
        alert_id: inv.alert_id,
        started_at: inv.started_at,
        completed_at: inv.completed_at,
        status: inv.status,
        hostname: inv.hostname,
        source_ip: inv.source_ip,
        user_id: inv.user_id,
        trigger_score: inv.trigger_score,
        severity: inv.severity,
        finding_type: inv.finding_type,
        summary: inv.summary,
        mitre_tactics: inv.mitre_tactics,
        mitre_techniques: inv.mitre_techniques,
        recommended_action: inv.recommended_action,
        confidence: inv.confidence,
        correlated_events: inv.correlated_events,
      },
      verification: ver
        ? {
            verification_id: ver.verification_id,
            status: ver.status,
            started_at: ver.started_at,
            completed_at: ver.completed_at,
            verdict: ver.verdict,
            confidence: ver.confidence,
            priority: ver.priority,
            analyst_summary: ver.analyst_summary,
            evidence_verified: ver.evidence_verified,
            merkle_batch_ids: merkleBatchIds.length > 0 ? merkleBatchIds : ver.merkle_batch_ids,
            recommended_action: ver.recommended_action,
            report_narrative: ver.report_narrative,
          }
        : null,
      merkle_batch_ids: merkleBatchIds,
      triage: tri,
      raw_log: raw,
      security_event: sec,
      timeline,
      attack_graph: {
        hunter: hunterEvidence?.attack_graph || null,
        verifier: verifierEvidence?.graph || null,
        mermaid: verifierEvidence?.mermaid || hunterEvidence?.attack_graph_mermaid || null,
      },
      evidence: {
        hunter: hunterEvidence,
        verifier: verifierEvidence,
        ioc_correlations: iocCorrelations,
      },
    });
  } catch (e: any) {
    log.error("Investigation detail error", { error: e.message, id, component: "api.investigations" });
    return NextResponse.json({ error: e.message || "Failed to fetch investigation" }, { status: 500 });
  }
}
