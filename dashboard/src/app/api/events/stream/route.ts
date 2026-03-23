import { NextResponse } from "next/server";
import { queryClickHouse } from "@/lib/clickhouse";
import { cached } from "@/lib/cache";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

/** Explicit columns per table for single-table queries */
const TABLE_COLUMNS: Record<string, string> = {
  raw_logs:
    "toString(event_id) AS event_id, timestamp, source AS log_source, level, message AS raw, 'raw_logs' AS _table",
  security_events:
    "toString(event_id) AS event_id, timestamp, source AS log_source, severity, category, description AS raw, hostname, mitre_technique, 'security_events' AS _table",
  process_events:
    "toString(event_id) AS event_id, timestamp, hostname, pid, binary_path, arguments AS raw, is_suspicious, 'process_events' AS _table",
  network_events:
    "toString(event_id) AS event_id, timestamp, hostname, IPv4NumToString(src_ip) AS src_ip, IPv4NumToString(dst_ip) AS dst_ip, dst_port, protocol, dns_query, 'network_events' AS _table",
};

/** Columns for the UNION ALL live feed — normalized across all tables */
const UNION_COLS: Record<string, string> = {
  raw_logs:
    "toString(event_id) AS event_id, timestamp, source AS log_source, '' AS hostname, toNullable(toUInt8(0)) AS severity, message AS raw, 'raw_logs' AS _table",
  security_events:
    "toString(event_id) AS event_id, timestamp, source AS log_source, hostname, toNullable(severity) AS severity, description AS raw, 'security_events' AS _table",
  process_events:
    "toString(event_id) AS event_id, timestamp, '' AS log_source, hostname, toNullable(toUInt8(is_suspicious)) AS severity, concat(binary_path, ' ', arguments) AS raw, 'process_events' AS _table",
  network_events:
    "toString(event_id) AS event_id, timestamp, protocol AS log_source, hostname, toNullable(toUInt8(is_suspicious)) AS severity, concat(IPv4NumToString(src_ip), ':', toString(src_port), ' → ', IPv4NumToString(dst_ip), ':', toString(dst_port), ' ', dns_query) AS raw, 'network_events' AS _table",
};

const VALID_TABLES = new Set(Object.keys(TABLE_COLUMNS));
const RATE_LIMIT = { maxTokens: 60, refillRate: 5 };

/** Cache TTL for live stream — 3s keeps it snappy without hammering ClickHouse */
const STREAM_CACHE_TTL_MS = 3_000;
/** Stale grace — serve stale data for 60s during background refresh (instant page nav) */
const STREAM_STALE_MS = 60_000;

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT, "/api/events/stream");
  if (limited) return limited;

  const { searchParams } = new URL(request.url);
  const table = searchParams.get("table") || "all";

  try {
    if (table === "all") {
      const data = await cached(`events:stream:all`, STREAM_CACHE_TTL_MS, async () => {
        // Query each table independently in parallel — faster than one UNION ALL
        // PREWHERE + optimize_read_in_order gives 3-4x speedup on large tables
        const tables = Object.keys(UNION_COLS);
        const results = await Promise.allSettled(
          tables.map((t) =>
            queryClickHouse(
              `SELECT ${UNION_COLS[t]}
               FROM clif_logs.${t}
               PREWHERE timestamp >= now() - INTERVAL 30 DAY
               ORDER BY timestamp DESC
               LIMIT 25
               SETTINGS max_threads = 2, optimize_read_in_order = 1`
            )
          )
        );

        // Merge results from all tables
        const merged: Record<string, unknown>[] = [];
        for (const r of results) {
          if (r.status === "fulfilled" && r.value.data.length > 0) {
            merged.push(...r.value.data);
          }
        }

        // Sort merged results by timestamp descending and take top 100
        merged.sort((a, b) => {
          const ta = String(a.timestamp ?? "");
          const tb = String(b.timestamp ?? "");
          return tb.localeCompare(ta);
        });

        return { data: merged.slice(0, 100) };
      }, STREAM_STALE_MS);
      return NextResponse.json(data);
    }

    if (!VALID_TABLES.has(table)) {
      return NextResponse.json(
        { error: "Invalid table parameter" },
        { status: 400 }
      );
    }

    const columns = TABLE_COLUMNS[table];
    const data = await cached(`events:stream:${table}`, STREAM_CACHE_TTL_MS, async () => {
      const result = await queryClickHouse(
        `SELECT ${columns}
         FROM clif_logs.${table}
         PREWHERE timestamp >= now() - INTERVAL 30 DAY
         ORDER BY timestamp DESC
         LIMIT 100
         SETTINGS max_threads = 2, optimize_read_in_order = 1`
      );
      return { data: result.data };
    }, STREAM_STALE_MS);
    return NextResponse.json(data);
  } catch (err) {
    log.error("Event stream failed", { table, error: err instanceof Error ? err.message : "unknown", component: "api/events/stream" });
    return NextResponse.json(
      { error: "Failed to fetch event stream" },
      { status: 500 }
    );
  }
}
