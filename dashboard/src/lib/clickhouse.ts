/**
 * ClickHouse HTTP interface client for the CLIF dashboard.
 *
 * Production-grade features:
 * - Environment-driven configuration (no hardcoded credentials)
 * - Exponential backoff with jitter on transient failures
 * - Client-side AbortController + server-side max_execution_time timeout
 * - Credential sanitization in error messages
 * - Structured logging on all retry/error/slow-query paths
 * - Keep-alive headers for connection reuse
 * - Query result size safety limits
 * - Table name allowlist to prevent SQL injection
 */

import { log } from "./logger";

// ─── Configuration ──────────────────────────────────────────────────────────────

const CH_HOST = process.env.CH_HOST || "localhost";
const CH_PORT = process.env.CH_PORT || "8123";
const CH_USER = process.env.CH_USER || "default";
const CH_PASSWORD = process.env.CH_PASSWORD || "";
const CH_DB = process.env.CH_DB || "clif_logs";

/** Query timeout in ms — prevents runaway ClickHouse queries */
const CH_QUERY_TIMEOUT_MS = Number(process.env.CH_QUERY_TIMEOUT_MS) || 30_000;
/** Max retry attempts on transient failures */
const CH_MAX_RETRIES = Number(process.env.CH_MAX_RETRIES) || 3;
/** Base backoff delay in ms (jittered exponential) */
const CH_RETRY_BASE_MS = 200;
/** Maximum rows to accept in a single response (safety limit) */
const CH_MAX_RESULT_ROWS = Number(process.env.CH_MAX_RESULT_ROWS) || 100_000;

// ─── Circuit Breaker ────────────────────────────────────────────────────────────
// After a network failure, skip all queries for a cooldown period to prevent
// log floods and wasted resources when ClickHouse is entirely unreachable.

/** Cooldown period in ms after circuit opens (default 10s) */
const CH_CIRCUIT_COOLDOWN_MS = Number(process.env.CH_CIRCUIT_COOLDOWN_MS) || 10_000;
/** Number of consecutive failures to trip the circuit */
const CH_CIRCUIT_THRESHOLD = Number(process.env.CH_CIRCUIT_THRESHOLD) || 3;

let circuitFailures = 0;
let circuitOpenUntil = 0;
let circuitLoggedAt = 0;

function circuitIsOpen(): boolean {
  if (circuitOpenUntil === 0) return false;
  if (Date.now() >= circuitOpenUntil) {
    // Half-open: allow one probe to see if ClickHouse is back
    circuitOpenUntil = 0;
    circuitFailures = 0;
    log.info("ClickHouse circuit breaker half-open, probing", {
      component: "clickhouse",
    });
    return false;
  }
  return true;
}

function circuitRecordFailure(): void {
  circuitFailures++;
  if (circuitFailures >= CH_CIRCUIT_THRESHOLD) {
    circuitOpenUntil = Date.now() + CH_CIRCUIT_COOLDOWN_MS;
    // Log the circuit trip at most once per cooldown
    const now = Date.now();
    if (now - circuitLoggedAt > CH_CIRCUIT_COOLDOWN_MS) {
      circuitLoggedAt = now;
      log.warn("ClickHouse circuit breaker OPEN — suppressing queries", {
        component: "clickhouse",
        cooldownMs: CH_CIRCUIT_COOLDOWN_MS,
        consecutiveFailures: circuitFailures,
      });
    }
  }
}

function circuitRecordSuccess(): void {
  if (circuitFailures > 0) {
    log.info("ClickHouse circuit breaker reset — connection restored", {
      component: "clickhouse",
    });
  }
  circuitFailures = 0;
  circuitOpenUntil = 0;
}

// ─── Startup validation ─────────────────────────────────────────────────────────

if (!process.env.CH_PASSWORD && process.env.NODE_ENV === "production") {
  log.warn("CH_PASSWORD environment variable is not set", {
    component: "clickhouse",
  });
}

export interface CHResult<T = Record<string, unknown>> {
  data: T[];
  rows: number;
  statistics?: { elapsed: number; rows_read: number; bytes_read: number };
}

/** Transient error codes worth retrying (ClickHouse-specific + network) */
const RETRIABLE_STATUS_CODES = new Set([502, 503, 504, 408, 429]);

function isRetriable(status: number, body: string): boolean {
  if (RETRIABLE_STATUS_CODES.has(status)) return true;
  // ClickHouse returns 500 for some transient resource-pressure errors
  if (status === 500 && /CANNOT_SCHEDULE_TASK|TOO_MANY_SIMULTANEOUS_QUERIES|MEMORY_LIMIT_EXCEEDED/.test(body)) return true;
  return false;
}

/** Sanitize ClickHouse error messages — strip credentials and internal paths */
function sanitizeError(raw: string): string {
  return raw
    .replace(/password=[^\s&]*/gi, "password=***")
    .replace(/user=[^\s&]*/gi, "user=***")
    .replace(/\/var\/lib\/clickhouse[^\s]*/g, "[internal-path]")
    .replace(/X-ClickHouse-Key:\s*\S+/gi, "X-ClickHouse-Key: ***")
    .slice(0, 500);
}

/** Jittered exponential backoff (full jitter): prevents thundering herd */
function backoffMs(attempt: number): number {
  const maxDelay = CH_RETRY_BASE_MS * Math.pow(2, attempt);
  return Math.floor(Math.random() * maxDelay);
}

export async function queryClickHouse<T = Record<string, unknown>>(
  sql: string,
  params?: Record<string, string | number>,
): Promise<CHResult<T>> {
  // Circuit breaker: fast-fail when ClickHouse is known to be down
  if (circuitIsOpen()) {
    throw new Error("ClickHouse circuit breaker is open — service unavailable");
  }

  const url = new URL(`http://${CH_HOST}:${CH_PORT}/`);
  url.searchParams.set("database", CH_DB);
  url.searchParams.set("default_format", "JSON");
  url.searchParams.set("max_execution_time", String(Math.ceil(CH_QUERY_TIMEOUT_MS / 1000)));
  url.searchParams.set("max_result_rows", String(CH_MAX_RESULT_ROWS));

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.set(`param_${key}`, String(value));
    }
  }

  let lastError: Error | null = null;
  const queryStart = Date.now();

  for (let attempt = 0; attempt <= CH_MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CH_QUERY_TIMEOUT_MS);

    try {
      const res = await fetch(url.toString(), {
        method: "POST",
        body: sql,
        headers: {
          "Content-Type": "text/plain",
          "X-ClickHouse-User": CH_USER,
          "X-ClickHouse-Key": CH_PASSWORD,
          Connection: "keep-alive",
        },
        signal: controller.signal,
        cache: "no-store",
      });

      if (!res.ok) {
        const text = await res.text();
        if (attempt < CH_MAX_RETRIES && isRetriable(res.status, text)) {
          circuitRecordFailure();
          if (circuitIsOpen()) {
            throw new Error("ClickHouse circuit breaker is open — service unavailable");
          }
          const delay = backoffMs(attempt);
          lastError = new Error(`ClickHouse HTTP ${res.status}`);
          log.warn("ClickHouse transient error, retrying", {
            component: "clickhouse",
            status: res.status,
            attempt: attempt + 1,
            maxRetries: CH_MAX_RETRIES,
            backoffMs: delay,
            query: sql.slice(0, 120),
          });
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        const sanitized = sanitizeError(text);
        log.error("ClickHouse query failed", {
          component: "clickhouse",
          status: res.status,
          error: sanitized,
          query: sql.slice(0, 200),
          elapsedMs: Date.now() - queryStart,
        });
        throw new Error(`ClickHouse error (HTTP ${res.status}): ${sanitized}`);
      }

      const json = await res.json();
      const result: CHResult<T> = {
        data: json.data ?? [],
        rows: json.rows ?? 0,
        statistics: json.statistics,
      };

      // Log slow queries (>5s) for performance monitoring
      const elapsed = Date.now() - queryStart;
      if (elapsed > 5000) {
        log.warn("Slow ClickHouse query", {
          component: "clickhouse",
          elapsedMs: elapsed,
          rowsRead: json.statistics?.rows_read,
          bytesRead: json.statistics?.bytes_read,
          query: sql.slice(0, 200),
        });
      }

      circuitRecordSuccess();
      return result;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        log.error("ClickHouse query timed out", {
          component: "clickhouse",
          timeoutMs: CH_QUERY_TIMEOUT_MS,
          query: sql.slice(0, 200),
        });
        throw new Error(`ClickHouse query timed out after ${CH_QUERY_TIMEOUT_MS}ms`);
      }
      if (attempt < CH_MAX_RETRIES && err instanceof TypeError) {
        circuitRecordFailure();
        // If circuit just opened, bail out immediately instead of retrying
        if (circuitIsOpen()) {
          throw new Error("ClickHouse circuit breaker is open — service unavailable");
        }
        const delay = backoffMs(attempt);
        lastError = err;
        log.warn("ClickHouse network error, retrying", {
          component: "clickhouse",
          error: err.message,
          attempt: attempt + 1,
          backoffMs: delay,
        });
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  circuitRecordFailure();
  log.error("ClickHouse query failed after max retries", {
    component: "clickhouse",
    retries: CH_MAX_RETRIES,
    query: sql.slice(0, 200),
  });
  throw lastError ?? new Error("ClickHouse query failed after max retries");
}

// ─── Table name safety ──────────────────────────────────────────────────────────

/** Allowlist of valid table names — prevents SQL injection via table interpolation */
const VALID_TABLES = new Set([
  "raw_logs",
  "security_events",
  "process_events",
  "network_events",
  "evidence_anchors",
  "events_per_minute",
  "security_severity_hourly",
  "triage_scores",
  "hunter_investigations",
  "verifier_results",
  "pipeline_metrics",
  "feedback_labels",
  "report_history",
  "sigma_rules",
  "triage_score_rollup",
  "arf_replay_buffer",
  "hunter_training_data",
  "entity_baselines",
  "sigma_rule_hits",
  "hunter_model_health",
  "asset_criticality",
  "mitre_mapping_rules",
  "features_entity_freq",
  "features_template_rarity",
  "features_entity_baseline",
]);

/**
 * Validate a table name against the allowlist.
 * @throws Error if the table name is not in the allowlist
 */
export function assertValidTable(table: string): asserts table is string {
  if (!VALID_TABLES.has(table)) {
    throw new Error(`Invalid table name: ${table.slice(0, 64)}`);
  }
}
