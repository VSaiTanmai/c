/**
 * Structured logging for the CLIF dashboard.
 *
 * Production-grade logger with:
 * - Structured JSON output for log aggregation (ELK, Datadog, etc.)
 * - Log levels with environment-aware filtering
 * - Automatic context enrichment (timestamp, service, requestId)
 * - Error sanitization to prevent credential/path leakage
 * - Performance-safe: no-ops for suppressed levels
 */

type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const MIN_LEVEL: LogLevel =
  (process.env.LOG_LEVEL as LogLevel) ??
  (process.env.NODE_ENV === "production" ? "info" : "debug");

/** Redact sensitive values from log payloads */
function redact(value: string): string {
  return value
    .replace(/password=[^\s&]*/gi, "password=***")
    .replace(/user=[^\s&]*/gi, "user=***")
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/g, "Bearer ***")
    .replace(/\/var\/lib\/clickhouse[^\s]*/g, "[internal-path]")
    .replace(
      /Cl1f_Ch@ngeM3_2026!/g,
      "***",
    );
}

interface LogEntry {
  level: LogLevel;
  msg: string;
  service: string;
  ts: string;
  [key: string]: unknown;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[MIN_LEVEL];
}

function emit(level: LogLevel, msg: string, meta?: Record<string, unknown>) {
  if (!shouldLog(level)) return;

  const entry: LogEntry = {
    level,
    msg: redact(msg),
    service: "clif-dashboard",
    ts: new Date().toISOString(),
    ...meta,
  };

  // Sanitize any string values in meta
  for (const [k, v] of Object.entries(entry)) {
    if (typeof v === "string") {
      entry[k] = redact(v);
    }
  }

  const serialized = JSON.stringify(entry);

  switch (level) {
    case "error":
      console.error(serialized);
      break;
    case "warn":
      console.warn(serialized);
      break;
    case "debug":
      console.debug(serialized);
      break;
    default:
      console.log(serialized);
  }
}

export const log = {
  debug: (msg: string, meta?: Record<string, unknown>) => emit("debug", msg, meta),
  info: (msg: string, meta?: Record<string, unknown>) => emit("info", msg, meta),
  warn: (msg: string, meta?: Record<string, unknown>) => emit("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => emit("error", msg, meta),
};
