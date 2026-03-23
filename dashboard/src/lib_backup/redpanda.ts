/**
 * Redpanda Admin API client for the CLIF dashboard.
 *
 * Production-grade features:
 * - Structured logging on failures (not silent swallowing)
 * - Request timeout with AbortController
 * - Retry with jittered backoff on transient network errors
 * - Path validation to prevent SSRF
 */

import { log } from "./logger";

const RP_URL = process.env.REDPANDA_ADMIN_URL || "http://localhost:9644";
const RP_TIMEOUT_MS = Number(process.env.RP_TIMEOUT_MS) || 5_000;
const RP_MAX_RETRIES = 2;

/** Validate path starts with / and contains no protocol/host (anti-SSRF) */
function isValidPath(path: string): boolean {
  return /^\/[a-zA-Z0-9/_\-?.&=%]*$/.test(path) && path.length < 256;
}

export async function rpGet<T = unknown>(path: string): Promise<T | null> {
  if (!isValidPath(path)) {
    log.error("Invalid Redpanda API path rejected", { component: "redpanda", path: path.slice(0, 64) });
    return null;
  }

  let lastError: unknown = null;

  for (let attempt = 0; attempt <= RP_MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), RP_TIMEOUT_MS);
    try {
      const res = await fetch(`${RP_URL}${path}`, {
        cache: "no-store",
        signal: controller.signal,
        headers: { Connection: "keep-alive" },
      });
      if (!res.ok) {
        log.warn("Redpanda API returned non-OK status", {
          component: "redpanda",
          path,
          status: res.status,
        });
        return null;
      }
      return (await res.json()) as T;
    } catch (err) {
      lastError = err;
      if (err instanceof DOMException && err.name === "AbortError") {
        log.warn("Redpanda API request timed out", {
          component: "redpanda",
          path,
          timeoutMs: RP_TIMEOUT_MS,
        });
        return null;
      }
      // Retry on network errors
      if (attempt < RP_MAX_RETRIES && err instanceof TypeError) {
        const delay = Math.floor(Math.random() * 200 * Math.pow(2, attempt));
        log.warn("Redpanda network error, retrying", {
          component: "redpanda",
          path,
          attempt: attempt + 1,
          error: err instanceof Error ? err.message : "unknown",
        });
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      log.error("Redpanda API request failed", {
        component: "redpanda",
        path,
        error: lastError instanceof Error ? lastError.message : "unknown",
      });
      return null;
    } finally {
      clearTimeout(timeout);
    }
  }
  return null;
}

export async function getClusterHealth() {
  return rpGet<{ is_healthy: boolean }>("/v1/cluster/health_overview");
}

export async function getBrokers() {
  return rpGet<{ node_id: number; is_alive: boolean }[]>("/v1/brokers");
}
