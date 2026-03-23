/**
 * Prometheus query client for the CLIF dashboard.
 *
 * Production-grade features:
 * - Structured logging on failures
 * - Request timeout with AbortController
 * - Input validation for numeric parameters
 * - Retry with jittered backoff on transient errors
 */

import { log } from "./logger";

const PROM_URL = process.env.PROMETHEUS_URL || "http://localhost:9090";
const PROM_TIMEOUT_MS = Number(process.env.PROM_TIMEOUT_MS) || 10_000;
const PROM_MAX_RETRIES = 2;

export interface PromResult {
  metric: Record<string, string>;
  value: [number, string];
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
      headers: { Connection: "keep-alive" },
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function promQuery(query: string): Promise<PromResult[]> {
  for (let attempt = 0; attempt <= PROM_MAX_RETRIES; attempt++) {
    try {
      const url = `${PROM_URL}/api/v1/query?query=${encodeURIComponent(query)}`;
      const res = await fetchWithTimeout(url, PROM_TIMEOUT_MS);
      if (!res.ok) {
        log.warn("Prometheus query returned non-OK status", {
          component: "prometheus",
          status: res.status,
          query: query.slice(0, 120),
        });
        return [];
      }
      const json = await res.json();
      return json?.data?.result ?? [];
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        log.warn("Prometheus query timed out", {
          component: "prometheus",
          timeoutMs: PROM_TIMEOUT_MS,
          query: query.slice(0, 120),
        });
        return [];
      }
      if (attempt < PROM_MAX_RETRIES && err instanceof TypeError) {
        const delay = Math.floor(Math.random() * 200 * Math.pow(2, attempt));
        log.warn("Prometheus network error, retrying", {
          component: "prometheus",
          attempt: attempt + 1,
          error: err instanceof Error ? err.message : "unknown",
        });
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      log.error("Prometheus query failed", {
        component: "prometheus",
        query: query.slice(0, 120),
        error: err instanceof Error ? err.message : "unknown",
      });
      return [];
    }
  }
  return [];
}

export async function promRangeQuery(
  query: string,
  start: number,
  end: number,
  step: number,
): Promise<{ metric: Record<string, string>; values: [number, string][] }[]> {
  // Validate numeric parameters to prevent URL injection
  if (!Number.isFinite(start) || !Number.isFinite(end) || !Number.isFinite(step) || step <= 0) {
    log.error("Invalid promRangeQuery parameters", {
      component: "prometheus",
      start,
      end,
      step,
    });
    return [];
  }

  for (let attempt = 0; attempt <= PROM_MAX_RETRIES; attempt++) {
    try {
      const url = `${PROM_URL}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${step}`;
      const res = await fetchWithTimeout(url, PROM_TIMEOUT_MS);
      if (!res.ok) {
        log.warn("Prometheus range query returned non-OK", {
          component: "prometheus",
          status: res.status,
          query: query.slice(0, 120),
        });
        return [];
      }
      const json = await res.json();
      return json?.data?.result ?? [];
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        log.warn("Prometheus range query timed out", { component: "prometheus", timeoutMs: PROM_TIMEOUT_MS });
        return [];
      }
      if (attempt < PROM_MAX_RETRIES && err instanceof TypeError) {
        const delay = Math.floor(Math.random() * 200 * Math.pow(2, attempt));
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      log.error("Prometheus range query failed", {
        component: "prometheus",
        error: err instanceof Error ? err.message : "unknown",
      });
      return [];
    }
  }
  return [];
}
