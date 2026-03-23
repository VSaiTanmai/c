/**
 * Token-bucket rate limiter for API routes.
 *
 * Provides per-IP rate limiting with configurable burst and refill rates.
 * Uses an in-memory store (per-process). For multi-replica deployments,
 * replace with Redis-backed implementation.
 *
 * Features:
 * - Fixed-window token bucket algorithm
 * - Automatic cleanup of expired entries to prevent memory leaks
 * - Configurable per-route limits
 * - Returns standard rate-limit headers (X-RateLimit-*)
 */

import { NextResponse } from "next/server";

interface Bucket {
  tokens: number;
  lastRefill: number;
}

const buckets = new Map<string, Bucket>();

/** Cleanup interval — remove expired buckets every 60s */
const CLEANUP_INTERVAL_MS = 60_000;
/** Buckets expire after 10 minutes of inactivity */
const BUCKET_TTL_MS = 600_000;

let cleanupTimer: ReturnType<typeof setInterval> | null = null;

function ensureCleanup() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    const cutoff = Date.now() - BUCKET_TTL_MS;
    buckets.forEach((bucket, key) => {
      if (bucket.lastRefill < cutoff) buckets.delete(key);
    });
  }, CLEANUP_INTERVAL_MS);
  // Allow process to exit without waiting for timer
  if (cleanupTimer && typeof cleanupTimer === "object" && "unref" in cleanupTimer) {
    cleanupTimer.unref();
  }
}

export interface RateLimitConfig {
  /** Maximum tokens (burst capacity) */
  maxTokens: number;
  /** Tokens refilled per second */
  refillRate: number;
}

/** Default: 60 requests/min with burst of 20 */
const DEFAULT_CONFIG: RateLimitConfig = {
  maxTokens: 20,
  refillRate: 1, // 1 token/sec = 60/min
};

/**
 * Check rate limit for a given client identifier.
 *
 * @param routePath Optional route path to scope rate limiting per-route per-client
 * @returns null if allowed, or a NextResponse with 429 status if rate-limited
 */
export function checkRateLimit(
  clientId: string,
  config: RateLimitConfig = DEFAULT_CONFIG,
  routePath?: string,
): NextResponse | null {
  ensureCleanup();

  const now = Date.now();
  // Key by clientId + route to prevent cross-route bucket interference
  const bucketKey = routePath ? `${clientId}::${routePath}` : clientId;
  let bucket = buckets.get(bucketKey);

  if (!bucket) {
    bucket = { tokens: config.maxTokens, lastRefill: now };
    buckets.set(bucketKey, bucket);
  }

  // Refill tokens based on elapsed time
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(
    config.maxTokens,
    bucket.tokens + elapsed * config.refillRate,
  );
  bucket.lastRefill = now;

  if (bucket.tokens < 1) {
    const retryAfter = Math.ceil((1 - bucket.tokens) / config.refillRate);
    return NextResponse.json(
      { error: "Too many requests. Please retry later." },
      {
        status: 429,
        headers: {
          "Retry-After": String(retryAfter),
          "X-RateLimit-Limit": String(config.maxTokens),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(Math.ceil(now / 1000) + retryAfter),
        },
      },
    );
  }

  bucket.tokens -= 1;
  return null; // Allowed
}

/**
 * Extract client IP from request headers (works behind reverse proxies).
 * Falls back to "unknown" if no identifiable header is found.
 */
export function getClientId(request: Request): string {
  const forwarded = request.headers.get("x-forwarded-for");
  if (forwarded) return forwarded.split(",")[0].trim();
  const real = request.headers.get("x-real-ip");
  if (real) return real;
  return "unknown";
}
