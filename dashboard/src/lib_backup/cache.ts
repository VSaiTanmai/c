/**
 * In-memory TTL cache with stale-while-revalidate for expensive server-side computations.
 *
 * Used by API routes to avoid re-executing identical ClickHouse queries
 * on every request. Each entry has a fresh TTL and a stale grace window.
 * During the stale window, the cached value is returned immediately while
 * a background refresh is triggered — making subsequent page loads instant.
 *
 * Thread-safe in Node.js single-threaded model. Cache is per-process
 * (does not share across workers/replicas).
 */

interface CacheEntry<T> {
  value: T;
  /** When the entry is considered stale (soft expiry) */
  freshUntil: number;
  /** When the entry must not be served at all (hard expiry = freshUntil + stale grace) */
  expiresAt: number;
}

const store = new Map<string, CacheEntry<unknown>>();

/** In-flight revalidation promises — prevents thundering herd */
const inflight = new Map<string, Promise<unknown>>();

/** Maximum cache entries to prevent unbounded growth */
const MAX_ENTRIES = 512;

/** Default stale grace period — serve stale data for this long while refreshing */
const DEFAULT_STALE_GRACE_MS = 30_000;

/**
 * Get a cached value, or compute and cache it.
 *
 * Stale-while-revalidate: if the entry is past its fresh TTL but within the
 * stale grace window, the stale value is returned immediately and a background
 * refresh is triggered. This makes navigating between pages feel instant after
 * the initial load.
 *
 * @param key       Unique cache key
 * @param ttlMs     Time-to-live in milliseconds (fresh period)
 * @param fn        Async factory function to produce the value on cache miss
 * @param staleMs   Optional stale grace period (default 30s)
 */
export async function cached<T>(
  key: string,
  ttlMs: number,
  fn: () => Promise<T>,
  staleMs: number = DEFAULT_STALE_GRACE_MS,
): Promise<T> {
  const now = Date.now();
  const existing = store.get(key) as CacheEntry<T> | undefined;

  // ── Fresh hit — return immediately ──
  if (existing && existing.freshUntil > now) {
    return existing.value;
  }

  // ── Stale hit — return stale value + trigger background revalidation ──
  if (existing && existing.expiresAt > now) {
    // Only start one background refresh per key
    if (!inflight.has(key)) {
      const revalidation = fn()
        .then((value) => {
          const n = Date.now();
          store.set(key, { value, freshUntil: n + ttlMs, expiresAt: n + ttlMs + staleMs });
        })
        .catch(() => {
          // Silently ignore — stale data continues to be served
        })
        .finally(() => {
          inflight.delete(key);
        });
      inflight.set(key, revalidation);
    }
    return existing.value;
  }

  // ── Cache miss — must compute synchronously ──

  // Evict expired entries lazily when cache is at capacity
  if (store.size >= MAX_ENTRIES) {
    store.forEach((v, k) => {
      if (v.expiresAt <= now) store.delete(k);
    });
    // If still at capacity after eviction, drop oldest entries
    if (store.size >= MAX_ENTRIES) {
      const keysToDelete = Array.from(store.keys()).slice(
        0,
        Math.floor(MAX_ENTRIES / 4),
      );
      keysToDelete.forEach((k) => store.delete(k));
    }
  }

  try {
    const value = await fn();
    store.set(key, { value, freshUntil: now + ttlMs, expiresAt: now + ttlMs + staleMs });
    return value;
  } catch (err) {
    // Stale-while-error: if we have ANY cached value (even expired), return it
    // rather than propagating the error. This prevents the dashboard from
    // flashing to zeros during transient ClickHouse/network failures.
    if (existing) {
      return existing.value;
    }
    throw err;
  }
}

/** Invalidate a specific cache key */
export function invalidate(key: string): void {
  store.delete(key);
}

/** Invalidate all cache entries matching a prefix */
export function invalidatePrefix(prefix: string): void {
  Array.from(store.keys()).forEach((key) => {
    if (key.startsWith(prefix)) store.delete(key);
  });
}

/** Clear all cached data */
export function clearAll(): void {
  store.clear();
}

/**
 * Pre-warm a cache key in the background without blocking.
 * If the key already has a fresh or stale entry, does nothing.
 * Useful for pre-loading adjacent routes (e.g. pre-warm stream cache
 * when dashboard loads, so navigating to live-feed is instant).
 */
export function prewarm<T>(
  key: string,
  ttlMs: number,
  fn: () => Promise<T>,
  staleMs: number = DEFAULT_STALE_GRACE_MS,
): void {
  const existing = store.get(key);
  // Already have data (fresh or stale) — skip
  if (existing && existing.expiresAt > Date.now()) return;
  // Already refreshing — skip
  if (inflight.has(key)) return;

  const warmup = fn()
    .then((value) => {
      const now = Date.now();
      store.set(key, { value, freshUntil: now + ttlMs, expiresAt: now + ttlMs + staleMs });
    })
    .catch(() => {
      // Silent — pre-warm is best-effort
    })
    .finally(() => {
      inflight.delete(key);
    });
  inflight.set(key, warmup);
}
