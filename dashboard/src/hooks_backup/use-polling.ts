"use client";

import { useEffect, useState, useCallback, useRef } from "react";

/** Max consecutive errors before backing off to max interval */
const MAX_BACKOFF_ERRORS = 5;
/** Maximum backoff multiplier (interval * 2^5 = 32x) */
const MAX_BACKOFF_MULTIPLIER = 32;
/** Per-request timeout in ms — prevents hanging fetches */
const FETCH_TIMEOUT_MS = 25_000;

/**
 * Production-grade polling hook with:
 * - Exponential backoff on consecutive errors
 * - AbortController cleanup on unmount
 * - Request timeout to prevent hanging
 * - Page visibility awareness (pauses when tab is hidden)
 * - Generation counter to prevent stale-closure overlap
 */
export function usePolling<T>(
  url: string,
  intervalMs: number = 5000,
  enabled: boolean = true,
): { data: T | null; loading: boolean; error: string | null; refresh: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const abortRef = useRef<AbortController | null>(null);
  const errorCountRef = useRef(0);
  /** Generation counter — incremented on each effect to prevent stale closures from scheduling */
  const generationRef = useRef(0);

  const fetchData = useCallback(async () => {
    // Cancel any in-flight request before starting a new one
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // Set a hard timeout on the fetch itself
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      const res = await fetch(url, {
        cache: "no-store",
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      if (mountedRef.current) {
        setData(json);
        setError(null);
        setLoading(false);
        errorCountRef.current = 0; // Reset backoff on success
      }
    } catch (err) {
      // Ignore aborted requests (component unmounted or new request started)
      if (err instanceof DOMException && err.name === "AbortError") return;
      if (mountedRef.current) {
        setError(err instanceof Error ? err.message : "Fetch failed");
        setLoading(false);
        errorCountRef.current = Math.min(
          errorCountRef.current + 1,
          MAX_BACKOFF_ERRORS,
        );
        // IMPORTANT: Do NOT clear data on error — preserve last known good data.
        // This prevents the dashboard from flashing to zeros during transient failures.
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }, [url]);

  useEffect(() => {
    mountedRef.current = true;
    if (!enabled) return;

    // Increment generation to invalidate any prior schedule chains
    const currentGen = ++generationRef.current;

    fetchData();

    // Exponential backoff: on errors, poll slower to reduce pressure
    const getInterval = () => {
      if (errorCountRef.current === 0) return intervalMs;
      const multiplier = Math.min(
        Math.pow(2, errorCountRef.current),
        MAX_BACKOFF_MULTIPLIER,
      );
      return intervalMs * multiplier;
    };

    let timer: ReturnType<typeof setTimeout>;
    const schedule = () => {
      timer = setTimeout(async () => {
        // Bail if this schedule chain is from a stale generation
        if (generationRef.current !== currentGen || !mountedRef.current) return;
        // Pause polling when page is hidden (saves resources)
        if (typeof document !== "undefined" && document.visibilityState === "hidden") {
          schedule(); // Re-check later
          return;
        }
        await fetchData();
        if (mountedRef.current && generationRef.current === currentGen) {
          schedule();
        }
      }, getInterval());
    };
    schedule();

    // Resume polling when tab becomes visible again
    const handleVisibility = () => {
      if (
        document.visibilityState === "visible" &&
        mountedRef.current &&
        generationRef.current === currentGen
      ) {
        fetchData();
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);

    return () => {
      mountedRef.current = false;
      clearTimeout(timer);
      // Cancel in-flight request on unmount — prevents state updates on dead component
      abortRef.current?.abort();
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [fetchData, intervalMs, enabled]);

  return { data, loading, error, refresh: fetchData };
}
