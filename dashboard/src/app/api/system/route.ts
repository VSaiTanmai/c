import { NextResponse } from "next/server";
import { rpGet } from "@/lib/redpanda";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";
import { cached } from "@/lib/cache";
import { log } from "@/lib/logger";

export const dynamic = "force-dynamic";

const CH_HOST = process.env.CH_HOST || "localhost";
const CH_PORT = process.env.CH_PORT || "8123";
const PROM_URL = process.env.PROMETHEUS_URL || "http://localhost:9090";
const PROM_TIMEOUT_MS = 8_000;

const RATE_LIMIT = { maxTokens: 20, refillRate: 1 };

async function fetchProm(query: string) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROM_TIMEOUT_MS);
  try {
    const url = `${PROM_URL}/api/v1/query?query=${encodeURIComponent(query)}`;
    const res = await fetch(url, {
      cache: "no-store",
      signal: controller.signal,
      headers: { Connection: "keep-alive" },
    });
    if (!res.ok) {
      log.warn("Prometheus query failed", { query, status: res.status, component: "api/system" });
      return null;
    }
    const json = await res.json();
    return json.data?.result ?? [];
  } catch (err) {
    log.warn("Prometheus query error", { query, error: err instanceof Error ? err.message : "unknown", component: "api/system" });
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function checkHealth(url: string, timeout = 3000): Promise<boolean> {
  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    const res = await fetch(url, {
      signal: controller.signal,
      cache: "no-store",
      headers: { Connection: "keep-alive" },
    });
    clearTimeout(id);
    return res.ok;
  } catch {
    return false;
  }
}

export async function GET(request: Request) {
  const limited = checkRateLimit(getClientId(request), RATE_LIMIT);
  if (limited) return limited;

  try {
    const data = await cached("system:health", 10_000, async () => {
      const [upTargets, chInserted, rpBrokers, ch01Health, ch02Health, rpBrokersAdmin, rpTopics, rpClusterHealth] = await Promise.allSettled([
        fetchProm('up'),
        fetchProm('ClickHouseProfileEvents_InsertedRows'),
        fetchProm('redpanda_cluster_brokers'),
        checkHealth(`http://${CH_HOST}:${CH_PORT}/ping`),
        checkHealth(`http://${CH_HOST}:8124/ping`),
        rpGet<{ node_id: number; num_cores: number; membership_status: string; is_alive?: boolean; disk_space?: Array<{ free: number; total: number; path: string }> }[]>("/v1/brokers"),
        rpGet<{ ns: string; topic: string; partition_id: number }[]>("/v1/partitions"),
        rpGet<{ is_healthy: boolean; controller_id: number }>("/v1/cluster/health_overview"),
      ]);

      const services: Array<{
        name: string;
        status: string;
        metric?: string;
      }> = [];

      // Parse up targets from Prometheus
      if (upTargets.status === "fulfilled" && upTargets.value) {
        for (const target of upTargets.value) {
          const instance = target.metric?.instance || "";
          // Skip clickhouse exporter targets (9363) — we check CH directly below
          if (instance.includes("9363")) continue;
          services.push({
            name: target.metric?.job || instance || "Unknown",
            status: target.value?.[1] === "1" ? "Healthy" : "Down",
            metric: instance,
          });
        }
      }

      // Add ClickHouse nodes with direct health check
      services.push({
        name: "ClickHouse",
        status: ch01Health.status === "fulfilled" && ch01Health.value ? "Healthy" : "Down",
        metric: `clickhouse01:${CH_PORT}`,
      });
      services.push({
        name: "ClickHouse",
        status: ch02Health.status === "fulfilled" && ch02Health.value ? "Healthy" : "Down",
        metric: "clickhouse02:8124",
      });

      // Build Redpanda live detail from Admin API
      const brokersData = rpBrokersAdmin.status === "fulfilled" ? rpBrokersAdmin.value : null;
      const partitionsData = rpTopics.status === "fulfilled" ? rpTopics.value : null;
      const clusterData = rpClusterHealth.status === "fulfilled" ? rpClusterHealth.value : null;

      // Derive topics from partitions list
      const topicMap = new Map<string, number>();
      if (partitionsData) {
        for (const p of partitionsData) {
          if (p.ns === "kafka") topicMap.set(p.topic, (topicMap.get(p.topic) ?? 0) + 1);
        }
      }
      const totalPartitions = partitionsData ? partitionsData.filter(p => p.ns === "kafka").length : null;
      const topicNames = topicMap.size > 0
        ? Array.from(topicMap.keys()).filter((n: string) => !n.startsWith("_"))
        : null;

      return {
        services,
        clickhouseInserted:
          chInserted.status === "fulfilled" ? chInserted.value?.[0]?.value?.[1] : null,
        redpandaBrokers:
          rpBrokers.status === "fulfilled" ? rpBrokers.value?.[0]?.value?.[1] : null,
        redpanda: {
          brokers: brokersData ? brokersData.length : null,
          brokerDetails: brokersData
            ? brokersData.map((b: { node_id: number; num_cores: number; membership_status: string; is_alive?: boolean }) => ({
                nodeId: b.node_id,
                cores: b.num_cores,
                status: b.membership_status,
                alive: b.is_alive ?? true,
              }))
            : null,
          totalPartitions,
          topics: topicNames,
          isHealthy: clusterData?.is_healthy ?? null,
          controllerId: clusterData?.controller_id ?? null,
        },
      };
    });

    return NextResponse.json(data);
  } catch (err) {
    log.error("System health fetch failed", { error: err instanceof Error ? err.message : "unknown", component: "api/system" });
    return NextResponse.json(
      { error: "Failed to fetch system health" },
      { status: 500 }
    );
  }
}
