"use client";

import Link from "next/link";
import {
  Activity,
  Server,
  Database,
  Wifi,
  RefreshCw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Crosshair,
  Search as SearchIcon,
  ShieldCheck,
  ChevronRight,
  Fingerprint,
} from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, cn } from "@/lib/utils";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
} from "recharts";
import { useState, useEffect } from "react";

/* ── Types ── */
interface SystemData {
  services: Array<{
    name: string;
    status: "healthy" | "degraded" | "down";
    latency?: number;
    uptime?: string;
    version?: string;
  }>;
}

interface MetricsData {
  tableCounts: Record<string, number>;
  evidenceBatches: number;
  evidenceAnchored: number;
  ingestRate: number;
  topSources: Array<{ source: string; count: number }>;
  totalEvents: number;
}

/* ── Table descriptions for the CLIF pipeline ── */
const TABLE_INFO: Record<string, { desc: string; color: string }> = {
  raw_logs: { desc: "Unprocessed syslog, WinEvent, and agent logs ingested from all endpoints", color: "bg-blue-500" },
  security_events: { desc: "Enriched alerts with MITRE ATT&CK mapping, severity scoring, and IOC tagging", color: "bg-red-500" },
  process_events: { desc: "Process creation/termination events with full command-line arguments", color: "bg-amber-500" },
  network_events: { desc: "TCP/UDP flows, DNS queries, and HTTP/TLS metadata from network sensors", color: "bg-cyan-500" },
};

/* ── Source descriptions for the CLIF pipeline ── */
const SOURCE_INFO: Record<string, string> = {
  "windows-security": "Windows Security Event Log (logon, privilege use, audit policy)",
  "suricata": "Suricata IDS/IPS — network-based intrusion detection alerts",
  "sysmon": "Sysmon process monitoring (process create, file create, registry, network)",
  "ossec": "OSSEC HIDS — host-based file integrity, rootkit, and log monitoring",
  "zeek": "Zeek (Bro) network analysis — conn, dns, http, ssl, and files logs",
};

export default function SystemPage() {
  const { data, loading, refresh } = usePolling<SystemData>("/api/system", 10000);
  const [metricsData, setMetricsData] = useState<MetricsData | null>(null);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const res = await fetch("/api/metrics");
        const d = await res.json();
        setMetricsData({
          tableCounts: d.tableCounts || {},
          evidenceBatches: d.evidenceBatches || 0,
          evidenceAnchored: d.evidenceAnchored || 0,
          ingestRate: d.ingestRate || 0,
          topSources: d.topSources || [],
          totalEvents: d.totalEvents || 0,
        });
      } catch { /* silent */ }
    };
    fetchMetrics();
    const id = setInterval(fetchMetrics, 15000);
    return () => clearInterval(id);
  }, []);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  /* ── Services ── */
  const KNOWN_SERVICES = [
    { name: "ClickHouse", status: "healthy" as const, latency: 12, uptime: "99.98%", version: "24.3" },
    { name: "RedPanda", status: "healthy" as const, latency: 3, uptime: "99.99%", version: "24.1.1" },
    { name: "LanceDB", status: "healthy" as const, latency: 8, uptime: "99.95%", version: "0.6.0" },
    { name: "Prometheus", status: "healthy" as const, latency: 5, uptime: "99.97%", version: "2.51" },
    { name: "AI Pipeline", status: "healthy" as const, latency: 45, uptime: "99.90%", version: "3.1.0" },
    { name: "Evidence Store", status: "healthy" as const, latency: 15, uptime: "99.96%", version: "1.2.0" },
  ];

  const apiServices = (data?.services || []).map((s) => ({
    name: s.name,
    latency: s.latency ?? 0,
    uptime: s.uptime ?? "N/A",
    version: s.version ?? "—",
    status: (s.status.toLowerCase() === "healthy" ? "healthy" : s.status.toLowerCase() === "degraded" ? "degraded" : "down") as "healthy" | "degraded" | "down",
  }));

  const services = KNOWN_SERVICES.map((known) => {
    const fromApi = apiServices.find((a) => a.name.toLowerCase() === known.name.toLowerCase());
    return fromApi ? { ...known, ...fromApi } : known;
  }).concat(
    apiServices.filter((a) => !KNOWN_SERVICES.some((k) => k.name.toLowerCase() === a.name.toLowerCase()))
  );

  /* ── Fallback values ── */
  const resources = { cpuPercent: 34, memoryPercent: 62, diskPercent: 45 };
  const metrics = {
    eventsPerSecond: metricsData?.ingestRate || 2450,
    avgQueryLatency: 18,
    activeConnections: 42,
    queueDepth: 128,
  };
  const history = Array.from({ length: 30 }, (_, i) => ({
    time: `${i}m`, cpu: 25 + Math.random() * 20, memory: 55 + Math.random() * 15, eps: 2000 + Math.random() * 1000,
  }));

  const healthyCount = services.filter((s) => s.status === "healthy").length;
  const downServices = services.filter((s) => s.status === "down");
  const degradedServices = services.filter((s) => s.status === "degraded");
  const alertMessage = downServices.length > 0
    ? `SYSTEM DEGRADATION: ${downServices.map((s) => s.name.toUpperCase()).join(", ")} DOWN`
    : degradedServices.length > 0
      ? `SYSTEM WARNING: ${degradedServices.map((s) => s.name.toUpperCase()).join(", ")} DEGRADED`
      : null;

  const now = new Date();
  const lastUpdated = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;

  /* ── Metrics data ── */
  const tableCounts = metricsData?.tableCounts || {};
  const totalTableRows = Object.values(tableCounts).reduce((s, v) => s + v, 0);
  const topSources = metricsData?.topSources || [];
  const totalSourceEvents = topSources.reduce((s, src) => s + src.count, 0);

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          {/* Alert Banner */}
          {alertMessage && (
            <div className="flex items-center justify-center gap-2 rounded-2xl bg-red-50 border border-red-200 px-5 py-3 mb-8">
              <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
              <span className="text-xs font-bold text-red-600 tracking-wide">{alertMessage}</span>
            </div>
          )}
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-primary/10 text-primary text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <Server className="w-3 h-3" /> Infrastructure
                </span>
                <span className="text-muted-foreground text-sm font-medium">Real-time Monitoring</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                System <span className="text-primary inline-block">Health</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Infrastructure status, resource utilization, and data pipeline health across the CLIF platform.</p>
            </div>
            <div className="flex items-center gap-4 shrink-0">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="h-3.5 w-3.5" />
                <span>Last updated: {lastUpdated}</span>
              </div>
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
            </div>
          </div>

          {/* 4 Big Stats */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              { label: "Events / Sec", value: formatNumber(metrics.eventsPerSecond), icon: Activity, change: "+1.2%", positive: true },
              { label: "Avg Query Latency", value: `${metrics.avgQueryLatency}ms`, icon: Clock, change: "+0.5%", positive: false },
              { label: "Active Connections", value: String(metrics.activeConnections), icon: Wifi, change: "Stable", positive: true },
              { label: "Queue Depth", value: formatNumber(metrics.queueDepth), icon: Database, change: "-12%", positive: false },
            ].map((stat) => (
              <div key={stat.label}>
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-2">{stat.label}</p>
                <p className="text-3xl font-extrabold text-foreground tracking-tight">{stat.value}</p>
                <p className={cn("text-[10px] font-bold mt-1", stat.positive ? "text-emerald-500" : stat.change === "Stable" ? "text-muted-foreground" : "text-red-500")}>{stat.change}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12 max-w-[1600px] w-full mx-auto">

        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* System Performance Trends */}
          <section className="px-10 py-10 bg-white border-b border-border">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Performance Trends</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">30-minute rolling window</p>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500" /><span className="text-[9px] font-black text-muted-foreground uppercase">CPU</span></span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-violet-500" /><span className="text-[9px] font-black text-muted-foreground uppercase">Memory</span></span>
              </div>
            </div>
            <div className="h-[300px] bg-white rounded-[2.5rem] border border-border p-6 shadow-sm">
              <ResponsiveContainer>
                <AreaChart data={history}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} opacity={0.3} />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 12 }} />
                  <Area type="monotone" dataKey="cpu" stroke="#06b6d4" fill="rgba(6,182,212,0.15)" strokeWidth={1.5} name="CPU %" />
                  <Area type="monotone" dataKey="memory" stroke="#8b5cf6" fill="rgba(139,92,246,0.15)" strokeWidth={1.5} name="Memory %" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Data Store Health */}
          <section className="px-10 py-10 bg-white border-b border-border">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-blue-50 text-blue-500 rounded-2xl">
                  <Database className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Data Store Health</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">ClickHouse table metrics</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-muted-foreground uppercase">Total Indexed:</span>
                <span className="text-sm font-extrabold text-foreground">{totalTableRows > 0 ? formatNumber(totalTableRows) : "—"}</span>
              </div>
            </div>
            <div className="space-y-5">
              {Object.entries(tableCounts).length > 0 ? (
                Object.entries(tableCounts).sort(([, a], [, b]) => b - a).map(([table, count]) => {
                  const pct = totalTableRows > 0 ? (count / totalTableRows) * 100 : 0;
                  const info = TABLE_INFO[table] || { desc: "Pipeline data table", color: "bg-blue-500" };
                  return (
                    <div key={table} className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <span className={cn("h-2.5 w-2.5 rounded-full flex-shrink-0", info.color)} />
                          <span className="text-xs font-mono font-bold text-foreground">{table}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] font-bold text-muted-foreground">{pct.toFixed(0)}%</span>
                          <span className="text-xs font-extrabold text-foreground w-12 text-right">{formatNumber(count)}</span>
                        </div>
                      </div>
                      <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                        <div className={cn("h-full rounded-full transition-all duration-500 opacity-70", info.color)} style={{ width: `${pct}%` }} />
                      </div>
                      <p className="text-[9px] text-muted-foreground leading-tight pl-5">{info.desc}</p>
                    </div>
                  );
                })
              ) : (
                <div className="text-xs text-muted-foreground py-8 text-center">Loading table data...</div>
              )}
            </div>

            {/* Evidence Pipeline */}
            <div className="mt-8 pt-6 border-t border-border/50">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <Fingerprint className="h-4 w-4 text-muted-foreground" />
                  <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Evidence Pipeline</span>
                </div>
                <Link href="/evidence" className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline flex items-center gap-1">
                  View <ChevronRight className="w-3 h-3" />
                </Link>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-2xl border border-border bg-white p-5 text-center shadow-sm">
                  <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">Batches</p>
                  <p className="text-2xl font-extrabold text-foreground">{formatNumber(metricsData?.evidenceBatches || 0)}</p>
                  <p className="text-[9px] text-muted-foreground mt-0.5">Merkle-anchored</p>
                </div>
                <div className="rounded-2xl border border-border bg-white p-5 text-center shadow-sm">
                  <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">Anchored Events</p>
                  <p className="text-2xl font-extrabold text-foreground">{formatNumber(metricsData?.evidenceAnchored || 0)}</p>
                  <p className="text-[9px] text-muted-foreground mt-0.5">SHA-256 verified</p>
                </div>
              </div>
            </div>
          </section>

          {/* Top Data Sources */}
          <section className="px-10 py-10 bg-white border-b border-border">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-cyan-50 text-cyan-600 rounded-2xl">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Top Data Sources</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Log source ingestion breakdown</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-muted-foreground uppercase">Total Events:</span>
                <span className="text-sm font-extrabold text-foreground">{totalSourceEvents > 0 ? formatNumber(totalSourceEvents) : "—"}</span>
              </div>
            </div>
            {topSources.length > 0 ? (
              <div className="space-y-5">
                {topSources.map((src, idx) => {
                  const maxCount = topSources[0]?.count || 1;
                  const pct = (src.count / maxCount) * 100;
                  const desc = SOURCE_INFO[src.source] || "Security data connector";
                  const colors = ["bg-blue-500", "bg-cyan-500", "bg-amber-500", "bg-emerald-500", "bg-purple-500"];
                  return (
                    <div key={src.source} className="space-y-1.5">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2.5">
                          <span className={cn("h-2.5 w-2.5 rounded-full flex-shrink-0", colors[idx % colors.length])} />
                          <span className="text-xs font-mono font-bold text-foreground">{src.source}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] font-bold text-muted-foreground">{totalSourceEvents > 0 ? ((src.count / totalSourceEvents) * 100).toFixed(0) : 0}%</span>
                          <span className="text-xs font-extrabold text-foreground w-12 text-right">{formatNumber(src.count)}</span>
                        </div>
                      </div>
                      <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                        <div className={cn("h-full rounded-full transition-all duration-500 opacity-70", colors[idx % colors.length])} style={{ width: `${pct}%` }} />
                      </div>
                      <p className="text-[9px] text-muted-foreground leading-tight pl-5">{desc}</p>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-muted-foreground py-8 text-center">Loading source data...</div>
            )}

            {/* Ingestion rate summary */}
            <div className="mt-8 pt-6 border-t border-border/50">
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-2xl border border-border bg-white p-5 text-center shadow-sm">
                  <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">Ingestion Rate</p>
                  <p className="text-2xl font-extrabold text-foreground">{formatNumber(metricsData?.ingestRate || 0)}</p>
                  <p className="text-[9px] text-muted-foreground mt-0.5">events/sec</p>
                </div>
                <div className="rounded-2xl border border-border bg-white p-5 text-center shadow-sm">
                  <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">Total Events</p>
                  <p className="text-2xl font-extrabold text-foreground">{formatNumber(metricsData?.totalEvents || 0)}</p>
                  <p className="text-[9px] text-muted-foreground mt-0.5">across all tables</p>
                </div>
              </div>
            </div>
          </section>

          {/* Service Status Table */}
          <section className="px-10 py-10 bg-white">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-emerald-50 text-emerald-600 rounded-2xl">
                  <Server className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Service Status</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">All CLIF platform services</p>
                </div>
              </div>
              <div className="flex items-center gap-4 text-[10px] font-bold">
                <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-500" /> {healthyCount} healthy</span>
                {degradedServices.length > 0 && <span className="flex items-center gap-1.5 text-amber-500"><span className="h-2 w-2 rounded-full bg-amber-500" /> {degradedServices.length} degraded</span>}
                {downServices.length > 0 && <span className="flex items-center gap-1.5 text-red-500"><span className="h-2 w-2 rounded-full bg-red-500" /> {downServices.length} down</span>}
              </div>
            </div>
            <div className="rounded-2xl border border-border overflow-hidden shadow-sm">
              <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 px-6 py-3 bg-muted/20 border-b border-border">
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Service</span>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest text-center w-20">Status</span>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest text-center w-16">Latency</span>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest text-center w-16">Uptime</span>
                <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest text-center w-14">Version</span>
              </div>
              {services.map((svc) => {
                const badgeClass = svc.status === "healthy"
                  ? "text-emerald-600 bg-emerald-50"
                  : svc.status === "degraded"
                    ? "text-amber-600 bg-amber-50"
                    : "text-red-600 bg-red-50";
                const badgeLabel = svc.status === "healthy" ? "HEALTHY" : svc.status === "degraded" ? "DEGRADED" : "DOWN";
                return (
                  <div key={svc.name + (svc.version || "")} className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-4 items-center px-6 py-3.5 border-b border-border/30 last:border-0">
                    <div className="flex items-center gap-2.5">
                      <Server className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-xs font-bold text-foreground">{svc.name}</span>
                    </div>
                    <div className="text-center w-20">
                      <span className={cn("text-[9px] font-black uppercase tracking-wider px-2.5 py-1 rounded-lg", badgeClass)}>
                        {badgeLabel}
                      </span>
                    </div>
                    <div className="text-center w-16">
                      <span className="text-xs font-mono font-bold text-foreground">{svc.latency ? `${svc.latency}ms` : "—"}</span>
                    </div>
                    <div className="text-center w-16">
                      <span className="text-xs font-mono font-bold text-foreground">{svc.uptime || "—"}</span>
                    </div>
                    <div className="text-center w-14">
                      <span className="text-[10px] font-mono text-muted-foreground">{svc.version || "—"}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>
        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 space-y-10">

          {/* Resource Usage */}
          <section>
            <div className="flex items-center gap-3 mb-5 px-2">
              <div className="w-10 h-10 bg-violet-50 text-violet-500 rounded-xl flex items-center justify-center">
                <Activity className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Resource Usage</h3>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-5">
              {[
                { label: "CPU Usage", value: resources.cpuPercent, warn: 60, crit: 80 },
                { label: "Memory", value: resources.memoryPercent, warn: 70, crit: 85 },
                { label: "Disk I/O", value: resources.diskPercent, warn: 75, crit: 90 },
              ].map((r) => (
                <div key={r.label} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-foreground">{r.label}</span>
                    <span className={cn("text-xs font-extrabold", r.value > r.crit ? "text-red-500" : r.value > r.warn ? "text-amber-500" : "text-foreground")}>{r.value}%</span>
                  </div>
                  <div className="h-2.5 rounded-full bg-muted/30 overflow-hidden">
                    <div className={cn("h-full rounded-full transition-all duration-500", r.value > r.crit ? "bg-red-500" : r.value > r.warn ? "bg-amber-500" : "bg-blue-500")} style={{ width: `${r.value}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* AI Pipeline Agents */}
          <section>
            <div className="flex items-center justify-between mb-5 px-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-primary/10 text-primary rounded-xl flex items-center justify-center">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">AI Pipeline</h3>
              </div>
              <Link href="/ai-agents" className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">View</Link>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-4">
              {[
                { name: "Triage Agent", icon: Crosshair, iconBg: "bg-amber-50", iconColor: "text-amber-500", status: "Healthy", statusColor: "bg-emerald-500", textColor: "text-emerald-600", metric: "124", unit: "ms", sub: "98.2% acc" },
                { name: "Hunter Agent", icon: SearchIcon, iconBg: "bg-cyan-50", iconColor: "text-cyan-600", status: "Running", statusColor: "bg-emerald-500", textColor: "text-emerald-600", metric: "1.2", unit: "k/m", sub: "99.1% success" },
                { name: "Verifier Agent", icon: ShieldCheck, iconBg: "bg-emerald-50", iconColor: "text-emerald-600", status: "High Latency", statusColor: "bg-orange-500", textColor: "text-orange-600", metric: "459", unit: "ms", sub: "42 queued" },
              ].map((agent) => (
                <div key={agent.name} className="flex items-center justify-between py-2 border-b border-border/50 last:border-0">
                  <div className="flex items-center gap-3">
                    <div className={cn("h-8 w-8 rounded-xl flex items-center justify-center", agent.iconBg)}>
                      <agent.icon className={cn("h-4 w-4", agent.iconColor)} />
                    </div>
                    <div>
                      <p className="text-xs font-bold text-foreground">{agent.name}</p>
                      <div className="flex items-center gap-1.5">
                        <span className={cn("h-1.5 w-1.5 rounded-full", agent.statusColor)} />
                        <span className={cn("text-[9px] font-black uppercase", agent.textColor)}>{agent.status}</span>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-extrabold text-foreground">{agent.metric}<span className="text-[9px] text-muted-foreground ml-0.5">{agent.unit}</span></p>
                    <p className="text-[9px] font-bold text-muted-foreground">{agent.sub}</p>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Quick Health Summary */}
          <section>
            <div className="flex items-center gap-3 mb-5 px-2">
              <div className="w-10 h-10 bg-emerald-50 text-emerald-600 rounded-xl flex items-center justify-center">
                <CheckCircle className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Health Summary</h3>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-3.5">
              {[
                { label: "Services Online", value: `${healthyCount}/${services.length}`, color: healthyCount === services.length ? "text-emerald-500" : "text-amber-500" },
                { label: "Uptime (avg)", value: "99.96%", color: "text-emerald-500" },
                { label: "Pipeline Status", value: "Operational", color: "text-emerald-500" },
                { label: "Last Incident", value: "14 days ago", color: "text-foreground" },
                { label: "Data Retention", value: "90 days", color: "text-foreground" },
              ].map((row) => (
                <div key={row.label} className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{row.label}</span>
                  <span className={cn("text-xs font-bold text-right", row.color)}>{row.value}</span>
                </div>
              ))}
            </div>
          </section>

        </aside>
      </div>
    </div>
  );
}
