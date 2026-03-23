"use client";

import React, { useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, formatRate, timeAgo } from "@/lib/utils";
import {
  TrendingUp,
  Cpu,
  Loader2,
} from "lucide-react";
import type { DashboardMetrics } from "@/lib/types";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

const SEVERITY_MAP: Record<number, { name: string; color: string }> = {
  0: { name: "Info", color: "#64748b" },
  1: { name: "Low", color: "#16a34a" },
  2: { name: "Warning", color: "#d97706" },
  3: { name: "High", color: "#ea580c" },
  4: { name: "Critical", color: "#be123c" },
};

type AlertItem = {
  event_id: string;
  timestamp: string;
  severity: number;
  event_type: string;
  source: string;
  raw: string;
  hostname?: string;
  user_id?: string;
};

function formatMTTRFromRate(ingestRate: number): string {
  if (!ingestRate || ingestRate <= 0) return "—";
  if (ingestRate > 1000) return "18m";
  if (ingestRate > 500) return "25m";
  return "39m";
}

function formatTimeLabel(timeStr: string): string {
  const d = new Date(timeStr.includes("Z") || timeStr.includes("+") ? timeStr : `${timeStr}Z`);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function clampPct(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function MiniDonut({ pct, color }: { pct: number; color: string }) {
  const v = clampPct(pct);
  const radius = 24;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (v / 100) * circumference;

  return (
    <div className="relative h-14 w-14 shrink-0" aria-hidden>
      <svg viewBox="0 0 64 64" className="h-full w-full -rotate-90">
        <circle cx="32" cy="32" r={radius} fill="none" stroke="#dbeafe" strokeWidth="7" />
        <circle
          cx="32"
          cy="32"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center text-[10px] font-black text-slate-700">{v}</div>
    </div>
  );
}

function MiniBars({ values, color }: { values: number[]; color: string }) {
  const trimmed = values.slice(-8);
  const max = Math.max(1, ...trimmed);
  return (
    <div className="relative ml-auto flex h-14 w-28 shrink-0 items-end gap-1" aria-hidden>
      <span className="absolute bottom-0 left-0 h-px w-full bg-slate-300" />
      {trimmed.map((v, idx) => (
        <span
          key={idx}
          className="w-2.5 rounded-sm"
          style={{
            height: `${Math.max(12, Math.round((v / max) * 52))}px`,
            backgroundColor: color,
            opacity: 0.45 + idx * 0.06,
          }}
        />
      ))}
    </div>
  );
}

function MiniMeter({ pct, color }: { pct: number; color: string }) {
  const v = clampPct(pct);
  return (
    <div className="ml-auto w-28 shrink-0" aria-hidden>
      <div className="h-2 w-full rounded-full bg-slate-300/70">
        <div className="h-2 rounded-full" style={{ width: `${v}%`, backgroundColor: color }} />
      </div>
      <div className="mt-1 text-right text-[9px] font-black text-slate-600">{v}%</div>
    </div>
  );
}

function MiniSparkline({ values, color }: { values: number[]; color: string }) {
  const trimmed = values.slice(-10);
  const max = Math.max(1, ...trimmed);
  const min = Math.min(...trimmed);
  const range = Math.max(1, max - min);
  const points = trimmed
    .map((v, i) => {
      const x = (i / Math.max(1, trimmed.length - 1)) * 70;
      const y = 24 - ((v - min) / range) * 20;
      return `${x},${y}`;
    })
    .join(" ");

  return (
    <svg width="120" height="30" viewBox="0 0 120 30" className="ml-auto shrink-0" aria-hidden>
      <polyline fill="none" stroke="#ffffff" strokeOpacity="0.6" strokeWidth="3" points={points} />
      <polyline fill="none" stroke={color} strokeWidth="2.4" points={points} />
      <circle cx="70" cy={trimmed.length ? 24 - ((trimmed[trimmed.length - 1] - min) / range) * 20 : 24} r="2.8" fill={color} />
    </svg>
  );
}

export default function DashboardPage() {
  const router = useRouter();

  const { data: metrics, loading: metricsLoading } = usePolling<DashboardMetrics>(
    "/api/metrics",
    5000
  );

  const { data: alertsData, loading: alertsLoading } = usePolling<{ alerts: AlertItem[] }>(
    "/api/alerts",
    12000
  );

  const severityData = useMemo(() => {
    if (!metrics?.severityDistribution?.length) return [];
    return metrics.severityDistribution.map((d) => ({
      name: SEVERITY_MAP[d.severity]?.name ?? `Sev ${d.severity}`,
      count: d.count,
      color: SEVERITY_MAP[d.severity]?.color ?? "#64748b",
    }));
  }, [metrics?.severityDistribution]);

  const severityTotal = useMemo(
    () => severityData.reduce((sum, item) => sum + item.count, 0),
    [severityData]
  );

  const timelineData = useMemo(() => {
    if (!metrics?.eventsTimeline?.length) return [];
    return metrics.eventsTimeline.map((d) => ({
      time: formatTimeLabel(d.time),
      events: d.count,
    }));
  }, [metrics?.eventsTimeline]);

  const investigations = Array.isArray(alertsData?.alerts) ? alertsData.alerts.slice(0, 4) : [];
  const criticalAlerts = metrics?.criticalAlertCount ?? 0;
  const riskScore = Math.min(99, Math.max(8, Math.round((metrics?.activeAlerts ?? 0) * 1.4 + criticalAlerts * 3.1)));
  const riskTrendPct = criticalAlerts > 0 ? -5 : -2;

  const pipelineHealth = useMemo(() => {
    const ingest = metrics?.ingestRate ?? 0;
    const evidence = metrics?.evidenceBatches ?? 0;
    const total = metrics?.totalEvents ?? 0;
    let score = 40;
    if (ingest > 0) score += 25;
    if (total > 0) score += 20;
    if (evidence > 0) score += 15;
    return Math.min(100, score);
  }, [metrics?.ingestRate, metrics?.evidenceBatches, metrics?.totalEvents]);

  const uptime = metrics?.uptime && metrics.uptime !== "—" ? `${metrics.uptime}%` : "—";
  const mttr = formatMTTRFromRate(metrics?.ingestRate ?? 0);
  const alertTrendPct =
    metrics?.prevActiveAlerts && metrics.prevActiveAlerts > 0
      ? Math.round(((metrics.activeAlerts - metrics.prevActiveAlerts) / metrics.prevActiveAlerts) * 100)
      : 0;

  const totalEventsPct = clampPct((Math.log10((metrics?.totalEvents ?? 0) + 1) / 7) * 100);
  const criticalSharePct = clampPct(((criticalAlerts || 0) / Math.max(1, metrics?.activeAlerts ?? 0)) * 100);
  const evidenceCoveragePct = clampPct(((metrics?.evidenceAnchored ?? 0) / Math.max(1, metrics?.totalEvents ?? 0)) * 100);
  const uptimePct = clampPct(Number(metrics?.uptime ?? 0));
  const mttrQualityPct = clampPct(100 - ((metrics?.ingestRate ?? 0) > 1000 ? 18 : (metrics?.ingestRate ?? 0) > 500 ? 25 : 39));
  const ingestBars = timelineData.length > 0 ? timelineData.slice(-6).map((d) => d.events) : [2, 4, 3, 6, 5, 7];
  const evidenceBars = [
    Math.max(1, metrics?.evidenceBatches ?? 1),
    Math.max(1, Math.round((metrics?.evidenceAnchored ?? 0) / 1000)),
    Math.max(1, Math.round((metrics?.totalEvents ?? 0) / 10000)),
    Math.max(1, Math.round((metrics?.evidenceAnchored ?? 0) / 2000)),
  ];
  const uptimeSpark = [
    Math.max(90, uptimePct - 2),
    Math.max(90, uptimePct - 1),
    Math.max(90, uptimePct - 1),
    Math.max(90, uptimePct),
    Math.max(90, uptimePct),
  ];
  const alertTrendBars = [
    Math.max(1, metrics?.prevActiveAlerts ?? 1),
    Math.max(1, metrics?.activeAlerts ?? 1),
    Math.max(1, criticalAlerts),
    Math.max(1, (metrics?.activeAlerts ?? 1) + Math.max(-2, Math.min(2, alertTrendPct))),
  ];
  const pipelineEntries = useMemo(
    () => Object.entries(metrics?.tableCounts ?? {}).sort((a, b) => b[1] - a[1]),
    [metrics?.tableCounts]
  );
  const pipelineMaxCount = pipelineEntries.length > 0 ? Math.max(1, pipelineEntries[0][1]) : 1;
  const mitreMatrix = useMemo(() => {
    const items = metrics?.mitreTopTechniques?.slice(0, 18) ?? [];
    return Array.from({ length: 18 }, (_, i) => items[i] ?? null);
  }, [metrics?.mitreTopTechniques]);

  if (metricsLoading && !metrics) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-slate-400">
          <Loader2 className="h-8 w-8 animate-spin" />
          <p className="text-sm font-medium">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <>
      <style
        dangerouslySetInnerHTML={{
          __html: `
          .ambient-glow {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: -1;
            background: #ffffff;
          }
          .bg-gradient-indigo {
            background: #0f172a;
          }
          .heatmap-cell {
            transition: all 0.2s ease;
          }
          .heatmap-cell:hover {
            transform: translateY(-1px);
            border-color: #94a3b8;
          }
          .glass-panel {
            backdrop-filter: blur(12px);
            background: rgba(255, 255, 255, 0.72);
            border: 1px solid rgba(226, 232, 240, 0.7);
          }
          .hover-lift {
            transition: transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.2s ease;
          }
          .hover-lift:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.04);
          }
          .tight-tracking {
            letter-spacing: -0.025em;
          }
          .metric-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 10px;
          }
          .metric-row > :last-child {
            margin-left: auto;
          }
          .metric-note {
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.02em;
          }
          .metric-panel {
            position: relative;
            overflow: hidden;
            background: rgba(255, 255, 255, 0.94);
            transition: transform 180ms ease, background-color 180ms ease, box-shadow 180ms ease;
          }
          .metric-panel:hover {
            transform: translateY(-1px);
            background: rgba(248, 250, 252, 0.9);
            box-shadow: inset 0 0 0 1px rgba(148,163,184,0.15), 0 10px 16px -14px rgba(15,23,42,0.4);
          }
          .metric-panel::after {
            content: "";
            position: absolute;
            right: -24px;
            top: -26px;
            width: 86px;
            height: 86px;
            border-radius: 9999px;
            background: rgba(148, 163, 184, 0.12);
            pointer-events: none;
          }
          .metric-label {
            margin-bottom: 2px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: 0.11em;
            text-transform: uppercase;
            color: #475569;
          }
          .metric-sub {
            margin-top: auto;
            font-size: 12px;
            font-weight: 600;
            color: #475569;
          }
          .metric-divider {
            height: 1px;
            width: 100%;
            margin-top: 8px;
            background: rgba(148, 163, 184, 0.35);
          }
        `,
        }}
      />

      <div className="ambient-glow" />
      <div className="min-h-screen -mx-4 -mt-4 flex flex-col bg-white text-slate-900 lg:-mx-6 lg:-mt-6">
        <main className="flex-1 space-y-8 p-8">
          <section className="space-y-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
              <div className="metric-panel glass-panel hover-lift flex flex-col justify-between rounded-xl p-6">
                <div>
                  <p className="mb-1 text-[10px] font-black uppercase tracking-[0.1em] text-primary">Global Ingestion</p>
                  <p className="mb-4 text-xs font-semibold text-slate-600">Total Events Ingested</p>
                  <div className="metric-row">
                    <h2 className="tight-tracking text-4xl font-black text-emerald-600 lg:text-5xl">{formatNumber(metrics?.totalEvents ?? 0)}</h2>
                    <MiniSparkline values={ingestBars} color="#334155" />
                  </div>
                  <div className="metric-divider" />
                  <div className="flex items-center gap-1 text-sm font-bold text-primary">
                    <TrendingUp className="h-4 w-4" /> Live
                  </div>
                </div>
              </div>

              <div className="metric-panel glass-panel hover-lift flex flex-col rounded-xl p-6">
                <p className="mb-4 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">Incident Response</p>
                <div className="metric-row">
                  <span className="tight-tracking text-3xl font-black text-slate-900 lg:text-4xl">{formatNumber(metrics?.activeAlerts ?? 0)}</span>
                  <MiniMeter pct={criticalSharePct} color="#ef4444" />
                </div>
                <div className="metric-divider" />
                {criticalAlerts > 0 && <span className="metric-note uppercase text-red-500">{criticalAlerts} Critical</span>}
                <div className="mt-1 text-[11px] font-bold uppercase text-slate-600">
                  Critical mix {criticalSharePct}%
                </div>
                <p className="metric-sub">Active alerts requiring triage</p>
              </div>

              <div className="metric-panel glass-panel hover-lift flex flex-col rounded-xl p-6">
                <p className="mb-4 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">Risk Assessment</p>
                <div className="metric-row">
                  <div className="flex items-end gap-2">
                    <span className="tight-tracking text-3xl font-black text-slate-900 lg:text-4xl">{riskScore}</span>
                    <span className="metric-note uppercase text-emerald-500">{riskTrendPct}%</span>
                  </div>
                  <MiniDonut pct={riskScore} color="#334155" />
                </div>
                <div className="metric-divider" />
                <p className="metric-sub">Overall infrastructure risk score</p>
              </div>

              <div className="metric-panel glass-panel hover-lift flex flex-col rounded-xl p-6">
                <p className="mb-4 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">Evidence Chain</p>
                <div className="metric-row">
                  <span className="tight-tracking text-3xl font-black text-primary lg:text-4xl">{formatNumber(metrics?.evidenceAnchored ?? 0)}</span>
                  <MiniBars values={evidenceBars} color="#334155" />
                </div>
                <div className="metric-divider" />
                <p className="metric-sub">{metrics?.evidenceBatches ?? 0} batches anchored</p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 rounded-xl border border-slate-100 bg-slate-50/50 p-4 md:grid-cols-4">
              <div className="flex min-w-0 items-center justify-between px-4 md:border-r md:border-slate-100">
                <div>
                <p className="mb-3 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">Ingest Rate</p>
                <div className="flex items-end gap-2">
                  <span className="tight-tracking text-base font-black text-slate-800">{formatRate(metrics?.ingestRate ?? 0)}</span>
                  <MiniBars values={ingestBars} color="#2563eb" />
                </div>
                </div>
              </div>

              <div className="flex min-w-0 items-center justify-between px-4 md:border-r md:border-slate-100">
                <div>
                <p className="mb-3 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">MTTR</p>
                <div className="flex items-end gap-2">
                  <span className="tight-tracking text-base font-black text-slate-800">{mttr}</span>
                  <MiniMeter pct={mttrQualityPct} color="#0ea5e9" />
                </div>
                </div>
              </div>

              <div className="flex min-w-0 items-center justify-between px-4 md:border-r md:border-slate-100">
                <div>
                <p className="mb-3 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">SLA Uptime</p>
                <div className="flex items-end gap-2">
                  <span className="tight-tracking whitespace-nowrap text-base font-black text-slate-800">{uptime}</span>
                  <MiniSparkline values={uptimeSpark} color="#16a34a" />
                </div>
                </div>
              </div>

              <div className="flex min-w-0 items-center justify-between px-4">
                <div>
                <p className="mb-3 text-[11px] font-black uppercase tracking-[0.1em] text-slate-600">Alert Trend</p>
                <div className="metric-row">
                  <div className="flex items-baseline gap-2">
                    <span className={`tight-tracking text-base font-bold ${alertTrendPct <= 0 ? "text-emerald-600" : "text-red-500"}`}>
                      {alertTrendPct > 0 ? "+" : ""}{alertTrendPct}%
                    </span>
                    <span className="text-[11px] font-bold uppercase text-slate-600">vs prior period</span>
                  </div>
                  <MiniBars values={alertTrendBars} color={alertTrendPct <= 0 ? "#16a34a" : "#ef4444"} />
                </div>
                </div>
              </div>
            </div>
          </section>

          <section className="grid grid-cols-12 gap-8">
            <div className="col-span-12 rounded-2xl border border-slate-100 bg-white p-8 shadow-sm lg:col-span-8">
              <div className="mb-6 flex items-center justify-between border-b border-slate-200 pb-3">
                <div>
                  <h3 className="text-lg font-bold text-slate-900 tight-tracking">Event Volume Timeline</h3>
                  <p className="text-sm text-slate-400">Real-time ingestion flow across sensors</p>
                </div>
                <span className="rounded bg-primary px-3 py-1 text-xs font-semibold text-white">Live</span>
              </div>
              <div className="relative h-96 w-full border border-slate-200 bg-slate-50 p-4">
                {timelineData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData} margin={{ top: 5, right: 5, bottom: 5, left: -20 }}>
                      <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "#64748b" }} dy={10} />
                      <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "#64748b" }} />
                      <RechartsTooltip
                        contentStyle={{ borderRadius: "8px", border: "none", boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)" }}
                        labelStyle={{ color: "#64748b", marginBottom: "4px" }}
                      />
                      <Area type="monotone" dataKey="events" name="Events" stroke="#3b82f6" strokeWidth={2} fill="#93c5fd" fillOpacity={0.35} />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-sm text-slate-400">No timeline data available</div>
                )}
              </div>
            </div>

            <div className="col-span-12 rounded-2xl border border-slate-100 bg-white p-8 shadow-sm lg:col-span-4">
              <h3 className="mb-6 text-lg font-bold text-slate-900 tight-tracking">Alert Severity Breakdown</h3>
              <div className="flex min-h-[18rem] flex-col">
                {severityData.length > 0 ? (
                  <>
                    <div className="mb-6 h-52 w-full">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={severityData} margin={{ top: 5, right: 5, bottom: 5, left: -20 }}>
                          <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
                          <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "#64748b" }} dy={10} />
                          <YAxis axisLine={false} tickLine={false} tick={{ fontSize: 10, fill: "#64748b" }} />
                          <RechartsTooltip cursor={{ fill: "#f1f5f9" }} contentStyle={{ borderRadius: "8px", border: "none", boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)" }} />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={40}>
                            {severityData.map((entry, idx) => (
                              <Cell key={`${entry.name}-${idx}`} fill={entry.color} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>

                    <div className="mt-auto space-y-3">
                      {severityData.map((entry) => (
                        <div key={entry.name} className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-2 font-semibold text-slate-600">
                            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: entry.color }} />
                            {entry.name}
                          </div>
                          <span className="font-bold">{severityTotal > 0 ? Math.round((entry.count / severityTotal) * 100) : 0}%</span>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="flex flex-1 items-center justify-center text-sm text-slate-400">No severity data available</div>
                )}
              </div>
            </div>

            <div className="col-span-12">
              <h3 className="mb-6 font-bold text-slate-800">MITRE ATT&CK Coverage</h3>
              {(metrics?.mitreTopTechniques?.length ?? 0) > 0 ? (
                <div className="grid grid-cols-6 grid-rows-3 gap-3">
                  {mitreMatrix.map((item, idx) => {
                    if (!item) {
                      return (
                        <div
                          key={`mitre-empty-${idx}`}
                          className="flex h-16 items-center justify-center rounded border border-dashed border-slate-200 bg-slate-50/50 text-[10px] font-semibold uppercase tracking-wide text-slate-400"
                        >
                          Empty
                        </div>
                      );
                    }

                    const intensity =
                      item.count > 100
                        ? "bg-rose-50 border-rose-400 text-rose-900"
                        : item.count > 50
                          ? "bg-amber-50 border-amber-400 text-amber-900"
                          : "bg-blue-50 border-blue-300 text-blue-900";

                    return (
                      <div key={`${item.technique}-${idx}`} className={`heatmap-cell h-16 rounded border-l-4 px-3 ${intensity} flex flex-col justify-center`}>
                        <p className="truncate text-[9px] font-black uppercase text-slate-500" title={item.tactic || "Unknown Tactic"}>
                          {item.tactic || "Unknown"}
                        </p>
                        <div className="mt-1">
                          <span className="text-[10px] font-bold">{item.technique}</span>
                          <span className="text-[10px] font-bold opacity-70">{formatNumber(item.count)} alerts</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="py-8 text-center text-sm text-slate-400">No MITRE ATT&CK data available yet</div>
              )}
            </div>

            <div className="col-span-12 border-r-0 border-t border-slate-300 pt-6 lg:col-span-6 lg:border-r lg:pr-6">
              <h3 className="mb-6 font-bold text-slate-800">Top Log Sources</h3>
              <div className="space-y-5">
                {(metrics?.topSources?.length ?? 0) > 0 ? (
                  metrics!.topSources!.slice(0, 5).map((src) => {
                    const maxCount = metrics!.topSources![0].count || 1;
                    const pct = Math.round((src.count / maxCount) * 100);
                    return (
                      <div key={src.source} className="space-y-1">
                        <div className="mb-1 flex justify-between text-xs font-bold">
                          <span className="text-slate-600">{src.source}</span>
                          <span className="text-slate-800">{formatNumber(src.count)} events</span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-full bg-slate-100">
                          <div className="h-full rounded-full bg-primary transition-all duration-1000" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div className="py-6 text-center text-sm text-slate-400">No log source data available</div>
                )}
              </div>
            </div>

            <div className="col-span-12 border-t border-slate-300 pt-6 lg:col-span-6 lg:pl-2">
              <h3 className="mb-6 font-bold text-slate-800">Pipeline Data Breakdown</h3>
              <div className="space-y-2">
                {pipelineEntries.map(([table, count], idx) => {
                  const sharePct = Math.round(((count || 0) / Math.max(1, metrics?.totalEvents ?? 0)) * 100);
                  const maxPct = clampPct((count / pipelineMaxCount) * 100);
                  const accent = ["#2563eb", "#0ea5e9", "#14b8a6", "#16a34a", "#f59e0b", "#ef4444"][idx % 6];

                  return (
                    <div key={table} className="rounded-lg border border-slate-200/80 bg-slate-50/65 px-3 py-2.5">
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex min-w-0 items-center gap-2">
                          <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: accent }} />
                          <p className="truncate text-sm font-semibold text-slate-800">{table.replace(/_/g, " ")}</p>
                        </div>
                        <div className="flex items-center gap-2 text-right">
                          <span className="rounded-md bg-white px-2 py-0.5 text-xs font-black text-slate-900 shadow-sm">{formatNumber(count)}</span>
                          <span className="rounded-md px-2 py-0.5 text-[10px] font-black uppercase tracking-wide text-slate-700" style={{ backgroundColor: `${accent}22` }}>
                            {sharePct}%
                          </span>
                        </div>
                      </div>
                      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200/70">
                        <div
                          className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${maxPct}%`, backgroundColor: accent }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          <section className="grid grid-cols-12 gap-8 pb-12">
            <div className="col-span-12 overflow-hidden rounded-2xl border border-slate-100 bg-white p-8 shadow-sm lg:col-span-9">
              <div className="mb-5 flex items-center justify-between border-b border-slate-300 pb-4">
                <h3 className="font-bold text-slate-800">Recent Investigations & Pipeline</h3>
                <Link href="/investigations" className="text-xs font-bold text-primary hover:underline">
                  View All Investigations
                </Link>
              </div>

              {investigations.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead className="border-y border-slate-200 text-[10px] font-black uppercase text-slate-400">
                      <tr>
                        <th className="rounded-tl-lg px-4 py-3">INV ID</th>
                        <th className="px-4 py-3">ALERT NAME</th>
                        <th className="px-4 py-3">STATUS</th>
                        <th className="px-4 py-3">PRIORITY</th>
                        <th className="px-4 py-3">ASSIGNEE</th>
                        <th className="rounded-tr-lg px-4 py-3">TIME</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-xs">
                      {investigations.map((alert) => {
                        const severity = alert.severity ?? 0;
                        const status = severity >= 4 ? "In Progress" : severity >= 3 ? "Open" : "Closed";
                        const statusStyle =
                          status === "Closed"
                            ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                            : "bg-amber-50 text-amber-700 border-amber-200";
                        const sevColor =
                          severity >= 4 ? "text-red-500" : severity >= 3 ? "text-amber-500" : "text-slate-500";
                        const sevLabel = severity >= 4 ? "Critical" : severity >= 3 ? "High" : "Medium";
                        const invId = `INV-${String(alert.event_id).slice(-6)}`;

                        return (
                          <tr key={`${alert.event_id}-${alert.timestamp}`} onClick={() => router.push("/investigations")} className="cursor-pointer transition-colors hover:bg-slate-50/70">
                            <td className="px-4 py-3 font-mono text-slate-500">{invId}</td>
                            <td className="max-w-[26rem] truncate px-4 py-3 font-bold text-slate-800">{alert.raw || alert.event_type}</td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-1 font-bold ${statusStyle}`}>{status}</span>
                            </td>
                            <td className={`px-4 py-3 font-bold ${sevColor}`}>{sevLabel}</td>
                            <td className="px-4 py-3">SOC Analyst</td>
                            <td className="px-4 py-3 text-slate-400">{timeAgo(alert.timestamp)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="py-8 text-center text-sm text-slate-400">
                  {alertsLoading ? "Loading investigations..." : "No investigations found"}
                </div>
              )}
            </div>

            <div className="col-span-12 space-y-6 lg:col-span-3">
              <div className="rounded-2xl border border-slate-100 bg-white p-8 shadow-sm">
                <h2 className="mb-8 text-lg font-bold text-slate-900 tight-tracking">Pipeline Summary</h2>
                <div className="space-y-5">
                  <div className="flex items-center justify-between border-b border-slate-50 py-2.5">
                    <span className="text-xs font-medium text-slate-500">Total Events</span>
                    <span className="text-sm font-bold text-slate-900">{formatNumber(metrics?.totalEvents ?? 0)}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-slate-50 py-2.5">
                    <span className="text-xs font-medium text-slate-500">Active Alerts</span>
                    <span className="text-sm font-bold text-slate-900">{formatNumber(metrics?.activeAlerts ?? 0)}</span>
                  </div>
                  <div className="flex items-center justify-between border-b border-slate-50 py-2.5">
                    <span className="text-xs font-medium text-slate-500">Evidence Batches</span>
                    <span className="text-sm font-bold text-slate-900">{metrics?.evidenceBatches ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between py-2.5">
                    <span className="text-xs font-medium text-slate-500">Pipeline Health</span>
                    <span className="text-xs font-black uppercase tracking-widest text-emerald-600">{pipelineHealth}%</span>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl bg-slate-900 p-8 shadow-xl shadow-slate-200">
                <h3 className="mb-8 text-[10px] font-black uppercase tracking-[0.2em] text-slate-500">Component Status</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`h-1.5 w-1.5 rounded-full ${(metrics?.ingestRate ?? 0) > 0 ? "bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.8)]" : "bg-slate-500"}`} />
                      <span className="text-[11px] font-bold tracking-tight text-white">Ingestion Tier</span>
                    </div>
                    <span className="text-[10px] font-bold text-slate-500">LIVE</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`h-1.5 w-1.5 rounded-full ${(metrics?.totalEvents ?? 0) > 0 ? "bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)]" : "bg-slate-500"}`} />
                      <span className="text-[11px] font-bold tracking-tight text-white">ClickHouse Cluster</span>
                    </div>
                    <span className="text-[10px] font-bold text-slate-500">ONLINE</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`h-1.5 w-1.5 rounded-full ${(metrics?.activeAlerts ?? 0) >= 0 ? "bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)]" : "bg-slate-500"}`} />
                      <span className="text-[11px] font-bold tracking-tight text-white">AI Triage Engine</span>
                    </div>
                    <span className="text-[10px] font-bold text-slate-500">ACTIVE</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className={`h-1.5 w-1.5 rounded-full ${(metrics?.evidenceBatches ?? 0) > 0 ? "bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)]" : "bg-orange-400 shadow-[0_0_10px_rgba(251,146,60,0.4)]"}`} />
                      <span className="text-[11px] font-bold tracking-tight text-white">Evidence Anchoring</span>
                    </div>
                    <span className={`text-[10px] font-bold ${(metrics?.evidenceBatches ?? 0) > 0 ? "text-slate-500" : "text-orange-400"}`}>
                      {(metrics?.evidenceBatches ?? 0) > 0 ? "SYNCED" : "SYNC"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        </main>
      </div>
    </>
  );
}
