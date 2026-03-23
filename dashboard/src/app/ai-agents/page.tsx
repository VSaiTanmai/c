"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import {
  Activity, Zap, TrendingUp,
  RefreshCw, Cpu, BarChart3, Fingerprint,
  ArrowRight, Crosshair, Search as SearchIcon, ShieldCheck,
  Settings, FileText, Radio,
} from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, cn } from "@/lib/utils";
import type { Agent } from "@/lib/types";

interface AgentsResponse {
  agents: Agent[];
  pipeline?: {
    hmacEnabled: boolean;
    totalProcessed: number;
    avgLatencyMs: number;
  };
  leaderboard?: Array<{
    model: string;
    type: string;
    f1: number;
    precision: number;
    recall: number;
    deployed: boolean;
    version: string;
  }>;
  xaiGlobal?: Array<{
    feature: string;
    importance: number;
  }>;
  drift?: {
    status: string;
    lastCheck: string;
    psiScore: number;
    threshold: number;
  };
}

/* Deterministic 24h performance data for bar chart */
const PERF_DATA = [
  { hour: "00:00", triage: 62, hunter: 40, verifier: 38 }, { hour: "01:00", triage: 55, hunter: 35, verifier: 33 },
  { hour: "02:00", triage: 48, hunter: 30, verifier: 28 }, { hour: "03:00", triage: 45, hunter: 28, verifier: 26 },
  { hour: "04:00", triage: 50, hunter: 32, verifier: 30 }, { hour: "05:00", triage: 58, hunter: 38, verifier: 35 },
  { hour: "06:00", triage: 75, hunter: 48, verifier: 45 }, { hour: "07:00", triage: 95, hunter: 58, verifier: 55 },
  { hour: "08:00", triage: 120, hunter: 72, verifier: 68 }, { hour: "09:00", triage: 145, hunter: 85, verifier: 80 },
  { hour: "10:00", triage: 160, hunter: 95, verifier: 90 }, { hour: "11:00", triage: 175, hunter: 105, verifier: 98 },
  { hour: "12:00", triage: 155, hunter: 90, verifier: 85 }, { hour: "13:00", triage: 168, hunter: 98, verifier: 92 },
  { hour: "14:00", triage: 180, hunter: 110, verifier: 104 }, { hour: "15:00", triage: 170, hunter: 100, verifier: 95 },
  { hour: "16:00", triage: 150, hunter: 88, verifier: 82 }, { hour: "17:00", triage: 130, hunter: 78, verifier: 72 },
  { hour: "18:00", triage: 105, hunter: 65, verifier: 60 }, { hour: "19:00", triage: 85, hunter: 52, verifier: 48 },
  { hour: "20:00", triage: 75, hunter: 45, verifier: 42 }, { hour: "21:00", triage: 68, hunter: 42, verifier: 39 },
  { hour: "22:00", triage: 60, hunter: 38, verifier: 35 }, { hour: "23:00", triage: 55, hunter: 34, verifier: 31 },
];

/* Pipeline activity logs */
const ACTIVITY_LOG = [
  { agent: "VERIFIER_AGENT", color: "text-emerald-500", dot: "bg-emerald-500", text: "Hash verification successful for event", highlight: "0x4F...E1", extra: "Result: CLEAN", time: "2s ago" },
  { agent: "TRIAGE_AGENT", color: "text-red-500", dot: "bg-red-500", text: "High-entropy payload detected on Topic:", highlight: "ingest.raw.json", extra: "Routing to Hunter.", time: "12s ago" },
  { agent: "HUNTER_AGENT", color: "text-amber-500", dot: "bg-amber-500", text: "IOC correlation matched pattern:", highlight: "Log4ShellExploit_A", extra: "Escalation triggered.", time: "52s ago" },
  { agent: "PIPELINE_SCHEDULER", color: "text-blue-500", dot: "bg-blue-500", text: "Model refresh cycle complete.", highlight: "LightGBM v2.4", extra: "weight updated to 0.50.", time: "8 ago" },
];

/* XAI feature importance */
const XAI_FEATURES = [
  { feature: "Source IP Reputation", importance: 0.42, color: "bg-blue-500" },
  { feature: "Payload Entropy", importance: 0.29, color: "bg-orange-500" },
  { feature: "Temporal Anomaly Score", importance: 0.15, color: "bg-cyan-500" },
  { feature: "DNS Request Density", importance: 0.09, color: "bg-emerald-500" },
];

/* Model leaderboard */
const MODELS = [
  { rank: "#1", model: "LightGBM v2.4", recall: 0.982, precision: 0.975, status: "ACTIVE", statusCls: "text-emerald-600 bg-emerald-50" },
  { rank: "#2", model: "XGBoost Optimized", recall: 0.971, precision: 0.982, status: "ACTIVE", statusCls: "text-emerald-600 bg-emerald-50" },
  { rank: "#3", model: "RF Multiclass", recall: 0.945, precision: 0.958, status: "SHADOW", statusCls: "text-blue-600 bg-blue-50" },
];

const MODEL_VOTING = [
  { name: "LightGBM", weight: 50, color: "#3b82f6" },
  { name: "Extended IF", weight: 30, color: "#10b981" },
  { name: "Autoencoder", weight: 20, color: "#f59e0b" },
];

export default function AIAgentsPage() {
  const { data, loading, refresh } = usePolling<AgentsResponse>("/api/ai/agents", 15000);
  const [showLogs, setShowLogs] = useState(true);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  const agents = data?.agents || [];
  const pipeline = data?.pipeline;
  const triage = agents.find((a) => a.name.toLowerCase().includes("triage"));
  const hunter = agents.find((a) => a.name.toLowerCase().includes("hunter"));
  const verifier = agents.find((a) => a.name.toLowerCase().includes("verifier"));

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-emerald-50 text-emerald-600 text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live Pipeline
                </span>
                <span className="text-muted-foreground text-sm font-medium">Cluster: US-EAST-01</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                AI <span className="text-primary inline-block">Systems</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Core Intelligence Pipeline Monitor — Triage, Hunter, and Verifier agents processing real-time telemetry.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" /> Reset Pipeline
              </button>
              <Link href="/explainability">
                <button className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                  <Settings className="w-4 h-4" /> Configuration
                </button>
              </Link>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total Processed</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(pipeline?.totalProcessed || 356)}</h3>
                <span className="text-emerald-500 text-xs font-bold flex items-center gap-0.5"><TrendingUp className="w-3 h-3" /> +12%</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Avg Latency</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{pipeline?.avgLatencyMs || 42}<span className="text-lg font-bold text-muted-foreground ml-1">ms</span></h3>
                <span className="text-emerald-500 text-xs font-bold">↓ -8%</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">HMAC Status</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{pipeline?.hmacEnabled !== false ? "On" : "Off"}</h3>
                <span className="text-emerald-500 text-xs font-bold">✓ Verified</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Kafka Topics</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">4</h3>
                <span className="text-emerald-500 text-[10px] font-bold uppercase tracking-tighter">0 msgs behind</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12">
        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* Performance Trends — Area Chart */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <BarChart3 className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Agent Performance Trends (24h)</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Events processed per hour</p>
                </div>
              </div>
              <div className="flex gap-5">
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-blue-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Triage</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-cyan-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">Hunter</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-emerald-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Verifier</span></div>
              </div>
            </div>
            <div className="h-[440px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              <ResponsiveContainer>
                <AreaChart data={PERF_DATA}>
                  <defs>
                    <linearGradient id="triageG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity={0.25}/><stop offset="100%" stopColor="#3b82f6" stopOpacity={0.02}/></linearGradient>
                    <linearGradient id="hunterG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.2}/><stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02}/></linearGradient>
                    <linearGradient id="verifierG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#10b981" stopOpacity={0.18}/><stop offset="100%" stopColor="#10b981" stopOpacity={0.02}/></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="hour" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} interval={2} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 16, fontSize: 12, fontWeight: 600, padding: "12px 16px" }} />
                  <Area type="monotone" dataKey="triage" stroke="#3b82f6" fill="url(#triageG)" strokeWidth={2.5} dot={false} name="Triage" />
                  <Area type="monotone" dataKey="hunter" stroke="#22d3ee" fill="url(#hunterG)" strokeWidth={2} dot={false} name="Hunter" />
                  <Area type="monotone" dataKey="verifier" stroke="#10b981" fill="url(#verifierG)" strokeWidth={2} dot={false} name="Verifier" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Score Fusion Engine */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
              <div>
                <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground mb-4">Model Voting Stack</p>
                <div className="min-h-[320px] bg-muted/20 rounded-2xl p-4 border border-border">
                  <div className="flex h-full flex-col">
                    <div className="h-[230px]">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={MODEL_VOTING}
                            dataKey="weight"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            innerRadius="40%"
                            outerRadius="72%"
                            paddingAngle={2}
                          >
                            {MODEL_VOTING.map((entry) => (
                              <Cell key={entry.name} fill={entry.color} />
                            ))}
                          </Pie>
                          <RechartsTooltip
                            formatter={(value: number) => [`${value}%`, "Weight"]}
                            contentStyle={{ borderRadius: "12px", border: "1px solid hsl(var(--border))", fontSize: 12 }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-2 grid grid-cols-1 gap-2 px-2 pb-2">
                      {MODEL_VOTING.map((m) => (
                        <div key={m.name} className="flex items-center justify-between rounded-lg border border-border bg-white px-3 py-2">
                          <div className="flex items-center gap-2">
                            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: m.color }} />
                            <span className="text-[11px] font-bold text-foreground">{m.name}</span>
                          </div>
                          <span className="text-xs font-mono font-extrabold text-muted-foreground">{m.weight}%</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              <div>
                <p className="text-xs font-black uppercase tracking-widest text-muted-foreground mb-4">Model Leaderboard</p>
                <div className="min-h-[320px] bg-white rounded-2xl border border-border shadow-sm p-4">
                  <div className="mb-3 flex items-center justify-end gap-4 text-[10px] font-black uppercase tracking-wider text-muted-foreground">
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-500" />Recall</span>
                    <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-blue-500" />Precision</span>
                  </div>
                  <div className="space-y-3">
                    {MODELS.map((m) => (
                      <div key={m.rank} className="rounded-xl border border-border bg-muted/10 px-3 py-3">
                        <div className="mb-2 flex items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="font-mono text-xs font-black text-primary">{m.rank}</p>
                            <p className="truncate text-sm font-bold text-foreground">{m.model}</p>
                          </div>
                          <span className={cn("rounded-full px-2.5 py-1 text-[10px] font-black uppercase", m.statusCls)}>{m.status}</span>
                        </div>
                        <div className="grid grid-cols-[1fr_auto] items-center gap-3">
                          <div className="space-y-1.5">
                            <div className="flex items-center gap-2">
                              <span className="w-4 text-[10px] font-black text-muted-foreground">R</span>
                              <div className="h-1.5 flex-1 rounded-full bg-muted/40 overflow-hidden">
                                <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.round(m.recall * 100)}%` }} />
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="w-4 text-[10px] font-black text-muted-foreground">P</span>
                              <div className="h-1.5 flex-1 rounded-full bg-muted/40 overflow-hidden">
                                <div className="h-full rounded-full bg-blue-500" style={{ width: `${Math.round(m.precision * 100)}%` }} />
                              </div>
                            </div>
                          </div>
                          <div className="text-right font-mono text-xs font-bold text-muted-foreground">
                            <p>{m.recall.toFixed(3)}</p>
                            <p>{m.precision.toFixed(3)}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>

        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 space-y-10">

          {/* Agent Confidence Donuts */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-white shadow-sm text-emerald-500 rounded-xl flex items-center justify-center border border-border">
                <TrendingUp className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Agent Confidence</h3>
            </div>
            <div className="bg-white rounded-2xl p-6 border border-border shadow-sm">
              <div className="flex items-center justify-around py-2">
                {[
                  { label: "Triage", pct: triage?.accuracy || 94.2, stroke: "#3b82f6" },
                  { label: "Hunter", pct: hunter?.accuracy || 91.5, stroke: "#06b6d4" },
                  { label: "Verifier", pct: verifier?.accuracy || 97.1, stroke: "#10b981" },
                ].map((a) => {
                  const r = 32, c = 2 * Math.PI * r, offset = c * (1 - a.pct / 100);
                  return (
                    <div key={a.label} className="flex flex-col items-center gap-2">
                      <svg width="80" height="80" viewBox="0 0 80 80">
                        <circle cx="40" cy="40" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="5" opacity="0.2" />
                        <circle cx="40" cy="40" r={r} fill="none" stroke={a.stroke} strokeWidth="5"
                          strokeDasharray={c} strokeDashoffset={offset} strokeLinecap="round"
                          transform="rotate(-90 40 40)" className="transition-all duration-700" />
                        <text x="40" y="42" textAnchor="middle" dominantBaseline="middle"
                          className="fill-foreground" style={{ fontSize: "14px", fontWeight: 700 }}>
                          {a.pct}%
                        </text>
                      </svg>
                      <span className="text-[10px] font-black text-muted-foreground uppercase">{a.label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* XAI Feature Importance */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-xl">
                <Fingerprint className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">XAI Feature Importance</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-5">
              {XAI_FEATURES.map((f) => (
                <div key={f.feature} className="space-y-2">
                  <div className="flex justify-between text-[10px] font-black text-muted-foreground uppercase tracking-widest">
                    <span>{f.feature}</span>
                    <span className="text-foreground">{f.importance.toFixed(2)}</span>
                  </div>
                  <div className="h-2.5 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full transition-all", f.color)} style={{ width: `${(f.importance / 0.5) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Pipeline Activity */}
          <section>
            <div className="flex items-center justify-between mb-6 px-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white shadow-sm text-primary rounded-xl flex items-center justify-center border border-border">
                  <Activity className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">Pipeline Activity</h3>
              </div>
              <button onClick={() => setShowLogs(!showLogs)} className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">
                {showLogs ? "Collapse" : "Expand"}
              </button>
            </div>
            {showLogs && (
              <div className="space-y-3">
                {ACTIVITY_LOG.map((log, i) => (
                    <div key={i} className="bg-white rounded-2xl p-5 border border-border shadow-sm hover:border-primary/30 transition-all">
                    <div className="flex items-start gap-3">
                      <div className={cn("w-2 h-2 rounded-full mt-1.5 shrink-0", log.dot)} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <p className={cn("text-[10px] font-black uppercase tracking-wider", log.color)}>{log.agent}</p>
                          <span className="text-[10px] font-bold text-muted-foreground">{log.time}</span>
                        </div>
                        <p className="text-xs text-muted-foreground leading-relaxed">
                          {log.text}{" "}
                          <code className="px-1.5 py-0.5 rounded bg-slate-900 text-emerald-400 font-mono text-[10px]">{log.highlight}</code>
                          {". "}{log.extra}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

        </aside>
      </div>

    </div>
  );
}
