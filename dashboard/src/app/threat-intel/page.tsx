"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, AreaChart, Area, ScatterChart, Scatter, ZAxis, Cell,
} from "recharts";
import {
  Globe, Shield, AlertTriangle, Search, RefreshCw, ExternalLink,
  Hash, Server, Mail, FileText, Target, Clock, Filter,
  ChevronDown, ChevronRight, Brain, Crosshair, Search as SearchIcon,
  ShieldCheck, Zap, CheckCircle, Link2, Activity, Eye, ArrowRight,
  AlertCircle, User, Monitor, Wifi,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, cn } from "@/lib/utils";
import type { IOC, ThreatPattern, Investigation } from "@/lib/types";

interface ThreatIntelResponse {
  iocs: IOC[];
  patterns: ThreatPattern[];
  stats?: {
    totalIOCs: number;
    activeThreats: number;
    mitreTechniques: number;
    lastUpdated: string;
  };
}

const IOC_ICONS: Record<string, typeof Globe> = {
  ip: Server, ipv4: Server, domain: Globe, url: ExternalLink,
  hash: Hash, sha256: Hash, email: Mail, file: FileText,
};

/* 24h simulated attack timeline data (deterministic to avoid hydration mismatch) */
const TIMELINE_DATA = [
  { hour: "00:00", critical: 1, high: 2, medium: 4 }, { hour: "01:00", critical: 0, high: 1, medium: 3 },
  { hour: "02:00", critical: 0, high: 1, medium: 2 }, { hour: "03:00", critical: 1, high: 2, medium: 3 },
  { hour: "04:00", critical: 0, high: 1, medium: 5 }, { hour: "05:00", critical: 1, high: 3, medium: 4 },
  { hour: "06:00", critical: 2, high: 4, medium: 6 }, { hour: "07:00", critical: 1, high: 3, medium: 5 },
  { hour: "08:00", critical: 3, high: 6, medium: 8 }, { hour: "09:00", critical: 4, high: 8, medium: 10 },
  { hour: "10:00", critical: 5, high: 9, medium: 12 }, { hour: "11:00", critical: 6, high: 11, medium: 14 },
  { hour: "12:00", critical: 7, high: 12, medium: 11 }, { hour: "13:00", critical: 5, high: 10, medium: 13 },
  { hour: "14:00", critical: 8, high: 13, medium: 15 }, { hour: "15:00", critical: 6, high: 11, medium: 12 },
  { hour: "16:00", critical: 4, high: 9, medium: 10 }, { hour: "17:00", critical: 5, high: 8, medium: 9 },
  { hour: "18:00", critical: 3, high: 6, medium: 7 }, { hour: "19:00", critical: 2, high: 5, medium: 8 },
  { hour: "20:00", critical: 1, high: 3, medium: 6 }, { hour: "21:00", critical: 2, high: 4, medium: 5 },
  { hour: "22:00", critical: 1, high: 2, medium: 4 }, { hour: "23:00", critical: 0, high: 1, medium: 3 },
];

/* IOC type distribution percentages */
const TYPE_DIST = [
  { type: "Domain", pct: 38, color: "#6366f1" },
  { type: "Server", pct: 28, color: "#f97316" },
  { type: "SHA256", pct: 20, color: "#eab308" },
  { type: "URL", pct: 10, color: "#06b6d4" },
  { type: "Email", pct: 4, color: "#10b981" },
];

/* MITRE ATT&CK tactics — bubble chart data */
const MITRE_BUBBLE_DATA = [
  { x: 1, y: 72, z: 180, name: "Recon", id: "TA0043", active: true },
  { x: 2, y: 25, z: 60,  name: "Resource Dev", id: "TA0042", active: false },
  { x: 3, y: 88, z: 240, name: "Initial Access", id: "TA0001", active: true },
  { x: 4, y: 18, z: 45,  name: "Execution", id: "TA0002", active: false },
  { x: 5, y: 65, z: 160, name: "Persistence", id: "TA0003", active: true },
  { x: 6, y: 20, z: 50,  name: "Priv Esc", id: "TA0004", active: false },
  { x: 7, y: 55, z: 140, name: "Def Evasion", id: "TA0005", active: true },
  { x: 8, y: 78, z: 200, name: "Cred Access", id: "TA0006", active: true },
  { x: 9, y: 60, z: 150, name: "Discovery", id: "TA0007", active: true },
  { x: 10, y: 82, z: 220, name: "Lat Movement", id: "TA0008", active: true },
  { x: 11, y: 15, z: 35,  name: "Collection", id: "TA0009", active: false },
  { x: 12, y: 70, z: 190, name: "Exfiltration", id: "TA0010", active: true },
];

/* Kill chain activity */
const KILL_CHAIN = [
  { stage: "RECONNAISSANCE", count: "14/192", pct: 82, color: "bg-orange-500" },
  { stage: "WEAPONIZATION", count: null, pct: 65, color: "bg-orange-400" },
  { stage: "DELIVERY", count: "32/192", pct: 48, color: "bg-orange-500" },
  { stage: "EXPLOITATION", count: null, pct: 45, color: "bg-red-500" },
  { stage: "INSTALLATION", count: "10/83", pct: 31, color: "bg-orange-400" },
  { stage: "C2 INFRASTRUCTURE", count: null, pct: 62, color: "bg-red-500" },
];

/* Threat feeds */
const THREAT_FEEDS = [
  { name: "AlienVault OTX", sync: "3m ago", iocs: 1246, health: "STABLE", hcls: "text-emerald-600 bg-emerald-50" },
  { name: "MISP Community", sync: "12m ago", iocs: 892, health: "STABLE", hcls: "text-emerald-600 bg-emerald-50" },
  { name: "Abuse.ch", sync: "1h ago", iocs: 45, health: "LAGGING", hcls: "text-amber-600 bg-amber-50" },
  { name: "ThreatFox", sync: "5m ago", iocs: 621, health: "STABLE", hcls: "text-emerald-600 bg-emerald-50" },
];

/* Risky entities */
const RISKY_ENTITIES = [
  { name: "jenks_reina", type: "user", label: "Runbook Violation", score: 94, color: "from-red-500 to-orange-500" },
  { name: "koss_theron", type: "user", label: "", score: 82, color: "from-orange-500 to-amber-500" },
  { name: "SVC_SQL_91", type: "host", label: "", score: 76, color: "from-amber-500 to-yellow-500" },
  { name: "WS_0_31", type: "host", label: "", score: 65, color: "from-yellow-500 to-lime-500" },
];

/* Recent critical alerts */
const RECENT_ALERTS = [
  { title: "Suspicious LSASS Memory Dump", desc: "Detected MiniDump of the AD DC lif, host rds/siem/dc 02.example.com", mitre: "T1003.001", time: "14m ago", sev: "CRITICAL" },
  { title: "Unexpected SSH Outbound to Unknown IP", desc: "Host rds/siem ssh reverse to 191.0.12.43.11", mitre: "T1021.004", time: "1h ago", sev: "HIGH" },
];

export default function ThreatIntelPage() {
  const { data, loading, refresh } = usePolling<ThreatIntelResponse>("/api/threat-intel", 30000);
  const [tab, setTab] = useState("iocs");
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("All Types");
  const [confFilter, setConfFilter] = useState(0);
  const [expandedPattern, setExpandedPattern] = useState<string | null>(null);
  const [selectedBubble, setSelectedBubble] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);

  useEffect(() => {
    fetch("/api/ai/investigations/list")
      .then((r) => r.json())
      .then((d) => setInvestigations(Array.isArray(d.investigations) ? d.investigations : []))
      .catch(() => {});
  }, []);

  const iocs = data?.iocs || [];
  const patterns = data?.patterns || [];
  const stats = data?.stats;

  const filteredIOCs = iocs.filter(
    (ioc) =>
      (typeFilter === "All Types" || ioc.type.toLowerCase() === typeFilter.toLowerCase()) &&
      ioc.confidence >= confFilter &&
      (filter === "" ||
        ioc.value.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.type.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.source?.toLowerCase().includes(filter.toLowerCase()) ||
        ioc.tags?.some((t) => t.toLowerCase().includes(filter.toLowerCase())))
  );

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="-m-6 -mt-4">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-primary/10 text-primary text-[11px] font-black uppercase tracking-tighter rounded">Live Intelligence</span>
                <span className="text-muted-foreground text-sm font-medium">Real-time threat monitoring</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                Threat <span className="text-primary inline-block">Intelligence</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">IOC management, threat patterns, MITRE ATT&CK mapping, and AI-driven enrichment across global feeds.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total IOCs</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(stats?.totalIOCs || iocs.length)}</h3>
                <span className="text-emerald-500 text-xs font-bold flex items-center gap-0.5"><Activity className="w-3 h-3" /> +12%</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Active Threats</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-red-500">{formatNumber(stats?.activeThreats || patterns.length)}</h3>
                <span className="text-muted-foreground text-xs font-bold uppercase tracking-tighter">Monitoring</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">MITRE Techniques</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(stats?.mitreTechniques || 42)}</h3>
                <span className="text-red-500 text-xs font-bold flex items-center gap-0.5"><Activity className="w-3 h-3" /> +2</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Last Updated</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">{stats?.lastUpdated ? timeAgo(stats.lastUpdated) : <><span>2</span> <span className="text-lg">mins</span></>}</h3>
                <span className="text-muted-foreground text-[10px] font-bold uppercase tracking-tighter">Real-time sync</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12 items-stretch">
        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* Attack Timeline */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-red-50 text-red-500 rounded-2xl">
                  <Activity className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Attack Timeline (24h)</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">2.4k Total hits detected</p>
                </div>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Critical</span></div>
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-orange-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">High</span></div>
                <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-cyan-400" /><span className="text-[10px] font-black text-muted-foreground uppercase">Medium</span></div>
              </div>
            </div>
            <div className="h-[420px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              <ResponsiveContainer>
                <AreaChart data={TIMELINE_DATA}>
                  <defs>
                    <linearGradient id="critG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#ef4444" stopOpacity={0.4}/><stop offset="100%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                    <linearGradient id="highG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f97316" stopOpacity={0.3}/><stop offset="100%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                    <linearGradient id="medG" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#06b6d4" stopOpacity={0.2}/><stop offset="100%" stopColor="#06b6d4" stopOpacity={0}/></linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                  <XAxis dataKey="hour" tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} interval={3} />
                  <YAxis tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 11 }} />
                  <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critG)" strokeWidth={2} name="Critical" />
                  <Area type="monotone" dataKey="high" stroke="#f97316" fill="url(#highG)" strokeWidth={1.5} name="High" />
                  <Area type="monotone" dataKey="medium" stroke="#06b6d4" fill="url(#medG)" strokeWidth={1} name="Medium" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Threat Feed Status Table */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-slate-900 text-white rounded-2xl">
                  <Wifi className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Threat Feed Status</h3>
              </div>
              <button onClick={refresh} className="text-[11px] font-black text-primary uppercase tracking-[0.2em] hover:underline">Force Sync All</button>
            </div>
            <div className="bg-muted/20 rounded-2xl overflow-hidden border border-border">
              <table className="w-full text-left">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Feed Source</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Last Sync</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">IOCs Pulled</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Health</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {THREAT_FEEDS.map((f) => (
                    <tr key={f.name} className="hover:bg-card transition-colors">
                      <td className="px-6 py-6">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                            <Globe className="w-4 h-4" />
                          </div>
                          <span className="font-bold text-foreground">{f.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-6 text-sm text-muted-foreground">{f.sync}</td>
                      <td className="px-6 py-6 text-sm font-bold text-foreground font-mono">{formatNumber(f.iocs)}</td>
                      <td className="px-6 py-6">
                        <span className={cn("px-3 py-1 text-[10px] font-black rounded uppercase", f.hcls)}>{f.health}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* IOC Matches Table */}
          <section className="px-10 py-10 bg-white border-t border-border">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Shield className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Recent IOC Matches</h3>
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <div className="relative">
                  <Filter className="absolute left-3.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    placeholder="Search threats..."
                    className="w-52 bg-card border border-border rounded-full pl-9 pr-4 py-2 text-sm focus:ring-1 focus:ring-primary/30 focus:outline-none transition-all"
                  />
                </div>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="px-3 py-2 bg-card border border-border rounded-full text-xs font-medium text-foreground outline-none"
                >
                  <option>All Types</option>
                  <option>ipv4</option>
                  <option>domain</option>
                  <option>sha256</option>
                  <option>url</option>
                  <option>email</option>
                </select>
                <select
                  value={confFilter}
                  onChange={(e) => setConfFilter(Number(e.target.value))}
                  className="px-3 py-2 bg-card border border-border rounded-full text-xs font-medium text-foreground outline-none"
                >
                  <option value={0}>All Confidence</option>
                  <option value={80}>Confidence &gt; 80</option>
                  <option value={90}>Confidence &gt; 90</option>
                </select>
                {filter && <button onClick={() => setFilter("")} className="text-[10px] font-black text-primary uppercase tracking-wider hover:underline">Clear</button>}
              </div>
            </div>
            <div className="bg-card rounded-[2.5rem] overflow-hidden border border-border shadow-sm">
              <table className="w-full text-left">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Type</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Value</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Confidence</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Source</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">MITRE</th>
                    <th className="px-5 py-3 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {filteredIOCs.map((ioc, i) => {
                    const IconComp = IOC_ICONS[ioc.type.toLowerCase()] || Shield;
                    return (
                      <tr key={i} className="hover:bg-muted/10 transition-colors">
                        <td className="px-5 py-4">
                          <span className="px-2.5 py-1 bg-slate-900 text-white rounded text-[10px] font-black uppercase flex items-center gap-1.5 w-fit">
                            <IconComp className="h-2.5 w-2.5" />{ioc.type}
                          </span>
                        </td>
                        <td className="px-5 py-4 font-mono text-xs text-muted-foreground max-w-[240px] truncate">{ioc.value}</td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-20 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                              <div className={cn("h-full rounded-full", ioc.confidence >= 90 ? "bg-red-500" : ioc.confidence >= 70 ? "bg-primary" : "bg-amber-400")} style={{ width: `${ioc.confidence}%` }} />
                            </div>
                            <span className="text-xs font-black" style={{ color: ioc.confidence >= 90 ? "#ef4444" : ioc.confidence >= 70 ? "#2563eb" : "#f59e0b" }}>{ioc.confidence}%</span>
                          </div>
                        </td>
                        <td className="px-5 py-4 text-xs text-muted-foreground">{ioc.source || "—"}</td>
                        <td className="px-5 py-4">
                          {ioc.mitre ? <span className="px-2.5 py-1 bg-indigo-50 text-indigo-600 text-[10px] font-black rounded uppercase">{ioc.mitre}</span> : "—"}
                        </td>
                        <td className="px-5 py-4 text-xs text-muted-foreground">{ioc.lastSeen ? timeAgo(ioc.lastSeen) : "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {filteredIOCs.length === 0 && (
                <div className="py-16 text-center text-sm text-muted-foreground">
                  {filter || typeFilter !== "All Types" || confFilter > 0 ? "No IOCs match your filters" : "No IOCs available"}
                </div>
              )}
            </div>
          </section>

          {/* Threat Patterns + Investigation Matches side by side — fills remaining height */}
          <section className="px-10 py-10 bg-white border-t border-border flex-1 overflow-y-auto">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-10 h-full">
              {/* Threat Patterns */}
              <div className="flex flex-col">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-orange-50 text-orange-500 rounded-2xl">
                    <Target className="w-5 h-5" />
                  </div>
                  <h3 className="text-2xl font-extrabold text-foreground">Threat Patterns</h3>
                </div>
                <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
                  {patterns.length > 0 ? patterns.map((pattern, idx) => (
                    <div key={idx} className="bg-muted/20 rounded-2xl p-5 border border-border hover:border-primary/30 transition-all cursor-pointer group"
                      onClick={() => setExpandedPattern(expandedPattern === pattern.name ? null : pattern.name)}>
                      <div className="flex items-start gap-4">
                        <div className={cn("flex h-9 w-9 shrink-0 items-center justify-center rounded-xl mt-0.5", pattern.severity >= 4 ? "bg-red-50 text-red-500" : "bg-orange-50 text-orange-500")}>
                          <Target className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", pattern.severity >= 4 ? "bg-red-50 text-red-600" : "bg-orange-50 text-orange-600")}>
                              {pattern.severity >= 4 ? "CRITICAL" : "HIGH"} · {pattern.mitre}
                            </span>
                          </div>
                          <h4 className="text-sm font-bold text-foreground group-hover:text-primary transition-colors">{pattern.name}</h4>
                          <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{pattern.description}</p>
                          <div className="flex items-center gap-4 mt-2">
                            <span className="flex items-center gap-1 text-[10px] font-bold text-muted-foreground">
                              <Shield className="h-2.5 w-2.5" /> {pattern.iocCount} Indicators
                            </span>
                            <span className="flex items-center gap-1 text-[10px] font-bold text-muted-foreground">
                              <Activity className="h-2.5 w-2.5" /> {pattern.matchedEvents} events
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )) : (
                    <div className="bg-muted/20 rounded-2xl p-12 border border-border text-center">
                      <p className="text-sm text-muted-foreground">No threat patterns available</p>
                    </div>
                  )}
                </div>
              </div>

              {/* Investigation Matches */}
              <div className="flex flex-col">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-4">
                    <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                      <Link2 className="w-5 h-5" />
                    </div>
                    <h3 className="text-2xl font-extrabold text-foreground">Investigation Matches</h3>
                  </div>
                  <Link href="/investigations" className="text-[11px] font-black text-primary uppercase tracking-widest hover:underline">View All</Link>
                </div>
                {investigations.length > 0 ? (
                  <div className="space-y-3">
                    {investigations.slice(0, 4).map((inv) => (
                      <Link key={inv.id} href={`/investigations/${inv.id}`}>
                        <div className="bg-muted/20 rounded-2xl p-5 border border-border hover:border-primary/30 transition-all cursor-pointer group flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", inv.severity >= 4 ? "bg-red-50 text-red-600" : inv.severity >= 3 ? "bg-orange-50 text-orange-600" : "bg-amber-50 text-amber-600")}>S{inv.severity}</span>
                            <div>
                              <p className="text-sm font-bold text-foreground group-hover:text-primary transition-colors line-clamp-1">{inv.title}</p>
                              <div className="flex items-center gap-2 mt-1">
                                <span className="text-[10px] text-muted-foreground font-bold">{inv.eventCount} events</span>
                                {inv.tags?.slice(0, 2).map((t) => (
                                  <span key={t} className="px-2 py-0.5 bg-indigo-50 text-indigo-600 text-[9px] font-black rounded uppercase">{t}</span>
                                ))}
                              </div>
                            </div>
                          </div>
                          <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-primary transition-colors" />
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="bg-muted/20 rounded-2xl p-12 border border-border text-center">
                    <p className="text-sm text-muted-foreground">No active investigations</p>
                  </div>
                )}
              </div>
            </div>
          </section>

        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 space-y-10">

          {/* IOC Type Distribution */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-card shadow-sm text-primary rounded-xl flex items-center justify-center border border-border">
                <Eye className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">IOC Type Distribution</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-5">
              {TYPE_DIST.map((t) => (
                <div key={t.type} className="space-y-2">
                  <div className="flex justify-between text-[10px] font-black text-muted-foreground uppercase tracking-widest">
                    <span>{t.type}</span>
                    <span className="text-foreground">{t.pct}%</span>
                  </div>
                  <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${t.pct}%`, background: t.color }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* Kill Chain Activity */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="p-2.5 bg-orange-50 text-orange-500 rounded-xl">
                <Zap className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Cyber Kill Chain</h3>
            </div>
            <div className="bg-card rounded-2xl p-6 border border-border shadow-sm space-y-4">
              {KILL_CHAIN.map((k) => (
                <div key={k.stage}>
                  <div className="flex justify-between text-[10px] font-bold text-muted-foreground uppercase mb-1.5">
                    <span>{k.stage}</span>
                    <span className="text-foreground">{k.count || `${k.pct}%`}</span>
                  </div>
                  <div className="h-2 w-full bg-muted/30 rounded-full overflow-hidden">
                    <div className={cn("h-full rounded-full", k.color)} style={{ width: `${k.pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* High-Risk Entities */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="w-10 h-10 bg-red-50 text-red-500 rounded-xl flex items-center justify-center">
                <AlertCircle className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">High-Risk Entities</h3>
            </div>
            <div className="space-y-3">
              {RISKY_ENTITIES.map((e) => (
                <div key={e.name} className="bg-card rounded-2xl p-5 border border-border shadow-sm flex items-center justify-between hover:border-primary/30 transition-all">
                  <div className="flex items-center gap-3">
                    <div className={cn("h-9 w-9 rounded-full flex items-center justify-center bg-gradient-to-br text-white text-[10px] font-bold", e.color)}>
                      {e.type === "user" ? <User className="h-3.5 w-3.5" /> : <Monitor className="h-3.5 w-3.5" />}
                    </div>
                    <div>
                      <p className="text-xs font-bold text-foreground">{e.name}</p>
                      {e.label && <p className="text-[10px] text-muted-foreground">{e.label}</p>}
                    </div>
                  </div>
                  <span className={cn("text-lg font-extrabold tabular-nums", e.score >= 90 ? "text-red-500" : e.score >= 70 ? "text-orange-500" : "text-amber-500")}>{e.score}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Critical Alerts */}
          <section>
            <div className="flex items-center justify-between mb-6 px-2">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-card shadow-sm text-red-500 rounded-xl flex items-center justify-center border border-border">
                  <AlertTriangle className="w-5 h-5" />
                </div>
                <h3 className="text-lg font-extrabold text-foreground">Critical Alerts</h3>
              </div>
              <Link href="/investigations" className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">View All</Link>
            </div>
            <div className="space-y-3">
              {RECENT_ALERTS.map((a) => (
                <div key={a.title} className="bg-card rounded-2xl p-5 border border-border shadow-sm hover:border-primary/30 transition-all cursor-pointer group">
                  <div className="flex justify-between items-start mb-3">
                    <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded", a.sev === "CRITICAL" ? "bg-red-50 text-red-600" : "bg-primary/10 text-primary")}>{a.sev}</span>
                    <span className="text-[10px] font-bold text-muted-foreground">{a.time}</span>
                  </div>
                  <h4 className="font-bold text-foreground text-sm mb-1 group-hover:text-primary transition-colors">{a.title}</h4>
                  <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{a.desc}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <span className="px-2.5 py-1 bg-indigo-50 text-indigo-600 text-[10px] font-black rounded uppercase">{a.mitre}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          {/* MITRE ATT&CK Tactic Bubbles */}
          <section>
            <div className="flex items-center gap-3 mb-6 px-2">
              <div className="p-2.5 bg-indigo-50 text-indigo-600 rounded-xl">
                <Target className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-lg font-extrabold text-foreground">MITRE ATT&CK Tactics</h3>
                <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest">{MITRE_BUBBLE_DATA.filter(t => t.active).length} Active · {MITRE_BUBBLE_DATA.filter(t => !t.active).length} Inactive</p>
              </div>
            </div>
            <div className="bg-white rounded-2xl p-6 border border-border shadow-sm">
              {/* Packed bubble cluster */}
              {(() => {
                const sorted = [...MITRE_BUBBLE_DATA].sort((a, b) => b.z - a.z);
                const radii = sorted.map(t => Math.max(26, Math.round(t.z / 6.4)));
                // Simple circle-packing: place each circle touching previously placed ones
                const positions: { x: number; y: number; r: number; data: typeof MITRE_BUBBLE_DATA[0] }[] = [];
                sorted.forEach((t, i) => {
                  const r = radii[i];
                  if (i === 0) {
                    positions.push({ x: 0, y: 0, r, data: t });
                  } else {
                    let bestX = 0, bestY = 0, bestDist = Infinity;
                    // Try placing against each existing circle at multiple angles
                    for (const p of positions) {
                      for (let a = 0; a < 360; a += 15) {
                        const rad = (a * Math.PI) / 180;
                        const dist = p.r + r + 2;
                        const cx = p.x + Math.cos(rad) * dist;
                        const cy = p.y + Math.sin(rad) * dist;
                        // Check no overlap with any existing
                        let valid = true;
                        for (const q of positions) {
                          const dx = cx - q.x, dy = cy - q.y;
                          if (Math.sqrt(dx * dx + dy * dy) < q.r + r + 1) { valid = false; break; }
                        }
                        if (valid) {
                          const d = Math.sqrt(cx * cx + cy * cy);
                          if (d < bestDist) { bestDist = d; bestX = cx; bestY = cy; }
                        }
                      }
                    }
                    positions.push({ x: bestX, y: bestY, r, data: t });
                  }
                });
                // Compute bounding box & center
                const minX = Math.min(...positions.map(p => p.x - p.r));
                const maxX = Math.max(...positions.map(p => p.x + p.r));
                const minY = Math.min(...positions.map(p => p.y - p.r));
                const maxY = Math.max(...positions.map(p => p.y + p.r));
                const w = maxX - minX;
                const h = maxY - minY;
                const cx = (minX + maxX) / 2;
                const cy = (minY + maxY) / 2;

                return (
                  <div className="relative mx-auto" style={{ width: Math.max(w + 20, 260), height: Math.max(h + 20, 260) }}>
                    {positions.map((p) => {
                      const t = p.data;
                      const size = p.r * 2;
                      const isSelected = selectedBubble === t.id;
                      return (
                        <div
                          key={t.id}
                          onClick={() => setSelectedBubble(isSelected ? null : t.id)}
                          className={cn(
                            "absolute rounded-full flex flex-col items-center justify-center cursor-pointer transition-all duration-300 select-none",
                            t.active
                              ? isSelected
                                ? "bg-primary text-white shadow-lg shadow-primary/30 z-10 scale-110"
                                : "bg-primary/10 text-primary hover:bg-primary/20 hover:scale-105 hover:z-10"
                              : isSelected
                                ? "bg-muted text-foreground shadow-md z-10 scale-110"
                                : "bg-muted/40 text-muted-foreground hover:bg-muted/60 hover:scale-105 hover:z-10 border border-border/50"
                          )}
                          style={{
                            width: size,
                            height: size,
                            left: p.x - cx + (Math.max(w + 20, 260)) / 2 - p.r,
                            top: p.y - cy + (Math.max(h + 20, 260)) / 2 - p.r,
                          }}
                        >
                          <span className="font-extrabold leading-none" style={{ fontSize: Math.max(10, size / 4) }}>{t.y}</span>
                          <span className={cn("font-black uppercase leading-tight text-center px-1 mt-0.5", size >= 60 ? "text-[7px]" : "text-[6px]")}>{t.name}</span>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}

              {/* Detail panel for selected bubble */}
              {selectedBubble && (() => {
                const t = MITRE_BUBBLE_DATA.find(b => b.id === selectedBubble);
                if (!t) return null;
                return (
                  <div className="mt-4 pt-4 border-t border-border animate-in fade-in slide-in-from-top-2 duration-200">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-bold text-foreground">{t.name}</p>
                        <p className="text-[10px] text-muted-foreground font-bold uppercase tracking-wider">{t.id}</p>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-extrabold text-primary">{t.y}</div>
                        <div className="text-[8px] font-black text-muted-foreground uppercase">Detections</div>
                      </div>
                    </div>
                    <div className="mt-3 h-1.5 w-full bg-muted/30 rounded-full overflow-hidden">
                      <div className={cn("h-full rounded-full transition-all duration-500", t.active ? "bg-primary" : "bg-muted-foreground/40")} style={{ width: `${t.y}%` }} />
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      <span className={cn("px-2 py-0.5 text-[9px] font-black rounded uppercase", t.active ? "bg-emerald-50 text-emerald-600" : "bg-muted text-muted-foreground")}>{t.active ? "Active" : "Inactive"}</span>
                      <span className="text-[9px] text-muted-foreground">{t.z} total events</span>
                    </div>
                  </div>
                );
              })()}
            </div>
          </section>

        </aside>
      </div>


    </div>
  );
}
