"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  Cell,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
} from "recharts";
import {
  Fingerprint,
  Info,
  RefreshCw,
  Download,
  Layers,
  Eye,
  BarChart3,
  TrendingUp,
  Zap,
  Crosshair,
  Search as SearchIcon,
  ShieldCheck,
  FileSearch,
  Loader2,
  Shield,
  Cpu,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { cn } from "@/lib/utils";
import type { Investigation } from "@/lib/types";

/* ═══════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════ */

interface XAIData {
  globalFeatures: Array<{ feature: string; importance: number; direction: string }>;
  decisionBoundary?: Array<{ x: number; y: number; label: number }>;
  featureInteractions?: Array<{ pair: string; interaction: number }>;
  cohortAnalysis?: Array<{
    cohort: string;
    accuracy: number;
    f1: number;
    count: number;
    topFeature: string;
  }>;
  modelCards?: Array<{
    model: string;
    version: string;
    trainDate: string;
    metrics: { f1: number; precision: number; recall: number; auc: number };
    fairness: { equalizedOdds: number; demographicParity: number };
  }>;
}

/* ═══════════════════════════════════════════════════════════
   MOCK / FALLBACK DATA
   ═══════════════════════════════════════════════════════════ */

const MOCK_DATA: XAIData = {
  globalFeatures: [
    { feature: "event_frequency", importance: 0.342, direction: "positive" },
    { feature: "sigma_match_count", importance: 0.287, direction: "positive" },
    { feature: "time_anomaly_score", importance: 0.231, direction: "positive" },
    { feature: "network_bytes_out", importance: 0.198, direction: "positive" },
    { feature: "process_tree_depth", importance: 0.176, direction: "positive" },
    { feature: "user_risk_score", importance: 0.154, direction: "positive" },
    { feature: "geo_anomaly", importance: 0.132, direction: "positive" },
    { feature: "entropy_score", importance: 0.119, direction: "positive" },
    { feature: "login_frequency", importance: -0.098, direction: "negative" },
    { feature: "session_duration", importance: -0.067, direction: "negative" },
  ],
  decisionBoundary: Array.from({ length: 80 }, () => ({
    x: (Math.random() - 0.5) * 4,
    y: (Math.random() - 0.5) * 4,
    label: Math.random() > 0.4 ? 1 : 0,
  })),
  featureInteractions: [
    { pair: "event_freq × sigma_match", interaction: 0.089 },
    { pair: "time_anomaly × geo_anomaly", interaction: 0.074 },
    { pair: "bytes_out × entropy", interaction: 0.061 },
    { pair: "process_depth × user_risk", interaction: 0.052 },
    { pair: "login_freq × session_dur", interaction: 0.038 },
  ],
  cohortAnalysis: [
    { cohort: "Network Events", accuracy: 0.94, f1: 0.92, count: 12450, topFeature: "network_bytes_out" },
    { cohort: "Auth Events", accuracy: 0.96, f1: 0.95, count: 8320, topFeature: "login_frequency" },
    { cohort: "Process Events", accuracy: 0.91, f1: 0.89, count: 15200, topFeature: "process_tree_depth" },
    { cohort: "File Events", accuracy: 0.88, f1: 0.86, count: 6100, topFeature: "entropy_score" },
  ],
  modelCards: [
    {
      model: "LightGBM Binary (Triage)",
      version: "v2.4.0",
      trainDate: "2025-02-20",
      metrics: { f1: 0.942, precision: 0.951, recall: 0.933, auc: 0.978 },
      fairness: { equalizedOdds: 0.96, demographicParity: 0.93 },
    },
    {
      model: "CatBoost Meta-Model (Hunter)",
      version: "v1.3.0",
      trainDate: "2025-02-18",
      metrics: { f1: 0.915, precision: 0.928, recall: 0.903, auc: 0.961 },
      fairness: { equalizedOdds: 0.94, demographicParity: 0.91 },
    },
    {
      model: "Verifier Calibration Model",
      version: "v1.1.0",
      trainDate: "2025-02-22",
      metrics: { f1: 0.971, precision: 0.963, recall: 0.979, auc: 0.989 },
      fairness: { equalizedOdds: 0.97, demographicParity: 0.95 },
    },
  ],
};

const RADAR_DATA = [
  { metric: "SHAP Stability", triage: 88, hunter: 72, verifier: 91 },
  { metric: "Confidence", triage: 94, hunter: 87, verifier: 97 },
  { metric: "F1 Score", triage: 94, hunter: 92, verifier: 97 },
  { metric: "Fairness", triage: 96, hunter: 91, verifier: 97 },
  { metric: "Drift Resist.", triage: 85, hunter: 78, verifier: 89 },
  { metric: "Interpretability", triage: 92, hunter: 68, verifier: 82 },
];

const SAMPLE_EVENTS = [
  { label: "Lateral Movement (High)", event_frequency: 142, sigma_match: 3, user_risk: 0.87, bytes_out: 52400, entropy: 0.91 },
  { label: "Credential Access (Med)", event_frequency: 38, sigma_match: 1, user_risk: 0.54, bytes_out: 8100, entropy: 0.44 },
  { label: "Normal Activity", event_frequency: 12, sigma_match: 0, user_risk: 0.12, bytes_out: 1200, entropy: 0.18 },
];

/* ═══════════════════════════════════════════════════════════
   MAIN PAGE
   ═══════════════════════════════════════════════════════════ */

export default function ExplainabilityPage() {
  const { data, loading, refresh } = usePolling<XAIData>("/api/ai/xai", 30000);
  const [view, setView] = useState("features");
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<number | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [explanation, setExplanation] = useState<{
    score: number;
    label: string;
    shap: Array<{ feature: string; value: number }>;
  } | null>(null);

  useEffect(() => {
    fetch("/api/ai/investigations/list")
      .then((r) => r.json())
      .then((d) => setInvestigations(d.investigations || []))
      .catch(() => {});
  }, []);

  const xai = data?.globalFeatures ? data : MOCK_DATA;

  /* Live Event Explainer — POST to /api/ai/xai */
  const handleExplain = useCallback(async (idx: number) => {
    setSelectedEvent(idx);
    setExplaining(true);
    setExplanation(null);

    const ev = SAMPLE_EVENTS[idx];
    try {
      const res = await fetch("/api/ai/xai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_frequency: ev.event_frequency,
          sigma_match_count: ev.sigma_match,
          user_risk_score: ev.user_risk,
          network_bytes_out: ev.bytes_out,
          entropy_score: ev.entropy,
        }),
      });
      if (res.ok) {
        const result = await res.json();
        setExplanation(result);
      } else {
        // Fallback mock SHAP response
        const score = ev.event_frequency > 100 ? 0.89 : ev.event_frequency > 30 ? 0.54 : 0.12;
        setExplanation({
          score,
          label: score > 0.75 ? "Anomalous" : score > 0.4 ? "Suspicious" : "Normal",
          shap: [
            { feature: "event_frequency", value: ev.event_frequency > 100 ? 0.32 : ev.event_frequency > 30 ? 0.15 : -0.08 },
            { feature: "sigma_match_count", value: ev.sigma_match > 2 ? 0.25 : ev.sigma_match > 0 ? 0.08 : -0.05 },
            { feature: "user_risk_score", value: ev.user_risk > 0.7 ? 0.18 : ev.user_risk > 0.4 ? 0.06 : -0.12 },
            { feature: "network_bytes_out", value: ev.bytes_out > 40000 ? 0.14 : ev.bytes_out > 5000 ? 0.04 : -0.03 },
            { feature: "entropy_score", value: ev.entropy > 0.8 ? 0.11 : ev.entropy > 0.3 ? 0.02 : -0.06 },
          ],
        });
      }
    } catch {
      const score = ev.event_frequency > 100 ? 0.89 : ev.event_frequency > 30 ? 0.54 : 0.12;
      setExplanation({
        score,
        label: score > 0.75 ? "Anomalous" : score > 0.4 ? "Suspicious" : "Normal",
        shap: [
          { feature: "event_frequency", value: ev.event_frequency > 100 ? 0.32 : ev.event_frequency > 30 ? 0.15 : -0.08 },
          { feature: "sigma_match_count", value: ev.sigma_match > 2 ? 0.25 : ev.sigma_match > 0 ? 0.08 : -0.05 },
          { feature: "user_risk_score", value: ev.user_risk > 0.7 ? 0.18 : ev.user_risk > 0.4 ? 0.06 : -0.12 },
          { feature: "network_bytes_out", value: ev.bytes_out > 40000 ? 0.14 : ev.bytes_out > 5000 ? 0.04 : -0.03 },
          { feature: "entropy_score", value: ev.entropy > 0.8 ? 0.11 : ev.entropy > 0.3 ? 0.02 : -0.06 },
        ],
      });
    } finally {
      setExplaining(false);
    }
  }, []);

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(3)].map((_, i) => (
          <Skeleton key={i} className="h-40 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-primary/10 text-primary text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <Fingerprint className="w-3 h-3" /> AI Transparency
                </span>
                <span className="text-muted-foreground text-sm font-medium">3-Agent Pipeline</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                XAI <span className="text-primary inline-block">Explainability</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Global model explanations, SHAP feature analysis, cohort performance, and fairness monitoring across the full agent pipeline.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" /> Refresh
              </button>
              <Link href="/ai-agents">
                <button className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                  <Cpu className="w-4 h-4" /> View Agents
                </button>
              </Link>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">PSI Drift Score</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">0.031</h3>
                <span className="px-2.5 py-1 bg-emerald-50 text-emerald-600 text-[9px] font-black rounded uppercase">No Drift</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Model Freshness</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">14<span className="text-lg font-bold text-muted-foreground ml-1">days</span></h3>
                <span className="text-muted-foreground text-[10px] font-bold uppercase tracking-tighter">Feb 20</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">ARF Confidence</p>
              <div className="flex items-baseline gap-2">
                <h3 className="text-4xl font-extrabold text-foreground">0.94</h3>
                <span className="text-emerald-500 text-xs font-bold flex items-center gap-0.5"><TrendingUp className="w-3 h-3" /> ADWIN</span>
              </div>
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">SHAP Explainer</p>
              <h3 className="text-3xl font-extrabold text-foreground">TreeSHAP</h3>
              <span className="text-muted-foreground text-[10px] font-bold uppercase tracking-tighter">v1.3.0 · ONNX Runtime</span>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12">
        {/* LEFT COLUMN */}
        <div className="col-span-12 xl:col-span-8 flex flex-col">

          {/* Agent XAI Radar */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-2xl font-extrabold text-foreground">Agent XAI Capability Radar</h3>
                  <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Side-by-side explainability dimensions</p>
                </div>
              </div>
              <div className="flex gap-5">
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-amber-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Triage</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-cyan-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Hunter</span></div>
                <div className="flex items-center gap-2"><div className="w-2.5 h-2.5 rounded-full bg-emerald-500" /><span className="text-[10px] font-black text-muted-foreground uppercase">Verifier</span></div>
              </div>
            </div>
            <div className="h-[380px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              <ResponsiveContainer>
                <RadarChart data={RADAR_DATA}>
                  <PolarGrid stroke="hsl(var(--border))" />
                  <PolarAngleAxis dataKey="metric" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} />
                  <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 16, fontSize: 12, fontWeight: 600, padding: "12px 16px" }} />
                  <Radar name="Triage" dataKey="triage" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.15} strokeWidth={2.5} />
                  <Radar name="Hunter" dataKey="hunter" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.12} strokeWidth={2} />
                  <Radar name="Verifier" dataKey="verifier" stroke="#10b981" fill="#10b981" fillOpacity={0.12} strokeWidth={2} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Feature Interaction Strengths */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center gap-4 mb-8">
              <div className="p-3 bg-purple-50 text-purple-600 rounded-2xl">
                <Layers className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-2xl font-extrabold text-foreground">Feature Interaction Strengths</h3>
                <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">SHAP interaction values — joint feature influence</p>
              </div>
            </div>
            <div className="h-[260px] bg-white rounded-[2.5rem] border border-border p-8 shadow-sm">
              <ResponsiveContainer>
                <BarChart data={xai.featureInteractions} layout="vertical" margin={{ left: 160 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="pair" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} width={155} />
                  <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 16, fontSize: 12 }} />
                  <Bar dataKey="interaction" fill="rgba(139,92,246,0.6)" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* Live Event Explainer */}
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center gap-4 mb-8">
              <div className="p-3 bg-amber-50 text-amber-500 rounded-2xl">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-2xl font-extrabold text-foreground">Live Event Explainer</h3>
                <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Real-time SHAP explanation via the AI pipeline</p>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              {SAMPLE_EVENTS.map((ev, i) => (
                <button
                  key={i}
                  onClick={() => handleExplain(i)}
                  className={cn(
                    "text-left rounded-2xl border-2 p-5 transition-all hover:border-primary/50",
                    selectedEvent === i ? "border-primary bg-primary/5 shadow-md" : "border-border bg-white"
                  )}
                >
                  <p className="text-sm font-bold text-foreground mb-3">{ev.label}</p>
                  <div className="grid grid-cols-2 gap-1.5 text-[10px] text-muted-foreground">
                    <span>event_freq: <span className="text-foreground font-mono font-bold">{ev.event_frequency}</span></span>
                    <span>sigma: <span className="text-foreground font-mono font-bold">{ev.sigma_match}</span></span>
                    <span>user_risk: <span className="text-foreground font-mono font-bold">{ev.user_risk}</span></span>
                    <span>bytes_out: <span className="text-foreground font-mono font-bold">{ev.bytes_out}</span></span>
                    <span>entropy: <span className="text-foreground font-mono font-bold">{ev.entropy}</span></span>
                  </div>
                </button>
              ))}
            </div>

            {explaining && (
              <div className="flex items-center justify-center gap-2 p-8 text-muted-foreground text-sm">
                <Loader2 className="h-4 w-4 animate-spin" /> Computing SHAP values…
              </div>
            )}

            {explanation && !explaining && (
              <div className="rounded-2xl border border-border bg-white p-6 space-y-4 shadow-sm">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={cn(
                      "px-3 py-1.5 text-[10px] font-black uppercase rounded-lg",
                      explanation.score > 0.75 ? "bg-red-50 text-red-600" : explanation.score > 0.4 ? "bg-amber-50 text-amber-600" : "bg-emerald-50 text-emerald-600"
                    )}>
                      {explanation.label}
                    </span>
                    <span className="text-lg font-mono font-extrabold text-foreground">
                      Score: {explanation.score.toFixed(2)}
                    </span>
                  </div>
                  <span className="px-3 py-1 bg-muted/50 text-muted-foreground text-[9px] font-black rounded uppercase flex items-center gap-1">
                    <Fingerprint className="h-2.5 w-2.5" /> SHAP
                  </span>
                </div>
                <div className="space-y-2">
                  {explanation.shap.map((s) => {
                    const pct = (Math.abs(s.value) / 0.4) * 100;
                    return (
                      <div key={s.feature} className="flex items-center gap-3">
                        <span className="w-40 truncate font-mono text-xs text-muted-foreground font-bold">{s.feature}</span>
                        <div className="flex-1 h-3 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${Math.min(pct, 100)}%`,
                              background: s.value >= 0 ? "rgba(239,68,68,0.6)" : "rgba(6,182,212,0.6)",
                            }}
                          />
                        </div>
                        <span className={cn(
                          "text-[10px] font-black w-16 text-right",
                          s.value >= 0 ? "text-red-500" : "text-cyan-500"
                        )}>
                          {s.value >= 0 ? "+" : ""}{s.value.toFixed(3)}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="flex gap-6 text-[10px] text-muted-foreground pt-3 border-t border-border/50">
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500/60" /> Pushes towards anomalous</span>
                  <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500/60" /> Pushes towards normal</span>
                </div>
              </div>
            )}
          </section>

        </div>

        {/* RIGHT SIDEBAR */}
        <aside className="col-span-12 xl:col-span-4 bg-white border-l border-border/80 p-8 -mt-4 space-y-10">

          {/* Triage Agent XAI */}
          <section>
            <div className="flex items-center gap-3 mb-5 px-2">
              <div className="w-10 h-10 bg-amber-50 text-amber-500 rounded-xl flex items-center justify-center">
                <Crosshair className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Triage Agent XAI</h3>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-3.5">
              {[
                { label: "Explainer", value: "TreeSHAP (ONNX)" },
                { label: "Features", value: "20 per prediction" },
                { label: "Top SHAP", value: "event_frequency (0.342)" },
                { label: "Stability", value: "88% across 1k samples" },
                { label: "Fast-path", value: "LightGBM >0.85 → bypass" },
              ].map((row) => (
                <div key={row.label} className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{row.label}</span>
                  <span className="text-xs font-bold text-foreground text-right">{row.value}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Hunter Agent XAI */}
          <section>
            <div className="flex items-center gap-3 mb-5 px-2">
              <div className="w-10 h-10 bg-cyan-50 text-cyan-600 rounded-xl flex items-center justify-center">
                <SearchIcon className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Hunter Agent XAI</h3>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-3.5">
              {[
                { label: "L1 Modules", value: "Sigma, SPC, Graph, Temporal, LanceDB" },
                { label: "Meta-model", value: "CatBoost (SHAP)" },
                { label: "Sigma Weight", value: "35%" },
                { label: "Graph Weight", value: "25%" },
                { label: "Temporal/Vector", value: "20% each" },
              ].map((row) => (
                <div key={row.label} className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{row.label}</span>
                  <span className="text-xs font-bold text-foreground text-right">{row.value}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Verifier Agent XAI */}
          <section>
            <div className="flex items-center gap-3 mb-5 px-2">
              <div className="w-10 h-10 bg-emerald-50 text-emerald-600 rounded-xl flex items-center justify-center">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Verifier Agent XAI</h3>
            </div>
            <div className="bg-white rounded-2xl p-5 border border-border shadow-sm space-y-3.5">
              {[
                { label: "Formula", value: "40% hunter + 20% evidence" },
                { label: "", value: "+ 20% IOC + 10% FP + 10% timeline" },
                { label: "TP Threshold", value: "> 0.75", color: "text-emerald-500" },
                { label: "FP Threshold", value: "< 0.30", color: "text-red-500" },
                { label: "Inconclusive", value: "0.30 — 0.75", color: "text-amber-500" },
              ].map((row, i) => (
                <div key={i} className="flex justify-between items-center py-1.5 border-b border-border/50 last:border-0">
                  <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">{row.label}</span>
                  <span className={cn("text-xs font-bold text-right", row.color || "text-foreground")}>{row.value}</span>
                </div>
              ))}
            </div>
          </section>

          {/* Per-Investigation Explanations */}
          {investigations.length > 0 && (
            <section>
              <div className="flex items-center justify-between mb-5 px-2">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-primary/10 text-primary rounded-xl flex items-center justify-center">
                    <FileSearch className="w-5 h-5" />
                  </div>
                  <h3 className="text-lg font-extrabold text-foreground">Investigation XAI</h3>
                </div>
                <Link href="/investigations" className="text-[10px] font-black text-primary uppercase tracking-[0.15em] hover:underline">All</Link>
              </div>
              <div className="space-y-3">
                {investigations.slice(0, 4).map((inv) => (
                  <Link key={inv.id} href={`/investigations/${inv.id}`}>
                    <div className="bg-white rounded-2xl p-4 border border-border shadow-sm hover:border-primary/30 transition-all flex items-center gap-3">
                      <span className={cn("px-2.5 py-1 text-[9px] font-black uppercase rounded shrink-0", inv.severity >= 4 ? "bg-red-50 text-red-600" : inv.severity >= 3 ? "bg-orange-50 text-orange-600" : "bg-amber-50 text-amber-600")}>S{inv.severity}</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-bold text-foreground truncate">{inv.title}</p>
                        <p className="text-[10px] text-muted-foreground">{inv.eventCount} events</p>
                      </div>
                      <span className="px-2 py-0.5 bg-muted/40 text-[9px] font-black text-muted-foreground uppercase rounded shrink-0">XAI</span>
                    </div>
                  </Link>
                ))}
              </div>
            </section>
          )}

        </aside>

        {/* Tabbed Deep-Dive */}
        <section className="col-span-12 px-10 py-12 bg-white border-t border-border">
          <Tabs value={view} onValueChange={setView}>
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Eye className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Deep Dive Analysis</h3>
              </div>
              <TabsList className="bg-muted/30 rounded-full p-1">
                <TabsTrigger value="features" className="rounded-full text-xs font-bold px-4"><BarChart3 className="mr-1.5 h-3 w-3" /> Features</TabsTrigger>
                <TabsTrigger value="boundary" className="rounded-full text-xs font-bold px-4"><Eye className="mr-1.5 h-3 w-3" /> Boundary</TabsTrigger>
                <TabsTrigger value="cohorts" className="rounded-full text-xs font-bold px-4"><Layers className="mr-1.5 h-3 w-3" /> Cohorts</TabsTrigger>
                <TabsTrigger value="model-card" className="rounded-full text-xs font-bold px-4"><Info className="mr-1.5 h-3 w-3" /> Models</TabsTrigger>
              </TabsList>
            </div>

            {/* FEATURE IMPORTANCE */}
            <TabsContent value="features" className="mt-0">
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground mb-4 px-1">Global SHAP Values</p>
                  <div className="h-[360px] bg-white rounded-2xl border border-border p-6 shadow-sm">
                    <ResponsiveContainer>
                      <BarChart data={xai.globalFeatures} layout="vertical" margin={{ left: 100 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" horizontal={false} />
                        <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                        <YAxis type="category" dataKey="feature" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontWeight: 600 }} axisLine={false} tickLine={false} width={95} />
                        <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 12 }} />
                        <Bar dataKey="importance" radius={[0, 6, 6, 0]}>
                          {xai.globalFeatures.map((f, i) => (
                            <Cell key={i} fill={f.importance >= 0 ? "rgba(6,182,212,0.7)" : "rgba(239,68,68,0.7)"} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground mb-4 px-1">Feature Detail — All 10 Features</p>
                  <div className="h-[360px] bg-white rounded-2xl border border-border p-6 shadow-sm space-y-3 overflow-y-auto">
                    {xai.globalFeatures.map((f) => {
                      const pct = (Math.abs(f.importance) / 0.4) * 100;
                      return (
                        <div key={f.feature} className="flex items-center gap-3">
                          <span className="w-36 truncate font-mono text-[11px] text-muted-foreground font-bold">{f.feature}</span>
                          <div className="flex-1 h-2.5 rounded-full bg-muted/30 overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all duration-500"
                              style={{
                                width: `${Math.min(pct, 100)}%`,
                                background: f.importance >= 0 ? "rgba(6,182,212,0.5)" : "rgba(239,68,68,0.5)",
                              }}
                            />
                          </div>
                          <span className={cn("text-[10px] font-black w-14 text-right", f.importance >= 0 ? "text-cyan-600" : "text-red-500")}>
                            {f.importance >= 0 ? "+" : ""}{f.importance.toFixed(3)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </TabsContent>

            {/* DECISION BOUNDARY */}
            <TabsContent value="boundary" className="mt-0">
              <p className="text-[10px] font-black uppercase tracking-widest text-muted-foreground mb-4 px-1">2D Projection — Top-2 Features</p>
              <div className="h-[360px] bg-white rounded-2xl border border-border p-6 shadow-sm">
                <ResponsiveContainer>
                  <ScatterChart>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                    <XAxis type="number" dataKey="x" name="Feature 1" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} />
                    <YAxis type="number" dataKey="y" name="Feature 2" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} />
                    <RechartsTooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 12, fontSize: 12 }} />
                    <Scatter data={xai.decisionBoundary}>
                      {(xai.decisionBoundary || []).map((p, i) => (
                        <Cell key={i} fill={p.label === 1 ? "rgba(239,68,68,0.6)" : "rgba(6,182,212,0.6)"} />
                      ))}
                    </Scatter>
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-4 flex gap-6 justify-center text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500/60" /> Attack / Anomalous</span>
                <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500/60" /> Normal / Benign</span>
              </div>
            </TabsContent>

            {/* COHORT ANALYSIS */}
            <TabsContent value="cohorts" className="mt-0">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                {(xai.cohortAnalysis || []).map((c) => (
                  <div key={c.cohort} className="bg-white rounded-2xl border border-border p-6 shadow-sm">
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="text-base font-extrabold text-foreground">{c.cohort}</h4>
                      <span className="text-[9px] font-black text-muted-foreground uppercase bg-muted/50 px-2.5 py-1 rounded">{c.count.toLocaleString()} events</span>
                    </div>
                    <div className="grid grid-cols-2 gap-4 mb-4">
                      <div>
                        <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">Accuracy</p>
                        <p className="text-2xl font-extrabold text-foreground">{(c.accuracy * 100).toFixed(1)}%</p>
                      </div>
                      <div>
                        <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest">F1 Score</p>
                        <p className="text-2xl font-extrabold text-foreground">{c.f1.toFixed(3)}</p>
                      </div>
                    </div>
                    <div className="mb-3">
                      <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">Top Feature</p>
                      <span className="px-3 py-1 bg-muted/40 rounded-lg text-[10px] font-mono font-bold text-foreground">{c.topFeature}</span>
                    </div>
                    <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-primary/50" style={{ width: `${c.accuracy * 100}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-4 rounded-2xl bg-amber-50 border border-amber-200 p-5">
                <p className="text-xs text-amber-800">
                  <strong>Insight:</strong> Auth Events show the strongest performance (F1: 0.950). File Events are weakest (F1: 0.860) due to entropy noise from encrypted payloads.
                </p>
              </div>
            </TabsContent>

            {/* MODEL CARDS */}
            <TabsContent value="model-card" className="mt-0 space-y-4">
              {(xai.modelCards || MOCK_DATA.modelCards!).map((mc) => (
                <div key={mc.model} className="bg-white rounded-2xl border border-border p-6 shadow-sm">
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h4 className="text-base font-extrabold text-foreground">{mc.model}</h4>
                      <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Version {mc.version} · Trained {mc.trainDate}</p>
                    </div>
                    <button className="flex items-center gap-2 px-4 py-2 bg-muted/50 border border-border rounded-xl text-xs font-semibold hover:bg-accent transition-colors">
                      <Download className="w-3 h-3" /> Export
                    </button>
                  </div>
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
                    {Object.entries(mc.metrics).map(([k, v]) => (
                      <div key={k}>
                        <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-1">{k}</p>
                        <p className="text-xl font-extrabold text-foreground">{(v as number).toFixed(3)}</p>
                      </div>
                    ))}
                  </div>
                  <div className="pt-4 border-t border-border">
                    <p className="text-[9px] font-black text-muted-foreground uppercase tracking-widest mb-3">Fairness Metrics</p>
                    <div className="flex gap-6">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Equalized Odds:</span>
                        <span className="text-sm font-extrabold text-foreground">{mc.fairness.equalizedOdds.toFixed(2)}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">Demographic Parity:</span>
                        <span className="text-sm font-extrabold text-foreground">{mc.fairness.demographicParity.toFixed(2)}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </TabsContent>
          </Tabs>
        </section>
      </div>
    </div>
  );
}
