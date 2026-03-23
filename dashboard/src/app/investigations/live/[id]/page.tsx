"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  ArrowLeft,
  Shield,
  Crosshair,
  Eye,
  BookOpen,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  BrainCircuit,
  Network,
  Target,
  FileText,
  ChevronDown,
  ChevronUp,
  Activity,
  ExternalLink,
} from "lucide-react";
import { toast } from "sonner";

/* ── Types (matches InvestigationReport from ai-agents page) ── */
interface InvestigationFull {
  investigation_id: string;
  created_at: string;
  status: string;
  error: string | null;
  trigger_source: string;
  trigger_event: Record<string, unknown>;
  triage: {
    is_attack: boolean;
    confidence: number;
    category: string;
    severity: string;
    priority: string;
    explanation: string;
    mitre_tactic: string;
    mitre_technique: string;
    classifier_used: string;
    log_type: string;
    xai_available?: boolean;
    xai_top_features?: Array<{ feature: string; shap_value: number; display_name: string; category: string }>;
    xai_prediction_drivers?: string;
    xai_waterfall?: { base_value: number; output_value: number; features: Array<{ feature: string; contribution: number }> };
    xai_category_attribution?: Record<string, number>;
    xai_model_type?: string;
    xai_feature_contributions?: Record<string, number>;
  } | null;
  hunt: {
    correlated_events: Array<{
      event_id: string;
      timestamp: string;
      source_table: string;
      category: string;
      severity: number;
      description: string;
      hostname: string;
      ip_address: string;
      similarity_score: number;
      correlation_type: string;
    }>;
    attack_chain: Array<{
      timestamp: string;
      action: string;
      source: string;
      detail: string;
    }>;
    affected_hosts: string[];
    affected_ips: string[];
    affected_users: string[];
    mitre_tactics: string[];
    mitre_techniques: string[];
  } | null;
  verification: {
    verdict: string;
    confidence: number;
    adjusted_confidence: number;
    false_positive_score: number;
    evidence_summary: string;
    checks_performed: number;
    checks_passed: number;
    checks_failed: number;
    check_details: Array<{ check: string; passed: boolean; detail: string }>;
    recommendation: string;
  } | null;
  report: {
    investigation_id: string;
    title: string;
    executive_summary: string;
    severity: string;
    sections: Record<string, string>;
    mitre_mapping: Array<{
      technique_id: string;
      technique_name: string;
      tactic: string;
      url: string;
    }>;
    recommendations: string[];
    affected_assets: Record<string, string[]>;
    timeline: Array<{ timestamp: string; event: string; source: string }>;
  } | null;
  agent_results: Array<{
    agent_name: string;
    status: string;
    started_at: string;
    finished_at: string;
    duration_ms: number;
    error: string | null;
  }>;
}

/* ── Helpers ── */
function severityVariant(sev: string): "critical" | "high" | "medium" | "low" | "info" {
  switch (sev?.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

function verdictIcon(v: string) {
  switch (v) {
    case "true_positive": return <AlertTriangle className="h-4 w-4 text-red-600" />;
    case "false_positive": return <CheckCircle2 className="h-4 w-4 text-emerald-600" />;
    case "benign": return <CheckCircle2 className="h-4 w-4 text-emerald-600" />;
    case "suspicious": return <Eye className="h-4 w-4 text-amber-600" />;
    default: return <Eye className="h-4 w-4 text-muted-foreground" />;
  }
}

function verdictColor(v: string): string {
  switch (v) {
    case "true_positive": return "bg-red-500/10 text-red-600 border-red-500/20";
    case "false_positive": return "bg-emerald-500/10 text-emerald-600 border-emerald-500/20";
    case "benign": return "bg-emerald-500/10 text-emerald-600 border-emerald-500/20";
    case "suspicious": return "bg-amber-500/10 text-amber-600 border-amber-500/20";
    default: return "bg-zinc-500/10 text-zinc-500 border-zinc-500/20";
  }
}

const AGENT_META: Record<string, { icon: typeof Shield; color: string; bg: string }> = {
  "Triage Agent": { icon: Shield, color: "text-blue-600", bg: "bg-blue-500/10" },
  "Hunter Agent": { icon: Crosshair, color: "text-amber-600", bg: "bg-amber-500/10" },
  "Verifier Agent": { icon: Eye, color: "text-purple-600", bg: "bg-purple-500/10" },
  "Reporter Agent": { icon: BookOpen, color: "text-emerald-600", bg: "bg-emerald-500/10" },
};

/* ── Collapsible Section ── */
function Section({
  title,
  icon: Icon,
  iconColor,
  badge,
  children,
  defaultOpen = true,
}: {
  title: string;
  icon: React.ElementType;
  iconColor: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Card>
      <CardHeader
        className="cursor-pointer select-none"
        onClick={() => setOpen(!open)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Icon className={`h-4 w-4 ${iconColor}`} />
            <CardTitle className="text-[15px] font-bold">{title}</CardTitle>
            {badge}
          </div>
          {open ? (
            <ChevronUp className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </CardHeader>
      {open && <CardContent className="pt-0">{children}</CardContent>}
    </Card>
  );
}

/* ══════════════════════════════════════════════════════════════
   Live Investigation Detail Page
   ══════════════════════════════════════════════════════════════ */
export default function LiveInvestigationPage({
  params,
}: {
  params: { id: string };
}) {
  const [data, setData] = useState<InvestigationFull | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchInv = async () => {
      try {
        const res = await fetch(`/api/ai/investigations/${params.id}`, {
          cache: "no-store",
        });
        if (res.status === 404) {
          setError("Investigation not found");
          return;
        }
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = await res.json();
        if (json.error) {
          setError(json.error);
        } else {
          setData(json);
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : "Failed to load investigation");
      } finally {
        setLoading(false);
      }
    };
    fetchInv();
  }, [params.id]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center gap-2">
        <Loader2 className="h-5 w-5 animate-spin text-primary" />
        <span className="text-sm text-muted-foreground">Loading investigation…</span>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex flex-col items-center gap-4 py-20">
        <XCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm font-medium">{error ?? "Investigation not found"}</p>
        <Link href="/investigations">
          <Button variant="outline" size="sm" className="gap-1">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Investigations
          </Button>
        </Link>
      </div>
    );
  }

  const triage = data.triage;
  const hunt = data.hunt;
  const ver = data.verification;
  const report = data.report;
  const xai = triage?.xai_available;

  return (
    <div className="space-y-6">
      {/* Back + Header */}
      <div>
        <Link
          href="/ai-agents"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors mb-3"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to AI Agents
        </Link>

        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              {triage && (
                <Badge variant={severityVariant(triage.severity)}>
                  {triage.severity?.toUpperCase()}
                </Badge>
              )}
              <span className="font-mono text-sm text-muted-foreground">
                {data.investigation_id}
              </span>
              <span
                className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-xs font-medium ${
                  data.status === "completed"
                    ? "bg-emerald-500/10 text-emerald-600 border-emerald-500/20"
                    : data.status === "closed"
                      ? "bg-zinc-500/10 text-zinc-500 border-zinc-500/20"
                      : "bg-blue-500/10 text-blue-600 border-blue-500/20"
                }`}
              >
                {data.status?.replace(/_/g, " ").toUpperCase()}
              </span>
              {ver && (
                <span
                  className={`inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 text-xs font-medium ${verdictColor(ver.verdict)}`}
                >
                  {verdictIcon(ver.verdict)}
                  {ver.verdict?.replace(/_/g, " ").toUpperCase()}
                </span>
              )}
            </div>
            <h1 className="mt-2 text-[26px] font-bold tracking-tight">
              {triage?.category ?? "Unknown"} Investigation
            </h1>
            <p className="text-sm text-muted-foreground">
              {triage?.explanation ?? "No explanation available"}
            </p>
          </div>
        </div>
      </div>

      {/* Agent Pipeline Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-[15px] font-bold flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Agent Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 overflow-x-auto pb-2">
            {data.agent_results.map((ar, i) => {
              const meta = AGENT_META[ar.agent_name] ?? {
                icon: Shield,
                color: "text-zinc-500",
                bg: "bg-zinc-500/10",
              };
              const AgentIcon = meta.icon;
              return (
                <div key={i} className="flex items-center gap-2">
                  <div
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${meta.bg}`}
                  >
                    <AgentIcon className={`h-4 w-4 ${meta.color}`} />
                    <div>
                      <p className="text-xs font-semibold">{ar.agent_name}</p>
                      <p className="text-[10px] text-muted-foreground">
                        {ar.duration_ms}ms ·{" "}
                        {ar.status === "completed" ? (
                          <span className="text-emerald-600">✓</span>
                        ) : (
                          <span className="text-red-600">✗</span>
                        )}
                      </p>
                    </div>
                  </div>
                  {i < data.agent_results.length - 1 && (
                    <div className="h-px w-6 bg-border" />
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* ── Triage ── */}
        <Section
          title="Triage Classification"
          icon={Shield}
          iconColor="text-blue-600"
          badge={
            triage?.priority ? (
              <Badge variant={severityVariant(triage.severity)} className="text-[10px]">
                {triage.priority}
              </Badge>
            ) : null
          }
        >
          {triage ? (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Category</p>
                  <p className="text-sm font-semibold">{triage.category}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Confidence</p>
                  <p className="text-sm font-semibold tabular-nums">{(triage.confidence * 100).toFixed(1)}%</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Classifier</p>
                  <p className="text-sm font-mono">{triage.classifier_used}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Log Type</p>
                  <p className="text-sm font-mono">{triage.log_type}</p>
                </div>
              </div>
              {(triage.mitre_tactic || triage.mitre_technique) && (
                <>
                  <Separator />
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">MITRE ATT&CK</p>
                    <div className="flex flex-wrap gap-1.5">
                      {triage.mitre_tactic && (
                        <Badge variant="outline" className="text-[10px]">
                          {triage.mitre_tactic}
                        </Badge>
                      )}
                      {triage.mitre_technique && (
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {triage.mitre_technique}
                        </Badge>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No triage data</p>
          )}
        </Section>

        {/* ── Verification ── */}
        <Section
          title="Verification"
          icon={Eye}
          iconColor="text-purple-600"
          badge={
            ver ? (
              <span
                className={`inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 text-[10px] font-medium ${verdictColor(ver.verdict)}`}
              >
                {ver.verdict?.replace(/_/g, " ")}
              </span>
            ) : null
          }
        >
          {ver ? (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Adj. Confidence</p>
                  <p className="text-sm font-semibold tabular-nums">{(ver.adjusted_confidence * 100).toFixed(1)}%</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">FP Score</p>
                  <p className="text-sm font-semibold tabular-nums">{ver.false_positive_score.toFixed(2)}</p>
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Checks</p>
                  <p className="text-sm font-semibold tabular-nums">
                    {ver.checks_passed}/{ver.checks_performed} passed
                  </p>
                </div>
              </div>
              <Separator />
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Evidence Summary</p>
                <p className="text-xs text-muted-foreground">{ver.evidence_summary}</p>
              </div>
              {ver.check_details.length > 0 && (
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Check Details</p>
                  {ver.check_details.map((cd, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      {cd.passed ? (
                        <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-600 mt-0.5" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5 shrink-0 text-red-600 mt-0.5" />
                      )}
                      <span className="text-muted-foreground">{cd.detail}</span>
                    </div>
                  ))}
                </div>
              )}
              {ver.recommendation && (
                <>
                  <Separator />
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Recommendation</p>
                    <p className="text-xs font-medium">{ver.recommendation}</p>
                  </div>
                </>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No verification data (benign event)</p>
          )}
        </Section>
      </div>

      {/* ── XAI / SHAP ── */}
      {xai && triage?.xai_top_features && triage.xai_top_features.length > 0 && (
        <Section
          title="Explainable AI (SHAP)"
          icon={BrainCircuit}
          iconColor="text-purple-600"
          badge={
            <Badge variant="outline" className="text-[10px]">
              {triage.xai_model_type ?? "tree"} model
            </Badge>
          }
        >
          <div className="space-y-4">
            {/* Prediction Drivers */}
            {triage.xai_prediction_drivers && (
              <div className="rounded-lg bg-muted/30 p-3">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
                  Prediction Drivers
                </p>
                <p className="text-xs leading-relaxed">
                  {triage.xai_prediction_drivers}
                </p>
              </div>
            )}

            {/* Top Features */}
            <div>
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                Top SHAP Features
              </p>
              <div className="space-y-1.5">
                {triage.xai_top_features.slice(0, 10).map((f, i) => {
                  const maxAbs = Math.max(
                    ...triage.xai_top_features!.map((x) => Math.abs(x.shap_value)),
                    0.01,
                  );
                  const pct = (Math.abs(f.shap_value) / maxAbs) * 100;
                  const isPositive = f.shap_value > 0;
                  return (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <span className="w-5 text-right text-[10px] text-muted-foreground tabular-nums">
                        {i + 1}
                      </span>
                      <span className="w-32 truncate font-mono text-[11px]">
                        {f.display_name || f.feature}
                      </span>
                      <div className="flex-1 flex items-center gap-1">
                        <div className="flex-1 h-3 bg-muted/50 rounded-full overflow-hidden relative">
                          <div
                            className={`h-full rounded-full ${isPositive ? "bg-red-500/70" : "bg-blue-500/70"}`}
                            style={{ width: `${Math.min(pct, 100)}%` }}
                          />
                        </div>
                        <span
                          className={`w-14 text-right tabular-nums text-[10px] ${
                            isPositive ? "text-red-600" : "text-blue-600"
                          }`}
                        >
                          {isPositive ? "+" : ""}
                          {f.shap_value.toFixed(3)}
                        </span>
                      </div>
                      <Badge variant="outline" className="text-[8px] px-1.5">
                        {f.category}
                      </Badge>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Category Attribution */}
            {triage.xai_category_attribution && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                  Category Attribution
                </p>
                <div className="space-y-1.5">
                  {Object.entries(triage.xai_category_attribution)
                    .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
                    .map(([cat, val]) => {
                      const maxCat = Math.max(
                        ...Object.values(triage.xai_category_attribution!).map(Math.abs),
                        0.01,
                      );
                      const pct = (Math.abs(val) / maxCat) * 100;
                      return (
                        <div key={cat} className="flex items-center gap-2 text-xs">
                          <span className="w-24 truncate capitalize">{cat.replace(/_/g, " ")}</span>
                          <div className="flex-1 h-2.5 bg-muted/50 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${val > 0 ? "bg-red-500/60" : "bg-blue-500/60"}`}
                              style={{ width: `${Math.min(pct, 100)}%` }}
                            />
                          </div>
                          <span className="w-14 text-right tabular-nums text-[10px] text-muted-foreground">
                            {val > 0 ? "+" : ""}{val.toFixed(3)}
                          </span>
                        </div>
                      );
                    })}
                </div>
              </div>
            )}

            {/* Waterfall */}
            {triage.xai_waterfall && (
              <div className="rounded-lg border p-3">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
                  Decision Waterfall
                </p>
                <div className="flex items-center gap-3 text-xs">
                  <span className="text-muted-foreground">
                    Base: <span className="font-mono">{triage.xai_waterfall.base_value.toFixed(4)}</span>
                  </span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-semibold">
                    Output: <span className="font-mono">{triage.xai_waterfall.output_value.toFixed(4)}</span>
                  </span>
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── Hunt Results ── */}
      {hunt && (hunt.correlated_events.length > 0 || hunt.attack_chain.length > 0) && (
        <Section
          title="Hunt Results"
          icon={Crosshair}
          iconColor="text-amber-600"
          badge={
            <Badge variant="outline" className="text-[10px]">
              {hunt.correlated_events.length} correlated
            </Badge>
          }
        >
          <div className="space-y-4">
            {/* Affected Assets */}
            {(hunt.affected_hosts.length > 0 || hunt.affected_ips.length > 0) && (
              <div className="grid grid-cols-2 gap-4">
                {hunt.affected_hosts.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Hosts</p>
                    <div className="flex flex-wrap gap-1">
                      {hunt.affected_hosts.map((h) => (
                        <Badge key={h} variant="outline" className="font-mono text-[10px]">
                          <Network className="mr-1 h-3 w-3" />
                          {h}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {hunt.affected_ips.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">IPs</p>
                    <div className="flex flex-wrap gap-1">
                      {hunt.affected_ips.map((ip) => (
                        <Badge key={ip} variant="outline" className="font-mono text-[10px]">
                          {ip}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* MITRE Techniques */}
            {hunt.mitre_techniques.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">MITRE Techniques</p>
                <div className="flex flex-wrap gap-1">
                  {hunt.mitre_techniques.map((t) => (
                    <a
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1"
                    >
                      <Badge variant="outline" className="font-mono text-[10px] cursor-pointer hover:bg-muted/50">
                        {t}
                        <ExternalLink className="ml-1 h-2.5 w-2.5" />
                      </Badge>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Attack Chain */}
            {hunt.attack_chain.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Attack Chain</p>
                <div className="relative space-y-2">
                  <div className="absolute left-[7px] top-2 bottom-2 w-px bg-border" />
                  {hunt.attack_chain.map((step, i) => (
                    <div key={i} className="flex gap-3 pl-0 relative">
                      <div className="relative z-10 mt-1">
                        <div className="h-3.5 w-3.5 rounded-full border-2 border-amber-500 bg-card" />
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground font-mono">{step.timestamp}</p>
                        <p className="text-xs font-medium">{step.action}</p>
                        <p className="text-[10px] text-muted-foreground">{step.detail}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Correlated Events Table */}
            {hunt.correlated_events.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Correlated Events</p>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b">
                        <th className="pb-2 text-left text-[10px] font-semibold uppercase text-muted-foreground">Type</th>
                        <th className="pb-2 text-left text-[10px] font-semibold uppercase text-muted-foreground">Source</th>
                        <th className="pb-2 text-left text-[10px] font-semibold uppercase text-muted-foreground">Description</th>
                        <th className="pb-2 text-right text-[10px] font-semibold uppercase text-muted-foreground">Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hunt.correlated_events.slice(0, 20).map((ce, i) => (
                        <tr key={i} className="border-b border-border/30">
                          <td className="py-1.5">
                            <Badge variant="outline" className="text-[9px]">
                              {ce.correlation_type}
                            </Badge>
                          </td>
                          <td className="py-1.5 font-mono text-[10px]">{ce.source_table}</td>
                          <td className="py-1.5 max-w-xs truncate text-muted-foreground">
                            {ce.description}
                          </td>
                          <td className="py-1.5 text-right tabular-nums">
                            {(ce.similarity_score * 100).toFixed(0)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* ── Report ── */}
      {report && (
        <Section
          title="Investigation Report"
          icon={BookOpen}
          iconColor="text-emerald-600"
          badge={
            <Badge variant={severityVariant(report.severity)} className="text-[10px]">
              {report.severity}
            </Badge>
          }
        >
          <div className="space-y-4">
            <div>
              <h3 className="text-sm font-bold">{report.title}</h3>
              {report.executive_summary && (
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  {report.executive_summary}
                </p>
              )}
            </div>

            {/* Report Sections */}
            {report.sections && Object.entries(report.sections).length > 0 && (
              <div className="space-y-3">
                {Object.entries(report.sections).map(([title, content]) => (
                  <div key={title} className="rounded-lg border p-3">
                    <p className="text-xs font-semibold mb-1">{title}</p>
                    <pre className="text-[11px] text-muted-foreground whitespace-pre-wrap font-mono leading-relaxed">
                      {content}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {/* MITRE Mapping */}
            {report.mitre_mapping && report.mitre_mapping.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">MITRE ATT&CK Mapping</p>
                <div className="flex flex-wrap gap-2">
                  {report.mitre_mapping.map((m, i) => (
                    <a
                      key={i}
                      href={m.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="rounded-md border px-2.5 py-1.5 text-xs hover:bg-muted/50 transition-colors"
                    >
                      <span className="font-mono font-semibold">{m.technique_id}</span>
                      <span className="text-muted-foreground"> — {m.technique_name}</span>
                      <span className="block text-[10px] text-muted-foreground">{m.tactic}</span>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {report.recommendations && report.recommendations.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Recommendations</p>
                <div className="space-y-1.5">
                  {report.recommendations.map((r, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <Target className="h-3.5 w-3.5 shrink-0 text-primary mt-0.5" />
                      <span>{r}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Timeline */}
            {report.timeline && report.timeline.length > 0 && (
              <div>
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Investigation Timeline</p>
                <div className="relative space-y-2">
                  <div className="absolute left-[7px] top-2 bottom-2 w-px bg-border" />
                  {report.timeline.map((t, i) => (
                    <div key={i} className="flex gap-3 relative">
                      <div className="relative z-10 mt-1">
                        <div className="h-3.5 w-3.5 rounded-full border-2 border-emerald-500 bg-card" />
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground font-mono">{t.timestamp}</p>
                        <p className="text-xs">{t.event}</p>
                        <p className="text-[10px] text-muted-foreground">{t.source}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Section>
      )}
    </div>
  );
}
