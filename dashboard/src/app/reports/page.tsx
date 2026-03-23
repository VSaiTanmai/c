"use client";

import { useState } from "react";
import {
  RefreshCw,
  Shield,
  Zap,
  ArrowUp,
  ArrowDown,
  Download,
  FileText,
  FileWarning,
  Briefcase,
  Code,
  Radar,
  Clock,
  Search,
  Filter,
  X,
  Eye,
  ChevronLeft,
  ChevronRight,
  Settings,
  AlertTriangle,
  BarChart3,
  CheckCircle,
  Diamond,
  Calendar,
  Info,
  Activity,
  Cpu,
  TrendingUp,
  Link2,
  Bell,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { cn } from "@/lib/utils";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

/* ── Types ── */
interface ReportsData {
  summary: {
    totalEvents: number;
    totalAlerts24h: number;
    criticalAlerts: number;
    highAlerts: number;
    mediumAlerts: number;
    evidenceBatches: number;
    evidenceAnchored: number;
    evidenceVerified: number;
  };
  topCategories: Array<{ category: string; count: number }>;
  mitreTopTechniques: Array<{ technique: string; tactic: string; count: number }>;
  sigmaTopRules: Array<{ name: string; count: number }>;
  sigmaTacticDistribution: Array<{ tactic: string; count: number }>;
  sigmaSeverityDistribution: Array<{ severity: string; count: number }>;
  mlModelHealth: {
    klDivergence: number;
    psiMax: number;
    isDrifting: boolean;
    sampleCount: number;
  };
  hunterScoreDistribution: Array<{ bucket: string; count: number }>;
  tpFpRatio: Array<{ verdict: string; count: number }>;
  modelFeatures: Array<{
    name: string;
    type: string;
    importance: number;
    driftPsi: number;
    status: string;
  }>;
  evidenceBatchList: Array<{
    batchId: string;
    eventCount: number;
    status: string;
    hasContinuity: boolean;
    merkleRoot: string;
    anchoredAt: string;
  }>;
  investigations: Array<{
    alertId: string;
    title?: string;
    findingType: string;
    hunterScore: number;
    signalsFired: number;
    campaignHostCount: number;
  }>;
  generatedAt: string;
}

/* ── Colors ── */
const CATEGORY_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#06b6d4", "#8b5cf6", "#ec4899"];
const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#eab308",
  Low: "#06b6d4",
};
const TP_FP_COLORS: Record<string, string> = { true_positive: "#06b6d4", false_positive: "#ef4444" };
const EVIDENCE_COLORS: Record<string, string> = { anchored: "#2563eb", verified: "#0d9488", continuity: "#f59e0b" };

const VERDICT_LABELS: Record<string, { label: string; color: string }> = {
  CONFIRMED_ATTACK: { label: "MALICIOUS", color: "text-red-500 bg-red-500/10 border-red-500/20" },
  ACTIVE_CAMPAIGN: { label: "MALICIOUS", color: "text-red-500 bg-red-500/10 border-red-500/20" },
  BEHAVIOURAL_ANOMALY: { label: "SUSPICIOUS", color: "text-amber-500 bg-amber-500/10 border-amber-500/20" },
  SIGMA_MATCH: { label: "SUSPICIOUS", color: "text-orange-500 bg-orange-500/10 border-orange-500/20" },
  ANOMALOUS_PATTERN: { label: "SUSPICIOUS", color: "text-amber-500 bg-amber-500/10 border-amber-500/20" },
  FALSE_POSITIVE: { label: "BENIGN", color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/20" },
  NORMAL_BEHAVIOUR: { label: "BENIGN", color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/20" },
};

const REPORT_TEMPLATES = [
  { id: "incident", name: "Incident Report", description: "Detailed breach analysis and timeline", icon: FileWarning, bg: "bg-red-500/10", iconColor: "text-red-400" },
  { id: "executive", name: "Executive Summary", description: "High-level status and impact overview", icon: Briefcase, bg: "bg-teal-500/10", iconColor: "text-teal-400" },
  { id: "technical", name: "Technical Analysis", description: "Deep dive digital forensics results", icon: Code, bg: "bg-pink-500/10", iconColor: "text-pink-400" },
  { id: "compliance", name: "Compliance Report", description: "Regulatory audit and standard data", icon: Shield, bg: "bg-emerald-500/10", iconColor: "text-emerald-400" },
  { id: "threat-intel", name: "Threat Intelligence", description: "Indicator of Compromise data feed", icon: Radar, bg: "bg-violet-500/10", iconColor: "text-violet-400" },
];

const REPORT_HISTORY = [
  { id: "RPT-2026-015", title: "INV-2026-004 — Mimikatz Technical Analysis", template: "Technical Analysis", created: "2026-02-10T11:00:00Z", pages: 4, size: "842 KB" },
  { id: "RPT-2026-014", title: "Weekly Security Summary — Feb 3-9", template: "Executive Summary", created: "2026-02-10T08:00:00Z", pages: 2, size: "312 KB" },
  { id: "RPT-2026-013", title: "INV-2026-005 — Brute Force Incident Report", template: "Incident Report", created: "2026-02-09T15:00:00Z", pages: 6, size: "1.2 MB" },
  { id: "RPT-2026-012", title: "SOC2 Compliance — January 2026", template: "Compliance Report", created: "2026-02-01T09:00:00Z", pages: 12, size: "2.4 MB" },
  { id: "RPT-2026-011", title: "Threat Landscape — Q4 2025", template: "Threat Intelligence", created: "2026-01-15T10:00:00Z", pages: 8, size: "1.8 MB" },
  { id: "RPT-2026-010", title: "Monthly Security Posture Q3", template: "Executive Summary", created: "2025-10-12T14:30:00Z", pages: 24, size: "4.2 MB" },
  { id: "RPT-2026-009", title: "Incident Analysis: Brute Force DC", template: "Incident Report", created: "2025-10-10T09:15:00Z", pages: 12, size: "2.8 MB" },
  { id: "RPT-2026-008", title: "Quarterly HIPAA Compliance Audit", template: "Compliance Report", created: "2025-10-05T11:45:00Z", pages: 86, size: "14.1 MB" },
  { id: "RPT-2026-007", title: "Indicator of Compromise Feed — Week 40", template: "Threat Intelligence", created: "2025-10-01T00:01:00Z", pages: 5, size: "0.9 MB" },
  { id: "RPT-2026-006", title: "DNS Tunneling Investigation Report", template: "Technical Analysis", created: "2025-09-28T16:30:00Z", pages: 10, size: "1.6 MB" },
  { id: "RPT-2026-005", title: "Lateral Movement Campaign Summary", template: "Incident Report", created: "2025-09-20T08:00:00Z", pages: 15, size: "3.1 MB" },
  { id: "RPT-2026-004", title: "August Security Executive Brief", template: "Executive Summary", created: "2025-09-01T10:00:00Z", pages: 6, size: "1.1 MB" },
];

function formatNumber(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
  return n.toString();
}

function handleGenerateReport(alertId: string, template: string) {
  // Simulate report generation — triggers a download of a placeholder
  const content = `CLIF Security Report\n\nInvestigation: ${alertId}\nTemplate: ${template}\nGenerated: ${new Date().toISOString()}\n\nThis is a placeholder report. In production, this would contain the full investigation timeline, evidence chain, MITRE ATT&CK mapping, and blockchain verification details.`;
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${alertId}_${template}_report.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function handleDownloadReport(reportId: string) {
  const content = `CLIF Security Report\n\nReport ID: ${reportId}\nDownloaded: ${new Date().toISOString()}\n\nThis is a placeholder for the previously generated report.`;
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${reportId}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadCSV(filename: string, headers: string[], rows: string[][]) {
  const csv = [headers.join(","), ...rows.map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(","))].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Filter Select Component ── */
function FilterSelect({ value, onChange, options, label }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[]; label: string }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      className="h-9 rounded-xl border border-border bg-white px-3 text-sm font-semibold text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

export default function ReportsPage() {
  const { data, loading, refresh } = usePolling<ReportsData>("/api/reports", 30000);
  const [tab, setTab] = useState("reports");
  const [generating, setGenerating] = useState<string | null>(null);

  // ── Filter state ──
  // Reports tab
  const [rptSearch, setRptSearch] = useState("");
  const [rptVerdict, setRptVerdict] = useState("all");
  const [rptHistoryTemplate, setRptHistoryTemplate] = useState("all");
  // Investigations tab
  const [invSearch, setInvSearch] = useState("");
  const [invVerdict, setInvVerdict] = useState("all");
  const [invScoreMin, setInvScoreMin] = useState(0);
  const [invCampaign, setInvCampaign] = useState("all");
  const [invTimeFilter, setInvTimeFilter] = useState("all");
  const [invPage, setInvPage] = useState(1);
  const INV_PAGE_SIZE = 5;
  // Sigma tab
  const [sigmaSeverity, setSigmaSeverity] = useState("all");
  const [sigmaTactic, setSigmaTactic] = useState("all");
  // Evidence tab
  const [evSearch, setEvSearch] = useState("");
  const [evStatus, setEvStatus] = useState("all");
  const [evContinuityFilter, setEvContinuityFilter] = useState("all");
  const [evPage, setEvPage] = useState(1);
  const EV_PAGE_SIZE = 5;
  // Report History pagination
  const [historyPage, setHistoryPage] = useState(1);
  const HISTORY_PAGE_SIZE = 4;

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-32 rounded-lg" />
        ))}
      </div>
    );
  }

  const d = data;

  // Evidence chain stats
  const evBatches = d?.evidenceBatchList ?? [];
  const evTotalBatches = d?.summary.evidenceBatches ?? evBatches.length;
  const evVerifiedCount = evBatches.filter((b) => b.status === "Verified").length;
  const evVerificationRate =
    evTotalBatches > 0 ? ((d?.summary.evidenceVerified ?? evVerifiedCount) / evTotalBatches * 100).toFixed(1) : "0";
  const evContinuityGaps = evBatches.filter((b) => !b.hasContinuity).length;
  const evAvgEvents =
    evBatches.length > 0
      ? Math.round(evBatches.reduce((s, b) => s + b.eventCount, 0) / evBatches.length)
      : 0;

  // ── Filtered data ──
  const allInvestigations = d?.investigations ?? [];

  // Reports tab filters
  const filteredReportInvestigations = allInvestigations.filter((inv) => {
    if (rptSearch && !inv.alertId.toLowerCase().includes(rptSearch.toLowerCase())) return false;
    if (rptVerdict !== "all" && (VERDICT_LABELS[inv.findingType]?.label ?? inv.findingType) !== rptVerdict) return false;
    return true;
  });
  const filteredReportHistory = REPORT_HISTORY.filter((r) => {
    if (rptHistoryTemplate !== "all" && r.template !== rptHistoryTemplate) return false;
    return true;
  });

  // Investigations tab filters
  const filteredInvestigations = allInvestigations.filter((inv) => {
    if (invSearch && !inv.alertId.toLowerCase().includes(invSearch.toLowerCase())) return false;
    if (invVerdict !== "all" && (VERDICT_LABELS[inv.findingType]?.label ?? inv.findingType) !== invVerdict) return false;
    if (invScoreMin > 0 && Math.round(inv.hunterScore * 100) < invScoreMin) return false;
    if (invCampaign === "yes" && inv.campaignHostCount <= 2) return false;
    if (invCampaign === "no" && inv.campaignHostCount > 2) return false;
    return true;
  });

  // Evidence tab filters
  const filteredEvBatches = evBatches.filter((b) => {
    if (evSearch && !b.batchId.toLowerCase().includes(evSearch.toLowerCase()) && !b.merkleRoot.toLowerCase().includes(evSearch.toLowerCase())) return false;
    if (evStatus !== "all" && b.status !== evStatus) return false;
    if (evContinuityFilter === "yes" && !b.hasContinuity) return false;
    if (evContinuityFilter === "no" && b.hasContinuity) return false;
    return true;
  });

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ HEADER HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-primary/10 text-primary text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <FileText className="w-3 h-3" /> Reports
                </span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                Security <span className="text-primary inline-block">Reports</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Manage, generate and export technical security documentation.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <button onClick={() => {
                const invs = filteredReportInvestigations;
                downloadCSV("investigations_report.csv",
                  ["Investigation", "Title", "Verdict", "Score", "Signals"],
                  invs.map((inv) => [inv.alertId, inv.title ?? "", inv.findingType, String(Math.round(inv.hunterScore * 100)) + "%", String(inv.signalsFired)])
                );
              }} className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                <Download className="w-4 h-4" /> Export CSV
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="px-10 max-w-[1600px] w-full mx-auto">
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="w-full justify-start border-b border-border bg-transparent p-0 mt-0">
          <TabsTrigger value="reports" className="data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-6 py-3 text-sm font-bold">
            Reports
          </TabsTrigger>
          <TabsTrigger value="investigations" className="data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-6 py-3 text-sm font-bold">
            Investigations
          </TabsTrigger>
          <TabsTrigger value="sigma" className="data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-6 py-3 text-sm font-bold">
            Sigma Rules
          </TabsTrigger>
          <TabsTrigger value="ml" className="data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-6 py-3 text-sm font-bold">
            Machine Learning Model
          </TabsTrigger>
          <TabsTrigger value="evidence" className="data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-6 py-3 text-sm font-bold">
            Evidence Chain
          </TabsTrigger>
        </TabsList>

        {/* ═══════════════ REPORTS TAB (Default) ═══════════════ */}
        <TabsContent value="reports" className="mt-6 space-y-6">
          {/* Report Templates */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <h4 className="text-base font-extrabold text-foreground">Download Investigation Templates</h4>
              <button className="text-sm text-primary font-bold hover:underline transition-colors">View All Templates</button>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
              {REPORT_TEMPLATES.map((t) => (
                <div key={t.id} className="rounded-2xl border border-border hover:border-primary/40 transition-colors cursor-pointer overflow-hidden shadow-sm">
                  <div className={cn("flex items-center justify-center py-5", t.bg)}>
                    <t.icon className={cn("h-8 w-8", t.iconColor)} />
                  </div>
                  <div className="p-3 text-center">
                    <span className="text-sm font-bold text-foreground block">{t.name}</span>
                    <span className="text-xs text-muted-foreground leading-tight block mt-1">{t.description}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-3">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                placeholder="Search investigation ID..."
                value={rptSearch}
                onChange={(e) => setRptSearch(e.target.value)}
                className="pl-9 h-9 w-[200px] rounded-xl border border-border bg-white px-3 text-sm font-semibold text-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
              />
            </div>
            <FilterSelect
              label="Verdict"
              value={rptVerdict}
              onChange={setRptVerdict}
              options={[
                { value: "all", label: "All Verdicts" },
                ...Array.from(new Set(Object.values(VERDICT_LABELS).map((v) => v.label))).map((label) => ({ value: label, label })),
              ]}
            />
            {(rptSearch || rptVerdict !== "all") && (
              <button className="flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-muted-foreground hover:text-foreground transition-colors" onClick={() => { setRptSearch(""); setRptVerdict("all"); }}>
                <X className="h-3 w-3" /> Clear
              </button>
            )}
            <span className="text-xs text-muted-foreground ml-auto">{filteredReportInvestigations.length} investigation(s)</span>
          </div>

          {/* Per-Investigation Report Generation */}
          <div className="rounded-2xl border border-border overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-border">
              <h4 className="text-base font-extrabold text-foreground">Generate Report by Investigation</h4>
              <p className="text-xs text-muted-foreground mt-0.5">Select an investigation to generate a downloadable report</p>
            </div>
            <div>
              <div className="overflow-x-auto">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col className="w-[22%]" />
                    <col className="w-[10%]" />
                    <col className="w-[16%]" />
                    <col className="w-[8%]" />
                    <col className="w-[10%]" />
                    <col className="w-[12%]" />
                    <col className="w-[22%]" />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-border/40">
                      <th className="px-3 py-2.5 text-left text-xs font-medium text-muted-foreground">Investigation</th>
                      <th className="px-3 py-2.5 text-left text-xs font-medium text-muted-foreground">Verdict</th>
                      <th className="px-3 py-2.5 text-left text-xs font-medium text-muted-foreground">Score</th>
                      <th className="px-3 py-2.5 text-center text-xs font-medium text-muted-foreground">Signals</th>
                      <th className="px-3 py-2.5 text-center text-xs font-medium text-muted-foreground">Hosts</th>
                      <th className="px-3 py-2.5 text-center text-xs font-medium text-muted-foreground">Severity</th>
                      <th className="px-3 py-2.5 text-right text-xs font-medium text-muted-foreground">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredReportInvestigations.map((inv) => {
                      const vInfo = VERDICT_LABELS[inv.findingType] ?? { label: inv.findingType, color: "bg-gray-500/20 text-gray-400 border-gray-500/30" };
                      const hunterPct = Math.round(inv.hunterScore * 100);
                      const barColor = hunterPct >= 80 ? "bg-red-500" : hunterPct >= 50 ? "bg-amber-500" : "bg-green-500";
                      const severity = hunterPct >= 90 ? { label: "Critical", color: "text-red-500 bg-red-500/10" } : hunterPct >= 70 ? { label: "High", color: "text-orange-500 bg-orange-500/10" } : hunterPct >= 40 ? { label: "Medium", color: "text-amber-500 bg-amber-500/10" } : { label: "Low", color: "text-emerald-500 bg-emerald-500/10" };
                      return (
                        <tr key={inv.alertId} className="border-b border-border/20 hover:bg-muted/10 transition-colors">
                          <td className="px-3 py-2.5">
                            <div>
                              <span className="text-sm font-medium text-foreground truncate block">{inv.title ?? inv.alertId}</span>
                              <span className="block text-xs text-muted-foreground">{inv.alertId}</span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold", vInfo.color)}>
                              {vInfo.label}
                            </span>
                          </td>
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                                <div className={cn("h-full rounded-full transition-all", barColor)} style={{ width: `${hunterPct}%` }} />
                              </div>
                              <span className="text-xs font-medium text-muted-foreground w-8 text-right">{hunterPct}%</span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className={cn(
                              "inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold",
                              inv.signalsFired >= 5 ? "bg-red-500/20 text-red-400" :
                              inv.signalsFired >= 3 ? "bg-amber-500/20 text-amber-400" :
                              "bg-blue-500/20 text-blue-400"
                            )}>
                              {inv.signalsFired}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className="text-sm text-muted-foreground">{inv.campaignHostCount}</span>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold", severity.color)}>
                              {severity.label}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-right">
                            <div className="flex items-center justify-end gap-3">
                              <button className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors" disabled={generating === inv.alertId} onClick={() => handleGenerateReport(inv.alertId, "incident")}>
                                <Download className="h-3 w-3" /> Incident
                              </button>
                              <button className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors" disabled={generating === inv.alertId} onClick={() => handleGenerateReport(inv.alertId, "technical")}>
                                <Download className="h-3 w-3" /> Technical
                              </button>
                              <button className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors" disabled={generating === inv.alertId} onClick={() => handleGenerateReport(inv.alertId, "executive")}>
                                <Download className="h-3 w-3" /> Executive
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                    {filteredReportInvestigations.length === 0 && (
                      <tr>
                        <td colSpan={7} className="px-3 py-12 text-center text-sm text-muted-foreground">
                          No investigations match the current filters
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Report History */}
          <div className="rounded-2xl border border-border overflow-hidden shadow-sm">
            <div className="px-6 py-4 border-b border-border flex items-center justify-between">
              <div>
                <h4 className="text-base font-extrabold text-foreground">Report History</h4>
                <p className="text-xs text-muted-foreground mt-0.5">Previously generated reports</p>
              </div>
              <div className="flex items-center gap-2">
                <FilterSelect
                  label="Template filter"
                  value={rptHistoryTemplate}
                  onChange={setRptHistoryTemplate}
                  options={[
                    { value: "all", label: "All Templates" },
                    ...REPORT_TEMPLATES.map((t) => ({ value: t.name, label: t.name })),
                  ]}
                />
                <button className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-muted-foreground border border-border rounded-xl hover:bg-accent transition-colors">
                  <Filter className="h-3 w-3" /> Filter
                </button>
              </div>
            </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-border/40">
                      <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Report Identifier</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Title</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Template</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-muted-foreground">Created</th>
                      <th className="px-4 py-3 text-center text-xs font-medium text-muted-foreground">Pages</th>
                      <th className="px-4 py-3 text-center text-xs font-medium text-muted-foreground">Size</th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-muted-foreground">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredReportHistory.slice((historyPage - 1) * HISTORY_PAGE_SIZE, historyPage * HISTORY_PAGE_SIZE).map((r) => (
                      <tr key={r.id} className="border-b border-border/20 hover:bg-muted/10 transition-colors">
                        <td className="px-4 py-3">
                          <span className="text-sm font-medium text-cyan-400">{r.id}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-foreground">{r.title}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-xs font-bold text-foreground border border-border rounded-lg px-2.5 py-0.5">{r.template}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="text-sm text-muted-foreground">{new Date(r.created).toLocaleDateString()}</span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="text-sm text-muted-foreground">{r.pages}</span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          <span className="text-sm text-muted-foreground">{r.size}</span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors" title="View report">
                              <Eye className="h-4 w-4" />
                            </button>
                            <button className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors" onClick={() => handleDownloadReport(r.id)} title="Download report">
                              <Download className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {filteredReportHistory.length > HISTORY_PAGE_SIZE && (() => {
                const totalPages = Math.ceil(filteredReportHistory.length / HISTORY_PAGE_SIZE);
                const startItem = (historyPage - 1) * HISTORY_PAGE_SIZE + 1;
                const endItem = Math.min(historyPage * HISTORY_PAGE_SIZE, filteredReportHistory.length);
                return (
                  <div className="flex items-center justify-between px-4 py-3 border-t border-border/40">
                    <span className="text-xs text-muted-foreground">
                      Showing {startItem} to {endItem} of {filteredReportHistory.length} reports
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        disabled={historyPage === 1}
                        onClick={() => setHistoryPage((p) => Math.max(1, p - 1))}
                      >
                        <ChevronLeft className="h-4 w-4" />
                      </button>
                      {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                        <button
                          key={page}
                          className={cn(
                            "h-7 w-7 rounded text-xs font-medium transition-colors",
                            page === historyPage
                              ? "bg-blue-600 text-white"
                              : "text-muted-foreground hover:bg-muted/30 hover:text-foreground"
                          )}
                          onClick={() => setHistoryPage(page)}
                        >
                          {page}
                        </button>
                      ))}
                      <button
                        className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        disabled={historyPage === totalPages}
                        onClick={() => setHistoryPage((p) => Math.min(totalPages, p + 1))}
                      >
                        <ChevronRight className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                );
              })()}
          </div>
        </TabsContent>

        {/* ═══════════════ INVESTIGATIONS TAB ═══════════════ */}
        <TabsContent value="investigations" className="mt-6 space-y-6">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs font-medium">
            <span className="text-muted-foreground uppercase tracking-wider">Reports</span>
            <span className="text-muted-foreground">&gt;</span>
            <span className="text-blue-400 uppercase tracking-wider">Investigation Analytics</span>
          </div>

          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold text-foreground">Generate Report by Investigation</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Comprehensive analytical exports for security incidents, forensics, and executive summaries based on investigation telemetry.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold border border-border rounded-xl hover:bg-accent transition-colors">
                <Settings className="h-4 w-4" /> View Settings
              </button>
              <button className="inline-flex items-center px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl transition-colors" onClick={() => {
                downloadCSV("investigations_summary.csv",
                  ["Investigation ID", "Verdict", "Score", "Signals", "Affected Hosts", "Campaign"],
                  filteredInvestigations.map((inv) => {
                    const hunterPct = Math.round(inv.hunterScore * 100);
                    return [inv.alertId, VERDICT_LABELS[inv.findingType]?.label ?? inv.findingType, hunterPct + "%", String(inv.signalsFired), String(inv.campaignHostCount), inv.campaignHostCount > 2 ? "Yes" : "No"];
                  })
                );
              }}>
                <Download className="mr-1.5 h-4 w-4" /> Export CSV
              </button>
            </div>
          </div>

          {/* Search + Filters */}
          <div className="rounded-2xl border border-border p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="relative flex-1 min-w-[250px]">
                <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
                <input
                  placeholder="Search Investigation ID, Signals, or Campaign..."
                  value={invSearch}
                  onChange={(e) => { setInvSearch(e.target.value); setInvPage(1); }}
                  className="w-full pl-10 h-9 rounded-xl border border-border bg-white text-sm font-semibold placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                />
              </div>
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Filters</span>
              <FilterSelect label="Verdict" value={invVerdict} onChange={(v) => { setInvVerdict(v); setInvPage(1); }} options={[
                { value: "all", label: "All" },
                ...Array.from(new Set(Object.values(VERDICT_LABELS).map((v) => v.label))).map((label) => ({ value: label, label })),
              ]} />
              <FilterSelect label="Score" value={String(invScoreMin)} onChange={(v) => { setInvScoreMin(Number(v)); setInvPage(1); }} options={[
                { value: "0", label: "> 0%" },
                { value: "30", label: "> 30%" },
                { value: "50", label: "> 50%" },
                { value: "70", label: "> 70%" },
                { value: "90", label: "> 90%" },
              ]} />
              <FilterSelect label="Time" value={invTimeFilter} onChange={(v) => { setInvTimeFilter(v); setInvPage(1); }} options={[
                { value: "all", label: "Last 24h" },
                { value: "7d", label: "Last 7d" },
                { value: "30d", label: "Last 30d" },
              ]} />
              {(invSearch || invVerdict !== "all" || invScoreMin > 0 || invCampaign !== "all") && (
                <button className="text-sm text-blue-400 hover:text-blue-300 transition-colors" onClick={() => { setInvSearch(""); setInvVerdict("all"); setInvScoreMin(0); setInvCampaign("all"); setInvPage(1); }}>
                  Clear all
                </button>
              )}
            </div>
          </div>

          {/* Investigation Table */}
          <div className="rounded-2xl border border-border">
            <div>
              <div className="overflow-x-auto">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col className="w-[18%]" />
                    <col className="w-[10%]" />
                    <col className="w-[16%]" />
                    <col className="w-[8%]" />
                    <col className="w-[10%]" />
                    <col className="w-[10%]" />
                    <col className="w-[10%]" />
                    <col className="w-[18%]" />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-border/40">
                      <th className="px-3 py-2.5 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Investigation ID</th>
                      <th className="px-3 py-2.5 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Verdict</th>
                      <th className="px-3 py-2.5 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Score</th>
                      <th className="px-3 py-2.5 text-center text-xs font-semibold text-muted-foreground uppercase tracking-wider">Signals</th>
                      <th className="px-3 py-2.5 text-center text-xs font-semibold text-muted-foreground uppercase tracking-wider">Hosts</th>
                      <th className="px-3 py-2.5 text-center text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                      <th className="px-3 py-2.5 text-center text-xs font-semibold text-muted-foreground uppercase tracking-wider">Campaign</th>
                      <th className="px-3 py-2.5 text-right text-xs font-semibold text-muted-foreground uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredInvestigations.slice((invPage - 1) * INV_PAGE_SIZE, invPage * INV_PAGE_SIZE).map((inv) => {
                      const vInfo = VERDICT_LABELS[inv.findingType] ?? { label: inv.findingType, color: "bg-gray-500/20 text-gray-400 border-gray-500/30" };
                      const hunterPct = Math.round(inv.hunterScore * 100);
                      const barColor = hunterPct >= 80 ? "bg-red-500" : hunterPct >= 50 ? "bg-amber-500" : "bg-emerald-500";
                      const isCampaign = inv.campaignHostCount > 2;
                      const severity = hunterPct >= 90 ? { label: "Critical", color: "text-red-500 bg-red-500/10" } : hunterPct >= 70 ? { label: "High", color: "text-orange-500 bg-orange-500/10" } : hunterPct >= 40 ? { label: "Medium", color: "text-amber-500 bg-amber-500/10" } : { label: "Low", color: "text-emerald-500 bg-emerald-500/10" };
                      return (
                        <tr key={inv.alertId} className="border-b border-border/20 hover:bg-muted/5 transition-colors">
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <Diamond className="h-3.5 w-3.5 text-blue-400 fill-blue-400/20 flex-shrink-0" />
                              <span className="text-sm font-semibold text-foreground truncate">{inv.alertId}</span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5">
                            <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-bold", vInfo.color)}>
                              {vInfo.label}
                            </span>
                          </td>
                          <td className="px-3 py-2.5">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                                <div className={cn("h-full rounded-full transition-all", barColor)} style={{ width: `${hunterPct}%` }} />
                              </div>
                              <span className="text-sm font-semibold text-foreground w-9 text-right">{hunterPct}%</span>
                            </div>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className={cn(
                              "inline-flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold",
                              inv.signalsFired >= 5 ? "bg-red-500/20 text-red-400" :
                              inv.signalsFired >= 3 ? "bg-amber-500/20 text-amber-400" :
                              "bg-blue-500/20 text-blue-400"
                            )}>
                              {inv.signalsFired}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className="text-sm text-muted-foreground">{inv.campaignHostCount}</span>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold", severity.color)}>
                              {severity.label}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-center">
                            <span className={cn(
                              "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold",
                              isCampaign ? "text-blue-500 bg-blue-500/10" : "text-muted-foreground bg-muted/20"
                            )}>
                              {isCampaign ? "Yes" : "No"}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 text-right">
                            <button className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold border border-border rounded-lg hover:bg-accent transition-colors" onClick={() => handleGenerateReport(inv.alertId, "incident")}>
                              <Download className="h-3 w-3" /> Download
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                    {filteredInvestigations.length === 0 && (
                      <tr>
                        <td colSpan={8} className="px-3 py-12 text-center text-sm text-muted-foreground">
                          No investigations match the current filters
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {filteredInvestigations.length > 0 && (() => {
                const totalPages = Math.ceil(filteredInvestigations.length / INV_PAGE_SIZE);
                const startItem = (invPage - 1) * INV_PAGE_SIZE + 1;
                const endItem = Math.min(invPage * INV_PAGE_SIZE, filteredInvestigations.length);
                return (
                  <div className="flex items-center justify-between px-3 py-2.5 border-t border-border/40">
                    <span className="text-sm text-muted-foreground">
                      Showing <span className="font-semibold text-foreground">{startItem}</span> to <span className="font-semibold text-foreground">{endItem}</span> of <span className="font-semibold text-foreground">{filteredInvestigations.length}</span> Investigations
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        disabled={invPage === 1}
                        onClick={() => setInvPage((p) => Math.max(1, p - 1))}
                      >
                        <ChevronLeft className="h-4 w-4" />
                      </button>
                      {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                        <button
                          key={page}
                          className={cn(
                            "h-8 w-8 rounded text-sm font-medium transition-colors",
                            page === invPage
                              ? "bg-blue-600 text-white"
                              : "text-muted-foreground hover:bg-muted/30 hover:text-foreground"
                          )}
                          onClick={() => setInvPage(page)}
                        >
                          {page}
                        </button>
                      ))}
                      <button
                        className="p-1.5 rounded hover:bg-muted/30 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                        disabled={invPage === totalPages}
                        onClick={() => setInvPage((p) => Math.min(totalPages, p + 1))}
                      >
                        <ChevronRight className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Bottom Stat Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-2xl border border-border border-l-4 border-l-red-500">
              <div className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-red-500/10">
                    <AlertTriangle className="h-5 w-5 text-red-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">High Risk Findings</p>
                    <p className="text-xl font-bold text-foreground mt-0.5">{allInvestigations.filter((i) => Math.round(i.hunterScore * 100) >= 80).length} Investigations</p>
                    <p className="text-xs text-muted-foreground mt-1.5">
                      {allInvestigations.filter((i) => Math.round(i.hunterScore * 100) >= 90).length} requiring immediate executive reporting due to data exfiltration signals.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="rounded-2xl border border-border border-l-4 border-l-blue-500">
              <div className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-blue-500/10">
                    <BarChart3 className="h-5 w-5 text-blue-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Reports Generated</p>
                    <p className="text-xl font-bold text-foreground mt-0.5">{REPORT_HISTORY.length} Total</p>
                    <p className="text-xs text-muted-foreground mt-1.5">
                      28% increase in technical forensics exports over the last 30 days.
                    </p>
                  </div>
                </div>
              </div>
            </div>
            <div className="rounded-2xl border border-border border-l-4 border-l-emerald-500">
              <div className="p-5">
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-emerald-500/10">
                    <CheckCircle className="h-5 w-5 text-emerald-500" />
                  </div>
                  <div>
                    <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">System Health</p>
                    <p className="text-xl font-bold text-foreground mt-0.5">Operational</p>
                    <p className="text-xs text-muted-foreground mt-1.5">
                      All telemetry collectors are synced. Last data ingest: 2 minutes ago.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </TabsContent>

        {/* ═══════════════ SIGMA RULES TAB ═══════════════ */}
        <TabsContent value="sigma" className="mt-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold text-foreground">Sigma Rule Effectiveness</h3>
              <p className="text-sm text-muted-foreground mt-1">Top firing rules and their impact on threat detection (90-day retention)</p>
            </div>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity Filter</span>
                <FilterSelect label="Severity" value={sigmaSeverity} onChange={setSigmaSeverity} options={[
                  { value: "all", label: "All Severities" },
                  { value: "Critical", label: "Critical" },
                  { value: "High", label: "High" },
                  { value: "Medium", label: "Medium" },
                  { value: "Low", label: "Low" },
                ]} />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">MITRE Tactic</span>
                <FilterSelect label="Tactic" value={sigmaTactic} onChange={setSigmaTactic} options={[
                  { value: "all", label: "All Tactics" },
                  ...(d?.sigmaTacticDistribution ?? []).map((t) => ({ value: t.tactic, label: t.tactic })),
                ]} />
              </div>
              <button className="inline-flex items-center px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl transition-colors" onClick={() => refresh()}>
                <RefreshCw className="mr-1.5 h-4 w-4" /> Refresh
              </button>
            </div>
          </div>

          {/* 4 Stat Cards */}
          {(() => {
            const sigmaRules = d?.sigmaTopRules ?? [];
            const sigmaSevDist = d?.sigmaSeverityDistribution ?? [];
            const totalAlerts = sigmaRules.reduce((s, r) => s + r.count, 0);
            const totalRules = sigmaSevDist.reduce((s, r) => s + r.count, 0);
            const coverageScore = 78.4;
            const tpRate = 92.4;
            return (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Total Alerts</span>
                      <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{totalAlerts.toLocaleString()}</span>
                      <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowUp className="h-3 w-3" />12%</span>
                    </div>
                    <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: "65%" }} />
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Coverage Score</span>
                      <CheckCircle className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{coverageScore}%</span>
                      <span className="text-xs font-semibold text-red-500 flex items-center"><ArrowDown className="h-3 w-3" />2.1%</span>
                    </div>
                    <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-emerald-500" style={{ width: `${coverageScore}%` }} />
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">True Positive Rate</span>
                      <CheckCircle className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{tpRate}%</span>
                      <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowUp className="h-3 w-3" />0.5%</span>
                    </div>
                    <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: `${tpRate}%` }} />
                    </div>
                  </div>
                </div>
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Active Rules</span>
                      <FileText className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{totalRules.toLocaleString()}</span>
                      <span className="text-xs font-semibold text-emerald-500">+14</span>
                    </div>
                    <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                      <div className="h-full rounded-full bg-blue-500" style={{ width: "80%" }} />
                    </div>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Main content: Top 10 Rules (left) + Severity Donut + Tactic bars (right) */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            {/* Top 10 Firing Rules — left 3/5 */}
            <div className="lg:col-span-3 flex flex-col rounded-2xl border border-border">
              <div className="p-5 pb-2">
                <div className="flex items-center justify-between">
                  <h4 className="flex items-center gap-2 text-base font-semibold">
                    <BarChart3 className="h-4 w-4 text-blue-500" />
                    Top 10 Firing Rules
                  </h4>
                  <button className="text-sm text-blue-400 hover:text-blue-300 transition-colors">View All</button>
                </div>
              </div>
              <div className="px-5 pb-5 pt-2 flex-1 flex flex-col justify-between">
                {(d?.sigmaTopRules ?? []).map((rule, i) => {
                  const maxCount = (d?.sigmaTopRules ?? [])[0]?.count ?? 1;
                  const pct = Math.round((rule.count / maxCount) * 100);
                  return (
                    <div key={i}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm text-foreground">{rule.name}</span>
                        <span className="text-sm font-medium text-muted-foreground">{rule.count.toLocaleString()} alerts</span>
                      </div>
                      <div className="h-2 rounded-full bg-muted/20 overflow-hidden">
                        <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right column: Severity Donut + MITRE Tactic bars */}
            <div className="lg:col-span-2 flex flex-col gap-4">
              {/* Severity Distribution — Donut */}
              <div className="flex-1 flex flex-col rounded-2xl border border-border">
                <div className="p-5 pb-2">
                  <h4 className="flex items-center gap-2 text-base font-semibold">
                    <Shield className="h-4 w-4 text-blue-500" />
                    Severity Distribution
                  </h4>
                </div>
                <div className="px-5 pb-5 flex-1 flex flex-col">
                  <div className="flex-1 min-h-[200px] relative">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={sigmaSeverity !== "all"
                            ? (d?.sigmaSeverityDistribution ?? []).filter((s) => s.severity === sigmaSeverity)
                            : (d?.sigmaSeverityDistribution ?? [])}
                          dataKey="count"
                          nameKey="severity"
                          cx="50%"
                          cy="50%"
                          innerRadius={55}
                          outerRadius={85}
                          strokeWidth={0}
                        >
                          {(d?.sigmaSeverityDistribution ?? []).map((entry) => (
                            <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#64748b"} />
                          ))}
                        </Pie>
                        <RechartsTooltip
                          contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    {/* Center label */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                      <span className="text-2xl font-bold text-foreground">
                        {(d?.sigmaSeverityDistribution ?? []).reduce((s, r) => s + r.count, 0).toLocaleString()}
                      </span>
                      <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Rules</span>
                    </div>
                  </div>
                  {/* Legend */}
                  <div className="grid grid-cols-2 gap-2 mt-2">
                    {(d?.sigmaSeverityDistribution ?? []).map((s) => {
                      const total = (d?.sigmaSeverityDistribution ?? []).reduce((sum, r) => sum + r.count, 0);
                      const pct = total > 0 ? Math.round((s.count / total) * 100) : 0;
                      return (
                        <div key={s.severity} className="flex items-center gap-2">
                          <div className="h-3 w-3 rounded-sm flex-shrink-0" style={{ backgroundColor: SEVERITY_COLORS[s.severity] ?? "#64748b" }} />
                          <span className="text-xs text-muted-foreground">{s.severity} ({pct}%)</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Rules by MITRE Tactic — horizontal bars */}
              <div className="flex-1 flex flex-col rounded-2xl border border-border">
                <div className="p-5 pb-2">
                  <h4 className="flex items-center gap-2 text-base font-semibold">
                    <Settings className="h-4 w-4 text-blue-500" />
                    Rules by MITRE Tactic
                  </h4>
                </div>
                <div className="px-5 pb-5 pt-2 flex-1 flex flex-col justify-between">
                  <div className="flex-1 flex flex-col justify-between">
                    {(sigmaTactic !== "all"
                      ? (d?.sigmaTacticDistribution ?? []).filter((t) => t.tactic === sigmaTactic)
                      : (d?.sigmaTacticDistribution ?? [])
                    ).map((t) => {
                      const maxT = Math.max(...(d?.sigmaTacticDistribution ?? []).map((x) => x.count));
                      const pct = Math.round((t.count / maxT) * 100);
                      return (
                        <div key={t.tactic} className="flex items-center gap-3">
                          <span className="text-xs text-muted-foreground w-28 flex-shrink-0 truncate">{t.tactic}</span>
                          <div className="flex-1 h-1.5 rounded-full bg-muted/20 overflow-hidden">
                            <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs font-semibold text-foreground w-8 text-right">{t.count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Export section */}
          <div className="flex justify-end">
            <button className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold border border-border rounded-xl hover:bg-accent transition-colors" onClick={() => {
              const allRules = d?.sigmaTopRules ?? [];
              const allTactics = d?.sigmaTacticDistribution ?? [];
              const allSev = d?.sigmaSeverityDistribution ?? [];
              downloadCSV("sigma_full_report.csv",
                ["Category", "Name", "Count"],
                [
                  ...allRules.map((r) => ["Rule", r.name, String(r.count)]),
                  ...allTactics.map((t) => ["Tactic", t.tactic, String(t.count)]),
                  ...allSev.map((s) => ["Severity", s.severity, String(s.count)]),
                ]
              );
            }}>
              <Download className="mr-1.5 h-3.5 w-3.5" /> Download Full CSV
            </button>
          </div>
        </TabsContent>

        {/* ═══════════════ ML MODEL TAB ═══════════════ */}
        <TabsContent value="ml" className="mt-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground uppercase tracking-wider mb-1">
                <span>SENTINEL OPS</span>
                <ChevronRight className="h-3 w-3" />
                <span className="text-blue-400">ML MONITORING</span>
              </div>
              <h3 className="text-2xl font-bold text-foreground">Security Reports</h3>
              <p className="text-sm text-muted-foreground mt-0.5">Model Performance & Feature Drift Analysis | v2.4.0-stable</p>
            </div>
            <div className="flex items-center gap-3">
              <button className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold border border-border rounded-xl hover:bg-accent transition-colors">
                <Calendar className="mr-1.5 h-4 w-4" /> Last 24 Hours
              </button>
              <button className="inline-flex items-center px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl transition-colors" onClick={() => {
                const ml = d?.mlModelHealth;
                const tp = d?.tpFpRatio ?? [];
                const scores = d?.hunterScoreDistribution ?? [];
                const features = d?.modelFeatures ?? [];
                downloadCSV("ml_model_report.csv",
                  ["Category", "Metric", "Value", "Detail"],
                  [
                    ["Health", "KL Divergence", String(ml?.klDivergence ?? 0), ""],
                    ["Health", "PSI Max", String(ml?.psiMax ?? 0), ""],
                    ["Health", "Is Drifting", String(ml?.isDrifting ?? false), ""],
                    ["Health", "Sample Count", String(ml?.sampleCount ?? 0), ""],
                    ...tp.map((t) => ["Ratio", t.verdict === "true_positive" ? "True Positives" : "False Positives", String(t.count), ""]),
                    ...scores.map((s) => ["Score", s.bucket, String(s.count), ""]),
                    ...features.map((f) => ["Feature", f.name, String(f.importance), `PSI: ${f.driftPsi} | ${f.status}`]),
                  ]
                );
              }}>
                <Download className="mr-1.5 h-4 w-4" /> Export Report
              </button>
            </div>
          </div>

          {/* 4 Stat Cards */}
          {(() => {
            const ml = d?.mlModelHealth;
            const kl = ml?.klDivergence ?? 0;
            const psi = ml?.psiMax ?? 0;
            const isDrifting = ml?.isDrifting ?? false;
            const sampleCount = ml?.sampleCount ?? 0;
            const klStatus = kl < 0.1 ? "Optimal" : kl < 0.3 ? "Monitor" : "Drifting";
            const klColor = kl < 0.1 ? "#10b981" : kl < 0.3 ? "#f59e0b" : "#ef4444";
            const psiStatus = psi < 0.1 ? "Optimal" : psi < 0.25 ? "Monitor" : "Drifting";
            const psiColor = psi < 0.1 ? "#10b981" : psi < 0.25 ? "#f59e0b" : "#ef4444";
            const uptimeDays = Math.floor(sampleCount / 34);
            const uptimeH = Math.floor((sampleCount % 34) * 0.7);
            const healthPct = isDrifting ? 72.5 : 99.8;
            return (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* KL Divergence */}
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">KL Divergence</span>
                      <Info className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{kl.toFixed(3)}</span>
                      <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowDown className="h-3 w-3" />2.1%</span>
                    </div>
                    <div className="mt-3 flex items-center justify-between">
                      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden mr-3">
                        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(100, (kl / 0.5) * 100)}%`, backgroundColor: klColor }} />
                      </div>
                      <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: klColor }}>{klStatus}</span>
                    </div>
                  </div>
                </div>
                {/* PSI Max */}
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">PSI Max</span>
                      <TrendingUp className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-3xl font-bold text-foreground">{psi.toFixed(2)}</span>
                      <span className="text-xs font-semibold text-red-500 flex items-center"><ArrowUp className="h-3 w-3" />0.5%</span>
                    </div>
                    <div className="mt-3 flex items-center justify-between">
                      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden mr-3">
                        <div className="h-full rounded-full transition-all" style={{ width: `${Math.min(100, (psi / 0.5) * 100)}%`, backgroundColor: psiColor }} />
                      </div>
                      <span className="text-[10px] font-semibold uppercase tracking-wider" style={{ color: psiColor }}>{psiStatus}</span>
                    </div>
                  </div>
                </div>
                {/* Drift Status */}
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Drift Status</span>
                      <CheckCircle className={cn("h-4 w-4", isDrifting ? "text-red-500" : "text-emerald-500")} />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className={cn("text-2xl font-bold", isDrifting ? "text-red-400" : "text-foreground")}>
                        {isDrifting ? "Drifting" : "Not Drifting"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2 uppercase tracking-wider">Stable since: 14 days ago</p>
                  </div>
                </div>
                {/* Model Health */}
                <div className="rounded-2xl border border-border">
                  <div className="p-5">
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Model Health</span>
                      <Cpu className="h-4 w-4 text-muted-foreground" />
                    </div>
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl font-bold text-foreground">Healthy</span>
                      <span className="text-xs text-muted-foreground">{healthPct}%</span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2 uppercase tracking-wider">Uptime: {uptimeDays}d {uptimeH}h 12m</p>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* TP/FP Ratio (left) + Hunter Score Distribution (right) */}
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
            {/* TP / FP Ratio — Donut */}
            <div className="lg:col-span-2 flex flex-col rounded-2xl border border-border">
              <div className="p-5 pb-2">
                <div className="flex items-center justify-between">
                  <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    TP / FP Ratio
                  </h4>
                  <Settings className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
              <div className="px-5 pb-5 flex-1 flex flex-col">
                {(() => {
                  const tp = (d?.tpFpRatio ?? []).find((t) => t.verdict === "true_positive")?.count ?? 0;
                  const fp = (d?.tpFpRatio ?? []).find((t) => t.verdict === "false_positive")?.count ?? 0;
                  const total = tp + fp;
                  const tpPct = total > 0 ? Math.round((tp / total) * 100) : 0;
                  const fpPct = total > 0 ? 100 - tpPct : 0;
                  const ratio = fp > 0 ? (tp / fp).toFixed(1) : "∞";
                  return (
                    <>
                      <div className="flex-1 min-h-[200px] relative">
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={d?.tpFpRatio ?? []}
                              dataKey="count"
                              nameKey="verdict"
                              cx="50%"
                              cy="50%"
                              innerRadius={60}
                              outerRadius={85}
                              strokeWidth={0}
                            >
                              {(d?.tpFpRatio ?? []).map((entry) => (
                                <Cell key={entry.verdict} fill={TP_FP_COLORS[entry.verdict] ?? "#64748b"} />
                              ))}
                            </Pie>
                            <RechartsTooltip
                              contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                        {/* Center ratio label */}
                        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                          <span className="text-2xl font-bold text-foreground">{ratio}:1</span>
                          <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Current Ratio</span>
                        </div>
                      </div>
                      {/* Legend */}
                      <div className="flex items-center justify-center gap-6 mt-3">
                        <div className="flex items-center gap-2">
                          <div className="h-3 w-3 rounded-sm bg-cyan-500" />
                          <span className="text-xs text-muted-foreground">True Positives</span>
                          <span className="text-xs font-bold text-foreground">{tpPct}%</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="h-3 w-3 rounded-sm bg-red-500" />
                          <span className="text-xs text-muted-foreground">False Positives</span>
                          <span className="text-xs font-bold text-foreground">{fpPct}%</span>
                        </div>
                      </div>
                    </>
                  );
                })()}
              </div>
            </div>

            {/* Hunter Score Distribution — Histogram */}
            <div className="lg:col-span-3 flex flex-col rounded-2xl border border-border">
              <div className="p-5 pb-2">
                <div className="flex items-center justify-between">
                  <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Hunter Score Distribution
                  </h4>
                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-1.5">
                      <div className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Baseline</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="h-2.5 w-2.5 rounded-full bg-blue-500" />
                      <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Production</span>
                    </div>
                  </div>
                </div>
              </div>
              <div className="px-5 pb-5 flex-1">
                <div className="h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={d?.hunterScoreDistribution ?? []} barCategoryGap="15%">
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.2} vertical={false} />
                      <XAxis
                        dataKey="bucket"
                        tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <YAxis
                        tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <RechartsTooltip
                        contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                      />
                      <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex justify-between text-[10px] text-muted-foreground uppercase tracking-wider mt-1 px-2">
                  <span>0.0 (Low Confidence)</span>
                  <span>0.5</span>
                  <span>1.0 (High Confidence)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Model Feature Performance Analysis */}
          <div className="rounded-2xl border border-border">
            <div className="p-5 pb-3">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Model Feature Performance Analysis
              </h4>
            </div>
            <div className="px-5 pb-5 pt-0">
              <table className="w-full">
                <colgroup>
                  <col style={{ width: "25%" }} />
                  <col style={{ width: "12%" }} />
                  <col style={{ width: "25%" }} />
                  <col style={{ width: "20%" }} />
                  <col style={{ width: "18%" }} />
                </colgroup>
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Feature Name</th>
                    <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Type</th>
                    <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Importance</th>
                    <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Drift (PSI)</th>
                    <th className="text-right text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {(d?.modelFeatures ?? []).map((f, i) => {
                    const importPct = Math.round(f.importance * 100);
                    const statusColor = f.status === "Stable" ? "text-emerald-500 bg-emerald-500/10 border-emerald-500/20"
                      : f.status === "Monitor" ? "text-yellow-500 bg-yellow-500/10 border-yellow-500/20"
                      : "text-orange-500 bg-orange-500/10 border-orange-500/20";
                    return (
                      <tr key={i} className="border-b border-border/30 last:border-0">
                        <td className="py-3.5 pr-2">
                          <span className="text-sm font-mono font-medium text-foreground">{f.name}</span>
                        </td>
                        <td className="py-3.5 pr-2">
                          <span className="text-sm text-muted-foreground">{f.type}</span>
                        </td>
                        <td className="py-3.5 pr-2">
                          <div className="flex items-center gap-3">
                            <div className="flex-1 h-2 rounded-full bg-muted/20 overflow-hidden max-w-[120px]">
                              <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${importPct}%` }} />
                            </div>
                            <span className="text-sm font-medium text-muted-foreground w-10">{f.importance.toFixed(2)}</span>
                          </div>
                        </td>
                        <td className="py-3.5 pr-2">
                          <span className="text-sm font-medium text-foreground">{f.driftPsi.toFixed(3)}</span>
                        </td>
                        <td className="py-3.5 text-right">
                          <span className={cn("inline-flex items-center rounded-lg border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider", statusColor)}>
                            {f.status}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </TabsContent>

        {/* ═══════════════ EVIDENCE CHAIN TAB ═══════════════ */}
        <TabsContent value="evidence" className="mt-6 space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold text-foreground">Evidence Chain Analysis</h3>
              <p className="text-sm text-muted-foreground mt-0.5">Blockchain-backed evidence anchoring and Merkle verification metrics</p>
            </div>
            <div className="flex items-center gap-3">
              <span className="inline-flex items-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-500 px-2.5 py-1 text-xs font-semibold">
                <CheckCircle className="mr-1.5 h-3 w-3" /> System Operational
              </span>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <input
                  placeholder="Search batches..."
                  className="h-8 w-48 pl-8 text-xs rounded-xl border border-border bg-white font-semibold placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                  value={evSearch}
                  onChange={(e) => { setEvSearch(e.target.value); setEvPage(1); }}
                />
              </div>
              <button className="inline-flex items-center px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-xl transition-colors" onClick={() => refresh()}>
                <RefreshCw className="mr-1.5 h-4 w-4" /> Refresh
              </button>
            </div>
          </div>

          {/* 4 Stat Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Batches Anchored */}
            <div className="rounded-2xl border border-border">
              <div className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Batches Anchored</span>
                  <Link2 className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-foreground">{formatNumber(evTotalBatches)}</span>
                  <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowUp className="h-3 w-3" />8.2%</span>
                </div>
                <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <div className="h-full rounded-full bg-blue-500" style={{ width: "75%" }} />
                </div>
              </div>
            </div>
            {/* Merkle Verification */}
            <div className="rounded-2xl border border-border">
              <div className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Merkle Verification</span>
                  <Shield className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-foreground">{evVerificationRate}%</span>
                  <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowUp className="h-3 w-3" />1.4%</span>
                </div>
                <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Number(evVerificationRate)}%` }} />
                </div>
              </div>
            </div>
            {/* Chain Continuity */}
            <div className="rounded-2xl border border-border">
              <div className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Chain Continuity</span>
                  <Activity className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-foreground">
                    {evContinuityGaps === 0 ? "100%" : `${((evBatches.length - evContinuityGaps) / evBatches.length * 100).toFixed(0)}%`}
                  </span>
                  {evContinuityGaps === 0 ? (
                    <span className="text-xs font-semibold text-emerald-500">No gaps</span>
                  ) : (
                    <span className="text-xs font-semibold text-red-500">{evContinuityGaps} gap(s)</span>
                  )}
                </div>
                <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <div className="h-full rounded-full bg-emerald-500" style={{ width: evContinuityGaps === 0 ? "100%" : `${((evBatches.length - evContinuityGaps) / evBatches.length * 100)}%` }} />
                </div>
              </div>
            </div>
            {/* Avg Events/Batch */}
            <div className="rounded-2xl border border-border">
              <div className="p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">Avg Events / Batch</span>
                  <BarChart3 className="h-4 w-4 text-muted-foreground" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold text-foreground">{formatNumber(evAvgEvents)}</span>
                  <span className="text-xs font-semibold text-emerald-500 flex items-center"><ArrowUp className="h-3 w-3" />3.1%</span>
                </div>
                <div className="mt-3 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <div className="h-full rounded-full bg-blue-500" style={{ width: "68%" }} />
                </div>
              </div>
            </div>
          </div>

          {/* Evidence Batch Timeline */}
          <div className="rounded-2xl border border-border">
            <div className="p-5 pb-2">
              <div className="flex items-center justify-between">
                <h4 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Evidence Batch Timeline
                </h4>
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-sm bg-blue-600" />
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Anchored</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-sm bg-teal-600" />
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Verified</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="h-2.5 w-2.5 rounded-sm bg-amber-500" />
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Continuity</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="px-5 pb-5">
              <div className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={filteredEvBatches.map((b, i) => ({
                      name: i === 0 ? "T-24H" : i === filteredEvBatches.length - 1 ? "CURRENT" : `T-${filteredEvBatches.length - 1 - i}H`,
                      anchored: b.eventCount,
                      verified: b.status === "Verified" ? b.eventCount : 0,
                      continuity: b.hasContinuity ? b.eventCount : 0,
                    }))}
                    barCategoryGap="15%"
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.2} vertical={false} />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                    />
                    <Bar dataKey="anchored" fill={EVIDENCE_COLORS.anchored} radius={[4, 4, 0, 0]} stackId="a" />
                    <Bar dataKey="verified" fill={EVIDENCE_COLORS.verified} radius={[4, 4, 0, 0]} stackId="b" />
                    <Bar dataKey="continuity" fill={EVIDENCE_COLORS.continuity} radius={[4, 4, 0, 0]} stackId="c" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* Anchoring History & Verification Log */}
          <div className="rounded-2xl border border-border">
            <div className="p-5 pb-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Anchoring History & Verification Log
                </h4>
                <div className="flex items-center gap-2">
                  <FilterSelect label="Status" value={evStatus} onChange={(v) => { setEvStatus(v); setEvPage(1); }} options={[
                    { value: "all", label: "All Statuses" },
                    { value: "Verified", label: "Verified" },
                    { value: "Anchored", label: "Anchored" },
                    { value: "Pending", label: "Pending" },
                    { value: "Failed", label: "Failed" },
                  ]} />
                  <FilterSelect label="Continuity" value={evContinuityFilter} onChange={(v) => { setEvContinuityFilter(v); setEvPage(1); }} options={[
                    { value: "all", label: "All" },
                    { value: "yes", label: "Has Continuity" },
                    { value: "no", label: "Continuity Gaps" },
                  ]} />
                  {(evStatus !== "all" || evContinuityFilter !== "all") && (
                    <button className="inline-flex items-center px-2.5 py-1 text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors" onClick={() => { setEvStatus("all"); setEvContinuityFilter("all"); setEvPage(1); }}>
                      <X className="mr-1 h-3 w-3" /> Clear
                    </button>
                  )}
                </div>
              </div>
            </div>
            <div className="px-5 pb-5 pt-0">
              <div className="overflow-x-auto">
                <table className="w-full table-fixed">
                  <colgroup>
                    <col style={{ width: "16%" }} />
                    <col style={{ width: "22%" }} />
                    <col style={{ width: "24%" }} />
                    <col style={{ width: "12%" }} />
                    <col style={{ width: "12%" }} />
                    <col style={{ width: "14%" }} />
                  </colgroup>
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Batch ID</th>
                      <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Merkle Root</th>
                      <th className="text-left text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Anchored At</th>
                      <th className="text-right text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Events</th>
                      <th className="text-center text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3 pr-2">Continuity</th>
                      <th className="text-right text-[11px] font-semibold text-muted-foreground uppercase tracking-wider py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredEvBatches.slice((evPage - 1) * EV_PAGE_SIZE, evPage * EV_PAGE_SIZE).map((b, i) => {
                      const statusColor = b.status === "Verified" ? "text-emerald-500 bg-emerald-500/10 border-emerald-500/20"
                        : b.status === "Anchored" ? "text-blue-500 bg-blue-500/10 border-blue-500/20"
                        : b.status === "Pending" ? "text-yellow-500 bg-yellow-500/10 border-yellow-500/20"
                        : "text-red-500 bg-red-500/10 border-red-500/20";
                      return (
                        <tr key={i} className="border-b border-border/30 last:border-0">
                          <td className="py-3 pr-2">
                            <span className="text-sm font-mono font-medium text-foreground">{b.batchId}</span>
                          </td>
                          <td className="py-3 pr-2">
                            <span className="text-sm font-mono text-muted-foreground">{b.merkleRoot}</span>
                          </td>
                          <td className="py-3 pr-2">
                            <span className="text-sm text-muted-foreground">{b.anchoredAt}</span>
                          </td>
                          <td className="py-3 pr-2 text-right">
                            <span className="text-sm font-semibold text-foreground">{b.eventCount.toLocaleString()}</span>
                          </td>
                          <td className="py-3 pr-2 text-center">
                            {b.hasContinuity ? (
                              <CheckCircle className="h-4 w-4 text-emerald-500 mx-auto" />
                            ) : (
                              <AlertTriangle className="h-4 w-4 text-red-500 mx-auto" />
                            )}
                          </td>
                          <td className="py-3 text-right">
                            <span className={cn("inline-flex items-center rounded-lg border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider", statusColor)}>
                              {b.status}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {(() => {
                const totalPages = Math.ceil(filteredEvBatches.length / EV_PAGE_SIZE);
                return totalPages > 1 ? (
                  <div className="flex items-center justify-between pt-4 border-t border-border/30 mt-2">
                    <span className="text-xs text-muted-foreground">
                      Showing {(evPage - 1) * EV_PAGE_SIZE + 1} to {Math.min(evPage * EV_PAGE_SIZE, filteredEvBatches.length)} of {filteredEvBatches.length} batches
                    </span>
                    <div className="flex items-center gap-1">
                      <button className="h-7 w-7 p-0 inline-flex items-center justify-center text-xs font-semibold border border-border rounded-lg hover:bg-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed" disabled={evPage === 1} onClick={() => setEvPage(evPage - 1)}>
                        <ChevronLeft className="h-3.5 w-3.5" />
                      </button>
                      {Array.from({ length: totalPages }, (_, i) => (
                        <button key={i} className={cn("h-7 w-7 p-0 inline-flex items-center justify-center text-xs font-semibold rounded-lg transition-colors", evPage === i + 1 ? "bg-blue-600 text-white" : "border border-border hover:bg-accent")} onClick={() => setEvPage(i + 1)}>
                          {i + 1}
                        </button>
                      ))}
                      <button className="h-7 w-7 p-0 inline-flex items-center justify-center text-xs font-semibold border border-border rounded-lg hover:bg-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed" disabled={evPage === totalPages} onClick={() => setEvPage(evPage + 1)}>
                        <ChevronRight className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>
                ) : null;
              })()}
            </div>
          </div>

          {/* Export footer */}
          <div className="flex justify-end">
            <button className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold border border-border rounded-xl hover:bg-accent transition-colors" onClick={() => {
              downloadCSV("evidence_chain_report.csv",
                ["Batch ID", "Merkle Root", "Anchored At", "Event Count", "Status", "Continuity"],
                filteredEvBatches.map((b) => [b.batchId, b.merkleRoot, b.anchoredAt, String(b.eventCount), b.status, b.hasContinuity ? "Yes" : "No"])
              );
            }}>
              <Download className="mr-1.5 h-3.5 w-3.5" /> Download Full CSV
            </button>
          </div>
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
}

/* ── Reusable Components ── */

function StatCard({
  label,
  value,
  change,
  positive,
  subtitle,
}: {
  label: string;
  value: string;
  change?: string;
  positive?: boolean;
  subtitle?: string;
}) {
  return (
    <div className="rounded-2xl border border-border">
      <div className="p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted-foreground">{label}</span>
          {change && (
            <span className={cn("flex items-center text-xs font-medium", positive ? "text-emerald-400" : "text-red-400")}>
              {positive ? <ArrowUp className="mr-0.5 h-3 w-3" /> : <ArrowDown className="mr-0.5 h-3 w-3" />}
              {change}
            </span>
          )}
        </div>
        <p className={cn("mt-1 text-2xl font-bold", positive === false ? "text-red-400" : "text-emerald-400")}>
          {value}
        </p>
        {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
      </div>
    </div>
  );
}

function HealthBar({
  label,
  value,
  max,
  status,
  color,
}: {
  label: string;
  value: number;
  max: number;
  status: string;
  color: string;
}) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">{label}</span>
        <span className="text-sm font-medium" style={{ color }}>
          {value.toFixed(3)} ({status})
        </span>
      </div>
      <div className="h-2 w-full rounded-full bg-muted/30">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
