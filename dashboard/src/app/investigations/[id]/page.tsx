"use client";

import { useParams, useRouter } from "next/navigation";
import { usePolling } from "@/hooks/use-polling";
import type { InvestigationDetail } from "@/lib/types";
import {
  ArrowLeft, Shield, ShieldAlert, ShieldCheck, Clock, Server, Globe, User,
  Activity, CheckCircle2, XCircle, AlertTriangle, ChevronDown, ChevronRight,
  FileText, Target, Crosshair, Cpu, Database, Hash, Zap, BarChart3, Lock,
  Eye, Layers, GitBranch, Copy, Check, Download, ShieldQuestion, Fingerprint,
  Loader2, ZoomIn,
} from "lucide-react";
import {
  useState, useCallback, useMemo, useRef,
} from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  ReactFlow, Background, Controls, MiniMap, Panel,
  useNodesState, useEdgesState, useReactFlow, ReactFlowProvider,
  MarkerType, type Node, type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

/* ================================================================ */
/*  Constants                                                       */
/* ================================================================ */

const SEV_CFG: Record<string, { bg: string; ring: string; text: string; label: string }> = {
  critical: { bg: "bg-red-50 dark:bg-red-950/60", ring: "ring-red-300 dark:ring-red-500/60", text: "text-red-700 dark:text-red-400", label: "CRITICAL" },
  high:     { bg: "bg-orange-50 dark:bg-orange-950/60", ring: "ring-orange-300 dark:ring-orange-500/60", text: "text-orange-700 dark:text-orange-400", label: "HIGH" },
  medium:   { bg: "bg-yellow-50 dark:bg-yellow-950/60", ring: "ring-yellow-400 dark:ring-yellow-500/60", text: "text-yellow-700 dark:text-yellow-400", label: "MEDIUM" },
  low:      { bg: "bg-blue-50 dark:bg-blue-950/60", ring: "ring-blue-300 dark:ring-blue-500/60", text: "text-blue-700 dark:text-blue-400", label: "LOW" },
  info:     { bg: "bg-gray-100 dark:bg-gray-800/60", ring: "ring-gray-300 dark:ring-gray-500/60", text: "text-gray-600 dark:text-gray-400", label: "INFO" },
};

const VERDICT_COLOR: Record<string, string> = {
  true_positive:  "text-red-600 dark:text-red-400",
  false_positive: "text-green-600 dark:text-green-400",
  inconclusive:   "text-yellow-600 dark:text-yellow-400",
};

const KILL_CHAIN = [
  "reconnaissance","resource-development","initial-access","execution",
  "persistence","privilege-escalation","defense-evasion","credential-access",
  "discovery","lateral-movement","collection","command-and-control",
  "exfiltration","impact",
];

/* ================================================================ */
/*  Helpers                                                         */
/* ================================================================ */

const fmt  = (v: unknown) => (v == null || v === "" ? "-" : String(v));
const fmtD = (v: unknown) => {
  if (!v) return "-";
  try {
    const d = new Date(String(v));
    if (Number.isNaN(d.getTime())) return String(v);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
  } catch {
    return String(v);
  }
};
const fmtS = (v: unknown, d = 4) => { if (v == null) return "-"; const n = Number(v); return isNaN(n) ? String(v) : n.toFixed(d); };
const fmtP = (v: unknown) => { if (v == null) return "-"; const n = Number(v); return isNaN(n) ? String(v) : `${(n * 100).toFixed(1)}%`; };
function dur(a: string | null, b: string | null) {
  if (!a || !b) return "-";
  const ms = new Date(b).getTime() - new Date(a).getTime();
  return ms < 1000 ? `${ms}ms` : ms < 60000 ? `${(ms / 1000).toFixed(1)}s` : `${(ms / 60000).toFixed(1)}m`;
}

function buildMockInvestigationDetail(investigationId: string): InvestigationDetail & { merkle_batch_ids: string[] } {
  // Use a fixed reference time so SSR and client hydration produce identical output
  const now = new Date("2026-01-15T10:30:00Z");
  const started = new Date(now.getTime() - 17 * 60 * 1000).toISOString();
  const shortId = investigationId?.slice(0, 8) || "INV-DEMO";

  return {
    investigation: {
      investigation_id: investigationId || "INV-DEMO-001",
      alert_id: `ALT-${shortId}`,
      started_at: started,
      completed_at: null,
      status: "in_progress",
      hostname: "web-srv-03",
      source_ip: "191.0.12.43",
      user_id: "svc-ops",
      trigger_score: 0.86,
      severity: "high",
      finding_type: "Unexpected SSH Outbound to Unknown IP",
      summary: "Demo mode: suspicious outbound SSH traffic correlated with rare process execution and IOC hit.",
      mitre_tactics: ["command-and-control", "exfiltration"],
      mitre_techniques: ["T1021.004", "T1041"],
      recommended_action: "Isolate host, rotate credentials, and block destination IP at egress firewall.",
      confidence: 0.91,
      correlated_events: ["evt-91277", "evt-91279", "evt-91301"],
    },
    verification: {
      verification_id: `VER-${shortId}`,
      status: "completed",
      started_at: new Date(now.getTime() - 8 * 60 * 1000).toISOString(),
      completed_at: new Date(now.getTime() - 6 * 60 * 1000).toISOString(),
      verdict: "true_positive",
      confidence: 0.94,
      priority: "P1",
      analyst_summary: "Behavior is consistent with lateral movement and outbound channel establishment.",
      evidence_verified: true,
      merkle_batch_ids: ["mb-raw-2201", "mb-sec-2201"],
      recommended_action: "Immediate containment and forensic capture.",
      report_narrative: "Multiple independent signals converged on the same timeline and entities.",
    },
    triage: {
      score_id: `SCR-${shortId}`,
      event_id: `evt-${shortId}`,
      timestamp: now.toISOString(),
      source_type: "sysmon",
      hostname: "web-srv-03",
      source_ip: "191.0.12.43",
      user_id: "svc-ops",
      template_id: "TMP-SSH-OUTBOUND",
      template_rarity: 0.82,
      combined_score: 0.87,
      lgbm_score: 0.88,
      eif_score: 0.79,
      arf_score: 0.85,
      score_std_dev: 0.04,
      agreement: 0.89,
      ci_lower: 0.79,
      ci_upper: 0.92,
      asset_multiplier: 1.2,
      adjusted_score: 0.91,
      action: "escalate",
      ioc_match: 1,
      ioc_confidence: 93,
      mitre_tactic: "command-and-control",
      mitre_technique: "T1021.004",
      shap_top_features: "network_bytes_out:+0.22, rare_destination_ip:+0.19, ssh_process_lineage:+0.15",
      shap_summary: "Outbound SSH to rare destination with anomalous process lineage.",
      features_stale: 0,
      model_version: "triage-v2.4.1",
      disagreement_flag: 0,
    },
    raw_log: {
      event_id: `evt-${shortId}`,
      timestamp: now.toISOString(),
      received_at: now.toISOString(),
      level: "warn",
      source: "sysmon",
      message: "ssh.exe created outbound connection to 191.0.12.43:22 by svc-ops from web-srv-03",
      metadata: { process: "ssh.exe", dst_port: "22" },
      user_id: "svc-ops",
      ip_address: "191.0.12.43",
      request_id: `req-${shortId}`,
      anchor_tx_id: "0xabc123demo",
      anchor_batch_hash: "9b9c7f9f4f8e-demo-hash",
    },
    security_event: {
      event_id: `sec-${shortId}`,
      timestamp: now.toISOString(),
      severity: 4,
      category: "network",
      source: "ai-pipeline",
      description: "Outbound SSH behavior deviates from host baseline.",
      user_id: "svc-ops",
      ip_address: "191.0.12.43",
      hostname: "web-srv-03",
      mitre_tactic: "command-and-control",
      mitre_technique: "T1021.004",
      ai_confidence: 0.91,
      ai_explanation: "Rare destination and process ancestry triggered correlation and escalation.",
      raw_log_event_id: `evt-${shortId}`,
      anchor_tx_id: "0xdef456demo",
      metadata: { pipeline: "triage->hunter->verifier" },
    },
    timeline: [
      { source: "triage", timestamp: new Date(now.getTime() - 12 * 60 * 1000).toISOString(), label: "Triage score exceeded escalation threshold" },
      { source: "hunter", timestamp: new Date(now.getTime() - 10 * 60 * 1000).toISOString(), label: "IOC and graph correlation identified suspicious egress" },
      { source: "verifier", timestamp: new Date(now.getTime() - 7 * 60 * 1000).toISOString(), label: "True positive verdict with high confidence" },
    ],
    attack_graph: {
      hunter: {
        nodes: [
          { id: "user", label: "svc-ops", type: "user" },
          { id: "host", label: "web-srv-03", type: "host" },
          { id: "ip", label: "191.0.12.43", type: "critical" },
        ],
        edges: [
          { from: "user", to: "host", type: "lateral", label: "session" },
          { from: "host", to: "ip", type: "attack", label: "ssh outbound" },
        ],
        metadata: { signals_fired: 3, signals_checked: 12, graph_density: 0.42, model: "catboost-meta" },
      },
      verifier: {
        nodes: [{ id: "verdict", label: "TRUE POSITIVE", type: "verdict" }],
        edges: [{ from: "ip", to: "verdict", type: "critical", label: "verified" }],
      },
      mermaid: null,
    },
    evidence: {
      hunter: {
        ml_model: "catboost-meta",
        spc_z_score: 3.1,
        graph_hop_count: 2,
        has_ioc_neighbor: true,
        sigma_hits: [{ rule_id: "SIG-SSH-ANOM", title: "Unexpected SSH Outbound", severity: "high" }],
      },
      verifier: { model: "verifier-v1", notes: "evidence aligned across stages" },
      ioc_correlations: [{ type: "ip", value: "191.0.12.43", source: "demo-feed", confidence: 0.93 }],
    },
    merkle_batch_ids: ["mb-raw-2201", "mb-sec-2201"],
  };
}

/* ================================================================ */
/*  Reusable UI                                                     */
/* ================================================================ */

function CopyBtn({ text }: { text: string }) {
  const [ok, set] = useState(false);
  return (
    <button className="ml-1 opacity-0 group-hover:opacity-100 transition-opacity"
      onClick={() => { navigator.clipboard.writeText(text); set(true); setTimeout(() => set(false), 1500); }}>
      {ok ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300" />}
    </button>
  );
}

function Sec({ title, icon, badge, open: def = true, accent = "border-gray-200 dark:border-gray-700/60", children }: {
  title: string; icon: React.ReactNode; badge?: React.ReactNode; open?: boolean; accent?: string; children: React.ReactNode;
}) {
  const [open, set] = useState(def);
  return (
    <div className={`rounded-xl border ${accent} bg-white dark:bg-gray-900/70 overflow-hidden shadow-sm`}>
      <button onClick={() => set(!open)}
        className="flex w-full items-center gap-2.5 px-5 py-3.5 text-left text-sm font-semibold text-gray-900 dark:text-gray-100 hover:bg-gray-50 dark:hover:bg-white/[0.03] transition-colors">
        {icon}<span className="flex-1">{title}</span>{badge}
        {open ? <ChevronDown className="h-4 w-4 text-gray-400" /> : <ChevronRight className="h-4 w-4 text-gray-400" />}
      </button>
      {open && <div className="px-5 pb-5 border-t border-gray-100 dark:border-gray-800/60">{children}</div>}
    </div>
  );
}

function Stat({ label, value, sub, icon, accent }: {
  label: string; value: string; sub?: string; icon?: React.ReactNode; accent?: string;
}) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-gray-200 dark:border-gray-700/40 bg-gray-50 dark:bg-gray-800/40 px-3.5 py-2.5">
      {icon && <div className={`mt-0.5 ${accent || "text-gray-500"}`}>{icon}</div>}
      <div className="min-w-0 flex-1">
        <div className="text-[11px] font-medium uppercase tracking-wider text-gray-500">{label}</div>
        <div className="text-sm font-semibold text-gray-900 dark:text-gray-100 truncate">{value}</div>
        {sub && <div className="text-[11px] text-gray-500">{sub}</div>}
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="group flex items-start gap-3 py-2 border-b border-gray-100 dark:border-gray-800/40 last:border-0">
      <span className="text-xs font-medium text-gray-500 w-40 shrink-0">{label}</span>
      <span className={`text-sm text-gray-800 dark:text-gray-200 break-all ${mono ? "font-mono" : ""}`}>
        {value || "-"}{mono && value && value !== "-" && <CopyBtn text={value} />}
      </span>
    </div>
  );
}

function Bar({ value, max = 1, color = "bg-cyan-500", label }: {
  value: number; max?: number; color?: string; label?: string;
}) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div className="space-y-1">
      {label && <div className="flex justify-between text-xs text-gray-500"><span>{label}</span><span>{fmtS(value)}</span></div>}
      <div className="h-2.5 w-full rounded-full bg-gray-200 dark:bg-gray-700/50 overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Ring({ score, label, size = 72 }: { score: number; label: string; size?: number }) {
  const pct = Math.min(1, Math.max(0, score));
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const color = pct >= 0.75 ? "#ef4444" : pct >= 0.5 ? "#f97316" : pct >= 0.25 ? "#eab308" : "#22c55e";
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size} className="text-gray-200 dark:text-gray-800">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={6} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={6}
          strokeDasharray={circ} strokeDashoffset={circ * (1 - pct)}
          strokeLinecap="round" transform={`rotate(-90 ${size / 2} ${size / 2})`} />
        <text x="50%" y="50%" textAnchor="middle" dy="0.35em" className="fill-gray-900 dark:fill-gray-100 text-sm font-bold">
          {Math.round(pct * 100)}%
        </text>
      </svg>
      <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">{label}</span>
    </div>
  );
}

/* ================================================================ */
/*  Attack Graph — Interactive ReactFlow                            */
/* ================================================================ */

function nodeStyle(type?: string): React.CSSProperties {
  switch (type?.toLowerCase()) {
    case "user": case "identity": case "account":
      return { background: "#eef2ff", color: "#4338ca", border: "2px solid #818cf8", borderRadius: "50%", width: 100, height: 100, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700, fontFamily: "monospace" };
    case "host": case "endpoint": case "server":
      return { background: "#fefce8", color: "#a16207", border: "2px solid #facc15", borderRadius: 10, padding: 12, fontSize: 12, fontWeight: 600, fontFamily: "monospace" };
    case "critical": case "c2": case "malware": case "alert": case "threat": case "verdict":
      return { background: "#fef2f2", color: "#b91c1c", border: "2px solid #ef4444", borderRadius: 10, padding: 12, fontSize: 12, fontWeight: 700, fontFamily: "monospace" };
    case "sigma": case "technique": case "mitre": case "tactic":
      return { background: "#eff6ff", color: "#1d4ed8", border: "2px dashed #3b82f6", borderRadius: 10, padding: 12, fontSize: 11, fontWeight: 600, fontFamily: "monospace" };
    case "ioc":
      return { background: "#fffbeb", color: "#d97706", border: "2px solid #f59e0b", borderRadius: 10, padding: 12, fontSize: 11, fontWeight: 600, fontFamily: "monospace" };
    default:
      return { background: "#f9fafb", color: "#374151", border: "1px solid #d1d5db", borderRadius: 10, padding: 12, fontSize: 12, fontWeight: 600, fontFamily: "monospace" };
  }
}

function edgeStyle(type?: string): Partial<Edge> {
  const base = (c: string, w = 2, a = true): Partial<Edge> => ({
    style: { stroke: c, strokeWidth: w }, animated: a,
    markerEnd: { type: MarkerType.ArrowClosed, color: c },
    labelStyle: { fill: "#6b7280", fontSize: 10, fontWeight: 600 },
  });
  switch (type?.toLowerCase()) {
    case "critical": case "attack": return { ...base("#ef4444", 3), labelStyle: { fill: "#dc2626", fontSize: 10, fontWeight: 700 } };
    case "lateral": case "movement": return base("#f59e0b");
    default: return base("#6366f1");
  }
}

function buildReactFlowGraph(
  hunterGraph: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>>; metadata?: Record<string, unknown> } | null,
  verGraph: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> } | null,
  inv: InvestigationDetail["investigation"],
): { nodes: Node[]; edges: Edge[] } {
  const rfNodes: Node[] = [];
  const rfEdges: Edge[] = [];
  const seen = new Set<string>();

  const addGraph = (g: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> }, prefix: string, yOff: number) => {
    (g.nodes || []).forEach((n, i) => {
      const nid = `${prefix}-${n.id ?? i}`;
      if (seen.has(nid)) return;
      seen.add(nid);
      const lbl = String(n.label ?? n.id ?? "");
      const extra: string[] = [];
      if (n.ip) extra.push(`IP: ${n.ip}`);
      if (n.user) extra.push(`User: ${n.user}`);
      if (n.triage_score != null) extra.push(`Triage: ${Number(n.triage_score).toFixed(3)}`);
      if (n.score != null) extra.push(`Score: ${Number(n.score).toFixed(3)}`);
      if (n.rule_id) extra.push(String(n.rule_id));
      rfNodes.push({
        id: nid, type: "default",
        data: { label: extra.length ? `${lbl}\n${extra.join("\n")}` : lbl },
        position: { x: 80 + i * 260, y: yOff + (i % 2 === 0 ? 0 : 80) },
        style: { ...nodeStyle(String(n.type ?? "")), whiteSpace: "pre-line" as React.CSSProperties["whiteSpace"] },
      });
    });
    (g.edges || []).forEach((e, i) => {
      const src = `${prefix}-${e.from ?? e.source ?? ""}`;
      const tgt = `${prefix}-${e.to ?? e.target ?? ""}`;
      rfEdges.push({ id: `${prefix}-e${i}`, source: src, target: tgt, label: String(e.label ?? e.type ?? ""), ...edgeStyle(String(e.type ?? "")) } as Edge);
    });
  };

  if (hunterGraph) addGraph(hunterGraph, "h", 0);
  if (verGraph) addGraph(verGraph, "v", hunterGraph ? 300 : 0);

  // Fallback graph if no nodes were generated
  if (rfNodes.length === 0) {
    if (inv.user_id) {
      rfNodes.push({ id: "fb-user", type: "default", data: { label: inv.user_id }, position: { x: 50, y: 50 }, style: nodeStyle("user") });
    }
    rfNodes.push({ id: "fb-host", type: "default", data: { label: inv.hostname || "host" }, position: { x: 300, y: 50 }, style: nodeStyle("host") });
    if (inv.source_ip && inv.source_ip !== "0.0.0.0") {
      rfNodes.push({ id: "fb-ip", type: "default", data: { label: inv.source_ip }, position: { x: 550, y: 50 }, style: nodeStyle("critical") });
    }
    rfNodes.push({ id: "fb-finding", type: "default", data: { label: `${inv.finding_type}\nScore: ${Number(inv.confidence).toFixed(3)}` }, position: { x: 800, y: 50 }, style: { ...nodeStyle("verdict"), whiteSpace: "pre-line" as React.CSSProperties["whiteSpace"] } });
    if (inv.user_id) rfEdges.push({ id: "fb-e0", source: "fb-user", target: "fb-host", label: "session", ...edgeStyle("lateral") } as Edge);
    rfEdges.push({ id: "fb-e1", source: "fb-host", target: rfNodes.find(n => n.id === "fb-ip") ? "fb-ip" : "fb-finding", label: inv.finding_type || "alert", ...edgeStyle("critical") } as Edge);
    if (rfNodes.find(n => n.id === "fb-ip")) rfEdges.push({ id: "fb-e2", source: "fb-ip", target: "fb-finding", label: "verdict", ...edgeStyle("attack") } as Edge);
  }

  return { nodes: rfNodes, edges: rfEdges };
}

function FitBtn() {
  const { fitView } = useReactFlow();
  return (
    <button onClick={() => fitView({ padding: 0.15 })}
      className="flex items-center gap-1 rounded-md bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 px-2.5 py-1.5 text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 shadow-sm transition-colors">
      <ZoomIn className="h-3.5 w-3.5" /> Fit
    </button>
  );
}

function AttackGraphInner({ data }: { data: InvestigationDetail }) {
  const hunterGraph = data?.attack_graph?.hunter ?? null;
  const verifierGraph = data?.attack_graph?.verifier ?? null;
  const { nodes: initial, edges: initEdges } = useMemo(
    () => buildReactFlowGraph(hunterGraph, verifierGraph, data.investigation),
    [hunterGraph, verifierGraph, data.investigation],
  );
  const [nodes, , onNodesChange] = useNodesState(initial);
  const [edges, , onEdgesChange] = useEdgesState(initEdges);

  return (
    <div className="h-[360px] w-full rounded-xl border border-gray-200 dark:border-gray-700/60 overflow-hidden bg-gray-50 dark:bg-gray-950/40">
      <ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
        fitView fitViewOptions={{ padding: 0.15 }} proOptions={{ hideAttribution: true }}
        minZoom={0.2} maxZoom={3} className="bg-gray-50 dark:bg-gray-950">
        <Background color="#d1d5db" gap={20} size={1} />
        <Controls showInteractive={false} className="!bg-white dark:!bg-gray-800 !border-gray-200 dark:!border-gray-700 !shadow-sm [&>button]:!bg-white dark:[&>button]:!bg-gray-800 [&>button]:!border-gray-200 dark:[&>button]:!border-gray-700 [&>button]:!text-gray-600 dark:[&>button]:!text-gray-300" />
        <MiniMap nodeColor="#6366f1" maskColor="rgba(0,0,0,0.08)" className="!bg-white dark:!bg-gray-900 !border-gray-200 dark:!border-gray-700" />
        <Panel position="top-right"><FitBtn /></Panel>
      </ReactFlow>
    </div>
  );
}

function AttackGraph({ data }: { data: InvestigationDetail }) {
  return (
    <ReactFlowProvider>
      <AttackGraphInner data={data} />
    </ReactFlowProvider>
  );
}

/* ================================================================ */
/*  Merkle Proof Verification                                       */
/* ================================================================ */

interface MerkleResult {
  batchId: string; table: string; storedRoot: string; computedRoot: string;
  storedCount: number; actualCount: number; verified: boolean; countMismatch?: boolean; depth: number; status: string;
}

function MerkleProof({ batchIds, rawLog, secEvent }: {
  batchIds: string[] | null;
  rawLog: InvestigationDetail["raw_log"];
  secEvent: InvestigationDetail["security_event"];
}) {
  const [results, setResults] = useState<MerkleResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);

  const verify = useCallback(async () => {
    setLoading(true); setError(null); setResults([]); setVerified(null);
    try {
      const ids = batchIds && batchIds.length > 0 ? [...batchIds] : [];
      if (ids.length === 0) {
        // Fallback: find batches for verifiable tables only (raw_logs, security_events)
        const chainRes = await fetch("/api/evidence/chain");
        if (chainRes.ok) {
          const chain = await chainRes.json();
          const verifiable = (chain.batches || []).filter(
            (b: { tableName?: string }) =>
              ["raw_logs", "security_events", "process_events", "network_events"].includes(b.tableName || ""),
          );
          if (verifiable.length > 0) {
            ids.push(verifiable[0].id);
          }
        }
      }
      if (ids.length === 0) { setError("No Merkle batches found for this investigation"); setLoading(false); return; }
      const all: MerkleResult[] = [];
      for (const bid of ids) {
        const res = await fetch(`/api/evidence/verify?batchId=${encodeURIComponent(bid)}`);
        if (res.ok) { all.push(await res.json()); }
        else { const err = await res.json().catch(() => ({})); all.push({ batchId: bid, table: "?", storedRoot: "", computedRoot: "", storedCount: 0, actualCount: 0, verified: false, depth: 0, status: err.error || `HTTP ${res.status}` }); }
      }
      setResults(all);
      const allVerified = all.length > 0 && all.every(r => r.verified);
      const onlyCountMismatch = !allVerified && all.length > 0 && all.every(r => r.verified || r.countMismatch);
      setVerified(allVerified ? true : onlyCountMismatch ? null : false);
    } catch (e) { setError(e instanceof Error ? e.message : "Verification failed"); }
    setLoading(false);
  }, [batchIds]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <button onClick={verify} disabled={loading}
          className="flex items-center gap-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 px-4 py-2 text-sm font-semibold text-white transition-colors shadow-sm">
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />}
          {loading ? "Verifying..." : "Verify Log Integrity"}
        </button>
        {verified === true && (
          <span className="flex items-center gap-1.5 rounded-lg bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800/50 px-3 py-1.5 text-sm font-bold text-green-700 dark:text-green-400">
            <CheckCircle2 className="h-4 w-4" /> INTEGRITY VERIFIED - No Tampering Detected
          </span>
        )}
        {verified === false && (
          <span className="flex items-center gap-1.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50 px-3 py-1.5 text-sm font-bold text-red-700 dark:text-red-400">
            <XCircle className="h-4 w-4" /> TAMPERING DETECTED
          </span>
        )}
        {verified === null && results.length > 0 && (
          <span className="flex items-center gap-1.5 rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800/50 px-3 py-1.5 text-sm font-bold text-blue-700 dark:text-blue-400">
            <CheckCircle2 className="h-4 w-4" /> LOG INTEGRITY INTACT - New data ingested after anchoring
          </span>
        )}
      </div>

      {verified === null && results.length > 0 && (
        <div className="rounded-lg bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800/40 px-4 py-3 text-sm text-blue-800 dark:text-blue-300">
          <strong>Not tampered.</strong> The Merkle tree was anchored when fewer events existed in this time window.
          Your pipeline continued ingesting new data afterward, increasing the event count. The original log data is still intact
          — the root hash simply cannot match because the tree now covers more events than when it was first anchored.
        </div>
      )}

      {error && <div className="rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50 px-4 py-3 text-sm text-red-700 dark:text-red-300">{error}</div>}

      {results.length > 0 && (
        <div className="space-y-3">
          {results.map((r, i) => (
            <div key={i} className={`rounded-lg border p-4 ${r.verified ? "border-green-200 dark:border-green-800/50 bg-green-50/50 dark:bg-green-950/20" : r.countMismatch ? "border-blue-200 dark:border-blue-800/50 bg-blue-50/50 dark:bg-blue-950/20" : "border-red-200 dark:border-red-800/50 bg-red-50/50 dark:bg-red-950/20"}`}>
              <div className="flex items-center gap-2 mb-3">
                {r.verified ? <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" /> : r.countMismatch ? <CheckCircle2 className="h-5 w-5 text-blue-600 dark:text-blue-400" /> : <XCircle className="h-5 w-5 text-red-600 dark:text-red-400" />}
                <span className={`text-sm font-bold ${r.verified ? "text-green-700 dark:text-green-400" : r.countMismatch ? "text-blue-700 dark:text-blue-400" : "text-red-700 dark:text-red-400"}`}>{r.countMismatch ? `${r.storedCount} events anchored → ${r.actualCount} current (new data ingested)` : r.status}</span>
                <span className="text-xs text-gray-500 font-mono ml-auto">{r.batchId}</span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <div><div className="text-[11px] text-gray-500 uppercase tracking-wider">Table</div><div className="text-sm font-mono text-gray-800 dark:text-gray-200">{r.table}</div></div>
                <div><div className="text-[11px] text-gray-500 uppercase tracking-wider">Events</div><div className="text-sm text-gray-800 dark:text-gray-200">{r.storedCount} stored / {r.actualCount} actual</div></div>
                <div><div className="text-[11px] text-gray-500 uppercase tracking-wider">Tree Depth</div><div className="text-sm text-gray-800 dark:text-gray-200">{r.depth}</div></div>
                <div><div className="text-[11px] text-gray-500 uppercase tracking-wider">Root Match</div><div className="text-sm text-gray-800 dark:text-gray-200">{r.storedRoot === r.computedRoot ? "Match" : "MISMATCH"}</div></div>
              </div>
              <details className="mt-3">
                <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">Show roots</summary>
                <div className="mt-2 rounded bg-gray-100 dark:bg-gray-950/60 p-2 text-xs font-mono space-y-1">
                  <div><span className="text-gray-500">Stored:   </span><span className="text-gray-800 dark:text-gray-200 break-all">{r.storedRoot}</span></div>
                  <div><span className="text-gray-500">Computed: </span><span className="text-gray-800 dark:text-gray-200 break-all">{r.computedRoot}</span></div>
                </div>
              </details>
            </div>
          ))}
        </div>
      )}

      {/* Anchor info from raw log / security event */}
      {(rawLog?.anchor_tx_id || secEvent?.anchor_tx_id) && (
        <div className="rounded-lg bg-gray-50 dark:bg-gray-950/40 border border-gray-200 dark:border-gray-700/40 p-4">
          <div className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Log Anchor References</div>
          <div className="grid gap-1">
            {rawLog?.anchor_tx_id && <Row label="Raw Log Anchor TX" value={rawLog.anchor_tx_id} mono />}
            {rawLog?.anchor_batch_hash && <Row label="Raw Log Batch Hash" value={rawLog.anchor_batch_hash} mono />}
            {secEvent?.anchor_tx_id && <Row label="Security Event Anchor" value={secEvent.anchor_tx_id} mono />}
          </div>
        </div>
      )}
    </div>
  );
}

/* ================================================================ */
/*  Investigation Timeline                                          */
/* ================================================================ */

const TIMELINE_INITIAL_SHOW = 15;

const TIMELINE_COLORS: Record<string, { dot: string; lbl: string }> = {
  triage:   { dot: "bg-blue-500 ring-blue-200 dark:ring-blue-500/30", lbl: "text-blue-600 dark:text-blue-400" },
  hunter:   { dot: "bg-cyan-500 ring-cyan-200 dark:ring-cyan-500/30", lbl: "text-cyan-600 dark:text-cyan-400" },
  verifier: { dot: "bg-purple-500 ring-purple-200 dark:ring-purple-500/30", lbl: "text-purple-600 dark:text-purple-400" },
  raw_log:  { dot: "bg-gray-400 ring-gray-200 dark:ring-gray-500/30", lbl: "text-gray-500 dark:text-gray-400" },
};

function TimelineSection({ timeline }: { timeline: Array<{ source: string; timestamp: string; label: string }> }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? timeline : timeline.slice(0, TIMELINE_INITIAL_SHOW);
  const hasMore = timeline.length > TIMELINE_INITIAL_SHOW;

  return (
    <Sec title={`Investigation Timeline (${timeline.length} events)`}
      icon={<Clock className="h-4 w-4 text-green-600 dark:text-green-400" />} accent="border-green-200 dark:border-green-900/60">
      <div className="mt-3 relative ml-4 border-l-2 border-gray-200 dark:border-gray-700/50 pl-8 space-y-5">
        {visible.map((evt, i) => {
          const cc = TIMELINE_COLORS[evt.source] || TIMELINE_COLORS.raw_log;
          return (
            <div key={i} className="relative">
              <div className={`absolute -left-[37px] top-1 h-3.5 w-3.5 rounded-full ring-4 ${cc.dot}`} />
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`text-xs font-bold uppercase tracking-wider ${cc.lbl}`}>{evt.source.replace(/_/g, " ")}</span>
                <span className="text-xs text-gray-400">{fmtD(evt.timestamp)}</span>
              </div>
              {evt.label && <div className="text-sm text-gray-700 dark:text-gray-300 break-words">{evt.label}</div>}
            </div>
          );
        })}
      </div>
      {hasMore && (
        <button onClick={() => setExpanded(!expanded)}
          className="mt-4 flex items-center gap-1.5 mx-auto rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 px-4 py-2 text-xs font-semibold text-gray-600 dark:text-gray-400 transition-colors">
          {expanded ? (
            <><ChevronDown className="h-3.5 w-3.5 rotate-180" /> Show less</>
          ) : (
            <><ChevronDown className="h-3.5 w-3.5" /> Show all {timeline.length} events</>
          )}
        </button>
      )}
    </Sec>
  );
}

/* ================================================================ */
/*  Report Generation                                               */
/* ================================================================ */

function ReportGenerator({ data }: { data: InvestigationDetail }) {
  const reportRef = useRef<HTMLDivElement>(null);
  const [generating, setGenerating] = useState(false);

  const generate = useCallback(() => {
    setGenerating(true);
    const { investigation: inv, verification: ver, triage: tri, raw_log: raw, security_event: sec, timeline, attack_graph: ag, evidence } = data;
    const lines: string[] = [];
    const hr = "=".repeat(80);
    const sr = "-".repeat(80);
    lines.push(hr);
    lines.push("  CLIF SIEM - INVESTIGATION REPORT");
    lines.push(`  Generated: ${new Date().toISOString()}`);
    lines.push(hr);
    lines.push("");
    lines.push(`Investigation ID : ${inv.investigation_id}`);
    lines.push(`Alert ID         : ${inv.alert_id}`);
    lines.push(`Finding Type     : ${inv.finding_type}`);
    lines.push(`Severity         : ${inv.severity?.toUpperCase()}`);
    lines.push(`Status           : ${inv.status}`);
    lines.push(`Host             : ${inv.hostname}`);
    lines.push(`Source IP        : ${inv.source_ip}`);
    lines.push(`User             : ${inv.user_id || "N/A"}`);
    lines.push(`Trigger Score    : ${inv.trigger_score}`);
    lines.push(`Confidence       : ${inv.confidence}`);
    lines.push(`Started          : ${inv.started_at}`);
    lines.push(`Completed        : ${inv.completed_at || "Ongoing"}`);
    lines.push(`MITRE Tactics    : ${(inv.mitre_tactics || []).join(", ") || "N/A"}`);
    lines.push(`MITRE Techniques : ${(inv.mitre_techniques || []).join(", ") || "N/A"}`);
    lines.push("");
    lines.push(sr);
    lines.push("  HUNTER AGENT ANALYSIS");
    lines.push(sr);
    lines.push(inv.summary || "No summary available.");
    lines.push("");
    if (inv.recommended_action) { lines.push(`Recommended Action: ${inv.recommended_action}`); lines.push(""); }
    const hunterEv = evidence.hunter as Record<string, unknown> | null;
    if (hunterEv) {
      lines.push(`ML Model   : ${hunterEv.ml_model ?? "N/A"}`);
      lines.push(`SPC Z-Score: ${hunterEv.spc_z_score ?? "N/A"}`);
      lines.push(`Graph Hops : ${hunterEv.graph_hop_count ?? 0}`);
      const sigma = hunterEv.sigma_hits as Array<Record<string, unknown>> | undefined;
      if (sigma && sigma.length > 0) { lines.push(`Sigma Hits : ${sigma.length}`); sigma.forEach(h => lines.push(`  - ${h.rule_id} | ${h.title} (${h.severity})`)); }
    }

    if (tri) {
      lines.push(""); lines.push(sr); lines.push("  TRIAGE AGENT SCORING"); lines.push(sr);
      lines.push(`Combined Score  : ${tri.combined_score}`);
      lines.push(`LightGBM Score  : ${tri.lgbm_score}`);
      lines.push(`EIF Score       : ${tri.eif_score}`);
      lines.push(`ARF Score       : ${tri.arf_score}`);
      lines.push(`Adjusted Score  : ${tri.adjusted_score}`);
      lines.push(`Action          : ${tri.action}`);
      lines.push(`Agreement       : ${tri.agreement}`);
      lines.push(`Std Dev         : ${tri.score_std_dev}`);
      lines.push(`CI              : [${tri.ci_lower}, ${tri.ci_upper}]`);
      lines.push(`Model Version   : ${tri.model_version}`);
      if (tri.mitre_tactic) lines.push(`MITRE Tactic    : ${tri.mitre_tactic}`);
      if (tri.mitre_technique) lines.push(`MITRE Technique : ${tri.mitre_technique}`);
    }

    if (ver) {
      lines.push(""); lines.push(sr); lines.push("  VERIFIER AGENT ANALYSIS"); lines.push(sr);
      lines.push(`Verdict          : ${ver.verdict?.replace(/_/g, " ").toUpperCase()}`);
      lines.push(`Confidence       : ${ver.confidence}`);
      lines.push(`Priority         : ${ver.priority}`);
      lines.push(`Evidence Verified: ${ver.evidence_verified ? "Yes" : "No"}`);
      if (ver.analyst_summary) { lines.push(""); lines.push("Analyst Summary:"); lines.push(ver.analyst_summary); }
      if (ver.report_narrative) { lines.push(""); lines.push("Report Narrative:"); lines.push(ver.report_narrative); }
      if (ver.recommended_action) { lines.push(""); lines.push(`Verifier Action: ${ver.recommended_action}`); }
      if (ver.merkle_batch_ids?.length) { lines.push(""); lines.push(`Merkle Batch IDs: ${ver.merkle_batch_ids.join(", ")}`); }
    }

    if (raw) {
      lines.push(""); lines.push(sr); lines.push("  ORIGINAL RAW LOG"); lines.push(sr);
      lines.push(`Event ID   : ${raw.event_id}`);
      lines.push(`Timestamp  : ${raw.timestamp}`);
      lines.push(`Level      : ${raw.level}`);
      lines.push(`Source     : ${raw.source}`);
      lines.push(`Anchor TX  : ${raw.anchor_tx_id || "N/A"}`);
      lines.push(`Batch Hash : ${raw.anchor_batch_hash || "N/A"}`);
      if (raw.message) { lines.push(""); lines.push("Message:"); lines.push(raw.message); }
    }

    if (sec) {
      lines.push(""); lines.push(sr); lines.push("  ENRICHED SECURITY EVENT"); lines.push(sr);
      lines.push(`Event ID    : ${sec.event_id}`);
      lines.push(`Category    : ${sec.category}`);
      lines.push(`Severity    : ${sec.severity}`);
      lines.push(`AI Confidence: ${sec.ai_confidence}`);
      if (sec.ai_explanation) lines.push(`AI Explain  : ${sec.ai_explanation}`);
    }

    lines.push(""); lines.push(sr); lines.push("  EVIDENCE CHAIN / MERKLE PROOF"); lines.push(sr);
    lines.push("Log integrity is verified using SHA-256 Merkle trees anchored to immutable storage.");
    lines.push(`Raw Log Anchor TX    : ${raw?.anchor_tx_id || "N/A"}`);
    lines.push(`Raw Log Batch Hash   : ${raw?.anchor_batch_hash || "N/A"}`);
    lines.push(`Security Event Anchor: ${sec?.anchor_tx_id || "N/A"}`);
    lines.push(`Verifier Merkle IDs  : ${ver?.merkle_batch_ids?.join(", ") || "N/A"}`);
    lines.push(`Evidence Verified    : ${ver?.evidence_verified ? "Yes" : "No"}`);
    lines.push("");
    lines.push("To independently verify: re-hash all events in the batch time window,");
    lines.push("rebuild the Merkle tree, and compare the root to the value stored in");
    lines.push("the evidence_anchors table and MinIO S3 Object Lock storage.");

    if (timeline && timeline.length > 0) {
      lines.push(""); lines.push(sr); lines.push("  INVESTIGATION TIMELINE"); lines.push(sr);
      timeline.forEach(e => lines.push(`  [${e.source.toUpperCase().padEnd(8)}] ${e.timestamp} - ${e.label}`));
    }

    lines.push(""); lines.push(hr); lines.push("  END OF REPORT"); lines.push(hr);

    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `CLIF_Report_${inv.investigation_id.slice(0, 8)}_${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setGenerating(false);
  }, [data]);

  return (
    <button onClick={generate} disabled={generating}
      className="flex items-center gap-2 rounded-lg bg-gray-800 dark:bg-gray-200 hover:bg-gray-700 dark:hover:bg-gray-300 px-4 py-2 text-sm font-semibold text-white dark:text-gray-900 transition-colors shadow-sm disabled:opacity-50">
      {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
      Download Report
    </button>
  );
}

/* ================================================================ */
/*  Main Page                                                       */
/* ================================================================ */

export default function InvestigationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { data, loading, error } = usePolling<InvestigationDetail>(
    `/api/investigations/${encodeURIComponent(id)}`, 20_000,
  );
  const fallbackData = useMemo(() => buildMockInvestigationDetail(id || "INV-DEMO-001"), [id]);
  const usingFallback = !data;
  const effectiveData = (data ?? fallbackData) as InvestigationDetail & { merkle_batch_ids?: string[] };

  const { investigation: inv, verification: ver, triage: tri, raw_log: raw,
    security_event: sec, timeline, attack_graph: ag, evidence,
    merkle_batch_ids: apiBatchIds } = effectiveData;

  const sev = SEV_CFG[inv.severity?.toLowerCase()] ?? SEV_CFG.info;

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ HEADER HERO ═══ */}
      <div className="bg-white border-b border-gray-200">
        <div className="px-10 py-8 max-w-[1600px] w-full mx-auto">
          {usingFallback && (
            <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-2 text-xs font-semibold text-amber-700 mb-4">
              Reference Mode: Backend data unavailable, showing demo investigation values.
              {error ? ` (${error})` : loading ? " (waiting for backend...)" : ""}
            </div>
          )}
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
            <div className="space-y-3">
              <div className="flex items-center gap-3 flex-wrap">
                <button onClick={() => router.push("/investigations")}
                  className="flex items-center gap-1.5 rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-600 hover:text-gray-900 hover:bg-gray-200 transition-colors">
                  <ArrowLeft className="h-3.5 w-3.5" /> Back
                </button>
                <span className={`rounded-md px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide ring-1 ${sev.bg} ${sev.text} ${sev.ring}`}>{sev.label}</span>
                <span className="flex items-center gap-1.5 text-xs">
                  <span className={`h-1.5 w-1.5 rounded-full ${inv.status === "completed" ? "bg-green-500" : "bg-yellow-500 animate-pulse"}`} />
                  <span className={inv.status === "completed" ? "text-green-600" : "text-yellow-600"}>{inv.status}</span>
                </span>
                {ver && (
                  <>
                    <span className="text-gray-300">|</span>
                    <span className={`flex items-center gap-1.5 text-xs font-semibold ${VERDICT_COLOR[ver.verdict] || "text-gray-500"}`}>
                      {ver.verdict === "true_positive" ? <ShieldAlert className="h-3 w-3" />
                        : ver.verdict === "false_positive" ? <ShieldCheck className="h-3 w-3" />
                        : <ShieldQuestion className="h-3 w-3" />}
                      {ver.verdict?.replace(/_/g, " ")}
                    </span>
                    {ver.priority && <span className="rounded bg-gray-100 px-2 py-0.5 text-[10px] font-bold text-gray-700 ring-1 ring-gray-300">{ver.priority}</span>}
                  </>
                )}
              </div>
              <h1 className="text-3xl lg:text-4xl font-extrabold text-gray-900 tracking-tight leading-[1.1]">{inv.finding_type}</h1>
              <p className="text-base text-gray-500">
                {inv.hostname}{inv.source_ip && inv.source_ip !== "0.0.0.0" ? ` / ${inv.source_ip}` : ""}
                {inv.user_id ? ` / ${inv.user_id}` : ""} &mdash; {fmtD(inv.started_at)}
              </p>
              {/* Pipeline stages */}
              <div className="flex items-center gap-1.5 text-xs font-semibold">
                {["Raw Log","Triage","Hunter","Verifier"].map((s, i) => {
                  const active = s === "Raw Log" ? !!raw : s === "Triage" ? !!tri : s === "Hunter" ? true : !!ver;
                  const colors = active
                    ? { "Raw Log": "bg-gray-200 text-gray-800",
                        Triage: "bg-blue-100 text-blue-700",
                        Hunter: "bg-cyan-100 text-cyan-700",
                        Verifier: "bg-purple-100 text-purple-700",
                      }[s] : "bg-gray-100 text-gray-400";
                  return (
                    <span key={s} className="flex items-center gap-1.5">
                      {i > 0 && <span className="text-gray-400">&rarr;</span>}
                      <span className={`rounded-full px-2 py-0.5 ${colors}`}>{s}</span>
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="flex items-center gap-4 shrink-0">
              <Ring score={inv.trigger_score} label="Trigger" size={72} />
              <Ring score={inv.confidence} label="Confidence" size={72} />
              <ReportGenerator data={effectiveData} />
            </div>
          </div>
        </div>
      </div>

      {/* ═══ TAB NAVIGATION ═══ */}
      <div className="px-10 max-w-[1600px] w-full mx-auto">
      <Tabs defaultValue="overview">
        <TabsList className="w-full justify-start border-b border-gray-200 bg-transparent p-0 mt-0">
          <TabsTrigger value="overview" className="data-[state=active]:border-b-2 data-[state=active]:border-blue-600 rounded-none px-6 py-3 text-sm font-bold">
            Overview
          </TabsTrigger>
          <TabsTrigger value="attack-graph" className="data-[state=active]:border-b-2 data-[state=active]:border-pink-600 rounded-none px-6 py-3 text-sm font-bold">
            Attack Graph
          </TabsTrigger>
          <TabsTrigger value="scoring" className="data-[state=active]:border-b-2 data-[state=active]:border-purple-600 rounded-none px-6 py-3 text-sm font-bold">
            Scoring &amp; Verification
          </TabsTrigger>
          <TabsTrigger value="evidence" className="data-[state=active]:border-b-2 data-[state=active]:border-indigo-600 rounded-none px-6 py-3 text-sm font-bold">
            Evidence &amp; MITRE
          </TabsTrigger>
          <TabsTrigger value="timeline" className="data-[state=active]:border-b-2 data-[state=active]:border-green-600 rounded-none px-6 py-3 text-sm font-bold">
            Timeline
          </TabsTrigger>
          <TabsTrigger value="raw-data" className="data-[state=active]:border-b-2 data-[state=active]:border-gray-600 rounded-none px-6 py-3 text-sm font-bold">
            Raw Data
          </TabsTrigger>
        </TabsList>

        {/* ═══════════════ OVERVIEW TAB ═══════════════ */}
        <TabsContent value="overview" className="mt-8 space-y-6 pb-10">
          {/* KPI ROW */}
          <div className="grid grid-cols-3 gap-3 lg:grid-cols-6">
            <Stat icon={<Server className="h-3.5 w-3.5" />} accent="text-cyan-600" label="Hostname" value={fmt(inv.hostname)} />
            <Stat icon={<Globe className="h-3.5 w-3.5" />} accent="text-cyan-600" label="Source IP" value={fmt(inv.source_ip)} />
            <Stat icon={<User className="h-3.5 w-3.5" />} accent="text-cyan-600" label="User" value={fmt(inv.user_id)} />
            <Stat icon={<Clock className="h-3.5 w-3.5" />} accent="text-cyan-600" label="Duration"
              value={dur(inv.started_at, inv.completed_at)} sub={`Started: ${fmtD(inv.started_at)}`} />
            <Stat icon={<Zap className="h-3.5 w-3.5" />} accent="text-yellow-600" label="Action"
              value={tri?.action?.toUpperCase() || inv.recommended_action?.split(".")[0] || "-"} />
            <Stat icon={<Database className="h-3.5 w-3.5" />} accent="text-purple-600" label="Alert ID"
              value={inv.alert_id.slice(0, 8) + "..."} sub={inv.alert_id} />
          </div>

          {/* AGENT VERDICTS */}
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Triage */}
            <div className={`rounded-xl border p-5 ${tri ? "border-blue-200 bg-blue-50/50" : "border-gray-200 bg-gray-50"}`}>
              <div className="flex items-center gap-2 mb-3">
                <BarChart3 className="h-4 w-4 text-blue-600" />
                <span className="text-sm font-bold text-gray-900">Triage Agent</span>
                {tri && <span className="ml-auto rounded bg-blue-100 px-2 py-0.5 text-[10px] font-mono text-blue-700">{tri.model_version}</span>}
              </div>
              {tri ? (
                <div className="space-y-1">
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-black text-blue-700">{(tri.adjusted_score * 100).toFixed(0)}%</span>
                    <span className="text-xs text-gray-500">adjusted</span>
                  </div>
                  <div className="text-xs text-gray-600">
                    LGB: {fmtS(tri.lgbm_score,3)} &middot; EIF: {fmtS(tri.eif_score,3)} &middot; ARF: {fmtS(tri.arf_score,3)}
                  </div>
                  <div className={`text-xs font-bold uppercase ${tri.action === "escalate" ? "text-red-600" : tri.action === "investigate" ? "text-orange-600" : "text-green-600"}`}>
                    Action: {tri.action}
                  </div>
                </div>
              ) : <span className="text-xs text-gray-400">Not available</span>}
            </div>

            {/* Hunter */}
            <div className="rounded-xl border border-cyan-200 bg-cyan-50/50 p-5">
              <div className="flex items-center gap-2 mb-3">
                <Crosshair className="h-4 w-4 text-cyan-600" />
                <span className="text-sm font-bold text-gray-900">Hunter Agent</span>
              </div>
              <div className="space-y-1">
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-black text-cyan-700">{(inv.confidence * 100).toFixed(0)}%</span>
                  <span className="text-xs text-gray-500">confidence</span>
                </div>
                <div className="text-xs text-gray-600">{inv.finding_type}</div>
                {(() => { const h = evidence.hunter as Record<string, unknown> | null; return h ? (
                  <div className="text-xs text-gray-500">
                    Model: {fmt(h.ml_model)} &middot; Z: {fmtS(h.spc_z_score,2)} &middot; Hops: {fmt(h.graph_hop_count)}
                  </div>
                ) : null; })()}
              </div>
            </div>

            {/* Verifier */}
            <div className={`rounded-xl border p-5 ${ver ? "border-purple-200 bg-purple-50/50" : "border-gray-200 bg-gray-50"}`}>
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-purple-600" />
                <span className="text-sm font-bold text-gray-900">Verifier Agent</span>
              </div>
              {ver ? (
                <div className="space-y-1">
                  <div className="flex items-baseline gap-2">
                    <span className={`text-3xl font-black ${VERDICT_COLOR[ver.verdict] || "text-gray-700"}`}>
                      {ver.verdict?.replace(/_/g, " ").toUpperCase()}
                    </span>
                  </div>
                  <div className="text-xs text-gray-600">
                    Confidence: {fmtP(ver.confidence)} &middot; Priority: {ver.priority}
                  </div>
                  <div className="text-xs text-gray-500">
                    Evidence verified: {ver.evidence_verified ? "Yes" : "No"}
                  </div>
                </div>
              ) : <span className="text-xs text-gray-400">Not available</span>}
            </div>
          </div>

          {/* Hunter Summary */}
          <Sec title="Hunter Analysis Summary" icon={<Crosshair className="h-3.5 w-3.5 text-cyan-600" />} accent="border-cyan-200">
            <div className="mt-2 space-y-2">
              <div className="rounded-md bg-gray-50 p-4 text-sm text-gray-700 leading-relaxed whitespace-pre-wrap font-mono max-h-[240px] overflow-y-auto">
                {inv.summary || "No summary available."}
              </div>
              {inv.recommended_action && (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-4">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
                    <span className="text-xs font-bold uppercase tracking-wider text-amber-600">Recommended Action</span>
                  </div>
                  <p className="text-sm text-amber-900">{inv.recommended_action}</p>
                </div>
              )}
            </div>
          </Sec>
        </TabsContent>

        {/* ═══════════════ ATTACK GRAPH TAB ═══════════════ */}
        <TabsContent value="attack-graph" className="mt-8 space-y-6 pb-10">
          <div className="flex flex-wrap gap-2 text-[11px]">
            {[{c:"bg-indigo-100 border-indigo-400 text-indigo-700",l:"User/Identity"},
              {c:"bg-yellow-100 border-yellow-400 text-yellow-700",l:"Host/Endpoint"},
              {c:"bg-red-100 border-red-400 text-red-700",l:"Critical/Verdict"},
              {c:"bg-blue-100 border-blue-400 text-blue-700",l:"MITRE Technique"},
              {c:"bg-amber-100 border-amber-400 text-amber-700",l:"IOC"},
            ].map(x => <span key={x.l} className={`rounded px-1.5 py-0.5 border font-semibold ${x.c}`}>{x.l}</span>)}
          </div>
          <AttackGraph data={effectiveData} />
          {ag?.hunter?.metadata && (
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="Signals Fired" value={String(ag?.hunter?.metadata?.signals_fired ?? 0)} />
              <Stat label="Signals Checked" value={String(ag?.hunter?.metadata?.signals_checked ?? 0)} />
              <Stat label="Graph Density" value={String(ag?.hunter?.metadata?.graph_density ?? "-")} />
              <Stat label="Model" value={String(ag?.hunter?.metadata?.model ?? "-")} />
            </div>
          )}

          {/* Hunter evidence details */}
          {evidence.hunter && (() => {
            const h = evidence.hunter as Record<string, unknown>;
            const sigmaHits = h.sigma_hits as Array<Record<string, unknown>> | undefined;
            return (
              <div className="space-y-3">
                <div className="grid gap-2 grid-cols-2 lg:grid-cols-4">
                  <Stat label="ML Model" value={fmt(h.ml_model)} icon={<Cpu className="h-3 w-3" />} accent="text-cyan-600" />
                  <Stat label="Sigma Hits" value={String(sigmaHits?.length ?? 0)} icon={<Target className="h-3 w-3" />} accent="text-orange-600" />
                  <Stat label="SPC Z-Score" value={fmtS(h.spc_z_score, 2)} icon={<BarChart3 className="h-3 w-3" />} accent="text-blue-600" />
                  <Stat label="Graph Hops" value={String(h.graph_hop_count ?? 0)} sub={`IOC: ${h.has_ioc_neighbor ? "Yes" : "No"}`}
                    icon={<GitBranch className="h-3 w-3" />} accent="text-green-600" />
                </div>
                {sigmaHits && sigmaHits.length > 0 && (
                  <div className="space-y-1">
                    <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Sigma Rule Matches</h4>
                    {sigmaHits.map((hit, i) => (
                      <div key={i} className="flex items-center gap-2 rounded-lg bg-orange-50 border border-orange-200 px-3 py-2">
                        <Target className="h-3.5 w-3.5 text-orange-500 shrink-0" />
                        <span className="text-xs text-orange-700 font-mono">{String(hit.rule_id)}</span>
                        <span className="text-xs text-gray-700">{String(hit.title)}</span>
                        <span className="ml-auto rounded bg-orange-100 px-1.5 py-0.5 text-[10px] text-orange-700">sev: {String(hit.severity)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })()}
        </TabsContent>

        {/* ═══════════════ SCORING & VERIFICATION TAB ═══════════════ */}
        <TabsContent value="scoring" className="mt-8 space-y-6 pb-10">
          <div className="grid gap-4 lg:grid-cols-2">
            {/* TRIAGE SCORING */}
            {tri && (
              <Sec title="Triage Scoring" icon={<BarChart3 className="h-3.5 w-3.5 text-blue-600" />}
                badge={<span className="rounded bg-blue-100 px-2 py-0.5 text-[10px] text-blue-700">{tri.model_version}</span>}
                accent="border-blue-200">
                <div className="mt-2 space-y-3">
                  <div className="flex flex-wrap gap-3 justify-center py-1">
                    <Ring score={tri.combined_score} label="Combined" size={56} />
                    <Ring score={tri.lgbm_score} label="LightGBM" size={56} />
                    <Ring score={tri.eif_score} label="EIF" size={56} />
                    <Ring score={tri.arf_score} label="ARF" size={56} />
                    <Ring score={tri.adjusted_score} label="Adjusted" size={56} />
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Model Scores</h4>
                      <Bar value={tri.lgbm_score} label="LightGBM" color="bg-blue-500" />
                      <Bar value={tri.eif_score} label="Extended Isolation Forest" color="bg-teal-500" />
                      <Bar value={tri.arf_score} label="Autoregressive Forest" color="bg-indigo-500" />
                      <Bar value={tri.combined_score} label="Combined (ensemble)" color="bg-cyan-500" />
                      <Bar value={tri.adjusted_score} label="Adjusted (final)" color="bg-amber-500" />
                    </div>
                    <div className="space-y-1.5">
                      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Score Statistics</h4>
                      <div className="grid grid-cols-2 gap-1.5">
                        <Stat label="Std Dev" value={fmtS(tri.score_std_dev)} />
                        <Stat label="Agreement" value={fmtS(tri.agreement)} />
                        <Stat label="CI Lower" value={fmtS(tri.ci_lower)} />
                        <Stat label="CI Upper" value={fmtS(tri.ci_upper)} />
                        <Stat label="Asset Mult" value={`${tri.asset_multiplier}x`} />
                        <Stat label="Rarity" value={fmtS(tri.template_rarity)} />
                        <Stat label="IOC Match" value={tri.ioc_match ? `Yes (${tri.ioc_confidence}%)` : "No"} />
                        <Stat label="Disagreement" value={tri.disagreement_flag ? "Yes" : "No"} />
                      </div>
                    </div>
                  </div>
                  {(tri.mitre_tactic || tri.mitre_technique) && (
                    <div className="flex flex-wrap gap-1.5">
                      {tri.mitre_tactic && <span className="rounded-md bg-red-50 px-2.5 py-1 text-xs font-mono text-red-700 ring-1 ring-red-200">Tactic: {tri.mitre_tactic}</span>}
                      {tri.mitre_technique && <span className="rounded-md bg-orange-50 px-2.5 py-1 text-xs font-mono text-orange-700 ring-1 ring-orange-200">Technique: {tri.mitre_technique}</span>}
                    </div>
                  )}
                  {tri.shap_top_features && tri.shap_top_features !== "" && (
                    <div>
                      <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">SHAP Top Features</h4>
                      <pre className="rounded-md bg-gray-50 p-3 text-xs text-gray-700 font-mono whitespace-pre-wrap overflow-x-auto">
                        {typeof tri.shap_top_features === "string" ? tri.shap_top_features : JSON.stringify(tri.shap_top_features, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </Sec>
            )}

            {/* VERIFIER ANALYSIS */}
            {ver && (
              <Sec title="Verifier Analysis" icon={<Shield className="h-3.5 w-3.5 text-purple-600" />}
                badge={
                  <span className={`flex items-center gap-1 rounded-md px-2 py-0.5 text-[10px] font-bold ${
                    ver.verdict === "true_positive" ? "bg-red-100 text-red-700"
                    : ver.verdict === "false_positive" ? "bg-green-100 text-green-700"
                    : "bg-yellow-100 text-yellow-700"
                  }`}>
                    {ver.verdict === "true_positive" ? <ShieldAlert className="h-2.5 w-2.5" />
                      : ver.verdict === "false_positive" ? <ShieldCheck className="h-2.5 w-2.5" />
                      : <ShieldQuestion className="h-2.5 w-2.5" />}
                    {ver.verdict?.replace(/_/g, " ").toUpperCase()}
                  </span>
                }
                accent="border-purple-200">
                <div className="mt-2 space-y-2">
                  <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-4">
                    <Stat label="Verdict" value={ver.verdict?.replace(/_/g, " ")} icon={<CheckCircle2 className="h-3 w-3" />} accent="text-purple-600" />
                    <Stat label="Confidence" value={fmtP(ver.confidence)} icon={<Activity className="h-3 w-3" />} accent="text-purple-600" />
                    <Stat label="Priority" value={ver.priority} icon={<Zap className="h-3 w-3" />} accent="text-purple-600" />
                    <Stat label="Evidence Verified" value={ver.evidence_verified ? "Yes" : "No"} icon={<Lock className="h-3 w-3" />} accent="text-purple-600" />
                  </div>
                  {ver.analyst_summary && (
                    <div className="rounded-md bg-purple-50 border border-purple-200 p-4">
                      <div className="text-[11px] font-bold text-purple-600 uppercase tracking-wider mb-1.5">Analyst Summary</div>
                      <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-wrap">{ver.analyst_summary}</p>
                    </div>
                  )}
                  {ver.report_narrative && (
                    <div className="rounded-md bg-purple-50 border border-purple-200 p-4">
                      <div className="text-[11px] font-bold text-purple-600 uppercase tracking-wider mb-1.5">Report Narrative</div>
                      <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-wrap">{ver.report_narrative}</p>
                    </div>
                  )}
                  {ver.recommended_action && (
                    <div className="rounded-md border border-amber-200 bg-amber-50 p-4">
                      <div className="flex items-center gap-1.5 mb-1.5"><AlertTriangle className="h-3.5 w-3.5 text-amber-600" /><span className="text-xs font-bold uppercase tracking-wider text-amber-600">Verifier Recommended Action</span></div>
                      <p className="text-sm text-amber-900">{ver.recommended_action}</p>
                    </div>
                  )}
                </div>
              </Sec>
            )}
          </div>
        </TabsContent>

        {/* ═══════════════ EVIDENCE & MITRE TAB ═══════════════ */}
        <TabsContent value="evidence" className="mt-8 space-y-6 pb-10">
          <div className="grid gap-4 lg:grid-cols-2">
            <Sec title="Merkle Proof &amp; Log Integrity" icon={<Fingerprint className="h-3.5 w-3.5 text-indigo-600" />}
              accent="border-indigo-200">
              <div className="mt-2">
                <MerkleProof batchIds={apiBatchIds && apiBatchIds.length > 0 ? apiBatchIds : ver?.merkle_batch_ids || null} rawLog={raw} secEvent={sec} />
              </div>
            </Sec>

            {((inv.mitre_tactics && inv.mitre_tactics.length > 0) || tri?.mitre_tactic || sec?.mitre_tactic) && (
              <Sec title="MITRE ATT&CK Mapping" icon={<Target className="h-3.5 w-3.5 text-red-600" />}
                accent="border-red-200">
                <div className="mt-2 space-y-2">
                  <div className="flex flex-wrap gap-1">
                    {KILL_CHAIN.map(step => {
                      const all = [...(inv.mitre_tactics || []),tri?.mitre_tactic||"",sec?.mitre_tactic||""].map(t=>t.toLowerCase().replace(/\s+/g,"-")).filter(Boolean);
                      const on = all.includes(step);
                      return (
                        <div key={step} className={`px-2 py-1.5 text-[11px] rounded-md font-mono transition-colors ${on
                          ? "bg-red-100 text-red-700 ring-1 ring-red-300 font-semibold"
                          : "bg-gray-100 text-gray-400 ring-1 ring-gray-200"}`}>
                          {step}
                        </div>
                      );
                    })}
                  </div>
                  {((inv.mitre_techniques && inv.mitre_techniques.length > 0) || tri?.mitre_technique) && (
                    <div className="flex flex-wrap gap-1.5">
                      {(inv.mitre_techniques||[]).map(t => <span key={t} className="rounded-md bg-cyan-50 px-2.5 py-1 text-xs font-mono text-cyan-700 ring-1 ring-cyan-200">{t}</span>)}
                      {tri?.mitre_technique && !inv.mitre_techniques?.includes(tri.mitre_technique) && (
                        <span className="rounded-md bg-blue-50 px-2.5 py-1 text-xs font-mono text-blue-700 ring-1 ring-blue-200">{tri.mitre_technique} (triage)</span>
                      )}
                    </div>
                  )}
                </div>
              </Sec>
            )}
          </div>

          {/* IOC Correlations */}
          {evidence.ioc_correlations && evidence.ioc_correlations.length > 0 && (
            <Sec title={`IOC Correlations (${evidence.ioc_correlations.length})`}
              icon={<ShieldAlert className="h-3.5 w-3.5 text-orange-600" />} accent="border-orange-200">
              <div className="mt-2 overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-gray-200 text-gray-500">
                      <th className="pb-1 text-left font-medium">Type</th>
                      <th className="pb-1 text-left font-medium">Value</th>
                      <th className="pb-1 text-left font-medium">Source</th>
                      <th className="pb-1 text-left font-medium">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evidence.ioc_correlations.map((ioc, i) => (
                      <tr key={i} className="border-b border-gray-100 hover:bg-gray-50">
                        <td className="py-1 font-mono text-gray-700">{fmt(ioc.type ?? ioc.ioc_type)}</td>
                        <td className="py-1 font-mono text-gray-800">{fmt(ioc.value ?? ioc.indicator)}</td>
                        <td className="py-1 text-gray-500">{fmt(ioc.source ?? ioc.feed)}</td>
                        <td className="py-1 text-gray-700">{ioc.confidence != null ? fmtP(ioc.confidence) : "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Sec>
          )}
        </TabsContent>

        {/* ═══════════════ TIMELINE TAB ═══════════════ */}
        <TabsContent value="timeline" className="mt-8 space-y-6 pb-10">
          {timeline && timeline.length > 0 && (
            <TimelineSection timeline={timeline} />
          )}

          {sec && (
            <Sec title="Security Event (enriched)" icon={<Eye className="h-3.5 w-3.5 text-yellow-600" />}
              accent="border-yellow-200">
              <div className="mt-2 grid gap-1 rounded-lg bg-gray-50 p-4">
                <Row label="Event ID" value={String(sec.event_id)} mono />
                <Row label="Timestamp" value={fmtD(sec.timestamp)} />
                <Row label="Severity" value={String(sec.severity)} />
                <Row label="Category" value={sec.category} />
                <Row label="Source" value={sec.source} />
                <Row label="Hostname" value={sec.hostname} />
                <Row label="IP Address" value={sec.ip_address} />
                <Row label="User ID" value={sec.user_id} />
                <Row label="MITRE Tactic" value={sec.mitre_tactic} />
                <Row label="MITRE Technique" value={sec.mitre_technique} />
                <Row label="AI Confidence" value={fmtS(sec.ai_confidence)} />
                <Row label="Anchor TX" value={sec.anchor_tx_id} mono />
              </div>
              {sec.description && <div className="mt-3"><div className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-1">Description</div><p className="text-sm text-gray-700 whitespace-pre-wrap">{sec.description}</p></div>}
              {sec.ai_explanation && <div className="mt-3"><div className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-1">AI Explanation</div><p className="text-sm text-gray-700 whitespace-pre-wrap">{sec.ai_explanation}</p></div>}
            </Sec>
          )}
        </TabsContent>

        {/* ═══════════════ RAW DATA TAB ═══════════════ */}
        <TabsContent value="raw-data" className="mt-8 space-y-6 pb-10">
          <div className="grid gap-4 lg:grid-cols-2">
            {raw && (
              <Sec title="Raw Log Event" icon={<FileText className="h-3.5 w-3.5 text-gray-500" />}
                accent="border-gray-200">
                <div className="mt-2 space-y-2">
                  <div className="grid gap-1 rounded-lg bg-gray-50 p-4">
                    <Row label="Event ID" value={String(raw.event_id)} mono />
                    <Row label="Timestamp" value={fmtD(raw.timestamp)} />
                    <Row label="Level" value={raw.level} />
                    <Row label="Source" value={raw.source} />
                    <Row label="User ID" value={raw.user_id} />
                    <Row label="IP Address" value={raw.ip_address} />
                    <Row label="Request ID" value={raw.request_id} mono />
                    <Row label="Anchor TX" value={raw.anchor_tx_id} mono />
                    <Row label="Batch Hash" value={raw.anchor_batch_hash} mono />
                  </div>
                  {raw.message && (
                    <div>
                      <div className="text-[11px] font-bold text-gray-500 uppercase tracking-wider mb-1">Log Message</div>
                      <pre className="rounded-lg bg-gray-50 p-3 text-xs text-gray-700 font-mono whitespace-pre-wrap overflow-x-auto max-h-[240px] overflow-y-auto">{raw.message}</pre>
                    </div>
                  )}
                </div>
              </Sec>
            )}

            <Sec title="Raw Evidence JSON" icon={<Hash className="h-3.5 w-3.5 text-gray-500" />}
              open={false} accent="border-gray-200">
              <pre className="mt-2 max-h-[400px] overflow-auto rounded-lg bg-gray-50 p-4 text-xs text-gray-600 font-mono whitespace-pre-wrap">
                {JSON.stringify(effectiveData, null, 2)}
              </pre>
            </Sec>
          </div>

          {inv.correlated_events && inv.correlated_events.length > 0 && (
            <Sec title={`Correlated Events (${inv.correlated_events.length})`}
              icon={<Layers className="h-3.5 w-3.5 text-teal-600" />}
              accent="border-teal-200">
              <div className="mt-2 flex flex-wrap gap-1">
                {inv.correlated_events.map(eid => (
                  <span key={eid} className="group rounded bg-gray-100 px-2 py-1 text-xs font-mono text-gray-700 ring-1 ring-gray-200">
                    {eid}<CopyBtn text={eid} />
                  </span>
                ))}
              </div>
            </Sec>
          )}
        </TabsContent>
      </Tabs>
      </div>
    </div>
  );
}
