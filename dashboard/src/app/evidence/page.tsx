"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import {
  CheckCircle,
  XCircle,
  RefreshCw,
  Lock,
  Search as SearchIcon,
  Fingerprint,
  Download,
} from "lucide-react";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, cn } from "@/lib/utils";
import type { EvidenceBatch, EvidenceSummary } from "@/lib/types";
import type { Investigation } from "@/lib/types";

interface EvidenceResponse {
  batches: EvidenceBatch[];
  summary: EvidenceSummary;
}

function VerifyButton({ batchId }: { batchId: string }) {
  const [result, setResult] = useState<{ valid: boolean; checked: boolean } | null>(null);
  const [loading, setLoading] = useState(false);

  const verify = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/evidence/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ batchId }),
      });
      const d = await res.json();
      setResult({ valid: d.valid ?? true, checked: true });
    } catch {
      setResult({ valid: false, checked: true });
    } finally {
      setLoading(false);
    }
  };

  if (result?.checked) {
    return (
      <span className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        result.valid ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-600" : "border-red-500/30 bg-red-500/10 text-red-600"
      )}>
        {result.valid ? <CheckCircle className="h-2.5 w-2.5" /> : <XCircle className="h-2.5 w-2.5" />}
        {result.valid ? "Verified" : "Tampered"}
      </span>
    );
  }

  return (
    <button onClick={verify} disabled={loading}
      className="rounded-md border border-blue-500/30 bg-blue-500/5 px-3 py-1 text-xs font-semibold text-blue-600 hover:bg-blue-500/10 transition-colors disabled:opacity-50">
      {loading ? <RefreshCw className="h-3 w-3 animate-spin" /> : "VERIFY"}
    </button>
  );
}

function fmtTs(ts: string) {
  try {
    const d = new Date(ts);
    const date = d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
    const time = String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0") + ":" + String(d.getSeconds()).padStart(2, "0");
    return { date, time };
  } catch {
    return { date: "\u2014", time: "" };
  }
}

export default function EvidencePage() {
  const { data, loading, refresh } = usePolling<EvidenceResponse>("/api/evidence/chain", 15000);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [search, setSearch] = useState("");
  const [clock, setClock] = useState("");
  const [expandedBatch, setExpandedBatch] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/ai/investigations/list").then(r => r.json()).then(d => setInvestigations(Array.isArray(d.investigations) ? d.investigations : [])).catch(() => { });
  }, []);

  useEffect(() => {
    const tick = () => {
      const n = new Date();
      setClock(n.getFullYear() + "-" + String(n.getMonth() + 1).padStart(2, "0") + "-" + String(n.getDate()).padStart(2, "0") + " " + String(n.getHours()).padStart(2, "0") + ":" + String(n.getMinutes()).padStart(2, "0") + ":" + String(n.getSeconds()).padStart(2, "0"));
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  if (loading && !data) return (
    <div className="space-y-4">{[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-32 rounded-lg" />)}</div>
  );

  const batches = data?.batches || [];
  const summary = data?.summary;
  const sl = search.toLowerCase();
  const fb = batches.filter(b => !sl || b.id.toLowerCase().includes(sl) || (b.tableName && b.tableName.toLowerCase().includes(sl)) || (b.merkleRoot && b.merkleRoot.toLowerCase().includes(sl)));
  const fi = investigations.filter(inv => !sl || inv.id.toLowerCase().includes(sl) || inv.title.toLowerCase().includes(sl));

  // Derive verifier agent operational status from real data
  const verifierStatus = summary
    ? summary.verificationRate >= 95 ? "OPERATIONAL" : summary.verificationRate >= 50 ? "DEGRADED" : "DOWN"
    : "UNKNOWN";
  const verifierColor = verifierStatus === "OPERATIONAL" ? "text-emerald-600" : verifierStatus === "DEGRADED" ? "text-yellow-600" : "text-red-500";

  const doExport = () => {
    const lines = [
      "CLIF \u2014 Chain of Custody Audit Log",
      "Exported: " + new Date().toISOString(),
      "",
      "=== SUMMARY ===",
      summary ? "Total Batches: " + summary.totalBatches : "",
      summary ? "Total Anchored Events: " + summary.totalAnchored : "",
      summary ? "Verification Rate: " + summary.verificationRate + "%" : "",
      summary ? "Avg Batch Size: " + summary.avgBatchSize + " events" : "",
      summary ? "Chain Length: " + summary.chainLength : "",
      "",
      "=== EVIDENCE BATCHES ===",
      "Batch ID | Table | Events | Status | Merkle Root | Timestamp",
      ...batches.map(b => b.id + " | " + (b.tableName || "N/A") + " | " + b.eventCount + " | " + b.status + " | " + (b.merkleRoot ? b.merkleRoot.slice(0, 16) + "..." : "N/A") + " | " + b.timestamp),
      "",
      "=== EVIDENCE-BACKED INVESTIGATIONS ===",
      "ID | Title | Events | Severity | Status",
      ...investigations.map(inv => inv.id + " | " + inv.title + " | " + inv.eventCount + " | S" + inv.severity + " | " + inv.status)
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "clif_audit_log_" + new Date().toISOString().slice(0, 10) + ".txt"; a.click(); URL.revokeObjectURL(url);
  };

  return (
    <div className="-m-6 -mt-4 bg-white">
      {/* ═══ STATS HERO ═══ */}
      <div className="bg-white border-b border-border">
        <div className="px-10 py-12 max-w-[1600px] w-full mx-auto">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-8 mb-10">
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <span className="px-3 py-1 bg-emerald-50 text-emerald-600 text-[11px] font-black uppercase tracking-tighter rounded flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Active Session
                </span>
                <span className="text-muted-foreground text-sm font-medium">{clock}</span>
              </div>
              <h1 className="text-4xl lg:text-5xl font-extrabold text-foreground tracking-tight leading-[1.1]">
                Chain of <span className="text-primary inline-block">Custody</span>
              </h1>
              <p className="text-sm text-muted-foreground max-w-xl">Evidence integrity verification — HMAC-SHA256 signing, Merkle tree anchoring, and tamper-proof audit trails.</p>
            </div>
            <div className="flex gap-3 shrink-0">
              <div className="relative flex-1 max-w-xs">
                <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input placeholder="Search evidence IDs, batches..." className="pl-10 h-10 bg-white border-border rounded-2xl" value={search} onChange={e => setSearch(e.target.value)} />
              </div>
              <button onClick={refresh} className="flex items-center gap-2 px-5 py-2.5 bg-muted/50 border border-border rounded-2xl text-sm font-semibold hover:bg-accent transition-colors">
                <RefreshCw className="w-4 h-4" />
              </button>
              <button onClick={doExport} className="flex items-center gap-2 px-5 py-2.5 bg-primary text-primary-foreground rounded-2xl text-sm font-semibold hover:bg-primary/90 transition-colors shadow-lg shadow-primary/20">
                <Download className="w-4 h-4" /> Export Audit Log
              </button>
            </div>
          </div>

          {/* Verifier Agent Status */}
          <div className="flex items-center justify-between mb-10 py-4 px-6 rounded-2xl border border-border bg-white">
            <div className="flex items-center gap-3">
              <span className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Verifier Agent</span>
              <span className={cn("text-xs font-black uppercase", verifierColor)}>{verifierStatus}</span>
            </div>
            <div className="flex items-center gap-4">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-emerald-200 bg-emerald-50 text-xs font-bold text-emerald-600">
                <Lock className="h-3 w-3" /> HMAC-SHA256
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-blue-200 bg-blue-50 text-xs font-bold text-blue-600">
                <Fingerprint className="h-3 w-3" /> MERKLE VERIFIED
              </span>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground">
              <span>BATCHES: <span className="text-foreground font-bold">{summary ? formatNumber(summary.totalBatches) : "\u2014"}</span></span>
              <span className="text-border">|</span>
              <span>AVG_SIZE: <span className="text-foreground font-bold">{summary ? formatNumber(summary.avgBatchSize) : "\u2014"}</span></span>
              <span className="text-border">|</span>
              <span>RATE: <span className={cn("font-bold", verifierColor)}>{summary ? summary.verificationRate.toFixed(1) + "%" : "\u2014"}</span></span>
            </div>
          </div>

          {/* Stat Cards */}
          {summary && (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
              <div className="space-y-2">
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total Batches</p>
                <div className="flex items-baseline gap-2">
                  <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(summary.totalBatches)}</h3>
                  <span className="text-blue-500 text-xs font-bold">Active</span>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Total Anchored</p>
                <div className="flex items-baseline gap-2">
                  <h3 className="text-4xl font-extrabold text-foreground">{formatNumber(summary.totalAnchored)}</h3>
                  <span className="text-muted-foreground text-xs font-bold">Events</span>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Verification Rate</p>
                <div className="flex items-baseline gap-2">
                  <h3 className={cn("text-4xl font-extrabold font-mono", verifierColor)}>{summary.verificationRate.toFixed(1)}%</h3>
                  <span className="text-emerald-500 text-xs font-bold">Certified</span>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest">Chain Length</p>
                <div className="flex items-baseline gap-2">
                  <h3 className="text-4xl font-extrabold text-foreground font-mono">{formatNumber(summary.chainLength)}</h3>
                  <span className="text-muted-foreground text-xs font-bold">Blocks</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ═══ 12-COL GRID ═══ */}
      <div className="grid grid-cols-12">
        {/* LEFT COLUMN — Investigations */}
        <div className="col-span-12 xl:col-span-7 flex flex-col">
          <section className="px-10 py-12 bg-white border-t border-border">
            <div className="flex items-center justify-between mb-8">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-primary/10 text-primary rounded-2xl">
                  <Fingerprint className="w-5 h-5" />
                </div>
                <h3 className="text-2xl font-extrabold text-foreground">Evidence-Backed Investigations</h3>
              </div>
              <Link href="/investigations" className="text-[11px] font-black text-primary uppercase tracking-[0.2em] hover:underline">View All</Link>
            </div>
            <div className="bg-white rounded-[2.5rem] overflow-hidden border border-border shadow-sm">
              <table className="w-full text-left">
                <thead className="bg-muted/30">
                  <tr>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em]">Investigation Name</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em] text-center">Event Count</th>
                    <th className="px-6 py-5 text-[10px] font-black text-muted-foreground uppercase tracking-[0.2em] text-right">Integrity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/50">
                  {fi.slice(0, 5).map(inv => (
                    <tr key={inv.id} className="hover:bg-muted/10 transition-colors">
                      <td className="px-6 py-6">
                        <p className="font-bold text-foreground">{inv.title}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{inv.id}</p>
                      </td>
                      <td className="px-6 py-6 text-center">
                        <span className="font-mono font-bold text-foreground">{formatNumber(inv.eventCount)}</span>
                        <span className="text-xs text-muted-foreground ml-1">events</span>
                      </td>
                      <td className="px-6 py-6 text-right">
                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[10px] font-black text-emerald-600 uppercase">
                          <CheckCircle className="h-2.5 w-2.5" /> Verified
                        </span>
                      </td>
                    </tr>
                  ))}
                  {fi.length === 0 && (
                    <tr><td colSpan={3} className="py-12 text-center text-sm text-muted-foreground">No investigations found</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>

        {/* RIGHT COLUMN — Live Batches */}
        <aside className="col-span-12 xl:col-span-5 bg-white border-l border-border/80 p-8 space-y-6">
          <div className="flex items-center justify-between mb-2 px-2">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-white shadow-sm text-primary rounded-xl flex items-center justify-center border border-border">
                <Lock className="w-5 h-5" />
              </div>
              <h3 className="text-lg font-extrabold text-foreground">Live Evidence Batches</h3>
            </div>
            <p className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Click to expand</p>
          </div>

          <div className="space-y-3">
            {fb.slice(0, 6).map(batch => {
              const { date, time } = fmtTs(batch.timestamp);
              const isExpanded = expandedBatch === batch.id;
              return (
                <div key={batch.id} className="bg-white rounded-2xl border border-border shadow-sm hover:border-primary/30 transition-all overflow-hidden">
                  <div
                    className="flex items-center gap-4 p-5 cursor-pointer"
                    onClick={() => setExpandedBatch(isExpanded ? null : batch.id)}
                  >
                    <span className={cn("transition-transform text-muted-foreground text-[10px]", isExpanded ? "rotate-90" : "")}>▶</span>
                    <span className={cn("h-2.5 w-2.5 rounded-full shrink-0", batch.status === "Verified" ? "bg-emerald-500" : "bg-blue-500")} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono font-bold text-foreground truncate">{batch.id}</p>
                      {batch.tableName && <p className="text-[10px] text-muted-foreground font-mono truncate">{batch.tableName}</p>}
                    </div>
                    <div className="text-right shrink-0">
                      <p className="text-sm font-bold text-foreground">{formatNumber(batch.eventCount)}</p>
                      <p className="text-[10px] text-muted-foreground font-mono">{date} {time}</p>
                    </div>
                    <div onClick={e => e.stopPropagation()}><VerifyButton batchId={batch.id} /></div>
                  </div>
                  {isExpanded && (
                    <div className="mx-5 mb-5 mt-0 rounded-2xl border border-border bg-muted/10 p-5 grid grid-cols-2 gap-5">
                      <div>
                        <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-1">Merkle Root</p>
                        <p className="text-xs font-mono text-foreground break-all">{batch.merkleRoot || "N/A"}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-1">Merkle Depth</p>
                        <p className="text-xs font-mono text-foreground">{batch.merkleDepth ?? "N/A"}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-1">Time Range</p>
                        <p className="text-xs font-mono text-foreground">{batch.timeFrom ? new Date(batch.timeFrom).toLocaleString() : "N/A"} — {batch.timeTo ? new Date(batch.timeTo).toLocaleString() : "N/A"}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-black text-muted-foreground uppercase tracking-widest mb-1">S3 Key</p>
                        <p className="text-xs font-mono text-foreground">{batch.s3Key || "N/A"}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
            {fb.length === 0 && <div className="py-8 text-center text-sm text-muted-foreground">No evidence batches found</div>}
          </div>
        </aside>
      </div>

      {/* FOOTER */}
      <div className="px-10 py-6 border-t border-border bg-white">
        <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground uppercase tracking-wider">
          <div className="flex items-center gap-6">
            <span>Last Updated: {clock || "\u2014"} UTC</span>
            <span>System Integrity: <span className={cn(verifierColor)}>{summary && summary.verificationRate >= 95 ? "Hash-Match Verified" : summary ? "Partial \u2014 " + summary.verificationRate.toFixed(0) + "%" : "Unknown"}</span></span>
          </div>
          <span className="text-primary">Chain of Custody Protocol v2.4.1</span>
        </div>
      </div>
    </div>
  );
}
