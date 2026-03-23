"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  FileSearch,
  Plus,
  Filter,
  Clock,
  User,
  Tag,
  ChevronRight,
  AlertTriangle,
  Brain,
  Crosshair,
  Search as SearchIcon,
  ShieldCheck,
  Bot,
  CheckCircle,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, severityLabel, cn } from "@/lib/utils";
import type { Investigation } from "@/lib/types";

const STATUS_VARIANTS: Record<string, "default" | "success" | "warning" | "destructive" | "info" | "cyan" | "purple"> = {
  open: "warning",
  "in-progress": "cyan",
  closed: "success",
  escalated: "destructive",
};

export default function InvestigationsPage() {
  const { data, loading } = usePolling<{ investigations: Investigation[] }>(
    "/api/ai/investigations/list",
    15000
  );
  const [filter, setFilter] = useState("");
  const [statusTab, setStatusTab] = useState("all");

  const investigations = data?.investigations || [];
  const filtered = investigations.filter((inv) => {
    const matchesFilter =
      !filter ||
      inv.title.toLowerCase().includes(filter.toLowerCase()) ||
      inv.id.toLowerCase().includes(filter.toLowerCase()) ||
      inv.description.toLowerCase().includes(filter.toLowerCase());
    const matchesTab =
      statusTab === "all" || inv.status.toLowerCase() === statusTab;
    return matchesFilter && matchesTab;
  });

  /* Calculate severity stats */
  const criticalCount = investigations.filter((i) => i.severity >= 4).length;
  const highCount = investigations.filter((i) => i.severity === 3).length;
  const openCount = investigations.filter((i) => i.status === "Open").length;
  const inProgressCount = investigations.filter((i) => i.status === "In Progress").length;
  const totalEvents = investigations.reduce((sum, i) => sum + i.eventCount, 0);

  const getSevVariant = (sev: number) => {
    if (sev >= 4) return "critical" as const;
    if (sev >= 3) return "high" as const;
    if (sev >= 2) return "medium" as const;
    if (sev >= 1) return "low" as const;
    return "info" as const;
  };

  if (loading && !data) {
    return (
      <div className="space-y-3">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-24 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary Stats Bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="rounded-lg border border-border bg-card/50 p-3 text-center">
          <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">Total Cases</p>
          <p className="text-xl font-bold text-foreground">{investigations.length}</p>
        </div>
        <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-3 text-center">
          <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">Critical</p>
          <p className="text-xl font-bold text-destructive">{criticalCount}</p>
        </div>
        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-center">
          <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">Open</p>
          <p className="text-xl font-bold text-amber-400">{openCount}</p>
        </div>
        <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 text-center">
          <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">In Progress</p>
          <p className="text-xl font-bold text-primary">{inProgressCount}</p>
        </div>
        <div className="rounded-lg border border-border bg-card/50 p-3 text-center">
          <p className="text-2xs font-medium text-muted-foreground uppercase tracking-wider">Total Events</p>
          <p className="text-xl font-bold text-foreground">{formatNumber(totalEvents)}</p>
        </div>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge variant="secondary">{filtered.length} cases</Badge>
          <Badge variant="info" className="text-2xs gap-1">
            <Brain className="h-2.5 w-2.5" /> AI-powered pipeline
          </Badge>
        </div>
        <Button size="sm">
          <Plus className="mr-1 h-3.5 w-3.5" />
          New Investigation
        </Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Filter className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search investigations..."
            className="pl-8 h-7 text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <Tabs value={statusTab} onValueChange={setStatusTab}>
          <TabsList>
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="open">Open</TabsTrigger>
            <TabsTrigger value="in progress">In Progress</TabsTrigger>
            <TabsTrigger value="closed">Closed</TabsTrigger>
            <TabsTrigger value="escalated">Escalated</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>

      {/* Investigation List */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <Card>
            <CardContent className="flex h-32 items-center justify-center text-sm text-muted-foreground">
              No investigations found
            </CardContent>
          </Card>
        ) : (
          filtered.map((inv) => {
            const isClosed = inv.status === "Closed";
            const isOpen = inv.status === "Open";
            return (
              <Link key={inv.id} href={`/investigations/${inv.id}`}>
                <Card className="transition-all hover:border-primary/30 cursor-pointer">
                  <CardContent className="flex items-center gap-4 p-4">
                    <Badge variant={getSevVariant(inv.severity)} className="shrink-0 w-16 justify-center">
                      {severityLabel(inv.severity)}
                    </Badge>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-foreground truncate">
                          {inv.title}
                        </span>
                        <Badge
                          variant={STATUS_VARIANTS[inv.status.toLowerCase()] || "secondary"}
                          className="text-2xs shrink-0"
                        >
                          {inv.status}
                        </Badge>
                      </div>
                      <p className="mt-0.5 text-xs text-muted-foreground truncate">
                        {inv.description}
                      </p>
                      <div className="mt-1.5 flex flex-wrap items-center gap-3 text-2xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Clock className="h-2.5 w-2.5" />
                          {timeAgo(inv.created)}
                        </span>
                        <span className="flex items-center gap-1">
                          <User className="h-2.5 w-2.5" />
                          {inv.assignee}
                        </span>
                        <span>{inv.eventCount} events</span>
                        {inv.tags.slice(0, 3).map((tag) => (
                          <Badge key={tag} variant="ghost" className="text-2xs">
                            <Tag className="mr-0.5 h-2 w-2" />
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* AI Agent Pipeline Status Mini */}
                    <div className="hidden sm:flex items-center gap-1 shrink-0">
                      <div className={cn("flex items-center gap-0.5 rounded-md border px-1.5 py-1", isClosed || !isOpen ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/30 bg-amber-500/5")}>
                        <Crosshair className="h-2.5 w-2.5 text-amber-400" />
                        {isClosed || !isOpen ? <CheckCircle className="h-2 w-2 text-emerald-400" /> : <Loader2 className="h-2 w-2 text-amber-400 animate-spin" />}
                      </div>
                      <div className={cn("flex items-center gap-0.5 rounded-md border px-1.5 py-1", isClosed || !isOpen ? "border-emerald-500/30 bg-emerald-500/5" : "border-amber-500/30 bg-amber-500/5")}>
                        <SearchIcon className="h-2.5 w-2.5 text-primary" />
                        {isClosed || !isOpen ? <CheckCircle className="h-2 w-2 text-emerald-400" /> : <Loader2 className="h-2 w-2 text-primary animate-spin" />}
                      </div>
                      <div className={cn("flex items-center gap-0.5 rounded-md border px-1.5 py-1", isClosed ? "border-emerald-500/30 bg-emerald-500/5" : isOpen ? "border-muted-foreground/20 bg-muted/10" : "border-emerald-500/30 bg-emerald-500/5")}>
                        <ShieldCheck className="h-2.5 w-2.5 text-emerald-400" />
                        {isClosed ? <CheckCircle className="h-2 w-2 text-emerald-400" /> : isOpen ? <Clock className="h-2 w-2 text-muted-foreground" /> : <CheckCircle className="h-2 w-2 text-emerald-400" />}
                      </div>
                    </div>

                    <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                  </CardContent>
                </Card>
              </Link>
            );
          })
        )}
      </div>
    </div>
  );
}
