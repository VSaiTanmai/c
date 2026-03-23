"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Bell,
  Check,
  X,
  Filter,
  RefreshCw,
  ChevronDown,
  AlertTriangle,
  Clock,
  Brain,
  FileSearch,
  ChevronRight,
  Eye,
  EyeOff,
  ShieldAlert,
  Bot,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { usePolling } from "@/hooks/use-polling";
import { formatNumber, timeAgo, severityLabel, cn } from "@/lib/utils";
import { toast } from "sonner";

interface Alert {
  id: string;
  title: string;
  severity: number;
  status: string;
  source: string;
  timestamp: string;
  count: number;
  mitre?: string;
  assignee?: string;
  ai_classified?: boolean;
  confidence?: number;
}

interface AlertsResponse {
  alerts: Alert[];
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function AlertsPage() {
  const { data, loading, refresh } = usePolling<AlertsResponse>(
    "/api/alerts",
    10000
  );
  const [filter, setFilter] = useState("");
  const [tab, setTab] = useState("all");
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());
  const [acknowledgedAlerts, setAcknowledgedAlerts] = useState<Set<string>>(new Set());
  const [dismissedAlerts, setDismissedAlerts] = useState<Set<string>>(new Set());

  const alerts = data?.alerts || [];
  const filtered = alerts.filter((a) => {
    if (dismissedAlerts.has(a.id)) return false;
    const matchesFilter =
      !filter ||
      a.title.toLowerCase().includes(filter.toLowerCase()) ||
      a.source.toLowerCase().includes(filter.toLowerCase());
    const matchesTab =
      tab === "all" ||
      (tab === "critical" && a.severity >= 4) ||
      (tab === "high" && a.severity === 3) ||
      (tab === "medium" && a.severity === 2) ||
      (tab === "open" && a.status === "open") ||
      (tab === "acknowledged" && acknowledgedAlerts.has(a.id));
    return matchesFilter && matchesTab;
  });

  const toggleSelect = (id: string) => {
    setSelectedAlerts((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectAll = () => {
    if (selectedAlerts.size === filtered.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(filtered.map((a) => a.id)));
    }
  };

  const acknowledgeSelected = () => {
    setAcknowledgedAlerts((prev) => {
      const next = new Set(prev);
      selectedAlerts.forEach((id) => next.add(id));
      return next;
    });
    toast.success(`${selectedAlerts.size} alert(s) acknowledged`);
    setSelectedAlerts(new Set());
  };

  const dismissSelected = () => {
    setDismissedAlerts((prev) => {
      const next = new Set(prev);
      selectedAlerts.forEach((id) => next.add(id));
      return next;
    });
    toast.success(`${selectedAlerts.size} alert(s) dismissed`);
    setSelectedAlerts(new Set());
  };

  const getSevVariant = (sev: number) => {
    if (sev >= 4) return "critical" as const;
    if (sev >= 3) return "high" as const;
    if (sev >= 2) return "medium" as const;
    if (sev >= 1) return "low" as const;
    return "info" as const;
  };

  if (loading && !data) {
    return (
      <div className="space-y-4">
        {[...Array(5)].map((_, i) => (
          <Skeleton key={i} className="h-20 rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="critical" className="gap-1">
          <AlertTriangle className="h-3 w-3" />
          {data?.critical || 0} Critical
        </Badge>
        <Badge variant="high">{data?.high || 0} High</Badge>
        <Badge variant="medium">{data?.medium || 0} Medium</Badge>
        <Badge variant="low">{data?.low || 0} Low</Badge>
        <span className="text-xs text-muted-foreground">
          {formatNumber(data?.total || 0)} total alerts
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          <Badge variant="info" className="text-2xs gap-1">
            <Bot className="h-2.5 w-2.5" /> AI-classified
          </Badge>
          <Button variant="ghost" size="icon-sm" onClick={refresh}>
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Bulk Actions Bar */}
      {selectedAlerts.size > 0 && (
        <div className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/5 p-2.5">
          <span className="text-xs font-medium text-foreground">{selectedAlerts.size} selected</span>
          <Button variant="outline" size="sm" onClick={acknowledgeSelected} className="text-xs gap-1">
            <Check className="h-3 w-3" /> Acknowledge
          </Button>
          <Button variant="outline" size="sm" onClick={dismissSelected} className="text-xs gap-1">
            <EyeOff className="h-3 w-3" /> Dismiss
          </Button>
          <Link href={`/investigations?from=alerts&ids=${Array.from(selectedAlerts).join(",")}`}>
            <Button variant="default" size="sm" className="text-xs gap-1">
              <FileSearch className="h-3 w-3" /> Create Investigation
            </Button>
          </Link>
          <Button variant="ghost" size="sm" onClick={() => setSelectedAlerts(new Set())} className="text-xs ml-auto">
            Clear Selection
          </Button>
        </div>
      )}

      {/* Filter + Tabs */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" onClick={selectAll} className="text-2xs">
            {selectedAlerts.size === filtered.length ? "Deselect All" : "Select All"}
          </Button>
        </div>
        <div className="relative flex-1 min-w-[200px]">
          <Filter className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search alerts..."
            className="pl-8 h-7 text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="all">All</TabsTrigger>
            <TabsTrigger value="critical">Critical</TabsTrigger>
            <TabsTrigger value="high">High</TabsTrigger>
            <TabsTrigger value="open">Open</TabsTrigger>
            <TabsTrigger value="acknowledged">Ack&apos;d</TabsTrigger>
          </TabsList>
        </Tabs>
      </div>

      {/* Alert List */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <Card>
            <CardContent className="flex h-32 items-center justify-center text-sm text-muted-foreground">
              No alerts match your criteria
            </CardContent>
          </Card>
        ) : (
          filtered.map((alert) => {
            const isSelected = selectedAlerts.has(alert.id);
            const isAcked = acknowledgedAlerts.has(alert.id);
            return (
              <Card
                key={alert.id}
                className={cn(
                  "transition-all hover:border-primary/30",
                  alert.severity >= 4 && "gradient-critical",
                  isSelected && "ring-2 ring-primary/50",
                  isAcked && "opacity-60"
                )}
              >
                <CardContent className="flex items-center gap-4 p-4">
                  {/* Selection checkbox */}
                  <button
                    onClick={() => toggleSelect(alert.id)}
                    className={cn(
                      "flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors",
                      isSelected ? "bg-primary border-primary" : "border-muted-foreground/40 hover:border-primary"
                    )}
                  >
                    {isSelected && <Check className="h-2.5 w-2.5 text-primary-foreground" />}
                  </button>

                  <Badge variant={getSevVariant(alert.severity)} className="shrink-0">
                    {severityLabel(alert.severity)}
                  </Badge>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {alert.title}
                    </p>
                    <div className="mt-1 flex flex-wrap items-center gap-2">
                      <span className="text-2xs text-muted-foreground">
                        {alert.source}
                      </span>
                      {alert.mitre && (
                        <Badge variant="purple" className="text-2xs">
                          {alert.mitre}
                        </Badge>
                      )}
                      <Badge variant="info" className="text-2xs gap-0.5">
                        <Brain className="h-2 w-2" /> AI
                      </Badge>
                      <span className="text-2xs text-muted-foreground">
                        <Clock className="mr-0.5 inline h-2.5 w-2.5" />
                        {timeAgo(alert.timestamp)}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {alert.count > 1 && (
                      <Badge variant="secondary" className="text-2xs">
                        ×{alert.count}
                      </Badge>
                    )}
                    {isAcked ? (
                      <Badge variant="success" className="text-2xs gap-0.5">
                        <Check className="h-2 w-2" /> Ack
                      </Badge>
                    ) : (
                      <Badge
                        variant={alert.status === "open" ? "warning" : "success"}
                        className="text-2xs"
                      >
                        {alert.status}
                      </Badge>
                    )}
                    {/* Quick actions */}
                    <div className="flex items-center gap-1">
                      {!isAcked && (
                        <Button variant="ghost" size="icon-sm" onClick={() => { setAcknowledgedAlerts((prev) => new Set(prev).add(alert.id)); toast.success("Alert acknowledged"); }} title="Acknowledge">
                          <Eye className="h-3 w-3" />
                        </Button>
                      )}
                      <Link href={`/investigations?from=alert&id=${alert.id}`}>
                        <Button variant="ghost" size="icon-sm" title="Create Investigation">
                          <ShieldAlert className="h-3 w-3" />
                        </Button>
                      </Link>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
