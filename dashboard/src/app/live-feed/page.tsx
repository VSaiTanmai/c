"use client";

import React, { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { Radio, Pause, Play, Filter, ArrowDown, AlertTriangle, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn, severityLabel, severityColor, timeAgo } from "@/lib/utils";
import type { EventRow } from "@/lib/types";

const MAX_EVENTS = 500;

export default function LiveFeedPage() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState<number | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let active = true;
    let timeoutId: ReturnType<typeof setTimeout>;

    async function poll() {
      if (!active) return;
      try {
        const res = await fetch("/api/events/stream");
        if (res.ok) {
          const json = await res.json();
          const newEvents: EventRow[] = json.data || [];
          if (!paused && newEvents.length > 0) {
            setEvents((prev) => {
              const ids = new Set(prev.map((e) => e.event_id));
              const fresh = newEvents.filter((e) => !ids.has(e.event_id));
              if (fresh.length === 0) return prev;
              const next = [...prev, ...fresh];
              return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
            });
          }
          setConnected(true);
        } else {
          setConnected(false);
        }
      } catch {
        setConnected(false);
      }
      if (active) timeoutId = setTimeout(poll, 3000);
    }

    poll();
    return () => {
      active = false;
      clearTimeout(timeoutId);
    };
  }, [paused]);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, autoScroll]);

  /* Severity stats */
  const severityStats = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    events.forEach((e) => {
      const s = e.severity || 0;
      if (s >= 4) counts.critical++;
      else if (s === 3) counts.high++;
      else if (s === 2) counts.medium++;
      else if (s === 1) counts.low++;
      else counts.info++;
    });
    return counts;
  }, [events]);

  const filtered = events.filter((e) => {
    const matchesSeverity = severityFilter === null || (e.severity || 0) === severityFilter;
    const matchesText = !filter ||
      e.raw?.toLowerCase().includes(filter.toLowerCase()) ||
      e.hostname?.toLowerCase().includes(filter.toLowerCase()) ||
      e.log_source?.toLowerCase().includes(filter.toLowerCase());
    return matchesSeverity && matchesText;
  });

  const getSeverityVariant = (sev?: number) => {
    if (!sev) return "info" as const;
    if (sev >= 4) return "critical" as const;
    if (sev >= 3) return "high" as const;
    if (sev >= 2) return "medium" as const;
    if (sev >= 1) return "low" as const;
    return "info" as const;
  };

  const getSeverityRowBg = (sev?: number) => {
    if (!sev) return "";
    if (sev >= 4) return "bg-destructive/8 border-l-2 border-l-destructive/50";
    if (sev >= 3) return "bg-orange-500/5 border-l-2 border-l-orange-500/40";
    if (sev >= 2) return "bg-amber-500/5 border-l-2 border-l-amber-500/30";
    return "";
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <div
            className={cn(
              "status-dot h-2 w-2",
              connected ? "status-dot-online" : "status-dot-offline"
            )}
          />
          <span className="text-xs text-muted-foreground">
            {connected ? "Connected" : "Disconnected"}
          </span>
          <Zap className="h-3 w-3 text-primary" />
          <span className="text-2xs font-mono text-muted-foreground">
            {events.length}/{MAX_EVENTS}
          </span>
        </div>

        <Button
          variant={paused ? "default" : "outline"}
          size="sm"
          onClick={() => setPaused(!paused)}
        >
          {paused ? <Play className="mr-1 h-3 w-3" /> : <Pause className="mr-1 h-3 w-3" />}
          {paused ? "Resume" : "Pause"}
        </Button>

        <Button
          variant={autoScroll ? "cyan" : "outline"}
          size="sm"
          onClick={() => setAutoScroll(!autoScroll)}
        >
          <ArrowDown className="mr-1 h-3 w-3" />
          Auto-scroll
        </Button>

        <div className="relative flex-1 min-w-[200px]">
          <Filter className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Filter events..."
            className="pl-8 h-7 text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>

        <Badge variant="secondary">{filtered.length} events</Badge>
      </div>

      {/* Severity Filter Buttons */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-2xs text-muted-foreground mr-1">Severity:</span>
        <Button variant={severityFilter === null ? "default" : "ghost"} size="sm" onClick={() => setSeverityFilter(null)} className="h-6 text-2xs px-2">
          All
        </Button>
        <Button variant={severityFilter === 4 ? "destructive" : "ghost"} size="sm" onClick={() => setSeverityFilter(severityFilter === 4 ? null : 4)} className="h-6 text-2xs px-2 gap-1">
          <AlertTriangle className="h-2.5 w-2.5" /> Critical ({severityStats.critical})
        </Button>
        <Button variant={severityFilter === 3 ? "default" : "ghost"} size="sm" onClick={() => setSeverityFilter(severityFilter === 3 ? null : 3)} className="h-6 text-2xs px-2">
          High ({severityStats.high})
        </Button>
        <Button variant={severityFilter === 2 ? "default" : "ghost"} size="sm" onClick={() => setSeverityFilter(severityFilter === 2 ? null : 2)} className="h-6 text-2xs px-2">
          Medium ({severityStats.medium})
        </Button>
        <Button variant={severityFilter === 1 ? "default" : "ghost"} size="sm" onClick={() => setSeverityFilter(severityFilter === 1 ? null : 1)} className="h-6 text-2xs px-2">
          Low ({severityStats.low})
        </Button>
      </div>

      {/* Event Stream */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-primary" />
            Live Event Stream
            {!paused && (
              <span className="status-dot status-dot-online ml-1 h-1.5 w-1.5" />
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-320px)]">
            <div className="space-y-0.5 font-mono text-xs">
              {filtered.length === 0 ? (
                <div className="flex h-32 items-center justify-center text-muted-foreground">
                  {events.length === 0
                    ? "Waiting for events..."
                    : "No events match filter"}
                </div>
              ) : (
                filtered.map((event, i) => (
                  <div
                    key={i}
                    className={cn(
                      "group flex items-start gap-2 rounded px-2 py-1 transition-colors hover:bg-muted/40",
                      getSeverityRowBg(event.severity)
                    )}
                  >
                    <span className="shrink-0 text-muted-foreground w-[140px]">
                      {event.timestamp
                        ? new Date(event.timestamp).toLocaleTimeString()
                        : "—"}
                    </span>
                    <Badge
                      variant={getSeverityVariant(event.severity)}
                      className="shrink-0 text-2xs w-16 justify-center"
                    >
                      {severityLabel(event.severity || 0)}
                    </Badge>
                    <span className="shrink-0 text-primary w-[100px] truncate">
                      {event.log_source || "unknown"}
                    </span>
                    <span className="shrink-0 text-muted-foreground w-[100px] truncate">
                      {event.hostname || "—"}
                    </span>
                    <span className="flex-1 truncate text-foreground/80">
                      {event.raw || JSON.stringify(event)}
                    </span>
                  </div>
                ))
              )}
              <div ref={bottomRef} />
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
