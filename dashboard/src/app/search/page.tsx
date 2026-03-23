"use client";

import React, { useState, useCallback } from "react";
import Link from "next/link";
import {
  Search as SearchIcon,
  Filter,
  Clock,
  Download,
  ChevronRight,
  Loader2,
  Brain,
  ShieldAlert,
  History,
  Bookmark,
  Trash2,
  Database,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { severityLabel, timeAgo, cn } from "@/lib/utils";
import type { EventRow } from "@/lib/types";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [searchType, setSearchType] = useState<"text" | "semantic">("text");
  const [results, setResults] = useState<EventRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [searchHistory, setSearchHistory] = useState<Array<{ query: string; type: string; count: number; time: Date }>>([]);
  const [savedSearches, setSavedSearches] = useState<Array<{ query: string; type: string }>>([
    { query: "lateral movement", type: "semantic" },
    { query: "failed login", type: "text" },
    { query: "suspicious process execution", type: "semantic" },
  ]);

  const handleSearch = useCallback(async () => {
    if (!query.trim()) return;
    setLoading(true);
    setSearched(true);
    try {
      const endpoint =
        searchType === "semantic" ? "/api/semantic-search" : "/api/events/search";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query.trim(), limit: 100 }),
      });
      if (res.ok) {
        const data = await res.json();
        const items = data.events || data.results || [];
        setResults(items);
        setSearchHistory((prev) => [
          { query: query.trim(), type: searchType, count: items.length, time: new Date() },
          ...prev.slice(0, 9),
        ]);
      }
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [query, searchType]);

  const handleSaveSearch = () => {
    if (!query.trim()) return;
    setSavedSearches((prev) => [{ query: query.trim(), type: searchType }, ...prev]);
  };

  const handleLoadSearch = (q: string, t: string) => {
    setQuery(q);
    setSearchType(t as "text" | "semantic");
  };

  const getSevVariant = (sev?: number) => {
    if (!sev) return "info" as const;
    if (sev >= 4) return "critical" as const;
    if (sev >= 3) return "high" as const;
    if (sev >= 2) return "medium" as const;
    if (sev >= 1) return "low" as const;
    return "info" as const;
  };

  return (
    <div className="space-y-4">
      {/* Search Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <SearchIcon className="h-5 w-5 text-primary" />
            Search
          </h2>
          <p className="text-sm text-muted-foreground">
            Full-text ClickHouse search &bull; LanceDB vector semantic search
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-2xs gap-1">
            <Database className="h-2.5 w-2.5" /> ClickHouse
          </Badge>
          <Badge variant="outline" className="text-2xs gap-1">
            <Brain className="h-2.5 w-2.5" /> LanceDB
          </Badge>
        </div>
      </div>

      {/* Search Bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex gap-2">
            <Tabs value={searchType} onValueChange={(v) => setSearchType(v as "text" | "semantic")}>
              <TabsList>
                <TabsTrigger value="text">Text</TabsTrigger>
                <TabsTrigger value="semantic">Semantic</TabsTrigger>
              </TabsList>
            </Tabs>
            <div className="relative flex-1">
              <SearchIcon className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={
                  searchType === "semantic"
                    ? "Describe what you're looking for..."
                    : "Search events by keyword..."
                }
                className="pl-9"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              />
            </div>
            <Button onClick={handleSearch} disabled={loading || !query.trim()}>
              {loading ? (
                <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              ) : (
                <SearchIcon className="mr-1 h-3.5 w-3.5" />
              )}
              Search
            </Button>
          </div>
          {searchType === "semantic" && (
            <p className="mt-2 text-2xs text-muted-foreground">
              Powered by LanceDB vector search — describe suspicious behavior in natural language
            </p>
          )}
        </CardContent>
      </Card>

      {/* Saved Searches & History */}
      {!searched && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <Bookmark className="h-4 w-4 text-primary" />
                Saved Searches
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {savedSearches.map((s, i) => (
                  <button
                    key={i}
                    onClick={() => handleLoadSearch(s.query, s.type)}
                    className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left hover:bg-muted/20 transition-colors"
                  >
                    <SearchIcon className="h-3 w-3 text-muted-foreground shrink-0" />
                    <span className="text-xs text-foreground flex-1 truncate">{s.query}</span>
                    <Badge variant="ghost" className="text-2xs">{s.type}</Badge>
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                <History className="h-4 w-4 text-muted-foreground" />
                Recent Searches
              </CardTitle>
            </CardHeader>
            <CardContent>
              {searchHistory.length === 0 ? (
                <p className="py-4 text-center text-xs text-muted-foreground">No searches yet</p>
              ) : (
                <div className="space-y-1">
                  {searchHistory.slice(0, 5).map((h, i) => (
                    <button
                      key={i}
                      onClick={() => handleLoadSearch(h.query, h.type)}
                      className="flex w-full items-center gap-2 rounded-md px-3 py-2 text-left hover:bg-muted/20 transition-colors"
                    >
                      <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                      <span className="text-xs text-foreground flex-1 truncate">{h.query}</span>
                      <Badge variant="ghost" className="text-2xs">{h.count} results</Badge>
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Results */}
      {searched && (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              {results.length} results found
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="text-xs" onClick={handleSaveSearch}>
                <Bookmark className="mr-1 h-3 w-3" /> Save Search
              </Button>
              {results.length > 0 && (
                <Link href="/investigations">
                  <Button variant="outline" size="sm" className="text-xs">
                    <ShieldAlert className="mr-1 h-3 w-3" /> Create Investigation
                  </Button>
                </Link>
              )}
            </div>
          </div>

          {results.length === 0 ? (
            <Card>
              <CardContent className="flex h-32 items-center justify-center text-sm text-muted-foreground">
                No events found
              </CardContent>
            </Card>
          ) : (
            <ScrollArea className="h-[calc(100vh-320px)]">
              <div className="space-y-1">
                {results.map((event, i) => (
                  <Card
                    key={i}
                    className={cn(
                      "cursor-pointer transition-all hover:border-primary/30",
                      expanded === i && "border-primary/30"
                    )}
                    onClick={() => setExpanded(expanded === i ? null : i)}
                  >
                    <CardContent className="p-3">
                      <div className="flex items-center gap-3">
                        <Badge variant={getSevVariant(event.severity)} className="shrink-0 text-2xs">
                          {severityLabel(event.severity || 0)}
                        </Badge>
                        <span className="text-2xs text-muted-foreground shrink-0">
                          {event.timestamp
                            ? new Date(event.timestamp).toLocaleString()
                            : "—"}
                        </span>
                        <span className="text-xs text-primary shrink-0">
                          {event.log_source || "—"}
                        </span>
                        <span className="flex-1 truncate font-mono text-xs text-foreground/80">
                          {event.raw || "—"}
                        </span>
                        <ChevronRight
                          className={cn(
                            "h-3.5 w-3.5 text-muted-foreground transition-transform",
                            expanded === i && "rotate-90"
                          )}
                        />
                      </div>

                      {expanded === i && (
                        <div className="mt-3 rounded-md border border-border bg-muted/30 p-3">
                          <pre className="clif-mono whitespace-pre-wrap text-xs text-foreground/90">
                            {JSON.stringify(event, null, 2)}
                          </pre>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </ScrollArea>
          )}
        </div>
      )}
    </div>
  );
}
