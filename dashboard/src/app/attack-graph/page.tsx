"use client";

import React, { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import {
  RefreshCw,
  Maximize2,
  GitBranch,
  Brain,
  Crosshair,
  Search as SearchIcon,
  ShieldCheck,
  ChevronRight,
  AlertTriangle,
  Eye,
} from "lucide-react";

interface GraphData {
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    severity?: number;
    mitre?: string;
  }>;
  edges: Array<{
    source: string;
    target: string;
    label?: string;
  }>;
}

const NODE_COLORS: Record<string, string> = {
  host: "#06b6d4",
  user: "#8b5cf6",
  process: "#3b82f6",
  alert: "#ef4444",
  technique: "#f59e0b",
  ip: "#10b981",
};

function toFlowNodes(data: GraphData): Node[] {
  const cols = 3;
  return data.nodes.map((n, i) => ({
    id: n.id,
    position: {
      x: (i % cols) * 280 + 50,
      y: Math.floor(i / cols) * 150 + 50,
    },
    data: {
      label: (
        <div className="text-center">
          <div className="text-xs font-medium">{n.label}</div>
          {n.mitre && (
            <div className="mt-0.5 text-2xs text-muted-foreground">{n.mitre}</div>
          )}
        </div>
      ),
    },
    style: {
      background: `${NODE_COLORS[n.type] || "#64748b"}15`,
      border: `1px solid ${NODE_COLORS[n.type] || "#64748b"}40`,
      borderRadius: 8,
      padding: "8px 12px",
      fontSize: 12,
      color: NODE_COLORS[n.type] || "#64748b",
    },
  }));
}

function toFlowEdges(data: GraphData): Edge[] {
  return data.edges.map((e, i) => ({
    id: `e-${i}`,
    source: e.source,
    target: e.target,
    label: e.label,
    animated: true,
    style: { stroke: "hsl(var(--muted-foreground))", strokeWidth: 1.5 },
    labelStyle: { fontSize: 10, fill: "hsl(var(--muted-foreground))" },
    markerEnd: { type: MarkerType.ArrowClosed, width: 12, height: 12 },
  }));
}

export default function AttackGraphPage() {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [nodes, setNodes, onNodesChange] = useNodesState([] as Node[]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([] as Edge[]);
  const [selectedNode, setSelectedNode] = useState<GraphData["nodes"][0] | null>(null);
  const [investigations, setInvestigations] = useState<Array<{ id: string; title: string; severity: number; hosts: string[]; users: string[]; tags: string[] }>>([]);
  const loadGraph = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/ai/investigations/list");
      if (res.ok) {
        const data = await res.json();
        // Build graph from investigation data
        const investigations = Array.isArray(data.investigations) ? data.investigations : [];
        const graphNodes: GraphData["nodes"] = [];
        const graphEdges: GraphData["edges"] = [];
        const seen = new Set<string>();
        setInvestigations(investigations.slice(0, 10));

        investigations.slice(0, 10).forEach((inv: { id: string; title: string; severity: number; hosts: string[]; users: string[]; tags: string[] }) => {
          const alertId = `alert-${inv.id}`;
          if (!seen.has(alertId)) {
            graphNodes.push({ id: alertId, label: inv.title.slice(0, 30), type: "alert", severity: inv.severity });
            seen.add(alertId);
          }

          inv.hosts?.forEach((h: string) => {
            const hostId = `host-${h}`;
            if (!seen.has(hostId)) {
              graphNodes.push({ id: hostId, label: h, type: "host" });
              seen.add(hostId);
            }
            graphEdges.push({ source: alertId, target: hostId, label: "on" });
          });

          inv.users?.forEach((u: string) => {
            const userId = `user-${u}`;
            if (!seen.has(userId)) {
              graphNodes.push({ id: userId, label: u, type: "user" });
              seen.add(userId);
            }
            graphEdges.push({ source: alertId, target: userId, label: "by" });
          });
        });

        const gd: GraphData = { nodes: graphNodes, edges: graphEdges };
        setGraphData(gd);
        setNodes(toFlowNodes(gd));
        setEdges(toFlowEdges(gd));
      }
    } catch {} finally {
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  if (loading) {
    return <Skeleton className="h-[600px] rounded-lg" />;
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
            <GitBranch className="h-5 w-5 text-primary" />
            Attack Graph
          </h2>
          <p className="text-sm text-muted-foreground">
            Visualize attack chains and relationships discovered by the Hunter Agent
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {graphData?.nodes.length || 0} nodes, {graphData?.edges.length || 0} edges
          </span>
          <Button variant="outline" size="sm" onClick={loadGraph}>
            <RefreshCw className="mr-1 h-3 w-3" /> Refresh
          </Button>
        </div>
      </div>

      {/* Hunter Agent Banner */}
      <Card className="border-cyan-500/20 bg-cyan-500/5">
        <CardContent className="p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <SearchIcon className="h-4 w-4 text-primary" />
              <span className="text-xs text-foreground">
                Attack graphs generated by <span className="font-medium">Hunter Agent</span> — correlating events via Sigma, SPC, Graph, and Temporal analyzers
              </span>
            </div>
            <div className="flex items-center gap-2">
              {Object.entries(NODE_COLORS).map(([type, color]) => (
                <Badge key={type} variant="ghost" className="text-2xs gap-1">
                  <div className="h-2 w-2 rounded-full" style={{ background: color }} />
                  {type}
                </Badge>
              ))}
              <Link href="/ai-agents">
                <Button variant="ghost" size="sm" className="text-xs">Agents <ChevronRight className="ml-1 h-3 w-3" /></Button>
              </Link>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Graph */}
      <Card>
        <CardContent className="p-0">
          <div className="h-[500px] rounded-lg overflow-hidden">
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={(_e, node) => {
                const gn = graphData?.nodes.find((n) => n.id === node.id);
                setSelectedNode(gn || null);
              }}
              fitView
              className="bg-background"
            >
              <Background color="hsl(var(--border))" gap={20} size={1} />
              <Controls className="[&>button]:bg-card [&>button]:border-border [&>button]:text-foreground" />
              <MiniMap
                nodeColor={(n) => {
                  const type = graphData?.nodes.find((gn) => gn.id === n.id)?.type;
                  return NODE_COLORS[type || ""] || "#64748b";
                }}
                className="rounded-lg border border-border bg-card"
              />
            </ReactFlow>
          </div>
        </CardContent>
      </Card>

      {/* Selected Node Detail Panel */}
      {selectedNode && (
        <Card className="border-primary/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Eye className="h-4 w-4 text-primary" />
              Node Detail: {selectedNode.label}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4 text-xs">
              <div>
                <p className="text-muted-foreground">Type</p>
                <Badge variant="ghost" className="mt-1 text-2xs gap-1">
                  <div className="h-2 w-2 rounded-full" style={{ background: NODE_COLORS[selectedNode.type] || "#64748b" }} />
                  {selectedNode.type}
                </Badge>
              </div>
              {selectedNode.severity != null && (
                <div>
                  <p className="text-muted-foreground">Severity</p>
                  <Badge variant={selectedNode.severity >= 4 ? "critical" : selectedNode.severity >= 3 ? "high" : "medium"} className="mt-1 text-2xs">
                    {selectedNode.severity}/5
                  </Badge>
                </div>
              )}
              {selectedNode.mitre && (
                <div>
                  <p className="text-muted-foreground">MITRE ATT&CK</p>
                  <Badge variant="purple" className="mt-1 text-2xs">{selectedNode.mitre}</Badge>
                </div>
              )}
              <div>
                <p className="text-muted-foreground">Connected Edges</p>
                <p className="mt-1 font-mono font-bold text-foreground">
                  {graphData?.edges.filter((e) => e.source === selectedNode.id || e.target === selectedNode.id).length || 0}
                </p>
              </div>
            </div>
            {selectedNode.type === "alert" && (
              <div className="mt-3">
                <Link href={`/investigations/${selectedNode.id.replace("alert-", "")}`}>
                  <Button variant="cyan" size="sm" className="text-xs">
                    <Eye className="mr-1 h-3 w-3" /> Open Investigation
                  </Button>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Related Investigations */}
      {investigations.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Investigations in Graph
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2 lg:grid-cols-3">
              {investigations.map((inv) => (
                <Link key={inv.id} href={`/investigations/${inv.id}`}>
                  <div className="flex items-center gap-2 rounded-lg border border-border p-2 hover:border-primary/30 transition-colors">
                    <Badge variant={inv.severity >= 4 ? "critical" : inv.severity >= 3 ? "high" : "medium"} className="text-2xs shrink-0">
                      S{inv.severity}
                    </Badge>
                    <span className="text-xs text-foreground truncate flex-1">{inv.title}</span>
                    <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
