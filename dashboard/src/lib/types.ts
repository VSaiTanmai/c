/* ── Dashboard metrics ── */
export interface DashboardMetrics {
  totalEvents: number;
  ingestRate: number;
  activeAlerts: number;
  topSources: Array<{ source: string; count: number }>;
  severityDistribution: Array<{ severity: number; count: number }>;
  eventsTimeline: Array<{ time: string; count: number }>;
  uptime?: string;
  criticalAlertCount?: number;
  tableCounts?: Record<string, number>;
  evidenceBatches?: number;
  evidenceAnchored?: number;
  mitreTopTechniques?: Array<{ technique: string; tactic: string; count: number }>;
  /* ── New: competitive feature additions ── */
  riskScore?: number;
  riskTrend?: number;
  mttr?: number;
  mttrTrend?: number;
  riskyEntities?: Array<{ entity: string; type: "user" | "host" | "ip"; riskScore: number; alertCount: number }>;
  mitreTacticHeatmap?: Array<{ tactic: string; techniques: number; alerts: number }>;
  /** Previous period values for KPI sparkline trends */
  prevTotalEvents?: number;
  prevActiveAlerts?: number;
  prevIngestRate?: number;
}

/* ── Generic event row ── */
export interface EventRow {
  timestamp: string;
  log_source?: string;
  hostname?: string;
  severity?: number;
  raw?: string;
  [key: string]: unknown;
}

/* ── Investigation (frontend-facing, mapped from ClickHouse in API layer) ── */
export interface Investigation {
  id: string;
  title: string;
  status: string;
  severity: number;
  created: string;
  updated: string;
  assignee: string;
  eventCount: number;
  description: string;
  tags: string[];
  hosts: string[];
  users: string[];
}

/* ── Full investigation detail (from /api/investigations/[id]) ── */
export interface InvestigationDetail {
  investigation: {
    investigation_id: string;
    alert_id: string;
    started_at: string;
    completed_at: string | null;
    status: string;
    hostname: string;
    source_ip: string;
    user_id: string;
    trigger_score: number;
    severity: string;
    finding_type: string;
    summary: string;
    mitre_tactics: string[];
    mitre_techniques: string[];
    recommended_action: string;
    confidence: number;
    correlated_events: string[];
  };
  verification: {
    verification_id: string;
    status: string;
    started_at: string;
    completed_at: string | null;
    verdict: string;
    confidence: number;
    priority: string;
    analyst_summary: string;
    evidence_verified: boolean;
    merkle_batch_ids: string[];
    recommended_action: string;
    report_narrative: string;
  } | null;
  triage: {
    score_id: string;
    event_id: string;
    timestamp: string;
    source_type: string;
    hostname: string;
    source_ip: string;
    user_id: string;
    template_id: string;
    template_rarity: number;
    combined_score: number;
    lgbm_score: number;
    eif_score: number;
    arf_score: number;
    score_std_dev: number;
    agreement: number;
    ci_lower: number;
    ci_upper: number;
    asset_multiplier: number;
    adjusted_score: number;
    action: string;
    ioc_match: number;
    ioc_confidence: number;
    mitre_tactic: string;
    mitre_technique: string;
    shap_top_features: string;
    shap_summary: string;
    features_stale: number;
    model_version: string;
    disagreement_flag: number;
  } | null;
  raw_log: {
    event_id: string;
    timestamp: string;
    received_at: string;
    level: string;
    source: string;
    message: string;
    metadata: Record<string, string>;
    user_id: string;
    ip_address: string;
    request_id: string;
    anchor_tx_id: string;
    anchor_batch_hash: string;
  } | null;
  security_event: {
    event_id: string;
    timestamp: string;
    severity: number;
    category: string;
    source: string;
    description: string;
    user_id: string;
    ip_address: string;
    hostname: string;
    mitre_tactic: string;
    mitre_technique: string;
    ai_confidence: number;
    ai_explanation: string;
    raw_log_event_id: string;
    anchor_tx_id: string;
    metadata: Record<string, string>;
  } | null;
  timeline: Array<{
    source: string;
    timestamp: string;
    label: string;
  }>;
  attack_graph: {
    hunter: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>>; metadata?: Record<string, unknown> } | null;
    verifier: { nodes: Array<Record<string, unknown>>; edges: Array<Record<string, unknown>> } | null;
    mermaid: string | null;
  };
  evidence: {
    hunter: Record<string, unknown> | null;
    verifier: Record<string, unknown> | null;
    ioc_correlations: Array<Record<string, unknown>> | null;
  };
}

/* ── AI Agent ── */
export interface Agent {
  id: string;
  name: string;
  status: string;
  description: string;
  casesProcessed: number;
  accuracy: number;
  avgResponseTime: string;
  lastAction: string;
  lastActionTime: string;
}

export interface AgentActivity {
  timestamp: string;
  agent: string;
  action: string;
}

export interface PendingApproval {
  id: string;
  agent: string;
  action: string;
  reason: string;
  investigation: string;
  severity: number;
  created: string;
}

/* ── Threat Intel ── */
export interface IOC {
  type: string;
  value: string;
  source: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  mitre: string;
  tags: string[];
  matchedEvents: number;
}

export interface ThreatPattern {
  name: string;
  description: string;
  mitre: string;
  iocCount: number;
  matchedEvents: number;
  severity: number;
}

/* ── Evidence / Chain of Custody ── */
export interface EvidenceBatch {
  id: string;
  timestamp: string;
  tableName: string;
  timeFrom: string;
  timeTo: string;
  eventCount: number;
  merkleRoot: string;
  merkleDepth: number;
  s3Key: string;
  s3VersionId: string;
  status: string;
  prevMerkleRoot: string;
  /* Legacy fields for backward compatibility */
  txId?: string;
  blockNumber?: number;
}

export interface EvidenceSummary {
  totalAnchored: number;
  totalBatches: number;
  verificationRate: number;
  avgBatchSize: number;
  chainLength: number;
}

/* ── Reports ── */
export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
}

export interface Report {
  id: string;
  title: string;
  template: string;
  created: string;
  status: string;
  pages: number;
  size: string;
}

/* ── Users ── */
export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  status: string;
  lastLogin: string;
}
