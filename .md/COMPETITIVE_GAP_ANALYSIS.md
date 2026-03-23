# CLIF Competitive Gap Analysis
## Cognitive Log Investigation Framework — SIH1733

**Date:** February 2026  
**Competitors Analyzed:** Splunk Enterprise Security, Elastic Security, Microsoft Sentinel, Google Chronicle/SecOps, CrowdStrike Falcon Next-Gen SIEM, IBM QRadar, Wazuh (Open Source), Palo Alto Cortex XSIAM, Exabeam/LogRhythm

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Competitor Feature Matrix](#competitor-feature-matrix)
3. [Page-by-Page Gap Analysis](#page-by-page-gap-analysis)
4. [Critical Missing Features](#critical-missing-features)
5. [CLIF Unique Strengths](#clif-unique-strengths)
6. [Priority Recommendations](#priority-recommendations)
7. [Features to Remove/De-prioritize](#features-to-removede-prioritize)

---

## Executive Summary

After intensive research across 9 major SIEM/SOC competitors, CLIF demonstrates strong foundational capabilities (real-time log analysis, AI-powered classification, attack graph visualization, evidence chain of custody) but has significant gaps in areas that all enterprise competitors have standardized on. The most critical gaps are:

1. **No Risk Scoring / UEBA** — Every major competitor (Splunk, Elastic, Sentinel, Chronicle, Exabeam) has entity risk scoring and user/entity behavior analytics
2. **No SOAR / Automated Playbooks** — Splunk SOAR, Sentinel Playbooks, Chronicle SOAR, CrowdStrike Fusion, Cortex XSOAR all offer automated response workflows
3. **No Case Management** — Elastic Cases, Sentinel Incidents, Chronicle Cases, CrowdStrike Case Management all offer structured case workflows
4. **No Compliance Dashboards** — Wazuh, Exabeam, QRadar, Sentinel all map detections to regulatory frameworks (PCI-DSS, HIPAA, SOX, GDPR)
5. **No AI Assistant / NLP Query** — Elastic AI Assistant, Chronicle Gemini, CrowdStrike Charlotte AI, Sentinel Copilot all offer natural language investigation

---

## Competitor Feature Matrix

| Feature | CLIF | Splunk ES | Elastic | Sentinel | Chronicle | CrowdStrike | QRadar | Wazuh | XSIAM | Exabeam |
|---------|------|-----------|---------|----------|-----------|-------------|--------|-------|-------|---------|
| **Security Posture Dashboard** | ⚠️ Basic | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ✅ Full |
| **Incident/Alert Management** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Real-time Log Feed** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Log Search (Keyword)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Semantic/AI Search** | ✅ | ❌ | ✅ | ❌ | ✅ (Gemini) | ✅ (Charlotte) | ❌ | ❌ | ✅ | ❌ |
| **Investigation Workflow** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Attack Graph Visualization** | ✅ | ❌ | ❌ | ✅ (Investigation Graph) | ✅ (Entity Graph) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **AI-Powered Classification** | ✅ | ❌ | ✅ (ML Jobs) | ❌ | ✅ (Curated) | ✅ (AI-native) | ❌ | ❌ | ✅ | ✅ (UEBA) |
| **MITRE ATT&CK Mapping** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **IOC Management** | ✅ | ✅ | ✅ | ✅ (Watchlists) | ✅ (TI Feeds) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Evidence Chain of Custody** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Merkle Tree Verification** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Report Generation** | ✅ | ✅ | ✅ | ✅ (Workbooks) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **System Health Monitoring** | ✅ | ✅ (Audit) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Risk Scoring / Risk Analysis** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| **UEBA (User & Entity Behavior)** | ❌ | ✅ (UBA) | ✅ (Entity Analytics) | ✅ (UEBA) | ✅ (UEBA) | ❌ | ✅ (UBA) | ❌ | ✅ | ✅ |
| **SOAR / Playbooks** | ❌ | ✅ (SOAR) | ❌ | ✅ (Logic Apps) | ✅ (300+ integrations) | ✅ (Fusion SOAR) | ❌ | ✅ (Active Response) | ✅ (XSOAR) | ✅ |
| **Case Management** | ❌ | ❌ | ✅ (Cases) | ✅ (Incidents) | ✅ (Cases) | ✅ | ❌ | ❌ | ✅ | ✅ |
| **AI Assistant / NLP Query** | ❌ | ❌ | ✅ (AI Assistant) | ✅ (Copilot) | ✅ (Gemini) | ✅ (Charlotte AI) | ❌ | ❌ | ✅ | ✅ (Nova) |
| **Compliance Dashboards** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| **Vulnerability Detection** | ❌ | ❌ | ✅ (Cloud) | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ (Xpanse) | ❌ |
| **File Integrity Monitoring** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Network Flow Analysis** | ❌ | ✅ (Protocol Intel) | ❌ | ❌ | ❌ | ❌ | ✅ (NDR) | ❌ | ❌ | ✅ (NetMon) |
| **Hunting Notebooks** | ❌ | ❌ | ❌ | ✅ (Jupyter) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Custom Dashboards** | ❌ | ✅ | ✅ | ✅ (Workbooks) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Similar Incident Detection** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Incident Timeline** | ❌ | ✅ | ✅ (Timeline) | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Bookmark / Evidence Tagging** | ❌ | ❌ | ❌ | ✅ (Bookmarks) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Attack Surface Management** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (Xpanse) | ❌ |

---

## Page-by-Page Gap Analysis

### 1. Dashboard Page (`/dashboard`)
**Current CLIF:** 5 KPI cards (Total Logs, Alerts, Critical, Open Investigations, AI Classifications), Alerts by Severity bar chart, Log Sources pie chart, 3 tables (Recent Alerts, Recent Logs, Active Investigations)

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Risk Score Widget** | Splunk ES, Elastic, Sentinel, Exabeam | 🔴 HIGH | A top-level risk score showing overall environment health (e.g., "Risk Score: 72/100") with trend over time. Splunk ES has a dedicated "Security Posture" dashboard with risk-scored notable events. |
| **MITRE ATT&CK Heatmap** | Sentinel, Elastic, Chronicle | 🔴 HIGH | Visual coverage map showing which MITRE techniques have been triggered. Sentinel shows this as the main detection overview. |
| **Top Risky Users/Assets** | Splunk ES (Risk Analysis), Exabeam, Sentinel (UEBA) | 🟡 MEDIUM | Widget showing top 5-10 users or hosts by cumulative risk score. Identifies potential insider threats or compromised accounts at a glance. |
| **Mean Time to Detect/Respond** | CrowdStrike, Google SecOps, Exabeam | 🟡 MEDIUM | MTTR/MTTD metrics showing SOC performance trends. Chronicle measures analyst productivity and MTTR. |
| **Geolocation Map** | Splunk ES, QRadar, Wazuh | 🟢 LOW | Map showing geographic distribution of threat origins or login locations. |
| **Trend Sparklines** | All competitors | 🟡 MEDIUM | Each KPI card should show 7-day trend. Currently just static numbers. |
| **Time Range Selector** | All competitors | 🔴 HIGH | Global time picker (Last 1h, 4h, 24h, 7d, 30d, custom). All competitors have this. CLIF hardcodes "last 24h". |

**What CLIF has that's good:**
- AI Classifications KPI is unique — no competitor shows ML pipeline stats on dashboard
- Dual chart approach (severity + sources) is solid
- Three tables covering alerts, logs, and investigations is comprehensive

---

### 2. Alerts Page (`/alerts`)
**Current CLIF:** 4 summary cards (Total, Critical, High, Unacknowledged), filtering by severity/status/source, bulk acknowledge/resolve, workflow states (New → Acknowledged → Investigating → Resolved/False Positive)

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Alert Grouping / Incident Correlation** | Sentinel, Elastic, CrowdStrike, XSIAM | 🔴 HIGH | Automatically group related alerts into incidents. XSIAM "stitches" alerts together. Sentinel aggregates alerts into incidents with entity mapping. CLIF shows flat alert list without correlation. |
| **Assignee / Owner** | Sentinel, Splunk ES, Elastic Cases | 🔴 HIGH | Assign alerts to specific SOC analysts. Track who is working on what. Sentinel allows owner assignment with directory integration. |
| **MITRE Tactic/Technique Tags** | Elastic, Sentinel, Splunk ES | 🔴 HIGH | Each alert should show mapped MITRE tactic/technique. Enables filtering alerts by kill chain stage. |
| **Risk-Based Prioritization** | Splunk ES (Risk-Based Alerting) | 🟡 MEDIUM | Alerts scored by risk, not just severity. Combines entity risk + alert severity for priority ranking. |
| **Alert Suppression Rules** | Splunk ES, CrowdStrike, Elastic | 🟡 MEDIUM | Let analysts create suppression/tuning rules to reduce noise without deleting detection logic. |
| **Run Playbook on Alert** | Sentinel, Chronicle, CrowdStrike | 🟡 MEDIUM | Trigger automated response directly from an alert row. |
| **Similar Alerts** | Sentinel | 🟢 LOW | Show 20 most similar historical alerts for context. Helps identify recurring patterns. |

**What CLIF has that's good:**
- Bulk actions are present (many competitors require one-by-one)
- Workflow state machine (New → Acknowledged → Investigating → Resolved/False Positive) is solid

---

### 3. Live Feed Page (`/live-feed`)
**Current CLIF:** 1-second polling, pause/resume, severity filtering, table display of streaming logs

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Log Format Auto-detection** | QRadar, Splunk, Chronicle | 🟢 LOW | Auto-identify and parse different log formats on ingest (already handled by backend, but show parsed view). |
| **Quick Drill-down** | All competitors | 🟡 MEDIUM | Click on any field value (IP, user, hostname) to filter or pivot to that entity's full view. |
| **Anomaly Highlighting** | Elastic (ML Jobs), Exabeam | 🟡 MEDIUM | ML-detected anomalies highlighted in real-time stream with visual markers. |
| **Data Source Health Indicators** | Splunk ES, CrowdStrike | 🟡 MEDIUM | Show which log sources are actively feeding data, and flag any that have stopped sending. |

**What CLIF has that's good:**
- 1-second polling rate is competitive (Elastic does near-real-time, most competitors are similar)
- Pause/resume is a standard but useful feature
- Real-time feed as a dedicated page is not common — most competitors embed it within search or dashboard

---

### 4. Search Page (`/search`)
**Current CLIF:** Dual mode (keyword + semantic AI search), CSV export, time-range filtering

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Saved Searches / Query Library** | Splunk, Elastic, Sentinel, Chronicle, QRadar | 🔴 HIGH | Save, name, and share search queries. Build a library of useful queries. Sentinel has "Hunting queries" which are shareable. |
| **Search-to-Detection Rule** | Elastic, Sentinel, Chronicle | 🔴 HIGH | Convert a search query directly into a detection rule. "Save as Alert" button. Critical for threat hunting workflow. |
| **Structured Query Language** | Splunk (SPL), Elastic (KQL/EQL), Sentinel (KQL), Chronicle (YARA-L), QRadar (AQL) | 🟡 MEDIUM | A domain-specific language for writing complex search queries. CLIF uses keyword/semantic but all enterprise tools have their own query language. |
| **Auto-suggest / Field Completion** | All competitors | 🟡 MEDIUM | As user types, suggest field names and values from the schema. |
| **Visualization from Search** | Splunk, Elastic, Sentinel (Workbooks) | 🟡 MEDIUM | Build charts/graphs directly from search results. "Visualize" button. |
| **Search History** | Splunk, Elastic, Sentinel | 🟢 LOW | View and re-run previous searches. |
| **Federated Search** | CrowdStrike, Sentinel | 🟢 LOW | Search across data in different locations/storage tiers. |

**What CLIF has that stands out:**
- **Semantic AI search is a major differentiator** — only Elastic, Chronicle (Gemini), and CrowdStrike (Charlotte) offer NLP-style search. Most competitors still rely on structured query languages.
- Dual keyword + semantic mode is unique

---

### 5. Investigations Page (`/investigations`)
**Current CLIF:** Investigation list + detail view with ReactFlow attack graph, investigation notes

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Case Management Workflow** | Elastic (Cases), Sentinel (Incidents), Chronicle (Cases), CrowdStrike | 🔴 HIGH | Full case lifecycle: create, assign, track SLA, attach evidence, collaborate, close. Send to Jira/ServiceNow. CLIF has basic investigation but lacks formal case management. |
| **Investigation Timeline** | Sentinel, Elastic (Timeline), Splunk ES, Exabeam | 🔴 HIGH | Interactive timeline showing chronological sequence of events/alerts. Sentinel shows parallel timeline with the investigation graph. Elastic "Timeline" is a dedicated investigation tool. |
| **Entity Pivot / Deep Dive** | Sentinel (Entity Pages), Splunk ES (Asset Investigator), Chronicle (Asset/User/IP views) | 🔴 HIGH | Click on any entity (user, IP, host, file hash) to see a 360° profile: all related alerts, activity timeline, risk score, UEBA insights. Major gap in CLIF. |
| **Collaboration Features** | Sentinel (Comments, Activity Log), CrowdStrike, Chronicle (Case Wall) | 🟡 MEDIUM | Multiple analysts can collaborate on the same case with comments, activity log, task assignment. Sentinel creates Microsoft Teams channels per incident. |
| **Notes / Bookmarks with Evidence Links** | Sentinel (Bookmarks), Elastic (Cases notes) | 🟡 MEDIUM | Save query results as bookmarks and attach them to investigations. Sentinel bookmarks can be added directly from log search. |
| **Automated Enrichment** | All enterprise competitors | 🟡 MEDIUM | Auto-enrich entities with GeoIP, WHOIS, threat intel, VirusTotal, reputation scores when an investigation is opened. |
| **SLA Tracking** | CrowdStrike, Palo Alto XSIAM, Exabeam | 🟢 LOW | Track time-to-respond SLAs per incident severity. |

**What CLIF has that stands out:**
- **ReactFlow attack graph is a differentiator** — only Sentinel (investigation graph) and Chronicle (entity graph) have similar visual investigation tools. Most competitors do not offer interactive graph-based investigation.
- Linking multiple investigations to a combined attack graph is unique

---

### 6. Attack Graph Page (`/attack-graph`)
**Current CLIF:** Combined multi-investigation attack graph visualization

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Exploration Queries** | Sentinel (Investigation Graph) | 🟡 MEDIUM | Hover over a node and get suggested "exploration queries" to expand the graph (e.g., "Related alerts", "Was this IP seen in other incidents?"). |
| **Entity Connections with Alerts** | Sentinel | 🟡 MEDIUM | Graph shows dotted lines between entities and related alerts, with severity color coding. |
| **Timeline Overlay** | Sentinel | 🟢 LOW | Parallel timeline alongside the graph showing when events occurred. |
| **Auto-Expanding Nodes** | Chronicle | 🟢 LOW | Automatically suggest and expand related entities based on threat intelligence. |

**What CLIF has that stands out:**
- **Multi-investigation combined graph is unique** — no competitor merges multiple investigations into a single graph
- ReactFlow-based interactive graphs are modern and well-implemented

---

### 7. AI Agents Page (`/ai-agents`)
**Current CLIF:** 5 tabs (Agents status, Investigate with agents, ML Model overview, Model leaderboard, Live classification)

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **AI Assistant Chat Interface** | Elastic (AI Assistant), Sentinel (Copilot), Chronicle (Gemini), CrowdStrike (Charlotte) | 🔴 HIGH | Chat-based interface for asking questions in natural language. "What happened to user John.Doe in the last 24 hours?" "Write a detection rule for brute force attacks." CLIF has AI agents but no conversational interface. |
| **AI-Generated Case Summaries** | Chronicle (Gemini), Elastic (Attack Discovery), CrowdStrike (Charlotte) | 🔴 HIGH | Auto-generate natural language summaries of incidents/cases. "This incident involves a lateral movement attempt from host-A to host-B..." |
| **Auto-Generated Detection Rules** | Elastic (AI Assistant), Chronicle (Gemini), CrowdStrike (agentic SOC) | 🟡 MEDIUM | AI suggests new detection rules based on discovered patterns. |
| **Alert Triage Recommendations** | CrowdStrike (Charlotte AI), XSIAM, Chronicle (Gemini) | 🟡 MEDIUM | AI recommends next steps for alert triage: "This alert is likely a true positive based on entity behavior. Recommended response: isolate host." |
| **Explainable AI** | Exabeam | 🟢 LOW | Show why the ML model classified a log a certain way, with feature importances and contributing factors. |

**What CLIF has that stands out:**
- **Dedicated AI Agents page is unique** — no competitor exposes their ML pipeline this transparently
- **Model leaderboard** is not found in any competitor
- **Live classification tab** showing real-time ML processing is novel
- Having 4 specialized agents (Classifier, Anomaly Detector, IOC Extractor, etc.) shown transparently is a differentiator for SIH

---

### 8. Threat Intelligence Page (`/threat-intel`)
**Current CLIF:** MITRE ATT&CK detection listing, IOC table with indicators

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Threat Intel Feed Management** | Sentinel (TI connectors), Chronicle (Applied TI), Splunk ES (TI Framework), CrowdStrike | 🔴 HIGH | Manage multiple threat intelligence feeds (STIX/TAXII, MISP, OTX, etc.). Enable/disable feeds, set confidence thresholds. CLIF shows IOCs but doesn't show feed sources or management. |
| **IOC Matching / Retro-hunting** | Chronicle (Retro-hunt), Elastic, Splunk ES | 🔴 HIGH | When a new IOC is added, automatically search all historical logs for matches. Chronicle does this at Google scale. |
| **MITRE ATT&CK Coverage Heatmap** | Sentinel, Elastic | 🟡 MEDIUM | Visual matrix showing which techniques are covered by rules and which have gaps. Not just detection listing but a strategy view. |
| **Threat Actor Profiles** | Chronicle (Mandiant TI), CrowdStrike (Adversary Universe), Splunk ES | 🟡 MEDIUM | Database of known threat actors with TTPs, motivations, targeted industries. |
| **IOC Enrichment** | Chronicle (VirusTotal), Sentinel, Splunk ES | 🟡 MEDIUM | Auto-enrich IOCs with reputation scores, related campaigns, and community intelligence. |
| **IOC Expiration / Lifecycle** | Sentinel (Watchlists), Elastic | 🟢 LOW | Auto-expire IOCs after a configurable period. Track IOC age and relevance. |

**What CLIF has that's good:**
- MITRE ATT&CK detection mapping is present
- IOC table with key indicators

---

### 9. Evidence Page (`/evidence`)
**Current CLIF:** Chain of custody tracking, Merkle tree verification for evidence integrity

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| No major gaps — this is a unique CLIF feature | — | — | — |

**What CLIF has that stands out:**
- **Chain of custody + Merkle tree verification is completely unique** — no competitor offers built-in forensic evidence integrity verification
- This is a major differentiator for legal/compliance scenarios
- Very relevant for SIH1733 (Smart India Hackathon) where the Indian government context values evidence preservation for law enforcement

---

### 10. Reports Page (`/reports`)
**Current CLIF:** Report templates, report generation history

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Scheduled Reports** | Splunk ES, QRadar, Elastic, Exabeam | 🟡 MEDIUM | Auto-generate reports on a schedule (daily, weekly, monthly) and email to stakeholders. |
| **Interactive Workbook-Style Reports** | Sentinel (Workbooks), Elastic (Dashboards) | 🟡 MEDIUM | Parameterized, interactive reports where users can change filters and drill down. |
| **Compliance Report Templates** | Wazuh, Exabeam, QRadar | 🟡 MEDIUM | Pre-built templates for PCI-DSS, HIPAA, SOX, ISO 27001, NIST CSF. |
| **Executive Summary Report** | Exabeam, Splunk ES | 🟢 LOW | High-level executive summary with risk posture, top incidents, and trend analysis. |
| **PDF/CSV/JSON Export** | All competitors | 🟢 LOW | Multiple export formats. |

**What CLIF has that's good:**
- Template system is present
- Generation history for audit trail

---

### 11. System Page (`/system`)
**Current CLIF:** Service health status, ClickHouse metrics, Redpanda metrics

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Data Ingestion Metrics** | Splunk ES (Audit), QRadar, Chronicle | 🟡 MEDIUM | EPS (events per second), data volume, ingestion lag, parsing failures per log source. |
| **License / Quota Usage** | Splunk ES, Sentinel, Chronicle | 🟢 LOW | Show how much of your data quota you're using. |
| **Content Update Status** | Splunk ES (Audit), QRadar (Content Extensions) | 🟢 LOW | Show status of detection rule updates, parser updates, etc. |

**What CLIF has that's good:**
- ClickHouse and Redpanda specific metrics are relevant for the Docker-based architecture
- Service health dashboard is well-implemented

---

### 12. Settings Page (`/settings`)
**Current CLIF:** General, Appearance (Light/Dark/System), Data Sources, Notifications, Integrations, Users, API Keys, Danger Zone

**What competitors do better:**

| Gap | Who Has It | Priority | Description |
|-----|-----------|----------|-------------|
| **Role-Based Access Control (RBAC)** | All enterprise competitors | 🔴 HIGH | Granular roles (Admin, Analyst, Viewer, etc.) with permission matrices. Sentinel has built-in Azure roles. |
| **Audit Log** | Sentinel, Splunk ES, QRadar | 🟡 MEDIUM | Track all user actions within the platform (who changed what, when). |
| **Data Retention Policies** | All competitors | 🟡 MEDIUM | Configure how long data is retained in hot/warm/cold storage. |
| **Detection Rule Management** | All competitors | 🟡 MEDIUM | Create, edit, enable/disable detection rules from settings. Not present as a dedicated section. |

---

### 13. MISSING Pages — Should Be Added

Based on competitor analysis, these are entirely new pages/features that CLIF should consider adding:

#### A. Entity Analytics / UEBA Page (🔴 HIGH PRIORITY)
**Who has it:** Splunk UBA, Elastic Entity Analytics, Sentinel UEBA, Exabeam (core product), Chronicle UEBA

**What it should include:**
- User risk score dashboard (risk score per user over time)
- Entity behavior baselines (normal login times, typical accessed resources)
- Anomaly detection (unusual login location, time, privilege escalation)
- Peer group analysis (comparing user behavior to their role group)
- Risk score calculation: accumulated from alerts, anomalies, rule matches
- Entity timeline showing all activity for a selected user/host

**Why CLIF needs it:** This is the #1 feature investors and customers expect. Every Gartner Leader has it. For SIH, demonstrating UEBA shows advanced threat detection capabilities beyond simple rules.

#### B. SOAR / Playbook Page (🔴 HIGH PRIORITY)
**Who has it:** Splunk SOAR, Sentinel (Automation Rules + Playbooks), Chronicle SOAR (300+ integrations), CrowdStrike Fusion SOAR, Palo Alto XSOAR, Exabeam SOAR

**What it should include:**
- Visual playbook builder (drag-and-drop workflow)
- Pre-built playbook templates (block IP, disable user, notify team, create ticket)
- Playbook execution history
- Automation rules (if severity=critical & type=malware → run playbook)
- Integration marketplace (list of available response actions)

**Why CLIF needs it:** Automation is the defining trend in SOC. MTTR is the key metric. Without automated response, CLIF is a "detect-only" tool.

#### C. Compliance Dashboard Page (🟡 MEDIUM PRIORITY)
**Who has it:** Wazuh, Exabeam, QRadar, Sentinel

**What it should include:**
- Framework selector (PCI-DSS, HIPAA, SOX, ISO 27001, NIST CSF, IT Act 2000 / CERT-In guidelines for Indian context)
- Compliance score percentage per framework
- Control mapping (which CLIF detections map to which compliance controls)
- Gap visualization (which controls have no coverage)

**Why CLIF needs it:** Given SIH1733 is for the Indian government, compliance with IT Act 2000, CERT-In, and Indian data protection laws is highly relevant.

#### D. AI Assistant Chat (🟡 MEDIUM PRIORITY)
**Who has it:** Elastic AI Assistant, Sentinel Copilot, Chronicle Gemini, CrowdStrike Charlotte AI, Exabeam Nova

**What it should include:**
- Chat panel accessible from any page
- Natural language queries: "Show me all failed login attempts for admin users in the last 24 hours"
- AI-generated summaries: "Summarize investigation INV-2024-001"
- Detection rule generation: "Create a rule to detect brute force attacks"
- Response recommendations: "What should I do about this alert?"

**Why CLIF needs it:** CLIF already has AI agents — exposing them through a chat interface would be low-effort but high-impact.

#### E. Hunting Page (🟢 LOW PRIORITY)
**Who has it:** Sentinel (Hunting), Splunk ES (Investigations), Elastic (Timeline)

**What it should include:**
- Pre-built hunting queries organized by MITRE tactic
- Hypothesis-driven hunting workflows
- Bookmarking results for later
- Convert hunting query to detection rule

---

## Critical Missing Features

### Tier 1 — Must Have (All major competitors have these)

| # | Feature | Competitors with it | Effort | Impact |
|---|---------|-------------------|--------|--------|
| 1 | **Entity Risk Scoring** | Splunk, Elastic, Sentinel, Chronicle, Exabeam, XSIAM | Medium | Very High |
| 2 | **Alert-to-Incident Correlation** | Sentinel, Elastic, CrowdStrike, XSIAM, Chronicle | Medium | Very High |
| 3 | **MITRE ATT&CK Coverage Heatmap** | Sentinel, Elastic | Low | High |
| 4 | **Saved Searches / Query Library** | All | Low | High |
| 5 | **Alert Assignment (Owner)** | Sentinel, Splunk, Elastic, CrowdStrike | Low | High |
| 6 | **Investigation Timeline** | Sentinel, Elastic, Exabeam, CrowdStrike | Medium | High |
| 7 | **Global Time Range Picker** | All | Low | High |
| 8 | **RBAC (Roles & Permissions)** | All | Medium | High |

### Tier 2 — Should Have (Most competitors have these)

| # | Feature | Competitors with it | Effort | Impact |
|---|---------|-------------------|--------|--------|
| 9 | **SOAR / Playbooks (basic)** | Sentinel, Chronicle, CrowdStrike, XSIAM, Exabeam | High | Very High |
| 10 | **AI Chat Assistant** | Elastic, Sentinel, Chronicle, CrowdStrike, Exabeam | Medium | High |
| 11 | **UEBA Page** | Splunk, Elastic, Sentinel, Exabeam, Chronicle | High | Very High |
| 12 | **Threat Intel Feed Management** | Sentinel, Chronicle, Splunk | Medium | Medium |
| 13 | **Entity Profile Pages (360° view)** | Sentinel, Splunk, Chronicle | Medium | High |
| 14 | **Scheduled Reports** | Splunk, QRadar, Elastic, Exabeam | Low | Medium |
| 15 | **Compliance Mapping** | Wazuh, Exabeam, QRadar | Medium | Medium |

### Tier 3 — Nice to Have (Some competitors have these)

| # | Feature | Competitors with it | Effort | Impact |
|---|---------|-------------------|--------|--------|
| 16 | **IOC Retro-hunting** | Chronicle, Elastic | Medium | Medium |
| 17 | **Custom Dashboards** | Splunk, Elastic, Sentinel | High | Medium |
| 18 | **Network Flow Analysis** | Splunk, QRadar, Exabeam | High | Low |
| 19 | **Jupyter Notebooks** | Sentinel | Medium | Low |
| 20 | **Geolocation Map** | Splunk, QRadar, Wazuh | Low | Low |

---

## CLIF Unique Strengths

These are features where CLIF leads or is unique among all competitors:

| # | Feature | Uniqueness | SIH Value |
|---|---------|-----------|-----------|
| 1 | **Evidence Chain of Custody + Merkle Tree Verification** | ✅ Completely unique — zero competitors have this | 🔴 Very High — forensic evidence integrity for law enforcement |
| 2 | **Semantic AI Search** | ⚠️ Rare — only Elastic/Chronicle/CrowdStrike (all paid enterprise) | 🔴 Very High — natural language log search is cutting edge |
| 3 | **Transparent AI Pipeline (4 Agents)** | ✅ Unique — no competitor exposes their ML pipeline | 🟡 High — shows technical depth for hackathon judges |
| 4 | **Model Leaderboard** | ✅ Unique — no competitor has ML model comparison dashboards | 🟡 High — innovative approach |
| 5 | **Multi-Investigation Combined Attack Graph** | ✅ Unique — Sentinel has a single-incident graph, CLIF merges multiple | 🟡 High — advanced correlation visualization |
| 6 | **Open-Source Architecture (ClickHouse + Redpanda + Docker)** | ⚠️ Rare — only Wazuh is open-source. Comparable scale to enterprise tools | 🔴 Very High — cost-effective for government deployment |
| 7 | **Live Classification Tab** | ✅ Unique — real-time ML classification view | 🟡 Medium — demonstrates ML pipeline in action |
| 8 | **ReactFlow Attack Graphs** | ⚠️ Rare — only Sentinel has comparable visual investigation | 🟡 High — interactive and well-implemented |

---

## Priority Recommendations

### Quick Wins (Low Effort, High Impact) — Do First
1. **Global Time Range Picker** — Add to top-bar, propagate to all pages
2. **Alert Assignment / Owner Field** — Add dropdown to alert rows
3. **MITRE ATT&CK Heatmap** — Add to threat-intel or dashboard page
4. **Saved Searches** — Add save/load buttons to search page
5. **KPI Trend Sparklines** — Add 7-day trend lines to dashboard cards
6. **MITRE Tactic Tags on Alerts** — Show tactic/technique badges on alert rows

### Medium Effort, High Impact — Do Next
7. **Entity Risk Scoring** — Calculate cumulative risk per user/host, show on dashboard
8. **Alert-to-Incident Correlation** — Group related alerts into incidents
9. **Investigation Timeline** — Add chronological event timeline to investigation detail
10. **Entity Profile (360° View)** — Click any user/IP/host to see all related activity
11. **AI Chat Interface** — Wrap existing AI agents in a chat UI accessible from any page

### High Effort, Very High Impact — Plan These
12. **UEBA Page** — Full user/entity behavior analytics with baselines and anomaly detection
13. **SOAR / Playbooks** — Visual playbook builder with pre-built automation templates
14. **Compliance Dashboard** — Map detections to regulatory frameworks (especially Indian IT Act, CERT-In)

---

## Features to Remove/De-prioritize

Based on competitor analysis, the following CLIF features are fine as-is and don't need enhancement:

| Feature | Status | Reasoning |
|---------|--------|-----------|
| Live Feed Page | ✅ Keep as-is | Unique as a dedicated page; competitors embed this in search |
| System Health Page | ✅ Keep as-is | Well-implemented; competitors have similar scope |
| Settings Page | ✅ Keep as-is (add RBAC later) | Comprehensive for current stage |
| Evidence Page | ✅ Keep and highlight | This is CLIF's strongest differentiator |
| Reports Page | ✅ Keep as-is | Add compliance templates later |

**Nothing should be removed.** All current pages serve distinct purposes. The focus should be on **adding missing features** and **deepening existing pages**.

---

## Summary Scorecard: CLIF vs Top 3 Competitors

| Category | CLIF | Splunk ES | Elastic Security | Microsoft Sentinel |
|----------|------|-----------|------------------|--------------------|
| Alert Management | 7/10 | 9/10 | 9/10 | 10/10 |
| Investigation Tools | 8/10 | 8/10 | 9/10 | 10/10 |
| AI/ML Capabilities | 8/10 | 6/10 | 8/10 | 7/10 |
| Threat Intelligence | 5/10 | 9/10 | 8/10 | 9/10 |
| SOAR/Automation | 0/10 | 9/10 | 3/10 | 10/10 |
| UEBA/Risk Scoring | 0/10 | 8/10 | 8/10 | 9/10 |
| Evidence/Forensics | 10/10 | 2/10 | 2/10 | 3/10 |
| Compliance | 0/10 | 4/10 | 3/10 | 7/10 |
| Search Capabilities | 8/10 | 10/10 | 9/10 | 8/10 |
| Visualization | 8/10 | 8/10 | 8/10 | 9/10 |
| **Overall** | **5.4/10** | **7.3/10** | **6.7/10** | **8.2/10** |

### Key Takeaway for SIH1733

CLIF's unique strengths (Evidence Chain of Custody, Semantic AI Search, Transparent ML Pipeline, Multi-Investigation Attack Graphs) are genuinely innovative features that enterprise competitors lack. However, the absence of table-stakes features (Risk Scoring, SOAR, UEBA, Alert Correlation, Case Management) creates a perception gap.

**Recommended Strategy:** 
1. **Lead with differentiators** — Evidence integrity, AI pipeline transparency, attack graphs
2. **Close the top 6 gaps** — Time picker, MITRE heatmap, alert assignment, saved searches, entity risk scoring, alert-to-incident correlation
3. **Add showcase features** — AI Chat interface (leveraging existing agents), compliance dashboard (Indian regulations)

This positions CLIF as an **AI-native, forensics-first SIEM** — a unique market position that no current competitor occupies.
