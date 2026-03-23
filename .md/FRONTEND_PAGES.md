# CLIF Dashboard — Frontend Pages & Features

> **Stack:** Next.js 14 (App Router) · React 18 · TypeScript · Tailwind CSS · shadcn/ui · Recharts · ReactFlow  
> **Theme:** Dark mode (HSL-based), Inter font family  
> **Port:** `localhost:3000`

---

## Global Layout

| Element | Details |
|---------|---------|
| **Sidebar** | Collapsible left panel with CLIF branding. 5 navigation sections, 12 items. Tooltip labels in collapsed mode. Icons from `lucide-react`. |
| **Top Bar** | Sticky header with global search (`⌘K` shortcut), notification bell (live unread count badge), and user avatar (Nethra / SOC Lead). |
| **Notification Panel** | Dropdown from bell icon — **no hard cap**, fetches all severity ≥ 3 alerts. Severity filter tabs (All / Critical / High), mark-all-read button, read/unread visual state (blue left border + bold for unread), paginated "Show more (N remaining)" link. 420 px wide. |
| **Error Boundary** | Global error boundary wrapping page content with fallback UI. |
| **Toast System** | `sonner` toast notifications for actions throughout the app. |
| **Keyboard Shortcuts** | Global keyboard shortcut system: `?` opens help dialog, `g <key>` vim-style navigation (g d = Dashboard, g a = Alerts, etc.), `/` focuses search input. Rendered via `KeyboardShortcutsProvider` in layout. |
| **Confirmation Dialog** | Reusable Radix-based component for destructive actions — type-to-confirm (e.g. type "TRUNCATE"), destructive styling, loading state. |

### Sidebar Navigation Structure

| Section | Pages |
|---------|-------|
| **MONITOR** | Dashboard · Live Feed · Alerts |
| **INVESTIGATE** | Search · Investigations · Attack Graph |
| **INTELLIGENCE** | Threat Intel · AI Agents |
| **EVIDENCE** | Chain of Custody · Reports |
| **SYSTEM** | System Health · Settings |

---

## 1. Dashboard (`/dashboard`)

**Purpose:** Real-time security operations overview — the main landing page.  
**Data Source:** `GET /api/metrics` (polled every 5 seconds)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Total Events** | KPI Card | All-time ingested event count with Database icon |
| **Ingestion Rate** | KPI Card | Current throughput in events/second with TrendingUp icon |
| **Active Alerts** | KPI Card | Alert count in past 24h; text turns red when > 0 |
| **Uptime** | KPI Card | Pipeline availability percentage |
| **Events / Minute** | Area Chart (Recharts) | Blue gradient area chart, 2-column span. Shows last 30 min of per-minute event counts. Custom tooltip showing exact event count. X-axis: time, Y-axis: count. Dark grid lines. |
| **Security Severity** | Bar Chart (Recharts) | Color-coded bars (grey/green/blue/amber/red for severity 0–4). 24h distribution. Custom tooltip. |
| **Event Distribution by Table** | Progress Bars | Horizontal bars for raw_logs (blue), security_events (red), process_events (amber), network_events (emerald). Shows count and percentage. |
| **Merkle Evidence Chain** | Status Card | Anchor Batches count, Events Anchored count, Chain Integrity badge (Verified/No Data) with emerald accent border. |
| **Top Sources** | Ranked List | Top log sources with horizontal progress bars relative to #1 source. Numbered 1–N. Monospace font for source names. |
| **Severity Breakdown** | Badge List | Sorted severity levels (Critical → Info) with colored badges and counts. |
| **MITRE ATT&CK Techniques** | Ranked List | Top observed techniques (last 7 days) with technique ID (monospace), tactic badge, count, and red progress bars. Only shown when data exists. |

---

## 2. Live Feed (`/live-feed`)

**Purpose:** Real-time streaming event viewer from all ingestion sources.  
**Data Source:** `GET /api/events/stream` (polled every 1 second)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Status Indicator** | Badge | Green pulsing dot when live; grey when paused. Shows current events/sec. |
| **High Throughput Warning** | Banner | Amber warning banner when rate exceeds 500 eps — "High throughput — UI may lag" |
| **Received Counter** | Badge | Total events received in session |
| **Pause / Resume** | Toggle Button | Play/Pause icons; pauses stream polling |
| **Auto-scroll** | Toggle Button | Keeps table scrolled to newest events |
| **Table Filter** | Button Group | All Tables · Raw Logs · Security · Process · Network — clears and resets stream on switch |
| **Text Filter** | Input | Filters visible events by raw content, hostname, or log source |
| **Clear** | Button | Resets event buffer and received counter |
| **Event Stream Table** | Scrollable Table | Columns: Timestamp (monospace HH:MM:SS.ms), Table (color-coded mini-badge: red=security, blue=process, **cyan=network**, grey=raw), Severity (colored badge), Source, Host, Raw (truncated). Max 2000 events buffered, 500 rendered (amber note when capped). Deduplication by `event_id`. |

---

## 3. Alerts (`/alerts`)

**Purpose:** Security alert queue with workflow state management.  
**Data Source:** `GET /api/alerts` (polled every 5 seconds)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Total Count** | Badge | Total alert count in header |
| **Severity Summary** | KPI Cards (4) | One card per severity level (Critical → Low), sorted highest first. Shows count with severity-colored icon. |
| **Bulk Actions** | Checkbox + Action Bar | Per-row checkboxes + select-all (CheckSquare/Square/MinusSquare). Bulk action bar: Acknowledge / Investigate / Resolve buttons — each opens a **ConfirmationDialog** before executing. |
| **Quick Filters** | Dropdowns | Hostname dropdown (auto-populated from unique hosts), Source dropdown (from unique sources). Filters combine with status filter. |
| **Workflow Filter** | Button Group | All · New (Bell) · Acknowledged (Eye) · Investigating (AlertTriangle) · Resolved (CheckCircle). Each with icon and **count** — disabled when count is 0. |
| **Alert Queue** | Interactive List | Each alert shows: Checkbox, Severity badge, event type, hostname, workflow state badge (color-coded: blue=New, amber=Acknowledged, **orange=Investigating**, emerald=Resolved), relative timestamp. Click to expand and view raw log content in monospace `<pre>` block. |
| **Error State** | Banner | ShieldAlert icon + error message + "Retrying with backoff" note when API fails. |
| **Empty State** | Contextual | When no alerts exist: shield icon + "All clear" message. When filters hide all results: "No matching alerts" + "Clear all filters" CTA. |

### Workflow State Logic
- Severity 4 → **New**
- Severity 3 → **Investigating**
- Severity 2 → **Acknowledged**
- Severity 0–1 → **Resolved**
- **State overrides:** Bulk actions update workflow state client-side immediately

---

## 4. Search (`/search`)

**Purpose:** Full-text and AI-powered semantic search across all ClickHouse tables.  
**Data Sources:** `GET /api/events/search` (keyword) · `GET /api/semantic-search` (AI/vector)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Search Input** | Text Input | Placeholder: *"Search events — e.g. lateral movement, C102, mimikatz"*. Has `data-search-input` for `/` keyboard shortcut focus. |
| **AI Search Toggle** | Button | Purple gradient when active; switches between ClickHouse keyword search and LanceDB vector/semantic search |
| **Table Selector** | Button Group | Raw Logs · Security Events · Process Events · Network Events |
| **Time Range** | Button Group | 5 min · 15 min · 1 hour · 6 hours · 24 hours · 7 days |
| **Min Severity** | Dropdown | Any · Low (1+) · Medium (2+) · High (3+) · Critical (4) |
| **Share Link** | Button | Copies current search URL (with all filters encoded) to clipboard |
| **Export CSV** | Button | Downloads results as CSV with auto-generated filename |
| **Results Table** | Paginated Table | Columns: Timestamp, Severity (colored badge), Source, Host, Content (truncated monospace). Extra **Similarity** column in AI mode (percentage badge: green ≥70%, amber 40–70%, grey <40%). |
| **Pagination** | Prev/Next | 50 results per page with page counter |
| **Error Display** | Card | Red-bordered card with error details when search fails |

### Features
- Auto-loads results on page mount
- AI mode: Semantic vector search via LanceDB (384-dim embeddings)
- Keyword mode: Full-text search via ClickHouse with time/table/severity filters
- **URL state persistence:** All filters (`q`, `table`, `range`, `severity`, `ai`) are synced to URL search params — searches are shareable via link

---

## 5. Investigations (`/investigations`)

**Purpose:** Case management — active and historical investigation files.  
**Data Source:** Local mock data (`lib/mock/investigations.json`)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **New Investigation** | Button | Opens investigation wizard (placeholder for LangGraph agent) |
| **Search** | Input | Filters by title, ID, or tags |
| **Status Filter** | Button Group | All · Open · In Progress · Closed (with count) |
| **Case List** | Card List | Each case card shows: Severity badge (colored), Case ID (monospace), Status badge (blue=Open, amber=In Progress, emerald=Closed), Title, Description (2-line clamp), Tags (with Tag icon), Assignee (User icon), Last updated (relative time), Event count, Chevron arrow for navigation. Entire card is clickable → links to detail page. |

---

## 6. Investigation Detail (`/investigations/[id]`)

**Purpose:** Single investigation deep-dive with AI agent timeline.  
**Data Source:** Local mock data (matched by dynamic `[id]` parameter)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Back Link** | Navigation | "Back to Investigations" with ArrowLeft icon |
| **Header** | Title Area | Severity badge, Case ID (monospace), Status badge, Title. Buttons: Export (PDF) and Contain (host isolation). |
| **Meta Cards** (4) | KPI Cards | Assignee, Last Updated (relative), Event count, Affected Hosts |
| **Description** | Card (2-col span) | Full case description, MITRE ATT&CK TTPs (tag badges with Tag icon), Affected Users (monospace badges), Affected Hosts (monospace badges with Network icon) |
| **AI Investigation Timeline** | Vertical Timeline | Chronological list with connected dots and vertical line. Each entry: timestamp (monospace), action description (e.g. "Triage Agent classified as lateral movement (confidence: 0.96)"). Shows agent actions: Triage → Hunter → Escalation → Verifier → Reporter. |

---

## 7. Attack Graph (`/attack-graph`)

**Purpose:** Interactive visual attack path analysis using graph visualization.  
**Data Source:** Static mock data (built-in node/edge definitions)  
**Library:** ReactFlow (`@xyflow/react`)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Graph Canvas** | ReactFlow | Full-height interactive graph with dark background (`hsl(0 0% 3.9%)`). Nodes are draggable, edges have animated dashes for active paths. |
| **Node Types** | Styled Nodes | **Users** (circular, indigo border): U4521@DOM2, U3102@DOM3, U8921@DOM1. **Hosts** (rounded rect, amber border): C102, C4501, C892, C1923, C3847. **Critical Targets** (rounded rect, red border): DC01, malware-c2.darkops.cc. |
| **Edge Labels** | Labeled Edges | "Kerberos Auth", "Interactive", "NTLM/Network", "Kerberos/TGS" (red, thick), "DNS Tunnel 2400+ queries" (red, animated), "Session", "Execution". |
| **Attack Chains** | 3 Investigations | **INV-2026-001**: U4521→C102→C4501→C892→DC01 (lateral movement). **INV-2026-003**: U3102→C1923→malware-c2.darkops.cc (DNS tunneling). **INV-2026-002**: U8921→C3847 (PowerShell chain: svchost→cmd→ps). |
| **Legend Panel** | Overlay (top-left) | Color legend: Indigo = User/Identity, Amber = Compromised Host, Red = Critical Target/C2. Animated edge = Active path. |
| **Investigation Tags** | Overlay (top-right) | Active investigation badges: INV-2026-001 (Critical), INV-2026-003 (Critical), INV-2026-002 (High). |
| **Controls** | Built-in | Zoom controls (bottom-left), MiniMap (bottom-right) with color-coded node colors. |
| **Reset / Fit View** | Buttons | Reset layout to initial positions; Fit View to auto-frame all nodes. |
| **Node Details** | Card (below graph) | Appears on node click — shows Node ID, Label, and connection (edge) count. |

---

## 8. Threat Intelligence (`/threat-intel`)

**Purpose:** IOC feeds, threat patterns, live MITRE ATT&CK detections.  
**Data Sources:** `GET /api/threat-intel` (live, polled every 30s) + local mock data (`lib/mock/threat-intel.json`)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Add IOC Feed** | Button | Placeholder for MISP/AlienVault OTX integration |
| **Live MITRE ATT&CK Detections** | Card Grid (4-col) | Live 24h technique detections from ClickHouse. Each shows: MITRE technique badge (color-coded by severity), tactic label, count. Total count in header badge. Primary-colored border. |
| **Active Threat Indicators** | Card Grid (3-col) | Live IOC matches from past 24h. Server icon + monospace hostname + hit count (red if severity ≥3, amber otherwise). Amber-bordered card. |
| **Threat Patterns** | Card Grid (5-col) | Each card: MITRE code badge, hit count, pattern name, description (2-line clamp), IOC count. 5 cards across. |
| **IOC Table** | Filterable Table | Columns: Type (icon + label: IPv4/Domain/SHA256/URL), Value (monospace, truncated at 50 chars), Source, Confidence (% with green/amber/red color), MITRE ID (badge), Hits (amber if > 0), Tags (mini badges), Last Seen (relative time). Filters: text search + type filter (All/IPv4/Domain/SHA256/URL). |

---

## 9. AI Agents (`/ai-agents`)

**Purpose:** Autonomous AI investigation agent management and activity monitoring.  
**Data Source:** Local mock data (`lib/mock/agents.json`)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Pending Approvals** | Alert Cards | Amber-bordered section for agent actions requiring human authorization. Each shows: approval ID, investigation badge, action description, reason, requesting agent, timestamp. Deny (outline) and Approve (amber) buttons. |
| **Agent Grid** | Card Grid (3-col) | 5 Agent types with dedicated icons: **Triage** (Eye), **Hunter** (Activity), **Verifier** (ShieldCheck), **Escalation** (AlertTriangle), **Reporter** (CheckCircle). Each card shows: Agent name + description, Status badge (emerald=Active, blue=Processing, grey=Idle with Zap/Cpu/Clock icons), 3 metrics (Cases processed, Accuracy %, Avg Response Time), Last Action description + timestamp. |
| **Agent Activity Feed** | Vertical Timeline | Scrollable feed with connected dots and vertical line. Each entry: Agent badge, relative timestamp, action description. |

### Agent Roster
1. **Triage Agent** — Initial event classification
2. **Hunter Agent** — Threat hunting and correlation
3. **Verifier Agent** — False positive verification
4. **Escalation Agent** — Severity and priority management
5. **Reporter Agent** — Report generation

---

## 10. Chain of Custody / Evidence (`/evidence`)

**Purpose:** Merkle tree evidence integrity verification with S3 archival.  
**Data Source:** `GET /api/evidence/chain` (polled every 15s) · `GET /api/evidence/verify` (on-demand)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Summary KPIs** (5) | KPI Cards | Total Anchored (events), Total Batches, Verification Rate (% in emerald), Avg Batch Size, Chain Length (blocks). |
| **Integrity Status** | Banner Card | Emerald-bordered card with shield icon. Shows "All Evidence Verified — Integrity Intact" or partial verification %. Displays batch count, event count, last anchor time. "Re-verify All" button. |
| **Anchor Batch History** | Data Table | Columns: Batch ID (monospace), Table (color-coded badge: blue=raw_logs, red=security, amber=process, emerald=network), Events (count), Merkle Root (truncated SHA-256 hash with copy-to-clipboard button), Depth, S3 Archive (key link), Status (PASS badge green / FAIL badge red / Verified badge), Verify button (per-batch, shows spinner during verification). |

### Features
- **Per-batch verification:** Recomputes Merkle root from ClickHouse data and compares to stored hash
- **Batch verification results:** Toast notification with PASS/FAIL, event count, depth, and root hash comparison
- **Bulk re-verify:** Sequentially verifies all batches with progress toast
- **S3 Object Lock:** Archive keys linked in table

---

## 11. Reports (`/reports`)

**Purpose:** AI-generated investigation reports and compliance documentation.  
**Data Source:** Local mock data (`lib/mock/reports.json`)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Generate Report** | Button | Placeholder for Quarto rendering engine (Week 12 milestone) |
| **Report Templates** | Card Grid (5-col) | 5 clickable template cards, each with icon + name + description. Templates: Incident Report (FileWarning), Executive Brief (Briefcase), Technical Analysis (Code), Compliance Audit (Shield), Threat Assessment (Radar). |
| **Report History** | Data Table | Columns: ID (monospace), Title, Template (badge), Created (relative time with Clock icon), Pages, Size, Status (green "Ready" badge), Download button. |

---

## 12. System Health (`/system`)

**Purpose:** Live infrastructure monitoring of all CLIF backend services.  
**Data Source:** `GET /api/system` (polled every 10 seconds)

### Visual Components

| Component | Type | Description |
|-----------|------|-------------|
| **Refresh** | Button | Manual data refresh |
| **Status Summary** (4) | KPI Cards | Total Services (Server icon), Healthy count (emerald), Down count (red), Redpanda Brokers |
| **ClickHouse** | Detail Card | Total Rows Inserted, Cluster Mode (2-Node ReplicatedMergeTree), S3 Tiering (Active/MinIO), Tables list. |
| **Redpanda Cluster** | Detail Card | Broker count, Partition count, Topics list, Controller Node ID. Health badge (green/red). Per-broker details: broker-N, core count, Active/Down badge. |
| **Service Status** | Service List | Each service: icon (Database=ClickHouse, Radio=Redpanda, Cpu=Consumer, Activity=Prometheus/Grafana, HardDrive=MinIO, Server=Node), label, scrape metric (monospace), health badge (green Healthy / red Down). Grouped by category. |

### Service Categories
- **Storage:** ClickHouse, MinIO
- **Streaming:** Redpanda
- **Pipeline:** CLIF Consumer
- **Monitoring:** Prometheus, Grafana
- **Infrastructure:** Node Exporter

---

## 13. Settings (`/settings`)

**Purpose:** Platform configuration, user management, integrations, and danger zone.  
**Data Source:** `GET /api/system` (for data source connectivity probe)

### Visual Components — Left Column (2/3 width)

| Component | Type | Description |
|-----------|------|-------------|
| **General** | Form Card | Inputs: Organization Name, Timezone, Log Retention (days), Max Events Per Query. Save Changes button. |
| **Data Sources** | Status List | ClickHouse, Redpanda, Prometheus, MinIO — each with host addresses (monospace) and live connectivity badge (Connected green / Unreachable red / Checking blue). Auto-probed on page load. |
| **Notifications** | Toggle List | 4 toggles: Critical alerts (on), Agent approvals (on), System health (on), Daily digest (off). Each with description. Visual toggle switches. |
| **Integrations** | Status List | MISP (Connected), AlienVault OTX (Connected), VirusTotal (API Key Set), LanceDB (Connected), Ethereum Anchor (Pending). Each with description and status badge. |

### Visual Components — Right Column (1/3 width)

| Component | Type | Description |
|-----------|------|-------------|
| **Users** | User List | Each user: avatar initials (primary circle), name, email, role badge (color-coded: primary=SOC Lead, amber=Senior Analyst, blue=Analyst, purple=Admin, grey=Viewer), last login time. "Add" button (placeholder). |
| **API Keys** | Key Card | Production Key and Development Key with masked display (`clif_pk_••••••••••••4f8a`). Active status badges. "Generate New Key" button. |
| **Danger Zone** | Destructive Card | Red-bordered section with: "Truncate All Tables" button → opens **ConfirmationDialog** requiring user to type "TRUNCATE" to proceed. "Reset Pipeline State" button → requires typing "RESET". Both show success toasts on confirmation. GitHub-style destructive confirmation pattern. |

---

## UI Component Library

All pages use a shared component library (`src/components/ui/`) built on **shadcn/ui**:

| Component | Usage |
|-----------|-------|
| `Card`, `CardHeader`, `CardTitle`, `CardContent` | Every page uses card-based layout |
| `Badge` | Severity levels (critical/high/medium/low/info variants), status indicators |
| `Button` | Actions, filters, toggles — variants: default, secondary, outline, ghost, destructive |
| `Input` | Search bars, form fields |
| `Skeleton` | Loading placeholders (pulse animation) |
| `Separator` | Visual dividers between sections |

### Color Conventions

| Color | Meaning |
|-------|---------|
| 🔴 `#ef4444` / `text-red-*` | Critical severity, down services, destructive actions |
| 🟠 `#f59e0b` / `text-amber-*` | High severity, warnings, pending actions |
| 🔵 `#3b82f6` / `text-blue-*` | Medium severity, informational, process events |
| 🟢 `#22c55e` / `text-emerald-*` | Low severity, healthy status, verified, pass |
| ⚪ `#64748b` / `text-zinc-*` | Info severity, idle, inactive |
| 🟣 `#8b5cf6` / `text-purple-*` | AI/semantic features only |
| 🟠 `#f97316` / `text-orange-*` | Investigating workflow state |
| 🩵 `#06b6d4` / `text-cyan-*` | Network events (table badge) |
| 🔷 Primary (HSL 217) | Branding, active navigation, primary actions |

### Data Polling Pattern

All live pages use a custom `usePolling` hook:

| Page | Endpoint | Interval |
|------|----------|----------|
| Dashboard | `/api/metrics` | 5s |
| Live Feed | `/api/events/stream` | 1s |
| Alerts | `/api/alerts` | 5s |
| Evidence | `/api/evidence/chain` | 15s |
| System | `/api/system` | 10s |
| Top Bar | `/api/metrics` + `/api/alerts` | 30s |
| Threat Intel | `/api/threat-intel` | 30s |

---

## API Routes (11 endpoints)

| Route | Method | Description |
|-------|--------|-------------|
| `/api/metrics` | GET | Dashboard KPIs, timeline, severity distribution, MITRE techniques, table counts |
| `/api/system` | GET | Service health from Prometheus, ClickHouse stats, Redpanda cluster info |
| `/api/alerts` | GET | Severity summary + recent high-severity alert list (24h) |
| `/api/events/search` | GET | Full-text keyword search across ClickHouse tables with pagination |
| `/api/events/stream` | GET | Latest events for live feed (per-table filtering) |
| `/api/semantic-search` | GET | AI vector search via LanceDB (384-dim embeddings) |
| `/api/similar-events` | GET | Find similar events by vector proximity |
| `/api/lancedb` | GET | LanceDB service health check |
| `/api/evidence/chain` | GET | Merkle evidence batch list + summary from ClickHouse |
| `/api/evidence/verify` | GET | On-demand Merkle root recomputation and verification |
| `/api/threat-intel` | GET | Live MITRE ATT&CK stats + top IOC matches from ClickHouse |

---

## New Components & Hooks (Post-Review)

| File | Type | Description |
|------|------|-------------|
| `components/ui/confirmation-dialog.tsx` | Component | GitHub/Vercel-style destructive confirmation dialog. Radix Dialog primitive, type-to-confirm input, destructive/default variants, loading state, auto-focus. Used by Settings danger zone and Alerts bulk actions. |
| `components/keyboard-shortcuts-dialog.tsx` | Component | Grouped shortcut reference panel. Formats keys with `<kbd>` badges, supports modifier combos and vim-style sequences with "then" separator. |
| `components/keyboard-shortcuts-provider.tsx` | Provider | Client component wired into layout. Defines all navigation shortcuts (`g d`, `g a`, etc.), `?` for help, `/` for search focus. Uses `useRouter` for navigation. |
| `hooks/use-keyboard-shortcuts.ts` | Hook | Global keyboard shortcut manager. Supports single keys (`?`), modifier combos (`ctrl+k`), and vim-style sequences (`g d` within 800ms). Ignores input/textarea/select/contentEditable elements. |

### Keyboard Shortcut Reference

| Shortcut | Action |
|----------|--------|
| `?` | Show keyboard shortcuts panel |
| `/` | Focus search input (when available) |
| `g d` | Go to Dashboard |
| `g l` | Go to Live Feed |
| `g a` | Go to Alerts |
| `g s` | Go to Search |
| `g i` | Go to Investigations |
| `g n` | Go to Attack Graph |
| `g t` | Go to Threat Intel |
| `g m` | Go to AI Agents |
| `g e` | Go to Evidence |
| `g r` | Go to Reports |
| `g h` | Go to System Health |
| `g x` | Go to Settings |
