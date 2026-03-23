# CLIF SOC Dashboard

Enterprise Security Operations Center dashboard for the CLIF (Cognitive Log Investigation Framework) prototype.

## Tech Stack

- **Next.js 14** (App Router)
- **TypeScript**
- **Tailwind CSS** — dark zinc/slate theme
- **shadcn/ui** — button, card, badge, input, tabs, skeleton, scroll-area, tooltip, separator
- **Recharts** — area charts, bar charts
- **@xyflow/react** (React Flow v12) — attack graph visualization
- **lucide-react** — icons

## Getting Started

```bash
npm install
npm run dev
```

Runs on **http://localhost:3001** (port 3000 is typically Grafana).

## Architecture

### API Routes (Real-time)

| Route | Source | Description |
|-------|--------|-------------|
| `/api/metrics` | ClickHouse HTTP | Event counts, severity distributions, ingestion rates |
| `/api/events/stream` | ClickHouse HTTP | Latest 100 raw_logs for live feed polling |
| `/api/alerts` | ClickHouse HTTP | Security events with severity ≥ 3 |
| `/api/system` | Prometheus + Direct HTTP | Service health from `up` metric + ClickHouse `/ping` |

### Mock Data (Demo)

Investigations, AI agents, threat intel IOCs, evidence chain, and reports use mock JSON files under `src/lib/mock/` for demo purposes. These will be replaced with real backend integrations.

### Key Libraries

- `src/lib/clickhouse.ts` — ClickHouse HTTP client (POST queries, JSON format)
- `src/lib/prometheus.ts` — Prometheus query wrapper
- `src/lib/redpanda.ts` — Redpanda Admin API client
- `src/hooks/use-polling.ts` — Generic polling hook with configurable interval

## Pages

12 pages across 5 sections: Monitor, Investigate, Intelligence, Evidence, System.

See the main [README](../README.md) for the full page reference table.

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
