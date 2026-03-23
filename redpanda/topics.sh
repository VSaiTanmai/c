#!/usr/bin/env bash
# =============================================================================
# CLIF — Redpanda Topic Creation Script
# =============================================================================
# Usage:  ./topics.sh [broker_address]
# Default broker: localhost:19092 (external listener)
# =============================================================================
set -euo pipefail

BROKER="${1:-localhost:19092}"
PARTITIONS="${REDPANDA_PARTITIONS:-12}"
RF="${REDPANDA_REPLICATION_FACTOR:-3}"
RETENTION="${REDPANDA_LOG_RETENTION_MS:-604800000}"  # 7 days

# ── High-throughput ingestion topics (12 partitions for max parallelism) ──
INGESTION_TOPICS=(
  "raw-logs"
  "security-events"
  "process-events"
  "network-events"
)

# ── AI agent pipeline topics ─────────────────────────────────────────────
# Triage Agent: template mining → ML inference → scoring → routing
# Hunter Agent: deep investigation of escalated anomalies
# Verifier Agent: forensic verification of hunter findings
TRIAGE_TOPICS=(
  "templated-logs"         # Drain3 output → ML inference input
  "triage-scores"          # All scored events (monitor + escalate)
  "anomaly-alerts"         # Escalated events → Hunter Agent
)
AGENT_TOPICS=(
  "hunter-tasks"           # Anomaly-alerts → Hunter Agent work queue
  "hunter-results"         # Hunter findings → Verifier / Dashboard
  "verifier-tasks"         # Hunter results → Verifier Agent work queue
  "verifier-results"       # Verified findings → Dashboard / SOAR
)
OPERATIONAL_TOPICS=(
  "feedback-labels"        # Analyst feedback → model retraining
  "dead-letter"            # Failed events from any pipeline stage
  "pipeline-commands"      # Control plane: pause/resume/retrain signals
)

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  CLIF — Creating Redpanda Topics                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo "  Broker     : ${BROKER}"
echo "  Partitions : ${PARTITIONS}"
echo "  Replicas   : ${RF}"
echo "  Retention  : ${RETENTION} ms ($(( RETENTION / 86400000 )) days)"
echo ""

# ── Create ingestion topics (12 partitions, max throughput) ──
echo "  ── Ingestion Topics (${PARTITIONS} partitions) ──"
for TOPIC in "${INGESTION_TOPICS[@]}"; do
  echo -n "  Creating ${TOPIC} ... "
  rpk topic create "${TOPIC}" \
    --brokers "${BROKER}" \
    --partitions "${PARTITIONS}" \
    --replicas "${RF}" \
    --topic-config retention.ms="${RETENTION}" \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760 \
    2>/dev/null && echo "✔" || echo "already exists ✔"
done

# ── Create triage pipeline topics (12 partitions — must keep pace with ingestion) ──
echo ""
echo "  ── Triage Agent Topics (${PARTITIONS} partitions) ──"
for TOPIC in "${TRIAGE_TOPICS[@]}"; do
  echo -n "  Creating ${TOPIC} ... "
  rpk topic create "${TOPIC}" \
    --brokers "${BROKER}" \
    --partitions "${PARTITIONS}" \
    --replicas "${RF}" \
    --topic-config retention.ms="${RETENTION}" \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760 \
    2>/dev/null && echo "✔" || echo "already exists ✔"
done

# ── Create agent topics (6 partitions — lower volume, still parallel) ──
AGENT_PARTITIONS=$(( PARTITIONS / 2 ))
[ "${AGENT_PARTITIONS}" -lt 3 ] && AGENT_PARTITIONS=3
echo ""
echo "  ── Agent Pipeline Topics (${AGENT_PARTITIONS} partitions) ──"
for TOPIC in "${AGENT_TOPICS[@]}"; do
  echo -n "  Creating ${TOPIC} ... "
  rpk topic create "${TOPIC}" \
    --brokers "${BROKER}" \
    --partitions "${AGENT_PARTITIONS}" \
    --replicas "${RF}" \
    --topic-config retention.ms="${RETENTION}" \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760 \
    2>/dev/null && echo "✔" || echo "already exists ✔"
done

# ── Create operational topics (3 partitions — low volume, high importance) ──
echo ""
echo "  ── Operational Topics (3 partitions) ──"
for TOPIC in "${OPERATIONAL_TOPICS[@]}"; do
  echo -n "  Creating ${TOPIC} ... "
  rpk topic create "${TOPIC}" \
    --brokers "${BROKER}" \
    --partitions 3 \
    --replicas "${RF}" \
    --topic-config retention.ms="$((RETENTION * 4))" \
    --topic-config cleanup.policy=delete \
    --topic-config compression.type=producer \
    --topic-config max.message.bytes=10485760 \
    2>/dev/null && echo "✔" || echo "already exists ✔"
done

echo ""
echo "  Current topic list:"
rpk topic list --brokers "${BROKER}"
echo ""
echo "  Done. ($(( ${#INGESTION_TOPICS[@]} + ${#TRIAGE_TOPICS[@]} + ${#AGENT_TOPICS[@]} + ${#OPERATIONAL_TOPICS[@]} )) topics created)"
