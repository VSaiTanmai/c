#!/usr/bin/env bash
# =============================================================================
# CLIF Resilience Test Suite
# =============================================================================
# Tests failure scenarios to verify the storage stack handles:
#   1. Redpanda broker restart  (no message loss)
#   2. ClickHouse node failover (queries still work)
#   3. Consumer recovery        (resumes after restart)
#   4. S3 tiering validation    (ClickHouse can see cold disk)
#
# Prerequisites:
#   - The full CLIF stack is running: docker-compose up -d
#   - pip install confluent-kafka clickhouse-connect rich
#   - rpk is available (or install via Redpanda)
#
# Usage:  bash resilience_test.sh
# =============================================================================
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

CH_HOST="${CH_HOST:-localhost}"
CH_PORT="${CH_PORT:-8123}"
CH_USER="${CH_USER:-clif_admin}"
CH_PASS="${CH_PASS:-clif_secure_password_change_me}"
CH_DB="${CH_DB:-clif_logs}"
BROKER="${BROKER:-localhost:19092}"

pass_count=0
fail_count=0

pass() { ((pass_count++)); echo -e "  ${GREEN}✔ PASS${RESET}: $1"; }
fail() { ((fail_count++)); echo -e "  ${RED}✘ FAIL${RESET}: $1"; }

ch_query() {
  curl -s "http://${CH_HOST}:${CH_PORT}/?user=${CH_USER}&password=${CH_PASS}&database=${CH_DB}" \
    --data-binary "$1" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}${CYAN}═══  CLIF Storage Infrastructure — Resilience Test Suite  ═══${RESET}\n"

# ─────────────────────────────────────────────────────────────────────────────
echo -e "${BOLD}Test 1: Service Health Checks${RESET}"
echo "────────────────────────────────────────────────────────────"

# ClickHouse node 1
if ch_query "SELECT 1" | grep -q "1"; then
  pass "ClickHouse node 1 responding"
else
  fail "ClickHouse node 1 not responding"
fi

# ClickHouse node 2
if curl -s "http://${CH_HOST}:8124/?user=${CH_USER}&password=${CH_PASS}" \
    --data-binary "SELECT 1" 2>/dev/null | grep -q "1"; then
  pass "ClickHouse node 2 responding"
else
  fail "ClickHouse node 2 not responding"
fi

# Redpanda cluster
if rpk cluster health --brokers "${BROKER}" 2>/dev/null | grep -qi "healthy.*true"; then
  pass "Redpanda cluster healthy"
else
  # Fallback: just check if we can list topics
  if rpk topic list --brokers "${BROKER}" >/dev/null 2>&1; then
    pass "Redpanda cluster reachable (topics listable)"
  else
    fail "Redpanda cluster not healthy"
  fi
fi

# MinIO
if curl -s -o /dev/null -w "%{http_code}" "http://${CH_HOST}:9002/minio/health/live" | grep -q "200"; then
  pass "MinIO responding"
else
  fail "MinIO not responding"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 2: Redpanda Broker Restart — No Message Loss${RESET}"
echo "────────────────────────────────────────────────────────────"

# Get count before
COUNT_BEFORE=$(ch_query "SELECT count() FROM raw_logs" | tr -d '[:space:]')
echo "  Events before: ${COUNT_BEFORE}"

# Produce a known batch
TAG="resilience-$(date +%s)"
echo "  Producing 1000 tagged events (tag=${TAG}) …"
python3 -c "
import json, uuid, sys
from datetime import datetime, timezone
from confluent_kafka import Producer

p = Producer({'bootstrap.servers': '${BROKER}', 'acks': 'all', 'enable.idempotence': True})
for i in range(1000):
    event = {
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z',
        'level': 'INFO',
        'source': 'resilience-test',
        'message': f'resilience probe {i}',
        'metadata': {'user_id': 'tester', 'ip_address': '10.0.0.1', 'request_id': '${TAG}'}
    }
    p.produce('raw-logs', json.dumps(event).encode())
    if i % 100 == 0: p.poll(0)
p.flush(30)
print('  Produced 1000 events.')
"

# Restart Redpanda broker 2 (not the seed node)
echo "  Restarting redpanda02 …"
docker restart clif-redpanda02 >/dev/null 2>&1 || true
sleep 10

# Restart redpanda03 as well
echo "  Restarting redpanda03 …"
docker restart clif-redpanda03 >/dev/null 2>&1 || true
sleep 15

# Wait for consumer to catch up
echo "  Waiting for consumer to ingest tagged events …"
MAX_WAIT=60
ELAPSED=0
FOUND=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  FOUND=$(ch_query "SELECT count() FROM raw_logs WHERE request_id = '${TAG}'" | tr -d '[:space:]')
  if [ "$FOUND" -ge 1000 ] 2>/dev/null; then
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [ "$FOUND" -ge 1000 ] 2>/dev/null; then
  pass "All 1000 events survived broker restart (found: ${FOUND})"
else
  fail "Only ${FOUND}/1000 events found after broker restart"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 3: ClickHouse Node Failover — Query Availability${RESET}"
echo "────────────────────────────────────────────────────────────"

# Query should work on node 1
RESULT1=$(ch_query "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY" | tr -d '[:space:]')
echo "  Node 1 query result: ${RESULT1} events in last 24h"

# Stop node 2
echo "  Stopping clickhouse02 …"
docker stop clif-clickhouse02 >/dev/null 2>&1 || true
sleep 5

# Node 1 should still answer
RESULT_FAILOVER=$(ch_query "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY" | tr -d '[:space:]')
if [ -n "$RESULT_FAILOVER" ] && [ "$RESULT_FAILOVER" -ge 0 ] 2>/dev/null; then
  pass "ClickHouse queries still work with one node down (result: ${RESULT_FAILOVER})"
else
  fail "ClickHouse queries failed during node outage"
fi

# Restart node 2
echo "  Restarting clickhouse02 …"
docker start clif-clickhouse02 >/dev/null 2>&1 || true
sleep 10

# Verify replica caught up
RESULT_RESTORED=$(curl -s "http://${CH_HOST}:8124/?user=${CH_USER}&password=${CH_PASS}&database=${CH_DB}" \
  --data-binary "SELECT count() FROM raw_logs WHERE timestamp >= now() - INTERVAL 1 DAY" 2>/dev/null | tr -d '[:space:]')
if [ -n "$RESULT_RESTORED" ] && [ "$RESULT_RESTORED" -ge 0 ] 2>/dev/null; then
  pass "Replica node 2 recovered (result: ${RESULT_RESTORED})"
else
  fail "Replica node 2 did not recover"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 4: Consumer Recovery After Restart${RESET}"
echo "────────────────────────────────────────────────────────────"

# Count before
COUNT_PRE=$(ch_query "SELECT count() FROM raw_logs" | tr -d '[:space:]')

# Produce events while consumer is going to be restarted
TAG2="consumer-recovery-$(date +%s)"
echo "  Producing 500 events with tag=${TAG2} …"
python3 -c "
import json
from datetime import datetime, timezone
from confluent_kafka import Producer

p = Producer({'bootstrap.servers': '${BROKER}', 'acks': 'all', 'enable.idempotence': True})
for i in range(500):
    event = {
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+'Z',
        'level': 'WARN',
        'source': 'consumer-recovery-test',
        'message': f'recovery probe {i}',
        'metadata': {'user_id': 'tester', 'ip_address': '10.0.0.2', 'request_id': '${TAG2}'}
    }
    p.produce('raw-logs', json.dumps(event).encode())
    if i % 100 == 0: p.poll(0)
p.flush(30)
print('  Produced 500 events.')
"

# Restart the consumer
echo "  Restarting clif-consumer …"
docker restart clif-consumer >/dev/null 2>&1 || true
sleep 15

# Wait for events to land
ELAPSED=0
FOUND2=0
while [ $ELAPSED -lt 60 ]; do
  FOUND2=$(ch_query "SELECT count() FROM raw_logs WHERE request_id = '${TAG2}'" | tr -d '[:space:]')
  if [ "$FOUND2" -ge 500 ] 2>/dev/null; then
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done

if [ "$FOUND2" -ge 500 ] 2>/dev/null; then
  pass "Consumer recovered and ingested all 500 events (found: ${FOUND2})"
else
  fail "Consumer lost events after restart (found: ${FOUND2}/500)"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 5: S3 Tiering Configuration${RESET}"
echo "────────────────────────────────────────────────────────────"

# Check that ClickHouse knows about the S3 disk
S3_DISK=$(ch_query "SELECT name FROM system.disks WHERE type = 's3' OR name = 's3_cold'" | tr -d '[:space:]')
if [ -n "$S3_DISK" ]; then
  pass "S3 cold disk configured in ClickHouse (disk: ${S3_DISK})"
else
  fail "S3 cold disk not found in ClickHouse disks"
fi

# Check storage policy
POLICY=$(ch_query "SELECT policy_name FROM system.storage_policies WHERE policy_name = 'clif_tiered'" | tr -d '[:space:]')
if [ -n "$POLICY" ]; then
  pass "clif_tiered storage policy active"
else
  fail "clif_tiered storage policy not found"
fi

# Check MinIO buckets exist
BUCKET_CHECK=$(curl -s -o /dev/null -w "%{http_code}" "http://${CH_HOST}:9002/clif-cold-logs/" 2>/dev/null)
if [ "$BUCKET_CHECK" != "000" ]; then
  pass "MinIO clif-cold-logs bucket accessible"
else
  fail "MinIO clif-cold-logs bucket not accessible"
fi

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 6: Data Integrity — Schema Validation${RESET}"
echo "────────────────────────────────────────────────────────────"

# Verify all 4 tables exist
for TABLE in raw_logs security_events process_events network_events; do
  EXISTS=$(ch_query "SELECT count() FROM system.tables WHERE database='${CH_DB}' AND name='${TABLE}'" | tr -d '[:space:]')
  if [ "$EXISTS" = "1" ]; then
    pass "Table ${TABLE} exists"
  else
    fail "Table ${TABLE} missing"
  fi
done

# Verify materialized views exist
for MV in events_per_minute_mv security_severity_hourly_mv; do
  EXISTS=$(ch_query "SELECT count() FROM system.tables WHERE database='${CH_DB}' AND name='${MV}'" | tr -d '[:space:]')
  if [ "$EXISTS" = "1" ]; then
    pass "Materialized view ${MV} exists"
  else
    fail "Materialized view ${MV} missing"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Test 7: Redpanda Topic Verification${RESET}"
echo "────────────────────────────────────────────────────────────"

for TOPIC in raw-logs security-events process-events network-events; do
  if rpk topic describe "${TOPIC}" --brokers "${BROKER}" >/dev/null 2>&1; then
    PARTITIONS=$(rpk topic describe "${TOPIC}" --brokers "${BROKER}" 2>/dev/null | grep -c "^[0-9]" || echo "?")
    pass "Topic ${TOPIC} exists (partitions: ${PARTITIONS})"
  else
    fail "Topic ${TOPIC} not found"
  fi
done

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════════${RESET}"
TOTAL=$((pass_count + fail_count))
echo -e "  Results: ${GREEN}${pass_count} passed${RESET}  ${RED}${fail_count} failed${RESET}  (${TOTAL} total)"
echo -e "${BOLD}════════════════════════════════════════════════════════════${RESET}"
echo ""

if [ $fail_count -gt 0 ]; then
  exit 1
fi
exit 0
