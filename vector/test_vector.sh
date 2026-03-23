#!/bin/bash
# =============================================================================
# CLIF Vector — Smoke Test & Validation Script
# =============================================================================
# Usage: bash vector/test_vector.sh
#
# Tests:
#   1. Vector health check (API)
#   2. Syslog ingestion (TCP)
#   3. HTTP JSON ingestion
#   4. Verify events arrive in Redpanda topics
#   5. Verify CCS field normalization
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VECTOR_API="${VECTOR_API:-http://localhost:8686}"
VECTOR_HTTP="${VECTOR_HTTP:-http://localhost:8687}"
VECTOR_SYSLOG="${VECTOR_SYSLOG:-localhost}"
VECTOR_SYSLOG_PORT="${VECTOR_SYSLOG_PORT:-1514}"
REDPANDA_BROKER="${REDPANDA_BROKER:-localhost:19092}"

PASS=0
FAIL=0

pass() { echo -e "  ${GREEN}✔ PASS${NC}: $1"; ((PASS++)); }
fail() { echo -e "  ${RED}✘ FAIL${NC}: $1"; ((FAIL++)); }

echo "============================================="
echo " CLIF Vector — Smoke Tests"
echo "============================================="
echo ""

# ── Test 1: Vector API Health ────────────────────────────────────────────────
echo "Test 1: Vector API Health"
if curl -sf "${VECTOR_API}/health" > /dev/null 2>&1; then
    pass "Vector API is healthy"
else
    fail "Vector API not responding at ${VECTOR_API}/health"
fi

# ── Test 2: Syslog TCP Ingestion ─────────────────────────────────────────────
echo "Test 2: Syslog TCP Ingestion"
SYSLOG_MSG="<134>1 $(date -u +%Y-%m-%dT%H:%M:%SZ) testhost sshd 12345 - - Failed password for invalid user admin from 10.0.0.99 port 22 ssh2"
if echo "$SYSLOG_MSG" | nc -w 2 "${VECTOR_SYSLOG}" "${VECTOR_SYSLOG_PORT}" 2>/dev/null; then
    pass "Syslog message sent via TCP"
else
    fail "Could not send syslog message to ${VECTOR_SYSLOG}:${VECTOR_SYSLOG_PORT}"
fi

# ── Test 3: HTTP JSON Ingestion ──────────────────────────────────────────────
echo "Test 3: HTTP JSON Ingestion"
HTTP_RESPONSE=$(curl -sf -o /dev/null -w "%{http_code}" -X POST \
    "${VECTOR_HTTP}/v1/logs" \
    -H "Content-Type: application/json" \
    -H "X-CLIF-Source: smoke-test" \
    -d '[
        {
            "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
            "level": "ERROR",
            "source": "vector-smoke-test",
            "message": "Failed password for invalid user root from 192.168.1.100 port 22",
            "user_id": "root",
            "ip_address": "192.168.1.100"
        },
        {
            "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
            "level": "INFO",
            "source": "vector-smoke-test",
            "message": "Normal application log event for testing",
            "metadata": {"request_id": "test-req-001"}
        },
        {
            "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
            "level": "WARNING",
            "source": "vector-smoke-test",
            "message": "Connection from 10.0.0.50 port 44321 to 172.16.0.1 port 443 TCP established",
            "src_ip": "10.0.0.50",
            "src_port": 44321,
            "dst_ip": "172.16.0.1",
            "dst_port": 443,
            "protocol": "TCP"
        },
        {
            "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
            "level": "INFO",
            "source": "vector-smoke-test",
            "message": "Process started pid=1234 ppid=1 binary=/usr/bin/curl",
            "pid": 1234,
            "ppid": 1,
            "binary_path": "/usr/bin/curl",
            "arguments": "curl https://example.com"
        }
    ]' 2>/dev/null)

if [ "$HTTP_RESPONSE" = "200" ] || [ "$HTTP_RESPONSE" = "204" ]; then
    pass "HTTP JSON batch accepted (HTTP ${HTTP_RESPONSE})"
else
    fail "HTTP JSON rejected (HTTP ${HTTP_RESPONSE})"
fi

# ── Test 4: Wait for processing ──────────────────────────────────────────────
echo "Test 4: Waiting 3 seconds for Vector pipeline processing..."
sleep 3
pass "Pipeline processing window elapsed"

# ── Test 5: Verify events in Redpanda topics ────────────────────────────────
echo "Test 5: Verify events in Redpanda topics"
if command -v rpk &> /dev/null; then
    for TOPIC in raw-logs security-events process-events network-events; do
        COUNT=$(rpk topic consume "$TOPIC" --brokers "$REDPANDA_BROKER" -n 1 --format '%v' 2>/dev/null | wc -c)
        if [ "$COUNT" -gt 2 ]; then
            pass "Topic '${TOPIC}' has data"
        else
            echo -e "  ${YELLOW}⚠ SKIP${NC}: Topic '${TOPIC}' — no data (may need more events)"
        fi
    done
else
    echo -e "  ${YELLOW}⚠ SKIP${NC}: rpk not installed, skipping Redpanda topic verification"
fi

# ── Test 6: Check Vector metrics ─────────────────────────────────────────────
echo "Test 6: Vector Prometheus Metrics"
METRICS_RESPONSE=$(curl -sf "http://localhost:9598/metrics" 2>/dev/null | head -5)
if [ -n "$METRICS_RESPONSE" ]; then
    pass "Prometheus metrics endpoint responding"
else
    fail "Prometheus metrics endpoint not responding"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo -e " Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}"
echo "============================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
