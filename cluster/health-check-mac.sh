#!/usr/bin/env bash
# =============================================================================
# CLIF Cluster — MacBook Health Check
# =============================================================================
# Quick verification that all Mac-side services are running and connected to PC1.
#
# Usage:  ./cluster/health-check-mac.sh
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")/.."

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Load DATA_IP
if [[ -f cluster/.env ]]; then
  source cluster/.env
fi
DATA_IP="${DATA_IP:-CHANGE_ME}"

echo -e "\n${CYAN}${BOLD}CLIF Cluster Health Check (MacBook)${NC}"
echo -e "PC1 DATA_IP: ${YELLOW}${DATA_IP}${NC}\n"

PASS=0
FAIL=0

check() {
  local name=$1 url=$2
  if curl -sf --max-time 3 "$url" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✔ ${name}${NC}"
    ((PASS++))
  else
    echo -e "  ${RED}✗ ${name}${NC}"
    ((FAIL++))
  fi
}

echo -e "${BOLD}── Local Services (MacBook) ──${NC}"
check "Vector"            "http://localhost:8686/health"
check "Triage Agent 1"    "http://localhost:8300/health"
check "Triage Agent 2"    "http://localhost:8301/health"
check "Triage Agent 3"    "http://localhost:8302/health"
check "Triage Agent 4"    "http://localhost:8303/health"
check "Hunter Agent"      "http://localhost:8400/health"
check "Prometheus"        "http://localhost:9090/-/healthy"
check "Grafana"           "http://localhost:3002/api/health"

echo -e "\n${BOLD}── Remote Services (PC1 @ ${DATA_IP}) ──${NC}"
check "ClickHouse HTTP"   "http://${DATA_IP}:8123/ping"
check "Redpanda Admin"    "http://${DATA_IP}:9644/v1/status/ready"

echo -e "\n${BOLD}── Kafka Connectivity ──${NC}"
if nc -z -w 2 "$DATA_IP" 19092 2>/dev/null; then
  echo -e "  ${GREEN}✔ Redpanda Kafka (${DATA_IP}:19092)${NC}"
  ((PASS++))
else
  echo -e "  ${RED}✗ Redpanda Kafka (${DATA_IP}:19092)${NC}"
  ((FAIL++))
fi

TOTAL=$((PASS + FAIL))
echo -e "\n${BOLD}Result: ${GREEN}${PASS}/${TOTAL} passed${NC}"
if [[ $FAIL -gt 0 ]]; then
  echo -e "${RED}${FAIL} service(s) unreachable${NC}"
  exit 1
fi
