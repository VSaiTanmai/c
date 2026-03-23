#!/usr/bin/env bash
# =============================================================================
# CLIF — Redpanda SASL/SCRAM Setup Script
# =============================================================================
# Run this AFTER Redpanda is running to create SASL users.
# Then enable SASL in docker-compose by setting REDPANDA_SASL_ENABLED=true
# and restarting all services.
# =============================================================================
set -euo pipefail

BROKER="${1:-localhost:19092}"
ADMIN_URL="${2:-http://localhost:9644}"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  CLIF — Redpanda SASL/SCRAM User Setup                  ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# Create superuser for admin operations
echo "Creating superuser: clif_admin..."
rpk acl user create clif_admin \
  --password "${REDPANDA_ADMIN_PASSWORD:-Cl1f_Rp@dmin_2026!}" \
  --mechanism SCRAM-SHA-256 \
  --api-urls "${ADMIN_URL}" 2>/dev/null || echo "  (already exists)"

# Create consumer user
echo "Creating user: clif_consumer..."
rpk acl user create clif_consumer \
  --password "${REDPANDA_CONSUMER_PASSWORD:-Cl1f_C0nsumer_2026!}" \
  --mechanism SCRAM-SHA-256 \
  --api-urls "${ADMIN_URL}" 2>/dev/null || echo "  (already exists)"

# Create producer user (for triage, hunter, vector)
echo "Creating user: clif_producer..."
rpk acl user create clif_producer \
  --password "${REDPANDA_PRODUCER_PASSWORD:-Cl1f_Pr0ducer_2026!}" \
  --mechanism SCRAM-SHA-256 \
  --api-urls "${ADMIN_URL}" 2>/dev/null || echo "  (already exists)"

# Grant ACLs
echo ""
echo "Granting ACLs..."

# Consumer: read all topics, write to consumer group
rpk acl create --allow-principal "User:clif_consumer" \
  --operation read --operation describe \
  --topic '*' \
  --brokers "${BROKER}" 2>/dev/null || true

rpk acl create --allow-principal "User:clif_consumer" \
  --operation read --operation describe \
  --group 'clif-*' \
  --brokers "${BROKER}" 2>/dev/null || true

# Producer: write to all topics
rpk acl create --allow-principal "User:clif_producer" \
  --operation write --operation describe --operation create \
  --topic '*' \
  --brokers "${BROKER}" 2>/dev/null || true

rpk acl create --allow-principal "User:clif_producer" \
  --operation read --operation describe \
  --group 'clif-*' \
  --brokers "${BROKER}" 2>/dev/null || true

echo ""
echo "SASL users and ACLs configured."
echo ""
echo "Next steps:"
echo "  1. Set REDPANDA_SASL_ENABLED=true in .env"
echo "  2. Restart all Redpanda brokers"
echo "  3. Restart all consumers and producers"
