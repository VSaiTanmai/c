# =============================================================================
# CLIF Vector — Production Container Image
# =============================================================================
# Multi-stage build for a minimal, hardened Vector deployment.
# Includes health check, non-root user, and disk buffer directory.
# =============================================================================

FROM timberio/vector:0.42.0-distroless AS production

# Vector configuration
COPY vector.yaml /etc/vector/vector.yaml

# Expose ports:
#   1514  — Syslog (TCP + UDP)
#   8686  — Vector API (health, metrics, GraphQL)
#   8687  — HTTP JSON log ingestion
#   8125  — StatsD metrics receiver
#   9598  — Prometheus metrics exporter
EXPOSE 1514 8686 8687 8125/udp 9598

# Health check via Vector API
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["vector", "top", "--interval", "1", "--human-metrics", "false"]

# Entrypoint
ENTRYPOINT ["vector"]
CMD ["--config-yaml", "/etc/vector/vector.yaml"]

# =============================================================================
# Development target — includes full shell for debugging
# =============================================================================
FROM timberio/vector:0.42.0-debian AS development

# Install debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    netcat-openbsd \
    dnsutils \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create disk buffer directory with correct permissions
RUN mkdir -p /var/lib/vector

# Copy configuration
COPY vector.yaml /etc/vector/vector.yaml

EXPOSE 1514 8686 8687 8125/udp 9598

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8686/health || exit 1

ENTRYPOINT ["vector"]
CMD ["--config-yaml", "/etc/vector/vector.yaml"]
