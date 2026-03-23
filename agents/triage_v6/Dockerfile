# =============================================================================
# CLIF Triage Agent — Production Dockerfile
# =============================================================================
# 3-model ML ensemble (LightGBM ONNX + EIF + River ARF) with Drain3 template
# mining, sliding-window feature extraction, and score fusion routing.
#
# Input:  raw-logs, security-events, process-events, network-events (Kafka)
# Output: triage-scores, anomaly-alerts (Kafka → ClickHouse via consumer)
# =============================================================================
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies required by confluent-kafka (librdkafka) and eif (C++ Cython)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        g++ \
        librdkafka-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip cache purge

# Copy application code
COPY config.py .
COPY drain3_miner.py .
COPY feature_extractor.py .
COPY model_ensemble.py .
COPY score_fusion.py .
COPY shap_explainer.py .
COPY app.py .
COPY drain3.ini .

# Supplementary files (created by the training pipeline — may not exist initially)
# drain3_state.bin    : Pre-seeded Drain3 templates (1,024 clusters) for cold-start
# features_arf_*.csv  : ARF bootstrap data used when arf_replay_buffer is empty
# Using shell trick: COPY with glob silently skips if no files match (BuildKit)
COPY drain3_state.bi[n] ./
COPY features_arf_stream_features.cs[v] ./

# Models are mounted as a read-only volume at /models
# (see docker-compose.pc2.yml: ./agents/triage/models:/models:ro)

EXPOSE 8300

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=45s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8300/health')"

CMD ["python", "app.py"]
