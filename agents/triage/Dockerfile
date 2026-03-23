# =============================================================================
# CLIF Triage Agent v7 — Production Dockerfile
# =============================================================================
# 2-model ML ensemble (LightGBM ONNX + Autoencoder ONNX) with EWMA rate
# tracking, kill-chain state machine, and parallel feature extraction.
#
# Input:  raw-logs, security-events, process-events, network-events (Kafka)
# Output: triage-scores, anomaly-alerts, hunter-tasks (Kafka)
# =============================================================================
FROM python:3.11-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies required by confluent-kafka (librdkafka)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
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
COPY ewma_tracker.py .
COPY kill_chain.py .
COPY feature_extractor.py .
COPY model_ensemble.py .
COPY score_fusion.py .
COPY shap_explainer.py .
COPY app.py .
COPY drain3.ini .

# Pre-seeded Drain3 templates (optional, for cold-start)
COPY drain3_state.bi[n] ./

# Models are mounted as a read-only volume at /models
# (see docker-compose.pc2.yml: ./agents/triage/models:/models:ro)
# Expected files:
#   /models/lgbm_v7.onnx
#   /models/autoencoder_v7.onnx
#   /models/ae_calibration_v7.json
#   /models/feature_scaler_v7.json
#   /models/manifest_v7.json

EXPOSE 8300

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=45s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8300/health')"

CMD ["python", "app.py"]
