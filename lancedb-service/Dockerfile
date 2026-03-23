FROM python:3.12-slim

LABEL maintainer="CLIF Team" \
      description="CLIF LanceDB — Semantic Vector Search & RAG Engine" \
      version="2.0.0"

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends g++ curl && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /usr/sbin/nologin clif

# Install CPU-only PyTorch first (smallest variant, ~200MB vs 2GB CUDA)
RUN pip install --no-cache-dir --timeout 600 \
    torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 600 -r requirements.txt

# Pre-download the embedding model so container starts fast (~90MB)
# Store in /app/models so it's accessible by the clif user
ENV HF_HOME=/app/models
ENV TRANSFORMERS_CACHE=/app/models
ENV SENTENCE_TRANSFORMERS_HOME=/app/models
RUN mkdir -p /app/models && \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')" && \
    chown -R clif:clif /app/models

COPY app.py .

# LanceDB storage
RUN mkdir -p /data/lancedb && chown clif:clif /data/lancedb
VOLUME ["/data/lancedb"]

EXPOSE 8100

# Drop back to non-root
USER clif

HEALTHCHECK --interval=15s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health')" || exit 1

ENTRYPOINT ["python", "-u", "app.py"]
