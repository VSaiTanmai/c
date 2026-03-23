FROM python:3.11-slim

WORKDIR /app

# Install system deps first (layer cache efficiency)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

# Models directory (also mounted as a named docker volume)
RUN mkdir -p /app/models

# Sigma rules directory
RUN mkdir -p /app/sigma/rules

EXPOSE 8400

# uvicorn with 1 worker (aiokafka is async – no benefit from multiple workers)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8400", "--workers", "1", "--loop", "asyncio"]
