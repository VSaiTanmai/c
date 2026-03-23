FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for confluent-kafka (librdkafka)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc librdkafka-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Non-root user for security
RUN useradd -r -s /usr/sbin/nologin clif && chown -R clif:clif /app
USER clif

CMD ["python", "-u", "app.py"]
