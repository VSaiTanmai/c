FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY merkle_anchor.py .

RUN useradd -r -s /usr/sbin/nologin clif && chown -R clif:clif /app
USER clif

CMD ["python", "-u", "merkle_anchor.py", "--daemon"]
