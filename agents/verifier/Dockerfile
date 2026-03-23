FROM python:3.11-slim

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code
COPY . .

EXPOSE 8500

# uvicorn with 1 worker (aiokafka is async – no benefit from multiple workers)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8500", "--workers", "1", "--loop", "asyncio"]
