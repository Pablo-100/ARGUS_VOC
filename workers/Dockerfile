FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y nmap curl && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

ENV PYTHONPATH=/app

RUN chown appuser:appuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .

# nmap -O (OS detection) and -sS (SYN scan) require root/raw sockets.
USER root

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import socket; socket.create_connection(('rabbitmq', 5672), timeout=3); socket.create_connection(('redis', 6379), timeout=3); raise SystemExit(0)"

CMD ["celery", "-A", "tasks", "worker", "--loglevel=info", "--concurrency=2", "-Q", "scan,enrich,score,index,ticket"]