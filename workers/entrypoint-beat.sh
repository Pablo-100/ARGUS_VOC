#!/bin/sh
set -e

# Fires an nmap network scan once whenever this container starts (server boot /
# docker compose up), then hands off to the regular beat scheduler (which also
# keeps the every-6h nmapsubnet-scan schedule). RabbitMQ queues the message so
# the worker picks it up as soon as it is ready.

sleep 20

if [ -z "${DISCOVERY_SUBNET}" ]; then
    DISCOVERY_SUBNET="192.168.184.0/24"
fi

echo "[entrypoint-beat] firing startup nmap network scan for: ${DISCOVERY_SUBNET}"
python - <<'PY' || echo "[entrypoint-beat] startup scan dispatch failed (6h schedule still covers it)"
import os
from tasks import app
app.send_task(
    "tasks.nmap_network_scan",
    args=(os.environ["DISCOVERY_SUBNET"],),
    countdown=30,
)
PY

exec celery -A tasks beat --loglevel=info --scheduler celery.beat.PersistentScheduler \
    --schedule=/data/celerybeat-schedule
