# Shuffle & Zeek — second-host deployment

These tools need more RAM than the VOC host can spare (see README Security /
resource notes). Deploy them on any second machine with 8+ GB RAM, then point
the Tools Hub at them via `.env` on the VOC host:

    SHUFFLE_URL=https://<shuffle-host>:3001
    ZABBIX_PUBLIC_URL=http://<zabbix-host-or-localhost>:8081   # if remote

The Tools Hub shows their live status automatically.

## Shuffle (SOAR) — docker compose snippet

```yaml
services:
  shuffle-frontend:
    image: ghcr.io/shuffle/shuffle-frontend:latest
    ports: ["3001:80"]
    environment:
      BACKEND_HOSTNAME: shuffle-backend
  shuffle-backend:
    image: ghcr.io/shuffle/shuffle-backend:latest
    ports: ["3002:5001"]
    environment:
      DATA_DIR: /shuffle-db-volume
    volumes:
      - shuffle_db:/shuffle-db-volume
      - /var/run/docker.sock:/var/run/docker.sock
  shuffle-orborus:
    image: ghcr.io/shuffle/shuffle-orborus:latest
    environment:
      BACKEND_HOSTNAME: shuffle-backend
      DOCKER_API_VERSION: "1.40"
volumes:
  shuffle_db:
```

## Zeek — sensor host

Zeek wants a dedicated NIC in monitor mode. Minimal single-node setup:

```yaml
services:
  zeek:
    image: zeek/zeek:lts
    network_mode: host       # sees host traffic
    cap_add: [NET_ADMIN, NET_RAW]
    entrypoint: /opt/zeek/bin/zeek
    command: ["-i", "eth0", "LogAscii::use_logs = T"]
    volumes:
      - zeek_logs:/opt/zeek/logs
volumes:
  zeek_logs:
```

Ship `zeek_logs` to Elasticsearch with Filebeat's zeek module, or forward
notable conn/weird logs into the VOC pipeline via Logstash HTTP (:5044).
