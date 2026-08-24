# VOC Platform - Complete Project Reference

> **Purpose**: This file is the single source of truth for the VOC (Vulnerability Operations Center) platform.
> Any AI assistant reading this file should understand the project 100% without asking questions.
> **Human-facing overview**: see `README.md` (features, architecture diagrams, quick start, credentials).

---

## 1. PROJECT OVERVIEW

**VOC** is a Vulnerability Operations Center platform that:
1. Scans network hosts for vulnerabilities using nmap
2. Enriches findings with MISP threat intelligence
3. Computes risk scores via a custom risk engine
4. Indexes everything to Elasticsearch for visualization in Kibana
5. Creates GLPI ITSM tickets for high-risk vulnerabilities
6. Monitors all infrastructure with Filebeat, Packetbeat, Auditbeat

**Tech Stack**: Docker Compose, Python 3.11, Celery, RabbitMQ, Redis, Elasticsearch 8.11, Kibana 8.11, Logstash 8.11, FastAPI, MariaDB, MISP, GLPI

**Beats**: Filebeat (logs), Metricbeat (metrics), Packetbeat (network), Auditbeat (audit), Heartbeat (uptime)

---

## 2. DIRECTORY STRUCTURE

```
/opt/voc-platform/
├── docker-compose.yml          # 18 services
├── .env                        # All secrets and config
├── .env.example                # Template (safe to commit)
├── .gitignore
├── elasticsearch/              # Empty (config in docker-compose)
├── kibana/dashboards/          # Empty (dashboards loaded via API)
├── logs/                       # Runtime logs (ICMP monitor, etc.)
├── logstash/
│   └── pipeline/
│       └── voc.conf            # Logstash pipeline: HTTP input -> ES output
├── risk-engine/
│   ├── Dockerfile              # python:3.11-slim
│   ├── main.py                 # FastAPI: POST /score, GET /health
│   ├── main.log                # App log (mounted into filebeat)
│   └── requirements.txt        # fastapi, uvicorn, pydantic
├── scripts/
│   ├── auditbeat-config.yml    # Auditbeat config
│   ├── elastic-agent-config.yml # Filebeat config (20+ inputs)
│   ├── heartbeat-config.yml    # Heartbeat uptime monitoring
│   ├── icmp-monitor.sh         # Cron-based ICMP ping monitor
│   ├── init-es-users.sh        # ES user init script
│   ├── metricbeat-config.yml   # Metricbeat system/docker/service metrics
│   └── packetbeat-config.yml   # Packetbeat config
└── workers/
    ├── Dockerfile              # python:3.11-slim + nmap + celery
    ├── glpi_client.py          # GLPI REST client (dedup + follow-ups)
    ├── logstash_client.py      # ELK indexing (incl. resolved)
    ├── misp_client.py          # MISP threat-intel client
    ├── nvd_client.py           # NVD CVE correlation
    ├── requirements.txt        # celery, redis, requests, nmap
    ├── tasks.log               # Worker log (mounted into filebeat)
    ├── tasks.py                # Celery app + tasks (multi-subnet scan)
    └── tests/                  # unit tests
```

---

## 3. ALL SERVICES (18 containers)

### 3.1 Infrastructure

| Service | Container | Image | Port | Purpose |
|---------|-----------|-------|------|---------|
| rabbitmq | voc-rabbitmq | rabbitmq:3.12-management-alpine | 5672, 15672 | Celery message broker |
| redis | voc-redis | redis:7-alpine | 6379 | Celery result backend + MISP cache |
| elasticsearch | voc-elasticsearch | elasticsearch:8.11.0 | 9200 | Search engine (all indices) |
| logstash | voc-logstash | logstash:8.11.0 | 5044, 9600 | Vulnerability data pipeline |
| mariadb | voc-mariadb | mariadb:10.6 | 3306 | GLPI database |
| misp_db | voc-misp-db | mariadb:10.6 | internal | MISP database |
| kibana | voc-kibana | kibana:8.11.0 | 5601 | Visualization UI |

### 3.2 Application

| Service | Container | Image | Port | Purpose |
|---------|-----------|-------|------|---------|
| risk-engine | voc-risk-engine | Custom (FastAPI) | 8000 | Risk score computation |
| glpi | voc-glpi | diouxx/glpi:latest | 8080 | IT Service Management |
| misp | voc-misp | misp-core:latest | 8443 | Threat Intelligence Platform |
| celery-worker | voc-celery-worker | Custom (Python+celery) | - | Task execution (concurrency=2) |
| celery-beat | voc-celery-beat | Custom (Python+celery) | - | Periodic task scheduler |
| portal | voc-portal | Custom (FastAPI+SQLite+SPA) | 4200 | Unified entry point: auth, tickets, dashboards |

### 3.3 Observability (5 Beats)

| Service | Container | Image | Network | Purpose |
|---------|-----------|-------|---------|---------|
| elastic-agent | voc-elastic-agent | filebeat:8.11.0 | bridge | Docker + system logs + ICMP |
| packetbeat | voc-packetbeat | packetbeat:8.11.0 | host | Network traffic (HTTP, DNS, TLS, AMQP, Redis, MySQL) |
| auditbeat | voc-auditbeat | auditbeat:8.11.0 | bridge | Process/file/user audit trail |
| metricbeat | voc-metricbeat | metricbeat:8.11.0 | bridge | System, Docker, Redis, MySQL, ES metrics |
| heartbeat | voc-heartbeat | heartbeat:8.11.0 | host | Service uptime monitoring (HTTP + ICMP) |

---

## 4. CREDENTIALS

> All secrets are **required** via `.env` (gitignored) — no defaults in compose.
> Replace with strong unique values before non-lab deployment.

| Service | Username | Password Source | Access |
|---------|----------|----------|--------|
| Elasticsearch | elastic | `ELASTIC_PASSWORD` (`.env`) | Superuser |
| Elasticsearch | voc-kibana | `ES_KIBANA_PASSWORD` (`.env`) | Kibana server + filebeat read |
| RabbitMQ | `RABBITMQ_USER` | `RABBITMQ_PASS` (`.env`) | Management UI at `<host-ip>:15672` |
| Redis | (none) | `REDIS_PASSWORD` (`.env`) | internal, no host port |
| MariaDB (GLPI) | `MARIADB_USER` | `MARIADB_PASSWORD` (`.env`) | internal, no host port |
| MariaDB (GLPI) | root | `MARIADB_ROOT_PASSWORD` (`.env`) | Superuser |
| MariaDB (MISP) | `MISP_DB_USER` | `MISP_DB_PASSWORD` (`.env`) | internal, no host port |
| MariaDB (MISP) | root | `MISP_DB_ROOT_PASSWORD` (`.env`) | Superuser |
| MISP | `MISP_ADMIN_EMAIL` | `MISP_ADMIN_PASSPHRASE` (`.env`) | Web UI at `<host-ip>:8443` |
| GLPI | (via API tokens) | `GLPI_APP_TOKEN` / `GLPI_USER_TOKEN` (`.env`) | `<host-ip>:8080` |
| Kibana | elastic | `ELASTIC_PASSWORD` (`.env`) | Web UI at `<host-ip>:5601` |
| Risk Engine | `X-API-Key` header | `RISK_ENGINE_API_KEY` (`.env`) | `<host-ip>:8000/score` |
| **VOC Portal** | `PORTAL_ADMIN_USERNAME` (default `admin`) | `PORTAL_ADMIN_PASSWORD` (`.env`) | Web UI at `<host-ip>:4200` |
| VOC Portal (demo) | analyst1 / user1 / user2 | `PORTAL_DEMO_PASSWORD` (`.env`) | roles `soc3` / `soc1` / `noc` |

---

## 5. DATA FLOW

### 5.1 Vulnerability Scan Pipeline

```
celery-beat (every 6h, 0 */6 * * * UTC)
  → RabbitMQ "scan" queue
    → celery-worker: nmap_network_scan task (multi-subnet, nmap -sn discovery)
      → chord(scan_host.s(host, False) for host in hosts)  (nmap -sV per host)
        → process_network_results (diff vs Redis voc:scan:state)
            - NEW vulns: MISP event + chain enrich → score → index → create_ticket (GLPI)
            - STILL PRESENT: chain enrich → score → index (no duplicate ticket/event)
            - RESOLVED: status=resolved doc to ELK (via logstash_client.index_resolved)
              → enrich: MISP API (POST https://misp:8443/events/restSearch/json)
              → score: Risk Engine API (POST http://risk-engine:8000/score)
              → index_to_elk: Logstash API (POST http://logstash:5044)
              → create_ticket: GLPI API (POST http://glpi:8080/apirest.php/Ticket)
```

> `DISCOVERY_SUBNET` supports **multiple comma-separated subnets** (default
> `192.168.184.0/24,192.168.1.0/24`). The discovery stage merges live hosts across all
> of them so the beat scan covers the whole reachable network in one run.

### 5.2 Log Collection Pipeline

```
Docker containers → /var/lib/docker/containers/*/*.log
  → Filebeat (autodiscovery + docker metadata)
    → Elasticsearch: filebeat-8.11.0-YYYY.MM.dd

Host OS → /var/log/{syslog,auth.log,kern.log,dmesg,dpkg.log,ufw.log,...}
  → Filebeat (13 system log inputs)
    → Elasticsearch: filebeat-8.11.0-YYYY.MM.dd

Application logs → risk-engine/main.log, workers/tasks.log
  → Filebeat
    → Elasticsearch: filebeat-8.11.0-YYYY.MM.dd

ICMP monitor → /opt/voc-platform/logs/icmp-monitor.log (cron every minute)
  → Filebeat
    → Elasticsearch: filebeat-8.11.0-YYYY.MM.dd
```

### 5.3 Network Monitoring

```
Host network stack (network_mode: host)
  → Packetbeat (AF_PACKET sniffer)
    → Protocols: HTTP, DNS, TLS, AMQP, Redis, MySQL, ICMP
    → Elasticsearch: packetbeat-8.11.0-YYYY.MM.dd
```

### 5.4 Audit Trail

```
Host kernel audit subsystem
  → Auditbeat (auditd, file_integrity, system)
    → Elasticsearch: auditbeat-8.11.0-YYYY.MM.dd
```

---

## 6. ELASTICSEARCH INDICES

| Index Pattern | Source | Content |
|---------------|--------|---------|
| `vulnerabilities-YYYY.MM.dd` | Logstash | CVE scan results with risk scores |
| `filebeat-8.11.0-YYYY.MM.dd` | Filebeat | Docker logs, system logs, ICMP |
| `packetbeat-8.11.0-YYYY.MM.dd` | Packetbeat | Network traffic metadata |
| `auditbeat-8.11.0-YYYY.MM.dd` | Auditbeat | Process/file/user audit events |
| `metricbeat-8.11.0-YYYY.MM.dd` | Metricbeat | System, Docker, service metrics |
| `heartbeat-8.11.0-YYYY.MM.dd` | Heartbeat | Service uptime checks |
| `attack-graph-YYYY.MM.dd` | Logstash (`source=voc_graph`) | Attack-path nodes/edges + blast-radius summary |
| `predictions-YYYY.MM.dd` | Logstash (`source=voc_prediction`) | Weekly top-10 exploitation forecast |
| `prediction-validation-YYYY.MM.dd` | Logstash (`source=voc_validation`) | Precision@10 vs CISA KEV, "new to KEV" hits |

---

## 7. KIBANA DATA VIEWS

| Data View ID | Pattern | Name | Time Field |
|--------------|---------|------|------------|
| `5ec5e7c3-59e9-4173-bd3e-50807575ec95` | `filebeat-*` | VOC Filebeat Logs | @timestamp |
| `8cd32128-068f-48dd-bc62-900ca6c2a97b` | `packetbeat-*` | VOC Network Traffic | @timestamp |
| `943fb14e-bfeb-4937-9e7b-b37e12ebe267` | `auditbeat-*` | VOC Audit Trail | @timestamp |
| `metricbeat-voc` | `metricbeat-*` | VOC Metrics | @timestamp |
| `heartbeat-voc` | `heartbeat-*` | VOC Uptime | @timestamp |
| `997fc760-9453-4b59-82bc-202e2f46cf32` | `vulnerabilities-*` | VOC Vulnerabilities | @timestamp |
| `attack-graph-*` | `attack-graph-*` | VOC Attack Graph | @timestamp |
| `predictions-*` | `predictions-*` | VOC Predictions | @timestamp |
| `prediction-validation-*` | `prediction-validation-*` | VOC Prediction Validation | @timestamp |

Default data view: `5ec5e7c3-59e9-4173-bd3e-50807575ec95` (filebeat-*)

---

## 8. CELERY TASK DETAILS

### 8.1 Task Routes (RabbitMQ Queues)

| Task | Queue | Purpose |
|------|-------|---------|
| `tasks.nmap_network_scan` | scan | Multi-subnet discovery (nmap -sn) |
| `tasks.scan_host` | scan | Port/service scanning (nmap -sV) |
| `tasks.process_network_results` | scan | Diff callback: new / still / resolved |
| `tasks.enrich` | enrich | MISP threat intel enrichment |
| `tasks.enhance` | enrich | Deep threat-intel + ATT&CK + CIS |
| `tasks.score` | score | Risk score computation |
| `tasks.index_to_elk` | index | Send to Logstash for ES indexing |
| `tasks.create_ticket` | ticket | Create GLPI tickets (risk >= 7.0, dedup) |
| `tasks.build_attack_graph` | index | Rebuild attack-path / blast-radius graph snapshot (daily 07:00) |
| `tasks.weekly_prediction` | index | Weekly top-10 exploitation forecast (Sun 06:00) |
| `tasks.validate_predictions` | index | Validate past predictions vs CISA KEV (Sun 06:30) |

### 8.4 SOC Analytics (`workers/soc_analytics.py`)

- **Attack graph**: hosts come from active `vulnerabilities-*` docs; an edge exists between
  two hosts in the same `DISCOVERY_SUBNET`; a node is **critical** if its IP is in
  `CRITICAL_ASSETS` (env) or its max risk ≥ `CRITICAL_RISK_THRESHOLD` (default 8.0);
  **blast radius** = sum of risk of all critical assets reachable from it (BFS over the edges).
  Docs: `doc_type: node|edge|summary`, edges use `src`/`tgt` (not `source`, reserved for routing).
- **Weekly prediction**: filters active CVEs (vuln present today, still reachable), scores
  `pred_score = 0.40·EPSS + 0.15·EPSS_percentile + 0.20·exploit_available + 0.10·in_kev + 0.15·(risk/10)`,
  returns the top-10 with `predicted_cves`, `kev_total`, `universe_size`.
- **Self-validation**: once a prediction is ≥ `horizon_days` old, its `predicted_cves` are
  checked against the real CISA KEV catalog → `precision_at_10`, `precision_new_at_10`
  (only CVEs added to KEV **after** the prediction date) and the hit lists.
- The graph snapshot is replaced each run (delete `snapshot_id=latest` → rebuild), so
  `attack-graph-*` always holds exactly the current snapshot; predictions/validations
  accumulate by week for the precision trend.

### 8.2 Risk Score Algorithm (risk-engine/main.py)

```
score = cvss_base
if is_critical_asset:  score += cvss_base * 0.5
if misp_threat_active: score += 2.0
if exploit_available:  score += 1.5
if network_exposure:   score += network_exposure * 2.0
if in_kev:             score += RISK_KEV_BOOST          # default 2.0
if epss >= threshold:  score += RISK_EPSS_BOOST         # threshold .5, boost 1.0
final = min(score, 10.0)

Severity: >=9 Critical, >=7 High, >=4 Medium, else Low
```

`/score` requires the `X-API-Key` header (`RISK_ENGINE_API_KEY`); `/health` is open.

### 8.3 GLPI Ticket Creation

- Only for vulns with `risk_score >= 7.0`
- Urgency: 5 (critical) if risk >= 9, else 4
- Impact: 4 (always)
- Priority: 5 (very high) if risk >= 7, else 4
- Title format: `[VOC] {severity} - {CVE} on {host}`
- **Deduplication**: `glpi_client.find_existing_ticket(host, vuln)` is called before
  creating a ticket; if an open ticket already matches (CVE + host) the creation is
  skipped and counted as a duplicate.

### 8.5 VOC Portal (`portal/`) — ticket routing & time formula

```
resolution_rate(user) = tickets solved / tickets ever assigned to user

best_assignee() = user with resolution_rate > 0.5 (SOLVE_THRESHOLD)
                  ranked by rate desc, then fewest open tickets desc
                  (only active users with role 'user' or 'soc')

assign_ticket()  = est_hours = base_hours[severity] / max(rate, 0.1)
                   base_hours = {critical: 6, high: 12, medium: 24, low: 48}
                   (after >=3 resolved tickets, blended 50/50 with the
                    user's historical average resolution time)

rebalance()      = every 'solve' re-runs assignment over all unassigned tickets
```

- Tickets come from **admin** (manual, `source=admin`) or **auto** (imported from
  `vulnerabilities-*` where `risk_score >= 7`, deduplicated by `host|cve`).
- **RBAC (capability-based, `portal/app/roles.py`)**: roles are a SOC staffing pyramid —
  `admin`, `voc` (vuln mgmt + import pipeline), `soc3` (edit/assign any ticket), `soc2`
  (assign/reopen, all-tickets view), `soc1` (own tickets), `noc` (services + ticket
  overview). Every endpoint is gated by a capability (`tickets.edit`, `users.manage`,
  `services.view`, …). Admins can grant **extra capabilities per user** (`grants` JSON on
  the user row) via the Edit-user modal — effective caps = role base + grants. Legacy
  roles `soc`/`user` auto-migrate to `soc2`/`soc1` on startup.
- **My Account** (any role): edit display name, change password (verifies current),
  and view effective privileges with a "granted" badge on grant-augmented caps.
- **Cross-platform identity provisioning** (`portal/app/provision.py`): when the admin
  creates a user in the portal, the same account is automatically provisioned on every
  platform with the same password — Elasticsearch/Kibana (native user + `viewer`/
  `kibana_admin`/`superuser` role per portal role), RabbitMQ (management user + vhost
  grant), GLPI (user + profile: Super-Admin/Admin/Technician/Read-Only per role), MISP
  (user with role, `change_pw` cleared). Role changes, enable/disable, password resets
  and deletes are synced everywhere; `/api/users` carries a per-platform status shown in
  the Team & Access table.
- **Single sign-on**: basic-auth platforms (Kibana, Elasticsearch, RabbitMQ) get SSO URLs
  (`user:pass@host`) shown on My Account + the Services page, so opening them in the
  browser lands already authenticated — no second login. GLPI/MISP use form login but
  accept the *same* credentials as the portal. The plaintext password is retained only in
  `users.platform_pass` to rebuild those URLs (lab compromise — replace with a real IdP in
  production). MISP's password policy was relaxed (`password_policy_length=6`,
  complexity `.*` in `scripts/misp-config.php`) so portal passwords satisfy it.
- **Data integrity verification**: every CVE in the pipeline is validated against the
  real EPSS/NVD feed (`epss_score` present = registered NVD CVE; spot-checks against
  `services.nvd.nist.gov` confirmed). Host IPs are verified as RFC1918, in the scanned
  `192.168.1.0/24` scope, and confirmed live via ping/ARP.
- **Dashboard drill-downs**: every widget is clickable — KPI cards, the 14-day trend
  chart, the severity donut, blast-radius assets, top CVEs, and the exploitation forecast
  all open detail modals (findings breakdown, per-day table, asset + its tickets,
  CVE + affected hosts, full forecast with EPSS/KEV). Ticket references inside modals
  open the full ticket view.
- **MITRE ATT&CK** (`/api/attack`): navigator-style heatmap grouped by tactic; CVEs map
  to techniques via a curated table plus port/service heuristics; tickets carry a
  `technique_id` and auto-backfill on startup.
- The rule is self-throttling: each auto-assignment pushes the user's rate back
  toward 50%, so a user only keeps receiving work while they keep solving.
- Data lives in a SQLite volume (`portal_data:/data`); JWT sessions (`PORTAL_SECRET`).
- Demo accounts after role migration: `analyst1` → `soc3`, `user1` → `soc1`,
  `user2` → `noc` (password `PORTAL_DEMO_PASSWORD`).

---

## 9. KNOWN ISSUES & LIMITATIONS

### 9.1 Resolved (as of 2026-08-15)

1. **Synthetic tickets/docs** (hosts `.50/.77/.80/.82`): GLPI tickets #393-396 and the
   ES document were deleted; the `enrich` guard (valid `scan_id` + `scan_type == "nmap"`)
   is deployed in the worker image.
2. **Periodic scan not running**: beat now fires `nmap_network_scan` every 6h and it was
   verified live across both subnets.
3. **ES yellow / unassigned replicas**: cluster is green (0 unassigned); a
   `voc-beats-zero-replicas` index template prevents recurrence on standalone beat indices.
4. **Worker OOM / re-delivery loop**: fixed by lowering concurrency to 2 and raising the
   worker (`768m`) and Redis (`192m`) memory limits; stale stuck tasks were purged.
5. **Scan fidelity**: `index_to_elk` now sends `service`/`product`/`version`/`cpe` so the
   fields survive to Elasticsearch (verified in documents).
6. **Ticket deduplication**: implemented via `find_existing_ticket`.
7. **Stale `voc-pipeline` queue**: no longer exists; all pipeline queues are consumed.
8. **Unused deps / dead code**: `pymisp` removed from requirements, the dead `discovery`
   task and its route deleted, redundant relative import normalized.

### 9.2 Remaining / Known Limitations

1. **ICMP capture**: Packetbeat cannot capture ICMP in Docker (AF_PACKET blocked). Workaround: `icmp-monitor.sh` cron job writes to log file, Filebeat collects it.
2. **Auditbeat socket/system**: `system/socket` and `system/service` datasets disabled (tracefs not available in Docker).
3. **MISP self-signed cert**: `.env` keeps `MISP_VERIFY_SSL=false` for the self-signed lab. **Production must set `true`** and provide trusted CAs. GLPI is HTTP in the lab.
4. **Fleet Server on 0.0.0.0:8220**: intentionally exposed so external host agents can enroll; keep it behind a firewall in production.
5. **Kibana encryption key rotation**: rotating `XPACK_*` keys invalidates previously encrypted saved objects (delete `.kibana*` indices to reset).

### 9.3 Hardening applied (2026-08-19)

- All secrets are **required** (`:?`) — `docker compose up` fails fast on any missing variable; no default credentials remain in `docker-compose.yml`.
- UI/admin ports exposed on `<host-ip>` for LAN access (protect at firewall); Redis / MariaDB / RabbitMQ broker expose **no host port**.
- Network isolation: `frontend` / `backend` / `data` tiers instead of the default flat bridge.
- TLS verification **on by default** for MISP/GLPI (`MISP_VERIFY_SSL` / `GLPI_VERIFY_SSL` default `true`).
- Risk engine authenticated via `X-API-Key` (`RISK_ENGINE_API_KEY`).
- Kibana encryption keys moved out of the image into `.env` (gitignored).
- NVD lookups cached in Redis (24h TTL) — shared across workers.
- `DISCOVERY_SUBNET` entries are CIDR-validated before scanning.

---

## 10. HOW TO INTERACT WITH SERVICES

### From Host Machine

```bash
# All credentials live in /opt/voc-platform/.env. For the commands below,
# either source it or substitute values from it:
#   set -a; source /opt/voc-platform/.env; set +a

# Elasticsearch
curl -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/_cat/indices?v
curl -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/_cluster/health

# Kibana
open http://localhost:5601  # login: elastic/${ELASTIC_PASSWORD}

# RabbitMQ Management
open http://localhost:15672  # login: ${RABBITMQ_USER}/${RABBITMQ_PASS}

# GLPI
open http://localhost:8080  # admin login: glpi / glpi (change on first login)

# MISP
open https://localhost:8443  # admin login: admin@admin.test / admin (change on first login)

# Risk Engine
curl http://localhost:8000/health
curl -X POST http://localhost:8000/score -H "Content-Type: application/json" \
  -d '{"cvss_base": 7.5, "is_critical_asset": true}'

# Logstash
curl http://localhost:9600/_node/stats
```

### From Inside Docker Network

```bash
# All services are reachable by container name
docker exec voc-celery-worker python -c "import requests; print(requests.get('http://risk-engine:8000/health').json())"
docker exec voc-celery-worker python -c "import requests; print(requests.get('http://logstash:9600/_node/stats').status_code)"
```

### Docker Commands

```bash
# Start all
docker compose -f /opt/voc-platform/docker-compose.yml up -d

# Restart specific service
docker compose -f /opt/voc-platform/docker-compose.yml restart celery-worker

# View logs
docker logs voc-celery-worker --tail 50 -f
docker logs voc-elastic-agent --tail 20

# Check status
docker ps --format "table {{.Names}}\t{{.Status}}"
```

---

## 11. NETWORK TOPOLOGY

```
Host: 192.168.184.135 (VMware)
  ├── Docker bridge: 172.18.0.0/16
  │   ├── voc-elasticsearch: 172.18.0.x:9200
  │   ├── voc-rabbitmq: 172.18.0.x:5672
  │   ├── voc-redis: 172.18.0.x:6379
  │   ├── voc-mariadb: 172.18.0.x:3306
  │   ├── voc-misp-db: 172.18.0.x
  │   ├── voc-glpi: 172.18.0.x
  │   ├── voc-misp: 172.18.0.x:8443
  │   ├── voc-logstash: 172.18.0.x:5044
  │   ├── voc-kibana: 172.18.0.x:5601
  │   ├── voc-risk-engine: 172.18.0.x:8000
  │   ├── voc-celery-worker: 172.18.0.x
  │   ├── voc-celery-beat: 172.18.0.x
  │   ├── voc-elastic-agent: 172.18.0.x
  │   └── voc-auditbeat: 172.18.0.x
  ├── Host network (voc-packetbeat)
  │   ├── ens33: 192.168.184.135
  │   ├── ens34: 192.168.87.3
  │   └── docker0: 172.17.0.1
  └── Discovery subnet: 192.168.184.0/24
```

---

## 12. CRON JOBS

| Schedule | Script | Purpose |
|----------|--------|---------|
| `* * * * *` | `/opt/voc-platform/scripts/icmp-monitor.sh` | Ping 8.8.8.8, 1.1.1.1, google.com every minute |
| `0 */6 * * *` | celery-beat `nmapsubnet-scan` | Full-subnet nmap scan (diff new/still/resolved) every 6h |
| `0 * * * *` | celery-beat `hourly-glpi-sync` | Sync GLPI tickets to ELK |

---

## 13. FILE PATHS (for reference)

### Config Files

| File | Format | Lines |
|------|--------|-------|
| `/opt/voc-platform/docker-compose.yml` | YAML | 450+ |
| `/opt/voc-platform/.env` | ENV | 99 |
| `/opt/voc-platform/scripts/elastic-agent-config.yml` | YAML | 207 |
| `/opt/voc-platform/scripts/packetbeat-config.yml` | YAML | 79 |
| `/opt/voc-platform/scripts/auditbeat-config.yml` | YAML | 100 |
| `/opt/voc-platform/scripts/metricbeat-config.yml` | YAML | 100 |
| `/opt/voc-platform/scripts/heartbeat-config.yml` | YAML | 93 |
| `/opt/voc-platform/logstash/pipeline/voc.conf` | Ruby | 35 |

### Application Code

| File | Language | Lines | Purpose |
|------|----------|-------|---------|
| `/opt/voc-platform/workers/tasks.py` | Python | 377 | 6 Celery tasks |
| `/opt/voc-platform/workers/glpi_client.py` | Python | 177 | GLPI REST client |
| `/opt/voc-platform/risk-engine/main.py` | Python | 85 | FastAPI risk engine |
| `/opt/voc-platform/portal/app/main.py` | Python | ~260 | Portal API: auth, tickets, users, dashboard |
| `/opt/voc-platform/portal/app/tickets.py` | Python | ~120 | >50% assignment rule + resolution-time formula |
| `/opt/voc-platform/portal/app/esdata.py` | Python | ~80 | Live Elasticsearch widgets |
| `/opt/voc-platform/portal/app/static/app.js` | JS | ~230 | Portal SPA frontend |

### Requirements

| File | Packages |
|------|----------|
| `/opt/voc-platform/workers/requirements.txt` | celery==5.3.6, redis==5.0.1, requests==2.31.0, python-nmap==0.7.1, python-gvm==24.3.0, pymisp==2.4.188 |
| `/opt/voc-platform/risk-engine/requirements.txt` | fastapi==0.104.1, uvicorn[standard]==0.24.0, pydantic==2.5.0 |

---

## 14. ENVIRONMENT VARIABLES

### Critical ones (used in code)

| Variable | Default | Used By |
|----------|---------|---------|
| `BROKER_URL` | `amqp://${RABBITMQ_USER}:${RABBITMQ_PASS}@rabbitmq:5672//` | celery-worker, celery-beat |
| `RESULT_BACKEND` | `redis://:${REDIS_PASSWORD}@redis:6379/0` | celery-worker, celery-beat |
| `MISP_URL` | `https://192.168.184.135:8443` | celery-worker (enrich task) |
| `MISP_KEY` | (set in .env) | celery-worker (enrich task) |
| `GLPI_URL` | `http://192.168.184.135:8080` | celery-worker (create_ticket) |
| `GLPI_APP_TOKEN` | (set in .env) | glpi_client.py |
| `GLPI_USER_TOKEN` | (set in .env) | glpi_client.py |
| `RISK_ENGINE_URL` | `http://risk-engine:8000` | celery-worker (score task) |
| `RISK_ENGINE_API_KEY` | (set in .env) | celery-worker (score task) |
| `LOGSTASH_URL` | `http://logstash:5044` | celery-worker (index_to_elk) |
| `DISCOVERY_SUBNET` | `192.168.184.0/24,192.168.1.0/24` | celery-beat (nmap multi-subnet scan, every 6h) |
| `ELASTIC_PASSWORD` | (set in .env) | ES, Filebeat, Packetbeat, Auditbeat |
| `REDIS_PASSWORD` | (set in .env) | Redis, MISP, celery |

---

## 15. QUICK DIAGNOSIS

### Service not starting

```bash
docker logs voc-<service-name> --tail 50
docker inspect voc-<service-name> --format '{{.State.Status}} {{.State.ExitCode}}'
```

### No data in Elasticsearch

```bash
# Check indices
curl -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/_cat/indices?v

# Check specific index
curl -u elastic:${ELASTIC_PASSWORD} http://localhost:9200/filebeat-*/_count

# Check for errors in filebeat
docker logs voc-elastic-agent 2>&1 | grep -i error | tail -10
```

### Celery tasks not running

```bash
# Check worker status
docker exec voc-celery-worker celery -A tasks inspect active

# Check RabbitMQ queues
curl -u ${RABBITMQ_USER}:${RABBITMQ_PASS} http://localhost:15672/api/queues

# Check worker logs
docker logs voc-celery-worker --tail 50
```

### Kibana not showing data

```bash
# Check data views
curl -u elastic:${ELASTIC_PASSWORD} "http://localhost:5601/api/data_views" -H "kbn-xsrf: true"

# Check kibana_user permissions
curl -u elastic:${ELASTIC_PASSWORD} "http://localhost:9200/_security/user/voc-kibana"
curl -u voc-kibana:${ES_KIBANA_PASSWORD} "http://localhost:9200/filebeat-*/_count"
```

---

## 16. REBUILD / RESET

```bash
# Full restart
cd /opt/voc-platform
docker compose down
docker compose up -d

# Reset Elasticsearch data
docker compose down
docker volume rm voc-platform_es_data
docker compose up -d

# Rebuild custom images
docker compose build --no-cache celery-worker celery-beat risk-engine
docker compose up -d

# Reset GLPI
docker compose down
docker volume rm voc-platform_mariadb_data voc-platform_glpi_config
docker compose up -d
```
