# 👁 ARGUS — Vulnerability Operations Center

> **One console. Every signal.** Remplacez tous vos dashboards éparpillés
> (Kibana, Zabbix, GLPI, MISP, RabbitMQ…) par une seule console SOC.

A production-oriented, self-hosted **Vulnerability Operations Center**: it
discovers assets on explicitly authorized networks, detects and correlates
vulnerabilities, enriches them with threat intelligence, computes
explainable contextual risk, opens SLA-tracked tickets with smart routing,
and — critically — **only closes tickets after a scanner-verified re-scan**.

```text
DISCOVER → IDENTIFY ASSETS → DETECT VULNERABILITIES → CORRELATE CVEs
→ ENRICH THREAT INTEL → CONTEXTUALIZE ASSET RISK → CALCULATE PRIORITY
→ CREATE SLA → CREATE TICKET → ASSIGN OWNER → REMEDIATE → RE-SCAN
→ VERIFY → CLOSE → MEASURE
```

---

## Overview

The VOC is a defensive vulnerability-management platform built from:

* **Nmap** (discovery + full TCP scan + service/version + OS detection) and an
  adapter layer ready for authenticated scanners (**Greenbone/OpenVAS GMP**)
* **NVD / EPSS / CISA KEV / OSV / Exploit-DB / VirusTotal / MISP**
  threat-intelligence enrichment
* A **FastAPI risk engine** producing explainable contextual scores
* **Celery + RabbitMQ + Redis** task pipeline with retries and a dead-letter
  queue for indexing outages
* **Elasticsearch + Logstash + Kibana + Beats** observability stack
* **GLPI** for ITSM ticket records, **MISP** for intel publishing
* A single-page **portal** (FastAPI + SQLite) unifying everything behind one
  login with capability-based RBAC

## Business Problem

Manual vulnerability management fails at scale: scanners output thousands of
raw findings, CVSS alone says nothing about *your* exposure, remediation is
tracked in spreadsheets, "fixed" means "somebody clicked resolved", and there
is no feedback loop between scans and tickets. The VOC automates that loop
end-to-end and makes every prioritization decision auditable.

## Architecture

![Architecture placeholder](docs/img/architecture.png)

```text
                        ┌───────────────────────────┐
   DISCOVERY_SUBNET ──▶ │ celery-worker             │
   (beat every 6h)      │  scan→enrich→enhance→     │──▶ risk-engine (/score)
                        │  score→index→ticket       │
                        └───────┬────────┬──────────┘
                     MISP API   │        │  Logstash HTTP :5044
                        ┌───────▼──┐  ┌──▼────────┐   ┌──────────────┐
                        │ MISP     │  │ Logstash  │──▶│ Elasticsearch│◀── Beats x5
                        └──────────┘  └───────────┘   │ + Kibana     │
                        ┌──────────┐                   └──────────────┘
                        │ GLPI ◀───┼── tickets          ▲
                        └──────────┘                    │ ES queries
                        ┌──────────┐                    │
                        │ portal   │────────────────────┘
                        │ (SPA+API)│── provisions users into ES/RMQ/GLPI/MISP
                        └──────────┘
```

### Technical architecture

| Layer | Components |
|---|---|
| Pipeline | Celery workers (`workers/tasks.py`), queues `scan/enrich/score/index/ticket` |
| Scanning | `scanners/nmap_adapter.py`, `scanners/openvas_adapter.py` (GMP over TLS), `ScannerAdapter` base |
| Assets | `workers/assets.py` — ES index `assets-v1` (alias `assets`), stable identity MAC+IP+hostname |
| Risk | `risk-engine/main.py` v3 contextual additive model, X-API-Key auth |
| Intel | `nvd_client.py` (CPE/version-aware), `threat_intel.py` (EPSS/KEV/OSV/EDB/VT), `misp_client.py` |
| Tickets | GLPI REST (`glpi_client.py`), portal SQLite lifecycle + SLA + verification bridge |
| Notifications | `notifications.py` provider adapters (Telegram/Email/log) drained from ES queue by beat |
| Data | Elasticsearch daily indices via Logstash `source` routing, ILM retention policy `voc-retention` |
| UI | Portal SPA (`static/app.js`) — dashboard, vulnerabilities (+detail modal), assets, tickets, ATT&CK, MISP/GLPI panels, infra, audit |

## Data flow

1. Beat fires `nmap_network_scan(DISCOVERY_SUBNET)` every 6h (CIDRs validated,
   mutual-exclusion lock in Redis).
2. Live hosts are scanned per-host (`scan_host`); results form a chord into
   `process_network_results`.
3. The diff vs Redis state classifies findings **new / still-present /
   resolved**, tracks tombstones so a returning CVE is flagged **REOPENED**.
4. Every host observation upserts the **asset inventory** (no duplicates).
5. Findings are enriched (MISP IOCs → CWE classification → ATT&CK mapping →
   remediation/CIS checklist → EPSS/KEV/OSV/Exploit-DB/VirusTotal).
6. Risk engine scores each finding **with asset context** from the inventory.
7. Documents land in `vulnerabilities-*` through Logstash with
   `finding_id` + `scan_id` correlation.
8. New findings ≥ risk 7 open GLPI tickets and portal tickets (SLA deadline
   computed from severity); critical ones trigger notifications.
9. Analysts work tickets; **solve = remediated**, which queues a verification
   request. The worker sweep re-scans; absent CVE ⇒ solved *(scanner)*,
   present CVE ⇒ reopened. Closure without verification is an audited admin
   override.

## Features

**Endpoint activity (FIM)** — the Endpoints tab shows every file
created/modified/deleted on the server (with sha256 hashes) and every process
execution, as captured by the Auditbeat agent watching `/etc`, `/home`,
`/root` and the platform directory · **Zabbix & Shuffle deployed** — optional
compose profiles (`--profile zabbix`, `--profile shuffle`) running on-host;
the Tools Hub probes them live · **Unified Tools Hub** — Kibana, Elasticsearch, GLPI, MISP, RabbitMQ, Zabbix
(optional profile), Shuffle/Zeek (second-host integrations) with live health
and single-sign-on deep links · **Dynamic roles** — admins create custom
roles and grant per-capability CRUD permissions from a visual matrix
(`roles.manage`), built-ins protected against lockout · **IP + hostname**
everywhere, with reverse-DNS resolution during scans, manual hostname
assignment that survives rescans, and automatic **device-change detection**
(same IP, different machine → flagged with observation history) · **Native
Dashboards tab** replicating key SOC views without a Kibana login.

Asset inventory with criticality · contextual explainable risk · CPE/CVE
correlation · **NSE active vulnerability checks** (findings carry
`confidence: confirmed|potential` — confirmed means an nmap scripting-engine
check actually probed the service and captured evidence) · authenticated-
scanner abstraction (OpenVAS adapter ready, requires a ≥4 GB-RAM deployment) ·
full vulnerability lifecycle with reopen-on-redetection · scanner-verified
remediation · SLA management & metrics · smart ticket routing with reasoning ·
immutable audit trail · notifications · MITRE ATT&CK mapping · attack-path/
blast-radius graph · weekly exploitation forecast with KEV validation ·
RBAC + brute-force protection · demo mode.

## Installation

Requirements: Linux host with Docker + Compose v2, ~8 GB RAM free, network
reachability to the authorized discovery subnets.

```bash
git clone <repo> /opt/voc-platform && cd /opt/voc-platform
cp .env.example .env
openssl rand -hex 32   # repeat for PORTAL_SECRET, RISK_ENGINE_API_KEY, etc.
$EDITOR .env           # fill REQUIRED secrets (compose refuses to start otherwise)
docker compose up -d
docker compose ps      # wait for all healthy
```

First start: Elasticsearch bootstrap (~2 min), then the setup container sets
the kibana_system password and applies ILM retention. The portal seeds its
admin user and imports high-risk findings automatically.

Open **http://<host>:4200** — log in as `PORTAL_ADMIN_USERNAME`.

## Configuration

All configuration lives in `.env` (see `.env.example`, fully commented).
Key groups: core secrets (REQUIRED), discovery CIDR, MISP/GLPI tokens, risk
boosts, SLA budgets (`SLA_*_HOURS`), routing thresholds (`ROUTING_*`),
scanner config (`OPENVAS_*`, `VERIFICATION_SCANNER`, `NMAP_SCAN_ARGS`),
notifications (`NOTIFICATION_PROVIDERS`, `TELEGRAM_*`, `SMTP_*`), retention
(`DATA_RETENTION_DAYS`).

## Security

* No default credentials — every secret is required via compose `:?`
  fail-fast (admin `'admin'` fallback needs explicit opt-in).
* Server-side capability RBAC on every endpoint (never UI-only); IDOR-tested.
* JWT (12 h TTL) + PBKDF2-SHA256 (120k iterations) password hashing.
* Login rate-limiting/lockout; success/failure/lockout all audited with IP.
* Security headers (CSP, nosniff, frame-options, referrer-policy).
* SSO deep-links with embedded credentials are OFF by default
  (`VOC_SSO_EMBED_CREDENTIALS=false`).
* Risk engine requires `X-API-Key`; Redis requires auth; admin surfaces bind
  to configurable interfaces — see firewall notes below.
* Nmap runs inside the worker container with `cap_drop: ALL` +
  `cap_add: NET_RAW/NET_ADMIN` only.
* Scanning targets are validated CIDRs from `DISCOVERY_SUBNET`; the platform
  never attacks third-party systems.

**Firewall guidance (production):** expose publicly only what users need
(portal 4200). Keep ES 9200, Kibana 5601, RabbitMQ 15672, Logstash 9600,
risk-engine 8000 off the internet (bind to localhost/VPN or firewall them);
Fleet 8220 must be reachable by enrolled agents only.

## Services

| Service | Container | Purpose | Port | Network | Persistence | Dependencies |
|---|---|---|---|---|---|---|
| RabbitMQ | voc-rabbitmq | Broker | 15672 (mgmt) | backend,data | rabbitmq_data | – |
| Redis | voc-redis | Cache/diff-state/DLQ | – | backend,data | redis_data | – |
| Elasticsearch | voc-elasticsearch | Findings/assets store | 9200 | backend,data | es_data | – |
| Logstash | voc-logstash | HTTP ingest + routing | 5044, 9600 | backend,data | – | ES |
| Kibana | voc-kibana | Dashboards | 5601 | frontend,backend | kibana.yml | ES |
| Fleet server | voc-fleet-server | Agent enrollment | 8220 | backend | fleet_server_state | ES, Kibana |
| Filebeat | voc-elastic-agent | Logs | – | backend | host mounts | ES |
| Metricbeat | voc-metricbeat | Metrics | – | backend/host | host mounts | ES |
| Packetbeat | voc-packetbeat | Network telemetry | – | host | – | ES |
| Auditbeat | voc-auditbeat | Audit/security events | – | backend | host mounts | ES |
| Heartbeat | voc-heartbeat | Availability probes | – | host | – | ES |
| Risk engine | voc-risk-engine | Contextual scoring API | 8000 | backend | – | – |
| MariaDB (GLPI) | voc-mariadb | GLPI DB | – | backend,data | mariadb_data | – |
| GLPI | voc-glpi | ITSM tickets | 8080 | frontend,backend | glpi_config | MariaDB |
| MariaDB (MISP) | voc-misp-db | MISP DB | – | backend,data | misp_db_data | – |
| MISP | voc-misp | Threat intel platform | 8443 | frontend,backend | config.php | misp-db, Redis |
| Celery worker | voc-celery-worker | Pipeline execution | – | backend | logs | RMQ, Redis, ES |
| Celery beat | voc-celery-beat | Schedules + startup scan | – | backend | beat_schedule_data | RMQ |
| Portal | voc-portal | Web UI/API | 4200 | frontend,backend | portal_data | ES |

Beats roles: Filebeat→logs, Metricbeat→metrics, Packetbeat→network telemetry,
Auditbeat→audit events, Heartbeat→availability. Each maps to dashboards; none
is decorative.

## API

Portal (JWT Bearer; interactive OpenAPI at `/docs`):

```
POST /api/login            POST /api/logout         GET  /api/me
GET  /api/dashboard        GET  /api/tickets?scope= POST /api/tickets
POST /api/tickets/{id}/assign|start|solve|reopen|close
GET  /api/assets           GET/PATCH /api/assets/{asset_id}
GET  /api/vulns            GET  /api/vulns/detail?finding_id=...
GET  /api/vulns/detail/history?finding_id=...
GET  /api/vulns/predictions[/validation]             GET /api/vulns/attack-graph
GET  /api/misp/events      POST /api/misp/events    GET /api/glpi/tickets/{id}
GET  /api/infra/queues     GET  /api/infra/es/health
GET  /api/audit?action=&limit=                      GET /api/health
```

Risk engine: `POST /score` (X-API-Key) → `{risk_score, severity, factors,
breakdown{base,threat,exploit,exposure,asset}, risk_factors[]}` · `GET /health`.

## Vulnerability lifecycle

```text
DETECTED → TRIAGED(auto-import) → TICKET_CREATED(GLPI) → ASSIGNED
→ IN_PROGRESS → REMEDIATED(user claim) → RESCAN_PENDING(queued)
→ VERIFICATION(worker sweep)
     ├─ CVE gone     → RESOLVED (resolved_by=scanner) → CLOSED
     └─ CVE present  → REOPENED (ticket + GLPI + ES flipped back, counted)
```
Every transition is audited. Re-detection of a previously-resolved finding by
a scheduled scan also triggers REOPENED automatically (tombstone logic).

## Risk scoring

```
final = min(base + threat + exploit + exposure + asset, 10)

base     = CVSS base score
threat   = KEV(+2.0) + EPSS≥0.5(+1.0) + active MISP context(+2.0)
exploit  = public exploit available (+1.5)
exposure = network_exposure × 2.0   (floor 1.5 when internet-exposed)
asset    = criticality 5 → +50% of CVSS · 4 → +25%
           + production env (+0.5) + attack-path relevance (≤ +1.0)
```
All weights are env-tunable (`RISK_*`). Every response includes a
machine-readable breakdown and a human-readable explanation list, e.g.

```text
CVSS contribution:       7.5   base_score
EPSS 0.70 above 0.50:    +1.0  threat_score
Internet-exposed floor:  +1.5  exposure_score
Criticality 4/5:         +1.88 asset_score
Final Risk:              10/10 CRITICAL
```

## Asset criticality

Assets get criticality **1 Low … 5 Mission Critical**, environment
(development/testing/staging/production), owner, business service, network
zone and internet-exposure flag — edited in the portal Assets tab (audited).
The pipeline feeds these into the risk engine automatically, so the same CVE
scores differently on a dev laptop vs an internet-facing production server.

## SLA

Default budgets (env-configurable): Critical 24 h · High 72 h · Medium 7 d ·
Low 30 d. States `ON_TRACK / DUE_SOON / OVERDUE / COMPLETED / BREACHED`.
Dashboard shows compliance %, overdue, due ≤24 h / ≤72 h, average remediation
time (MTTR).

## Ticket routing

Auto-assignment requires resolution rate > 50 %; highest rate wins, ties
broken by lowest open load. Critical tickets additionally require rate ≥ 70 %
and < 5 open tickets. Every assignment stores a transparent reason:

```text
Assigned to: analyst1
Reason: Resolution rate: 86%; Open tickets: 3; Avg remediation time: 9.4h;
        Eligible for Critical: YES
```

## Threat intelligence

* **NVD** — CPE + version-range aware lookup (no port-only assumptions),
  CWE extraction, Redis-cached, rate-limited.
* **EPSS** (FIRST) — exploitation probability per CVE.
* **CISA KEV** — actively-exploited catalog + ransomware-campaign flag.
* **MISP** — restSearch enrichment of new findings + event publication.
* **OSV / Exploit-DB / VirusTotal** — exploit availability signals.

## NSE active checks ("confirmed" findings)

After each host scan the worker runs a second nmap pass restricted to the
ports already found open, using `--script "vuln and not (dos or intrusive)"`
(detection-only: DoS/intrusive/exploit scripts are excluded). Any VULNERABLE
result is correlated to CVE ids and stored with:

* `confidence: confirmed` + the raw script output as `evidence`
* severity from the script's risk factor, CVSS/CWE filled from NVD

Findings matched only on product/version keep `confidence: potential`.
The Vulnerabilities explorer shows CONFIRMED/potential badges; the detail
modal renders the evidence block. Configure via `NMAP_NSE_VULN_SCAN`,
`NMAP_VULN_SCRIPTS`, `NSE_HOST_TIMEOUT`.

## Attack path

The daily graph (`attack-graph-*`) models **same-subnet network
reachability** between assets observed by the scanner, plus blast radius =
summed risk of reachable critical assets. It is honest about terminology:
edges are reachability, not confirmed exploitability — "Confirmed Attack
Path" claims require an authenticated-scanner finding.

## Forecasting

Weekly ranking of top-N CVEs likely to be exploited within 7 days:
weighted heuristic (EPSS 40 %, percentile 15 %, public exploit 20 %, KEV 10 %,
internal risk 15 %) — a transparent scoring model, not an ML model.
Self-validation stores precision@10 against new KEV entries
(`prediction-validation-*`).

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| ES yellow/red | Disk watermark breach — free space or raise `watermark.high`; replicas auto-set 0 |
| No findings after scan | Wrong `DISCOVERY_SUBNET`, hosts unreachable from container, check `docker logs voc-celery-worker` |
| `enrich rejected missing_scan_id` | Out-of-band payload without valid scan metadata — expected guard |
| GLPI tickets missing | Check `GLPI_APP_TOKEN/USER_TOKEN`, category id exists |
| Verification stuck pending | Scanner unavailable — request keeps `attempts`, check worker logs |
| Portal restart loop `readonly database` | `chown -R 999:999` the `portal_data` volume |

## Security hardening (production recommendations)

Swap portal auth to an IdP/SAML and drop `platform_pass` storage; put TLS in
front of the portal/Kibana/GLPI/MISP (reverse proxy); restrict admin ports to
a management network; set `VOC_SSO_EMBED_CREDENTIALS=false` (default);
rotate secrets quarterly; enable Elasticsearch snapshot backups.

## Backup / Restore

State lives in named volumes: `es_data` (findings/assets/analytics),
`mariadb_data`, `misp_db_data`, `glpi_config`, `redis_data`,
`portal_data` (SQLite users/tickets/audit), `rabbitmq_data`,
`fleet_server_state`. Snapshot ES via its snapshot API, dump MariaDB with
`mysqldump`, copy the volumes. Never back secrets into Git; `.env` stays on
the host. Restore = restore volume contents, then `docker compose up -d`.

## Upgrade

1. Back up volumes (above). 2. `git pull`. 3. Review `.env.example` diff.
4. `docker compose build && docker compose up -d`. Schema changes are applied
idempotently at portal startup (column-level migrations, data preserved).

## Screenshots

*Dashboard:* `docs/img/dashboard.png` *(placeholder)* · *Vulnerability detail:*
`docs/img/vuln-detail.png` *(placeholder)* · *Assets:* `docs/img/assets.png`
*(placeholder)* · *Audit trail:* `docs/img/audit.png` *(placeholder)*
