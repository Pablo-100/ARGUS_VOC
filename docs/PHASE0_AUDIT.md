# PHASE 0 - AUDIT BASELINE (internal, 2026-08-23)

## Current state (verified against source + running stack)

### Services
| Service | Image | Host port | Networks | Volume |
|---|---|---|---|---|
| rabbitmq | rabbitmq:3.12-mgmt-alpine | 15672 | backend,data | rabbitmq_data |
| redis | redis:7-alpine | none | backend,data | redis_data |
| elasticsearch | 8.11.0 | 9200 | backend,data | es_data |
| logstash | 8.11.0 | 5044,9600 | backend,data | pipeline ro |
| kibana | voc-kibana:8.11.0 | 5601 | frontend,backend | kibana.yml ro |
| fleet-server | elastic-agent:8.11.0 | 8220 | backend | certs,state |
| risk-engine | ./risk-engine | 8000 | backend | - |
| beats x5 | 8.11.0 | - | backend/host | host mounts |
| mariadb (GLPI) | mariadb:10.6 | none | backend,data | mariadb_data |
| glpi | diouxx/glpi:latest | 8080 | frontend,backend | glpi_config |
| misp-db | mariadb:10.6 | none | backend,data | misp_db_data |
| misp | misp-docker/misp-core:latest | 8443 | frontend,backend | config.php ro |
| celery-worker | ./workers | - | backend NET_RAW | logs |
| celery-beat | ./workers | - | backend | beat_schedule_data |
| portal | ./portal | 4200 | frontend,backend | portal_data |

### Queues
scan, enrich, score, index, ticket.

### Beat schedule
nmap subnet scan every 6h; GLPI sync hourly; attack graph daily 07:00;
prediction Sun 06:00; validation Sun 06:30; DLQ drain every 15min.

### ES indices (Logstash source routing)
vulnerabilities-*, glpi-*, predictions-*, prediction-validation-*,
attack-graph-*, openvas-* (branch exists, no producer), beats data streams.

### Auth
Portal JWT HS256 12h, pbkdf2-120k; roles admin/voc/soc3/soc2/soc1/noc,
capability RBAC server-side. Cross-platform provisioning to ES/RMQ/GLPI/MISP.
risk-engine X-API-Key when configured.

### Lifecycles today
Vulns: nmap diff -> active/resolved docs. Tickets: open->assigned->
in_progress->solved (user click = resolved, NO verification). Auto-import of
risk>=7 findings (dedup_key).

## Gaps vs mandate
1. No asset inventory. 2. Asset criticality not wired into risk engine.
3. No scanner abstraction (logstash openvas branch has no producer).
4. Lifecycle incomplete; no verification-by-rescan; no reopen-on-redetection.
5. No SLA logic. 6. No notifications. 7. Audit minimal (no IP/old/new/login).
8. Dashboard lacks SLA/MTTR/KEV/exposed metrics; trend double-counts docs.
9. No vuln detail page.

## Bugs found
B1 tickets.best_assignee filters role IN ("user","soc") but roles migrated to
   soc1/soc2/soc3/noc/voc -> auto-assignment silently dead.
B2 tasks.score sends constant DEFAULT_NETWORK_EXPOSURE for all findings;
   is_critical_asset never populated upstream.
B3 esdata top_hosts aggregates field "host" but docs use "host_ip" -> empty.
B4 seed.py _source typo "vuln_typo".
B5 vulns severity term filter case-sensitive vs stored "Critical"/"High".
B6 ES cluster RED: disk 91% > high watermark 90% -> unassigned shards;
   packetbeat ~1GB/day unbounded (no ILM).
B7 compose portal env lists ES_URL twice (cosmetic).
B8 datetime.utcnow() deprecated on py3.11 (replace where touched).

## Security issues found
S1 SSO links embed plaintext credentials in URLs -> gate behind flag.
S2 users.platform_pass stores plaintext (needed for reprovisioning); never
   returned by API already; must be documented + SSO gated.
S3 No rate limiting / brute-force protection on /api/login; failures unaudited.
S4 No security headers middleware.
S5 Admin surfaces bound 0.0.0.0 (documented intent) -> make bind configurable,
   document firewall requirements.
S6 Redis command tolerates empty password -> make password mandatory path.
S7 celery-worker root (required by nmap raw sockets) -> cap_drop ALL +
   cap_add NET_RAW.

## Baseline validation (pre-change)
- python -m py_compile workers/risk-engine/portal: OK
- worker unit tests: 21 ran OK (1 skip inside worker image)
- compose ps: 18 services up; ES unhealthy/red (disk watermark), rest healthy
