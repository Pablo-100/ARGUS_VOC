# 🔑 VOC/ARGUS — Inventaire des identifiants (LOCAL UNIQUEMENT — NE JAMAIS COMMITER)

## Interfaces Web
| Outil | URL | User | Mot de passe |
|---|---|---|---|
| Portail ARGUS | http://192.168.184.135:4200 | admin | voir .env PORTAL_ADMIN_PASSWORD |
| (démo portal) | — | analyst1 / user1 / user2 | voir .env PORTAL_DEMO_PASSWORD |
| Zabbix | http://192.168.184.135:8081 | Admin | voir .env ZABBIX_ADMIN_PASSWORD |
| Shuffle | http://192.168.184.135:3001 | admin | adminadmin |
| Kibana | http://192.168.184.135:5601 | elastic | voir .env ELASTIC_PASSWORD |
| GLPI | http://192.168.184.135:8080 | glpi | glpi |
| MISP | https://192.168.184.135:8443 | admin@voc.local | voir .env MISP_ADMIN_PASSPHRASE |
| RabbitMQ | http://192.168.184.135:15672 | voc | voir .env RABBITMQ_PASS |

## API / Clés
| Service | Clé |
|---|---|
| Elasticsearch | user=elastic, mdp=.env ELASTIC_PASSWORD |
| MISP API | .env MISP_KEY |
| Risk Engine | header X-API-Key = .env RISK_ENGINE_API_KEY |
| Fleet enrollment | .env FLEET_SERVER_TOKEN |

## Bases & Système
| Service | User | Mdp |
|---|---|---|
| MariaDB root | root | .env MARIADB_ROOT_PASSWORD |
| MariaDB GLPI | glpi | .env MARIADB_PASSWORD |
| MariaDB MISP | misp | .env MISP_DB_PASSWORD |
| Redis | (aucun user) | .env REDIS_PASSWORD |
| SSH tbini | tbini / clé serveur | tbini |
| su root tbini | root | tbini |

## Machines du réseau
| Machine | IP | Rôle |
|---|---|---|
| voc-server | 192.168.184.135 | Plateforme (25 conteneurs) |
| tbini | 192.168.184.138 | Agent Fleet + FIM + Deep Scan (Debian 12) |
