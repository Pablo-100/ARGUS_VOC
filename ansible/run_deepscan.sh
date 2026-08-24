#!/bin/bash
# Wrapper ARGUS Deep Scan — lancé par le timer systemd
set -a
source /opt/voc-platform/.env
set +a
cd /opt/voc-platform/ansible
exec /usr/bin/ansible-playbook -i ./inventory.ini ./deepscan.yml \
  -e "scan_profile=${SCAN_PROFILE:-max}" \
  -e "es_user=elastic" \
  -e "es_password=${ELASTIC_PASSWORD}"
