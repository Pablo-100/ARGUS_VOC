#!/bin/bash
# init-es-users.sh - Initialize Elasticsearch user passwords
# This script sets the kibana_system password to match the docker-compose configuration.
# It should be run after Elasticsearch is healthy and the elastic superuser password is set.

set -e

ES_HOST="${ES_HOST:-http://localhost:9200}"
ES_ELASTIC_PASSWORD="${ELASTIC_PASSWORD:?ELASTIC_PASSWORD must be set (refusing insecure default)}"
ES_KIBANA_PASSWORD="${ES_KIBANA_PASSWORD:?ES_KIBANA_PASSWORD must be set (refusing insecure default)}"

echo "Waiting for Elasticsearch to be ready..."
for i in $(seq 1 30); do
    if curl -s -u elastic:"${ES_ELASTIC_PASSWORD}" "${ES_HOST}/_cluster/health" | grep -q '"status"'; then
        echo "Elasticsearch is ready."
        break
    fi
    echo "Waiting... ($i/30)"
    sleep 5
done

echo "Setting kibana_system password..."
curl -s -X POST -u elastic:"${ES_ELASTIC_PASSWORD}" "${ES_HOST}/_security/user/kibana_system/_password" \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"${ES_KIBANA_PASSWORD}\"}"\
    && echo "kibana_system password set successfully." \
    || echo "Failed to set kibana_system password."

echo "Setting voc-kibana password (the user Kibana actually connects as)..."
curl -s -X POST -u elastic:"${ES_ELASTIC_PASSWORD}" "${ES_HOST}/_security/user/voc-kibana/_password" \
    -H 'Content-Type: application/json' \
    -d "{\"password\":\"${ES_KIBANA_PASSWORD}\"}"\
    && echo "voc-kibana password set successfully." \
    || echo "Failed to set voc-kibana password."

echo "Verifying voc-kibana authentication..."
if curl -s -u voc-kibana:"${ES_KIBANA_PASSWORD}" "${ES_HOST}/_cluster/health" | grep -q '"status"'; then
    echo "voc-kibana authentication verified."
else
    echo "WARNING: voc-kibana authentication failed. Check passwords."
fi

echo "ES user initialization complete."