FROM docker.elastic.co/kibana/kibana:8.11.0

COPY --chown=kibana:kibana agent_versions_list.json \
     /usr/share/kibana/x-pack/plugins/fleet/target/agent_versions_list.json

COPY --chown=kibana:kibana kibana.yml /usr/share/kibana/config/kibana.yml
