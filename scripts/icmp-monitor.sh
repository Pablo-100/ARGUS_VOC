#!/bin/bash
# ICMP capture script - logs ping results to a file for Filebeat
# Run via cron: * * * * * /opt/voc-platform/scripts/icmp-monitor.sh

LOGFILE="/opt/voc-platform/logs/icmp-monitor.log"
mkdir -p /opt/voc-platform/logs

# Ping known targets
TARGETS="8.8.8.8 1.1.1.1 google.com"

for target in $TARGETS; do
    result=$(ping -c 1 -W 2 "$target" 2>&1)
    if echo "$result" | grep -q "bytes from"; then
        rtt=$(echo "$result" | grep -oP 'time=\K[0-9.]+')
        ttl=$(echo "$result" | grep -oP 'ttl=\K[0-9]+')
        seq=$(echo "$result" | grep -oP 'icmp_seq=\K[0-9]+')
        echo "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"message\":\"ICMP echo reply from $target\",\"icmp.type\":0,\"icmp.code\":0,\"src_ip\":\"$(hostname -I | awk '{print $1}')\",\"dst_ip\":\"$target\",\"network.protocol\":\"icmp\",\"network.transport\":\"ipv4\",\"rtt_ms\":$rtt,\"ttl\":$ttl,\"seq\":$seq,\"log_type\":\"icmp_monitor\",\"platform\":\"voc\"}" >> "$LOGFILE"
    else
        echo "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%S.000Z)\",\"message\":\"ICMP timeout to $target\",\"icmp.type\":8,\"icmp.code\":0,\"src_ip\":\"$(hostname -I | awk '{print $1}')\",\"dst_ip\":\"$target\",\"network.protocol\":\"icmp\",\"network.transport\":\"ipv4\",\"error\":\"timeout\",\"log_type\":\"icmp_monitor\",\"platform\":\"voc\"}" >> "$LOGFILE"
    fi
done
