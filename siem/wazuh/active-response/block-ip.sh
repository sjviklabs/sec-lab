#!/bin/bash
# Active Response: Block IP via iptables
# Triggered by Wazuh when a rule with active-response fires
#
# Usage: Configured in ossec.conf as:
#   <active-response>
#     <command>block-ip</command>
#     <location>local</location>
#     <rules_id>100101</rules_id>
#     <timeout>3600</timeout>
#   </active-response>

ACTION=$1
USER=$2
IP=$3

LOG="/var/ossec/logs/active-responses.log"

if [ -z "$IP" ]; then
    echo "$(date) - No IP provided, exiting" >> "$LOG"
    exit 1
fi

case "$ACTION" in
    add)
        iptables -I INPUT -s "$IP" -j DROP
        echo "$(date) - Blocked $IP" >> "$LOG"
        ;;
    delete)
        iptables -D INPUT -s "$IP" -j DROP
        echo "$(date) - Unblocked $IP" >> "$LOG"
        ;;
    *)
        echo "$(date) - Unknown action: $ACTION" >> "$LOG"
        exit 1
        ;;
esac

exit 0
