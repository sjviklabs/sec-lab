# Agent Enrollment

How to deploy Wazuh agents across the LXC fleet and enroll them with the manager.

## Agent Install (Debian 12)

```bash
# Add Wazuh repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list

# Install agent pinned to manager version
apt-get update
WAZUH_MANAGER="192.168.10.37" apt-get install -y wazuh-agent=4.9.2-1

# Enable and start
systemctl daemon-reload
systemctl enable --now wazuh-agent
```

**Important:** The agent version must match the manager version. Installing a newer agent against an older manager will fail with "Agent version must be lower or equal to manager version."

## Verify Enrollment

From the manager:
```bash
# List all agents
/var/ossec/bin/manage_agents -l

# Check specific agent status
/var/ossec/bin/agent_control -i 001
```

From the agent:
```bash
# Check agent logs for successful connection
tail -20 /var/ossec/logs/ossec.log
```

## Batch Deployment

For deploying across multiple LXCs, prerequisites first:
```bash
# Some minimal LXCs don't have curl or gnupg
apt-get install -y curl gnupg
```

Then run the install block above. The `WAZUH_MANAGER` environment variable sets the manager IP in `ossec.conf` during install, so no manual config editing is needed.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Agent version must be lower or equal" | Agent newer than manager | Pin agent version: `apt-get install wazuh-agent=4.9.2-1` |
| "Invalid server address: MANAGER_IP" | Config has placeholder | `sed -i 's/MANAGER_IP/192.168.10.37/' /var/ossec/etc/ossec.conf` |
| "No such tag 'users'" | Config from newer version | Purge and reinstall with correct version |
| Agent shows "Never connected" | Agent service not running | `systemctl restart wazuh-agent` |
