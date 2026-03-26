# Dashboard Customization

The Wazuh dashboard is an OpenSearch Dashboards fork accessible at `https://wazuh.lan`.

## Default Views

Out of the box, the dashboard includes:
- **Security Events**: Aggregated alerts by severity, agent, rule group
- **Integrity Monitoring**: FIM events across all agents
- **Vulnerability Detection**: CVE scan results per agent
- **SCA (Security Configuration Assessment)**: CIS benchmark compliance scores
- **MITRE ATT&CK**: Alert mapping to the ATT&CK framework

## Custom Dashboards (Planned)

- **Lab Overview**: Single-pane view of all 7 agents with alert counts by severity
- **Lateral Movement Tracker**: SSH logins between internal hosts over time
- **FIM Heatmap**: File change frequency across endpoints

## Access

- URL: `https://wazuh.lan`
- Default admin credentials are generated during install
- Routed through Traefik with `insecureSkipVerify` (self-signed cert)
