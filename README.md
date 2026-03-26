# SJV SOC Lab

Cybersecurity lab and portfolio built on a self-hosted Proxmox cluster. Running Wazuh SIEM with 7 monitored endpoints, custom detection rules mapped to MITRE ATT&CK, and incident response playbooks.

## What's Here

- **[siem/](siem/)** - Wazuh SIEM deployment, custom rules, agent enrollment, Sigma-to-Wazuh conversion
- **[playbooks/](playbooks/)** - Incident response playbooks for common scenarios
- **[detection/](detection/)** - Sigma detection rules and alert logic
- **[hardening/](hardening/)** - OS and service hardening baselines
- **[monitoring/](monitoring/)** - Infrastructure monitoring notes
- **[automation/](automation/)** - Scripts for log triage and response
- **[plans/](plans/)** - Roadmap for lab expansion

## Lab Stack

| Component | Details |
|-----------|---------|
| SIEM | Wazuh 4.9.2 all-in-one (manager + indexer + dashboard) |
| Endpoints | 7 Debian 12 LXC containers on Proxmox |
| Detection | Built-in rules + custom rules with MITRE ATT&CK mapping |
| Alerting | Email via msmtp/Gmail for high-severity events |
| Monitoring | Grafana + Prometheus (infra), Wazuh (security) |

This is a working lab, not a production environment. Everything here is built for learning and demonstrating real skills.
