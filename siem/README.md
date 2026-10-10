# SIEM Integration

Wazuh 4.9.2 all-in-one deployment running on a Proxmox LXC, collecting events from 7 endpoints across the lab.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Wazuh Manager                       │
│          LXC 107 · <WAZUH_MANAGER_IP> · wazuh.example.local        │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Manager  │  │ Indexer  │  │    Dashboard     │   │
│  │ (1514)   │  │ (9200)   │  │    (443/HTTPS)   │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
└─────────────────┬───────────────────────────────────┘
                  │ Agent enrollment (1515)
      ┌───────────┼───────────┬──────────────┐
      │           │           │              │
  ┌───┴───┐  ┌───┴───┐  ┌───┴───┐    ┌────┴────┐
  │nx-web │  │monitor│  │adguard│    │ + 4 more│
  │  -01  │  │       │  │       │    │  agents │
  └───────┘  └───────┘  └───────┘    └─────────┘
```

## What's Deployed

| Component | Version | Location |
|-----------|---------|----------|
| Wazuh Manager | 4.9.2 | LXC 107 (all-in-one) |
| Wazuh Indexer | 4.9.2 | Same LXC (OpenSearch) |
| Wazuh Dashboard | 4.9.2 | https://wazuh.example.local |
| Agents | 4.9.2 | 7 LXC endpoints |

## Agents

| Agent | VMID | Host | Priority |
|-------|------|------|----------|
| nx-web-01 | 101 | Web services | High |
| monitor | 105 | Grafana/Prometheus | High |
| syncthing | 102 | Vault data sync | Medium |
| adguard | 100 | DNS | Medium |
| traefik | 104 | Reverse proxy | Medium |
| uptime-kuma | 108 | Availability monitoring | Low |
| 5etools | 106 | D&D reference | Low |

## Detection Coverage

Out of the box:
- File Integrity Monitoring (FIM) on /etc, /root, /home
- Rootkit detection
- SSH brute force detection
- Log analysis (syslog, auth.log, dpkg.log)
- Vulnerability detection (CVE scanning)
- CIS Debian 12 benchmark (SCA)

Custom rules (see `wazuh/local_rules.xml`):
- Sudo privilege escalation (100100-100101)
- Sudoers file modification via FIM (100110)
- Internal SSH lateral movement (100120)
- Critical service state changes (100130)

## Directory Structure

```
siem/
├── README.md                    # This file
├── wazuh/
│   ├── deployment-guide.md      # Step-by-step LXC + Wazuh install
│   ├── agent-enrollment.md      # Agent deployment across fleet
│   ├── local_rules.xml          # Custom detection rules
│   └── active-response/
│       ├── block-ip.py          # Active response: block an alert's source IP
│       └── test_block_ip.py     # Unit tests (python3 -m unittest)
├── sigma-to-wazuh/
│   ├── README.md                # Conversion methodology
│   └── converted-rules/        # Wazuh rules from Sigma
└── dashboards/
    └── README.md                # Dashboard customization notes
```

## Related

- [Detection Rules](../detection/) - Sigma rules that map to the custom Wazuh rules
- [Monitoring](../monitoring/) - Prometheus/Grafana infra monitoring (separate from security monitoring)
- [Playbooks](../playbooks/) - IR procedures that reference SIEM alerts
