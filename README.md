# sec-lab

A hands-on security operations lab. IR playbooks, Sigma detection rules, hardening baselines, monitoring configs, and automation scripts, all built around real home lab infrastructure.

This isn't a production SOC. It's a working portfolio of security engineering practices, grounded in NIST, MITRE ATT&CK, and CIS frameworks.

## What's in here

### Playbooks (`playbooks/`)

Four incident response playbooks following the NIST 800-61 lifecycle. Each one maps to MITRE ATT&CK techniques and includes triage criteria, investigation steps, and containment actions.

- Incident Triage (general entry point)
- Phishing Response (T1566)
- Malware Containment (T1059, T1204, T1071)
- Unauthorized Access (T1078, T1110, T1021)

### Detection (`detection/`)

Sigma-format detection rules. Vendor-neutral, version-controlled, testable against log samples before deployment.

- Brute force authentication
- Lateral movement over SMB
- Privilege escalation via sudo
- Suspicious PowerShell execution

Also includes alert correlation patterns and threshold vs. anomaly detection docs.

### Hardening (`hardening/`)

CIS/NIST-inspired baselines with Ansible roles that enforce them. Not just documentation. The roles are runnable.

- SSH hardening (key-only auth, fail2ban, sshd config)
- Firewall (UFW default-deny, allowlisted ports)
- Common baseline (packages, timezone, core services)
- Written guides explaining the rationale for each control

### Monitoring (`monitoring/`)

Prometheus alerting rules and a Grafana SOC overview dashboard. Alerts are security-focused: unusual egress, unexpected reboots, stale backups. Every alert has context annotations and severity classifications.

### Automation (`automation/`)

Python and Bash scripts for SOC workflows. Zero external dependencies.

- `log-parser.py` parses auth.log for failed/successful logins, summarizes by IP
- `backup-validator.sh` checks backup recency, size, and checksum integrity
- `ioc-checker.py` triages IOCs against a local blocklist

### Roadmap (`plans/`)

Tracked next steps: SIEM integration (Wazuh/ELK), honeypot deployment, threat intel feeds via MISP, purple team exercises with Atomic Red Team, network traffic analysis, vulnerability scanning, and forensics toolkit buildout.

## CI

A GitHub Actions workflow runs markdownlint on PRs and pushes to main.

## License

[MIT](LICENSE)
