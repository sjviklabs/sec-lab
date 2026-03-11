# Incident Response Playbooks

Structured response procedures for common security incidents, built around NIST 800-61 (Computer Security Incident Handling Guide).

## Methodology

Each playbook follows the NIST incident response lifecycle:

1. **Preparation** -- tooling, access, and documentation ready before an incident
2. **Detection & Analysis** -- triage the alert, confirm scope, classify severity
3. **Containment, Eradication & Recovery** -- stop the bleeding, remove the threat, restore operations
4. **Post-Incident Activity** -- lessons learned, detection tuning, documentation

Playbooks are not scripts. They are decision frameworks -- a practitioner uses them to stay structured under pressure, not to replace judgment. Every incident has context that a checklist cannot anticipate.

## Template Rationale

Each playbook includes:

- **MITRE ATT&CK mapping** -- ties the incident type to known adversary behavior, which drives investigation priorities and detection coverage gaps
- **Trigger conditions** -- what fires this playbook (alert source, user report, automated detection)
- **Severity classification** -- consistent language across the team for escalation decisions
- **Investigation steps** -- ordered by priority, not exhaustiveness
- **Containment and remediation** -- actions with explicit decision criteria (when to isolate, when to monitor)
- **Handoff format** -- what the ticket must contain before escalation or closure

## Playbooks

| Playbook | MITRE Techniques | Status |
|----------|-----------------|--------|
| [Incident Triage](incident-triage.md) | General | Active |
| [Phishing Response](phishing-response.md) | T1566.001, T1566.002 | Active |
| [Malware Containment](malware-containment.md) | T1059, T1204, T1071 | Active |
| [Unauthorized Access](unauthorized-access.md) | T1078, T1110, T1021 | Active |

## Usage

Start with **Incident Triage** for any new alert. It determines severity and routes to the appropriate specialized playbook. Specialized playbooks assume triage is complete.
