# Incident Triage Playbook

**Status:** Active
**Owner:** Steven J. Vik
**Last Updated:** 2026-03-10
**NIST Phase:** Detection & Analysis

## MITRE ATT&CK Mapping

Triage is technique-agnostic -- it applies to any alert. The goal is to classify the event quickly enough to route it to the right specialized playbook, where specific technique mappings apply.

## Trigger Conditions

- SIEM correlation rule fires
- EDR detection alert
- User reports suspicious activity (phishing, unusual behavior, unauthorized access)
- Threat intelligence match (IOC hit on inbound/outbound traffic)
- Automated anomaly detection (baseline deviation)

## 1. Initial Context Collection (5-10 minutes)

Before touching any tool, answer these questions from the alert data alone:

| Field | Source |
|-------|--------|
| Alert name and source | SIEM, EDR, email gateway, user report |
| Affected host(s) | Hostname, IP (e.g., `soc-web-01` / `10.0.0.25`) |
| Affected user(s) | Username, role, privilege level |
| Timestamp and duration | First seen, last seen, ongoing? |
| One-sentence summary | In your own words -- what happened? |

Document this in the ticket immediately. Do not investigate further until context is recorded.

## 2. Severity Classification

| Level | Criteria | Response Time |
|-------|----------|---------------|
| **P1 - Critical** | Active data exfiltration, ransomware execution, compromised admin account | Immediate -- all hands |
| **P2 - High** | Confirmed compromise with limited scope, lateral movement detected | 30 minutes |
| **P3 - Medium** | Suspicious activity requiring investigation, no confirmed impact | 4 hours |
| **P4 - Low** | Informational, likely false positive, policy violation | Next business day |

If uncertain between two levels, classify at the higher severity. Downgrade after investigation, not before.

## 3. Investigation Steps

### 3a. Validate the Alert

- Is this a known false positive? Check tuning notes and previous tickets for this rule.
- Can the alert be correlated with a known change window or maintenance activity?
- Does the alert fire on a single event or a pattern?

### 3b. Enrich with Context

- **Host context:** Is this a server, workstation, or cloud instance? What services does it run? Check asset inventory.
- **User context:** Is this a privileged account? Service account? Has the user reported anything?
- **Network context:** Check recent connections from the host -- any known-bad IPs or unusual destinations?
- **Temporal context:** Has this host or user generated other alerts in the past 24-72 hours?

### 3c. Check for Scope Expansion

- Search SIEM for the same IOCs (IP, hash, domain) across all log sources
- Check if other hosts communicated with the same external destination
- Look for the same user account authenticating from multiple hosts

## 4. Immediate Containment Decision

These are not automatic actions. Each requires a judgment call based on severity and confidence.

| Question | If Yes |
|----------|--------|
| Is a host actively communicating with a known C2? | Isolate the host via EDR |
| Is a compromised account still logged in? | Disable the account, kill active sessions |
| Is malware spreading laterally? | Isolate affected segment, block hash at EDR |
| Is data actively leaving the network? | Block destination at firewall, preserve traffic logs |

**Record every action taken** with timestamp and rationale in the ticket.

## 5. Routing

After triage, route to the appropriate specialized playbook:

| Indicator | Route To |
|-----------|----------|
| Phishing email, malicious link/attachment | [Phishing Response](phishing-response.md) |
| Malware execution, suspicious process, AV detection | [Malware Containment](malware-containment.md) |
| Brute force, impossible travel, privilege escalation | [Unauthorized Access](unauthorized-access.md) |
| None of the above / unclear | Continue investigation, escalate if no progress in 30 minutes |

## 6. Handoff Format

Before escalating or closing, the ticket must contain:

- [ ] One-sentence summary of the alert
- [ ] Affected hosts, users, and timeframe
- [ ] Severity classification with rationale
- [ ] What was investigated and what was found
- [ ] Containment actions taken (if any)
- [ ] Recommended next steps
- [ ] Relevant log queries or artifact references
