# Unauthorized Access Playbook

**Status:** Active
**Owner:** Steven J. Vik
**Last Updated:** 2026-03-10
**NIST Phase:** Detection & Analysis, Containment

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Valid Accounts | T1078 | Adversary uses legitimate credentials |
| Brute Force | T1110 | Password guessing, spraying, or credential stuffing |
| Remote Services | T1021 | Lateral movement via RDP, SSH, SMB, WinRM |

**Related techniques:** T1098 (Account Manipulation), T1136 (Create Account), T1548 (Abuse Elevation Control Mechanism)

## Trigger Conditions

- **Impossible travel:** Same account authenticates from geographically distant locations within an impossible timeframe
- **Brute force alert:** Threshold exceeded for failed authentication attempts against one or more accounts
- **Privilege escalation:** User gains admin or root access outside of approved change process
- **Off-hours access:** Authentication to sensitive systems outside normal working hours
- **New device or location:** Account used from an unrecognized device, IP, or geolocation
- **Service account anomaly:** Interactive login from a service account, or service account used from unexpected host

## Severity Classification

| Level | Criteria |
|-------|----------|
| **P1 - Critical** | Admin/root account compromised, domain controller accessed, or active lateral movement |
| **P2 - High** | Confirmed unauthorized login to any account, or privilege escalation outside change control |
| **P3 - Medium** | Brute force in progress (no success confirmed), impossible travel on standard user |
| **P4 - Low** | Failed login spike from single source (likely automated scan), no successful auth |

## Investigation Steps

### 1. Account Lockdown

**If unauthorized access is confirmed (not suspected):**
- Disable the account immediately
- Revoke all active sessions and tokens (OAuth, SSO, VPN)
- Revoke API keys associated with the account
- If service account: assess impact of disabling before acting (document the decision either way)

**If suspected but unconfirmed:**
- Do not disable yet -- forced lockout tips off the attacker and may cause business disruption
- Force MFA re-enrollment or step-up authentication
- Monitor the account in real time

### 2. Session Review

- List all active and recent sessions for the account (last 72 hours)
- Identify source IPs, geolocations, device fingerprints, and user agents
- Check VPN logs: was a VPN used to appear internal?
- Check SSO/IdP logs: what applications did the account access during the suspicious session?
- Look for session token reuse from multiple IPs (session hijacking indicator)

### 3. Authentication Log Analysis

**Questions to answer:**
- When did the unauthorized access start? (First anomalous login, not first alert)
- Was there a brute force or spray pattern before the successful login?
- Did the attacker authenticate with the correct password on the first attempt? (Credential dump likely)
- What authentication method was used? (Password, SSO, API key, certificate)
- Was MFA bypassed, and if so, how? (MFA fatigue, SIM swap, token theft)

**Log sources:**
- Active Directory / LDAP authentication logs
- SSO/IdP logs (Entra ID, Okta, etc.)
- VPN gateway logs
- Application-specific auth logs
- Linux: `/var/log/auth.log`, `/var/log/secure`, journal

### 4. Lateral Movement Check

- From the compromised account, what other systems were accessed?
- Were any new accounts created or existing accounts modified?
- Check for RDP, SSH, SMB, or WinRM connections originating from the compromised session
- Search for the source IP across all log sources -- the attacker may have used multiple accounts
- Check for Kerberos ticket anomalies (pass-the-ticket, golden ticket) if AD environment

### 5. Credential Reset and Hardening

- Reset password for the compromised account (generate, do not let user choose)
- Reset passwords for any account that shares credentials (yes, this happens)
- Rotate API keys and secrets associated with the account
- Enable or re-enroll MFA
- Review and remove any unauthorized MFA devices, app passwords, or recovery options
- If admin account: rotate the KRBTGT password twice (if AD compromise suspected)

### 6. Access Audit

- Review what the account has access to -- was any sensitive data accessed or exfiltrated?
- Check file access logs, database query logs, email forwarding rules, cloud storage downloads
- Review any changes made during the unauthorized session (group membership, permissions, configurations)
- Check for persistence: new SSH keys, scheduled tasks, forwarding rules, OAuth app grants

## Escalation Criteria

Escalate to full incident response if any of the following are true:

- Admin or root account was compromised
- Lateral movement is confirmed
- Data exfiltration is suspected or confirmed
- Attacker created new accounts or modified group memberships
- The access vector is unknown (how did they get the credentials?)
- Multiple accounts are compromised (coordinated attack)

## Handoff Format

Before closing or escalating:

- [ ] Compromised account(s) identified and secured
- [ ] Timeline of unauthorized access (first login through last observed activity)
- [ ] Access vector determined (brute force, credential dump, phishing, session hijack, etc.)
- [ ] Scope: what systems and data were accessed
- [ ] All containment actions with timestamps
- [ ] Lateral movement assessment (confirmed/ruled out)
- [ ] Credential reset confirmation
- [ ] Recommended hardening (MFA gaps, password policy, monitoring gaps)
