# Phishing Response Playbook

**Status:** Active
**Owner:** Steven J. Vik
**Last Updated:** 2026-03-10
**NIST Phase:** Detection & Analysis, Containment

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Spearphishing Attachment | T1566.001 | Malicious file delivered via email |
| Spearphishing Link | T1566.002 | Malicious URL delivered via email |

**Related techniques** (if payload executed): T1204 (User Execution), T1059 (Command and Scripting Interpreter)

## Trigger Conditions

- User reports a suspicious email (phish button, help desk ticket, direct report)
- Email gateway flags inbound message (URL reputation, attachment sandbox, header anomaly)
- EDR detects execution from email client temp directory
- Threat intel match on sender domain or embedded URL

## Severity Classification

| Level | Criteria |
|-------|----------|
| **P1 - Critical** | User executed payload, credentials confirmed stolen, or multiple users affected |
| **P2 - High** | User clicked link and entered credentials (unconfirmed use), or attachment opened |
| **P3 - Medium** | Phishing email delivered, no user interaction confirmed |
| **P4 - Low** | Phishing email blocked by gateway, no delivery |

## Investigation Steps

### 1. Email Header Analysis

Collect from the original message (not a forward -- forwards strip headers):

- **Envelope sender** (MAIL FROM) vs. display name -- mismatch is a strong signal
- **Received headers** -- trace the mail path, identify the originating IP
- **SPF/DKIM/DMARC results** -- did the message pass or fail authentication?
- **Reply-To** -- does it differ from the From address?
- **X-Originating-IP** -- if present, check reputation

### 2. URL and Attachment Analysis

**For URLs:**
- Extract all URLs from the message body and headers (don't click them)
- Check against URL reputation services (VirusTotal, URLScan.io)
- If the URL is live, submit to a sandbox for screenshot and redirect chain analysis
- Check for typosquatting on the domain (e.g., `m1crosoft.com`, `goog1e.com`)

**For Attachments:**
- Calculate file hash (SHA256)
- Submit to sandbox (Any.Run, Joe Sandbox, or local Cuckoo instance)
- Check hash against VirusTotal and threat intel feeds
- Note file type -- `.html`, `.iso`, `.lnk`, `.one` are high-risk

### 3. IOC Extraction

Document all indicators for downstream blocking and hunting:

| IOC Type | Value | Example |
|----------|-------|---------|
| Sender address | Full address | `hr-update@phishdomain.com` |
| Sender domain | Domain only | `phishdomain.com` |
| Reply-To | If different | `collector@evil.com` |
| URLs | Full URL | `https://phishdomain.com/login` |
| Attachment hash | SHA256 | `a1b2c3d4...` |
| Originating IP | Source IP | `203.0.113.50` |

### 4. Scope Assessment -- Mailbox Search

Search for the same message across all mailboxes:

- Match on sender address, subject line, and/or attachment hash
- Identify all recipients and whether they opened/clicked
- Check sent folders for compromised accounts forwarding the phish internally

### 5. Containment

**Immediate (within 15 minutes of confirmation):**
- Block sender address and domain at the email gateway
- Quarantine all matching messages across all mailboxes
- If credential phishing: force password reset on affected users, revoke active sessions
- If payload delivered: pivot to [Malware Containment](malware-containment.md)

**Short-term:**
- Add malicious URLs and domains to DNS sinkhole / web proxy block list
- Add file hashes to EDR block list
- Submit IOCs to threat intel platform (MISP or equivalent)

### 6. User Communication

- Notify affected users that the email was malicious and what action was taken
- If credentials were entered: require password reset, enable MFA if not already active
- If widespread campaign: send org-wide notification describing what to look for
- Do not blame the user. Reporting is the behavior you want to reinforce.

## Handoff Format

Before closing or escalating:

- [ ] Original email preserved (`.eml` format, not screenshot)
- [ ] All IOCs documented in the ticket
- [ ] Number of recipients and confirmed interactions (opened, clicked, submitted creds)
- [ ] Containment actions with timestamps
- [ ] If payload executed: linked malware containment ticket
- [ ] Recommended detection tuning (new gateway rule, Sigma rule, etc.)
