# Log Correlation Patterns

Multi-source event correlation for detecting attack chains that no single rule catches alone.

## Why Correlation Matters

Individual events are ambiguous. A failed login is noise. A failed login followed by a successful login from a new IP, followed by admin share access on a different host, followed by a large outbound transfer -- that is an attack chain. Correlation connects the dots across log sources and time windows.

The patterns below describe detection logic independent of any specific SIEM. They define the sequence, the join keys, and the time windows. Implementation details (SPL, KQL, YARA-L) are environment-specific.

---

## Pattern 1: Credential Compromise to Lateral Movement

**Chain:** Auth failure burst --> Successful login --> Access to new host

**Logic:**
```
STAGE 1: Brute force signal
  WHERE event_type = "authentication"
    AND outcome = "failure"
    AND count(event) > 10 within 10 minutes
    AND grouped by target_username, source_ip

STAGE 2: Successful login (same account)
  WHERE event_type = "authentication"
    AND outcome = "success"
    AND target_username = STAGE_1.target_username
    AND timestamp within 60 minutes of STAGE_1.last_event

STAGE 3: Lateral movement (same account, different host)
  WHERE event_type IN ("smb_share_access", "rdp_login", "ssh_login")
    AND username = STAGE_1.target_username
    AND destination_host != STAGE_2.host
    AND timestamp within 4 hours of STAGE_2.timestamp
```

**Join key:** `target_username`
**Time window:** Stage 1 to Stage 3 within 4 hours
**Severity:** High if Stage 3 fires, Medium if only Stage 1 + 2

---

## Pattern 2: Phishing to Payload Execution

**Chain:** Email delivery --> User click --> Process execution --> Outbound C2

**Logic:**
```
STAGE 1: Suspicious email delivered
  WHERE event_source = "email_gateway"
    AND verdict IN ("suspicious", "malicious")
    AND action = "delivered"

STAGE 2: URL click or attachment open (same user)
  WHERE event_source IN ("proxy", "edr")
    AND (url IN STAGE_1.extracted_urls
         OR file_hash IN STAGE_1.attachment_hashes)
    AND user = STAGE_1.recipient
    AND timestamp within 24 hours of STAGE_1.timestamp

STAGE 3: Suspicious process execution (same host)
  WHERE event_source = "edr"
    AND parent_process IN ("outlook.exe", "chrome.exe", "firefox.exe", "msedge.exe")
    AND process IN ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe")
    AND host = STAGE_2.host
    AND timestamp within 5 minutes of STAGE_2.timestamp

STAGE 4: Outbound connection to uncategorized/new domain
  WHERE event_source IN ("proxy", "dns", "firewall")
    AND destination NOT IN known_good_domains
    AND source_host = STAGE_3.host
    AND timestamp within 30 minutes of STAGE_3.timestamp
```

**Join keys:** `recipient/user`, `host`, `extracted IOCs`
**Time window:** Stage 1 to Stage 4 within 24 hours
**Severity:** Critical if Stage 4 fires, High at Stage 3

---

## Pattern 3: Privilege Escalation to Data Access

**Chain:** Standard user action --> Privilege gain --> Sensitive data access

**Logic:**
```
STAGE 1: Privilege change detected
  WHERE event_type IN ("group_membership_change", "role_assignment", "sudo_root")
    AND target_user NOT IN admin_whitelist
    AND change NOT IN approved_change_tickets

STAGE 2: Access to sensitive resources (same account)
  WHERE event_type IN ("file_access", "database_query", "share_access")
    AND resource_classification IN ("confidential", "restricted")
    AND user = STAGE_1.target_user
    AND timestamp within 2 hours of STAGE_1.timestamp
    AND user has NO prior access history to this resource

STAGE 3: Data exfiltration signal (same host or account)
  WHERE event_type IN ("large_upload", "usb_write", "email_attachment", "cloud_sync")
    AND data_volume > baseline_threshold
    AND (user = STAGE_1.target_user OR host = STAGE_2.host)
    AND timestamp within 4 hours of STAGE_2.timestamp
```

**Join key:** `target_user`, `host`
**Time window:** Stage 1 to Stage 3 within 6 hours
**Severity:** Critical at Stage 3, High at Stage 2

---

## Pattern 4: Service Account Abuse

**Chain:** Service account interactive login --> Unusual activity --> Persistence

**Logic:**
```
STAGE 1: Service account used interactively
  WHERE event_type = "authentication"
    AND account_type = "service"
    AND logon_type IN ("interactive", "remote_interactive")
    -- Service accounts should never log in interactively

STAGE 2: Unusual activity from service account
  WHERE (event_type = "process_creation"
         AND user = STAGE_1.account
         AND process NOT IN expected_service_processes)
    OR (event_type = "authentication"
         AND user = STAGE_1.account
         AND destination_host NOT IN expected_service_hosts)
    AND timestamp within 2 hours of STAGE_1.timestamp

STAGE 3: Persistence mechanism created
  WHERE event_type IN ("scheduled_task_created", "service_installed", "registry_run_key")
    AND user = STAGE_1.account
    AND timestamp within 4 hours of STAGE_1.timestamp
```

**Join key:** `service account name`
**Time window:** Stage 1 to Stage 3 within 4 hours
**Severity:** High at Stage 1 (service accounts should not log in interactively), Critical at Stage 3

---

## Implementation Notes

- **Lookback windows** should be tuned to your environment. Faster networks and smaller orgs can tighten windows. Larger environments with async log collection may need wider windows.
- **Whitelists** (admin users, known hosts, expected processes) must be maintained as living documents. Stale whitelists create blind spots.
- **Join key reliability** depends on consistent identity across log sources. If your SIEM normalizes `username` differently across sources, correlation breaks silently.
- **Test with red team data.** Correlation rules are hard to validate with production logs alone because real attack chains are rare. Use atomic red team tests or purple team exercises to generate the event sequences.
