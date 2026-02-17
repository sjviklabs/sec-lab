# Initial Incident Triage Playbook

Status: Draft  
Owner: Steven J. Vik  
Last updated: 2026-02-16

## 1. Trigger

This playbook is used when a new security alert or ticket is created, for example:

- SIEM correlation rule fires
- EDR detects suspicious activity
- User reports phishing or suspicious behavior

## 2. Collect basic context (5–10 minutes)

For each new alert, collect at least:

- Alert source and name (SIEM rule, EDR detection, email report)
- Affected host(s) and user(s)
- Time range of suspicious activity
- High-level description in your own words

Document this in the ticket before doing deeper analysis.

## 3. Quick severity assessment

Classify the alert as:

- **Informational** – no clear security impact, likely noise
- **Suspicious** – requires more investigation, but impact unknown
- **Confirmed incident** – clear evidence of compromise or policy violation

If severity is “confirmed incident”, escalate according to your IR plan.

## 4. Immediate containment questions

Ask:

- Do we need to isolate a host now?
- Do we need to disable an account now?
- Do we need to block an IP, domain, or hash now?

If the answer is “yes” and you have authority, take the action and record it in the ticket.

## 5. Hand-off / next steps

At the end of triage, make sure the ticket includes:

- Summary of what triggered the alert
- What you checked
- Current severity
- Any containment actions taken
- Recommended next steps (monitor, escalate, close)

This playbook will evolve as I learn and practice more incident response.

