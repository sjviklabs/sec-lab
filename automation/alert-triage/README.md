# Alert triage with Claude

Weekly LLM triage of Wazuh alerts, built so that the SIEM never gets internet access and
the LLM never gets SIEM access.

```
Windows task (weekly)
  └─ ssh soc-export ──► Proxmox node ──► pct exec <wazuh CT> soc_export.py
        forced-command key: one command, one source IP, no forwarding, no pty
  ◄── ~25 KB JSON aggregate (from ~170k alerts/week)
  └─ triage.py ──► Claude API (single call, no tools) ──► markdown report
```

| File | Runs on | Does |
|---|---|---|
| `soc_export.py` | Wazuh manager | Reads 7 days of `ossec-alerts-DD.json.gz` and collapses them to one record per rule: count, level, MITRE ATT&CK IDs, top agents and source IPs, two truncated log samples. Stdlib only, read-only. |
| `triage.py` | Workstation | Fetches the aggregate, sends it to Claude Sonnet 5.5, writes the report. On failure, appends a notice to a note so a dead job is visible. |

## Design choices

- **Aggregate before the LLM.** 172,852 raw alerts become ~8k tokens. Deterministic
  counting is free and exact; the model only gets the judgment work: what matters,
  which rules to tune, and what isn't being watched. Cost is about $0.05 per week.
- **No new network path to the SIEM.** The indexer stays bound to localhost. The only
  access is an SSH key whose `authorized_keys` entry forces one command and is pinned
  to one source IP.
- **Log samples are untrusted.** They are written by monitored hosts, so they are
  attacker-influenced. The model has no tools and its output is only a report, so
  prompt injection can at most distort the text. The system prompt labels the samples
  as data.
- **Secrets.** The API key lives in a dedicated workspace with a spend cap. On the
  workstation it is stored encrypted with Windows DPAPI, and it is never in the repo
  or in shell history.

## Run

```bash
python triage.py --ssh-target soc-export --out-dir ./reports
```
