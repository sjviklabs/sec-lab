# sec-lab — Claude memory

## What this repo is

The SJVIK SOC lab — Wazuh SIEM, custom Sigma detection rules mapped to MITRE ATT&CK, IR playbooks, hardening baselines. Running on a live 3-node Proxmox cluster.

This is a **public artifact repo** (Tier 1 standalone per REPO-STANDARD §7). Useful as a tool whether or not anyone reads any SJVIK Labs book. Backs the SOC analyst products (Bundle, Interview Kit, Cheat Sheet) and the Field Manual where SOC content appears.

## Directory layout

| Folder | Purpose |
|---|---|
| `siem/` | Wazuh deployment configs |
| `detection/` | Sigma rules (per MITRE technique) |
| `playbooks/` | IR runbooks and walkthroughs |
| `hardening/` | OS + service baselines |
| `monitoring/` | Telemetry + dashboard configs |
| `automation/` | Triage / response scripts (Python + Shell) |
| `plans/` | Roadmap and phase planning |

## Conventions

- **Sigma rules:** YAML, named per MITRE technique ID (e.g., `t1059_001_powershell_encoded_command.yml`)
- **Detection metadata:** every rule has `tags:` for `attack.<tactic>.<technique>` mapping
- **IR playbooks:** Markdown, structured as Triage → Containment → Eradication → Recovery → Lessons
- **Languages:** ~72% Python, ~28% Shell. snake_case for Python, lowercase-with-dashes for shell scripts.
- **Conventional Commits** (`feat:`, `fix:`, `docs:`, `chore:`)

## Common commands

- Lint Sigma rules: `python scripts/lint_sigma.py detection/` (when present)
- Run automation tests: `python -m pytest automation/`
- Markdown lint: `markdownlint **/*.md`

## OPSEC note

This repo is public. Do not commit:
- Live IP addresses tied to operational SJVIK NOC infrastructure (the <LAB_NETWORK>.x range)
- Internal hostnames (`*.lan`)
- Wazuh API keys, agent enrollment passwords, or auth tokens
- Customer or client log data

If a Sigma rule's specificity would expose proprietary infrastructure layout, sanitize to placeholders or keep it in the private `infra-docs` repo instead.

## Cross-repo

- Full Ansible IaC for the cluster: private `sjviklabs/infra-ansible` (curated public slice in `sjviklabs/infra-roles-public`)
- NOC state docs: private `sjviklabs/infra-docs`
- Planning hub: private `sjviklabs/noc-planning` (also `~/.claude/`)
- Companion code for the SOC books: `sjviklabs/books-companion` (when public)

## Standard

Per [SJVIK Labs Repo Standard](https://github.com/sjviklabs/.github) §1 + §9:
- **Status:** Stable (v1.0.0)
- License: MIT
- Branch protection on `main` (no force-push, no deletion)
- Dependabot + secret scanning + push protection enabled
