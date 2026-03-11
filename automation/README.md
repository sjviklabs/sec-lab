# Automation

Python and Bash scripts for operational security tasks in the SOC lab.

## Purpose

These scripts automate repetitive SOC and sysadmin workflows: log analysis, backup validation, and IOC triage. They use only standard library dependencies — no pip installs required.

## Scripts

| Script | Language | Purpose |
|--------|----------|---------|
| `log-parser.py` | Python 3 | Parse auth.log for failed/successful logins, summarize by IP and user |
| `backup-validator.sh` | Bash | Verify backup recency, size, and optional checksum integrity |
| `ioc-checker.py` | Python 3 | Triage IOCs (IPs, domains, hashes) against a local blocklist |

## Usage

All scripts are standalone and self-documenting:

```bash
# Log analysis
python3 scripts/log-parser.py --file /var/log/auth.log --format table --top-n 10

# Backup validation
bash scripts/backup-validator.sh /backup/daily/ 24

# IOC triage
python3 scripts/ioc-checker.py --ioc-file suspicious.txt --blocklist blocklists/known-bad.txt
```

Run any script with `--help` or `-h` for full usage details.

## Design Principles

- **No external dependencies.** Python stdlib only, POSIX-compatible Bash. These run on any Linux host without setup.
- **Structured output.** All scripts support multiple output formats (table, JSON, CSV) for integration with other tools.
- **Fictional example data.** All IPs, hostnames, and hashes in examples and comments use non-routable or clearly fictional values.
