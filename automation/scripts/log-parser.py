#!/usr/bin/env python3
"""
log-parser.py -- Parse auth.log for authentication events.

Extracts failed and successful SSH login attempts from syslog-format
auth.log files. Produces a summary of top offending IPs, targeted
usernames, and a timeline of events.

Usage:
    python3 log-parser.py --file /var/log/auth.log
    python3 log-parser.py --file /var/log/auth.log --format json --top-n 20
    python3 log-parser.py --file auth.log --format csv > report.csv

Output formats: table (default), json, csv

Dependencies: Python 3.6+ standard library only.
"""

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter
from datetime import datetime


FAILED_PASSWORD_RE = re.compile(
    r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:invalid user )?(\S+)\s+from\s+(\S+)"
)

ACCEPTED_RE = re.compile(
    r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted (?:publickey|password) for (\S+)\s+from\s+(\S+)"
)

INVALID_USER_RE = re.compile(
    r"^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid user (\S+)\s+from\s+(\S+)"
)


def parse_log(filepath):
    events = {"failed": [], "accepted": [], "invalid_user": []}
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            match = FAILED_PASSWORD_RE.search(line)
            if match:
                events["failed"].append({"timestamp": match.group(1), "user": match.group(2), "ip": match.group(3), "type": "failed_password"})
                continue
            match = ACCEPTED_RE.search(line)
            if match:
                events["accepted"].append({"timestamp": match.group(1), "user": match.group(2), "ip": match.group(3), "type": "accepted"})
                continue
            match = INVALID_USER_RE.search(line)
            if match:
                events["invalid_user"].append({"timestamp": match.group(1), "user": match.group(2), "ip": match.group(3), "type": "invalid_user"})
    return events


def build_summary(events, top_n):
    failed_ips = Counter(e["ip"] for e in events["failed"])
    failed_users = Counter(e["user"] for e in events["failed"])
    accepted_ips = Counter(e["ip"] for e in events["accepted"])
    invalid_users = Counter(e["user"] for e in events["invalid_user"])
    return {
        "total_failed": len(events["failed"]),
        "total_accepted": len(events["accepted"]),
        "total_invalid_user": len(events["invalid_user"]),
        "unique_failed_ips": len(failed_ips),
        "top_failed_ips": failed_ips.most_common(top_n),
        "top_failed_users": failed_users.most_common(top_n),
        "top_accepted_ips": accepted_ips.most_common(top_n),
        "top_invalid_users": invalid_users.most_common(top_n),
    }


def format_table(summary):
    lines = []
    lines.append("=" * 60)
    lines.append("AUTH LOG ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append("  Total failed login attempts:   {}".format(summary["total_failed"]))
    lines.append("  Total successful logins:       {}".format(summary["total_accepted"]))
    lines.append("  Total invalid user attempts:   {}".format(summary["total_invalid_user"]))
    lines.append("  Unique source IPs (failed):    {}".format(summary["unique_failed_ips"]))
    lines.append("")
    lines.append("-" * 60)
    lines.append("TOP FAILED SOURCE IPs")
    lines.append("  {:<25} {:>10}".format("IP Address", "Attempts"))
    lines.append("  {} {}".format("-" * 25, "-" * 10))
    for ip, count in summary["top_failed_ips"]:
        lines.append("  {:<25} {:>10}".format(ip, count))
    lines.append("")
    lines.append("-" * 60)
    lines.append("TOP TARGETED USERNAMES (failed)")
    lines.append("  {:<25} {:>10}".format("Username", "Attempts"))
    lines.append("  {} {}".format("-" * 25, "-" * 10))
    for user, count in summary["top_failed_users"]:
        lines.append("  {:<25} {:>10}".format(user, count))
    lines.append("")
    lines.append("-" * 60)
    lines.append("SUCCESSFUL LOGIN SOURCES")
    lines.append("  {:<25} {:>10}".format("IP Address", "Logins"))
    lines.append("  {} {}".format("-" * 25, "-" * 10))
    for ip, count in summary["top_accepted_ips"]:
        lines.append("  {:<25} {:>10}".format(ip, count))
    lines.append("")
    if summary["top_invalid_users"]:
        lines.append("-" * 60)
        lines.append("TOP INVALID USERNAMES (reconnaissance)")
        lines.append("  {:<25} {:>10}".format("Username", "Attempts"))
        lines.append("  {} {}".format("-" * 25, "-" * 10))
        for user, count in summary["top_invalid_users"]:
            lines.append("  {:<25} {:>10}".format(user, count))
        lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def format_json(summary):
    output = {
        "total_failed": summary["total_failed"],
        "total_accepted": summary["total_accepted"],
        "total_invalid_user": summary["total_invalid_user"],
        "unique_failed_ips": summary["unique_failed_ips"],
        "top_failed_ips": [{"ip": ip, "count": c} for ip, c in summary["top_failed_ips"]],
        "top_failed_users": [{"user": u, "count": c} for u, c in summary["top_failed_users"]],
        "top_accepted_ips": [{"ip": ip, "count": c} for ip, c in summary["top_accepted_ips"]],
        "top_invalid_users": [{"user": u, "count": c} for u, c in summary["top_invalid_users"]],
    }
    return json.dumps(output, indent=2)


def format_csv(summary):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "key", "value"])
    writer.writerow(["summary", "total_failed", summary["total_failed"]])
    writer.writerow(["summary", "total_accepted", summary["total_accepted"]])
    writer.writerow(["summary", "total_invalid_user", summary["total_invalid_user"]])
    writer.writerow(["summary", "unique_failed_ips", summary["unique_failed_ips"]])
    for ip, count in summary["top_failed_ips"]:
        writer.writerow(["top_failed_ips", ip, count])
    for user, count in summary["top_failed_users"]:
        writer.writerow(["top_failed_users", user, count])
    for ip, count in summary["top_accepted_ips"]:
        writer.writerow(["top_accepted_ips", ip, count])
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(
        description="Parse auth.log for SSH authentication events.",
        epilog="Example: python3 log-parser.py --file /var/log/auth.log --format table",
    )
    parser.add_argument("--file", "-f", required=True, help="Path to auth.log file")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format (default: table)")
    parser.add_argument("--top-n", type=int, default=10, help="Number of top entries to show (default: 10)")
    args = parser.parse_args()
    try:
        events = parse_log(args.file)
    except FileNotFoundError:
        print("Error: File not found: {}".format(args.file), file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("Error: Permission denied: {}".format(args.file), file=sys.stderr)
        sys.exit(1)
    summary = build_summary(events, args.top_n)
    formatters = {"table": format_table, "json": format_json, "csv": format_csv}
    print(formatters[args.format](summary))


if __name__ == "__main__":
    main()