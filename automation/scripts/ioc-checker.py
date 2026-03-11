#!/usr/bin/env python3
"""
ioc-checker.py -- Triage Indicators of Compromise against a local blocklist.

Reads IOCs (IP addresses, domains, file hashes) from a file or stdin and
checks each against a local blocklist. Outputs a triage report showing
matched and unmatched indicators with confidence levels.

Usage:
    python3 ioc-checker.py --ioc-file suspicious.txt --blocklist known-bad.txt
    echo "10.0.50.100" | python3 ioc-checker.py --blocklist known-bad.txt
    python3 ioc-checker.py --ioc-file iocs.txt --blocklist known-bad.txt --format json

Blocklist format (one entry per line):
    10.0.50.100
    evil-domain.example.com
    d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592

Dependencies: Python 3.6+ standard library only.
"""

import argparse
import csv
import io
import json
import re
import sys
from collections import defaultdict


IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def classify_ioc(value):
    """Determine the type of an IOC value."""
    if IPV4_RE.match(value):
        return "ipv4"
    if SHA256_RE.match(value):
        return "sha256"
    if SHA1_RE.match(value):
        return "sha1"
    if MD5_RE.match(value):
        return "md5"
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def load_blocklist(filepath):
    """Load blocklist entries into a set."""
    entries = set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line.lower())
    except FileNotFoundError:
        print("Error: Blocklist not found: {}".format(filepath), file=sys.stderr)
        sys.exit(1)
    return entries


def load_iocs(filepath=None):
    """Load IOCs from file or stdin."""
    iocs = []
    source = sys.stdin if filepath is None else open(filepath, "r", encoding="utf-8")
    try:
        for line in source:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(line)
    finally:
        if filepath is not None:
            source.close()
    return iocs


def check_iocs(iocs, blocklist):
    """Check each IOC against the blocklist."""
    results = []
    for ioc in iocs:
        ioc_type = classify_ioc(ioc)
        matched = ioc.lower() in blocklist
        if matched:
            if ioc_type in ("sha256", "sha1"):
                confidence = "high"
            elif ioc_type in ("md5", "ipv4", "domain"):
                confidence = "medium"
            else:
                confidence = "low"
        else:
            confidence = "n/a"
        results.append({"ioc": ioc, "type": ioc_type, "matched": matched, "confidence": confidence})
    return results


def format_table(results):
    """Format results as a human-readable triage report."""
    matched = [r for r in results if r["matched"]]
    unmatched = [r for r in results if not r["matched"]]
    lines = []
    lines.append("=" * 72)
    lines.append("IOC TRIAGE REPORT")
    lines.append("=" * 72)
    lines.append("")
    lines.append("  Total IOCs checked:  {}".format(len(results)))
    lines.append("  Matched (blocked):   {}".format(len(matched)))
    lines.append("  Unmatched (clean):   {}".format(len(unmatched)))
    lines.append("")
    if matched:
        lines.append("-" * 72)
        lines.append("MATCHED -- Present in blocklist")
        lines.append("  {:<45} {:<10} {:<10}".format("IOC", "Type", "Confidence"))
        lines.append("  {} {} {}".format("-" * 45, "-" * 10, "-" * 10))
        for r in matched:
            lines.append("  {:<45} {:<10} {:<10}".format(r["ioc"], r["type"], r["confidence"]))
        lines.append("")
    if unmatched:
        lines.append("-" * 72)
        lines.append("UNMATCHED -- Not in blocklist")
        lines.append("  {:<45} {:<10}".format("IOC", "Type"))
        lines.append("  {} {}".format("-" * 45, "-" * 10))
        for r in unmatched:
            lines.append("  {:<45} {:<10}".format(r["ioc"], r["type"]))
        lines.append("")
    type_counts = defaultdict(lambda: {"total": 0, "matched": 0})
    for r in results:
        type_counts[r["type"]]["total"] += 1
        if r["matched"]:
            type_counts[r["type"]]["matched"] += 1
    lines.append("-" * 72)
    lines.append("SUMMARY BY TYPE")
    lines.append("  {:<12} {:>8} {:>10} {:>10}".format("Type", "Total", "Matched", "Hit Rate"))
    lines.append("  {} {} {} {}".format("-" * 12, "-" * 8, "-" * 10, "-" * 10))
    for ioc_type, counts in sorted(type_counts.items()):
        rate = "{}%".format(int(counts["matched"] / counts["total"] * 100)) if counts["total"] > 0 else "0%"
        lines.append("  {:<12} {:>8} {:>10} {:>10}".format(ioc_type, counts["total"], counts["matched"], rate))
    lines.append("")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_json(results):
    """Format results as JSON."""
    matched = [r for r in results if r["matched"]]
    unmatched = [r for r in results if not r["matched"]]
    return json.dumps({"total": len(results), "matched_count": len(matched), "unmatched_count": len(unmatched), "matched": matched, "unmatched": unmatched}, indent=2)


def format_csv(results):
    """Format results as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["ioc", "type", "matched", "confidence"])
    writer.writeheader()
    writer.writerows(results)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description="Triage IOCs against a local blocklist.")
    parser.add_argument("--ioc-file", default=None, help="File containing IOCs. Reads stdin if omitted.")
    parser.add_argument("--blocklist", "-b", required=True, help="Path to blocklist file")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output format (default: table)")
    args = parser.parse_args()
    blocklist = load_blocklist(args.blocklist)
    iocs = load_iocs(args.ioc_file)
    if not iocs:
        print("No IOCs provided. Use --ioc-file or pipe via stdin.", file=sys.stderr)
        sys.exit(1)
    results = check_iocs(iocs, blocklist)
    formatters = {"table": format_table, "json": format_json, "csv": format_csv}
    print(formatters[args.format](results))


if __name__ == "__main__":
    main()