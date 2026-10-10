#!/usr/bin/env python3
"""Aggregate the last N days of Wazuh alerts into a compact JSON summary.

Runs on the Wazuh manager. Stdlib only, read-only, no network. Raw alerts
(~30 MB/day here) are far too large for an LLM; this collapses them to one
record per rule with counts, agents, source IPs and a couple of samples.

Usage: python3 soc_export.py [--days 7] [--alerts-dir /var/ossec/logs/alerts]
Prints JSON to stdout.
"""
import argparse, collections, datetime as dt, gzip, json, os, sys

SAMPLES = 2
SAMPLE_CHARS = 300
LOW_LEVEL_TOP = 40   # rules below --min-level: keep only the noisiest N
TOP_N = 5            # agents / source IPs listed per rule


def day_files(alerts_dir, days):
    today = dt.date.today()
    for back in range(days, 0, -1):  # complete days only, oldest first
        d = today - dt.timedelta(days=back)
        path = os.path.join(alerts_dir, str(d.year), d.strftime("%b"),
                            "ossec-alerts-%02d.json.gz" % d.day)
        yield d, path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--min-level", type=int, default=7)
    ap.add_argument("--alerts-dir", default="/var/ossec/logs/alerts")
    a = ap.parse_args()

    rules, by_level, by_day, missing = {}, collections.Counter(), {}, []
    total = bad = 0
    for day, path in day_files(a.alerts_dir, a.days):
        if not os.path.exists(path):
            missing.append(str(day))
            continue
        n = 0
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    al = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                n += 1
                r = al.get("rule", {})
                level = int(r.get("level", 0))
                by_level[level] += 1
                rec = rules.get(r.get("id"))
                if rec is None:
                    m = r.get("mitre", {})
                    rec = rules[r.get("id")] = {
                        "rule_id": r.get("id"), "level": level,
                        "description": r.get("description", ""),
                        "groups": r.get("groups", []),
                        "mitre": {k: m.get(k, []) for k in ("id", "tactic", "technique")} if m else {},
                        "count": 0, "first": al.get("timestamp"), "last": None,
                        "agents": collections.Counter(), "srcips": collections.Counter(),
                        "samples": [],
                    }
                rec["count"] += 1
                rec["last"] = al.get("timestamp")
                rec["agents"][al.get("agent", {}).get("name", "?")] += 1
                src = al.get("data", {}).get("srcip")
                if src:
                    rec["srcips"][src] += 1
                if len(rec["samples"]) < SAMPLES and al.get("full_log"):
                    rec["samples"].append(al["full_log"][:SAMPLE_CHARS])
        by_day[str(day)] = n
        total += n

    high = [r for r in rules.values() if r["level"] >= a.min_level]
    low = sorted((r for r in rules.values() if r["level"] < a.min_level),
                 key=lambda r: -r["count"])[:LOW_LEVEL_TOP]
    for r in high + low:
        r["agents"] = dict(r["agents"].most_common(TOP_N))
        r["srcips"] = dict(r["srcips"].most_common(TOP_N))

    json.dump({
        "generated": dt.datetime.now().isoformat(timespec="seconds"),
        "window_days": a.days, "days_missing": missing,
        "total_alerts": total, "unparseable_lines": bad,
        "alerts_per_day": by_day,
        "alerts_by_level": {str(k): v for k, v in sorted(by_level.items())},
        "distinct_rules": len(rules),
        "min_level": a.min_level,
        "rules_at_or_above_min_level": sorted(high, key=lambda r: (-r["level"], -r["count"])),
        "noisiest_low_level_rules": low,
    }, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
