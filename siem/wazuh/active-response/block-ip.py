#!/usr/bin/env python3
"""Wazuh active response: drop inbound traffic from an alert's source IP.

Speaks the JSON-over-stdin protocol Wazuh has used since 4.2. (The older
argv form, `block-ip add <user> <ip>`, receives no arguments on 4.2+ and
silently does nothing.)

The source IP comes from log data, which an attacker can influence, so it is
validated before it reaches the firewall:
  * a single address only; CIDR ranges such as 0.0.0.0/0 are rejected
  * never loopback, unspecified, multicast, or link-local
  * never anything listed in the allowlist file

Install on the agent as /var/ossec/active-response/bin/block-ip.py
(root:wazuh, mode 0750) and wire it to a rule whose alerts carry `srcip`,
for example an sshd brute-force rule:

  <command>
    <name>block-ip</name>
    <executable>block-ip.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <active-response>
    <command>block-ip</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>3600</timeout>
  </active-response>

Check the rule ID against your ruleset: grep -n "brute force"
/var/ossec/ruleset/rules/0095-sshd_rules.xml
"""

import ipaddress
import json
import subprocess
import sys
from datetime import datetime

NAME = "block-ip"
LOG = "/var/ossec/logs/active-responses.log"
# One IP or CIDR per line; '#' starts a comment. Put your management
# subnet, gateway, and monitoring hosts here so an alert can never cut you off.
ALLOWLIST = "/var/ossec/etc/lists/block-ip-allowlist"


def log(message):
    # repr() keeps attacker-supplied text on one line in the log.
    line = f"{datetime.now():%Y/%m/%d %H:%M:%S} {NAME}: {message}\n"
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


def load_allowlist(path=None):
    networks = []
    try:
        with open(path or ALLOWLIST, encoding="utf-8") as f:
            for raw in f:
                entry = raw.split("#", 1)[0].strip()
                if not entry:
                    continue
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    log(f"ignoring bad allowlist entry {entry!r}")
    except FileNotFoundError:
        pass
    return networks


def parse_ip(value):
    """Return an address safe to block, or None."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return None
    return ip


def run(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def firewall(ip, command):
    tool = "iptables" if ip.version == 4 else "ip6tables"
    rule = ["INPUT", "-s", str(ip), "-j", "DROP"]
    present = run([tool, "-C", *rule]) == 0
    if command == "add" and not present:
        return run([tool, "-I", *rule])
    if command == "delete":
        # Remove every copy, in case an older script inserted duplicates.
        while run([tool, "-C", *rule]) == 0:
            if run([tool, "-D", *rule]) != 0:
                return 1
    return 0


def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def main(stdin=sys.stdin):
    try:
        msg = json.loads(stdin.readline())
    except (ValueError, TypeError):
        log("could not parse input from execd")
        return 1

    command = msg.get("command")
    alert = (msg.get("parameters") or {}).get("alert") or {}
    raw_ip = (alert.get("data") or {}).get("srcip")

    if command not in ("add", "delete"):
        log(f"unknown command {command!r}")
        return 1

    ip = parse_ip(raw_ip)
    if ip is None:
        log(f"refusing to act on source IP {raw_ip!r}")
        return 1

    if any(ip in net for net in load_allowlist()):
        log(f"{ip} is allowlisted, not blocking")
        return 0

    if command == "add":
        # Stateful handshake: execd answers "abort" if this key is already
        # being handled, so the same IP is not blocked twice.
        send({
            "version": 1,
            "origin": {"name": NAME, "module": "active-response"},
            "command": "check_keys",
            "parameters": {"keys": [str(ip)]},
        })
        try:
            reply = json.loads(stdin.readline())
        except (ValueError, TypeError):
            log("no valid check_keys reply from execd")
            return 1
        if reply.get("command") != "continue":
            log(f"{ip} already handled, aborting")
            return 0

    if firewall(ip, command) != 0:
        log(f"firewall {command} failed for {ip}")
        return 1
    log(f"{'blocked' if command == 'add' else 'unblocked'} {ip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
