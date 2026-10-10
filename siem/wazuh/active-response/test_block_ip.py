"""Tests for block-ip.py. Run: python3 -m unittest discover -s siem/wazuh/active-response"""

import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("block_ip", Path(__file__).with_name("block-ip.py"))
block_ip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(block_ip)


def execd(command, srcip, reply="continue"):
    """What Wazuh execd writes to the script's stdin."""
    lines = [json.dumps({
        "version": 1,
        "command": command,
        "parameters": {"alert": {"data": {"srcip": srcip}}},
    })]
    if command == "add":
        lines.append(json.dumps({"version": 1, "command": reply}))
    return io.StringIO("\n".join(lines) + "\n")


class BlockIpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.allowlist = os.path.join(self.tmp.name, "allow")
        block_ip.LOG = os.path.join(self.tmp.name, "ar.log")
        block_ip.ALLOWLIST = self.allowlist
        self.calls = []
        self.rules = set()

        def fake_run(cmd):
            self.calls.append(cmd)
            tool, op, rule = cmd[0], cmd[1], tuple(cmd[2:])
            key = (tool, rule)
            if op == "-C":
                return 0 if key in self.rules else 1
            if op == "-I":
                self.rules.add(key)
            if op == "-D":
                self.rules.discard(key)
            return 0

        block_ip.run = fake_run
        # Capture the check_keys messages the script writes to execd.
        self.real_stdout = block_ip.sys.stdout
        self.sent = block_ip.sys.stdout = io.StringIO()

    def tearDown(self):
        block_ip.sys.stdout = self.real_stdout
        self.tmp.cleanup()

    def inserts(self):
        return [c for c in self.calls if c[1] == "-I"]

    def test_blocks_ipv4(self):
        self.assertEqual(block_ip.main(execd("add", "203.0.113.7")), 0)
        self.assertEqual(self.inserts(), [["iptables", "-I", "INPUT", "-s", "203.0.113.7", "-j", "DROP"]])

    def test_blocks_ipv6_with_ip6tables(self):
        block_ip.main(execd("add", "2001:db8::7"))
        self.assertEqual(self.inserts()[0][0], "ip6tables")

    def test_unblock_removes_rule(self):
        block_ip.main(execd("add", "203.0.113.7"))
        self.assertEqual(block_ip.main(execd("delete", "203.0.113.7")), 0)
        self.assertEqual(self.rules, set())

    def test_does_not_duplicate_rules(self):
        block_ip.main(execd("add", "203.0.113.7"))
        block_ip.main(execd("add", "203.0.113.7"))
        self.assertEqual(len(self.inserts()), 1)

    def test_rejects_ranges_and_junk(self):
        for bad in ["0.0.0.0/0", "0.0.0.0", "127.0.0.1", "::1", "fe80::1",
                    "224.0.0.1", "1.2.3.4; rm -rf /", "", None, "999.1.1.1"]:
            with self.subTest(srcip=bad):
                self.assertEqual(block_ip.main(execd("add", bad)), 1)
        self.assertEqual(self.inserts(), [])

    def test_allowlist_protects_networks(self):
        Path(self.allowlist).write_text("# mgmt\n10.0.0.0/24\n198.51.100.9 # gateway\n")
        for ip in ["10.0.0.25", "198.51.100.9"]:
            with self.subTest(ip=ip):
                self.assertEqual(block_ip.main(execd("add", ip)), 0)
        self.assertEqual(self.inserts(), [])

    def test_abort_from_execd_skips_block(self):
        self.assertEqual(block_ip.main(execd("add", "203.0.113.7", reply="abort")), 0)
        self.assertEqual(self.inserts(), [])

    def test_check_keys_handshake_names_the_ip(self):
        block_ip.main(execd("add", "203.0.113.7"))
        sent = json.loads(self.sent.getvalue())
        self.assertEqual(sent["command"], "check_keys")
        self.assertEqual(sent["parameters"]["keys"], ["203.0.113.7"])

    def test_unknown_command_and_bad_json(self):
        self.assertEqual(block_ip.main(execd("frobnicate", "203.0.113.7")), 1)
        self.assertEqual(block_ip.main(io.StringIO("not json\n")), 1)

    def test_log_lines_cannot_be_forged(self):
        block_ip.main(execd("add", "x\n2026/01/01 00:00:00 block-ip: blocked 6.6.6.6"))
        lines = Path(block_ip.LOG).read_text().splitlines()
        self.assertEqual(len(lines), 1)


if __name__ == "__main__":
    unittest.main()
