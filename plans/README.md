# Roadmap

Where this lab is headed. Each item is scoped, justified, and tracked.

---

## SIEM Integration

**What:** Deploy Wazuh or ELK stack for centralized log aggregation, correlation, and search.

**Why:** Individual host logs don't tell the full story. A SIEM turns scattered events into correlated incidents and enables historical threat hunting.

**Status:** Complete (Wazuh 4.9.2, 7 agents, custom rules, email alerting)

---

## Honeypot Deployment

**What:** Deploy Cowrie (SSH honeypot) and evaluate T-Pot for broader protocol coverage.

**Why:** Honeypots generate high-fidelity alerts with near-zero false positives. Any interaction is suspicious by definition — useful for detecting lateral movement and external scanning.

**Status:** Researching

---

## Threat Intelligence Feeds

**What:** Stand up MISP for threat intel management with automated IOC ingestion from public feeds (Abuse.ch, AlienVault OTX).

**Why:** Detection rules are only as good as the indicators behind them. Automated feed ingestion keeps signature-based detections current without manual curation.

**Status:** Planned

---

## Purple Team Exercises

**What:** Run Atomic Red Team tests mapped directly to detection rules — validate that alerts fire when attacks execute.

**Why:** A detection rule that has never been tested is a hypothesis, not a control. Purple teaming closes the loop between offense and defense.

**Status:** Planned

---

## Network Traffic Analysis

**What:** Deploy Zeek and/or Suricata for passive network monitoring, PCAP analysis, and signature-based IDS.

**Why:** Host-based telemetry misses network-level indicators — C2 beaconing patterns, DNS tunneling, lateral movement over SMB. Network visibility fills that gap.

**Status:** Researching

---

## Vulnerability Management

**What:** Schedule regular OpenVAS/Greenbone scans against lab targets with tracked remediation.

**Why:** You can't defend what you haven't inventoried. Scheduled scanning catches misconfigurations and missing patches before an attacker does.

**Status:** Not Started

---

## Forensics Toolkit

**What:** Build a DFIR script library — disk imaging workflows, log collection scripts, memory analysis with Volatility.

**Why:** Incident response speed depends on having tools and procedures ready before the incident. A cold-start forensics effort loses evidence.

**Status:** Not Started

---

## Lab Environment as Code

**What:** Define practice targets (vulnerable VMs, attack scenarios) as Terraform and/or Vagrant configurations.

**Why:** Reproducible environments mean repeatable testing. Tear down and rebuild a compromised target in minutes instead of hours.

**Status:** Not Started

---

## CI/CD Security Pipeline

**What:** Integrate SAST (Semgrep, Bandit) and DAST (ZAP) scanning into a CI/CD pipeline for lab tooling and scripts.

**Why:** Shift-left security applied to the lab's own code. Catches hardcoded secrets, injection flaws, and dependency vulnerabilities before deployment.

**Status:** Not Started

---

## Compliance Mapping

**What:** Map all implemented controls (hardening baselines, alerting rules, access policies) to NIST 800-53 and CIS Benchmarks.

**Why:** Controls without framework mapping are hard to communicate to auditors, hiring managers, and teams. Mapping demonstrates structured thinking, not just technical skill.

**Status:** Planned
