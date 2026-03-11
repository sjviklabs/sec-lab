# Hardening

Baseline security configurations for SOC lab infrastructure, inspired by CIS Benchmarks and NIST SP 800-123.

## Approach

**Defense-in-depth.** No single control is sufficient. Every host gets layered hardening: OS baseline, SSH lockdown, firewall rules, audit logging, and continuous validation.

**Configuration as code.** All hardening is enforced via Ansible roles, not manual checklists. Drift is detectable and correctable by re-running the playbook.

**Least privilege by default.** Services run as non-root. Firewalls default-deny. SSH is key-only. Sudo access is explicit and audited.

## Structure

```
hardening/
├── baselines/          # Written hardening guides (the "why" and "what")
│   ├── ssh-hardening.md
│   └── linux-baseline.md
└── ansible-roles/      # Enforceable automation (the "how")
    ├── common/         # Base packages, timezone, core services
    ├── ssh-hardening/  # sshd_config, fail2ban, key-only auth
    └── firewall/       # UFW default-deny + allowlisted ports
```

## Usage

Apply all hardening roles to a host group:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/harden.yml --limit soc-servers
```

Apply a single role:

```bash
ansible-playbook -i inventory/hosts.yml playbooks/harden.yml --tags ssh
```

## Baselines vs. Roles

The `baselines/` docs explain the rationale and expected state for each control. The `ansible-roles/` directories enforce that state. If you're reviewing a host manually, read the baseline. If you're deploying or remediating, run the role.
