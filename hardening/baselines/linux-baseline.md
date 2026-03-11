# Linux Baseline Hardening Checklist

Minimum security configuration for all SOC lab Linux hosts. Based on CIS Benchmark Level 1 recommendations for Ubuntu/Debian.

---

## 1. Package Management

### Minimal Install
Install only what's needed. Every additional package is additional attack surface.

```bash
# Audit installed packages
dpkg --list | wc -l

# Remove unnecessary packages
apt purge telnet rsh-client rsh-redone-client
```

### Automatic Security Updates
Unattended upgrades ensure critical patches are applied without waiting for a maintenance window.

```bash
apt install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

Verify configuration:

```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
# APT::Periodic::Update-Package-Lists "1";
# APT::Periodic::Unattended-Upgrade "1";
```

---

## 2. User Management

### Least Privilege
- No shared accounts. Every operator gets a named account.
- No direct root login. Use `sudo` with per-user grants.
- Review accounts regularly — disable what's unused.

```bash
# List users with login shells
grep -v '/nologin\|/false' /etc/passwd

# List sudo group members
getent group sudo

# Lock an unused account
usermod -L -e 1 olduser
```

### Sudo Configuration
- Use `/etc/sudoers.d/` drop-ins (not editing sudoers directly)
- Require password for sudo (no `NOPASSWD` except for automation service accounts)
- Log all sudo usage

```bash
# /etc/sudoers.d/analyst
analyst ALL=(ALL) ALL
Defaults:analyst log_output, log_input
```

### Password Policy
Even with SSH key-only auth, local passwords should have sane policies for console access:

```bash
# /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   1
PASS_MIN_LEN    14
PASS_WARN_AGE   14
```

---

## 3. Filesystem

### Mount Options
Restrict executable and setuid behavior on filesystems that don't need it:

```
# /etc/fstab additions
tmpfs  /tmp      tmpfs  defaults,noexec,nosuid,nodev  0 0
tmpfs  /dev/shm  tmpfs  defaults,noexec,nosuid,nodev  0 0
```

### File Permissions Audit
```bash
# Find world-writable files
find / -xdev -type f -perm -o+w -ls

# Find files with no owner
find / -xdev -nouser -o -nogroup

# Find SUID/SGID binaries
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls

# Verify critical file permissions
stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow
# Expected: 644 root:root, 640 root:shadow, 644 root:root, 640 root:shadow
```

---

## 4. Network

### Disable Unnecessary Services
```bash
# List listening services
ss -tlnp

# Disable services not needed on this host
systemctl disable --now cups avahi-daemon
```

### Firewall Defaults
See `ansible-roles/firewall/` for automated enforcement. The baseline policy:

- **Default deny** inbound
- **Default allow** outbound (restrict further in high-security zones)
- **Explicitly allow** only required services (SSH, monitoring agent, application ports)

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw enable
```

### Kernel Network Hardening
```bash
# /etc/sysctl.d/90-network-hardening.conf

# Disable IP forwarding (unless this host is a router)
net.ipv4.ip_forward = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1
```

Apply without reboot:

```bash
sysctl --system
```

---

## 5. Logging

### Retention
Ensure logs survive long enough for incident investigation:

```bash
# /etc/systemd/journald.conf
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=90day
```

```bash
# /etc/logrotate.d/rsyslog — retain 90 days
/var/log/auth.log
/var/log/syslog
{
    rotate 90
    daily
    compress
    delaycompress
    missingok
    notifempty
}
```

### Log Forwarding
Forward logs to a central SIEM/log collector. Without forwarding, a compromised host can destroy its own logs.

```bash
# /etc/rsyslog.d/50-forward.conf
*.* @@soc-siem-01:514
```

Use TCP (`@@`) over UDP (`@`) for reliable delivery. TLS is preferred for production — see rsyslog documentation for `imtcp` with TLS configuration.

---

## 6. Kernel Hardening

Beyond network sysctl settings:

```bash
# /etc/sysctl.d/90-kernel-hardening.conf

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict eBPF
kernel.unprivileged_bpf_disabled = 1

# Restrict ptrace scope (1 = parent process only)
kernel.yama.ptrace_scope = 1

# Restrict kernel module loading after boot (set to 1 after all modules loaded)
# kernel.modules_disabled = 1  # WARNING: irreversible until reboot

# ASLR enabled (should be default)
kernel.randomize_va_space = 2
```

---

## 7. Audit Framework (auditd)

`auditd` provides kernel-level syscall auditing — the last line of defense for detecting privilege escalation, file tampering, and unauthorized access.

```bash
apt install auditd
systemctl enable --now auditd
```

### Key Audit Rules

```bash
# /etc/audit/rules.d/soc-lab.rules

# Monitor authentication files
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# Log all sudo usage
-a always,exit -F path=/usr/bin/sudo -F perm=x -k sudo_usage

# Log privilege escalation attempts
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation

# Log failed file access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access_denied
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access_denied

# Make audit config immutable (requires reboot to change)
-e 2
```

Load rules:

```bash
augenrules --load
```

Query audit log:

```bash
# Recent sudo events
ausearch -k sudo_usage --start recent

# Failed access today
ausearch -k access_denied --start today

# Changes to /etc/passwd
ausearch -k identity -f /etc/passwd
```

---

## Validation

Run a quick compliance check after hardening:

```bash
# Verify no world-writable files in system dirs
find /etc /usr /var -xdev -type f -perm -o+w 2>/dev/null | wc -l
# Expected: 0

# Verify no accounts with empty passwords
awk -F: '($2 == "" ) { print $1 }' /etc/shadow
# Expected: no output

# Verify SSH hardening applied
sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'
# Expected: permitrootlogin no, passwordauthentication no, pubkeyauthentication yes

# Verify firewall active
ufw status verbose

# Verify auditd running
systemctl is-active auditd
```
