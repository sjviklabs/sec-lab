# SSH Hardening Guide

Secure SSH configuration for SOC lab hosts. Based on CIS Benchmark recommendations for OpenSSH Server.

---

## 1. Disable Root Login

Direct root login over SSH is unnecessary when `sudo` is configured properly. Disabling it eliminates the most targeted username in brute-force attacks.

```
PermitRootLogin no
```

## 2. Disable Password Authentication

Password auth is vulnerable to brute-force and credential stuffing. Key-only authentication eliminates this attack surface entirely.

```
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
```

## 3. Key-Only Authentication (Ed25519)

Ed25519 keys are preferred — shorter, faster, and more resistant to side-channel attacks than RSA.

Generate a key pair:

```bash
ssh-keygen -t ed25519 -C "analyst@soc-lab" -f ~/.ssh/id_ed25519_soc
```

Deploy the public key:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519_soc.pub analyst@soc-web-01
```

Restrict accepted key types in `sshd_config`:

```
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
```

## 4. Restrict Allowed Users and Groups

Limit SSH access to explicitly authorized accounts. This prevents service accounts or unused user accounts from being leveraged.

```
AllowGroups ssh-users
# Or restrict to specific users:
# AllowUsers analyst deployer
```

Ensure the group exists and only intended users are members:

```bash
groupadd ssh-users
usermod -aG ssh-users analyst
```

## 5. Non-Default Port

Changing the SSH port reduces noise from automated scanners. It is **not** a security control — it's an operational convenience that reduces log volume.

```
Port 2222
```

**Trade-offs:**
- Reduces automated scan noise significantly (less log clutter, fewer fail2ban triggers)
- Adds friction for legitimate users (must specify port every time)
- Does not stop targeted attackers — port scanning reveals the service trivially
- Can break tooling that assumes port 22
- Must be reflected in firewall rules, monitoring, and documentation

**Recommendation:** Use a non-default port in internet-facing environments. For internal lab networks, port 22 is fine — focus hardening effort on authentication controls instead.

## 6. Session and Authentication Limits

Restrict brute-force windows and detect abandoned sessions:

```
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 3
MaxStartups 10:30:60

ClientAliveInterval 300
ClientAliveCountMax 2
```

| Setting | Purpose |
|---------|---------|
| `MaxAuthTries 3` | Lock out after 3 failed attempts per connection |
| `LoginGraceTime 30` | Close unauthenticated connections after 30 seconds |
| `MaxSessions 3` | Limit multiplexed sessions per connection |
| `MaxStartups 10:30:60` | Rate-limit unauthenticated connections |
| `ClientAliveInterval 300` | Send keepalive every 5 minutes |
| `ClientAliveCountMax 2` | Disconnect after 2 missed keepalives (10 min idle timeout) |

## 7. Fail2ban Integration

Fail2ban monitors auth logs and bans IPs after repeated failures. It complements `MaxAuthTries` by operating at the network level.

```ini
# /etc/fail2ban/jail.d/sshd.conf
[sshd]
enabled  = true
port     = 2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
```

This bans an IP for 1 hour after 3 failures within 10 minutes.

Verify bans:

```bash
fail2ban-client status sshd
```

## 8. Audit Logging

Ensure SSH events are captured for incident investigation:

```
LogLevel VERBOSE
SyslogFacility AUTH
```

`VERBOSE` logging records key fingerprints on login — critical for identifying which key was used when multiple are authorized.

Forward SSH logs to your SIEM (see `linux-baseline.md` for log forwarding configuration).

## 9. Additional Hardening

Disable features that are rarely needed and expand attack surface:

```
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
Banner /etc/ssh/banner.txt
```

## 10. Testing and Validation

After applying changes, validate before closing your current session:

```bash
# Test config syntax (catch errors before restart)
sshd -t

# Restart sshd
systemctl restart sshd

# From another terminal — verify you can still log in
ssh -p 2222 analyst@soc-web-01

# Verify password auth is rejected
ssh -p 2222 -o PubkeyAuthentication=no analyst@soc-web-01
# Expected: Permission denied (publickey)

# Verify root login is rejected
ssh -p 2222 root@soc-web-01
# Expected: Permission denied (publickey)

# Check listening port
ss -tlnp | grep sshd
```

**Never close your current SSH session until you've confirmed you can open a new one.** If the config is broken and you disconnect, you'll need console access to recover.
