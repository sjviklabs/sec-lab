# Wazuh Deployment Guide

How the Wazuh all-in-one (manager + indexer + dashboard) was deployed on a Proxmox LXC.

## Prerequisites

- Proxmox VE 8.x with available resources (2 CPU, 4GB RAM, 32GB disk)
- Debian 12 LXC template
- Network connectivity between all endpoints

## Step 1: Create the LXC

```bash
pct create 107 local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst \
  --hostname wazuh \
  --cores 2 \
  --memory 4096 \
  --swap 512 \
  --rootfs local-lvm:32 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.10.37/24,gw=192.168.10.1 \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
```

## Step 2: Prepare the OS

```bash
apt-get update && apt-get install -y curl sudo openssh-server
systemctl enable --now sshd
```

## Step 3: Install Wazuh All-in-One

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
bash wazuh-install.sh -a
```

This installs:
- **Wazuh Manager** (event collection, rule engine, active response) on port 1514
- **Wazuh Indexer** (OpenSearch-based log storage) on port 9200
- **Wazuh Dashboard** (web UI) on port 443

The installer outputs the admin password. Save it.

## Step 4: Post-Install Configuration

### DNS (AdGuard)
Add rewrite: `wazuh.lan` -> `192.168.10.37`

### Reverse Proxy (Traefik)
Add router and service for `wazuh.lan` pointing to `https://192.168.10.37:443`.
Requires `insecureSkipVerify` since Wazuh uses self-signed TLS.

### SSH Hardening
```bash
apt-get install -y fail2ban unattended-upgrades
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd
```

### Monitoring (Uptime Kuma)
Add HTTP monitor for `https://192.168.10.37:443` with TLS verification disabled.

### Email Alerting
```bash
apt-get install -y msmtp msmtp-mta
```

Configure `/etc/msmtprc` with SMTP credentials. Wazuh uses `/usr/sbin/sendmail` which msmtp-mta provides.

Enable in `/var/ossec/etc/ossec.conf`:
```xml
<email_notification>yes</email_notification>
<smtp_server>localhost</smtp_server>
<email_from>alerts@yourdomain.com</email_from>
<email_to>you@yourdomain.com</email_to>
```

## Step 5: Verify

```bash
# Dashboard responds
curl -sk https://wazuh.lan

# Manager is running
systemctl is-active wazuh-manager

# Check enrolled agents
/var/ossec/bin/agent_control -l
```

## Resource Usage

After full deployment with 7 agents:
- Manager LXC: ~1.5GB RAM, minimal CPU at idle
- Each agent: ~50MB RAM on the endpoint
