# Monitoring

Prometheus alerting rules and Grafana dashboards for security-focused observability.

## Purpose

Monitoring in a security context isn't just uptime tracking — it's an early warning system. These configurations prioritize alerts that indicate potential compromise, data exfiltration, or infrastructure degradation that could mask an attack.

## Stack

- **Prometheus** — metrics collection and alerting rules
- **Grafana** — visualization dashboards
- **node_exporter** — host-level metrics (CPU, memory, disk, network)

## Alert Design Principles

1. **Every alert must be actionable.** If the response is "look at it and probably ignore it," the alert shouldn't exist.
2. **Severity drives response time.** Critical = immediate action. Warning = investigate within the hour.
3. **Context in the annotation.** Every alert includes what's wrong, current value, and where to start investigating.
4. **Tune before you deploy.** Thresholds are starting points — adjust based on your baseline.
5. **Security-relevant signals first.** Unusual egress, unexpected reboots, and stale backups matter more than transient CPU spikes.

## Contents

| File | Description |
|------|-------------|
| `prometheus-rules/node-alerts.yml` | Host-level alerts: CPU, memory, disk, network, uptime |
| `prometheus-rules/service-alerts.yml` | Service-level alerts: availability, error rates, SSL, backups |
| `dashboards/soc-overview.json` | Grafana SOC overview dashboard (importable JSON) |
