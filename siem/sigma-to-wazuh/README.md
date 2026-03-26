# Sigma to Wazuh Conversion

Converting Sigma detection rules to Wazuh format.

## Approach

Sigma rules in `detection/sigma-rules/` define detection logic in a vendor-neutral format. Wazuh uses its own XML rule format with different matching semantics.

The conversion is manual for now. Each Sigma rule maps to one or more Wazuh `<rule>` entries in `local_rules.xml`.

## Mapping Table

| Sigma Rule | Wazuh Rule ID | Coverage |
|------------|---------------|----------|
| `brute-force-auth.yml` | Built-in (5710-5712) | Full - Wazuh has native SSH brute force detection |
| `privilege-escalation-sudo.yml` | 100100, 100101, 100110 | Full - sudo exec, auth failure, sudoers FIM |
| `lateral-movement-smb.yml` | 100120 (SSH variant) | Partial - SSH lateral movement only, no SMB in lab |
| `suspicious-powershell.yml` | N/A | Not applicable - no Windows endpoints in lab |

## Conversion Notes

Sigma's `logsource` maps to Wazuh's `<if_sid>` (parent rule) and `<match>` (pattern). Key differences:

- Sigma uses field-based matching. Wazuh uses regex on the full log line or decoded fields.
- Sigma supports `|contains|all` for AND matching. Wazuh uses multiple `<match>` tags.
- Sigma `filter` sections become Wazuh `<if_sid>` + negated match or separate exclusion rules.
- MITRE ATT&CK mapping is supported natively in both formats.

## Future

If the rule count grows, evaluate `sigma-cli` with the Wazuh backend for automated conversion:
```bash
sigma convert -t wazuh -p wazuh-linux detection/sigma-rules/*.yml
```
