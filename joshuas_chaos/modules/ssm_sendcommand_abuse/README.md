# ssm_sendcommand_abuse

**Category:** execution  
**MITRE ATT&CK:** T1651

## Description

Lists SSM managed instances and assesses `SendCommand` risk. Execute sends
only `whoami` and `hostname` to AttackLab-tagged instances.

## Safety

- Only targets instances tagged `AttackLab=true`
- Allowed commands: `whoami`, `hostname` ONLY
- No reverse shells, download cradles, or credential commands

## Detection

- CloudTrail: `ssm:SendCommand`
- CloudWatch SSM log group output
