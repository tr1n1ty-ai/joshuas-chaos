# ec2_steal_instance_credentials

**Category:** credential-access
**MITRE ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**Stratus Red Team:** `aws.credential-access.ec2-steal-instance-credentials`

## Description

Simulates EC2 instance credential theft by using SSM to run a benign command on an
AttackLab-tagged instance that queries the IMDS endpoint for the **IAM role name only**.
Actual credential values are never retrieved.

## What it does

**Dry-run:**
1. Checks `ssm:SendCommand` permission via `iam:SimulatePrincipalPolicy`.
2. Paginates `ec2:DescribeInstances` with `tag:AttackLab=true` filter.
3. Paginates `ssm:DescribeInstanceInformation` for SSM-managed instances.
4. Cross-references to find AttackLab instances that are also SSM-managed.
5. Reports the attack path without executing.

**Execute:**
1. Safety checks: account and region allowlist.
2. Finds running AttackLab instances that are SSM-managed.
3. Sends `AWS-RunShellScript` via SSM with command:
   `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`
4. Polls `ssm:GetCommandInvocation` up to 6 times (5s between attempts).
5. Records the role name returned. **The credential endpoint is never queried.**

## Safety invariant

The IMDS path `/latest/meta-data/iam/security-credentials/` returns only the IAM role
name attached to the instance. A real attacker would follow up with
`/latest/meta-data/iam/security-credentials/{role_name}` to obtain actual temporary
credential values. This module **explicitly does NOT** perform that second step.

## Required permissions

| Permission | Purpose |
|---|---|
| `ec2:DescribeInstances` | Find AttackLab-tagged instances |
| `ssm:SendCommand` | Send IMDS query command |
| `ssm:GetCommandInvocation` | Poll command result |
| `ssm:DescribeInstanceInformation` | Find SSM-managed instances |

## CloudTrail events generated

- `DescribeInstances`
- `SendCommand`
- `GetCommandInvocation`

## Detection notes

- **GuardDuty:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
- **CloudTrail:** `ssm:SendCommand` followed by `sts:GetCallerIdentity` from unexpected IP
