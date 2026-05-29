# ec2_enumerate_from_instance

## Description

Simulate post-compromise discovery commands on an AttackLab EC2 instance via SSM. Runs benign enumeration commands (whoami, hostname, curl IMDS role name) that mirror real attacker reconnaissance patterns.

## Stratus Red Team

`aws.discovery.ec2-enumerate-from-instance`

## MITRE ATT&CK

- **T1580** — Cloud Infrastructure Discovery
- **T1082** — System Information Discovery

## Required Permissions

- `ec2:DescribeInstances`
- `ssm:SendCommand`
- `ssm:GetCommandInvocation`
- `ssm:DescribeInstanceInformation`

## CloudTrail Events

- `DescribeInstances`
- `SendCommand`
- `GetCommandInvocation`

## Allowed Commands (strictly enforced)

```python
_DISCOVERY_COMMANDS = [
    "whoami",
    "hostname",
    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]
```

The IMDS curl retrieves the **role name only** — it does not follow up with the credential endpoint.

## Behavior

### dry_run

- Checks `ssm:SendCommand` permission via IAM policy simulation.
- Enumerates AttackLab-tagged instances via `ec2:DescribeInstances` paginator.
- Enumerates SSM-managed instances via `ssm:DescribeInstanceInformation` paginator.
- Cross-references both sets to find eligible targets.
- Reports what would be executed — no commands sent.

### execute

- Safety checks: account allowlist, region allowlist.
- Finds running AttackLab + SSM-managed instances.
- Sends `ssm:SendCommand` with `AWS-RunShellScript` and `_DISCOVERY_COMMANDS`.
- Polls `ssm:GetCommandInvocation` up to **6 attempts with 5s sleep** between each.
- **All stdout/stderr passed through `masking.mask_string()` before recording.**
- Records masked outputs per instance.

### cleanup

SSM commands complete on their own — no state to clean. Returns immediately.

## Detection Notes

- **CloudTrail:** `ssm:SendCommand` with document `AWS-RunShellScript` — unusual if originating from an operator not normally using SSM.
- **GuardDuty:** `UnauthorizedAccess:EC2/SSHBruteForce` may fire if combined with lateral movement; no specific finding for SSM discovery commands.
- **Mitigation:** Restrict `ssm:SendCommand` to specific instance resource tags; enable SSM Session Manager logging to CloudWatch/S3.
