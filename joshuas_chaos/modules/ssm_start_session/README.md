# ssm_start_session

## Description

Detect if principal has `ssm:StartSession` permission and enumerate SSM-managed instances that could be targeted for interactive shell access. **Dry-run only** — interactive sessions cannot be safely automated.

## MITRE ATT&CK

- **T1021.007** — Remote Services: Cloud Services

## Stratus Red Team

`aws.execution.ssm-start-session`

## CloudTrail Events

- `DescribeInstanceInformation`
- `StartSession`
- `DescribeInstances`

## Required Permissions

- `ssm:DescribeInstanceInformation`
- `ssm:StartSession`
- `ec2:DescribeInstances`

## Detection Notes

- **CloudTrail**: `ssm:StartSession` events (each session generates a session ID)
- **SSM Session Manager logs** (if enabled): full session transcript recorded to CloudWatch/S3
- **GuardDuty**: No specific finding for SSM sessions — detection gap

## Key Risk

`ssm:StartSession` bypasses security groups, NACLs, and bastion hosts entirely. An attacker with this permission can open an interactive shell on any SSM-managed instance without SSH keys or network connectivity.

## Execute Mode

Not implemented. Use the AWS Console or CLI to initiate sessions manually:

```bash
aws ssm start-session --target <instance-id>
```

## Cleanup

No state is created — this module is dry-run only.
