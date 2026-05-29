# ec2_user_data_execution

## Description

Simulate code execution via EC2 user data modification on a stopped AttackLab instance. Execute sets a benign user data script (prints hostname to `/tmp/attacklab_test.txt`) on stopped instances tagged `AttackLab=true`. The instance is NOT started — only the attribute is modified.

## MITRE ATT&CK

- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1078.004** — Valid Accounts: Cloud Accounts

## Stratus Red Team

`aws.execution.ec2-user-data`

## CloudTrail Events

- `DescribeInstances`
- `ModifyInstanceAttribute`
- `DescribeInstanceAttribute`

## Required Permissions

- `ec2:DescribeInstances`
- `ec2:ModifyInstanceAttribute`
- `ec2:DescribeInstanceAttribute`

## Detection Notes

- **CloudTrail**: `ModifyInstanceAttribute` event (userData attribute)
- **GuardDuty**: No specific finding for this technique — detection gap
- User data runs as root/SYSTEM on instance start — equivalent to RCE with highest privilege

## Prerequisites

At least one EC2 instance tagged `AttackLab=true` must be in the **stopped** state.

## Cleanup

Restores original user data on all modified instances. If an instance was terminated between execute and cleanup, the step is skipped (idempotent). Clears all backup state after completion.
