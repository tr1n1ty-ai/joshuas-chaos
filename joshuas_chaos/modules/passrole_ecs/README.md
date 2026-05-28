# passrole_ecs

**Category:** privilege-escalation  
**MITRE ATT&CK:** T1610

## Description

Detects `iam:PassRole` + `ecs:RunTask` risk and simulates by running a
benign ECS task that executes `aws sts get-caller-identity` only.

## Safety

- Only targets ECS clusters with `AttackLab` in their name
- Task command: `aws sts get-caller-identity` only
- Cleanup stops the task and deregisters the task definition
