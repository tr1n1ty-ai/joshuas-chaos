# passrole_cloudformation

**Category:** privilege-escalation  
**MITRE ATT&CK:** T1098

## Description

Detects `cloudformation:CreateStack` + `iam:PassRole` risk and simulates
by creating a harmless tagged CloudFormation stack containing only an output
(no resources with permissions).

## Safety

- Stack name: `AttackLabPassRoleCFNTest`
- Template: output-only, no resources, no IAM grants
- Cleanup deletes the stack
