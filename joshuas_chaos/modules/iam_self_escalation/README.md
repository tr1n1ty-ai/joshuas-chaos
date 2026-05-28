# iam_self_escalation

**Category:** privilege-escalation  
**MITRE ATT&CK:** T1098  
**Mode:** Dry-run ONLY

## Description

Detects if the calling IAM principal has permissions that could allow
self-escalation or lateral privilege movement.

## Checked Permissions

- `iam:AttachUserPolicy` / `iam:AttachRolePolicy`
- `iam:PutUserPolicy` / `iam:PutRolePolicy`
- `iam:CreatePolicyVersion`
- `iam:AddUserToGroup`
- `iam:AttachGroupPolicy`

## Detection

- CloudTrail: IAM policy attachment events from unexpected principals
- IAM Access Analyzer: Overly-permissive policy findings
