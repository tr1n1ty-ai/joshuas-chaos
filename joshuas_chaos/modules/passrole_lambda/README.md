# passrole_lambda

**Category:** privilege-escalation  
**MITRE ATT&CK:** T1098, T1610

## Description

Detects `iam:PassRole` + Lambda permission combinations and simulates
abuse by creating a benign Lambda function that only calls
`sts:GetCallerIdentity`.

## Safety

- Only creates a function named `AttackLabPassRoleLambdaTest`
- Lambda code ONLY calls `sts:GetCallerIdentity` — no credential dumping
- Cleanup deletes the function

## Detection

- CloudTrail: `CreateFunction` with role ARN
- CloudTrail: `iam:PassRole` for `lambda.amazonaws.com`
