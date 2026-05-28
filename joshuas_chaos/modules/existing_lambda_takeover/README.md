# existing_lambda_takeover

**Category:** persistence  
**MITRE ATT&CK:** T1525

## Description

Lists Lambda functions the principal can potentially update, then simulates
takeover by replacing AttackLab-tagged function code with benign
`sts:GetCallerIdentity` code.

## Safety

- Only updates functions tagged `AttackLab=true` or named `AttackLab*`
- Replacement code: `sts:GetCallerIdentity` only
- Cleanup deploys a labeled placeholder; restore from deployment pipeline
