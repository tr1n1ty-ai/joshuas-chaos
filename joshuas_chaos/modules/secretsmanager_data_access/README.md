# secretsmanager_data_access

**Category:** credential-access  
**MITRE ATT&CK:** T1555

## Description

Assesses Secrets Manager data access risk. Execute reads only
AttackLab-tagged secrets — all secret values are fully masked
(`[REDACTED]`) in output, logs, and results.

## Safety

- Only reads secrets tagged `AttackLab=true` or named `AttackLab*`
- Secret values: NEVER stored, logged, or displayed
- Read-only access — no secret modification

## Detection

- CloudTrail: `secretsmanager:GetSecretValue`
- GuardDuty: `CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI`
