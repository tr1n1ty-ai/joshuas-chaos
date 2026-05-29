# secretsmanager_batch_retrieve

**Category:** credential-access
**MITRE ATT&CK:** T1555 — Credentials from Password Stores
**Stratus Red Team:** `aws.credential-access.secretsmanager-batch-retrieve-secrets`

## Description

Simulates batch Secrets Manager credential access using the `BatchGetSecretValue` API.
Execute targets only AttackLab-tagged secrets — all secret values are fully masked
immediately upon receipt and never stored or logged.

## What it does

**Dry-run:**
1. Checks `secretsmanager:BatchGetSecretValue` permission.
2. Paginates `secretsmanager:ListSecrets` to enumerate all secrets.
3. Filters for AttackLab-tagged or AttackLab-prefixed secrets.
4. Highlights the detection evasion advantage of `BatchGetSecretValue`.

**Execute:**
1. Safety checks: account and region allowlist.
2. Lists and filters to AttackLab-tagged secrets only.
3. Calls `secretsmanager:BatchGetSecretValue` with all target ARNs.
4. Falls back to individual `GetSecretValue` if `BatchGetSecretValue` is unavailable.
5. Records only the secret name and type (SecretString vs SecretBinary).
6. ALL secret values are set to `[REDACTED]` immediately and never stored.

## Key detection insight

`BatchGetSecretValue` generates a **single CloudTrail event** regardless of how many
secrets are retrieved, compared to one event per secret with `GetSecretValue`. This
makes large-scale secret exfiltration significantly harder to detect at scale.

## Required permissions

| Permission | Purpose |
|---|---|
| `secretsmanager:ListSecrets` | Enumerate available secrets |
| `secretsmanager:BatchGetSecretValue` | Retrieve all secrets in one API call |
| `secretsmanager:GetSecretValue` | Fallback for older SDK/regions |

## CloudTrail events generated

- `ListSecrets`
- `BatchGetSecretValue` (single event for all secrets)
- `GetSecretValue` (fallback only, one per secret)

## Detection notes

- **CloudTrail:** `BatchGetSecretValue` — single event regardless of secret count
- **GuardDuty:** `CredentialAccess:SecretsManager/SuspiciousGetSecretValueAPI`
