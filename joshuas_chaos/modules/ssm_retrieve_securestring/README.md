# ssm_retrieve_securestring

**Category:** credential-access
**MITRE ATT&CK:** T1555 — Credentials from Password Stores
**Stratus Red Team:** `aws.credential-access.ssm-retrieve-securestring-parameters`

## Description

Simulates SSM Parameter Store credential access by retrieving `SecureString` parameters
tagged `AttackLab=true` with `WithDecryption=True`. All parameter values are fully masked
immediately upon receipt and never stored or logged.

## What it does

**Dry-run:**
1. Checks `ssm:GetParameters` permission.
2. Paginates `ssm:DescribeParameters` filtered to `Type=SecureString`.
3. Attempts `ssm:ListTagsForResource` per parameter for tag-based filtering;
   falls back to name-prefix filtering if unavailable.
4. Reports risk and lists AttackLab parameters that would be targeted.

**Execute:**
1. Safety checks: account and region allowlist.
2. Describes and filters parameters to AttackLab-tagged SecureString only.
3. Calls `assert_resource_safe` on each parameter before touching it.
4. Batches `ssm:GetParameters` calls with `WithDecryption=True` (max 10 per call).
5. Records parameter names and types only — ALL values are `[REDACTED]` immediately.

## Required permissions

| Permission | Purpose |
|---|---|
| `ssm:DescribeParameters` | Enumerate available parameters |
| `ssm:GetParameters` | Retrieve parameter values with decryption |
| `ssm:GetParameter` | Single-parameter retrieval (optional) |
| `kms:Decrypt` | Decrypt KMS-encrypted SecureString parameters |

## CloudTrail events generated

- `DescribeParameters`
- `GetParameters` (with `WithDecryption=true`)
- `Decrypt` (KMS — one per KMS-encrypted parameter)

## Detection notes

- **CloudTrail:** `GetParameters` with `WithDecryption=true` from unexpected principal
- **CloudTrail:** `kms:Decrypt` event for each KMS-encrypted parameter
- **AWS Config:** `ssm-document-not-public`

## Note on tag filtering

SSM parameter tags are not included in `DescribeParameters` output. Tag retrieval
requires a separate `ssm:ListTagsForResource` call per parameter. If this permission
is unavailable, the module falls back to name-prefix filtering (`/AttackLab` or
`AttackLab` prefix).
