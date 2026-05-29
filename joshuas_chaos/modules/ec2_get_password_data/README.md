# ec2_get_password_data

**Category:** credential-access
**MITRE ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**Stratus Red Team:** `aws.credential-access.ec2-get-password-data`

## Description

Detects if the calling principal has `ec2:GetPasswordData` permission and enumerates
Windows EC2 instances whose encrypted Administrator password could be retrieved.

This is a **dry-run only** module. It does not call `ec2:GetPasswordData` — retrieving
EC2 password data is credential access that could expose real credentials even in lab
environments.

## What it does

**Dry-run:**
1. Uses `iam:SimulatePrincipalPolicy` to check `ec2:GetPasswordData` permission.
2. Paginates `ec2:DescribeInstances` with `platform=windows` filter.
3. Collects Windows instance IDs, states, and tags.
4. Reports risk if the permission is confirmed.

**Execute:** Raises `NotImplementedError` — this operation is too sensitive for lab execution.

## Required permissions

| Permission | Purpose |
|---|---|
| `ec2:DescribeInstances` | Enumerate Windows EC2 instances |
| `ec2:GetPasswordData` | Retrieve encrypted Administrator password |

## CloudTrail events generated

- `DescribeInstances` — enumeration
- `GetPasswordData` — password data retrieval (dry-run only checks for this)

## Detection notes

- **CloudTrail:** `GetPasswordData` events, especially from unexpected principals
- **GuardDuty:** `CredentialAccess:EC2/Unusualpasswordreset`

## Attack context

An attacker with `ec2:GetPasswordData` and the private key used to launch a Windows
instance can decrypt the Administrator password. This enables RDP lateral movement to
Windows workloads. The encrypted password data itself is visible to anyone with the
`GetPasswordData` permission — decryption requires the corresponding private key.
