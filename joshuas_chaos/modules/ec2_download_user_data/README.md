# ec2_download_user_data

## Description

Enumerate EC2 instances and retrieve their user data, which often contains bootstrap scripts with hardcoded credentials, API keys, or configuration secrets. Execute targets AttackLab-tagged instances only.

## Stratus Red Team

`aws.discovery.ec2-download-user-data`

## MITRE ATT&CK

- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1078.004** — Valid Accounts: Cloud Accounts

## Required Permissions

- `ec2:DescribeInstances`
- `ec2:DescribeInstanceAttribute`

## CloudTrail Events

- `DescribeInstances`
- `DescribeInstanceAttribute` (with `attribute=userData`)

## Behavior

### dry_run

- Checks `ec2:DescribeInstanceAttribute` permission via IAM policy simulation.
- Enumerates **all** EC2 instances (no tag filter) — reports total count.
- Separately identifies AttackLab-tagged instances.
- Reports risk if the principal can call `DescribeInstanceAttribute` on all visible instances.
- Reports count of AttackLab instances that would be targeted on execute.
- No API calls that modify resources.

### execute

- Safety checks: account allowlist, region allowlist.
- Targets only AttackLab-tagged instances.
- Calls `ec2:DescribeInstanceAttribute` with `Attribute='userData'` per instance.
- Decodes base64 user data.
- **Immediately passes all content through `masking.mask_string()` before storing.**
- Records: instance ID, byte length, whether sensitive patterns were detected, masked preview (first 500 chars).
- Raw user data is **never stored**.

### cleanup

Read-only — no state to clean. Returns immediately.

## Detection Notes

- **CloudTrail:** `DescribeInstanceAttribute` with `attribute=userData` — watch for this on production instances, not just lab instances.
- **GuardDuty:** No default detection for user data retrieval — this is a known blind spot.
- **Mitigation:** Restrict `ec2:DescribeInstanceAttribute` on production instances; avoid placing credentials in user data.
