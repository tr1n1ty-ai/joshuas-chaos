# s3_versioning_recovery

**Category:** data-protection  
**MITRE ATT&CK:** T1485, T1486

## Description

Simulates an attacker suspending S3 bucket versioning on lab-safe buckets,
creating a detection and recovery opportunity.

## Phases

- **dry-run**: Lists all S3 buckets and their versioning status. No modifications.
- **execute**: Suspends versioning on AttackLab-tagged or approved buckets,
  waits for detection window, then re-enables versioning.
- **cleanup**: Idempotently re-enables versioning on all AttackLab-tagged buckets.

## Safety

Only targets buckets tagged `AttackLab=true` or listed in `config.modules.s3_versioning_recovery.approved_buckets`.

## Detection

- CloudTrail: `PutBucketVersioning` with `Status=Suspended`
- AWS Config: `s3-bucket-versioning-enabled` rule triggers NON_COMPLIANT
- Security Hub: S3.14
