# cloudtrail_lifecycle_rule

This module detects whether the calling principal has `s3:PutLifecycleConfiguration` permission on the S3 buckets used by CloudTrail for log storage, and enumerates any existing lifecycle rules on those buckets. An attacker with this permission can add S3 lifecycle rules with a very short expiration period (e.g., 1 day) to auto-delete CloudTrail log objects, destroying historical audit evidence without disabling or deleting the trail itself. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.cloudtrail-lifecycle-rule`

## CloudTrail Events Generated

- `DescribeTrails`
- `GetBucketLifecycleConfiguration`
- `PutLifecycleConfiguration` (dry-run only — not actually called)

## Detection Notes

- **CloudTrail (S3 data events):** Alert on `PutBucketLifecycle` events targeting S3 buckets that contain CloudTrail logs.
- **AWS Config:** `s3-bucket-logging-enabled` and `s3-lifecycle-policy-check` rules can detect unexpected lifecycle configurations.
- **Security Hub:** S3-related findings including unexpected bucket policy changes.
- Consider S3 Object Lock on CloudTrail log buckets to prevent both deletion and lifecycle-based expiry.
