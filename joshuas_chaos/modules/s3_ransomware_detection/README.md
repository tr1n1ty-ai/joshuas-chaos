# s3_ransomware_detection

This module assesses the S3 ransomware attack surface by checking whether the principal has `s3:DeleteObject` and `s3:PutObject` permissions, and by enumerating the versioning and MFA delete configuration of all accessible S3 buckets (capped at the first 50 to avoid memory issues). Buckets without versioning are fully vulnerable to irreversible deletion-based ransomware; buckets with versioning but without MFA delete are vulnerable to version-purge attacks that precede client-side encryption ransomware. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1485 — Data Destruction
- **Technique:** T1486 — Data Encrypted for Impact

## Stratus Red Team Techniques

- `aws.impact.s3-ransomware-batch-deletion`
- `aws.impact.s3-ransomware-client-side-encryption`
- `aws.impact.s3-ransomware-individual-deletion`

## CloudTrail Events Generated

- `ListBuckets`
- `GetBucketVersioning`
- `DeleteObject` (dry-run only — not actually called)
- `PutObject` (dry-run only — not actually called)

## Detection Notes

- **GuardDuty:** `Impact:S3/MaliciousIPCaller` fires on mass object deletions from suspicious IPs.
- **CloudTrail:** Alert on high-volume `DeleteObject` or `PutObject` events in a short window, especially when coming from a single principal.
- **S3 server access logs:** Mass delete patterns, particularly across many object keys in rapid succession.
- **Security Hub:** S3 bucket versioning findings; `[S3.14]` S3 buckets should use versioning.
- **Preventive control:** Enable S3 Object Lock with governance or compliance mode on critical buckets to make both deletion and version-purge attacks impossible.
