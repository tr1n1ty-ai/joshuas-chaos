# cloudtrail_delete

This module detects whether the calling principal has `cloudtrail:DeleteTrail` permission and enumerates all CloudTrail trails in the current region (excluding shadow trails), reporting each trail's name, ARN, home region, and current logging status. It is dry-run only and performs no mutations. This technique is used by attackers to destroy audit trails as a defense-evasion step before or during an intrusion.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.cloudtrail-delete`

## CloudTrail Events Generated

- `DescribeTrails`
- `GetTrailStatus`
- `DeleteTrail` (dry-run only — not actually called)

## Detection Notes

- **GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled` fires when CloudTrail logging is disabled or a trail is deleted.
- **CloudTrail:** Alert on any `DeleteTrail` API call, especially from non-administrative principals or from unusual source IPs.
- **AWS Config:** Enable the `cloud-trail-enabled` managed rule to detect when trails go missing.
- **Security Hub:** `[CloudTrail.1]` — CloudTrail should be enabled and configured with at least one multi-region trail.
