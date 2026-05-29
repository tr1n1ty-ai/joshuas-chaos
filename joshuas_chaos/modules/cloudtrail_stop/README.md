# cloudtrail_stop

This module detects whether the calling principal has `cloudtrail:StopLogging` permission and enumerates all CloudTrail trails in the current region with their current logging status. An attacker with this permission can call `StopLogging` on active trails, halting all CloudTrail log collection immediately without deleting the trail configuration. This is one of the simplest and most impactful defense-evasion techniques available to a compromised principal with CloudTrail write access. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.cloudtrail-stop`

## CloudTrail Events Generated

- `DescribeTrails`
- `GetTrailStatus`
- `StopLogging` (dry-run only — not actually called)

## Detection Notes

- **GuardDuty:** `Stealth:IAMUser/CloudTrailLoggingDisabled` fires when logging is stopped on a trail.
- **CloudTrail:** Alert on any `StopLogging` API call; this should never occur in a production environment without a change-management ticket.
- **AWS Config:** `cloud-trail-enabled` managed rule detects when trails stop delivering logs.
- **Security Hub:** `[CloudTrail.1]` — CloudTrail should be enabled and configured with at least one multi-region trail.
