# cloudtrail_event_selectors

This module detects whether the calling principal has `cloudtrail:PutEventSelectors` permission and enumerates the current event selector configuration on all CloudTrail trails. An attacker with this permission can modify event selectors to set `ReadWriteType=None` or use advanced selectors that exclude all management events, effectively making CloudTrail capture no logs while the trail remains in an "enabled" state. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.cloudtrail-event-selectors`

## CloudTrail Events Generated

- `DescribeTrails`
- `GetEventSelectors`
- `PutEventSelectors` (dry-run only — not actually called)

## Detection Notes

- **CloudTrail:** Alert on `PutEventSelectors` API calls, particularly when the resulting selectors exclude `WriteOnly` or `All` management events.
- **AWS Config:** `cloud-trail-enabled` rule detects gaps in logging coverage.
- **Security Hub:** `[CloudTrail.1]` — CloudTrail should be enabled and configured with at least one multi-region trail.
- Monitor for CloudTrail trails that are active but showing zero event ingestion over time, which may indicate event selector manipulation.
