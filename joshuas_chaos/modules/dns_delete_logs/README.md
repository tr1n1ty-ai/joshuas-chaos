# dns_delete_logs

This module detects whether the calling principal has `route53resolver:DeleteResolverQueryLogConfig` permission and enumerates all Route53 Resolver DNS query log configurations in the current region. An attacker who deletes DNS query log configurations removes visibility into all domain lookups made by resources in associated VPCs, which is particularly valuable for hiding C2 communication over DNS. The module handles regions where the Route53 Resolver service is unavailable gracefully. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.dns-delete-logs`

## CloudTrail Events Generated

- `ListResolverQueryLogConfigs`
- `DeleteResolverQueryLogConfig` (dry-run only — not actually called)

## Detection Notes

- **CloudTrail:** Alert on `DeleteResolverQueryLogConfig` API calls; DNS logging removal is rarely legitimate outside of explicit decommissioning.
- **AWS Config:** `vpc-flow-logs-enabled` rule; also consider custom Config rules monitoring Route53 Resolver logging associations.
- **Security Hub:** Route53 Resolver query logging findings.
- Note that after deletion, any VPC previously associated with the deleted config will stop generating DNS logs immediately, creating a forensic blind spot for domain-based C2.
