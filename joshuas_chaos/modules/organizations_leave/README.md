# organizations_leave

This module detects whether the calling AWS account is a member of an AWS Organization and whether the principal has `organizations:LeaveOrganization` permission. An attacker who removes an account from its organization instantly eliminates all Service Control Policy (SCP) guardrails, shared security tooling (GuardDuty aggregation, Security Hub delegated admin, AWS Config aggregation), and any organization-level CloudTrail. This is one of the highest-impact single-call defense-evasion techniques in AWS. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562 — Impair Defenses

## Stratus Red Team Technique

`aws.defense-evasion.organizations-leave`

## CloudTrail Events Generated

- `DescribeOrganization`
- `LeaveOrganization` (dry-run only — not actually called)

## Detection Notes

- **CloudTrail (organization trail):** Alert on `LeaveOrganization` API calls; this should only ever happen through a documented off-boarding process.
- **AWS Organizations:** Configure an SCP that denies `organizations:LeaveOrganization` for all member accounts except the management account.
- **Security Hub:** Organizations-level findings; also monitor for sudden disappearance of member accounts from the organization console.
- Use AWS Config aggregation at the organization level to detect when an account stops reporting findings.
