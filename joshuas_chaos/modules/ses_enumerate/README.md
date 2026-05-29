# ses_enumerate

## Description

Enumerate SES (Simple Email Service) configuration including verified identities, sending limits, and account-level settings. Fully read-only — dry_run and execute perform identical enumeration.

## Stratus Red Team

`aws.discovery.ses-enumerate`

## MITRE ATT&CK

- **T1087.004** — Account Discovery: Cloud Account

## Required Permissions

- `ses:GetAccountSendingEnabled`
- `ses:GetSendQuota`
- `ses:ListIdentities`
- `ses:GetIdentityVerificationAttributes`

## CloudTrail Events

- `GetAccountSendingEnabled`
- `GetSendQuota`
- `ListIdentities`
- `GetIdentityVerificationAttributes`

## Behavior

### dry_run / execute (identical — read-only)

1. Checks `ses:ListIdentities` permission via IAM policy simulation.
2. Calls `ses:GetSendQuota` — returns Max24HourSend, MaxSendRate, SentLast24Hours.
3. Calls `ses:GetAccountSendingEnabled` — checks if sending is active.
4. Uses paginator for `ses:ListIdentities` — collects all email/domain identities.
5. Batches up to 100 identities per `ses:GetIdentityVerificationAttributes` call.
6. Handles gracefully if SES is not configured in the current region.
7. Reports risk if SES is enabled with a significant send quota.

### cleanup

Read-only — no state modified. Returns immediately with confirmation message.

## Detection Notes

- **CloudTrail:** SES enumeration events (`ListIdentities`, `GetSendQuota`, etc.) are low-signal individually but suspicious when seen in bulk or from unexpected principals.
- **GuardDuty:** No specific finding for SES enumeration.
- **Risk:** A principal with `ses:SendEmail` and knowledge of verified identities can launch phishing campaigns or spam at scale using the account's SES quota. The enumeration itself is the reconnaissance phase for that attack.
- **Mitigation:** Apply least-privilege IAM — separate `ses:SendEmail` from `ses:ListIdentities`; monitor for enumeration of SES resources from non-SES-application principals.
