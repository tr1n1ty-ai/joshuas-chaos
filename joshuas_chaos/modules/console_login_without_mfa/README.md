# console_login_without_mfa

This module enumerates all IAM users in the account that have an active console login profile (password-based access) but no registered MFA devices. These accounts are susceptible to password-only console login, which means that an attacker who obtains or guesses a user's password can authenticate to the AWS Management Console without any second factor. The module uses paginators to handle large user populations and reports each vulnerable user along with their `PasswordLastUsed` timestamp. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1078.004 — Valid Accounts: Cloud Accounts

## Stratus Red Team Technique

`aws.initial-access.console-login-without-mfa`

## CloudTrail Events Generated

- `ListUsers`
- `GetLoginProfile`
- `ListMFADevices`

## Detection Notes

- **CloudTrail:** `ConsoleLogin` events that include `"additionalEventData": {"MFAUsed": "No"}` indicate a password-only login; alert on these immediately.
- **AWS Config rule:** `iam-user-mfa-enabled` — flags IAM users with console passwords who have no MFA device enrolled.
- **Security Hub:** `[IAM.5]` MFA should be enabled for all IAM users that have a console password.
- **Preventive control:** Enforce an IAM policy (or SCP) that denies all actions when `aws:MultiFactorAuthPresent` is false for console-enabled users, forcing MFA before any API calls can be made.
