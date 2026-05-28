# cross_account_role_chain

**Category:** lateral-movement  
**MITRE ATT&CK:** T1550.001

## Description

Maps `sts:AssumeRole` paths from explicitly configured role ARNs. Does NOT
brute-force accounts or enumerate outside allowlisted accounts.

## Configuration

```yaml
modules:
  cross_account_role_chain:
    enabled: true
    allowed_role_arns:
      - "arn:aws:iam::123456789012:role/AttackLabTargetRole"
```

## Safety

- Only assumes roles in `allowed_role_arns` AND `allowed_accounts`
- Credentials from assumed sessions are never stored or logged
- STS sessions expire automatically (15 min)

## Detection

- CloudTrail: `sts:AssumeRole` cross-account
- IAM Access Analyzer: cross-account access findings
