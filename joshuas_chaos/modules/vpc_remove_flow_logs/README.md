# vpc_remove_flow_logs

This module detects whether the calling principal has `ec2:DeleteFlowLogs` permission and enumerates all VPC Flow Logs in the current region, reporting each log's ID, associated resource, destination type, and delivery status. An attacker who deletes VPC Flow Logs removes all network-layer visibility into traffic flowing through the VPC, hiding lateral movement, data exfiltration, and C2 communication from network-based detection systems. It is dry-run only and performs no mutations.

## MITRE ATT&CK

- **Technique:** T1562.008 — Impair Defenses: Disable or Modify Cloud Logs

## Stratus Red Team Technique

`aws.defense-evasion.vpc-remove-flow-logs`

## CloudTrail Events Generated

- `DescribeFlowLogs`
- `DeleteFlowLogs` (dry-run only — not actually called)

## Detection Notes

- **CloudTrail:** Alert on `DeleteFlowLogs` API calls; VPC Flow Log deletion is almost never legitimate in a monitored environment.
- **AWS Config:** `vpc-flow-logs-enabled` managed rule detects when VPCs lack active flow log configurations.
- **Security Hub:** `[EC2.6]` — VPC flow logging should be enabled in all VPCs.
- **GuardDuty:** Network anomaly baselines will degrade after flow log deletion, reducing detection fidelity for subsequent network-based findings.
