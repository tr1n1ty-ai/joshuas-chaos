# Joshua's Chaos

> **AUTHORIZED USE ONLY.** For AWS lab environments, purple-team exercises, detection engineering, and security chaos engineering only. Never run against production or any account without explicit written authorization.

---

```yaml
# AGENT METADATA — machine-readable project summary
project: joshuas-chaos
type: aws-security-chaos-engineering-framework
language: python
min_python: "3.11"
entry_point: main.py
config_file: config.yaml
package_dir: joshuas_chaos/
test_runner: pytest
module_count: 16
default_mode: dry-run
execute_requires_flags: [--execute, --confirm-account, --i-understand-this-is-authorized]
safe_resource_tag: "AttackLab=true"
safe_resource_prefix: "AttackLab"
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/th3pac1fist/joshuas-chaos.git
cd joshuas-chaos

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure (required before any run)
# Edit config.yaml — replace REPLACE_WITH_YOUR_LAB_ACCOUNT_ID with your AWS account ID

# 4. First run — dry-run is always the default, no AWS changes made
python main.py run s3_versioning_recovery --dry-run
```

---

## Prerequisites

### Python
- Python 3.11 or higher required
- Check: `python3 --version`

### Python dependencies
```bash
pip install -r requirements.txt
# Core: boto3, botocore, pyyaml, colorama
# Dev/test: pytest, ruff, mypy, moto
```

### AWS credentials
Any standard boto3 credential source works:
- `~/.aws/credentials` profile
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- IAM instance profile (EC2/CloudShell)
- AWS SSO

Minimum IAM permissions for **dry-run only**:
```
sts:GetCallerIdentity
iam:SimulatePrincipalPolicy  (optional — degrades gracefully if missing)
```

Each module lists its own `required_permissions` in `python main.py describe <module>`.

---

## Configuration

`config.yaml` must exist and be valid before the tool will run. It fails closed — missing or malformed config is a hard exit.

### Full config reference

```yaml
# AWS account IDs the tool is allowed to operate in.
# REQUIRED. Must match sts:GetCallerIdentity output exactly.
# Tool refuses to run if current account is not in this list.
allowed_accounts:
  - "REPLACE_WITH_YOUR_LAB_ACCOUNT_ID"

# AWS regions the tool is allowed to operate in.
# REQUIRED. Tool refuses to run if --region is not in this list.
allowed_regions:
  - "us-east-1"
  - "us-east-2"
  - "us-west-2"

# Controls which severity of modules can execute.
# REQUIRED. Accepted values: "low" | "medium" | "high"
impact_mode: "low"

# Defines what makes a resource safe to target in execute mode.
# Execute mode ONLY touches resources matching tag OR name prefix.
# REQUIRED.
resource_safety:
  required_tag_key: "AttackLab"        # Tag key that marks a resource as lab-safe
  required_tag_value: "true"           # Tag value required
  allowed_name_prefix: "AttackLab"     # Name prefix that also marks a resource as lab-safe

# Per-module configuration. Each module key maps to module name.
# Set enabled: false to prevent a module from loading.
modules:
  s3_versioning_recovery:
    enabled: true
    approved_buckets: []               # Explicit bucket names to target (in addition to tagged)

  cross_account_role_chain:
    enabled: true
    allowed_role_arns: []              # Role ARNs to attempt assumption (allowlisted only)

  bedrock_agent_tool_abuse:
    enabled: false                     # Disabled by default — requires explicit config
    allowed_agent_ids: []
    allowed_action_groups: []

  # All other modules accept: enabled: true|false
```

### Config validation errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ConfigError: missing key 'allowed_accounts'` | Required field absent | Add field to config.yaml |
| `SafetyError: account X not in allowlist` | Current AWS account not listed | Add account ID to allowed_accounts |
| `SafetyError: region X not in allowlist` | Region not listed | Add region or use --region with an allowed region |
| `ConfigError: config.yaml not found` | File missing | Create config.yaml from the template above |

---

## CLI Reference

### Global flags (apply to all subcommands)

```bash
python main.py [GLOBAL FLAGS] <subcommand> [SUBCOMMAND FLAGS]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--config PATH` | path | `./config.yaml` | Path to config file |
| `--profile NAME` | string | AWS default | AWS profile name |
| `--region REGION` | string | First in config | AWS region override |
| `--output-dir PATH` | path | `./output` | Directory for JSON result files |
| `--no-intro` | flag | false | Skip WarGames intro animation |

### Subcommands

#### `list` — show all available modules
```bash
python main.py list
```

#### `describe` — show module details, required permissions, CloudTrail events
```bash
python main.py describe <module_name>

# Example
python main.py describe passrole_lambda
```

#### `run` — execute a module
```bash
# Dry-run (default — no AWS changes)
python main.py run <module_name> --dry-run

# Execute mode (all three flags required, no exceptions)
python main.py run <module_name> \
    --execute \
    --confirm-account <account-id> \
    --i-understand-this-is-authorized
```

| Flag | Required for execute | Description |
|------|---------------------|-------------|
| `--dry-run` | no | Run in dry-run mode (default) |
| `--execute` | yes | Enable execute mode |
| `--confirm-account ID` | yes | Must exactly match current account ID from STS |
| `--i-understand-this-is-authorized` | yes | Explicit authorization acknowledgment |

#### `cleanup` — undo execute-mode changes
```bash
python main.py cleanup <module_name> --confirm-account <account-id>
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success, no errors |
| `1` | Module error (NotImplementedError, AWS API failure) |
| `2` | Configuration or AWS context error (bad config, no credentials) |
| `3` | Safety check failed (wrong account, missing execute flags, SafetyError) |

---

## Safety Enforcement Chain

Every run executes these checks in order. Any failure is a hard exit — the tool never continues past a failed safety check.

```
1. Load config.yaml
   └─ Fail: ConfigError → exit 2

2. Call sts:GetCallerIdentity
   └─ Fail: no credentials / network error → exit 2

3. Assert account ID in config.allowed_accounts
   └─ Fail: SafetyError → exit 3

4. Assert region in config.allowed_regions
   └─ Fail: SafetyError → exit 3

5. [execute mode only] Assert all three execute flags present and correct
   └─ Fail: SafetyError → exit 3

6. [execute mode only] Per-resource: assert tag AttackLab=true OR name prefix AttackLab
   └─ Fail: resource skipped or SafetyError raised

7. Module runs (dry-run / execute / cleanup)
   └─ SafetyError from within module → exit 3
   └─ NotImplementedError (module is dry-run only) → exit 1
```

---

## Modules

### Module capability matrix

| Module | Category | Mode | Dry-run only | Requires lab resource | MITRE |
|--------|----------|------|--------------|-----------------------|-------|
| `s3_versioning_recovery` | data-protection | dry/execute/cleanup | no | S3 bucket tagged AttackLab=true | T1485, T1486 |
| `iam_self_escalation` | privilege-escalation | dry only | **yes** | none | T1098 |
| `create_access_key_abuse` | credential-access | dry/execute/cleanup | no | IAM user named AttackLab* | T1098.001 |
| `trust_policy_abuse` | privilege-escalation | dry/execute/cleanup | no | IAM role named AttackLabTrustRole | T1098.003 |
| `passrole_lambda` | privilege-escalation | dry/execute/cleanup | no | IAM role named AttackLab* | T1098, T1610 |
| `passrole_ecs` | privilege-escalation | dry/execute/cleanup | no | ECS cluster + task def tagged AttackLab=true | T1610 |
| `passrole_cloudformation` | privilege-escalation | dry/execute/cleanup | no | none (creates AttackLabPassRoleCFNTest) | T1098 |
| `existing_lambda_takeover` | persistence | dry/execute/cleanup | no | Lambda function tagged AttackLab=true | T1525 |
| `codebuild_abuse` | execution | dry/execute | no | CodeBuild project tagged AttackLab=true | T1610 |
| `glue_job_abuse` | execution | dry/execute | no | Glue job tagged AttackLab=true | T1610 |
| `ssm_sendcommand_abuse` | execution | dry/execute/cleanup | no | EC2 instance tagged AttackLab=true + SSM agent | T1651 |
| `ec2_imds_exposure` | credential-access | dry only | **yes** | none | T1552.005 |
| `ecs_task_role_exposure` | credential-access | dry only | **yes** | none | T1552.005 |
| `secretsmanager_data_access` | credential-access | dry/execute | no | Secret tagged AttackLab=true | T1555 |
| `cross_account_role_chain` | lateral-movement | dry/execute | no | Role ARNs in config.allowed_role_arns | T1550.001 |
| `bedrock_agent_tool_abuse` | execution | dry/execute | no | Agent ID in config (disabled by default) | T1059 |

### What dry-run does vs execute

| Mode | AWS API calls | Changes made | Output |
|------|--------------|--------------|--------|
| `dry-run` | Read-only (List*, Describe*, SimulatePrincipalPolicy) | None | Risk findings, permission assessment |
| `execute` | Read + targeted writes on AttackLab resources only | Yes — reversible | Findings + CloudTrail events generated |
| `cleanup` | Targeted deletes/restores on AttackLab resources | Yes — undoes execute | Confirmation findings |

---

## Output

Every run writes a JSON result file to `./output/` (or `--output-dir`):

```
output/
  passrole_lambda_dry-run_20260101T120000.json
  passrole_lambda_execute_20260101T120500.json
```

### Result schema

```json
{
  "module": "passrole_lambda",
  "mode": "dry-run",
  "account_id": "123456789012",
  "principal_arn": "arn:aws:iam::123456789012:user/lab-user",
  "region": "us-east-1",
  "risk_summary": "...",
  "required_permissions": ["iam:PassRole", "lambda:CreateFunction"],
  "observed_permissions": ["iam:PassRole"],
  "aws_api_calls": ["iam:SimulatePrincipalPolicy"],
  "cloudtrail_events": ["CreateFunction20150331"],
  "findings": ["[HIGH RISK] Principal has iam:PassRole AND Lambda permissions."],
  "detections": ["CloudTrail: lambda:CreateFunction with role ARN"],
  "cleanup_required": false,
  "safe_to_execute": true,
  "errors": []
}
```

All secret values, access key IDs, session tokens, and passwords are automatically masked to `[REDACTED]` in all output files and logs.

---

## Adding a New Module

### 1. Create the module directory

```
joshuas_chaos/modules/your_module_name/
  __init__.py      # empty
  module.py        # implementation
  README.md        # optional — module-specific docs
```

### 2. Implement `module.py` using this skeleton

```python
"""Your Module — one-line description."""

import logging
import botocore.exceptions
from joshuas_chaos.core.aws_context import AWSContext
from joshuas_chaos.core.config import AppConfig
from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.safety import SafetyChecker, SafetyError
from joshuas_chaos.modules import ChaosModule

logger = logging.getLogger("joshuas_chaos")


class YourModule(ChaosModule):
    name = "your_module_name"          # must match directory name
    description = "What this does."
    category = "privilege-escalation"  # see existing modules for convention
    required_permissions = ["service:Action"]
    cloudtrail_events = ["ActionName"]
    mitre_attack = ["T1098"]
    destructive = False
    reversible = True

    def check_prereqs(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        return ModuleResult(
            module=self.name, mode="check_prereqs",
            account_id=identity.account_id, principal_arn=identity.arn,
            region=context.region, risk_summary="Prereq check.",
            required_permissions=self.required_permissions,
            observed_permissions=[], aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=["Run dry-run to assess."], detections=[],
            cleanup_required=False, safe_to_execute=True,
        )

    def dry_run(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        # Read-only AWS calls only. No changes.
        findings = ["[DRY-RUN] Would do X."]
        return ModuleResult(
            module=self.name, mode="dry-run",
            account_id=identity.account_id, principal_arn=identity.arn,
            region=context.region, risk_summary="No changes made.",
            required_permissions=self.required_permissions,
            observed_permissions=[], aws_api_calls=[],
            cloudtrail_events=self.cloudtrail_events,
            findings=findings, detections=[],
            cleanup_required=False, safe_to_execute=True,
        )

    def execute(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        # Always gate execute with safety checks
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        checker.assert_resource_safe("AttackLabTargetResource", {"AttackLab": "true"})
        # ... AWS calls here, targeting AttackLab resources only ...
        return ModuleResult(...)

    def cleanup(self, context: AWSContext, config: AppConfig) -> ModuleResult:
        identity = context.get_caller_identity()
        # Always gate cleanup with safety checks too
        checker = SafetyChecker(config, identity)
        checker.assert_account_allowed()
        checker.assert_region_allowed(context.region)
        # ... undo execute changes idempotently ...
        return ModuleResult(...)


# Required — module loader discovers this singleton
MODULE = YourModule()
```

### 3. Add to config.yaml

```yaml
modules:
  your_module_name:
    enabled: true
```

### 4. Run discovery check

```bash
python main.py list   # your_module_name should appear
python main.py describe your_module_name
python main.py run your_module_name --dry-run
```

### Module rules (enforced)
- `cleanup()` must call `assert_account_allowed()` and `assert_region_allowed()` before any AWS mutations
- Execute must only target resources tagged `AttackLab=true` or named `AttackLab*`
- Never log or store raw secret values, access keys, or session tokens
- Every method must return a `ModuleResult` — never return `None` or raise uncaught exceptions
- `MODULE = YourClass()` must be set at module level for auto-discovery

---

## Testing

```bash
# Run all unit tests (no real AWS credentials required)
python3 -m pytest

# Verbose output
python3 -m pytest -v

# Run specific test file
python3 -m pytest tests/test_safety.py -v
```

Tests use `botocore.stub.Stubber` to mock AWS responses. No real AWS account needed.

```bash
# Lint
ruff check .

# Type check
mypy .
```

---

## Project Structure

```
joshuas-chaos/
├── main.py                          # Entry point shim → joshuas_chaos.main.cli_main()
├── config.yaml                      # Safety configuration (edit before running)
├── pyproject.toml                   # Build, ruff, mypy, pytest config
├── requirements.txt                 # Python dependencies
├── joshuas_chaos/
│   ├── main.py                      # CLI (argparse) + interactive curses menu
│   ├── core/
│   │   ├── models.py                # AppConfig, ModuleResult, CallerIdentity dataclasses
│   │   ├── config.py                # yaml.safe_load config loader — fails closed
│   │   ├── safety.py                # SafetyChecker — account/region/resource/flag enforcement
│   │   ├── aws_context.py           # AWSContext — boto3 session wrapper, STS identity
│   │   ├── masking.py               # Secret redaction — masks keys/tokens/passwords in strings/dicts
│   │   ├── permissions.py           # PermissionChecker — iam:SimulatePrincipalPolicy wrapper
│   │   ├── module_loader.py         # Dynamic module discovery via importlib
│   │   ├── output.py                # JSON result writer + terminal table formatter
│   │   ├── logger.py                # File-only logger → logs/joshuas_chaos.log
│   │   └── menu.py                  # WarGames curses UI
│   └── modules/
│       ├── __init__.py              # ChaosModule ABC (base class for all modules)
│       └── <module_name>/
│           ├── __init__.py
│           ├── module.py            # ChaosModule subclass + MODULE singleton
│           └── README.md
├── tests/
│   ├── test_config.py
│   ├── test_safety.py
│   ├── test_masking.py
│   ├── test_module_loader.py
│   ├── test_output_schema.py
│   └── test_s3_versioning_recovery.py
└── logs/                            # Runtime logs (gitignored)
    ├── joshuas_chaos.log
    └── error.log
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ConfigError: config.yaml not found` | config.yaml missing | Create config.yaml — copy the template from the Configuration section |
| `SafetyError: account 123456789012 not in allowlist` | Default sentinel still in config | Replace `REPLACE_WITH_YOUR_LAB_ACCOUNT_ID` with your real account ID |
| `AWSContextError: Unable to locate credentials` | No AWS credentials configured | Run `aws configure` or set `AWS_PROFILE` env var |
| `SafetyError: region us-west-1 not in allowlist` | Region not listed in config | Add region to `allowed_regions` in config.yaml |
| `[ERROR] Execute mode requires --execute...` | Tried execute via menu | Execute is CLI-only — use `python main.py run <module> --execute ...` |
| Module not appearing in `list` | Import error in module.py | Check logs/error.log for the import traceback |
| All permissions show `[UNKNOWN]` | `iam:SimulatePrincipalPolicy` denied | Expected in restricted envs — dry-run findings still valid, permissions just unconfirmed |

---

## Legal

This software is for **authorized security testing only**. Use only in accounts and environments where you have explicit written authorization. The authors accept no responsibility for unauthorized or harmful use.
