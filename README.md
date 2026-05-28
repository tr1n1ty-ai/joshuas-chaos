# Joshua's Chaos: AWS Security Chaos Engineering Framework

> **FOR AUTHORIZED USE ONLY.** This tool is designed exclusively for authorized AWS lab environments, purple-team exercises, detection engineering, and security chaos engineering. Never run against production accounts or systems without explicit written authorization.

---

## Overview

Joshua's Chaos is a modular Python framework for AWS security chaos engineering and attack-path validation. It includes 16 purpose-built modules covering privilege escalation, credential access, lateral movement, and execution scenarios — all mapped to MITRE ATT&CK techniques.

The tool retains its WarGames-inspired terminal UI (CPE1704TKS sequence, GREETINGS PROFESSOR FALKEN) while providing a production-grade safety architecture.

## Safety Architecture

Every execution is gated by multiple layers of safety:

- **Dry-run is the default** — no changes are made unless `--execute` is explicitly passed
- **Three-flag execute gate**: `--execute`, `--confirm-account <account-id>`, `--i-understand-this-is-authorized`
- **Account allowlist**: refuses to run unless `sts:GetCallerIdentity` returns an account in `config.yaml`
- **Region allowlist**: refuses to operate in non-allowlisted regions
- **Resource safety**: execute mode only targets resources tagged `AttackLab=true` or named with the `AttackLab` prefix
- **Fail closed**: exits if `config.yaml` is missing or malformed
- **No credential exposure**: all secret values, access keys, and session tokens are masked in output and never logged
- **No disabling security controls**: no CloudTrail, GuardDuty, SCPs, or IAM Access Analyzer disruption

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/user/joshuas-chaos.git
cd joshuas-chaos
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

## Configuration

Edit `config.yaml` before running:

```yaml
allowed_accounts:
  - "YOUR_LAB_ACCOUNT_ID"   # Must match sts:GetCallerIdentity

allowed_regions:
  - "us-east-1"
  - "us-east-2"

resource_safety:
  required_tag_key: "AttackLab"
  required_tag_value: "true"
  allowed_name_prefix: "AttackLab"
```

## Usage

### Interactive Menu (WarGames UI)

```bash
python main.py
```

### CLI Commands

```bash
# List all modules
python main.py list

# Describe a module
python main.py describe passrole_lambda

# Dry run (default, no changes)
python main.py run passrole_lambda --dry-run

# Execute mode (requires all three flags)
python main.py run passrole_lambda \
    --execute \
    --confirm-account 123456789012 \
    --i-understand-this-is-authorized

# Cleanup
python main.py cleanup passrole_lambda --confirm-account 123456789012
```

## Modules

| Module | Category | MITRE ATT&CK |
|--------|----------|--------------|
| `s3_versioning_recovery` | data-protection | T1485, T1486 |
| `iam_self_escalation` | privilege-escalation | T1098 |
| `create_access_key_abuse` | credential-access | T1098.001 |
| `trust_policy_abuse` | privilege-escalation | T1098.003 |
| `passrole_lambda` | privilege-escalation | T1098, T1610 |
| `passrole_ecs` | privilege-escalation | T1610 |
| `passrole_cloudformation` | privilege-escalation | T1098 |
| `existing_lambda_takeover` | persistence | T1525 |
| `codebuild_abuse` | execution | T1610 |
| `glue_job_abuse` | execution | T1610 |
| `ssm_sendcommand_abuse` | execution | T1651 |
| `ec2_imds_exposure` | credential-access | T1552.005 |
| `ecs_task_role_exposure` | credential-access | T1552.005 |
| `secretsmanager_data_access` | credential-access | T1555 |
| `cross_account_role_chain` | lateral-movement | T1550.001 |
| `bedrock_agent_tool_abuse` | execution | T1059 |

## Running Tests

```bash
pytest -v -m unit
```

Tests use `botocore.stub.Stubber` and do not require real AWS credentials.

## Project Structure

```
joshuas_chaos/
  core/           # Framework infrastructure (config, safety, AWS context, etc.)
  modules/        # 16 chaos modules, each with check_prereqs/dry_run/execute/cleanup
main.py           # Entry point shim
config.yaml       # Safety configuration (edit before running)
tests/            # Unit tests with botocore Stubber mocking
```

## Adding a New Module

1. Create `joshuas_chaos/modules/your_module/` with `__init__.py` and `module.py`
2. Subclass `ChaosModule` from `joshuas_chaos.modules`
3. Implement `check_prereqs`, `dry_run`, `execute`, `cleanup`
4. Set `MODULE = YourModuleClass()` at module level for auto-discovery
5. Add `your_module:` section to `config.yaml`

## Legal Notice

This software is for authorized security testing only. Use only in accounts and environments where you have explicit written authorization. The authors accept no responsibility for unauthorized or harmful use.
