"""Tests for core/module_loader.py."""

from pathlib import Path

import pytest

from joshuas_chaos.core.module_loader import ModuleLoadError, discover_modules, get_module


@pytest.mark.unit
class TestDiscoverModules:
    def test_discovers_all_expected_modules(self) -> None:
        modules_dir = Path(__file__).parents[1] / "joshuas_chaos" / "modules"
        modules = discover_modules(modules_dir)

        expected = {
            "s3_versioning_recovery",
            "iam_self_escalation",
            "create_access_key_abuse",
            "trust_policy_abuse",
            "passrole_lambda",
            "passrole_ecs",
            "passrole_cloudformation",
            "existing_lambda_takeover",
            "codebuild_abuse",
            "glue_job_abuse",
            "ssm_sendcommand_abuse",
            "ec2_imds_exposure",
            "ecs_task_role_exposure",
            "secretsmanager_data_access",
            "cross_account_role_chain",
            "bedrock_agent_tool_abuse",
        }
        assert expected.issubset(set(modules.keys())), (
            f"Missing modules: {expected - set(modules.keys())}"
        )

    def test_each_module_has_required_attributes(self) -> None:
        from joshuas_chaos.modules import ChaosModule

        modules_dir = Path(__file__).parents[1] / "joshuas_chaos" / "modules"
        modules = discover_modules(modules_dir)

        for name, mod in modules.items():
            assert isinstance(mod, ChaosModule), f"{name} is not a ChaosModule"
            assert hasattr(mod, "name"), f"{name} missing .name"
            assert hasattr(mod, "description"), f"{name} missing .description"
            assert hasattr(mod, "category"), f"{name} missing .category"
            assert hasattr(mod, "required_permissions"), f"{name} missing .required_permissions"
            assert hasattr(mod, "cloudtrail_events"), f"{name} missing .cloudtrail_events"
            assert hasattr(mod, "mitre_attack"), f"{name} missing .mitre_attack"

    def test_empty_dir_returns_empty_dict(self, tmp_path: Path) -> None:
        modules = discover_modules(tmp_path)
        assert modules == {}

    def test_dir_without_module_py_is_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "empty_module").mkdir()
        (tmp_path / "empty_module" / "__init__.py").write_text("")
        modules = discover_modules(tmp_path)
        assert "empty_module" not in modules


@pytest.mark.unit
class TestGetModule:
    def test_returns_correct_module(self) -> None:
        modules_dir = Path(__file__).parents[1] / "joshuas_chaos" / "modules"
        modules = discover_modules(modules_dir)
        mod = get_module("s3_versioning_recovery", modules)
        assert mod.name == "s3_versioning_recovery"

    def test_raises_for_unknown_module(self) -> None:
        modules_dir = Path(__file__).parents[1] / "joshuas_chaos" / "modules"
        modules = discover_modules(modules_dir)
        with pytest.raises(ModuleLoadError, match="not found"):
            get_module("nonexistent_module_xyz", modules)
