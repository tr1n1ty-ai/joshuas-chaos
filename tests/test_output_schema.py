"""Tests for core/output.py and ModuleResult schema."""

import json
from dataclasses import fields
from pathlib import Path

import pytest

from joshuas_chaos.core.models import ModuleResult
from joshuas_chaos.core.output import format_result_table, write_result


def _make_result(**kwargs) -> ModuleResult:
    defaults = dict(
        module="test_module",
        mode="dry-run",
        account_id="123456789012",
        principal_arn="arn:aws:iam::123456789012:user/test",
        region="us-east-1",
        risk_summary="Test risk summary",
        required_permissions=["s3:ListBuckets"],
        observed_permissions=[],
        aws_api_calls=["s3:ListBuckets"],
        cloudtrail_events=["ListBuckets"],
        findings=["Found 3 buckets"],
        detections=["CloudTrail: ListBuckets"],
        cleanup_required=False,
        safe_to_execute=True,
        errors=[],
        metadata={},
    )
    defaults.update(kwargs)
    return ModuleResult(**defaults)


@pytest.mark.unit
class TestModuleResultSchema:
    def test_has_all_required_fields(self) -> None:
        required = {
            "module",
            "mode",
            "account_id",
            "principal_arn",
            "region",
            "risk_summary",
            "required_permissions",
            "observed_permissions",
            "aws_api_calls",
            "cloudtrail_events",
            "findings",
            "detections",
            "cleanup_required",
            "safe_to_execute",
        }
        actual = {f.name for f in fields(ModuleResult)}
        assert required.issubset(actual), f"Missing fields: {required - actual}"

    def test_can_instantiate_with_defaults(self) -> None:
        result = _make_result()
        assert result.module == "test_module"
        assert result.mode == "dry-run"
        assert result.cleanup_required is False

    def test_errors_defaults_to_empty_list(self) -> None:
        result = ModuleResult(
            module="x",
            mode="dry-run",
            account_id="123",
            principal_arn="arn:aws:iam::123:user/x",
            region="us-east-1",
            risk_summary="test",
            required_permissions=[],
            observed_permissions=[],
            aws_api_calls=[],
            cloudtrail_events=[],
            findings=[],
            detections=[],
            cleanup_required=False,
            safe_to_execute=True,
        )
        assert result.errors == []
        assert result.metadata == {}


@pytest.mark.unit
class TestWriteResult:
    def test_creates_json_file(self, tmp_path: Path) -> None:
        result = _make_result()
        output_path = write_result(result, tmp_path)
        assert output_path.exists()
        assert output_path.suffix == ".json"

    def test_json_is_valid_and_contains_module_name(self, tmp_path: Path) -> None:
        result = _make_result(module="s3_versioning_recovery")
        output_path = write_result(result, tmp_path)
        data = json.loads(output_path.read_text())
        assert data["module"] == "s3_versioning_recovery"

    def test_json_filename_contains_module_name(self, tmp_path: Path) -> None:
        result = _make_result(module="passrole_lambda")
        output_path = write_result(result, tmp_path)
        assert "passrole_lambda" in output_path.name

    def test_output_dir_is_created_if_missing(self, tmp_path: Path) -> None:
        new_dir = tmp_path / "nested" / "output"
        result = _make_result()
        write_result(result, new_dir)
        assert new_dir.exists()

    def test_sensitive_values_are_masked_in_output(self, tmp_path: Path) -> None:
        result = _make_result(
            metadata={"SecretAccessKey": "SUPERSECRETVALUE"},
        )
        output_path = write_result(result, tmp_path)
        content = output_path.read_text()
        assert "SUPERSECRETVALUE" not in content
        assert "REDACTED" in content

    def test_json_output_matches_result_fields(self, tmp_path: Path) -> None:
        result = _make_result(
            module="ec2_imds_exposure",
            mode="dry-run",
            account_id="111111111111",
            findings=["Found 2 IMDSv1 instances"],
        )
        output_path = write_result(result, tmp_path)
        data = json.loads(output_path.read_text())
        assert data["module"] == "ec2_imds_exposure"
        assert data["mode"] == "dry-run"
        assert data["account_id"] == "111111111111"
        assert "Found 2 IMDSv1 instances" in data["findings"]


@pytest.mark.unit
class TestFormatResultTable:
    def test_returns_string(self) -> None:
        result = _make_result()
        table = format_result_table(result)
        assert isinstance(table, str)
        assert len(table) > 0

    def test_contains_module_name(self) -> None:
        result = _make_result(module="my_test_module")
        table = format_result_table(result)
        assert "my_test_module".upper() in table

    def test_contains_findings(self) -> None:
        result = _make_result(findings=["Critical finding here"])
        table = format_result_table(result)
        assert "Critical finding here" in table

    def test_contains_errors(self) -> None:
        result = _make_result(errors=["Something went wrong"])
        table = format_result_table(result)
        assert "Something went wrong" in table
