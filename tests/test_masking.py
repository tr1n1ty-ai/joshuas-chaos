"""Tests for core/masking.py."""

import pytest

from joshuas_chaos.core.masking import mask_dict, mask_string


@pytest.mark.unit
class TestMaskString:
    def test_akia_key_id_is_masked(self) -> None:
        text = "Key: AKIAIOSFODNN7EXAMPLE"
        result = mask_string(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_asia_key_id_is_masked(self) -> None:
        text = "AccessKeyId: ASIAIOSFODNN7EXAMPLE"
        result = mask_string(text)
        assert "ASIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_secret_access_key_is_masked(self) -> None:
        text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = mask_string(text)
        assert "wJalrXUtnFEMI" not in result
        assert "REDACTED" in result

    def test_session_token_is_masked(self) -> None:
        token_val = "A" * 120
        text = f"aws_session_token={token_val}"
        result = mask_string(text)
        assert token_val not in result
        assert "REDACTED" in result

    def test_password_is_masked(self) -> None:
        text = "password=supersecretpassword123"
        result = mask_string(text)
        assert "supersecretpassword123" not in result
        assert "REDACTED" in result

    def test_private_key_is_masked(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----"
        result = mask_string(text)
        assert "MIIEowIBAAK" not in result
        assert "REDACTED" in result

    def test_clean_string_passes_through_unchanged(self) -> None:
        text = "Hello, this is a normal string with no secrets."
        result = mask_string(text)
        assert result == text

    def test_empty_string_passes_through(self) -> None:
        assert mask_string("") == ""

    def test_non_string_passes_through(self) -> None:
        assert mask_string(42) == 42  # type: ignore[arg-type]


@pytest.mark.unit
class TestMaskDict:
    def test_secret_access_key_in_dict_is_redacted(self) -> None:
        data = {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        }
        result = mask_dict(data)
        assert result["AccessKeyId"] != "AKIAIOSFODNN7EXAMPLE" or "REDACTED" in result.get("AccessKeyId", "")
        assert result["SecretAccessKey"] == "[REDACTED]"

    def test_session_token_in_dict_is_redacted(self) -> None:
        data = {"SessionToken": "longsessiontoken" * 10}
        result = mask_dict(data)
        assert result["SessionToken"] == "[REDACTED]"

    def test_password_in_dict_is_redacted(self) -> None:
        data = {"password": "mysupersecret"}
        result = mask_dict(data)
        assert result["password"] == "[REDACTED]"

    def test_nested_dict_is_recursed(self) -> None:
        data = {
            "outer": {
                "SecretAccessKey": "secret123",
                "normal": "value",
            }
        }
        result = mask_dict(data)
        assert result["outer"]["SecretAccessKey"] == "[REDACTED]"
        assert result["outer"]["normal"] == "value"

    def test_list_values_are_recursed(self) -> None:
        data = {
            "items": [
                {"SecretAccessKey": "secret"},
                {"normal": "value"},
            ]
        }
        result = mask_dict(data)
        assert result["items"][0]["SecretAccessKey"] == "[REDACTED]"
        assert result["items"][1]["normal"] == "value"

    def test_original_dict_is_not_mutated(self) -> None:
        data = {"SecretAccessKey": "original_secret"}
        original_copy = dict(data)
        mask_dict(data)
        assert data == original_copy

    def test_non_sensitive_keys_pass_through(self) -> None:
        data = {"bucket_name": "my-bucket", "region": "us-east-1"}
        result = mask_dict(data)
        assert result == data

    def test_secret_string_in_dict_is_redacted(self) -> None:
        data = {"SecretString": '{"username": "admin", "password": "secret"}'}
        result = mask_dict(data)
        assert result["SecretString"] == "[REDACTED]"
