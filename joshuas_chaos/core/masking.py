"""Masking and redaction of sensitive values in strings and dicts."""

import re
from typing import Any

# Patterns to redact
_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # AWS access key IDs (AKIA... or ASIA...)
    (
        "aws_access_key_id",
        re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])", re.IGNORECASE),
        "[REDACTED_ACCESS_KEY_ID]",
    ),
    # AWS secret access keys (40-char base64-like strings following known label)
    (
        "aws_secret_access_key",
        re.compile(
            r"(aws_secret_access_key|SecretAccessKey|secret_access_key)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED_SECRET_KEY]",
    ),
    # Session tokens (long base64 strings following label)
    (
        "session_token",
        re.compile(
            r"(aws_session_token|SessionToken|session_token)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{100,})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED_SESSION_TOKEN]",
    ),
    # Passwords
    (
        "password",
        re.compile(
            r"(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED_PASSWORD]",
    ),
    # Private keys (PEM blocks)
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # Bearer tokens
    (
        "bearer_token",
        re.compile(
            r"(Authorization|Bearer)\s*[=:]?\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)",
            re.IGNORECASE,
        ),
        r"\1: Bearer [REDACTED_BEARER_TOKEN]",
    ),
    # API keys
    (
        "api_key",
        re.compile(
            r"(api_key|apikey|api-key)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED_API_KEY]",
    ),
    # Secret values (generic label)
    (
        "secret_value",
        re.compile(
            r"(secret|SecretString|SecretBinary)\s*[=:]\s*['\"]?([^\s'\"]{4,})['\"]?",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED_SECRET]",
    ),
    # Authorization headers (raw)
    (
        "authorization_header",
        re.compile(
            r"(Authorization)\s*:\s*(.+)",
            re.IGNORECASE,
        ),
        r"\1: [REDACTED_AUTH_HEADER]",
    ),
]

# Keys in dicts that should always have their values redacted
_SENSITIVE_DICT_KEYS: frozenset[str] = frozenset(
    {
        "SecretAccessKey",
        "secret_access_key",
        "aws_secret_access_key",
        "SessionToken",
        "session_token",
        "aws_session_token",
        "password",
        "passwd",
        "pwd",
        "private_key",
        "api_key",
        "apikey",
        "Authorization",
        "authorization",
        "SecretString",
        "SecretBinary",
        "token",
        "bearer",
    }
)


def mask_string(text: str) -> str:
    """Apply all masking patterns to a string and return the sanitized version."""
    if not isinstance(text, str):
        return text
    result = text
    for _name, pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def mask_dict(data: dict) -> dict:
    """Recursively mask sensitive values in a dict, returning a new dict."""
    if not isinstance(data, dict):
        return data
    result: dict[str, Any] = {}
    for key, value in data.items():
        if key in _SENSITIVE_DICT_KEYS:
            result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = mask_dict(value)
        elif isinstance(value, list):
            result[key] = _mask_list(value)
        elif isinstance(value, str):
            result[key] = mask_string(value)
        else:
            result[key] = value
    return result


def _mask_list(items: list) -> list:
    """Recursively mask items in a list."""
    masked = []
    for item in items:
        if isinstance(item, dict):
            masked.append(mask_dict(item))
        elif isinstance(item, list):
            masked.append(_mask_list(item))
        elif isinstance(item, str):
            masked.append(mask_string(item))
        else:
            masked.append(item)
    return masked
