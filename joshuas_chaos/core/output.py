"""Output formatting and result persistence."""

import json
import logging
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from colorama import Fore, Style

from joshuas_chaos.core.masking import mask_dict
from joshuas_chaos.core.models import ModuleResult

logger = logging.getLogger("joshuas_chaos")

_OUTPUT_DIR = Path(__file__).parents[2] / "output"


def write_result(result: ModuleResult, output_dir: Path | None = None) -> Path:
    """Serialize a ModuleResult to JSON in output_dir/{module}_{timestamp}.json.

    The output is sanitized via mask_dict before writing.
    Returns the path to the written file.
    """
    dest = output_dir or _OUTPUT_DIR
    dest.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
    filename = dest / f"{result.module}_{timestamp}.json"

    raw = asdict(result)
    sanitized = mask_dict(raw)

    filename.write_text(json.dumps(sanitized, indent=2, default=str))
    logger.info("Result written to %s", filename)
    return filename


def format_result_table(result: ModuleResult) -> str:
    """Return a colored terminal table string for a ModuleResult."""
    lines: list[str] = []

    def section(title: str) -> str:
        return f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n{Fore.YELLOW}{title}{Style.RESET_ALL}"

    def row(key: str, value: str, color: str = Fore.WHITE) -> str:
        return f"  {Fore.GREEN}{key:<28}{Style.RESET_ALL}{color}{value}{Style.RESET_ALL}"

    mode_color = Fore.RED if result.mode == "execute" else Fore.CYAN
    safe_color = Fore.GREEN if result.safe_to_execute else Fore.RED

    lines.append(section(f"MODULE RESULT: {result.module.upper()}"))
    lines.append(row("Mode", result.mode, mode_color))
    lines.append(row("Account", result.account_id))
    lines.append(row("Principal", result.principal_arn))
    lines.append(row("Region", result.region))
    lines.append(row("Risk Summary", result.risk_summary))
    lines.append(row("Safe to Execute", str(result.safe_to_execute), safe_color))
    lines.append(row("Cleanup Required", str(result.cleanup_required)))

    if result.required_permissions:
        lines.append(section("Required Permissions"))
        for perm in result.required_permissions:
            lines.append(f"  {Fore.YELLOW}  - {perm}{Style.RESET_ALL}")

    if result.observed_permissions:
        lines.append(section("Observed Permissions (Allowed)"))
        for perm in result.observed_permissions:
            lines.append(f"  {Fore.GREEN}  - {perm}{Style.RESET_ALL}")

    if result.aws_api_calls:
        lines.append(section("AWS API Calls Made"))
        for call in result.aws_api_calls:
            lines.append(f"  {Fore.WHITE}  - {call}{Style.RESET_ALL}")

    if result.cloudtrail_events:
        lines.append(section("Expected CloudTrail Events"))
        for event in result.cloudtrail_events:
            lines.append(f"  {Fore.MAGENTA}  - {event}{Style.RESET_ALL}")

    if result.findings:
        lines.append(section("Findings"))
        for finding in result.findings:
            lines.append(f"  {Fore.RED}  [!] {finding}{Style.RESET_ALL}")

    if result.detections:
        lines.append(section("Detection Opportunities"))
        for detection in result.detections:
            lines.append(f"  {Fore.BLUE}  [D] {detection}{Style.RESET_ALL}")

    if result.errors:
        lines.append(section("Errors"))
        for error in result.errors:
            lines.append(f"  {Fore.RED}  [E] {error}{Style.RESET_ALL}")

    lines.append(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")
    return "\n".join(lines)
