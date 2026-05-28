"""CLI entry point for Joshua's Chaos security chaos engineering framework."""

import argparse
import sys
from pathlib import Path

from colorama import Fore, Style
from colorama import init as colorama_init

colorama_init()


def _print_banner() -> None:
    banner = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗
║          JOSHUA'S CHAOS - AWS Security Chaos Engineering      ║
║    For authorized lab, purple-team, and detection eng. only   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def _print_error(msg: str) -> None:
    print(f"{Fore.RED}[ERROR] {msg}{Style.RESET_ALL}", file=sys.stderr)


def _print_info(msg: str) -> None:
    print(f"{Fore.CYAN}[INFO] {msg}{Style.RESET_ALL}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="joshuas-chaos",
        description="AWS Security Chaos Engineering Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                                          # interactive menu
  python main.py list                                     # list modules
  python main.py describe passrole_lambda                 # describe module
  python main.py run passrole_lambda --dry-run            # dry run (default)
  python main.py run passrole_lambda --execute \\
      --confirm-account 123456789012 \\
      --i-understand-this-is-authorized                   # execute mode
  python main.py cleanup passrole_lambda \\
      --confirm-account 123456789012                      # cleanup
        """,
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile name",
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS region (overrides config)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for JSON output files",
    )
    parser.add_argument(
        "--no-intro",
        action="store_true",
        help="Skip the WarGames intro animation",
    )

    subparsers = parser.add_subparsers(dest="command")

    # list
    subparsers.add_parser("list", help="List all available modules")

    # describe
    describe_parser = subparsers.add_parser("describe", help="Describe a module")
    describe_parser.add_argument("module_name", help="Module name")

    # run
    run_parser = subparsers.add_parser("run", help="Run a module")
    run_parser.add_argument("module_name", help="Module name")
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Run in dry-run mode (default)",
    )
    run_parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Run in execute mode (requires additional flags)",
    )
    run_parser.add_argument(
        "--confirm-account",
        default="",
        help="Confirm the target AWS account ID (required for execute)",
    )
    run_parser.add_argument(
        "--i-understand-this-is-authorized",
        action="store_true",
        default=False,
        dest="i_understand",
        help="Confirm authorized use (required for execute)",
    )

    # cleanup
    cleanup_parser = subparsers.add_parser("cleanup", help="Run cleanup for a module")
    cleanup_parser.add_argument("module_name", help="Module name")
    cleanup_parser.add_argument(
        "--confirm-account",
        default="",
        help="Confirm the target AWS account ID",
    )

    return parser


def _run_module(
    module,
    context,
    config,
    mode: str,
    safety_checker=None,
    execute_flags: dict | None = None,
) -> int:
    """Execute a module method and print/save results. Returns exit code."""
    from joshuas_chaos.core.output import format_result_table, write_result
    from joshuas_chaos.core.safety import SafetyError

    try:
        if mode == "dry-run":
            result = module.dry_run(context, config)
        elif mode == "execute":
            # Execute flags are ALWAYS required — never skip this check
            if safety_checker is None or execute_flags is None:
                _print_error(
                    "Execute mode requires --execute --confirm-account <id> "
                    "--i-understand-this-is-authorized. Use the CLI run command."
                )
                return 3
            safety_checker.assert_execute_flags(
                execute=execute_flags.get("execute", False),
                confirm_account=execute_flags.get("confirm_account", ""),
                i_understand=execute_flags.get("i_understand", False),
            )
            result = module.execute(context, config)
        elif mode == "cleanup":
            result = module.cleanup(context, config)
        else:
            _print_error(f"Unknown mode: {mode}")
            return 1
    except SafetyError as exc:
        _print_error(f"Safety check failed: {exc}")
        return 3
    except NotImplementedError as exc:
        _print_error(str(exc))
        return 1

    print(format_result_table(result))

    output_path = write_result(result)
    _print_info(f"Result saved to: {output_path}")

    return 0 if not result.errors else 1


def cli_main(argv: list[str] | None = None) -> int:
    """Main CLI entry point. Returns exit code."""
    from joshuas_chaos.core.aws_context import AWSContext, AWSContextError
    from joshuas_chaos.core.config import ConfigError, load_config
    from joshuas_chaos.core.logger import setup_logging
    from joshuas_chaos.core.module_loader import ModuleLoadError, discover_modules, get_module
    from joshuas_chaos.core.safety import SafetyChecker, SafetyError

    setup_logging()
    _print_banner()

    parser = _build_parser()
    args = parser.parse_args(argv)

    # Load config — fail closed
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        _print_error(f"Configuration error: {exc}")
        _print_error("Refusing to run without a valid config.yaml.")
        return 2

    # Initialize AWS context
    region = args.region or config.allowed_regions[0]
    try:
        context = AWSContext(profile_name=args.profile, region=region)
        identity = context.get_caller_identity()
    except AWSContextError as exc:
        _print_error(f"AWS context error: {exc}")
        return 2

    _print_info(
        f"Account: {identity.account_id} | Principal: {identity.arn} | Region: {region}"
    )

    # Safety: assert account in allowlist before doing anything
    checker = SafetyChecker(config, identity)
    try:
        checker.assert_account_allowed()
        checker.assert_region_allowed(region)
    except SafetyError as exc:
        _print_error(f"Safety check failed: {exc}")
        return 3

    # Discover modules
    modules = discover_modules()

    # No command → interactive menu
    if not args.command:
        from joshuas_chaos.core.menu import display_intro, run_curses_menu

        if not args.no_intro:
            try:
                display_intro()
            except KeyboardInterrupt:
                pass

        try:
            selection = run_curses_menu(modules)
        except KeyboardInterrupt:
            print("\nExiting.")
            return 0

        if selection == "exit" or not selection:
            print(f"{Fore.GREEN}GAME OVER{Style.RESET_ALL}")
            return 0

        parts = selection.split(":", 1)
        if len(parts) != 2:
            return 0

        mode, module_name = parts

        try:
            module = get_module(module_name, modules)
        except ModuleLoadError as exc:
            _print_error(str(exc))
            return 1

        if mode == "execute":
            _print_error(
                "Execute mode via menu requires --execute --confirm-account and "
                "--i-understand-this-is-authorized flags. Use CLI run command."
            )
            return 3

        return _run_module(module, context, config, mode)

    # list
    if args.command == "list":
        print(f"\n{Fore.YELLOW}Available Modules:{Style.RESET_ALL}\n")
        for name, mod in sorted(modules.items()):
            enabled = config.modules.get(name, {}).get("enabled", True)
            status = f"{Fore.GREEN}enabled{Style.RESET_ALL}" if enabled else f"{Fore.RED}disabled{Style.RESET_ALL}"
            print(
                f"  {Fore.CYAN}{name:<40}{Style.RESET_ALL} "
                f"{Fore.WHITE}{mod.category:<25}{Style.RESET_ALL} "
                f"{Fore.YELLOW}{mod.mitre_attack}{Style.RESET_ALL} [{status}]"
            )
        print()
        return 0

    # describe
    if args.command == "describe":
        try:
            module = get_module(args.module_name, modules)
        except ModuleLoadError as exc:
            _print_error(str(exc))
            return 1

        print(f"\n{Fore.YELLOW}Module: {module.name}{Style.RESET_ALL}")
        print(f"  Description:  {module.description}")
        print(f"  Category:     {module.category}")
        print(f"  Destructive:  {module.destructive}")
        print(f"  Reversible:   {module.reversible}")
        print(f"  MITRE ATT&CK: {module.mitre_attack}")
        print("  Required Permissions:")
        for perm in module.required_permissions:
            print(f"    - {perm}")
        print("  CloudTrail Events:")
        for event in module.cloudtrail_events:
            print(f"    - {event}")
        print()
        return 0

    # run
    if args.command == "run":
        try:
            module = get_module(args.module_name, modules)
        except ModuleLoadError as exc:
            _print_error(str(exc))
            return 1

        if args.execute:
            mode = "execute"
            execute_flags = {
                "execute": True,
                "confirm_account": args.confirm_account,
                "i_understand": args.i_understand,
            }
            try:
                checker.assert_execute_flags(
                    execute=True,
                    confirm_account=args.confirm_account,
                    i_understand=args.i_understand,
                )
            except SafetyError as exc:
                _print_error(f"Execute safety check failed: {exc}")
                return 3
        else:
            mode = "dry-run"
            execute_flags = None

        return _run_module(
            module,
            context,
            config,
            mode,
            checker,
            execute_flags,
        )

    # cleanup
    if args.command == "cleanup":
        try:
            module = get_module(args.module_name, modules)
        except ModuleLoadError as exc:
            _print_error(str(exc))
            return 1

        if args.confirm_account and args.confirm_account != identity.account_id:
            _print_error(
                f"--confirm-account '{args.confirm_account}' does not match "
                f"current account '{identity.account_id}'."
            )
            return 3

        return _run_module(module, context, config, "cleanup")

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(cli_main())
