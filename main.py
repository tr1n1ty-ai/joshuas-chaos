"""Entry point shim — delegates to joshuas_chaos.main.

The original implementation has been refactored into the joshuas_chaos package.
This file is kept as the top-level entry point for backwards compatibility.
"""

import sys


def main() -> None:
    from joshuas_chaos.main import cli_main

    sys.exit(cli_main())


if __name__ == "__main__":
    main()
