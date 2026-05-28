"""Terminal UI: WarGames intro and curses-based module selection menu."""

import curses
import time

from colorama import Fore, Style

DELAY = 0.060
WORDLIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
TARGET = "CPE1704TKS"


def _print_slowly(text: str, color: str = Fore.GREEN, delay: float = DELAY) -> None:
    """Print text character-by-character for dramatic effect."""
    for ch in text:
        print(f"{color}{ch}{Style.RESET_ALL}", end="", flush=True)
        time.sleep(delay)


def _animate_target_word() -> None:
    """Animate the CPE1704TKS decoding sequence (single-threaded version)."""
    import random

    cur = list(" " * len(TARGET))

    def step() -> bool:
        """One animation tick. Returns True when complete."""
        all_done = True
        for i in range(len(TARGET)):
            if cur[i] != TARGET[i]:
                cur[i] = random.choice(WORDLIST)
                all_done = False
        return all_done

    complete = [False] * len(TARGET)
    max_iters = 200

    for _ in range(max_iters):
        for i in range(len(TARGET)):
            if not complete[i]:
                if cur[i] == TARGET[i]:
                    complete[i] = True
                else:
                    import random
                    cur[i] = random.choice(WORDLIST)
        display = "".join(cur)
        print(f"{Fore.GREEN}{display}{Style.RESET_ALL}", end="\r", flush=True)
        time.sleep(DELAY)
        if all(complete):
            break

    # Final resolved state
    print(f"{Fore.GREEN}{TARGET}{Style.RESET_ALL}")


def display_intro() -> None:
    """Display the WarGames-style intro sequence."""
    _animate_target_word()
    print()
    time.sleep(1)
    _print_slowly("GREETINGS PROFESSOR FALKEN\n\n")
    _print_slowly("\nSHALL WE PLAY A GAME?\n")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    _print_slowly("\nA STRANGE GAME.\n")
    _print_slowly("THE ONLY WINNING MOVE\n")
    _print_slowly("IS NOT TO PLAY.\n")
    time.sleep(2)
    _print_slowly("\nHOW ABOUT A NICE GAME OF SECURITY CHAOS ENGINEERING?\n")
    time.sleep(2)
    _print_slowly("\nHERE ARE A FEW EXPERIMENTS TO CHOOSE FROM:\n")
    time.sleep(1)


# ---------------------------------------------------------------------------
# Curses menu
# ---------------------------------------------------------------------------

_MENU_ACTIONS = [
    "List Modules",
    "Describe Module",
    "Run Dry Run",
    "Execute Lab Module",
    "Cleanup Module",
    "Exit",
]


def _draw_menu(
    stdscr,
    title: str,
    options: list[str],
    selected_row: int,
) -> None:
    stdscr.clear()
    height, width = stdscr.getmaxyx()

    # Title
    try:
        stdscr.addstr(0, 1, title, curses.A_BOLD)
    except curses.error:
        pass

    for idx, option in enumerate(options):
        y = idx + 2
        if y >= height - 1:
            break
        x = 3
        text = option[:width - 4]
        try:
            if idx == selected_row:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(y, x, text)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(y, x, text)
        except curses.error:
            pass

    try:
        stdscr.addstr(height - 1, 1, "Use arrows to navigate, Enter to select, q to quit")
    except curses.error:
        pass

    stdscr.refresh()


def _run_selection_menu(stdscr, title: str, options: list[str]) -> str | None:
    """Generic single-selection curses menu. Returns selected option or None."""
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.curs_set(0)

    cur_row = 0
    _draw_menu(stdscr, title, options, cur_row)

    while True:
        key = stdscr.getch()
        if key == curses.KEY_UP and cur_row > 0:
            cur_row -= 1
        elif key == curses.KEY_DOWN and cur_row < len(options) - 1:
            cur_row += 1
        elif key in (curses.KEY_ENTER, 10, 13):
            return options[cur_row]
        elif key in (ord("q"), ord("Q")):
            return None
        _draw_menu(stdscr, title, options, cur_row)


def run_curses_menu(modules: dict) -> str:
    """Run the full interactive curses menu.

    Returns a command string like 'dry-run:module_name' or 'exit'.
    """
    module_names = sorted(modules.keys())

    def _menu(stdscr) -> str:
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.curs_set(0)

        while True:
            action = _run_selection_menu(
                stdscr,
                "SECURITY CHAOS ENGINEERING - SELECT ACTION",
                _MENU_ACTIONS,
            )

            if action is None or action == "Exit":
                return "exit"

            if action == "List Modules":
                _draw_menu(
                    stdscr,
                    "AVAILABLE MODULES",
                    [f"{name}: {modules[name].description}" for name in module_names],
                    -1,
                )
                stdscr.getch()
                continue

            if action == "Describe Module":
                selected = _run_selection_menu(
                    stdscr, "SELECT MODULE TO DESCRIBE", module_names
                )
                if selected:
                    mod = modules[selected]
                    info = [
                        f"Name:        {mod.name}",
                        f"Description: {mod.description}",
                        f"Category:    {mod.category}",
                        f"Destructive: {mod.destructive}",
                        f"Reversible:  {mod.reversible}",
                        "MITRE ATT&CK:",
                        *[f"  {t}" for t in mod.mitre_attack],
                        "Required Permissions:",
                        *[f"  {p}" for p in mod.required_permissions],
                        "",
                        "Press any key...",
                    ]
                    _draw_menu(stdscr, f"MODULE: {selected}", info, -1)
                    stdscr.getch()
                continue

            if action == "Run Dry Run":
                selected = _run_selection_menu(
                    stdscr, "SELECT MODULE FOR DRY RUN", module_names
                )
                if selected:
                    return f"dry-run:{selected}"
                continue

            if action == "Execute Lab Module":
                selected = _run_selection_menu(
                    stdscr, "SELECT MODULE TO EXECUTE", module_names
                )
                if selected:
                    return f"execute:{selected}"
                continue

            if action == "Cleanup Module":
                selected = _run_selection_menu(
                    stdscr, "SELECT MODULE TO CLEANUP", module_names
                )
                if selected:
                    return f"cleanup:{selected}"
                continue

        return "exit"

    return curses.wrapper(_menu)
