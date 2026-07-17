"""Console UI helpers: colors, boxes, headers, and input prompts.

Standard library only. Colors are used only when writing to a real terminal and
NO_COLOR is unset; when piped or redirected to a file it falls back to plain text.
"""

from __future__ import annotations

import os
import sys
from typing import Callable, Optional

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _sgr(code: str) -> str:
    return f"\033[{code}m" if _COLOR else ""


RESET = _sgr("0")
BOLD = _sgr("1")
DIM = _sgr("2")
RED = _sgr("31")
GREEN = _sgr("32")
YELLOW = _sgr("33")
BLUE = _sgr("34")
MAGENTA = _sgr("35")
CYAN = _sgr("36")
GRAY = _sgr("90")


def _visible_len(text: str) -> int:
    """Visible character length, ignoring ANSI escape sequences."""
    result = 0
    i = 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
            continue
        result += 1
        i += 1
    return result


def header(title: str) -> None:
    """Print a colored title banner at the top of the screen."""
    line = "═" * (len(title) + 2)
    print()
    print(f"{CYAN}╔{line}╗{RESET}")
    print(f"{CYAN}║ {BOLD}{title}{RESET}{CYAN} ║{RESET}")
    print(f"{CYAN}╚{line}╝{RESET}")


def box(lines: list[str], color: str = CYAN) -> None:
    """Show the lines inside a framed box (aligns correctly around ANSI codes)."""
    width = max((_visible_len(ln) for ln in lines), default=0)
    print(f"{color}┌{'─' * (width + 2)}┐{RESET}")
    for ln in lines:
        pad = " " * (width - _visible_len(ln))
        print(f"{color}│{RESET} {ln}{pad} {color}│{RESET}")
    print(f"{color}└{'─' * (width + 2)}┘{RESET}")


def info(msg: str) -> None:
    print(f"{BLUE}ℹ{RESET}  {msg}")


def success(msg: str) -> None:
    print(f"{GREEN}✔{RESET}  {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}⚠{RESET}  {msg}")


def error(msg: str) -> None:
    print(f"{RED}✖{RESET}  {msg}")


def hint(msg: str) -> None:
    print(f"{GRAY}   {msg}{RESET}")


def rule() -> None:
    print(f"{GRAY}{'─' * 52}{RESET}")


def ask(prompt: str, validator: Optional[Callable[[str], Optional[str]]] = None) -> str:
    """Ask for text input. `validator` returns an error message (str) or None.

    If it returns None the input is accepted; if it returns a str, the error is
    printed and the prompt is repeated.
    """
    while True:
        try:
            value = input(f"{BOLD}{prompt}{RESET} ")
        except EOFError:
            print()
            raise KeyboardInterrupt
        if validator is None:
            return value
        problem = validator(value)
        if problem is None:
            return value
        error(problem)


def ask_int(prompt: str, minimum: int, maximum: int) -> int:
    """Ask for an integer within a range; reject out-of-range input politely."""

    def validate(raw: str) -> Optional[str]:
        raw = raw.strip()
        if not raw.lstrip("-").isdigit():
            return "Please enter an integer."
        value = int(raw)
        if value < minimum or value > maximum:
            return f"The value must be between {minimum} and {maximum}."
        return None

    return int(ask(f"{prompt} {GRAY}[{minimum}–{maximum}]{RESET}", validate).strip())


def confirm(prompt: str, default: bool = True) -> bool:
    """Yes/No question. Empty input selects the default."""
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = ask(f"{prompt} {GRAY}{suffix}{RESET}").strip().lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        error("Please type 'y' or 'n'.")


def pause() -> None:
    try:
        input(f"\n{GRAY}Press Enter to continue…{RESET} ")
    except (EOFError, KeyboardInterrupt):
        print()
