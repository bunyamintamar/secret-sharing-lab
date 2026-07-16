"""Konsol arayüzü yardımcıları: renkler, kutular, başlıklar ve girdi soruları.

Sadece standart kütüphane. Renkler yalnızca gerçek bir terminale yazılırken ve
NO_COLOR ayarlı değilken kullanılır; boru (pipe) veya dosyaya yazımda düz metne düşer.
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
    """ANSI kaçış dizilerini saymadan görünen karakter uzunluğu."""
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
    """Ekranın üstüne renkli bir başlık şeridi basar."""
    line = "═" * (len(title) + 2)
    print()
    print(f"{CYAN}╔{line}╗{RESET}")
    print(f"{CYAN}║ {BOLD}{title}{RESET}{CYAN} ║{RESET}")
    print(f"{CYAN}╚{line}╝{RESET}")


def box(lines: list[str], color: str = CYAN) -> None:
    """Satırları çerçeveli bir kutu içinde gösterir (ANSI'yi doğru hizalar)."""
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
    """Metin girdisi ister. validator, hata mesajı (str) veya None döndürür.

    None döndürürse girdi kabul edilir; str döndürürse hata basılır ve tekrar sorulur.
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
    """Belirli aralıkta bir tam sayı ister; aralık dışını nazikçe reddeder."""

    def validate(raw: str) -> Optional[str]:
        raw = raw.strip()
        if not raw.lstrip("-").isdigit():
            return "Lütfen bir tam sayı girin."
        value = int(raw)
        if value < minimum or value > maximum:
            return f"Değer {minimum} ile {maximum} arasında olmalı."
        return None

    return int(ask(f"{prompt} {GRAY}[{minimum}–{maximum}]{RESET}", validate).strip())


def confirm(prompt: str, default: bool = True) -> bool:
    """Evet/Hayır sorusu. Boş girdi varsayılanı seçer."""
    suffix = "[E/h]" if default else "[e/H]"
    while True:
        answer = ask(f"{prompt} {GRAY}{suffix}{RESET}").strip().lower()
        if answer == "":
            return default
        if answer in ("e", "evet", "y", "yes"):
            return True
        if answer in ("h", "hayır", "hayir", "n", "no"):
            return False
        error("Lütfen 'e' veya 'h' yazın.")


def pause() -> None:
    try:
        input(f"\n{GRAY}Devam etmek için Enter'a basın…{RESET} ")
    except (EOFError, KeyboardInterrupt):
        print()
