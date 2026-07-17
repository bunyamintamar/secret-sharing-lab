#!/usr/bin/env python3
"""Shamir Secret Sharing — friendly console application.

Run:
    python3 sss.py

Splits a secret (text) into n shares; any k shares reconstruct it, fewer than k
reveal no information. All operations happen in the GF(256) finite field.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shamir import Share, split, combine, SSSError, ui
from shamir.encoding import (
    ParsedShare,
    decode_share,
    encode_share,
    new_set_id,
    EncodingError,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Explanation screen
# ─────────────────────────────────────────────────────────────────────────────

def show_intro() -> None:
    ui.header("What is Shamir Secret Sharing?")
    print(f"""
You have a secret: a password, an encryption key, a recovery phrase.
Entrusting it to {ui.BOLD}a single person{ui.RESET} is risky (they may lose it or be compromised);
{ui.BOLD}copying it to everyone{ui.RESET} is risky too (anyone can unlock it alone).

Shamir's solution is a {ui.CYAN}(k, n) threshold scheme{ui.RESET}:
""")
    ui.box([
        f"{ui.BOLD}n{ui.RESET} = total number of shares (how many pieces to split into)",
        f"{ui.BOLD}k{ui.RESET} = threshold (how many shares are needed to combine)",
        "",
        f"{ui.GREEN}Any k shares{ui.RESET}   → the secret is fully reconstructed",
        f"{ui.YELLOW}Fewer than k{ui.RESET}  → zero information (every secret equally likely)",
    ])
    print(f"""
{ui.DIM}How does it work?{ui.RESET} The secret becomes the constant term of a secret
polynomial of degree (k-1). Shares are points on that curve. k points determine
the curve uniquely and reveal the constant term (the secret); k-1 points fit
infinitely many curves, so they give nothing away.

{ui.DIM}Example (3, 5):{ui.RESET} Split the secret into 5 shares, hand them to 5
people you trust. Any 3 together recover the secret; even 2 colluding cannot.
""")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Split the secret
# ─────────────────────────────────────────────────────────────────────────────

def do_split() -> None:
    ui.header("Split the secret into shares")
    ui.info("First I'll ask for the secret, then the number of shares and the threshold.")
    print()

    secret_text = ui.ask(
        "Secret (one line of text):",
        validator=lambda s: "The secret cannot be empty." if s == "" else None,
    )
    secret_bytes = secret_text.encode("utf-8")
    ui.hint(f"{len(secret_bytes)} bytes (UTF-8).")
    print()

    ui.info("Number of shares (n): into how many pieces? (at most 255)")
    n = ui.ask_int("Total shares n:", 2, 255)

    print()
    ui.info(f"Threshold (k): how many of these {n} shares should reconstruct the secret?")
    ui.hint("k=n means everyone is required; smaller k needs fewer shares (but is less secure).")
    k = ui.ask_int("Threshold k:", 2, n)

    try:
        shares = split(secret_bytes, threshold=k, shares=n)
    except SSSError as exc:
        ui.error(str(exc))
        return

    set_id = new_set_id()
    encoded = [encode_share(s.x, s.y, k, set_id) for s in shares]

    print()
    ui.success(f"{n} shares generated. Any {ui.BOLD}{k}{ui.RESET} of the shares below"
               f" reconstruct the secret.")
    ui.hint(f"Set id: {set_id:04x} — every share from this split carries it.")
    print()

    for i, line in enumerate(encoded, start=1):
        ui.box([
            f"{ui.BOLD}Share {i} / {n}{ui.RESET}",
            f"{ui.CYAN}{line}{ui.RESET}",
        ], color=ui.GRAY)

    print()
    ui.warn("Store the shares in DIFFERENT places/people. If they all sit in one place the scheme is pointless.")
    ui.warn(f"If you lose more than {n - k} shares the secret is UNRECOVERABLE — there is no backup.")
    print()

    if ui.confirm("Save the shares to files?", default=False):
        _save_shares(encoded, set_id, k, n)

    ui.pause()


def _save_shares(encoded: list[str], set_id: int, k: int, n: int) -> None:
    folder = ui.ask(
        "Folder path:",
        validator=lambda s: "Cannot be empty." if s.strip() == "" else None,
    ).strip()
    folder = os.path.expanduser(folder)
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as exc:
        ui.error(f"Could not create the folder: {exc}")
        return

    for i, line in enumerate(encoded, start=1):
        path = os.path.join(folder, f"share-{i:02d}.txt")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# Shamir Secret Sharing share\n")
                fh.write(f"# set={set_id:04x}  threshold(k)={k}  total(n)={n}  share={i}\n")
                fh.write(f"# Combining requires at least {k} share files.\n")
                fh.write(line + "\n")
        except OSError as exc:
            ui.error(f"Could not write '{path}': {exc}")
            return

    ui.success(f"{n} shares saved to '{folder}' (share-01.txt … share-{n:02d}.txt).")


# ─────────────────────────────────────────────────────────────────────────────
#  Combine the shares
# ─────────────────────────────────────────────────────────────────────────────

def do_combine() -> None:
    ui.header("Combine shares")
    ui.info("You can provide shares by pasting them or by loading a folder of files.")
    print()

    print(f"  {ui.BOLD}1{ui.RESET}) Paste shares one by one")
    print(f"  {ui.BOLD}2{ui.RESET}) Load from files in a folder")
    print()
    choice = ui.ask_int("Choice:", 1, 2)

    if choice == 1:
        parsed = _collect_shares_pasted()
    else:
        parsed = _collect_shares_from_files()

    if not parsed:
        ui.warn("No valid shares received, combining cancelled.")
        ui.pause()
        return

    _try_reconstruct(parsed)
    ui.pause()


def _collect_shares_pasted() -> list[ParsedShare]:
    ui.info("Paste one share per line. Leave a blank line to finish (Enter).")
    collected: list[ParsedShare] = []
    threshold_hint: int | None = None

    while True:
        remaining = ""
        if threshold_hint is not None:
            need = threshold_hint - len(collected)
            if need > 0:
                remaining = f"{ui.GRAY}(at least {need} more){ui.RESET}"
            else:
                remaining = f"{ui.GREEN}(enough, press Enter to finish){ui.RESET}"
        line = ui.ask(f"Share {len(collected) + 1} {remaining}:")
        if line.strip() == "":
            break
        try:
            share = decode_share(line)
        except EncodingError as exc:
            ui.error(str(exc))
            continue
        if any(s.x == share.x for s in collected):
            ui.warn(f"Share x={share.x} is already added, skipped.")
            continue
        collected.append(share)
        threshold_hint = share.threshold
        ui.success(f"Share added (x={share.x}). Total {len(collected)} shares.")

    return collected


def _collect_shares_from_files() -> list[ParsedShare]:
    folder = ui.ask(
        "Folder containing the share files:",
        validator=lambda s: "Cannot be empty." if s.strip() == "" else None,
    ).strip()
    folder = os.path.expanduser(folder)
    if not os.path.isdir(folder):
        ui.error(f"Folder not found: {folder}")
        return []

    collected: list[ParsedShare] = []
    seen_x: set[int] = set()
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except OSError:
            continue
        for raw in content.splitlines():
            raw = raw.strip()
            if raw == "" or raw.startswith("#"):
                continue
            try:
                share = decode_share(raw)
            except EncodingError:
                continue
            if share.x in seen_x:
                continue
            seen_x.add(share.x)
            collected.append(share)

    if collected:
        ui.success(f"{len(collected)} valid shares loaded.")
    else:
        ui.warn("No valid shares found in the folder.")
    return collected


def _try_reconstruct(parsed: list[ParsedShare]) -> None:
    # Different set ids probably mean shares from different secrets got mixed.
    set_ids = {s.set_id for s in parsed}
    if len(set_ids) > 1:
        ui.warn("Shares come from different splits (set ids differ) — "
                "shares from separate secrets were probably mixed. The result may be meaningless.")

    thresholds = {s.threshold for s in parsed}
    k = min(thresholds)
    if len(thresholds) > 1:
        ui.warn(f"Shares report different thresholds {sorted(thresholds)}; "
                f"the smallest ({k}) will be used.")

    if len(parsed) < k:
        ui.error(f"Not enough shares: {len(parsed)} present, at least {k} required.")
        return

    shares = [Share(x=s.x, y=s.y) for s in parsed]
    try:
        secret_bytes = combine(shares)
    except SSSError as exc:
        ui.error(str(exc))
        return

    print()
    try:
        text = secret_bytes.decode("utf-8")
        ui.success("Secret successfully reconstructed:")
        ui.box([f"{ui.GREEN}{ui.BOLD}{text}{ui.RESET}"], color=ui.GREEN)
    except UnicodeDecodeError:
        ui.warn("The result is not valid text (shares may be wrong or missing).")
        ui.box([f"Raw bytes (hex): {secret_bytes.hex()}"], color=ui.YELLOW)


# ─────────────────────────────────────────────────────────────────────────────
#  Main menu
# ─────────────────────────────────────────────────────────────────────────────

def main_menu() -> None:
    ui.header("Shamir Secret Sharing — Console")
    print(f"{ui.DIM}Split a secret into shares, then reconstruct it with a threshold number of shares.{ui.RESET}")

    actions = {
        "1": ("Split a secret into shares", do_split),
        "2": ("Combine shares (reconstruct the secret)", do_combine),
        "3": ("What is Shamir Secret Sharing?", show_intro),
        "4": ("Exit", None),
    }

    while True:
        print()
        ui.rule()
        for key, (label, _) in actions.items():
            print(f"  {ui.BOLD}{ui.CYAN}{key}{ui.RESET}) {label}")
        ui.rule()

        choice = ui.ask("Your choice:").strip()
        if choice not in actions:
            ui.error("Invalid choice, please enter a number from the menu.")
            continue

        label, func = actions[choice]
        if func is None:
            print(f"\n{ui.CYAN}See you! Keep your shares safe.{ui.RESET}\n")
            return
        func()


def main() -> int:
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{ui.GRAY}Cancelled. Exiting.{ui.RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
