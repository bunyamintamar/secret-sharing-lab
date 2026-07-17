#!/usr/bin/env python3
"""Verifiable Secret Sharing (Feldman VSS) — console application.

Run:
    python3 vss.py

Difference from classic SSS: the dealer publishes public **commitments**. Each
shareholder can prove their share is correct without learning the secret; a
cheating dealer (or a corrupted share) is caught immediately.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shamir import ui, vss
from shamir.vss import VSSShare, VSSError
from shamir.vss_encoding import (
    ParsedCommitments,
    ParsedVSSShare,
    decode_commitments,
    decode_share,
    encode_commitments,
    encode_share,
    new_set_id,
    VSSEncodingError,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Explanation
# ─────────────────────────────────────────────────────────────────────────────

def show_intro() -> None:
    ui.header("What is Verifiable Secret Sharing (VSS)?")
    print(f"""
With classic Shamir you have to {ui.BOLD}trust the dealer{ui.RESET} who creates the shares.
If they hand you a bad share, you only find out when combining — too late.

{ui.CYAN}Feldman VSS{ui.RESET} fixes this: alongside the shares the dealer publishes
public {ui.BOLD}commitments{ui.RESET}. These commitments reveal nothing about the secret,
yet they are enough for everyone to verify their own share.
""")
    ui.box([
        f"{ui.BOLD}Commitments{ui.RESET} = g^(coefficient) mod p  (public)",
        f"{ui.BOLD}Verify{ui.RESET}      = g^share  ==  value expected from the commitments",
        "",
        f"{ui.GREEN}Share checks out{ui.RESET}  → the dealer is honest for this share",
        f"{ui.RED}Share fails{ui.RESET}      → the share is corrupted or the dealer cheated",
    ])
    print(f"""
{ui.DIM}Security:{ui.RESET} Because the discrete logarithm is hard, the secret cannot be
recovered from a commitment.
{ui.DIM}Group:{ui.RESET} RFC 3526 2048-bit safe prime. The secret is encoded as a single
integer in Z_q (at most {vss.MAX_SECRET_BYTES} bytes). For educational use.
""")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Split
# ─────────────────────────────────────────────────────────────────────────────

def do_split() -> None:
    ui.header("Split the secret (with commitments)")
    secret_text = ui.ask(
        "Secret (one line of text):",
        validator=lambda s: "The secret cannot be empty." if s == "" else None,
    )
    secret_bytes = secret_text.encode("utf-8")
    if len(secret_bytes) > vss.MAX_SECRET_BYTES:
        ui.error(f"The secret is too long: {len(secret_bytes)} bytes. At most "
                 f"{vss.MAX_SECRET_BYTES} bytes.")
        return
    ui.hint(f"{len(secret_bytes)} bytes (UTF-8).")
    print()

    n = ui.ask_int("Total shares n:", 2, 255)
    print()
    ui.info(f"How many of these {n} shares should reconstruct the secret?")
    k = ui.ask_int("Threshold k:", 2, n)

    try:
        shares, commitments = vss.split(secret_bytes, threshold=k, shares=n)
    except VSSError as exc:
        ui.error(str(exc))
        return

    set_id = new_set_id()
    enc_shares = [encode_share(s.x, s.y, k, set_id) for s in shares]
    enc_commit = encode_commitments(commitments, k, set_id)

    print()
    ui.success(f"{n} shares and 1 commitment block generated. Any {ui.BOLD}{k}{ui.RESET} shares reconstruct the secret.")
    ui.hint(f"Set id: {set_id:04x}")
    print()

    ui.info("SHARES (secret — one per person/place):")
    for i, line in enumerate(enc_shares, start=1):
        ui.box([f"{ui.BOLD}Share {i}/{n}{ui.RESET}", f"{ui.CYAN}{line}{ui.RESET}"], color=ui.GRAY)

    print()
    ui.info("COMMITMENTS (public — share openly for verification):")
    ui.box([f"{ui.MAGENTA}{_shorten(enc_commit)}{ui.RESET}",
            f"{ui.DIM}(full text {len(enc_commit)} characters — saving is recommended){ui.RESET}"],
           color=ui.GRAY)

    print()
    ui.warn("Keep the shares secret, share the commitments openly. Shareholders can "
            "check their share with 'Verify my share'.")
    print()
    if ui.confirm("Save the shares and commitments to files?", default=True):
        _save_all(enc_shares, enc_commit, set_id, k, n)
    ui.pause()


def _shorten(s: str, head: int = 40, tail: int = 12) -> str:
    return s if len(s) <= head + tail + 3 else f"{s[:head]}…{s[-tail:]}"


def _save_all(enc_shares: list[str], enc_commit: str, set_id: int, k: int, n: int) -> None:
    folder = ui.ask("Folder path:",
                    validator=lambda s: "Cannot be empty." if s.strip() == "" else None).strip()
    folder = os.path.expanduser(folder)
    try:
        os.makedirs(folder, exist_ok=True)
        for i, line in enumerate(enc_shares, start=1):
            with open(os.path.join(folder, f"share-{i:02d}.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"# VSS share  set={set_id:04x} k={k} n={n} share={i}\n")
                fh.write("# SECRET. Verification requires commitments.txt.\n")
                fh.write(line + "\n")
        with open(os.path.join(folder, "commitments.txt"), "w", encoding="utf-8") as fh:
            fh.write(f"# VSS commitments  set={set_id:04x} k={k}\n")
            fh.write("# PUBLIC data — can be shared with anyone.\n")
            fh.write(enc_commit + "\n")
    except OSError as exc:
        ui.error(f"Could not save: {exc}")
        return
    ui.success(f"Saved {n} shares + commitments.txt to '{folder}'.")


# ─────────────────────────────────────────────────────────────────────────────
#  Verify
# ─────────────────────────────────────────────────────────────────────────────

def do_verify() -> None:
    ui.header("Verify my share")
    ui.info("First provide the commitments, then the share to verify.")
    print()

    commits = _ask_commitments()
    if commits is None:
        ui.pause()
        return

    line = ui.ask("Share to verify:")
    try:
        share = decode_share(line)
    except VSSEncodingError as exc:
        ui.error(str(exc))
        ui.pause()
        return

    if share.set_id != commits.set_id:
        ui.warn(f"Share ({share.set_id:04x}) and commitments ({commits.set_id:04x}) have "
                f"different set ids — they probably don't belong to the same split.")

    ok = vss.verify_share(share.x, share.y, commits.values)
    print()
    if ok:
        ui.success(f"Share is VALID (x={share.x}). The dealer is honest for this share; "
                   f"it can be used safely when combining.")
    else:
        ui.error(f"Share is INVALID (x={share.x}). It does not match the commitments — "
                 f"the share is corrupted or the dealer cheated. DO NOT use this share.")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Combine
# ─────────────────────────────────────────────────────────────────────────────

def do_combine() -> None:
    ui.header("Combine shares")
    ui.info("Optionally provide the commitments first; each share is verified before "
            "combining and bad shares are dropped.")
    print()

    commits = None
    if ui.confirm("Verify with commitments? (recommended)", default=True):
        commits = _ask_commitments()

    ui.info("Paste shares one by one. Leave a blank line to finish.")
    parsed: list[ParsedVSSShare] = []
    seen: set[int] = set()
    while True:
        raw = ui.ask(f"Share {len(parsed) + 1}:")
        if raw.strip() == "":
            break
        try:
            s = decode_share(raw)
        except VSSEncodingError as exc:
            ui.error(str(exc))
            continue
        if s.x in seen:
            ui.warn(f"x={s.x} is already added, skipped.")
            continue
        if commits is not None and not vss.verify_share(s.x, s.y, commits.values):
            ui.error(f"Share x={s.x} does NOT match the commitments — dropped (will not be used).")
            continue
        seen.add(s.x)
        parsed.append(s)
        tag = " (verified)" if commits is not None else ""
        ui.success(f"Share added (x={s.x}){tag}. Total {len(parsed)}.")

    if not parsed:
        ui.warn("No valid shares, cancelled.")
        ui.pause()
        return

    k = min(s.threshold for s in parsed)
    if len(parsed) < k:
        ui.error(f"Not enough shares: {len(parsed)} present, at least {k} required.")
        ui.pause()
        return

    try:
        secret = vss.combine([VSSShare(x=s.x, y=s.y) for s in parsed])
        text = secret.decode("utf-8")
        print()
        ui.success("Secret reconstructed:")
        ui.box([f"{ui.GREEN}{ui.BOLD}{text}{ui.RESET}"], color=ui.GREEN)
    except (VSSError, UnicodeDecodeError):
        ui.error("Could not reconstruct the secret — shares may be missing/incompatible.")
    ui.pause()


# ─────────────────────────────────────────────────────────────────────────────
#  Commitment input (paste or from file)
# ─────────────────────────────────────────────────────────────────────────────

def _ask_commitments() -> ParsedCommitments | None:
    print(f"  {ui.BOLD}1{ui.RESET}) Paste the commitments")
    print(f"  {ui.BOLD}2{ui.RESET}) Load commitments.txt from a folder")
    choice = ui.ask_int("Choice:", 1, 2)
    if choice == 1:
        raw = ui.ask("Commitment block (VCOM1-…):")
    else:
        folder = ui.ask("Folder path:").strip()
        path = os.path.join(os.path.expanduser(folder), "commitments.txt")
        raw = _first_vcom_line(path)
        if raw is None:
            ui.error(f"No commitments found in '{path}'.")
            return None
    try:
        return decode_commitments(raw)
    except VSSEncodingError as exc:
        ui.error(str(exc))
        return None


def _first_vcom_line(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("VCOM1-"):
                    return line
    except OSError:
        return None
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Menu
# ─────────────────────────────────────────────────────────────────────────────

def main_menu() -> None:
    ui.header("Verifiable Secret Sharing — Console")
    print(f"{ui.DIM}Without trusting the dealer: split, verify, and combine shares.{ui.RESET}")

    actions = {
        "1": ("Split a secret (with commitments)", do_split),
        "2": ("Verify my share", do_verify),
        "3": ("Combine shares", do_combine),
        "4": ("What is VSS?", show_intro),
        "5": ("Exit", None),
    }
    while True:
        print()
        ui.rule()
        for key, (label, _) in actions.items():
            print(f"  {ui.BOLD}{ui.CYAN}{key}{ui.RESET}) {label}")
        ui.rule()
        choice = ui.ask("Your choice:").strip()
        if choice not in actions:
            ui.error("Invalid choice.")
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
