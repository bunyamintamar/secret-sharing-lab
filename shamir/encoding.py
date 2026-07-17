"""Encode/decode shares as safe, human-readable text strings.

Each share becomes a single-line string. As the diagrams warn, if metadata is
not carried alongside a share, nobody can combine it years later — so the scheme
version, the threshold (k), and a "set id" are embedded into the share, with a
checksum appended (to catch typos).

Format:
    SSS1-<setid>-<k>-<x>-<hexY>-<crc>
      SSS1   : version tag
      setid  : 4-digit hex; identical for every share from the same split
               (so shares from different secrets are noticed if mixed)
      k      : threshold (number of shares needed to combine)
      x      : share number (1..255)
      hexY   : the share's byte data (hex)
      crc    : CRC-16 checksum of the preceding fields (4-digit hex)

Example:  SSS1-a3f1-3-2-9e02b755-1a2b
"""

from __future__ import annotations

import secrets
import zlib
from dataclasses import dataclass

_PREFIX = "SSS1"


class EncodingError(Exception):
    """Raised when a share string cannot be decoded / its checksum fails."""


@dataclass
class ParsedShare:
    """The fields of a decoded share string."""

    set_id: int
    threshold: int
    x: int
    y: bytes


def new_set_id() -> int:
    """Generate a random 16-bit set id for a split."""
    return secrets.randbits(16)


def _crc(body: str) -> int:
    return zlib.crc32(body.encode("ascii")) & 0xFFFF


def encode_share(x: int, y: bytes, threshold: int, set_id: int) -> str:
    """Encode a share as a single-line string."""
    body = f"{_PREFIX}-{set_id:04x}-{threshold}-{x}-{y.hex()}"
    return f"{body}-{_crc(body):04x}"


def decode_share(text: str) -> ParsedShare:
    """Decode a share string; raise EncodingError on a bad format or checksum."""
    cleaned = text.strip()
    parts = cleaned.split("-")
    if len(parts) != 6 or parts[0] != _PREFIX:
        raise EncodingError(
            "Unrecognized share format. Expected: "
            "SSS1-<setid>-<k>-<x>-<hex>-<crc>"
        )

    prefix, setid_hex, k_str, x_str, y_hex, crc_hex = parts

    body = "-".join(parts[:5])
    try:
        expected_crc = int(crc_hex, 16)
    except ValueError:
        raise EncodingError("The checksum field (crc) is not hex.")
    if _crc(body) != expected_crc:
        raise EncodingError(
            "Checksum mismatch — the share was most likely mistyped."
        )

    try:
        set_id = int(setid_hex, 16)
        threshold = int(k_str)
        x = int(x_str)
        y = bytes.fromhex(y_hex)
    except ValueError:
        raise EncodingError("Could not read the share fields (number/hex error).")

    if not (1 <= x <= 255):
        raise EncodingError(f"Invalid share number x={x} (must be 1..255).")
    if threshold < 2:
        raise EncodingError(f"Invalid threshold k={threshold} (at least 2).")
    if len(y) == 0:
        raise EncodingError("The share's data part is empty.")

    return ParsedShare(set_id=set_id, threshold=threshold, x=x, y=y)
