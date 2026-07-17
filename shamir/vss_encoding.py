"""Text encoding for VSS shares and commitments (with a CRC checksum).

Formats:
    Share       :  VSS1-<setid>-<k>-<x>-<yhex>-<crc>
    Commitments :  VCOM1-<setid>-<k>-<C0hex.C1hex.….C(k-1)hex>-<crc>

  setid : shares and commitments from the same split carry the same 4-digit id.
  yhex  : the share value y (integer in Z_q), hex.
  Cjhex : commitment C_j (integer mod p), hex; separated by dots.
  crc   : CRC-16 checksum of the preceding fields (compatible with zlib.crc32 & 0xFFFF).
"""

from __future__ import annotations

import secrets
import zlib
from dataclasses import dataclass


class VSSEncodingError(Exception):
    """Raised when a VSS string cannot be decoded / its checksum fails."""


@dataclass
class ParsedVSSShare:
    set_id: int
    threshold: int
    x: int
    y: int


@dataclass
class ParsedCommitments:
    set_id: int
    threshold: int
    values: list[int]


def new_set_id() -> int:
    return secrets.randbits(16)


def _crc(body: str) -> int:
    return zlib.crc32(body.encode("ascii")) & 0xFFFF


def encode_share(x: int, y: int, threshold: int, set_id: int) -> str:
    body = f"VSS1-{set_id:04x}-{threshold}-{x}-{y:x}"
    return f"{body}-{_crc(body):04x}"


def decode_share(text: str) -> ParsedVSSShare:
    parts = text.strip().split("-")
    if len(parts) != 6 or parts[0] != "VSS1":
        raise VSSEncodingError(
            "Unrecognized share format. Expected: VSS1-<setid>-<k>-<x>-<yhex>-<crc>"
        )
    body = "-".join(parts[:5])
    try:
        if _crc(body) != int(parts[5], 16):
            raise VSSEncodingError("Checksum mismatch — the share may be mistyped.")
        set_id = int(parts[1], 16)
        threshold = int(parts[2])
        x = int(parts[3])
        y = int(parts[4], 16)
    except ValueError:
        raise VSSEncodingError("Could not read the share fields.")
    if not (1 <= x <= 255):
        raise VSSEncodingError(f"Invalid share number x={x}.")
    if threshold < 2:
        raise VSSEncodingError(f"Invalid threshold k={threshold}.")
    return ParsedVSSShare(set_id=set_id, threshold=threshold, x=x, y=y)


def encode_commitments(commitments: list[int], threshold: int, set_id: int) -> str:
    joined = ".".join(f"{c:x}" for c in commitments)
    body = f"VCOM1-{set_id:04x}-{threshold}-{joined}"
    return f"{body}-{_crc(body):04x}"


def decode_commitments(text: str) -> ParsedCommitments:
    parts = text.strip().split("-")
    if len(parts) != 5 or parts[0] != "VCOM1":
        raise VSSEncodingError(
            "Unrecognized commitment format. Expected: VCOM1-<setid>-<k>-<C0.C1…>-<crc>"
        )
    body = "-".join(parts[:4])
    try:
        if _crc(body) != int(parts[4], 16):
            raise VSSEncodingError("Commitment checksum mismatch — it may be mistyped.")
        set_id = int(parts[1], 16)
        threshold = int(parts[2])
        values = [int(h, 16) for h in parts[3].split(".") if h != ""]
    except ValueError:
        raise VSSEncodingError("Could not read the commitment fields.")
    if len(values) != threshold:
        raise VSSEncodingError(
            f"The number of commitments ({len(values)}) does not match the threshold (k={threshold})."
        )
    return ParsedCommitments(set_id=set_id, threshold=threshold, values=values)
