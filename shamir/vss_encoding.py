"""VSS payları ve taahhütleri için metin kodlaması (CRC sağlamalı).

Biçimler:
    Pay        :  VSS1-<setid>-<k>-<x>-<yhex>-<crc>
    Taahhütler :  VCOM1-<setid>-<k>-<C0hex.C1hex.….C(k-1)hex>-<crc>

  setid : aynı bölmenin payları ve taahhütleri aynı 4-haneli kimliği taşır.
  yhex  : pay değeri y (Z_q'da tam sayı), onaltılık.
  Cjhex : taahhüt C_j (mod p tam sayı), onaltılık; nokta ile ayrılır.
  crc   : önceki alanların CRC-16 sağlaması (zlib.crc32 & 0xFFFF ile uyumlu).
"""

from __future__ import annotations

import secrets
import zlib
from dataclasses import dataclass


class VSSEncodingError(Exception):
    """Bir VSS dizesi çözülemediğinde / sağlaması tutmadığında atılır."""


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
            "Tanınmayan pay biçimi. Beklenen: VSS1-<setid>-<k>-<x>-<yhex>-<crc>"
        )
    body = "-".join(parts[:5])
    try:
        if _crc(body) != int(parts[5], 16):
            raise VSSEncodingError("Sağlama toplamı tutmuyor — pay yanlış yazılmış olabilir.")
        set_id = int(parts[1], 16)
        threshold = int(parts[2])
        x = int(parts[3])
        y = int(parts[4], 16)
    except ValueError:
        raise VSSEncodingError("Pay alanları okunamadı.")
    if not (1 <= x <= 255):
        raise VSSEncodingError(f"Geçersiz pay numarası x={x}.")
    if threshold < 2:
        raise VSSEncodingError(f"Geçersiz eşik k={threshold}.")
    return ParsedVSSShare(set_id=set_id, threshold=threshold, x=x, y=y)


def encode_commitments(commitments: list[int], threshold: int, set_id: int) -> str:
    joined = ".".join(f"{c:x}" for c in commitments)
    body = f"VCOM1-{set_id:04x}-{threshold}-{joined}"
    return f"{body}-{_crc(body):04x}"


def decode_commitments(text: str) -> ParsedCommitments:
    parts = text.strip().split("-")
    if len(parts) != 5 or parts[0] != "VCOM1":
        raise VSSEncodingError(
            "Tanınmayan taahhüt biçimi. Beklenen: VCOM1-<setid>-<k>-<C0.C1…>-<crc>"
        )
    body = "-".join(parts[:4])
    try:
        if _crc(body) != int(parts[4], 16):
            raise VSSEncodingError("Taahhüt sağlaması tutmuyor — yanlış yazılmış olabilir.")
        set_id = int(parts[1], 16)
        threshold = int(parts[2])
        values = [int(h, 16) for h in parts[3].split(".") if h != ""]
    except ValueError:
        raise VSSEncodingError("Taahhüt alanları okunamadı.")
    if len(values) != threshold:
        raise VSSEncodingError(
            f"Taahhüt sayısı ({len(values)}) eşik değeriyle (k={threshold}) uyuşmuyor."
        )
    return ParsedCommitments(set_id=set_id, threshold=threshold, values=values)
