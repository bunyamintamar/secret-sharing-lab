"""Payları güvenli, okunabilir metin dizelerine kodlar / çözer.

Her pay tek satırlık bir dizeye dönüşür. Diyagramlarda uyardığımız gibi payın
yanında metadata taşınmazsa yıllar sonra kimse birleştiremez — bu yüzden şema,
eşik (k) ve bir "set kimliği" payın içine gömülür, sonuna da bir sağlama toplamı
eklenir (yazım hatalarını yakalamak için).

Biçim:
    SSS1-<setid>-<k>-<x>-<hexY>-<crc>
      SSS1   : sürüm etiketi
      setid  : 4 haneli onaltılık; aynı bölmeden çıkan tüm paylarda aynıdır
               (farklı sırların payları yanlışlıkla karışırsa fark edilir)
      k      : eşik değeri (birleştirme için gereken pay sayısı)
      x      : pay numarası (1..255)
      hexY   : payın bayt verisi (onaltılık)
      crc    : önceki alanların CRC-16 sağlaması (4 haneli onaltılık)

Örnek:  SSS1-a3f1-3-2-9e02b755-1a2b
"""

from __future__ import annotations

import secrets
import zlib
from dataclasses import dataclass

_PREFIX = "SSS1"


class EncodingError(Exception):
    """Bir pay dizesi çözülemediğinde / sağlaması tutmadığında atılır."""


@dataclass
class ParsedShare:
    """Çözülmüş bir pay dizesinin alanları."""

    set_id: int
    threshold: int
    x: int
    y: bytes


def new_set_id() -> int:
    """Bir bölme işlemi için rastgele 16-bit set kimliği üretir."""
    return secrets.randbits(16)


def _crc(body: str) -> int:
    return zlib.crc32(body.encode("ascii")) & 0xFFFF


def encode_share(x: int, y: bytes, threshold: int, set_id: int) -> str:
    """Bir payı tek satırlık dizeye kodlar."""
    body = f"{_PREFIX}-{set_id:04x}-{threshold}-{x}-{y.hex()}"
    return f"{body}-{_crc(body):04x}"


def decode_share(text: str) -> ParsedShare:
    """Bir pay dizesini çözer; biçim veya sağlama hatalıysa EncodingError atar."""
    cleaned = text.strip()
    parts = cleaned.split("-")
    if len(parts) != 6 or parts[0] != _PREFIX:
        raise EncodingError(
            "Tanınmayan pay biçimi. Beklenen: "
            "SSS1-<setid>-<k>-<x>-<hex>-<crc>"
        )

    prefix, setid_hex, k_str, x_str, y_hex, crc_hex = parts

    body = "-".join(parts[:5])
    try:
        expected_crc = int(crc_hex, 16)
    except ValueError:
        raise EncodingError("Sağlama alanı (crc) onaltılık değil.")
    if _crc(body) != expected_crc:
        raise EncodingError(
            "Sağlama toplamı tutmuyor — pay büyük olasılıkla yanlış yazılmış."
        )

    try:
        set_id = int(setid_hex, 16)
        threshold = int(k_str)
        x = int(x_str)
        y = bytes.fromhex(y_hex)
    except ValueError:
        raise EncodingError("Pay alanları okunamadı (sayı/onaltılık hatası).")

    if not (1 <= x <= 255):
        raise EncodingError(f"Geçersiz pay numarası x={x} (1..255 olmalı).")
    if threshold < 2:
        raise EncodingError(f"Geçersiz eşik değeri k={threshold} (en az 2).")
    if len(y) == 0:
        raise EncodingError("Payın veri kısmı boş.")

    return ParsedShare(set_id=set_id, threshold=threshold, x=x, y=y)
