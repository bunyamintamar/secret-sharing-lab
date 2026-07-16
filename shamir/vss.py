"""Feldman Doğrulanabilir Sır Paylaşımı (VSS).

Klasik Shamir'de dağıtıcıya güvenmek zorundasın: sana bozuk bir pay verirse
bunu ancak birleştirme anında (çok geç) anlarsın. Feldman VSS bunu çözer:
dağıtıcı, polinomun katsayılarına dair açık **taahhütler** (commitments)
yayımlar. Herkes kendi payının bu taahhütlerle tutarlı olduğunu, sırrı hiç
öğrenmeden matematiksel olarak doğrular. Hileli bir dağıtıcı anında yakalanır.

Şema (büyük asal p, q=(p-1)/2 asal, g order-q üreteci):
  - Polinom f(x) = a0 + a1 x + ... + a(k-1) x^(k-1),  katsayılar Z_q'da, a0 = sır.
  - Pay i = f(i) mod q.
  - Taahhüt C_j = g^(a_j) mod p   (j = 0..k-1).  C_0 = g^sır.
  - Doğrulama (pay i, s_i):   g^(s_i)  ==  Π_j  C_j^(i^j)   (mod p).
      Çünkü g^f(i) = g^(Σ a_j i^j) = Π (g^a_j)^(i^j) = Π C_j^(i^j).
  - Birleştirme: Lagrange interpolasyonu ile f(0) = sır (Z_q üzerinde).

Not: Bu, GF(256) tabanlı temel SSS'ten ayrı bir şemadır — VSS büyük asal
cisimde (Z_q) çalışır, çünkü taahhütler ayrık logaritmanın zor olduğu bir
grupta yaşar. Parametreler RFC 3526 2048-bit MODP grubudur (doğrulanmış
güvenli asal). Eğitim amaçlıdır.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .core import SSSError

# ── Grup parametreleri: RFC 3526 2048-bit MODP (güvenli asal, doğrulanmış) ────
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)          # 2048-bit güvenli asal
Q = (P - 1) // 2             # asal — polinom cisminin ve alt grubun mertebesi
G = 4                        # order-Q alt grubunun üreteci (2^2, daima QR)

# Sır, Z_q içinde tek bir tam sayı olarak kodlanır. Marker baytı (0x01) baştaki
# sıfır baytlarını korur. En fazla bu kadar bayt kodlanabilir (m < Q şartı):
MAX_SECRET_BYTES = (Q.bit_length() - 1) // 8 - 1   # 2048-bit için ~254 bayt


class VSSError(SSSError):
    """VSS'e özgü hatalar (temel SSSError'dan türer)."""


@dataclass
class VSSShare:
    """VSS payı: bir x noktası ve o noktadaki y = f(x) mod q değeri."""

    x: int
    y: int
    threshold: int | None = None


def _encode_secret(secret: bytes) -> int:
    if len(secret) == 0:
        raise VSSError("Sır boş olamaz.")
    if len(secret) > MAX_SECRET_BYTES:
        raise VSSError(
            f"Sır çok uzun: {len(secret)} bayt. VSS için en fazla "
            f"{MAX_SECRET_BYTES} bayt (2048-bit grup sınırı)."
        )
    m = int.from_bytes(b"\x01" + secret, "big")
    if m >= Q:
        raise VSSError("Sır grup mertebesine sığmıyor (çok uzun).")
    return m


def _decode_secret(m: int) -> bytes:
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    if not raw or raw[0] != 0x01:
        raise VSSError("Geri getirilen değer geçersiz (paylar hatalı/eksik olabilir).")
    return raw[1:]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """f(x) mod q — Horner yöntemi."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % Q
    return result


def split(secret: bytes, threshold: int, shares: int) -> tuple[list[VSSShare], list[int]]:
    """Sırrı (threshold, shares) = (k, n) ile böler.

    Dönüş: (paylar, taahhütler). Taahhütler herkese açık yayımlanır; herkes
    kendi payını verify_share ile doğrular.
    """
    if threshold < 2:
        raise VSSError("Eşik değeri (k) en az 2 olmalıdır.")
    if shares < threshold:
        raise VSSError(f"Pay sayısı (n={shares}) eşikten (k={threshold}) küçük olamaz.")
    if shares > 255:
        raise VSSError("Pay sayısı (n) en fazla 255 olabilir.")

    secret_int = _encode_secret(bytes(secret))
    # coeffs[0] = sır; kalan k-1 katsayı Z_q'da kriptografik rastgele.
    coeffs = [secret_int] + [secrets.randbelow(Q) for _ in range(threshold - 1)]

    out = [
        VSSShare(x=i, y=_eval_poly(coeffs, i), threshold=threshold)
        for i in range(1, shares + 1)
    ]
    commitments = [pow(G, a, P) for a in coeffs]   # C_j = g^(a_j) mod p
    return out, commitments


def verify_share(x: int, y: int, commitments: list[int]) -> bool:
    """Pay (x, y) verilen taahhütlerle tutarlı mı? Sır öğrenilmeden kontrol edilir.

    g^y  ==  Π_j  C_j^(x^j)   (mod p)  ise pay geçerlidir.
    """
    if not commitments:
        raise VSSError("Taahhüt listesi boş.")
    lhs = pow(G, y % Q, P)
    rhs = 1
    for j, c in enumerate(commitments):
        rhs = (rhs * pow(c, pow(x, j, Q), P)) % P
    return lhs == rhs


def _lagrange_at_zero(points: list[tuple[int, int]]) -> int:
    """(x, y) noktalarından f(0)'ı Z_q üzerinde hesaplar."""
    result = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        lam = (num * pow(den, -1, Q)) % Q
        result = (result + yi * lam) % Q
    return result


def combine(shares: list[VSSShare]) -> bytes:
    """Payları birleştirip sırrı geri getirir (en az k pay)."""
    if len(shares) < 2:
        raise VSSError("Birleştirme için en az 2 pay gerekir.")
    seen: set[int] = set()
    for s in shares:
        if not (1 <= s.x <= 255):
            raise VSSError(f"Geçersiz pay numarası x={s.x}.")
        if s.x in seen:
            raise VSSError(f"Aynı pay numarası (x={s.x}) iki kez verildi.")
        seen.add(s.x)
    secret_int = _lagrange_at_zero([(s.x, s.y) for s in shares])
    return _decode_secret(secret_int)
