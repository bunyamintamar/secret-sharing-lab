"""Shamir Secret Sharing çekirdeği: sırrı bayt bayt böl ve birleştir.

Fikir (tek bir bayt için):
  - Derecesi (k-1) olan gizli bir polinom seç: f(x) = s + a1*x + ... + a(k-1)*x^(k-1)
    Burada s gizli bayt (sabit terim, yani f(0) = s), diğer katsayılar rastgele.
  - Pay i = f(i) noktasıdır (i = 1..n). Not: x=0 kullanılmaz, çünkü f(0) sırdır.
  - Herhangi k pay (nokta) elde varsa polinom benzersizdir; Lagrange
    interpolasyonu ile f(0) = s geri hesaplanır.
  - k'den az nokta ile f(0) tamamen belirsizdir: her olası bayt eşit olasıdır.

Bir sır çok baytlıysa her bayt bağımsız bir polinomla, aynı x noktalarında
paylaşılır. Böylece pay i, sırla aynı uzunlukta bir bayt dizisidir.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import gf256


class SSSError(Exception):
    """Sır paylaşımı sırasında oluşan bilinen hataların ortak türü."""


@dataclass
class Share:
    """Tek bir pay: bir x noktası ve o noktadaki y baytları.

    x : 1..255 aralığında benzersiz pay numarası (asla 0 olamaz).
    y : sırla aynı uzunlukta bayt dizisi; y[j] = f_j(x), j'inci baytın polinomu.
    threshold : bu payın ait olduğu şemanın eşik değeri (k). Bilgi amaçlı;
                birleştirmede gösterilir, matematiksel olarak zorunlu değildir.
    """

    x: int
    y: bytes
    threshold: int | None = field(default=None)


def _eval_poly(coeffs: list[int], x: int) -> int:
    """coeffs katsayılı polinomu GF(256) içinde x noktasında değerlendirir.

    coeffs[0] sabit terim (sır baytı), coeffs[i] ise x^i'nin katsayısıdır.
    Horner yöntemi: en yüksek dereceden başlayıp geriye doğru katlarız.
    """
    result = 0
    for coeff in reversed(coeffs):
        result = gf256.add(gf256.mul(result, x), coeff)
    return result


def split(secret: bytes, threshold: int, shares: int) -> list[Share]:
    """Sırrı (threshold, shares) = (k, n) eşik şemasıyla paylara böler.

    secret    : paylaşılacak sır (bayt dizisi).
    threshold : sırrı geri getirmek için gereken minimum pay sayısı (k).
    shares    : üretilecek toplam pay sayısı (n).

    Dönüş: n adet Share. Herhangi k tanesi sırrı geri getirir.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise SSSError("Sır bayt dizisi (bytes) olmalıdır.")
    if len(secret) == 0:
        raise SSSError("Sır boş olamaz.")
    if threshold < 2:
        raise SSSError("Eşik değeri (k) en az 2 olmalıdır.")
    if shares < threshold:
        raise SSSError(
            f"Pay sayısı (n={shares}) eşik değerinden (k={threshold}) küçük olamaz."
        )
    if shares > 255:
        raise SSSError("Pay sayısı (n) en fazla 255 olabilir (x = 1..255).")

    secret = bytes(secret)
    # x noktaları 1..n. Her pay için y baytlarını biriktireceğiz.
    x_points = list(range(1, shares + 1))
    y_accum: list[bytearray] = [bytearray() for _ in x_points]

    # Her sır baytı için bağımsız bir polinom kur ve tüm x noktalarında değerlendir.
    for secret_byte in secret:
        # coeffs[0] = sır baytı; kalan k-1 katsayı kriptografik rastgele.
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for idx, x in enumerate(x_points):
            y_accum[idx].append(_eval_poly(coeffs, x))

    return [
        Share(x=x, y=bytes(y_accum[idx]), threshold=threshold)
        for idx, x in enumerate(x_points)
    ]


def _lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """Verilen (x, y) noktalarından geçen polinomun f(0) değerini döndürür.

    Lagrange interpolasyonu, x=0 noktasına özelleştirilmiş biçimde:
      f(0) = Σ_i  y_i * Π_{j≠i}  x_j / (x_j - x_i)
    Tüm aritmetik GF(256) içinde (çıkarma = XOR).
    """
    result = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1    # Π x_j
        denominator = 1  # Π (x_j - x_i)
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = gf256.mul(numerator, xj)
            denominator = gf256.mul(denominator, gf256.sub(xj, xi))
        term = gf256.mul(yi, gf256.div(numerator, denominator))
        result = gf256.add(result, term)
    return result


def combine(shares: list[Share]) -> bytes:
    """Payları birleştirip sırrı geri hesaplar.

    En az k pay verilmelidir. Fazla pay verilirse hepsi kullanılır (tutarlıysa
    sonuç değişmez). Payların hepsi aynı uzunlukta olmalı ve x'ler benzersiz olmalı.
    """
    if len(shares) < 2:
        raise SSSError("Birleştirme için en az 2 pay gerekir.")

    length = len(shares[0].y)
    if length == 0:
        raise SSSError("Paylar boş.")

    seen_x: set[int] = set()
    for share in shares:
        if share.x < 1 or share.x > 255:
            raise SSSError(f"Geçersiz pay numarası x={share.x} (1..255 olmalı).")
        if share.x in seen_x:
            raise SSSError(f"Aynı pay numarası (x={share.x}) iki kez verildi.")
        seen_x.add(share.x)
        if len(share.y) != length:
            raise SSSError(
                "Paylar farklı uzunlukta — muhtemelen farklı sırlara ait "
                "veya bozuk paylar karıştırılmış."
            )

    secret = bytearray()
    for byte_index in range(length):
        points = [(share.x, share.y[byte_index]) for share in shares]
        secret.append(_lagrange_interpolate_at_zero(points))
    return bytes(secret)
