"""Shamir Secret Sharing — eğitim amaçlı, saf Python implementasyonu.

Bu paket sırrı (k, n) eşik şemasıyla paylaşır:
  - n adet pay üretilir,
  - herhangi k pay sırrı geri getirir,
  - k'den az pay sıfır bilgi verir.

Alt modüller:
  gf256 : GF(256) sonlu cisim aritmetiği (toplama = XOR, çarpma = tablo).
  core  : sırrı bayt bayt böl/birleştir (Lagrange interpolasyonu).
"""

from .core import Share, split, combine, SSSError

__all__ = ["Share", "split", "combine", "SSSError"]
