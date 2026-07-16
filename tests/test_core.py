"""Çekirdek testleri: GF(256) aritmetiği ve böl/birleştir round-trip.

Bağımlılıksız çalışır:  python3 -m tests.test_core   (proje kökünden)
"""

import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir import Share, split, combine, SSSError  # noqa: E402
from shamir import gf256  # noqa: E402

_passed = 0
_failed = 0


def check(condition: bool, message: str) -> None:
    global _passed, _failed
    if condition:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {message}")


def test_gf256_field_axioms() -> None:
    # 1 çarpımsal birim
    check(all(gf256.mul(1, a) == a for a in range(256)), "1 birim eleman")
    # 0 ile çarpım daima 0
    check(all(gf256.mul(0, a) == 0 for a in range(256)), "0 yutan eleman")
    # Toplama = XOR ve kendini götürür
    check(all(gf256.add(a, a) == 0 for a in range(256)), "a + a = 0")
    # Her sıfırdan farklı elemanın tersi vardır: a * inv(a) = 1
    check(all(gf256.mul(a, gf256.inverse(a)) == 1 for a in range(1, 256)),
          "çarpımsal ters")
    # Bölme, çarpmanın tersidir: (a*b)/b == a
    ok = True
    for a in range(256):
        for b in range(1, 256):
            if gf256.div(gf256.mul(a, b), b) != a:
                ok = False
                break
        if not ok:
            break
    check(ok, "(a*b)/b == a")
    # Dağılma: a*(b+c) == a*b + a*c (birkaç örnek)
    check(all(
        gf256.mul(a, gf256.add(b, c)) == gf256.add(gf256.mul(a, b), gf256.mul(a, c))
        for a, b, c in [(3, 7, 200), (255, 1, 128), (17, 17, 42)]
    ), "dağılma özelliği")


def test_roundtrip_all_k_subsets() -> None:
    secret = b"Gizli!"
    shares = split(secret, threshold=3, shares=5)
    check(len(shares) == 5, "5 pay üretildi")
    # 3'lü tüm alt kümeler aynı sırrı vermeli
    all_ok = True
    for combo in itertools.combinations(shares, 3):
        if combine(list(combo)) != secret:
            all_ok = False
            break
    check(all_ok, "herhangi 3 pay sırrı geri getirir")
    # 4 ve 5 pay da çalışmalı
    check(combine(shares[:4]) == secret, "4 pay ile round-trip")
    check(combine(shares) == secret, "5 pay ile round-trip")


def test_below_threshold_is_wrong() -> None:
    # k-1 pay ile birleştirme yanlış sonuç verir (bilgi vermez).
    secret = b"parola-1234"
    shares = split(secret, threshold=3, shares=5)
    wrong = combine(shares[:2])  # sadece 2 pay, k=3
    check(wrong != secret, "k-1 pay sırrı vermez")


def test_text_secret_roundtrip() -> None:
    # Türkçe karakterli metin sır — UTF-8 üzerinden.
    text = "Şifrem: gökçe-2024 🐢"
    shares = split(text.encode("utf-8"), threshold=2, shares=3)
    recovered = combine([shares[0], shares[2]]).decode("utf-8")
    check(recovered == text, "unicode metin round-trip")


def test_various_sizes() -> None:
    ok = True
    for k, n in [(2, 2), (2, 3), (3, 4), (5, 9), (10, 10)]:
        secret = os.urandom(37)
        shares = split(secret, threshold=k, shares=n)
        if combine(shares[:k]) != secret:
            ok = False
            break
    check(ok, "çeşitli (k,n) boyutları round-trip")


def test_validation_errors() -> None:
    def raises(fn) -> bool:
        try:
            fn()
            return False
        except SSSError:
            return True

    check(raises(lambda: split(b"x", 1, 3)), "k<2 reddedilir")
    check(raises(lambda: split(b"x", 4, 3)), "n<k reddedilir")
    check(raises(lambda: split(b"", 2, 3)), "boş sır reddedilir")
    check(raises(lambda: combine([Share(1, b"ab"), Share(2, b"abc")])),
          "farklı uzunluk reddedilir")
    check(raises(lambda: combine([Share(1, b"ab"), Share(1, b"cd")])),
          "tekrar eden x reddedilir")


def main() -> int:
    tests = [
        test_gf256_field_axioms,
        test_roundtrip_all_k_subsets,
        test_below_threshold_is_wrong,
        test_text_secret_roundtrip,
        test_various_sizes,
        test_validation_errors,
    ]
    for test in tests:
        print(f"- {test.__name__}")
        test()
    print(f"\n{_passed} kontrol geçti, {_failed} başarısız.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
