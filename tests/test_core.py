"""Core tests: GF(256) arithmetic and split/combine round-trip.

Runs with no dependencies:  python3 -m tests.test_core   (from the project root)
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
    # 1 is the multiplicative identity
    check(all(gf256.mul(1, a) == a for a in range(256)), "1 is the identity element")
    # multiplying by 0 is always 0
    check(all(gf256.mul(0, a) == 0 for a in range(256)), "0 is the absorbing element")
    # addition = XOR and is self-canceling
    check(all(gf256.add(a, a) == 0 for a in range(256)), "a + a = 0")
    # every nonzero element has an inverse: a * inv(a) = 1
    check(all(gf256.mul(a, gf256.inverse(a)) == 1 for a in range(1, 256)),
          "multiplicative inverse")
    # division is the inverse of multiplication: (a*b)/b == a
    ok = True
    for a in range(256):
        for b in range(1, 256):
            if gf256.div(gf256.mul(a, b), b) != a:
                ok = False
                break
        if not ok:
            break
    check(ok, "(a*b)/b == a")
    # distributivity: a*(b+c) == a*b + a*c (a few examples)
    check(all(
        gf256.mul(a, gf256.add(b, c)) == gf256.add(gf256.mul(a, b), gf256.mul(a, c))
        for a, b, c in [(3, 7, 200), (255, 1, 128), (17, 17, 42)]
    ), "distributive property")


def test_roundtrip_all_k_subsets() -> None:
    secret = b"Secret!"
    shares = split(secret, threshold=3, shares=5)
    check(len(shares) == 5, "5 shares generated")
    # every 3-subset must give the same secret
    all_ok = True
    for combo in itertools.combinations(shares, 3):
        if combine(list(combo)) != secret:
            all_ok = False
            break
    check(all_ok, "any 3 shares reconstruct the secret")
    # 4 and 5 shares must also work
    check(combine(shares[:4]) == secret, "round-trip with 4 shares")
    check(combine(shares) == secret, "round-trip with 5 shares")


def test_below_threshold_is_wrong() -> None:
    # combining with k-1 shares gives a wrong result (reveals nothing).
    secret = b"password-1234"
    shares = split(secret, threshold=3, shares=5)
    wrong = combine(shares[:2])  # only 2 shares, k=3
    check(wrong != secret, "k-1 shares do not reveal the secret")


def test_text_secret_roundtrip() -> None:
    # Text secret with non-ASCII characters — via UTF-8.
    text = "My password: café-2024 🐢"
    shares = split(text.encode("utf-8"), threshold=2, shares=3)
    recovered = combine([shares[0], shares[2]]).decode("utf-8")
    check(recovered == text, "unicode text round-trip")


def test_various_sizes() -> None:
    ok = True
    for k, n in [(2, 2), (2, 3), (3, 4), (5, 9), (10, 10)]:
        secret = os.urandom(37)
        shares = split(secret, threshold=k, shares=n)
        if combine(shares[:k]) != secret:
            ok = False
            break
    check(ok, "round-trip across various (k,n) sizes")


def test_validation_errors() -> None:
    def raises(fn) -> bool:
        try:
            fn()
            return False
        except SSSError:
            return True

    check(raises(lambda: split(b"x", 1, 3)), "k<2 is rejected")
    check(raises(lambda: split(b"x", 4, 3)), "n<k is rejected")
    check(raises(lambda: split(b"", 2, 3)), "empty secret is rejected")
    check(raises(lambda: combine([Share(1, b"ab"), Share(2, b"abc")])),
          "different lengths are rejected")
    check(raises(lambda: combine([Share(1, b"ab"), Share(1, b"cd")])),
          "repeated x is rejected")


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
    print(f"\n{_passed} checks passed, {_failed} failed.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
