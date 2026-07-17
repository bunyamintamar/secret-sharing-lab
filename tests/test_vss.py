"""Feldman VSS tests: round-trip, verification, and cheating detection.

Runs standalone:  python3 -m tests.test_vss   (from the project root)
"""

import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir import vss  # noqa: E402
from shamir.vss import VSSShare, VSSError  # noqa: E402

_passed = 0
_failed = 0


def check(condition: bool, message: str) -> None:
    global _passed, _failed
    if condition:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL: {message}")


def raises(fn) -> bool:
    try:
        fn()
        return False
    except VSSError:
        return True


def test_group_params() -> None:
    # Safe-prime and generator sanity checks (is the code using the right parameters?)
    check(vss.P.bit_length() == 2048, "P is 2048-bit")
    check(pow(vss.G, vss.Q, vss.P) == 1, "g is an order-q generator (g^q=1)")
    check((2 * vss.Q + 1) == vss.P, "P = 2q+1 (safe-prime structure)")


def test_roundtrip_all_k_subsets() -> None:
    secret = b"VSS secret!"
    shares, commits = vss.split(secret, threshold=3, shares=5)
    check(len(shares) == 5 and len(commits) == 3, "5 shares + 3 commitments")
    ok = all(vss.combine(list(c)) == secret for c in itertools.combinations(shares, 3))
    check(ok, "any 3 shares reconstruct the secret")
    check(vss.combine(shares) == secret, "round-trip with 5 shares")


def test_honest_shares_verify() -> None:
    shares, commits = vss.split(b"verification", threshold=3, shares=6)
    ok = all(vss.verify_share(s.x, s.y, commits) for s in shares)
    check(ok, "all honest shares verify")


def test_tampered_share_fails_verify() -> None:
    shares, commits = vss.split(b"tamper", threshold=3, shares=5)
    bad = shares[1]
    check(not vss.verify_share(bad.x, bad.y + 1, commits),
          "a tampered share (y+1) fails verification")
    check(not vss.verify_share(bad.x, (bad.y * 2 + 7) % vss.Q, commits),
          "a randomly corrupted share is rejected")


def test_cheating_dealer_caught_then_recover() -> None:
    # The dealer tampers with one share; verification catches it, and we recover from the good ones.
    secret = b"password-2024"
    shares, commits = vss.split(secret, threshold=3, shares=5)
    # corrupt share number 3 (dealer cheating)
    shares[2] = VSSShare(x=shares[2].x, y=(shares[2].y + 12345) % vss.Q,
                         threshold=3)
    good = [s for s in shares if vss.verify_share(s.x, s.y, commits)]
    bad = [s for s in shares if not vss.verify_share(s.x, s.y, commits)]
    check(len(bad) == 1 and bad[0].x == 3, "the cheating share (x=3) was detected")
    check(len(good) >= 3, "at least 3 good shares remain")
    check(vss.combine(good[:3]) == secret, "the secret was recovered from good shares")


def test_below_threshold_wrong() -> None:
    secret = b"below-threshold"
    shares, _ = vss.split(secret, threshold=3, shares=5)
    # combining with 2 shares gives a wrong (or invalid) result, not the real secret.
    try:
        result = vss.combine(shares[:2])
        check(result != secret, "k-1 shares do not give the real secret")
    except VSSError:
        check(True, "k-1 shares -> invalid result -> error")


def test_text_secret_roundtrip() -> None:
    text = "VSS password: café-42 🛡️"
    shares, _ = vss.split(text.encode("utf-8"), threshold=2, shares=3)
    check(vss.combine([shares[0], shares[2]]).decode("utf-8") == text,
          "unicode+emoji round-trip")


def test_validation() -> None:
    check(raises(lambda: vss.split(b"x", 1, 3)), "k<2 is rejected")
    check(raises(lambda: vss.split(b"x", 4, 3)), "n<k is rejected")
    check(raises(lambda: vss.split(b"", 2, 3)), "empty secret is rejected")
    check(raises(lambda: vss.split(b"A" * (vss.MAX_SECRET_BYTES + 1), 2, 3)),
          "too-long secret is rejected")
    check(raises(lambda: vss.combine([VSSShare(1, 5), VSSShare(1, 9)])),
          "repeated x is rejected")


def main() -> int:
    tests = [
        test_group_params,
        test_roundtrip_all_k_subsets,
        test_honest_shares_verify,
        test_tampered_share_fails_verify,
        test_cheating_dealer_caught_then_recover,
        test_below_threshold_wrong,
        test_text_secret_roundtrip,
        test_validation,
    ]
    for test in tests:
        print(f"- {test.__name__}")
        test()
    print(f"\n{_passed} checks passed, {_failed} failed.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
