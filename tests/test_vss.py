"""Feldman VSS testleri: round-trip, doğrulama ve hile yakalama.

Bağımsız çalışır:  python3 -m tests.test_vss   (proje kökünden)
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
    # Güvenli asal ve üreteç sağlaması (kod, doğru parametrelerle mi çalışıyor?)
    check(vss.P.bit_length() == 2048, "P 2048-bit")
    check(pow(vss.G, vss.Q, vss.P) == 1, "g order-q üreteç (g^q=1)")
    check((2 * vss.Q + 1) == vss.P, "P = 2q+1 (güvenli asal yapısı)")


def test_roundtrip_all_k_subsets() -> None:
    secret = b"Gizli VSS!"
    shares, commits = vss.split(secret, threshold=3, shares=5)
    check(len(shares) == 5 and len(commits) == 3, "5 pay + 3 taahhüt")
    ok = all(vss.combine(list(c)) == secret for c in itertools.combinations(shares, 3))
    check(ok, "herhangi 3 pay sırrı geri getirir")
    check(vss.combine(shares) == secret, "5 pay ile round-trip")


def test_honest_shares_verify() -> None:
    shares, commits = vss.split(b"dogrulama", threshold=3, shares=6)
    ok = all(vss.verify_share(s.x, s.y, commits) for s in shares)
    check(ok, "dürüst payların hepsi doğrulanır")


def test_tampered_share_fails_verify() -> None:
    shares, commits = vss.split(b"kurcala", threshold=3, shares=5)
    bad = shares[1]
    check(not vss.verify_share(bad.x, bad.y + 1, commits),
          "kurcalanmış pay (y+1) doğrulamadan geçemez")
    check(not vss.verify_share(bad.x, (bad.y * 2 + 7) % vss.Q, commits),
          "rastgele bozulmuş pay reddedilir")


def test_cheating_dealer_caught_then_recover() -> None:
    # Dağıtıcı bir paya hile karıştırıyor; doğrulama yakalıyor, iyi paylarla kurtarıyoruz.
    secret = b"parola-2024"
    shares, commits = vss.split(secret, threshold=3, shares=5)
    # 3 numaralı payı boz (dağıtıcı hilesi)
    shares[2] = VSSShare(x=shares[2].x, y=(shares[2].y + 12345) % vss.Q,
                         threshold=3)
    good = [s for s in shares if vss.verify_share(s.x, s.y, commits)]
    bad = [s for s in shares if not vss.verify_share(s.x, s.y, commits)]
    check(len(bad) == 1 and bad[0].x == 3, "hileli pay (x=3) tespit edildi")
    check(len(good) >= 3, "en az 3 sağlam pay kaldı")
    check(vss.combine(good[:3]) == secret, "sağlam paylarla sır kurtarıldı")


def test_below_threshold_wrong() -> None:
    secret = b"esik-alti"
    shares, _ = vss.split(secret, threshold=3, shares=5)
    # 2 pay ile birleştirme yanlış (ya da geçersiz) sonuç verir, doğru sırrı vermez.
    try:
        result = vss.combine(shares[:2])
        check(result != secret, "k-1 pay doğru sırrı vermez")
    except VSSError:
        check(True, "k-1 pay geçersiz sonuç -> hata")


def test_text_secret_roundtrip() -> None:
    text = "VSS şifre: gökçe-42 🛡️"
    shares, _ = vss.split(text.encode("utf-8"), threshold=2, shares=3)
    check(vss.combine([shares[0], shares[2]]).decode("utf-8") == text,
          "unicode+emoji round-trip")


def test_validation() -> None:
    check(raises(lambda: vss.split(b"x", 1, 3)), "k<2 reddedilir")
    check(raises(lambda: vss.split(b"x", 4, 3)), "n<k reddedilir")
    check(raises(lambda: vss.split(b"", 2, 3)), "boş sır reddedilir")
    check(raises(lambda: vss.split(b"A" * (vss.MAX_SECRET_BYTES + 1), 2, 3)),
          "çok uzun sır reddedilir")
    check(raises(lambda: vss.combine([VSSShare(1, 5), VSSShare(1, 9)])),
          "tekrar eden x reddedilir")


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
    print(f"\n{_passed} kontrol geçti, {_failed} başarısız.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
