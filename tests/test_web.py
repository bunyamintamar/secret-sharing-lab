"""Web API iş mantığı testleri (_do_split / _do_combine).

Sunucu başlatmadan, doğrudan işleyicileri çağırır.
Bağımsız çalışır:  python3 -m tests.test_web   (proje kökünden)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir import SSSError  # noqa: E402
from web.server import _do_split, _do_combine  # noqa: E402

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
    except SSSError:
        return True


def test_split_combine_roundtrip() -> None:
    secret = "Şifre: 42-🔐"
    out = _do_split({"secret": secret, "n": 5, "k": 3})
    check(len(out["shares"]) == 5, "5 pay üretildi")
    check(out["k"] == 3 and out["n"] == 5, "n/k geri döndü")
    # Pay 1, 3, 5 ile birleştir
    picked = [out["shares"][0], out["shares"][2], out["shares"][4]]
    res = _do_combine({"shares": picked})
    check(res["is_text"] is True, "metin olarak çözüldü")
    check(res["secret"] == secret, "sır round-trip (unicode+emoji)")


def test_below_threshold() -> None:
    out = _do_split({"secret": "gizli", "n": 5, "k": 3})
    check(raises(lambda: _do_combine({"shares": out["shares"][:2]})),
          "eşik altı reddedilir")


def test_split_validation() -> None:
    check(raises(lambda: _do_split({"secret": "", "n": 3, "k": 2})), "boş sır")
    check(raises(lambda: _do_split({"secret": "x", "n": 2, "k": 5})), "k>n")
    check(raises(lambda: _do_split({"secret": "x", "n": "abc", "k": 2})), "n sayı değil")


def test_combine_bad_share() -> None:
    check(raises(lambda: _do_combine({"shares": ["merhaba", "dünya"]})),
          "bozuk paylar reddedilir")
    check(raises(lambda: _do_combine({"shares": []})), "boş liste reddedilir")


def test_combine_mixed_sets_warns() -> None:
    a = _do_split({"secret": "aaa", "n": 3, "k": 2})["shares"]
    b = _do_split({"secret": "bbb", "n": 3, "k": 2})["shares"]
    res = _do_combine({"shares": [a[0], b[1]]})
    check(len(res["warnings"]) >= 1, "farklı set kimlikleri uyarı üretir")


def main() -> int:
    tests = [
        test_split_combine_roundtrip,
        test_below_threshold,
        test_split_validation,
        test_combine_bad_share,
        test_combine_mixed_sets_warns,
    ]
    for test in tests:
        print(f"- {test.__name__}")
        test()
    print(f"\n{_passed} kontrol geçti, {_failed} başarısız.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
