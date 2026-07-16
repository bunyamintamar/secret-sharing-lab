"""VSS pay/taahhüt kodlama testleri: round-trip, sağlama, biçim, uçtan uca.

Bağımsız çalışır:  python3 -m tests.test_vss_encoding   (proje kökünden)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir import vss  # noqa: E402
from shamir.vss_encoding import (  # noqa: E402
    decode_commitments,
    decode_share,
    encode_commitments,
    encode_share,
    new_set_id,
    VSSEncodingError,
)

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
    except VSSEncodingError:
        return True


def test_share_roundtrip() -> None:
    sid = 0xABCD
    line = encode_share(x=2, y=123456789, threshold=3, set_id=sid)
    p = decode_share(line)
    check(p.x == 2 and p.y == 123456789 and p.threshold == 3 and p.set_id == sid,
          "pay alanları round-trip")


def test_commitments_roundtrip() -> None:
    sid = 0x0042
    vals = [pow(4, 111, vss.P), pow(4, 222, vss.P), pow(4, 333, vss.P)]
    line = encode_commitments(vals, threshold=3, set_id=sid)
    p = decode_commitments(line)
    check(p.values == vals and p.threshold == 3 and p.set_id == sid,
          "taahhütler round-trip")


def test_checksum() -> None:
    line = encode_share(x=1, y=0xDEAD, threshold=2, set_id=0x1234)
    bad = line[:-2] + ("00" if line[-2:] != "00" else "11")
    check(raises(lambda: decode_share(bad)), "bozuk pay sağlaması yakalanır")


def test_bad_formats() -> None:
    check(raises(lambda: decode_share("merhaba")), "alakasız metin (pay)")
    check(raises(lambda: decode_commitments("VSS1-1-2-3-4-5")), "yanlış önek (taahhüt)")
    check(raises(lambda: decode_commitments("VCOM1-0042-3-a.b-0000")),
          "eksik taahhüt sayısı reddedilir")


def test_end_to_end_encode_verify() -> None:
    # split -> kodla -> çöz -> doğrula -> birleştir
    secret = "uçtan uca".encode("utf-8")
    shares, commits = vss.split(secret, threshold=3, shares=5)
    sid = new_set_id()
    enc_shares = [encode_share(s.x, s.y, 3, sid) for s in shares]
    enc_commits = encode_commitments(commits, 3, sid)

    dec_commits = decode_commitments(enc_commits).values
    # Kodlanmış paylar hâlâ doğrulanıyor mu?
    ds = [decode_share(e) for e in enc_shares]
    check(all(vss.verify_share(d.x, d.y, dec_commits) for d in ds),
          "kodlanıp çözülen paylar doğrulanır")
    # 1,3,5 ile birleştir
    from shamir.vss import VSSShare
    picked = [VSSShare(ds[i].x, ds[i].y) for i in (0, 2, 4)]
    check(vss.combine(picked) == secret, "kodlama üzerinden round-trip")


def main() -> int:
    tests = [
        test_share_roundtrip,
        test_commitments_roundtrip,
        test_checksum,
        test_bad_formats,
        test_end_to_end_encode_verify,
    ]
    for test in tests:
        print(f"- {test.__name__}")
        test()
    print(f"\n{_passed} kontrol geçti, {_failed} başarısız.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
