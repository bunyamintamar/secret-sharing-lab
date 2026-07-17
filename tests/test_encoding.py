"""Share encoding/decoding tests: round-trip, checksum, format errors.

Runs standalone:  python3 -m tests.test_encoding   (from the project root)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir.encoding import (  # noqa: E402
    decode_share,
    encode_share,
    new_set_id,
    EncodingError,
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
    except EncodingError:
        return True


def test_roundtrip() -> None:
    set_id = 0xA3F1
    y = bytes([0x9E, 0x02, 0xB7, 0x55])
    line = encode_share(x=2, y=y, threshold=3, set_id=set_id)
    parsed = decode_share(line)
    check(parsed.x == 2, "x round-trip")
    check(parsed.y == y, "y round-trip")
    check(parsed.threshold == 3, "k round-trip")
    check(parsed.set_id == set_id, "set_id round-trip")


def test_format_shape() -> None:
    line = encode_share(x=1, y=b"\x01\x02", threshold=2, set_id=0x000F)
    parts = line.split("-")
    check(len(parts) == 6, "6-field format")
    check(parts[0] == "SSS1", "version tag")
    check(parts[1] == "000f", "set_id is zero-padded to 4 hex digits")


def test_checksum_catches_typo() -> None:
    line = encode_share(x=5, y=b"\xde\xad\xbe\xef", threshold=3, set_id=0x1234)
    # corrupt a single digit in the data part
    idx = line.index("deadbeef")
    corrupted = line[:idx] + "de00beef" + line[idx + 8:]
    check(raises(lambda: decode_share(corrupted)), "corrupted data is caught by the checksum")


def test_whitespace_tolerant() -> None:
    line = encode_share(x=1, y=b"\xaa\xbb", threshold=2, set_id=0x00AB)
    parsed = decode_share(f"   {line}\n")
    check(parsed.x == 1, "leading/trailing whitespace is trimmed")


def test_bad_formats() -> None:
    check(raises(lambda: decode_share("hello")), "unrelated text is rejected")
    check(raises(lambda: decode_share("SSS1-0001-2-1")), "missing fields are rejected")
    check(raises(lambda: decode_share("XXXX-0001-2-1-aabb-0000")), "wrong prefix is rejected")
    # x=0 is invalid
    body = "SSS1-0001-2-0-aabb"
    import zlib
    crc = zlib.crc32(body.encode()) & 0xFFFF
    check(raises(lambda: decode_share(f"{body}-{crc:04x}")), "x=0 is rejected")


def test_set_id_range() -> None:
    ids = [new_set_id() for _ in range(200)]
    check(all(0 <= i <= 0xFFFF for i in ids), "set_id is in the 16-bit range")


def main() -> int:
    tests = [
        test_roundtrip,
        test_format_shape,
        test_checksum_catches_typo,
        test_whitespace_tolerant,
        test_bad_formats,
        test_set_id_range,
    ]
    for test in tests:
        print(f"- {test.__name__}")
        test()
    print(f"\n{_passed} checks passed, {_failed} failed.")
    return 1 if _failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
