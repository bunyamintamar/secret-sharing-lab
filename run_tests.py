#!/usr/bin/env python3
"""Tüm test süitlerini tek komutla çalıştırır:  python3 run_tests.py"""

import sys

from tests import test_core, test_encoding, test_vss, test_vss_encoding


def main() -> int:
    failures = 0
    suites = [
        ("core", test_core),
        ("encoding", test_encoding),
        ("vss", test_vss),
        ("vss_encoding", test_vss_encoding),
    ]
    for name, module in suites:
        print(f"\n########## {name} ##########")
        failures += module.main()
    print("\n" + "=" * 30)
    print("TÜM TESTLER GEÇTİ ✔" if failures == 0 else f"{failures} SÜİT BAŞARISIZ ✖")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
