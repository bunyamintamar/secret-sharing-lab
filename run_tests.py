#!/usr/bin/env python3
"""Tüm test süitlerini tek komutla çalıştırır:  python3 run_tests.py"""

import sys

from tests import test_core, test_encoding, test_web


def main() -> int:
    failures = 0
    for name, module in [("core", test_core), ("encoding", test_encoding), ("web", test_web)]:
        print(f"\n########## {name} ##########")
        failures += module.main()
    print("\n" + "=" * 30)
    print("TÜM TESTLER GEÇTİ ✔" if failures == 0 else f"{failures} SÜİT BAŞARISIZ ✖")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
