#!/usr/bin/env python3
"""Run every test suite with one command:  python3 run_tests.py"""

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
    print("ALL TESTS PASSED ✔" if failures == 0 else f"{failures} SUITE(S) FAILED ✖")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
