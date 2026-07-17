"""Shamir Secret Sharing — educational, pure-Python implementation.

This package splits a secret with a (k, n) threshold scheme:
  - n shares are produced,
  - any k shares reconstruct the secret,
  - fewer than k shares reveal zero information.

Submodules:
  gf256 : GF(256) finite-field arithmetic (addition = XOR, multiplication = table).
  core  : split/combine a secret byte by byte (Lagrange interpolation).
"""

from .core import Share, split, combine, SSSError

__all__ = ["Share", "split", "combine", "SSSError"]
