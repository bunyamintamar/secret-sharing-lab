"""Shamir Secret Sharing core: split and combine a secret byte by byte.

Idea (for a single byte):
  - Pick a secret polynomial of degree (k-1): f(x) = s + a1*x + ... + a(k-1)*x^(k-1)
    where s is the secret byte (constant term, i.e. f(0) = s) and the other
    coefficients are random.
  - Share i is the point f(i) (i = 1..n). Note: x=0 is never used, since f(0)
    is the secret itself.
  - Given any k shares (points) the polynomial is unique; Lagrange
    interpolation recovers f(0) = s.
  - With fewer than k points, f(0) is completely undetermined: every possible
    byte is equally likely.

For a multi-byte secret, each byte is shared with its own independent polynomial
at the same x points. Thus share i is a byte string the same length as the secret.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from . import gf256


class SSSError(Exception):
    """Common type for the known errors raised during secret sharing."""


@dataclass
class Share:
    """A single share: an x point and the y bytes at that point.

    x : share number in 1..255, unique (never 0).
    y : byte string the same length as the secret; y[j] = f_j(x), the polynomial
        of byte j.
    threshold : the scheme's threshold (k) this share belongs to. Informational;
                shown when combining, not mathematically required.
    """

    x: int
    y: bytes
    threshold: int | None = field(default=None)


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate the polynomial with coefficients `coeffs` at x in GF(256).

    coeffs[0] is the constant term (the secret byte), coeffs[i] the coefficient
    of x^i. Horner's method: fold from the highest degree down.
    """
    result = 0
    for coeff in reversed(coeffs):
        result = gf256.add(gf256.mul(result, x), coeff)
    return result


def split(secret: bytes, threshold: int, shares: int) -> list[Share]:
    """Split the secret into shares with a (threshold, shares) = (k, n) scheme.

    secret    : the secret to share (byte string).
    threshold : minimum number of shares needed to reconstruct (k).
    shares    : total number of shares to produce (n).

    Returns n Shares. Any k of them reconstruct the secret.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise SSSError("The secret must be a byte string (bytes).")
    if len(secret) == 0:
        raise SSSError("The secret cannot be empty.")
    if threshold < 2:
        raise SSSError("The threshold (k) must be at least 2.")
    if shares < threshold:
        raise SSSError(
            f"The number of shares (n={shares}) cannot be less than the threshold (k={threshold})."
        )
    if shares > 255:
        raise SSSError("The number of shares (n) can be at most 255 (x = 1..255).")

    secret = bytes(secret)
    # x points are 1..n. We accumulate the y bytes for each share.
    x_points = list(range(1, shares + 1))
    y_accum: list[bytearray] = [bytearray() for _ in x_points]

    # For each secret byte, build an independent polynomial and evaluate it at all x points.
    for secret_byte in secret:
        # coeffs[0] = secret byte; the remaining k-1 coefficients are cryptographically random.
        coeffs = [secret_byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for idx, x in enumerate(x_points):
            y_accum[idx].append(_eval_poly(coeffs, x))

    return [
        Share(x=x, y=bytes(y_accum[idx]), threshold=threshold)
        for idx, x in enumerate(x_points)
    ]


def _lagrange_interpolate_at_zero(points: list[tuple[int, int]]) -> int:
    """Return f(0) for the polynomial through the given (x, y) points.

    Lagrange interpolation specialized to x=0:
      f(0) = Σ_i  y_i * Π_{j≠i}  x_j / (x_j - x_i)
    All arithmetic in GF(256) (subtraction = XOR).
    """
    result = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1    # Π x_j
        denominator = 1  # Π (x_j - x_i)
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = gf256.mul(numerator, xj)
            denominator = gf256.mul(denominator, gf256.sub(xj, xi))
        term = gf256.mul(yi, gf256.div(numerator, denominator))
        result = gf256.add(result, term)
    return result


def combine(shares: list[Share]) -> bytes:
    """Combine shares and reconstruct the secret.

    At least k shares must be given. Extra shares are all used (if consistent,
    the result is unchanged). All shares must be the same length and the x values
    must be unique.
    """
    if len(shares) < 2:
        raise SSSError("At least 2 shares are needed to combine.")

    length = len(shares[0].y)
    if length == 0:
        raise SSSError("The shares are empty.")

    seen_x: set[int] = set()
    for share in shares:
        if share.x < 1 or share.x > 255:
            raise SSSError(f"Invalid share number x={share.x} (must be 1..255).")
        if share.x in seen_x:
            raise SSSError(f"The same share number (x={share.x}) was given twice.")
        seen_x.add(share.x)
        if len(share.y) != length:
            raise SSSError(
                "Shares have different lengths — probably shares from different "
                "secrets, or corrupted shares, were mixed."
            )

    secret = bytearray()
    for byte_index in range(length):
        points = [(share.x, share.y[byte_index]) for share in shares]
        secret.append(_lagrange_interpolate_at_zero(points))
    return bytes(secret)
