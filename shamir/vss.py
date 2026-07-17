"""Feldman Verifiable Secret Sharing (VSS).

With classic Shamir you have to trust the dealer: if they hand you a bad share,
you only find out when combining (too late). Feldman VSS fixes this: the dealer
publishes public **commitments** to the polynomial's coefficients. Everyone can
verify their own share is consistent with those commitments without learning the
secret. A cheating dealer is caught immediately.

Scheme (large prime p, q=(p-1)/2 prime, g a generator of the order-q subgroup):
  - Polynomial f(x) = a0 + a1 x + ... + a(k-1) x^(k-1),  coefficients in Z_q, a0 = secret.
  - Share i = f(i) mod q.
  - Commitment C_j = g^(a_j) mod p   (j = 0..k-1).  C_0 = g^secret.
  - Verification (share i, s_i):   g^(s_i)  ==  Π_j  C_j^(i^j)   (mod p).
      Because g^f(i) = g^(Σ a_j i^j) = Π (g^a_j)^(i^j) = Π C_j^(i^j).
  - Combine: Lagrange interpolation to get f(0) = secret (over Z_q).

Note: this is a separate scheme from the basic GF(256) SSS — VSS works in a large
prime field (Z_q) because the commitments live in a group where the discrete
logarithm is hard. The parameters are the RFC 3526 2048-bit MODP group (a
verified safe prime). For educational use.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .core import SSSError

# ── Group parameters: RFC 3526 2048-bit MODP (safe prime, verified) ──────────
_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
P = int(_P_HEX, 16)          # 2048-bit safe prime
Q = (P - 1) // 2             # prime — order of the polynomial field and subgroup
G = 4                        # generator of the order-Q subgroup (2^2, always a QR)

# The secret is encoded as a single integer in Z_q. A marker byte (0x01) keeps
# leading zero bytes. At most this many bytes can be encoded (m < Q constraint):
MAX_SECRET_BYTES = (Q.bit_length() - 1) // 8 - 1   # ~254 bytes for a 2048-bit group


class VSSError(SSSError):
    """VSS-specific errors (derives from the base SSSError)."""


@dataclass
class VSSShare:
    """A VSS share: an x point and the value y = f(x) mod q at that point."""

    x: int
    y: int
    threshold: int | None = None


def _encode_secret(secret: bytes) -> int:
    if len(secret) == 0:
        raise VSSError("The secret cannot be empty.")
    if len(secret) > MAX_SECRET_BYTES:
        raise VSSError(
            f"The secret is too long: {len(secret)} bytes. At most "
            f"{MAX_SECRET_BYTES} bytes for VSS (2048-bit group limit)."
        )
    m = int.from_bytes(b"\x01" + secret, "big")
    if m >= Q:
        raise VSSError("The secret does not fit in the group order (too long).")
    return m


def _decode_secret(m: int) -> bytes:
    raw = m.to_bytes((m.bit_length() + 7) // 8, "big")
    if not raw or raw[0] != 0x01:
        raise VSSError("The recovered value is invalid (shares may be wrong/missing).")
    return raw[1:]


def _eval_poly(coeffs: list[int], x: int) -> int:
    """f(x) mod q — Horner's method."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % Q
    return result


def split(secret: bytes, threshold: int, shares: int) -> tuple[list[VSSShare], list[int]]:
    """Split the secret with a (threshold, shares) = (k, n) scheme.

    Returns (shares, commitments). The commitments are published publicly; anyone
    verifies their own share with verify_share.
    """
    if threshold < 2:
        raise VSSError("The threshold (k) must be at least 2.")
    if shares < threshold:
        raise VSSError(f"The number of shares (n={shares}) cannot be less than the threshold (k={threshold}).")
    if shares > 255:
        raise VSSError("The number of shares (n) can be at most 255.")

    secret_int = _encode_secret(bytes(secret))
    # coeffs[0] = secret; the remaining k-1 coefficients are cryptographically random in Z_q.
    coeffs = [secret_int] + [secrets.randbelow(Q) for _ in range(threshold - 1)]

    out = [
        VSSShare(x=i, y=_eval_poly(coeffs, i), threshold=threshold)
        for i in range(1, shares + 1)
    ]
    commitments = [pow(G, a, P) for a in coeffs]   # C_j = g^(a_j) mod p
    return out, commitments


def verify_share(x: int, y: int, commitments: list[int]) -> bool:
    """Is share (x, y) consistent with the given commitments? Checked without
    learning the secret.

    Valid iff  g^y  ==  Π_j  C_j^(x^j)   (mod p).
    """
    if not commitments:
        raise VSSError("The commitment list is empty.")
    lhs = pow(G, y % Q, P)
    rhs = 1
    for j, c in enumerate(commitments):
        rhs = (rhs * pow(c, pow(x, j, Q), P)) % P
    return lhs == rhs


def _lagrange_at_zero(points: list[tuple[int, int]]) -> int:
    """Compute f(0) over Z_q from the (x, y) points."""
    result = 0
    for i, (xi, yi) in enumerate(points):
        num = 1
        den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % Q
            den = (den * (xi - xj)) % Q
        lam = (num * pow(den, -1, Q)) % Q
        result = (result + yi * lam) % Q
    return result


def combine(shares: list[VSSShare]) -> bytes:
    """Combine shares and reconstruct the secret (at least k shares)."""
    if len(shares) < 2:
        raise VSSError("At least 2 shares are needed to combine.")
    seen: set[int] = set()
    for s in shares:
        if not (1 <= s.x <= 255):
            raise VSSError(f"Invalid share number x={s.x}.")
        if s.x in seen:
            raise VSSError(f"The same share number (x={s.x}) was given twice.")
        seen.add(s.x)
    secret_int = _lagrange_at_zero([(s.x, s.y) for s in shares])
    return _decode_secret(secret_int)
