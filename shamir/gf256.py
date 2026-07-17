"""GF(256) — arithmetic over the 256-element finite field.

Every byte (0..255) is an element of this field. In secret sharing all addition
and multiplication happen here, so every result is again a valid byte (no
overflow) and shares below the threshold leak zero information.

Rules:
  - Addition and subtraction = bitwise XOR (no carry, a + a = 0).
  - Multiplication           = product modulo the irreducible polynomial
                               x^8 + x^4 + x^3 + x + 1 (0x11B). For speed,
                               log/antilog tables are precomputed.

This is the same field and the same polynomial used by AES.
"""

# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1  ->  0b1_0001_1011 = 0x11B
_REDUCING_POLY = 0x11B

# A generator of the multiplicative group. 0x03 is primitive for this
# polynomial: 3^0, 3^1, ... 3^254 walk through all 255 nonzero elements.
_GENERATOR = 0x03

# exp[i] = GENERATOR^i (antilog table), log[v] = i such that exp[i] = v
_EXP = [0] * 512  # 512: index without a modulo when (log[a]+log[b]) overflows
_LOG = [0] * 256


def _russian_peasant_multiply(a: int, b: int) -> int:
    """Multiply two bytes in GF(256) without tables (used to build the tables).

    "Russian peasant multiplication" — walk the bits of b, accumulating a (XOR),
    and at each step multiply a by x (shift left), reducing by the polynomial
    whenever it overflows the 8th bit.
    """
    result = 0
    while b:
        if b & 1:
            result ^= a          # addition = XOR
        b >>= 1
        a <<= 1                  # a = a * x
        if a & 0x100:            # overflowed the 8th bit
            a ^= _REDUCING_POLY  # reduce by the polynomial
    return result


def _build_tables() -> None:
    """Fill the log/antilog tables once, driven by the generator."""
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _russian_peasant_multiply(x, _GENERATOR)
    # Repeat the exp table across 255..509 so that in multiplication the sum
    # (log[a] + log[b]) can index directly even when it exceeds 255.
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()


def add(a: int, b: int) -> int:
    """GF(256) addition (= subtraction). Bitwise XOR."""
    return a ^ b


# Addition and subtraction are the same operation, so sub aliases add.
sub = add


def mul(a: int, b: int) -> int:
    """GF(256) multiplication. Multiplying by 0 is always 0."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def div(a: int, b: int) -> int:
    """GF(256) division: a / b. b must be nonzero."""
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[_LOG[a] - _LOG[b] + 255]  # +255 keeps the subtraction non-negative


def pow_(a: int, exponent: int) -> int:
    """GF(256) exponentiation: a^exponent."""
    if exponent == 0:
        return 1
    if a == 0:
        return 0
    return _EXP[(_LOG[a] * exponent) % 255]


def inverse(a: int) -> int:
    """Multiplicative inverse of a (a * inverse(a) == 1). a must be nonzero."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(256)")
    return _EXP[255 - _LOG[a]]
