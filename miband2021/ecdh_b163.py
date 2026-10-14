"""ECDH over the NIST B-163 binary curve.

A dependency-free Python port of Gadgetbridge's ``ECDH_B163.java`` (which is
itself a port of https://github.com/kokke/tiny-ECDH-c).

Serialisation is byte-for-byte identical to the Java implementation used by
Gadgetbridge / the Huami "2021" protocol:

* scalars are 24 bytes (``2 * 24 = 48`` for a public point ``x || y``),
* every value is a little-endian integer (6 x uint32 words, LE byte order).

The field GF(2^163) arithmetic is done with Python big integers instead of
32-bit word vectors.  The reduction polynomial and the curve parameters are
taken verbatim from the Java source.
"""

from __future__ import annotations

CURVE_DEGREE = 163
PRV_KEY_SIZE = 24
PUB_KEY_SIZE = 2 * PRV_KEY_SIZE  # 48

# Reduction polynomial x^163 + x^7 + x^6 + x^3 + 1
_POLY = (1 << 163) | (1 << 7) | (1 << 6) | (1 << 3) | 1

# Field element 1
_ONE = 1


def _from_words(words):
    """Little-endian uint32 word vector -> python int (matches bytes_to_int)."""
    return sum(w << (32 * i) for i, w in enumerate(words))


# --- NIST B-163 curve parameters (word vectors from ECDH_B163.java) ----------
_CURVE_B_WORDS = [0x4A3205FD, 0x512F7874, 0x1481EB10, 0xB8C953CA, 0x0A601907, 0x00000002]
_BASE_X_WORDS = [0xE8343E36, 0xD4994637, 0xA0991168, 0x86A2D57E, 0xF0EBA162, 0x00000003]
_BASE_Y_WORDS = [0x797324F1, 0xB11C5C0C, 0xA2CDD545, 0x71A0094F, 0xD51FBC6C, 0x00000000]
_BASE_ORDER_WORDS = [0xA4234C33, 0x77E70C12, 0x000292FE, 0x00000000, 0x00000000, 0x00000004]

CURVE_B = _from_words(_CURVE_B_WORDS)
BASE_X = _from_words(_BASE_X_WORDS)
BASE_Y = _from_words(_BASE_Y_WORDS)
BASE_ORDER = _from_words(_BASE_ORDER_WORDS)

# bitvec_degree(base_order) == 163 -> scalars are masked to 162 bits
_SCALAR_BITS = BASE_ORDER.bit_length() - 1
_SCALAR_MASK = (1 << _SCALAR_BITS) - 1


# ---------------------------------------------------------------------------
# GF(2^163) arithmetic
# ---------------------------------------------------------------------------
def gf_add(a: int, b: int) -> int:
    """Addition in GF(2^m) is XOR."""
    return a ^ b


def gf_mul(a: int, b: int) -> int:
    """Carry-less multiplication with reduction by _POLY."""
    z = 0
    tmp = a
    if b & 1:
        z = tmp
    for i in range(1, CURVE_DEGREE):
        tmp <<= 1
        if (tmp >> CURVE_DEGREE) & 1:
            tmp ^= _POLY
        if (b >> i) & 1:
            z ^= tmp
    return z


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^163): a^(2^163 - 2)."""
    if a == 0:
        raise ZeroDivisionError("0 has no inverse in GF(2^163)")
    result = 1
    base = a
    exp = (1 << CURVE_DEGREE) - 2
    while exp:
        if exp & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        exp >>= 1
    return result


# ---------------------------------------------------------------------------
# EC point arithmetic on y^2 + x*y = x^3 + a*x^2 + b  (a == 1 for NIST curves)
# ---------------------------------------------------------------------------
def _is_zero(x: int, y: int) -> bool:
    return x == 0 and y == 0


def _double(x: int, y: int):
    if x == 0:
        return 0, 0
    l = gf_mul(gf_inv(x), y)
    l = gf_add(l, x)
    y_new = gf_mul(x, x)
    x_new = gf_mul(l, l)
    l = gf_add(l, _ONE)
    x_new = gf_add(x_new, l)
    l = gf_mul(l, x_new)
    y_new = gf_add(y_new, l)
    return x_new, y_new


def _add(x1: int, y1: int, x2: int, y2: int):
    if _is_zero(x2, y2):
        return x1, y1
    if _is_zero(x1, y1):
        return x2, y2
    if x1 == x2:
        if y1 == y2:
            return _double(x1, y1)
        return 0, 0
    a = gf_add(y1, y2)
    b = gf_add(x1, x2)
    c = gf_mul(gf_inv(b), a)
    d = gf_mul(c, c)
    d = gf_add(d, c)
    d = gf_add(d, b)
    d = gf_add(d, _ONE)
    x1 = gf_add(x1, d)
    a = gf_mul(x1, c)
    a = gf_add(a, d)
    y1 = gf_add(y1, a)
    return d, y1


def _mul_point(x: int, y: int, k: int):
    """Double-and-add scalar multiplication (k * (x, y))."""
    tx, ty = 0, 0
    for i in range(k.bit_length() - 1, -1, -1):
        tx, ty = _double(tx, ty)
        if (k >> i) & 1:
            tx, ty = _add(tx, ty, x, y)
    return tx, ty


def _on_curve(x: int, y: int) -> bool:
    """Check y^2 + x*y == x^3 + x^2 + b."""
    if _is_zero(x, y):
        return False
    a = gf_mul(x, x)
    b = gf_mul(a, x)
    a = gf_add(a, b)
    a = gf_add(a, CURVE_B)
    b = gf_mul(y, y)
    a = gf_add(a, b)
    b = gf_mul(x, y)
    return a == b


# ---------------------------------------------------------------------------
# ECDH
# ---------------------------------------------------------------------------
def generate_public(private_ec: bytes):
    """Return the 48-byte public point for a 24-byte private scalar.

    Mirrors ``ECDH_B163.ecdh_generate_public``.  Returns ``None`` when the
    random scalar is too small (degree < CURVE_DEGREE / 2).
    """
    if len(private_ec) != PRV_KEY_SIZE:
        raise ValueError("private key must be %d bytes" % PRV_KEY_SIZE)
    priv = int.from_bytes(private_ec, "little")
    if priv.bit_length() < CURVE_DEGREE // 2:
        return None
    priv &= _SCALAR_MASK
    x, y = _mul_point(BASE_X, BASE_Y, priv)
    return x.to_bytes(PRV_KEY_SIZE, "little") + y.to_bytes(PRV_KEY_SIZE, "little")


def generate_shared(private_ec: bytes, remote_public_ec: bytes):
    """Return the 48-byte shared point for our private key and their public point."""
    if len(private_ec) != PRV_KEY_SIZE:
        raise ValueError("private key must be %d bytes" % PRV_KEY_SIZE)
    if len(remote_public_ec) != PUB_KEY_SIZE:
        raise ValueError("remote public key must be %d bytes" % PUB_KEY_SIZE)
    priv = int.from_bytes(private_ec, "little")
    rx = int.from_bytes(remote_public_ec[:PRV_KEY_SIZE], "little")
    ry = int.from_bytes(remote_public_ec[PRV_KEY_SIZE:], "little")
    if _is_zero(rx, ry) or not _on_curve(rx, ry):
        return None
    priv &= _SCALAR_MASK
    x, y = _mul_point(rx, ry, priv)
    return x.to_bytes(PRV_KEY_SIZE, "little") + y.to_bytes(PRV_KEY_SIZE, "little")