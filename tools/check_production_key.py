#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project
"""Refuse a production trust anchor that the bootloader could not use.

cmake/ProductionKey.cmake checks that EBLDR_PRODUCTION_KEY is 64 hexadecimal
characters and is not the development key. Neither check asks whether the bytes
are a public key at all. They can fail to be one in two ways that matter:

  * they decode to no point on edwards25519 -- the exact defect the shipped
    development key had until it was fixed, and one mistyped hex digit in a
    release secret reproduces it;
  * they decode to a point of low order (every signature verifies) or one
    outside the prime-order subgroup (the verifier refuses every image)
    (core/ed25519_verify.c, public_key_is_valid_subgroup).

A device built with such an anchor refuses every firmware image it is ever
offered, with a green build and a status line saying the production key is in
place. That fails closed, so it is not a compromise; it is still unrecoverable
in the field. This tool applies the verifier's own acceptance rule before the
key is compiled into anything: the encoding decodes to a point, [L]P is the
identity and P is not. Pure Python, no dependencies, so it can run anywhere a
release is cut.

Usage: check_production_key.py <64 hex chars>      exit 0 if acceptable
"""

import sys

P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P
# The order of the prime-order subgroup: 2^252 + 27742317777372353535851937790883648493.
L = 2**252 + 27742317777372353535851937790883648493
# sqrt(-1) mod p, used when recovering x.
SQRT_M1 = pow(2, (P - 1) // 4, P)

# RFC 8032 section 7.1 TEST 1 public key: what core/keystore.c compiles in when
# no production key is given. Its secret is printed in the RFC.
DEV_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

IDENTITY = (0, 1, 1, 0)  # extended coordinates (X, Y, Z, T)


def _decode(key: bytes):
    """RFC 8032 section 5.1.3. Returns (x, y) or raises ValueError."""
    if len(key) != 32:
        raise ValueError("a public key is exactly 32 bytes")
    y = int.from_bytes(key, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        raise ValueError("y coordinate is not below p (non-canonical encoding)")
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == u:
        pass
    elif vx2 == (-u) % P:
        x = (x * SQRT_M1) % P
    else:
        raise ValueError("the bytes decode to no point on edwards25519")
    if x == 0 and sign == 1:
        raise ValueError("x is zero but the sign bit is set (invalid encoding)")
    if (x & 1) != sign:
        x = P - x
    return x, y


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(point, n):
    result, addend = IDENTITY, point
    while n:
        if n & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        n >>= 1
    return result


def _is_identity(p):
    x, y, z, _ = p
    return x % P == 0 and (y - z) % P == 0


def check_production_key_hex(hex_key: str) -> None:
    """Raise ValueError with a one-line reason if hex_key is not acceptable."""
    hex_key = hex_key.strip()
    if len(hex_key) != 64:
        raise ValueError(
            f"EBLDR_PRODUCTION_KEY must be exactly 64 hexadecimal characters; "
            f"got {len(hex_key)}")
    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("EBLDR_PRODUCTION_KEY contains a non-hexadecimal character")
    if hex_key.lower() == DEV_KEY_HEX:
        raise ValueError(
            "EBLDR_PRODUCTION_KEY is the RFC 8032 section 7.1 TEST 1 public key -- "
            "the development key, whose secret is published")
    x, y = _decode(key)
    point = (x, y, 1, x * y % P)
    if _is_identity(point):
        raise ValueError("the key is the identity point; any signature verifies "
                         "against it")
    if not _is_identity(_mul(point, L)):
        # Outside the prime-order subgroup. Two very different things land
        # here and an operator needs to be told which:
        #   [8]P == identity: P has order 2, 4 or 8. Every signature verifies
        #   against it -- fails open. Somebody handed over an attack vector.
        #   otherwise: P has order 2L, 4L or 8L. That is where a mistyped hex
        #   digit lands about half the time. The verifier refuses it and every
        #   image is rejected -- fails closed. Somebody typed the secret wrong.
        if _is_identity(_mul(point, 8)):
            raise ValueError("the key is a point of low order (order 2, 4 or 8); "
                             "every signature would verify against it")
        raise ValueError("the key is on the curve but not in the prime-order "
                         "subgroup -- a mistyped hex digit usually lands here; "
                         "the verifier refuses it and every image would be rejected. "
                         "Check the secret against the key that was generated")


def main(argv) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    try:
        check_production_key_hex(argv[1])
    except ValueError as e:
        print(f"production key refused: {e}", file=sys.stderr)
        return 1
    print("production key accepted: a point in the prime-order subgroup of "
          "edwards25519, and not the development key")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
