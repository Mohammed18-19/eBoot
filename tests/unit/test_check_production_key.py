# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""tools/check_production_key.py applies the verifier's acceptance rule to a
candidate production key before it is compiled into anything. These vectors
pin each branch of that rule; every refusal is checked for its *reason*, so a
key refused for the wrong reason (a mistyped vector, say) is a failure here
rather than a pass.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from check_production_key import check_production_key_hex, main  # noqa: E402

# RFC 8032 section 7.1 TEST 2 and TEST 3 public keys: real curve points.
TEST2 = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
TEST3 = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
DEV = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
# What core/keystore.c compiled in before eBoot#116: decodes to no point.
OFF_CURVE = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18c42c47684377725"


@pytest.mark.parametrize("key", [TEST2, TEST3, TEST2.upper()])
def test_a_real_key_is_accepted(key):
    check_production_key_hex(key)


def test_mixed_order_is_not_reported_as_low_order():
    """Both classes are outside the prime-order subgroup and both are refused,
    but they fail in opposite directions: a genuine low-order point makes every
    signature verify, a mixed-order one makes the verifier refuse every image.
    The message must say which, because the operator's next action differs."""
    with pytest.raises(ValueError) as low:
        check_production_key_hex("ec" + "ff" * 30 + "7f")           # order 2
    with pytest.raises(ValueError) as mixed:
        check_production_key_hex(DEV[:-1] + "b")                     # order 8L
    assert "low order" in str(low.value)
    assert "every signature would verify" in str(low.value)
    assert "low order" not in str(mixed.value)
    assert "prime-order subgroup" in str(mixed.value)
    assert "mistyped" in str(mixed.value)


@pytest.mark.parametrize("key,reason", [
    (DEV, "development key"),
    (DEV.upper(), "development key"),
    (OFF_CURVE, "no point on edwards25519"),
    ("01" + "00" * 31, "identity"),                 # the identity point
    ("ec" + "ff" * 30 + "7f", "low order"),          # order 2
    ("00" * 31 + "80", "low order"),                 # order 4
    ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
     "low order"),                                   # order 8
    # On the curve, outside the prime-order subgroup, NOT low order: order 8L.
    # This is where a mistyped hex digit lands about half the time, and it is
    # the case an operator will actually hit, so it must not be reported as
    # "low order" -- that names an attack vector when the cause is a typo.
    ("03" + "00" * 31, "prime-order subgroup"),
    (DEV[:-1] + "b", "prime-order subgroup"),        # dev key, last digit mistyped
    ("ff" * 31 + "7f", "not below p"),               # y = 2^255 - 1
    ("ed" + "ff" * 30 + "7f", "not below p"),        # y = p exactly
    (TEST2[:-2], "exactly 64"),
    (TEST2 + "00", "exactly 64"),
    ("zz" + TEST2[2:], "non-hexadecimal"),
])
def test_an_unusable_key_is_refused_for_the_stated_reason(key, reason):
    with pytest.raises(ValueError) as exc:
        check_production_key_hex(key)
    assert reason in str(exc.value), str(exc.value)


def test_cli_exit_codes(capsys):
    assert main(["check", TEST2]) == 0
    assert main(["check", OFF_CURVE]) == 1
    assert "refused" in capsys.readouterr().err
    assert main(["check"]) == 2
