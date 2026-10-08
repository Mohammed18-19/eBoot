# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""The configure-time gate on the compiled-in trust anchor.

core/keystore.c falls back to a compiled-in public key on a board without
OTP -- every board under boards/ today. Without EBLDR_PRODUCTION_KEY that key
is the RFC 8032 test key, whose secret is published. These tests run real
CMake configures against the repository and pin what the gate does:

  * a Release build of a real board refuses to configure without a key,
    and says why, before anything else goes wrong;
  * EBLDR_ALLOW_DEV_KEY=ON is the one way past that, and it is explicit;
  * the development key and a malformed value are refused as production keys;
  * a real key produces the generated translation unit with those bytes.

Configure only; nothing is compiled.
"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# RFC 8032 section 7.1 TEST 2 public key: a real curve point that is not the
# development key.
GOOD_KEY = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
# RFC 8032 section 7.1 TEST 1 public key: core/keystore.c's fallback.
DEV_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

GATE_MESSAGE = "EBLDR_PRODUCTION_KEY is not set"

pytestmark = pytest.mark.skipif(
    shutil.which("cmake") is None, reason="cmake is not on PATH")


def configure(*defs):
    build = Path(tempfile.mkdtemp(prefix="eboot-gate-"))
    try:
        result = subprocess.run(
            ["cmake", "-S", str(REPO_ROOT), "-B", str(build), *defs],
            capture_output=True, text=True)
        generated = build / "generated" / "production_key.c"
        text = generated.read_text() if generated.exists() else None
        return result, text
    finally:
        shutil.rmtree(build, ignore_errors=True)


def first_error(stderr):
    """The first 'CMake Error' block, so ordering can be asserted."""
    blocks = re.split(r"(?=CMake Error)", stderr)
    return next((b for b in blocks if b.startswith("CMake Error")), "")


# Every build type that is not Debug is release-shaped: the optimised types
# under every spelling CMake accepts, and no build type at all -- a cross build
# still gets -Os from CMakeLists.txt, and a multi-config generator has no type
# at configure time. The gate used to match the literal "Release" only, and
# the other five configured a real board around it.
RELEASE_SHAPED = ["Release", "RelWithDebInfo", "MinSizeRel",
                  "release", "RELEASE", None]


@pytest.mark.parametrize("build_type", RELEASE_SHAPED,
                         ids=[t or "unset" for t in RELEASE_SHAPED])
def test_release_shaped_board_build_refuses_without_a_key(build_type):
    defs = ["-DEBLDR_BOARD=stm32f4"]
    if build_type is not None:
        defs.append("-DCMAKE_BUILD_TYPE=" + build_type)
    result, generated = configure(*defs)
    assert result.returncode != 0
    assert GATE_MESSAGE in result.stderr
    # The gate, not a missing toolchain or a board port, is what stops it.
    assert GATE_MESSAGE in first_error(result.stderr), result.stderr
    assert "Only a Debug build is exempt" in result.stderr
    assert generated is None


@pytest.mark.parametrize("build_type", ["Debug", "debug", "DEBUG"])
def test_debug_board_build_is_the_one_exemption(build_type):
    result, _ = configure("-DCMAKE_BUILD_TYPE=" + build_type,
                          "-DEBLDR_BOARD=stm32f4")
    assert result.returncode == 0, result.stderr
    assert GATE_MESSAGE not in result.stderr


def test_release_board_build_can_say_it_is_not_a_release():
    result, _ = configure("-DCMAKE_BUILD_TYPE=Release", "-DEBLDR_BOARD=stm32f4",
                          "-DEBLDR_ALLOW_DEV_KEY=ON")
    assert GATE_MESSAGE not in result.stderr


def test_host_build_is_not_gated():
    # No board, so nothing reaches a device: no key, no opt-out, no gate message.
    result, generated = configure("-DCMAKE_BUILD_TYPE=Release")
    assert result.returncode == 0, result.stderr
    assert GATE_MESSAGE not in result.stderr
    assert generated is None, "no key was given, so nothing should be generated"


def test_development_key_is_refused_as_a_production_key():
    for spelling in (DEV_KEY, DEV_KEY.upper()):
        result, generated = configure("-DEBLDR_PRODUCTION_KEY=" + spelling)
        assert result.returncode != 0
        assert "development key" in result.stderr, result.stderr
        assert generated is None


@pytest.mark.parametrize("bad", ["abc", GOOD_KEY[:-2], GOOD_KEY + "00",
                                 "zz" + GOOD_KEY[2:]])
def test_malformed_key_is_refused(bad):
    result, generated = configure("-DEBLDR_PRODUCTION_KEY=" + bad)
    assert result.returncode != 0
    assert "exactly 64" in result.stderr, result.stderr
    assert generated is None


# The bytes core/keystore.c shipped before eBoot#116: 64 hex characters, not
# the development key, and no point on edwards25519. The length and dev-key
# checks accept them; only the curve check refuses them.
OFF_CURVE_KEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18c42c47684377725"
# The order-2 point. On the curve, refused by the verifier's subgroup check.
LOW_ORDER_KEY = "ec" + "ff" * 30 + "7f"


@pytest.mark.parametrize("key,reason", [
    (OFF_CURVE_KEY, "no point on edwards25519"),
    (LOW_ORDER_KEY, "low order"),
    ("01" + "00" * 31, "identity"),
])
def test_key_the_verifier_would_refuse_is_refused_at_configure(key, reason):
    result, generated = configure("-DCMAKE_BUILD_TYPE=Release",
                                  "-DEBLDR_BOARD=stm32f4",
                                  "-DEBLDR_PRODUCTION_KEY=" + key)
    assert result.returncode != 0
    assert "not a usable Ed25519 public key" in result.stderr, result.stderr
    assert reason in result.stderr, result.stderr
    assert generated is None, "an unusable key must not be compiled in"


def test_production_key_without_python_refuses_rather_than_skipping_the_check():
    """The point check runs in Python. A production-key configure on a machine
    with no python3 must stop, not warn and compile an unchecked key in: this
    gate is the only control for a build made outside release.yml, and a
    warning scrolls past. CMAKE_DISABLE_FIND_PACKAGE_Python3 is how CMake
    itself simulates the interpreter being absent."""
    result, generated = configure("-DCMAKE_BUILD_TYPE=Release", "-DEBLDR_BOARD=stm32f4",
                                  "-DEBLDR_PRODUCTION_KEY=" + GOOD_KEY,
                                  "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE")
    assert result.returncode != 0, "a production key was compiled in unchecked"
    assert "python3 was not found" in result.stderr, result.stderr
    assert "CMake Warning" not in result.stderr, "it must refuse, not warn"
    assert generated is None
    # A development build never runs the check, so it is unaffected.
    result, _ = configure("-DCMAKE_BUILD_TYPE=Debug", "-DEBLDR_BOARD=stm32f4",
                          "-DCMAKE_DISABLE_FIND_PACKAGE_Python3=TRUE")
    assert result.returncode == 0, result.stderr


def test_real_key_generates_the_anchor_source():
    result, generated = configure("-DCMAKE_BUILD_TYPE=Release",
                                  "-DEBLDR_BOARD=stm32f4",
                                  "-DEBLDR_PRODUCTION_KEY=" + GOOD_KEY.upper())
    assert GATE_MESSAGE not in result.stderr
    assert generated is not None, result.stderr
    assert "ebldr_production_key[EOS_ED25519_PUB_KEY_SIZE]" in generated
    emitted = "".join(re.findall(r"0x([0-9a-f]{2})", generated))
    assert emitted == GOOD_KEY, "the generated bytes must be the configured key"
