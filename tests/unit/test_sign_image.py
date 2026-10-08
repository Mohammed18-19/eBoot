# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""End-to-end tests for the image signing toolchain.

These exercise the property the v2 header format exists for: the Ed25519
signature covers the whole header prefix, so none of the metadata the
bootloader acts on — load address, entry point, size, flags — can be changed
without invalidating it.

Signing hash[] alone (the v1 behaviour) left every one of those fields free to
edit while keeping a legitimate signature. Clearing EOS_IMG_FLAG_HASH_SHA256 in
particular downgraded integrity checking from SHA-256 to forgeable CRC32.
"""

import struct
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS = REPO_ROOT / "tools"

pytest.importorskip("cryptography", reason="signing tools require 'cryptography'")

# Header offsets — include/eos_image.h static-asserts these.
MAGIC_OFFSET = 0
HDR_VERSION_OFFSET = 4
IMAGE_SIZE_OFFSET = 8
LOAD_ADDR_OFFSET = 12
ENTRY_ADDR_OFFSET = 16
IMAGE_VERSION_OFFSET = 20
FLAGS_OFFSET = 24
HASH_OFFSET = 28
SIG_TYPE_OFFSET = 60
SIG_LEN_OFFSET = 61
SIGNATURE_OFFSET = 92
SIGNED_LEN = SIGNATURE_OFFSET
HEADER_SIZE = 156

IMG_FLAG_HASH_SHA256 = 1 << 6


def _run(*args):
    return subprocess.run([sys.executable, *map(str, args)],
                          capture_output=True, text=True)


@pytest.fixture(scope="module")
def signed_image(tmp_path_factory):
    """A packed, Ed25519-signed image plus its keypair."""
    work = tmp_path_factory.mktemp("signing")
    payload = bytes(range(256)) * 8          # 2048 deterministic bytes
    (work / "fw.bin").write_bytes(payload)

    keys = work / "keys"
    r = _run(TOOLS / "sign_image.py", "--genkey", "--output", keys)
    assert r.returncode == 0, r.stderr

    r = _run(TOOLS / "imgpack.py",
             "--input", work / "fw.bin", "--output", work / "fw.eimg",
             "--load-addr", "0x08010000", "--entry-addr", "0x08010100",
             "--version", "1.2.3")
    assert r.returncode == 0, r.stderr

    r = _run(TOOLS / "sign_image.py", "--image", work / "fw.eimg",
             "--method", "ed25519", "--key", keys / "private.pem")
    assert r.returncode == 0, r.stderr

    return {"image": work / "fw.eimg",
            "public": keys / "public.pem",
            "private": keys / "private.pem",
            "payload": payload,
            "work": work}


def _verify(image_path, public_key):
    return _run(TOOLS / "sign_image.py", "--image", image_path,
                "--verify", "--key", public_key)


def test_signed_image_verifies(signed_image):
    r = _verify(signed_image["image"], signed_image["public"])
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "Ed25519:        OK" in r.stdout
    assert "SHA-256:        OK" in r.stdout


def test_signing_bumps_header_to_v2(signed_image):
    data = signed_image["image"].read_bytes()
    version = struct.unpack_from("<H", data, HDR_VERSION_OFFSET)[0]
    assert version == 2, "signing must mark the image as using the v2 format"


def test_signing_sets_the_sha256_flag(signed_image):
    data = signed_image["image"].read_bytes()
    flags = struct.unpack_from("<I", data, FLAGS_OFFSET)[0]
    assert flags & IMG_FLAG_HASH_SHA256


def test_signature_is_over_the_header_prefix(signed_image):
    """Check the signed message independently of the tool that produced it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    data = signed_image["image"].read_bytes()
    public_key = serialization.load_pem_public_key(
        signed_image["public"].read_bytes())
    signature = data[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 64]

    # Verifies over bytes [0, 92) ...
    public_key.verify(signature, data[:SIGNED_LEN])

    # ... and not over hash[] alone, which is what v1 signed.
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, data[HASH_OFFSET:HASH_OFFSET + 32])


@pytest.mark.parametrize("name,offset,fmt,value", [
    ("entry_addr",     ENTRY_ADDR_OFFSET,    "<I", 0x08099999),
    ("load_addr",      LOAD_ADDR_OFFSET,     "<I", 0x20000000),
    ("image_size",     IMAGE_SIZE_OFFSET,    "<I", 1024),
    ("image_version",  IMAGE_VERSION_OFFSET, "<I", 0x09000000),
    ("sig_type",       SIG_TYPE_OFFSET,      "<B", 1),
    ("hdr_version",    HDR_VERSION_OFFSET,   "<H", 1),
])
def test_tampering_with_header_metadata_is_rejected(
        signed_image, name, offset, fmt, value):
    """Every field the bootloader trusts is bound to the signature."""
    data = bytearray(signed_image["image"].read_bytes())
    original = struct.unpack_from(fmt, data, offset)[0]
    assert original != value, f"{name} test value must differ from the original"
    struct.pack_into(fmt, data, offset, value)

    tampered = signed_image["work"] / f"tampered_{name}.eimg"
    tampered.write_bytes(bytes(data))

    r = _verify(tampered, signed_image["public"])
    assert r.returncode != 0, (
        f"tampering with {name} was accepted:\n{r.stdout}\n{r.stderr}")


def test_clearing_the_sha256_flag_is_rejected(signed_image):
    """The downgrade this format change exists to prevent.

    With flags outside the signed region, clearing EOS_IMG_FLAG_HASH_SHA256
    switched integrity checking from SHA-256 to CRC32 while leaving the
    signature valid.
    """
    data = bytearray(signed_image["image"].read_bytes())
    flags = struct.unpack_from("<I", data, FLAGS_OFFSET)[0]
    struct.pack_into("<I", data, FLAGS_OFFSET, flags & ~IMG_FLAG_HASH_SHA256)

    tampered = signed_image["work"] / "tampered_flags.eimg"
    tampered.write_bytes(bytes(data))

    r = _verify(tampered, signed_image["public"])
    assert r.returncode != 0, (
        f"SHA-256 -> CRC32 downgrade was accepted:\n{r.stdout}\n{r.stderr}")


def test_tampering_with_the_payload_is_rejected(signed_image):
    data = bytearray(signed_image["image"].read_bytes())
    data[HEADER_SIZE] ^= 0xFF

    tampered = signed_image["work"] / "tampered_payload.eimg"
    tampered.write_bytes(bytes(data))

    r = _verify(tampered, signed_image["public"])
    assert r.returncode != 0
    assert "SHA-256 mismatch" in r.stderr


def test_verify_rejects_a_signed_image_under_the_wrong_key(signed_image, tmp_path):
    other = tmp_path / "otherkeys"
    assert _run(TOOLS / "sign_image.py", "--genkey", "--output", other).returncode == 0

    r = _verify(signed_image["image"], other / "public.pem")
    assert r.returncode != 0
    assert "does not verify" in r.stderr



def _pack_unsigned(tmp_path, payload=None):
    """Pack a raw payload into an unsigned .eimg via imgpack.py."""
    payload = payload if payload is not None else b"\xA5" * 512
    (tmp_path / "fw.bin").write_bytes(payload)
    r = _run(TOOLS / "imgpack.py",
             "--input", tmp_path / "fw.bin", "--output", tmp_path / "fw.eimg",
             "--load-addr", "0x08010000", "--entry-addr", "0x08010100",
             "--version", "1.0.0")
    assert r.returncode == 0, r.stderr
    return tmp_path / "fw.eimg"


def test_sha256_method_sets_the_integrity_flag(tmp_path):
    """--method sha256 must set EOS_IMG_FLAG_HASH_SHA256."""
    image = _pack_unsigned(tmp_path)
    r = _run(TOOLS / "sign_image.py", "--image", image, "--method", "sha256")
    assert r.returncode == 0, r.stderr

    data = image.read_bytes()
    flags = struct.unpack_from("<I", data, FLAGS_OFFSET)[0]
    assert flags & IMG_FLAG_HASH_SHA256, (
        "SHA-256 signing left EOS_IMG_FLAG_HASH_SHA256 unset")
    assert data[SIG_TYPE_OFFSET] == 2  # SIG_SHA256


def test_sha256_method_verifies_as_sha256(tmp_path):
    """--verify must take the SHA-256 path after --method sha256."""
    image = _pack_unsigned(tmp_path, bytes(range(256)) * 4)
    r = _run(TOOLS / "sign_image.py", "--image", image, "--method", "sha256")
    assert r.returncode == 0, r.stderr

    r = _run(TOOLS / "sign_image.py", "--image", image, "--verify")
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "SHA-256:        OK" in r.stdout
    assert "CRC32:" not in r.stdout


def test_verify_requires_a_signature_when_a_key_is_given(tmp_path):
    """An unsigned image must not pass --verify just because its CRC is fine."""
    (tmp_path / "fw.bin").write_bytes(b"\xA5" * 512)
    r = _run(TOOLS / "imgpack.py",
             "--input", tmp_path / "fw.bin", "--output", tmp_path / "u.eimg",
             "--load-addr", "0x08010000", "--entry-addr", "0x08010100",
             "--version", "1.0.0")
    assert r.returncode == 0, r.stderr

    keys = tmp_path / "k"
    assert _run(TOOLS / "sign_image.py", "--genkey", "--output", keys).returncode == 0

    r = _verify(tmp_path / "u.eimg", keys / "public.pem")
    assert r.returncode != 0
    assert "expected an Ed25519 signature" in r.stderr


# --- --genkey emits the value the build reads, not a header nothing includes ---

def _raw_pubkey_from_pem(pem_path):
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(pem_path.read_bytes())
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_genkey_writes_the_hex_the_build_consumes_and_no_dead_header(tmp_path):
    """--genkey used to write keys/public_key.h defining ebldr_default_pubkey[],
    a symbol nothing in the tree includes or links, so the documented
    procedure left the RFC test key as the trust anchor with no error. The
    build's actual input is -DEBLDR_PRODUCTION_KEY=<64 hex>; that is what
    must be written, and it must be the key in public.pem."""
    keys = tmp_path / "keys"
    r = _run(TOOLS / "sign_image.py", "--genkey", "--output", keys)
    assert r.returncode == 0, r.stderr

    assert not (keys / "public_key.h").exists(), "the dead header is back"
    hex_path = keys / "public_key.hex"
    assert hex_path.exists(), "public_key.hex was not written"
    hex_key = hex_path.read_text().strip()
    assert len(hex_key) == 64 and all(c in "0123456789abcdef" for c in hex_key)
    assert bytes.fromhex(hex_key) == _raw_pubkey_from_pem(keys / "public.pem")
    # the tool tells the developer exactly how to use it
    assert "-DEBLDR_PRODUCTION_KEY=" in r.stdout
    assert "key_lifecycle.md" in r.stdout


def test_genkey_output_passes_the_configure_time_key_check(tmp_path):
    """The gate runs tools/check_production_key.py on EBLDR_PRODUCTION_KEY. A
    freshly generated key is a real curve point in the prime-order subgroup,
    so the value --genkey writes must pass that check as-is -- otherwise the
    documented path produces a key the build refuses."""
    keys = tmp_path / "keys"
    assert _run(TOOLS / "sign_image.py", "--genkey", "--output", keys).returncode == 0
    hex_key = (keys / "public_key.hex").read_text().strip()
    r = _run(TOOLS / "check_production_key.py", hex_key)
    assert r.returncode == 0, r.stderr


def test_extract_pubkey_writes_hex_too(tmp_path):
    keys = tmp_path / "keys"
    assert _run(TOOLS / "sign_image.py", "--genkey", "--output", keys).returncode == 0
    out = tmp_path / "anchor.hex"
    r = _run(TOOLS / "sign_image.py", "--extract-pubkey", keys / "private.pem", "--output", out)
    assert r.returncode == 0, r.stderr
    assert out.read_text().strip() == (keys / "public_key.hex").read_text().strip()
    assert "ebldr_default_pubkey" not in out.read_text()


def _sign_image_flags():
    """Every long option sign_image.py actually defines."""
    import re
    src = (TOOLS / "sign_image.py").read_text(encoding="utf-8", errors="replace")
    return set(re.findall(r"add_argument\(\s*'(--[a-z-]+)'", src))


@pytest.mark.parametrize("rel", ["docs/quickstart.md", "docs/key_lifecycle.md"])
def test_docs_name_the_key_path_the_build_reads(rel):
    """Both documents told developers about a header. quickstart named
    public_key.h; key_lifecycle showed --key-out and --pub-header, two flags
    sign_image.py has never defined. Each must now name the file --genkey
    writes and the flag that consumes it, and no header."""
    doc = (REPO_ROOT / rel).read_text(encoding="utf-8")
    assert "public_key.hex" in doc, rel
    assert "-DEBLDR_PRODUCTION_KEY=" in doc, rel
    assert "public_key.h\n" not in doc and "public_key.h." not in doc and "public_key.h " not in doc, rel


@pytest.mark.parametrize("rel", ["docs/quickstart.md", "docs/key_lifecycle.md", "README.md"])
def test_docs_only_show_sign_image_flags_that_exist(rel):
    """A documented flag the tool does not have is the same defect as a
    documented header nothing reads: the reader follows it and gets an
    argparse error at best, or a silently-wrong build at worst."""
    import re
    path = REPO_ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} absent")
    doc = path.read_text(encoding="utf-8")
    shown = set()
    # Lines ending in a backslash continue the invocation. [^\n]* alone
    # swallows that backslash, so the first version of this never read a
    # continuation line and could not fail on the flags it was written for.
    for block in re.findall(r"sign_image\.py(?:[^\n]*\\\n)*[^\n]*", doc):
        shown |= set(re.findall(r"(--[a-z-]+)", block))
    phantom = sorted(shown - _sign_image_flags())
    assert not phantom, f"{rel} documents sign_image.py flags that do not exist: {phantom}"
