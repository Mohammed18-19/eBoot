#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project
"""Refuse any release artifact that embeds the development trust anchor.

core/keystore.c compiles in the RFC 8032 section 7.1 TEST 1 public key when
EBLDR_PRODUCTION_KEY is unset. Its secret is printed in the RFC, so an image
built on it trusts a key anyone can sign for. The configure-time gate refuses
that for release-shaped board builds; this is the second, independent check,
run over what the release workflow actually ships.

Six release jobs used to carry this scan inline, each a copy, and the copies
read only .elf .bin .a .o while the artifacts step also shipped .hex, .uf2 and
.efi. Two lists maintained by hand beside each other drift; this is the one
copy, and tests/unit/test_release_workflow_production_key.py asserts that its
suffix set covers every suffix the workflow collects.

Two of those formats are not raw bytes. Intel HEX is ASCII, and a UF2 file is
512-byte blocks with headers, so grepping either for the key's raw bytes finds
nothing even when the key is there -- a scan that opened them and reported
clean would be worse than no scan. Both are decoded to the image they encode
before being searched.

usage: check_no_dev_anchor.py [BUILD_DIR ...]      (default: build)

Exit 0 and print one line when nothing under the directories embeds the key.
Print one ::error per hit and exit 1 otherwise.
"""

import pathlib
import struct
import sys

# RFC 8032 section 7.1 TEST 1 public key, as compiled in by core/keystore.c.
DEV_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

# Everything the release workflow collects, plus the intermediates the key
# actually lives in. Keep RAW and DECODED disjoint and complete: the test
# checks their union against release.yml's `find ... -name` globs.
# Both .o and .obj: CMake names objects .obj under CMAKE_SYSTEM_NAME=Generic,
# which is every cross target, so an .o-only entry scanned nothing on exactly
# the builds whose objects matter most.
RAW_SUFFIXES = {".elf", ".bin", ".a", ".o", ".obj", ".efi"}
DECODED_SUFFIXES = {".hex", ".uf2"}
SUFFIXES = RAW_SUFFIXES | DECODED_SUFFIXES

UF2_MAGIC0 = 0x0A324655
UF2_MAGIC1 = 0x9E5D5157
UF2_BLOCK = 512


def decode_intel_hex(text):
    """Return the contiguous byte runs an Intel HEX file describes.

    Only the record types a firmware image uses: 00 data, 01 EOF, 02
    extended segment, 04 extended linear. Anything else stops the decode
    rather than being skipped, so an unexpected format is a failure, not a
    quiet gap in coverage.
    """
    upper = 0
    chunks = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith(":"):
            raise ValueError(f"not an Intel HEX record: {line[:20]!r}")
        rec = bytes.fromhex(line[1:])
        # Byte count, two address bytes, type, checksum: five bytes minimum.
        # Indexing before checking turned a truncated record into an
        # IndexError traceback instead of the ::error line this tool promises.
        if len(rec) < 5:
            raise ValueError(f"Intel HEX record is truncated: {line[:20]!r}")
        length, addr, rtype = rec[0], (rec[1] << 8) | rec[2], rec[3]
        if len(rec) != 5 + length:
            raise ValueError(f"Intel HEX record length field disagrees with the record: {line[:20]!r}")
        data = rec[4:4 + length]
        if (sum(rec) & 0xFF) != 0:
            raise ValueError("Intel HEX checksum mismatch")
        if rtype == 0x00:
            chunks[upper + addr] = data
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            upper = ((data[0] << 8) | data[1]) << 4
        elif rtype == 0x04:
            upper = ((data[0] << 8) | data[1]) << 16
        else:
            raise ValueError(f"unsupported Intel HEX record type {rtype:#04x}")
    return _runs(chunks)


def decode_uf2(blob):
    """Return the contiguous byte runs a UF2 file's payload blocks describe."""
    if len(blob) % UF2_BLOCK:
        raise ValueError("UF2 file is not a whole number of 512-byte blocks")
    chunks = {}
    for off in range(0, len(blob), UF2_BLOCK):
        m0, m1, _flags, addr, size = struct.unpack_from("<IIIII", blob, off)
        if m0 != UF2_MAGIC0 or m1 != UF2_MAGIC1:
            raise ValueError(f"bad UF2 block magic at offset {off}")
        if size > 476:
            raise ValueError(f"UF2 payload size {size} exceeds the block")
        chunks[addr] = blob[off + 32:off + 32 + size]
    return _runs(chunks)


def _runs(chunks):
    """Merge address->bytes chunks into contiguous runs, so a key that
    straddles two records or two blocks is still one search."""
    runs, cur, cur_addr = [], bytearray(), None
    for addr in sorted(chunks):
        data = chunks[addr]
        if cur_addr is not None and addr == cur_addr + len(cur):
            cur += data
        else:
            if cur:
                runs.append(bytes(cur))
            cur, cur_addr = bytearray(data), addr
    if cur:
        runs.append(bytes(cur))
    return runs


def images_of(path):
    """The byte images to search for a given artifact."""
    suffix = path.suffix.lower()
    if suffix == ".hex":
        return decode_intel_hex(path.read_text(encoding="ascii", errors="strict"))
    if suffix == ".uf2":
        return decode_uf2(path.read_bytes())
    return [path.read_bytes()]


def scan(roots):
    hits, undecodable = [], []
    for root in roots:
        for p in sorted(pathlib.Path(root).rglob("*")):
            # Case-folded: a .BIN or .HEX artifact is the same artifact, and
            # skipping it would report it clean without having read it.
            if not p.is_file() or p.suffix.lower() not in SUFFIXES:
                continue
            try:
                if any(DEV_KEY in img for img in images_of(p)):
                    hits.append(str(p))
            except (ValueError, UnicodeDecodeError, IndexError, struct.error) as e:
                undecodable.append((str(p), f"{type(e).__name__}: {e}"))
    return hits, undecodable


def main(argv):
    roots = argv[1:] or ["build"]
    hits, undecodable = scan(roots)
    for h in hits:
        print(f"::error file={h}::embeds the development trust anchor")
    for path, why in undecodable:
        # A file the scan could not read is a file the scan did not check.
        print(f"::error file={path}::could not be decoded for the anchor scan: {why}")
    if hits or undecodable:
        return 1
    print(f"no artifact under {', '.join(roots)} contains the development key "
          f"(suffixes searched: {' '.join(sorted(SUFFIXES))})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
