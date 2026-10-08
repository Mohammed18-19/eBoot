# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Every release-shaped CMake configure in the workflows carries a trust
anchor, and the release scans what it built for the development key.

The gate in CMakeLists.txt is what makes a Release board build refuse the
development key. This pins the other half: that release.yml actually passes
EBLDR_PRODUCTION_KEY on every board configure (so an unset secret fails
closed instead of being worked around), never passes EBLDR_ALLOW_DEV_KEY, and
scans every firmware build for the development key's bytes -- and that the
bytes it scans for are the ones core/keystore.c and cmake/ProductionKey.cmake
name.
"""

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
SCAN_STEP = "Refuse an artifact that embeds the development anchor"


def load(name):
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def run_steps(job):
    return [s for s in job.get("steps", []) if isinstance(s.get("run"), str)]


def configure_lines(run):
    """Each `cmake -B` configure in a run block, with its backslash
    continuation lines. A continuation that itself starts another
    `cmake -B` (the esp32 jobs chain two with `||`) is its own configure."""
    lines = run.splitlines()
    blocks, i = [], 0
    while i < len(lines):
        if "cmake -B" in lines[i]:
            block = lines[i]
            while block.rstrip().endswith("\\") and i + 1 < len(lines):
                i += 1
                block += "\n" + lines[i]
            blocks.append(block)
        i += 1
    out = []
    for block in blocks:
        out.extend(part for part in re.split(r"(?=cmake -B)", block) if "cmake -B" in part)
    return out


def board_of(block):
    m = re.search(r"-DEBLDR_BOARD=(\S+)", block)
    return m.group(1) if m else None


# Mirrors the gate in CMakeLists.txt: any optimised build type, case-insensitive,
# or none named at all. The gate test parametrises the same spellings, so if
# the two drift it fails there rather than going quiet here.
RELEASE_SHAPED = re.compile(
    r"-DCMAKE_BUILD_TYPE=(Release|RelWithDebInfo|MinSizeRel)\b", re.IGNORECASE)

def is_release_shaped(block):
    if "$BUILD_TYPE" in block or RELEASE_SHAPED.search(block):
        return True
    return "-DCMAKE_BUILD_TYPE=" not in block


def dev_key_from_keystore():
    src = (REPO_ROOT / "core" / "keystore.c").read_text(encoding="utf-8")
    m = re.search(r"default_dev_key\[EOS_ED25519_PUB_KEY_SIZE\]\s*=\s*\{([^}]*)\}", src)
    assert m, "default_dev_key[] not found in core/keystore.c"
    return "".join(f"{int(x, 16):02x}" for x in re.findall(r"0x([0-9a-fA-F]{2})", m.group(1)))


def dev_key_from_cmake():
    src = (REPO_ROOT / "cmake" / "ProductionKey.cmake").read_text(encoding="utf-8")
    m = re.search(r'set\(EBLDR_DEV_KEY_HEX\s*"([0-9a-f]{64})"\)', src)
    assert m, "EBLDR_DEV_KEY_HEX not found in cmake/ProductionKey.cmake"
    return m.group(1)


def test_every_release_board_configure_passes_the_production_key():
    doc = load("release.yml")
    seen = 0
    for job_id, job in doc["jobs"].items():
        for step in run_steps(job):
            for block in configure_lines(step["run"]):
                if board_of(block) in (None, "none"):
                    continue
                seen += 1
                assert "-DEBLDR_PRODUCTION_KEY=" in block, (
                    f"release.yml job {job_id!r}: a board configure without "
                    f"EBLDR_PRODUCTION_KEY would ship the development key:\n{block}")
                assert "secrets.EBLDR_PRODUCTION_KEY_HEX" in block, (
                    f"release.yml job {job_id!r}: the key must come from the "
                    f"EBLDR_PRODUCTION_KEY_HEX secret, not a literal:\n{block}")
                assert "EBLDR_ALLOW_DEV_KEY" not in block, (
                    f"release.yml job {job_id!r} opts into the development key")
    assert seen == 8, f"expected the 8 board configures release.yml had, found {seen}"


def test_every_release_firmware_job_scans_for_the_development_key():
    doc = load("release.yml")
    firmware_jobs = [
        (job_id, job) for job_id, job in doc["jobs"].items()
        if any(board_of(b) not in (None, "none")
               for s in run_steps(job) for b in configure_lines(s["run"]))]
    assert len(firmware_jobs) == 6, [j for j, _ in firmware_jobs]
    for job_id, job in firmware_jobs:
        names = [s.get("name") for s in job["steps"]]
        assert SCAN_STEP in names, f"release.yml job {job_id!r} has no scan step"
        build = next(i for i, s in enumerate(job["steps"])
                     if isinstance(s.get("run"), str) and "cmake --build" in s["run"])
        scan = names.index(SCAN_STEP)
        collect = names.index("Collect artifacts")
        assert build < scan < collect, (
            f"release.yml job {job_id!r}: the scan must run after the build and "
            f"before artifacts are collected")


SCAN_TOOL = "tools/check_no_dev_anchor.py"


def scan_tool():
    import importlib.util
    spec = importlib.util.spec_from_file_location("check_no_dev_anchor", REPO_ROOT / SCAN_TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_scan_step_calls_the_one_scanner():
    """Six jobs used to carry the scan inline, each a copy, and the copies
    drifted from the artifact list. One tool, called six times, cannot."""
    doc = load("release.yml")
    scans = [s["run"].strip() for job in doc["jobs"].values() for s in run_steps(job)
             if s.get("name") == SCAN_STEP]
    assert len(scans) == 6, scans
    for run in scans:
        assert run == f"python3 {SCAN_TOOL} build", run


def test_the_scanner_looks_for_the_key_keystore_actually_compiles_in():
    keystore = dev_key_from_keystore()
    cmake = dev_key_from_cmake()
    assert keystore == cmake, "core/keystore.c and cmake/ProductionKey.cmake disagree on the development key"
    assert scan_tool().DEV_KEY.hex() == keystore, (
        "the scanner does not name the development key core/keystore.c compiles in")


def collected_suffixes(doc):
    """Every `-name \"*.ext\"` glob in every Collect artifacts step."""
    found = set()
    for job in doc["jobs"].values():
        for s in run_steps(job):
            if s.get("name") == "Collect artifacts":
                found |= set(re.findall(r'-name "\*(\.[a-z0-9]+)"', s["run"]))
    return found


def test_the_scanner_covers_every_suffix_the_workflow_ships():
    """The scan list and the artifact list were maintained by hand beside each
    other and disagreed: the scan read .elf .bin .a .o while Collect shipped
    .hex .uf2 .efi too. This pins the one against the other."""
    shipped = collected_suffixes(load("release.yml"))
    assert shipped >= {".elf", ".bin", ".a", ".hex", ".uf2", ".efi"}, shipped
    missing = shipped - scan_tool().SUFFIXES
    assert not missing, f"release.yml ships {sorted(missing)} but the scanner never opens them"


def _intel_hex(data, base=0x08000000):
    def rec(t, addr, payload):
        body = bytes([len(payload), (addr >> 8) & 0xFF, addr & 0xFF, t]) + payload
        return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()
    lines = [rec(0x04, 0, (base >> 16).to_bytes(2, "big"))]
    lines += [rec(0x00, (base & 0xFFFF) + off, data[off:off + 16]) for off in range(0, len(data), 16)]
    return "\n".join(lines + [rec(0x01, 0, b"")]) + "\n"


def _uf2(data, base=0x2000):
    import struct
    blocks = [data[i:i + 256] for i in range(0, len(data), 256)]
    return b"".join(
        struct.pack("<IIIIIIII", 0x0A324655, 0x9E5D5157, 0, base + n * 256, len(blk), n, len(blocks), 0)
        + blk.ljust(476, b"\0") + struct.pack("<I", 0x0AB16F30)
        for n, blk in enumerate(blocks))


def test_the_scanner_decodes_hex_and_uf2_rather_than_grepping_them(tmp_path):
    """Intel HEX is ASCII and UF2 is blocked with headers, so the key's raw
    bytes never appear in either file even when the key is in the image. A
    scan that opened them and grepped would report clean; that is worse than
    not opening them. The key is placed so it straddles both a 16-byte HEX
    record and a 256-byte UF2 block, which is the case a per-record search
    would also miss."""
    tool = scan_tool()
    image = bytes(range(245)) + tool.DEV_KEY + bytes(50)
    off = image.index(tool.DEV_KEY)
    assert off % 16 != 0 and off // 256 != (off + 31) // 256
    build = tmp_path / "build"; build.mkdir()
    (build / "fw.hex").write_text(_intel_hex(image))
    (build / "fw.uf2").write_bytes(_uf2(image))
    (build / "clean.elf").write_bytes(bytes(range(256)) * 4)
    # the premise: a raw search finds nothing in either encoded file
    assert tool.DEV_KEY not in (build / "fw.hex").read_bytes()
    assert tool.DEV_KEY not in (build / "fw.uf2").read_bytes()
    hits, undecodable = tool.scan([build])
    assert undecodable == []
    assert sorted(Path(h).name for h in hits) == ["fw.hex", "fw.uf2"], hits


def test_a_truncated_hex_record_is_reported_not_raised(tmp_path):
    """`:00` is a record with a byte count and nothing else. Indexing it before
    checking its length escaped as an IndexError traceback -- still exit 1, so
    it failed closed, but by accident: the operator lost the file-annotated
    "could not be decoded" line the tool promises. Now a ValueError, caught,
    reported against the file."""
    tool = scan_tool()
    build = tmp_path / "build"; build.mkdir()
    (build / "short.hex").write_text(":00\n")
    hits, undecodable = tool.scan([build])          # must not raise
    assert hits == []
    assert len(undecodable) == 1 and undecodable[0][0].endswith("short.hex")
    assert "truncated" in undecodable[0][1]


def test_cross_target_object_files_are_scanned(tmp_path):
    """CMake names objects .obj under CMAKE_SYSTEM_NAME=Generic -- every cross
    target. The .o entry existed to scan object files, which is where the key
    actually lives after keystore.c compiles, and on those builds it matched
    nothing. The proof step in build.yml learned this first; the scanner
    had not."""
    tool = scan_tool()
    assert ".obj" in tool.SUFFIXES and ".o" in tool.SUFFIXES
    build = tmp_path / "build"; build.mkdir()
    (build / "keystore.c.obj").write_bytes(bytes(32) + tool.DEV_KEY)
    (build / "keystore.c.o").write_bytes(bytes(32) + tool.DEV_KEY)
    hits, undecodable = tool.scan([build])
    assert undecodable == []
    assert sorted(Path(h).name for h in hits) == ["keystore.c.o", "keystore.c.obj"], hits


def test_suffix_match_is_case_insensitive(tmp_path):
    """A .BIN is the same artifact as a .bin. Skipping it on case would report
    it clean without reading it, which is the one thing this scan must not do."""
    tool = scan_tool()
    build = tmp_path / "build"; build.mkdir()
    (build / "FW.BIN").write_bytes(bytes(64) + tool.DEV_KEY)
    (build / "FW.HEX").write_text(_intel_hex(bytes(64) + tool.DEV_KEY))
    hits, undecodable = tool.scan([build])
    assert undecodable == []
    assert sorted(Path(h).name for h in hits) == ["FW.BIN", "FW.HEX"], hits


def test_the_scanner_passes_a_clean_tree_and_fails_an_unreadable_file(tmp_path):
    tool = scan_tool()
    build = tmp_path / "build"; build.mkdir()
    (build / "clean.bin").write_bytes(bytes(range(256)) * 8)
    assert tool.scan([build]) == ([], [])
    # a .hex the scanner cannot decode is a file it did not check: that is
    # a failure, not a quiet gap in coverage
    (build / "odd.hex").write_text(":garbage\n")
    hits, undecodable = tool.scan([build])
    assert hits == [] and len(undecodable) == 1




def unguarded_release_board_configures(doc):
    """Every `cmake -B` configure in `doc` that is a Release build of a real
    board and passes neither a production key nor the explicit opt-out.
    Such a configure fails under CMakeLists.txt's gate, and a CI job that
    hits the gate is a job that has stopped testing the tree."""
    found = []
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return found
    for job_id, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue
        for step in run_steps(job):
            for block in configure_lines(step["run"]):
                if board_of(block) in (None, "none") or not is_release_shaped(block):
                    continue
                if ("-DEBLDR_PRODUCTION_KEY=" in block
                        or "-DEBLDR_ALLOW_DEV_KEY=ON" in block):
                    continue
                found.append((job_id, board_of(block), block))
    return found


def test_no_ci_workflow_cross_compiles_a_release_board_without_saying_so():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job_id, board, block in unguarded_release_board_configures(doc):
            raise AssertionError(
                f"{path.name} job {job_id!r}: a Release build of {board} with "
                f"no key and no opt-out cannot configure:\n{block}")


def test_the_guard_flags_exactly_the_unguarded_release_board_configure():
    """The check above, driven with a synthetic workflow so its every branch
    runs on a green tree: the one job that is Release + real board with
    neither flag is reported, and nothing else is."""
    doc = yaml.safe_load("""
jobs:
  bad:
    steps:
      - run: |
          cmake -B build -DEBLDR_BOARD=stm32f4 -DCMAKE_BUILD_TYPE=Release
          cmake --build build
  keyed:
    steps:
      - run: cmake -B build -DEBLDR_BOARD=stm32f4 -DEBLDR_PRODUCTION_KEY="x" -DCMAKE_BUILD_TYPE=Release
  opted-out:
    steps:
      - run: |
          cmake -B build -DEBLDR_BOARD=stm32f4 \\
            -DCMAKE_BUILD_TYPE=$BUILD_TYPE \\
            -DEBLDR_ALLOW_DEV_KEY=ON
  debug:
    steps:
      - run: cmake -B build -DEBLDR_BOARD=stm32f4 -DCMAKE_BUILD_TYPE=Debug
  host:
    steps:
      - run: cmake -B build -DEBLDR_BOARD=none -DCMAKE_BUILD_TYPE=Release
  no-board:
    steps:
      - run: cmake -B build -DCMAKE_BUILD_TYPE=Release
  not-a-job: 42
""")
    flagged = unguarded_release_board_configures(doc)
    assert [(job, board) for job, board, _ in flagged] == [("bad", "stm32f4")]

    # Documents without a jobs mapping are not workflows and are ignored.
    assert unguarded_release_board_configures(None) == []
    assert unguarded_release_board_configures({"name": "x"}) == []
    assert unguarded_release_board_configures({"jobs": "not a mapping"}) == []
