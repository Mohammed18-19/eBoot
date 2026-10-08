# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Stage-0 verifies a stage-1 image that exists.

On every board build with a stage-1 linker script, eboot_firmware.bin was
zero bytes: stage1/ exported eboot_main() only, the script had no ENTRY()
and kept no section, and with -nostartfiles and --gc-sections the linker
had nothing to anchor. tools/embed_stage1_hash.py took the size verbatim
and emitted stage1_expected_size = 0u with the SHA-256 of the empty string;
stage0/jump_stage1.c ran its hash loop zero times, matched nothing against
nothing, recorded IMAGE_VALID and jumped. The first link of the secure boot
chain reported success without having measured anything.

Three independent guards, each of which alone would have caught it:

1. the embed tool refuses an empty image, and one below a size floor;
2. stage-0 refuses stage1_expected_size == 0 at boot, before the loop;
3. every board's stage-1 linker script is anchored -- ENTRY, and both of
   the board's scripts keep a section some source file actually emits --
   stage1/reset_entry.c provides that section, and the stage-1 executable
   is built from it. A script that keeps a name nothing emits keeps
   nothing, and the link succeeds with an empty image and no warning.

The stm32f4 image is ~13 KiB after the fix; the cross-compile jobs in
ci.yml and build.yml exercise the real link.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "embed_stage1_hash.py"
JUMP = REPO_ROOT / "stage0" / "jump_stage1.c"
STAGE1_ENTRY = REPO_ROOT / "stage1" / "reset_entry.c"
STAGE0_ENTRY = REPO_ROOT / "stage0" / "reset_entry.c"
CMAKE = REPO_ROOT / "CMakeLists.txt"


def _run_tool(tmp_path, payload, *extra):
    src = tmp_path / "eboot_firmware.bin"
    src.write_bytes(payload)
    out = tmp_path / "stage1_hash.c"
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--input", str(src), "--output", str(out), *extra],
        capture_output=True, text=True,
    )
    return proc, out


def _strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


# ---- 1. the embed tool ------------------------------------------------------

def test_embed_tool_refuses_an_empty_image(tmp_path):
    proc, out = _run_tool(tmp_path, b"")
    assert proc.returncode == 1
    assert "empty" in proc.stderr and "no stage-1 image" in proc.stderr
    assert not out.exists(), "nothing may be generated for an image that is not there"


def test_embed_tool_refuses_an_empty_image_whatever_the_floor(tmp_path):
    proc, out = _run_tool(tmp_path, b"", "--min-size", "0")
    assert proc.returncode == 1
    assert not out.exists()


def test_embed_tool_refuses_an_image_below_the_floor(tmp_path):
    proc, out = _run_tool(tmp_path, b"\x00" * 64)   # a vector table and nothing else
    assert proc.returncode == 1
    assert "below the" in proc.stderr and "floor" in proc.stderr
    assert not out.exists()


def test_embed_tool_describes_a_real_image(tmp_path):
    import hashlib

    payload = bytes(range(256)) * 32          # 8 KiB, above the floor
    proc, out = _run_tool(tmp_path, payload)
    assert proc.returncode == 0, proc.stderr
    text = out.read_text(encoding="utf-8")
    assert f"stage1_expected_size = {len(payload)}u;" in text
    digest = hashlib.sha256(payload).digest()
    assert f"SHA-256:       {digest.hex()}" in text
    emitted = re.findall(r"0x([0-9a-f]{2})", text.split("stage1_expected_hash")[1].split("}")[0])
    assert bytes(int(h, 16) for h in emitted) == digest


def test_embed_tool_floor_is_below_a_real_stage1_and_above_a_vector_table():
    text = TOOL.read_text(encoding="utf-8")
    m = re.search(r"^DEFAULT_MIN_SIZE\s*=\s*(\d+)", text, re.M)
    assert m, "DEFAULT_MIN_SIZE not defined"
    floor = int(m.group(1))
    assert 64 < floor <= 8192, floor   # 16 vectors * 4 bytes < floor < the smallest real stage-1


# ---- 2. stage-0 at boot ----------------------------------------------------

def test_stage0_refuses_an_empty_expected_size_before_hashing():
    text = _strip_c_comments(JUMP.read_text(encoding="utf-8"))
    block = text[text.index("EBLDR_VERIFY_STAGE1"):text.index("while (off < stage1_expected_size)")]
    guard = re.search(
        r"if\s*\(\s*stage1_expected_size\s*==\s*0\s*\)\s*\{(.*?)\}", block, re.DOTALL)
    assert guard, "stage-0 does not refuse stage1_expected_size == 0 before the hash loop"
    body = guard.group(1)
    assert "EBLDR_FAIL_STAGE1_NO_IMAGE" in body
    assert "eos_recovery_enter" in body
    assert "return;" in body


def test_the_no_image_detail_code_is_named():
    types = (REPO_ROOT / "include" / "eos_types.h").read_text(encoding="utf-8")
    assert re.search(r"#define\s+EBLDR_FAIL_STAGE1_NO_IMAGE\s+0xBAD3\b", types)


# ---- 3. the link is anchored -------------------------------------------------

def _kept_sections(script):
    return set(re.findall(r"KEEP\s*\(\s*\*\s*\(\s*(\.[\w.]+)\s*\)\s*\)", script))


def _emitted_sections():
    """Every section name some C file under stage0/, stage1/ or boards/ places
    code or data in with __attribute__((section("..."))). A linker script
    that KEEPs anything else keeps nothing, and --gc-sections then discards
    the whole image without a warning -- which is how cortex_r5 has shipped
    a 0-byte stage-0 (#137)."""
    names = set()
    for d in ("stage0", "stage1", "boards"):
        for path in (REPO_ROOT / d).rglob("*.c"):
            names.update(re.findall(r'section\s*\(\s*"(\.[\w.]+)"\s*\)',
                                    path.read_text(encoding="utf-8", errors="replace")))
    assert names, "no __attribute__((section(...))) found anywhere"
    return names


def _boards_with_stage1():
    return sorted(p.parent.name for p in (REPO_ROOT / "boards").glob("*/*_stage1.ld"))


# A port whose linker scripts keep a section nothing emits, so both of its
# images link to zero bytes. Its entry shape (a direct branch to the image
# base, per board_cortex_r5.c) is a port decision; until it is made, the
# strict xfail below pins the state: the test fails the day it is fixed,
# so the mark has to come off with the fix.
KNOWN_UNANCHORED = {"cortex_r5": "#137: cortex_r5 keeps .vectors, which no source file emits"}


def _maybe_xfail(board):
    if board in KNOWN_UNANCHORED:
        return pytest.param(board, marks=pytest.mark.xfail(reason=KNOWN_UNANCHORED[board], strict=True))
    return board


def test_there_are_stage1_linker_scripts():
    assert "stm32f4" in _boards_with_stage1()


@pytest.mark.parametrize("board", [_maybe_xfail(b) for b in _boards_with_stage1()])
def test_stage1_linker_script_is_anchored_on_a_section_the_tree_emits(board):
    s1 = REPO_ROOT / "boards" / board / f"{board}_stage1.ld"
    s0 = REPO_ROOT / "boards" / board / f"{board}_stage0.ld"
    assert s0.exists(), f"{s1.name} has no stage-0 counterpart"
    emitted = _emitted_sections()
    text1 = s1.read_text(encoding="utf-8")
    assert re.search(r"^\s*ENTRY\s*\(\s*Reset_Handler\s*\)", text1, re.M), \
        f"{s1.relative_to(REPO_ROOT)} has no ENTRY(Reset_Handler)"
    for script in (s0, s1):
        kept = _kept_sections(script.read_text(encoding="utf-8"))
        assert kept, f"{script.relative_to(REPO_ROOT)} keeps no section, so nothing anchors its image"
        phantom = sorted(kept - emitted)
        assert not phantom, (
            f"{script.relative_to(REPO_ROOT)} keeps {phantom}, which no .c under stage0/, "
            f"stage1/ or boards/ emits (emitted: {sorted(emitted)}); --gc-sections will "
            f"discard the image")


def test_stage1_has_a_reset_entry_that_owns_the_vector_table():
    text = _strip_c_comments(STAGE1_ENTRY.read_text(encoding="utf-8"))
    assert re.search(r"\bvoid\s+Reset_Handler\s*\(\s*void\s*\)\s*\{", text)
    assert "eboot_main" in text[text.index("void Reset_Handler"):]
    table = re.search(r'section\s*\(\s*"\.isr_vector"\s*\)[^;]*?\{(.*?)\}\s*;', text, re.DOTALL)
    assert table, "stage1/reset_entry.c places no table in .isr_vector"
    entries = [e.strip() for e in table.group(1).split(",") if e.strip()]
    assert entries[0] == "(uint32_t)&_estack", entries[:2]
    assert entries[1] == "(uint32_t)Reset_Handler", entries[:2]
    assert len(entries) >= 16 and entries[15] == "(uint32_t)SysTick_Handler", (
        "the table must reach SysTick: board_early_init() enables its interrupt")


def test_stage0_vector_table_reaches_systick_too():
    text = _strip_c_comments(STAGE0_ENTRY.read_text(encoding="utf-8"))
    table = re.search(r'section\s*\(\s*"\.isr_vector"\s*\)[^;]*?\{(.*?)\}\s*;', text, re.DOTALL)
    assert table
    entries = [e.strip() for e in table.group(1).split(",") if e.strip()]
    assert len(entries) >= 16 and entries[15] == "(uint32_t)SysTick_Handler"


def test_stage1_executable_is_built_from_its_reset_entry():
    text = CMAKE.read_text(encoding="utf-8")
    m = re.search(r"add_executable\s*\(\s*eboot_firmware\s+([^)]*)\)", text)
    assert m, "no add_executable(eboot_firmware ...) in CMakeLists.txt"
    assert "stage1/reset_entry.c" in m.group(1).split()
