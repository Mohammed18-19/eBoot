# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""A build option that reaches the compiler must be read by something.

CMakeLists.txt offered EBLDR_REQUIRE_SIGNATURES and EBLDR_RECOVERY_AUTH as
options, forwarded each as a compile definition, and the README listed both
as ON by default. No source file tested either macro, so a build with the
option OFF was byte-for-byte the build with it ON: the switch documented a
capability the tree did not have. docs/book/book.md went further and listed
four options that were never in CMakeLists.txt at all.

Two source-level rules keep that from coming back:

1. Every EBLDR_* name that CMakeLists.txt turns into a compile definition is
   referenced by a preprocessor line in at least one C or header file.
2. Every EBLDR_* name a documentation table presents as a build option is
   declared by CMakeLists.txt (option() or a CACHE set()).
"""

import re

import pytest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CMAKE = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")

SOURCE_DIRS = ("core", "hal", "include", "stage0", "stage1", "boards", "tests")
DOC_TABLES = ("README.md", "docs/book/book.md")


def _strip_cmake_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _declared_options():
    text = _strip_cmake_comments(CMAKE)
    names = set(re.findall(r"\boption\(\s*(EBLDR_[A-Z0-9_]+)", text))
    names |= set(re.findall(r"\bset\(\s*(EBLDR_[A-Z0-9_]+)\b[^)]*\bCACHE\b", text))
    return names


def _forwarded_definitions(text=None):
    """Every EBLDR_ name CMakeLists.txt forwards to the compiler, by any of the
    three ordinary spellings: add_compile_definitions(EBLDR_X),
    add_compile_definitions(EBLDR_X=1), and target_compile_definitions(<tgt>
    <scope> EBLDR_X). The first version of this matched only the first shape,
    with the closing paren required to follow the name, so the other two
    re-introduced a dead switch without the guard noticing."""
    if text is None:
        text = _strip_cmake_comments(CMAKE)
    names = set()
    for args in re.findall(r"(?:add|target)_compile_definitions\(([^)]*)\)", text):
        for tok in re.findall(r"\bEBLDR_[A-Z0-9_]+(?:=[^\s)]*)?", args):
            names.add(tok.split("=", 1)[0])
    return names


def _preprocessor_references():
    refs = set()
    for d in SOURCE_DIRS:
        for path in (REPO_ROOT / d).rglob("*"):
            if path.suffix not in (".c", ".h"):
                continue
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.lstrip().startswith("#"):
                    refs.update(re.findall(r"\bEBLDR_[A-Z0-9_]+\b", line))
    return refs


def _documented_options(rel):
    names = set()
    for line in (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines():
        if line.startswith("|"):
            first_cell = line.split("|")[1]
            names.update(re.findall(r"\bEBLDR_[A-Z0-9_]+\b", first_cell))
    return names


def test_cmake_declares_the_options_this_guard_relies_on():
    declared = _declared_options()
    assert {"EBLDR_BOARD", "EBLDR_BUILD_TESTS", "EBLDR_VERIFY_STAGE1"} <= declared, declared


def test_every_forwarded_definition_is_read_by_a_source_file():
    unread = sorted(_forwarded_definitions() - _preprocessor_references())
    assert not unread, (
        "CMakeLists.txt forwards these as compile definitions, but no C or "
        "header file under %s tests them, so the option changes nothing: %s"
        % (", ".join(SOURCE_DIRS), unread))


# The three shapes a compile definition is forwarded in. The guard once matched
# only the first; the reviewer demonstrated the other two passing it with a dead
# name in place. Each is asserted to be collected, with the =value stripped.
FORWARD_SHAPES = [
    ("add_compile_definitions(EBLDR_DEAD_A)", "EBLDR_DEAD_A"),
    ("add_compile_definitions(EBLDR_DEAD_B=1)", "EBLDR_DEAD_B"),
    ("target_compile_definitions(eboot_core PRIVATE EBLDR_DEAD_C)", "EBLDR_DEAD_C"),
    ("target_compile_definitions(eboot_core PUBLIC EBLDR_DEAD_D=0 OTHER=1)", "EBLDR_DEAD_D"),
    ("add_compile_definitions(\n    EBLDR_DEAD_E=1\n    EBLDR_DEAD_F\n)", "EBLDR_DEAD_E"),
]


@pytest.mark.parametrize("snippet, name", FORWARD_SHAPES, ids=[s[1] for s in FORWARD_SHAPES])
def test_every_way_of_forwarding_a_definition_is_seen(snippet, name):
    assert name in _forwarded_definitions(snippet)


def test_a_forwarded_definition_nothing_reads_is_caught_in_every_shape():
    """The guard is only worth having if each shape, with a name no source
    references, fails it. Run against the real tree plus one appended line,
    which is exactly how a dead switch would come back."""
    real = _strip_cmake_comments(CMAKE)
    refs = _preprocessor_references()
    for snippet, name in FORWARD_SHAPES:
        unread = _forwarded_definitions(real + "\n" + snippet) - refs
        assert name in unread, f"{snippet!r} forwarded a name nothing reads and the guard missed it"


def test_every_declared_option_is_documented():
    """test_documented_options_exist checks documented <= declared. This is the
    other direction: an option that exists and is documented nowhere is a
    switch a user cannot know about. Clean today, enumerated by the reviewer."""
    declared = _declared_options()
    documented = set()
    for rel in DOC_TABLES:
        documented |= _documented_options(rel)
    # EBLDR_BOARD is covered in README prose above the table, not the table itself.
    undocumented = sorted(declared - documented - {"EBLDR_BOARD"})
    assert not undocumented, "declared in CMakeLists.txt but in no options table: %s" % undocumented


def test_documented_options_exist():
    declared = _declared_options()
    for rel in DOC_TABLES:
        phantom = sorted(_documented_options(rel) - declared)
        assert not phantom, "%s lists build options CMakeLists.txt does not declare: %s" % (rel, phantom)


def test_no_option_offers_to_skip_verification_or_authentication():
    # These were removed because nothing read them. Re-adding one as a real
    # switch would add a way to build a bootloader that does not verify, which
    # is a design change and not a configuration.
    declared = _declared_options()
    assert "EBLDR_REQUIRE_SIGNATURES" not in declared
    assert "EBLDR_RECOVERY_AUTH" not in declared
