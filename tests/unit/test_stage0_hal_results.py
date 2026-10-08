# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Every HAL read in stage-0 checks its result.

stage0/jump_stage1.c hashed stage-1 with a loop that discarded the return
value of eos_hal_flash_read(): a read that failed left the buffer holding
the previous chunk, or whatever the stack held, and that was hashed as if
it were stage-1. The mismatch that followed sent the device to recovery
with the wrong reason (0xBAD1, "hash mismatch") -- and only by luck; the
loop in core/crypto_boot.c that does the same job refuses a failed read.

stage0/ is only compiled by a cross build, so this is a source-level guard
in the style of test_stage0_reset_entry.py: every call to a HAL read or
write function in stage0/*.c must have its result examined -- assigned, or
tested in the same statement.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STAGE0 = sorted((REPO_ROOT / "stage0").glob("*.c"))

# HAL calls whose failure means the bytes are not what they claim to be.
CHECKED_CALLS = ("eos_hal_flash_read", "eos_hal_flash_write", "eos_hal_flash_erase",
                 "eos_hal_otp_read", "eos_hal_otp_write", "eos_hal_monotonic_read")


def _strip_comments(text):
    """Drop comments and preprocessor lines, so neither can supply a token
    the checks below look for (a `#ifdef` used to read as an `if`)."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return re.sub(r"(?m)^\s*#[^\n]*", " ", text)


def _statements_calling(text, name):
    """Each statement (up to its ';') that contains a call to *name*, with
    the offset where that statement ends, for the look-ahead below."""
    out = []
    for m in re.finditer(re.escape(name) + r"\s*\(", text):
        start = max(text.rfind(";", 0, m.start()), text.rfind("{", 0, m.start()),
                    text.rfind("}", 0, m.start()))
        end = text.find(";", m.end())
        out.append((text[start + 1:end].strip(), end + 1))
    return out


def _rest_of_enclosing_block(text, pos):
    """Text from *pos* to the `}` that closes the block *pos* is in."""
    depth = 0
    for i in range(pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            if depth == 0:
                return text[pos:i]
            depth -= 1
    return text[pos:]


def _result_is_examined(statement, name, block_after):
    """True when the call's value is tested, not merely received.

    Tested means one of: the call sits inside an `if`/`while` condition or
    a `return`; or it is assigned to a name that a later `if`/`while` or
    `return` in the same block reads. A bare assignment is not enough: an
    `int rd = read(...); (void)rd;` discards the result as surely as no
    assignment at all.
    """
    head = statement[:statement.index(name)]
    # Inside the condition's parentheses, not merely after an `if`: the head of
    # `if (need) read(...)` also starts with "if (", and that call's result is
    # discarded in the body. An unclosed "(" in the head is what says the call
    # sits within the condition.
    in_condition = re.match(r"(if|while)\s*\(", head) and head.count("(") > head.count(")")
    if in_condition or re.match(r"return\b", head):
        return True
    assigned = re.match(r"(?:[A-Za-z_][\w\s\*]*\s)?([A-Za-z_]\w*)\s*=\s*$", head)
    if not assigned:
        return False
    var = assigned.group(1)
    tested = re.compile(
        r"(?:\b(?:if|while)\s*\([^;{]*\b%s\b[^;{]*\))|(?:\breturn\b[^;]*\b%s\b)" % (var, var))
    return bool(tested.search(block_after))


def test_stage0_files_exist():
    assert STAGE0, "no stage0/*.c found"
    assert any(p.name == "jump_stage1.c" for p in STAGE0)


def test_every_hal_read_and_write_in_stage0_examines_its_result():
    discarded = []
    for path in STAGE0:
        text = _strip_comments(path.read_text(encoding="utf-8"))
        for name in CHECKED_CALLS:
            for stmt, end in _statements_calling(text, name):
                if not _result_is_examined(stmt, name, _rest_of_enclosing_block(text, end)):
                    discarded.append(f"{path.name}: {stmt}")
    assert not discarded, (
        "these stage-0 statements discard a HAL result, so a failed read or "
        "write is treated as data:\n  " + "\n  ".join(discarded))


def test_the_stage1_hash_loop_refuses_a_failed_read():
    """The specific regression: a failed read in the stage-1 hash loop must
    leave the loop for recovery, with a reason distinct from a bad hash."""
    text = _strip_comments((REPO_ROOT / "stage0" / "jump_stage1.c").read_text(encoding="utf-8"))
    loop = text[text.index("while (off < stage1_expected_size)"):]
    loop = loop[:loop.index("eos_sha256_final")]
    assert re.search(r"if\s*\(\s*eos_hal_flash_read\([^;]*\)\s*!=\s*EOS_OK\s*\)", loop), \
        "the stage-1 hash loop does not test eos_hal_flash_read()'s result"
    assert "eos_recovery_enter" in loop, "a failed read must enter recovery"
    assert "EBLDR_FAIL_STAGE1_READ" in loop, "a failed read must be logged with its own reason, not the hash-mismatch one"
    assert "return;" in loop, "after recovery the loop must not fall through to the jump"


def test_every_recovery_entry_in_stage0_is_followed_by_return():
    """The mismatch path had the same fall-through: eos_recovery_enter()
    with no return after it, so a hash that failed reached the IMAGE_VALID
    record and the jump, held back only by recovery never returning -- an
    invariant its `int` return type does not promise. Every entry into
    recovery inside a function that goes on to jump must be followed by a
    return, and a positive record must not sit on the failure path."""
    text = _strip_comments((REPO_ROOT / "stage0" / "jump_stage1.c").read_text(encoding="utf-8"))
    body = text[text.index("void ebldr_stage0_main"):]
    calls = [m.end() for m in re.finditer(r"eos_recovery_enter\s*\([^;]*\)\s*;", body)]
    assert calls, "no eos_recovery_enter() call found in ebldr_stage0_main"
    unreturned = []
    for end in calls:
        following = body[end:].lstrip()
        depth = body.count("{", 0, end) - body.count("}", 0, end)
        closes_function = following.startswith("}") and depth == 1
        if not (following.startswith("return") or closes_function):
            unreturned.append(body[end - 40:end + 40].strip())
    assert not unreturned, "eos_recovery_enter() falls through to what follows it:\n  " + "\n  ".join(unreturned)

    mismatch = body[body.index("if (match1 || match2)"):]
    mismatch = mismatch[:mismatch.index("}") + 1]
    assert "return;" in mismatch
    assert "EOS_LOG_IMAGE_VALID" not in mismatch
    assert "EBLDR_FAIL_STAGE1_HASH" in mismatch


def test_the_guard_rejects_an_assigned_but_untested_result(tmp_path):
    """Two bypasses the review demonstrated against the earlier guard: a
    result assigned and then cast to void, and a discarded call placed
    right after a `#ifdef` line. Neither may pass."""
    assigned = "void f(void) {\n    int rd = eos_hal_flash_read(0, 0, 0);\n    (void)rd;\n}\n"
    text = _strip_comments(assigned)
    (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
    assert not _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end))

    ifdef = "void f(void) {\n#ifdef X\n    eos_hal_flash_read(0, 0, 0);\n#endif\n}\n"
    text = _strip_comments(ifdef)
    (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
    assert not _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end))

    # A call as a one-line if/while body: the statement starts with "if ("
    # but the call is outside the condition and its result is discarded.
    for body in ("void f(int need) {\n    if (need) eos_hal_flash_read(0, 0, 0);\n}\n",
                 "void f(int n) {\n    while (n--) eos_hal_flash_read(0, 0, 0);\n}\n"):
        text = _strip_comments(body)
        (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
        assert not _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end)), stmt

    # A call deeper inside a condition is still inside it.
    nested = "void f(int ok) {\n    if (ok && eos_hal_flash_read(0, 0, 0) != EOS_OK) return;\n}\n"
    text = _strip_comments(nested)
    (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
    assert _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end))

    tested = "void f(void) {\n    int rc = eos_hal_flash_read(0, 0, 0);\n    if (rc != EOS_OK) return;\n}\n"
    text = _strip_comments(tested)
    (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
    assert _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end))

    inline = "void f(void) {\n    if (eos_hal_flash_read(0, 0, 0) != EOS_OK) return;\n}\n"
    text = _strip_comments(inline)
    (stmt, end), = _statements_calling(text, "eos_hal_flash_read")
    assert _result_is_examined(stmt, "eos_hal_flash_read", _rest_of_enclosing_block(text, end))
