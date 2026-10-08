# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""Every boot-log event the firmware emits has a name the recovery client prints.

core/recovery.c logged its authentication outcomes as bare hex -- 0x20, 0x21
and then 0x22 -- with a trailing comment for a name, while include/eos_types.h
defined EOS_LOG_* for every other event and tools/uart_recovery.py mapped
codes to names for the `log` command. The table stopped at 0x21, so the one
event that says "this device was never provisioned" printed as UNKNOWN(0x22)
on the client that exists to read it. Nothing tied the three lists together.

Three rules, all source-level, all cheap:

1. Every event passed to eos_boot_log_append() in core/, stage0/ and stage1/
   is an EOS_LOG_* name, never a literal.
2. Every EOS_LOG_* code defined in include/eos_types.h is in the client's
   BOOT_LOG_EVENT_NAMES, under the same name minus the prefix.
3. The client names no code the header does not define.
"""

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TYPES_H = REPO_ROOT / "include" / "eos_types.h"
CLIENT = REPO_ROOT / "tools" / "uart_recovery.py"
FIRMWARE_DIRS = ("core", "stage0", "stage1")


def _strip_c_comments(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


EVENT_DEFINE = re.compile(r"^\s*#define\s+EOS_LOG_([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+)\b", re.M)


def header_events(text=None):
    """{name: code} for every #define EOS_LOG_<NAME> <hex> in eos_types.h.

    The match stops at the value rather than at end of line: this header
    writes trailing comments on its defines (EOS_LOG_MAGIC has one), and a
    parser that anchors on end of line silently drops any code written that
    way -- under-collection, which no downstream rule can notice.
    """
    if text is None:
        text = TYPES_H.read_text(encoding="utf-8")
    found = EVENT_DEFINE.findall(text)
    events = {name: int(code, 16) for name, code in found if name != "MAGIC"}
    assert events, "no EOS_LOG_* event codes found in include/eos_types.h"
    return events


def client_events():
    """{code: name} from BOOT_LOG_EVENT_NAMES, read from the source without importing
    the client (it imports pyserial at module level)."""
    tree = ast.parse(CLIENT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "BOOT_LOG_EVENT_NAMES" for t in node.targets
        ):
            table = ast.literal_eval(node.value)
            assert table, "BOOT_LOG_EVENT_NAMES is empty"
            return table
    raise AssertionError("BOOT_LOG_EVENT_NAMES not found in tools/uart_recovery.py")


def firmware_append_sites():
    """[(file:line, event expression)] for every eos_boot_log_append() call."""
    sites = []
    for d in FIRMWARE_DIRS:
        for path in sorted((REPO_ROOT / d).glob("*.c")):
            text = _strip_c_comments(path.read_text(encoding="utf-8"))
            for m in re.finditer(r"\beos_boot_log_append\s*\(\s*([^,)]+?)\s*[,)]", text):
                expr = m.group(1).strip()
                if expr.startswith("uint32_t"):
                    continue  # the definition / extern declaration, not a call
                line = text.count("\n", 0, m.start()) + 1
                sites.append((f"{path.relative_to(REPO_ROOT)}:{line}", expr))
    assert sites, "no eos_boot_log_append() call sites found"
    return sites


def test_firmware_logs_events_by_name_only():
    events = header_events()
    literal = [(where, expr) for where, expr in firmware_append_sites()
               if not re.fullmatch(r"EOS_LOG_[A-Z0-9_]+", expr)]
    assert not literal, "eos_boot_log_append() called with a bare event value: %s" % literal
    unknown = [(where, expr) for where, expr in firmware_append_sites()
               if expr[len("EOS_LOG_"):] not in events]
    assert not unknown, "event names with no #define in include/eos_types.h: %s" % unknown


def test_client_names_every_event_the_header_defines():
    events = header_events()
    table = client_events()
    missing = sorted("EOS_LOG_%s = 0x%02X" % (name, code)
                     for name, code in events.items() if code not in table)
    assert not missing, "tools/uart_recovery.py BOOT_LOG_EVENT_NAMES lacks: %s" % missing
    renamed = sorted("0x%02X: header %s, client %s" % (code, name, table[code])
                     for name, code in events.items() if table.get(code) not in (None, name))
    assert not renamed, "client and header disagree on a name: %s" % renamed


def test_client_names_no_event_the_header_does_not_define():
    codes = set(header_events().values())
    extra = sorted("0x%02X: %s" % (code, name) for code, name in client_events().items()
                   if code not in codes)
    assert not extra, "tools/uart_recovery.py names codes the firmware never emits: %s" % extra


def test_the_authentication_events_are_named_and_decodable():
    events = header_events()
    assert events["AUTH_SUCCESS"] == 0x20
    assert events["AUTH_FAIL"] == 0x21
    assert events["AUTH_UNPROVISIONED"] == 0x22
    assert client_events()[0x22] == "AUTH_UNPROVISIONED"


def test_header_parser_sees_a_define_with_a_trailing_comment():
    """The failure mode of the parser is collecting fewer rows than the file
    has, which nothing downstream can detect; pin the one style this header
    already uses that an end-of-line anchor would miss."""
    sample = (
        "#define EOS_LOG_BOOT_START      0x01\n"
        "#define EOS_LOG_AUTH_NO_ENTROPY    0x23  /* board provides no rng_get */\n"
        "#define EOS_LOG_WITH_CPP_COMMENT 0x24 // trailing\n"
        "#define EOS_LOG_MAGIC       0x454C4F47  /* \"ELOG\" */\n"
    )
    events = header_events(sample)
    assert events == {"BOOT_START": 0x01, "AUTH_NO_ENTROPY": 0x23, "WITH_CPP_COMMENT": 0x24}


def test_header_parser_collects_every_event_define_in_the_real_header():
    """Cross-check the parser against a looser count of the same lines, so a
    future style the strict pattern misses shows up as a mismatch."""
    text = TYPES_H.read_text(encoding="utf-8")
    loose = [m.group(1) for m in re.finditer(r"^\s*#define\s+EOS_LOG_([A-Z0-9_]+)\b", text, re.M)
             if m.group(1) != "MAGIC"]
    assert sorted(header_events()) == sorted(loose)

