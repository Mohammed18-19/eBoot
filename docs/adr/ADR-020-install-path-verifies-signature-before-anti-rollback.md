---
adr: 20
title: Install path verifies the signature before anti-rollback
status: Proposed
date: 2026-09-14
deciders: Architecture Council, eBoot maintainers
source: EmbeddedOS Master Design v2.0 §8.1 (boot order) and §15 (update flow), as cited in the architecture review of #115; ADR-011 (eOTA firmware/update contract)
---

# ADR-020 — Install path verifies the signature before anti-rollback

## Context

Two pull requests merged on 09-07 both change `eos_fw_update_finalize()` and disagree on
the order of its checks:

- #103 added an authenticated TLV anti-rollback counter: the image's security counter is
  read from its TLV area and compared against the persistent floor at install.
- #104 made the install path verify the image signature unconditionally, no longer gated
  on the header's own `sig_type`.

#103's authored commits all predate #104's merge, and #104 was written without #103's
counter check in place, so neither says which check comes first. The master design orders BOOT as Verify Manifest → Verify Image →
Check Version Policy (§8.1). Its update flow (§15) is Download → Verify → Install and
never places the anti-rollback check. The ordering the install path uses therefore
existed only in a PR body.

## Decision

In the install path (`core/fw_update.c`, `eos_fw_update_finalize()`):

1. Signature verification over the signed header prefix (`EOS_IMG_SIGNED_LEN`, the first
   92 bytes of the header) precedes anti-rollback evaluation.
2. The TLV security counter is read only after the prefix that binds it (`tlv_len`,
   `tlv_hash`) has been authenticated.
3. An image that fails signature verification is refused as `EOS_ERR_SIGNATURE` and its
   counter is never consulted.

This mirrors the boot ordering of §8.1: authenticate first, then apply version policy to
what was authenticated.

## Consequences

- A test that wants to observe the anti-rollback stage must present a genuinely signed
  image. eBoot has no Ed25519 signer in C, so `tools/gen_fw_update_test_sigs.py` signs
  the header prefixes that `tests/unit/test_fw_update.c` and
  `tests/unit/test_fw_transport.c` build and emits `tests/vectors/fw_update_test_sigs.h`;
  `tests/unit/test_fw_update_test_sigs.py` pins the committed header to the generator's
  output.
- An unsigned image cannot demonstrate a rollback regression. It is refused as
  `EOS_ERR_SIGNATURE` before its counter is compared, so a rollback test built on an
  unsigned image exercises the signature check, not the floor.

## Note on numbering

ADR-001 through ADR-011 belong to the master-design series and are not in this
repository; `eos` holds ADR-012 through ADR-019. This record is numbered 020 so that no
number is reused. It extends ADR-011, the eOTA firmware/update contract.
