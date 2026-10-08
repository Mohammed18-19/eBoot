---
adr: 21
title: Recovery INFO stays unauthenticated and carries a capability byte; LOG does not
status: Proposed
date: 2026-09-15
deciders: Architecture Council, eBoot maintainers
source: docs/threat_model.md T-404; the automated review of #131 (finding 2) and #139 (finding 4); .ai/security.md on documented weaker postures
---

# ADR-021 — Recovery INFO stays unauthenticated and carries a capability byte; LOG does not

## Context

`docs/threat_model.md` T-404 records the recovery `INFO` and `LOG` commands
as an information-disclosure surface, with the planned mitigation "Restrict
INFO/LOG to authenticated sessions (Phase 3)".

#131 makes authenticated recovery unreachable *by construction* on a board
with no entropy source: `AUTH` refuses to issue a challenge it cannot make
random. The event it logs, `EOS_LOG_AUTH_NO_ENTROPY`, is readable only over
`LOG`, which requires the authentication the missing entropy prevents. What an
integrator on such a board observed was a bare `NACK` — indistinguishable from
a wrong secret, an unreadable OTP, or an unprovisioned one — after
`0+1+2+4+8 = 15 s` of backoff across five attempts.

#139 answers that by adding one byte, `caps`, to the `INFO` response:
`RCVR_CAP_RNG` and `RCVR_CAP_OTP`, derived from the board's ops table. The
question "why does AUTH always NACK on this board?" is then answered before
the first `AUTH` is sent. That design depends on `INFO` being reachable
*before* authentication, which is exactly what T-404's planned mitigation
would remove. The two cannot both stand.

## Decision

1. **`INFO` remains unauthenticated, deliberately.** Its response is flash
   geometry (five `uint32`) and the capability byte. Every one of those
   values is something an attacker with UART access learns anyway — geometry
   from the board's public documentation or from the first `ERASE` that
   NACKs out of range, capabilities by attempting `AUTH` once. Disclosing
   them costs nothing the attacker did not already have and buys the
   integrator a diagnosis that otherwise costs 15 s and a wrong conclusion.

2. **`LOG` remains authenticated.** Boot history — which slot booted, why the
   previous boot failed, recovery entry and exit reasons — is the material
   T-404 is right to protect, and nothing in #131 or #139 needs it before
   authentication.

3. **The `INFO` response is a wire contract:** 22 bytes, packed — `ack`,
   five little-endian `uint32`, `caps` — defined in `core/recovery.c` with a
   `_Static_assert` on its size, documented in `docs/architecture.md`, and
   parsed by `tools/uart_recovery.py`, which refuses the 24-byte unpacked
   response of pre-fix firmware rather than decoding it. Adding a field means
   changing all three and the assert.

## Consequences

- T-404's mitigation narrows from "INFO/LOG" to "LOG", and its disclosure
  column records `caps`. The `INFO` half is closed by this decision rather
  than by Phase 3.
- A future field in `INFO` must pass the same test as `caps`: would an
  attacker learn it by trying anyway? If not, it belongs behind `AUTH`, or in
  `LOG`.
- The three bytes of uninitialised stack that `INFO` used to send (#140) are
  a separate defect — a leak of *unintended* data — and are fixed regardless
  of this decision.

## Note on numbering

ADR-020 is the highest number in use; this is 021. It stands alone rather
than extending ADR-020, which concerns the install path.
