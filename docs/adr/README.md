# Architecture Decision Records

One file per decision. A record is never edited after it reaches **Accepted** — it is
superseded by a later record that names it.

| Status | Meaning |
|---|---|
| Proposed | Written, not yet ratified by the maintainers named in `deciders`. |
| Accepted | Ratified. Binding on new code. |
| Superseded | Replaced; the replacing ADR is named in the header. |

## Index

| ADR | Title | Status |
|---|---|---|
| 020 | [Install path verifies the signature before anti-rollback](ADR-020-install-path-verifies-signature-before-anti-rollback.md) | Proposed |
| 021 | [Recovery INFO stays unauthenticated and carries a capability byte; LOG does not](ADR-021-recovery-info-stays-unauthenticated.md) | Proposed |

## Note on numbering

ADR-001 through ADR-011 belong to the master-design series and are not in this
repository. The `eos` repository holds ADR-012 through ADR-019. This set starts at 020 so
that no number is reused; ADR-020 extends ADR-011, the eOTA firmware/update contract.
