# HMS contract v1

**Implementation contract for HMS-02–05, pending human review.** This document
freezes the workstream's intended data model and semantics. It does not add a
runtime API, npm types, a host adapter, or supported-package status. Changes to
this contract must explain compatibility and update the examples and matrix.
The four existing exports remain the HMS-00 spike API.

Start with the [input and operation contract](protocol.md), then the
[security profile and threat model](security.md). The
[capability matrix](capabilities.md) separates implemented behavior from plans.
[Limits](limits.md) records measured spike boundaries and proposed enforcement.

| Artifact | Meaning |
|---|---|
| `types.ts` | Type-only model for future implementation; not a package export |
| `../../examples/profiles/request.json` | Body-bearing webhook verification profile |
| `../../examples/profiles/response.json` | Response profile bound to its associated request |
| `../evidence/hms-01-limits.json` | Reproducible observations of the unchanged spike |

Both examples require capabilities absent from the current spike. They are
configuration examples, not runnable sign/verify demonstrations. HMS-04 provides
the new API; HMS-05 provides body/replay enforcement. Never pass these profiles
to the old boolean verifier and assume they are enforced.
