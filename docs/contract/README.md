# HMS contract v1

**Implementation contract for HMS-02–05, pending human review.** This document
freezes the workstream's intended data model and semantics. It does not add a
runtime API, npm types, a host adapter, or supported-package status. Changes to
this contract must explain compatibility and update the examples and matrix.
The four existing root exports remain the HMS-00 spike API. The separately
implemented [HMS-02 fields API](../signature-fields.md) provides syntax operations
only. The [HMS-03 base API](../signature-base.md) now implements bounded message
snapshots and canonical bytes. The [HMS-04 protocol API](../protocol.md) exports
`sign` and `verify` for body-excluded, replay-none profiles; required body/replay
capabilities remain gated until HMS-05. HMS-03 adds an explicit `structuredFields` map to the design Profile
and two SF count limits. Both examples and authoring checks are updated together.

Start with the [input and operation contract](protocol.md), then the
[security profile and threat model](security.md). The
[capability matrix](capabilities.md) separates implemented behavior from plans.
[Limits](limits.md) records measured spike boundaries and proposed enforcement.

| Artifact | Meaning |
|---|---|
| `types.ts` | Type-only model for future implementation; not a package export |
| `../../examples/profiles/request.json` | Body-bearing webhook verification profile |
| `../../examples/profiles/response.json` | Response profile bound to its associated request |
| `../../examples/profiles/hmac-request.json` | Runnable HMS-04 profile via `examples/hmac.mjs` |
| `../evidence/hms-01-limits.json` | Reproducible observations of the unchanged spike |

The original request/response examples require capabilities absent from the current spike. They are
configuration examples, not runnable sign/verify demonstrations. HMS-04 implements
the explicit HMAC API; HMS-05 provides body/replay enforcement. Never pass these profiles
to the old boolean verifier and assume they are enforced.
