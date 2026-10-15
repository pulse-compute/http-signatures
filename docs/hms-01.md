# HMS-01 — protocol contract and security profile

**Status:** contract and example fixtures ready for review; runtime realization
remains HMS-02–05 work. Owner: `http-signatures` protocol package. No host,
compiler, lowerer, ABI, release or publication changes.

## Receipt

- Specification: Library `Pulse-HTTP-Signatures-RFC9421-Workstream-Spec-2026-10-15(2).md`, HMS-01.
- PR base: merged HMS-00 `main`, `42c6e0e669e31773dc7eabbf7c73e6576cc7b6e8`.
- Base tree: `127c12c8e4225aa0be48d8b6e646f9425d08d5ba`; matches local baseline.
- Branch: `hms-01/protocol-contract`, targeting `main` with human merge.
- Final head SHA and PR URL are recorded in the PR description after creation.
- Protocol source and original test suite are unchanged from HMS-00.

## Acceptance map

| HMS-01 requirement | Deliverable |
|---|---|
| Request/response, ordered raw-ish fields, original target, associated request | `docs/contract/types.ts` and `protocol.md` |
| Component descriptor model, ordered parameters, equality and context | `protocol.md` |
| Explicit sign/verify capabilities and deterministic result/error taxonomy | `types.ts`, phase table in `protocol.md` |
| Coverage, algorithm/key trust, created/expires/skew, context, nonce policy | `security.md` |
| Secret, target, payload, time trust boundaries and threat model | `security.md`, snapshot contract in `protocol.md` |
| Supported / unsupported / unavailable distinction | `capabilities.md`, separate execution qualification table |
| Request and response profile examples | `examples/profiles/request.json`, `response.json` |
| Provisional measured limits and explicit measurement gaps | `limits.md`, `docs/evidence/hms-01-limits.json`, measurement script |
| No ambient lookup/fallback, fail-closed required components | Contract rules; explicitly not yet enforced by recovered spike |

## Validation

Node v24.19.0 / npm 11.9.0, Linux:

- `npm run check:contract`: type-only TS syntax accepted by Node type stripping;
  both JSON design profiles pass focused authoring checks for mandatory policy,
  coverage and resource limits. This is not full TypeScript type checking or a
  runtime profile validator. No TypeScript dependency was added.
- `npm run check`: existing syntax, package-name import, export and private guard
  pass. No package export was added.
- `npm test`: all six recovered tests pass (128.82 ms in the implementation run).
  Exact RFC 9421 B.2.5 evidence is retained; no new RFC conformance vector claimed.
- `node scripts/measure-reference-limits.mjs`: 21 boundary observations asserted;
  repeated output byte-matches the checked-in JSON on the pinned Node version.
- CI runs those checks on a fresh checkout. Remote result is recorded in the PR.

Measurement limits: these are acceptance/rejection probes of the old spike,
not latency, memory, hostile-work or v1 enforcement qualification. There are no
new runtime sign/verify methods. The example profiles intentionally require
unsupported capabilities and must not be passed to the old API as if enforced.

## Files and follow-up

Added: `docs/contract/{README.md,types.ts,protocol.md,security.md,limits.md,capabilities.md}`,
`docs/evidence/hms-01-limits.json`, `docs/hms-01.md`,
`examples/profiles/{request.json,response.json}`,
`scripts/{check-contract.mjs,measure-reference-limits.mjs}`.
Updated: `README.md`, `CONTRIBUTING.md`, `package.json`, `.github/workflows/test.yml`.

Known check failures: none locally. Known gaps: all v1 runtime enforcement,
full Structured Fields/canonicalization, content/replay, explicit-capability
execution, target adapters and Native qualification remain open as shown in the
matrix. The existing global Web Crypto fallback remains a documented spike gap.

Next dependency: **HMS-02** (Extra High reasoning effort), bounded RFC 8941
signature-field parsing and serialization. It must implement parameter-preserving
parsing and duplicate/limit handling against this contract. HMS-03 implements
component resolution; HMS-04 the explicit profile API; HMS-05 body/replay paths.
Contract review may refine policy choices before those implementation steps.

Architecture approval: no new authority is introduced here. Human review is
required before broadening trusted lowering or changing Pulse host/compiler
contracts, after the HMS-07 investigation and before HMS-08 implementation.
