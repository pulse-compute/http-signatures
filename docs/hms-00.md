# HMS-00 — recovery and repository bootstrap

**Status:** experimental JavaScript reference; awaiting human PR review.
**Owner:** `http-signatures` protocol package. No Pulse core, host, compiler,
release manifest, deployment, or publication changes.

## Provenance and immutable baseline

Specification: Library `Pulse-HTTP-Signatures-RFC9421-Workstream-Spec-2026-10-15(2).md`
(v1, dated 2026-10-15). Source: Library
`Pulse-HTTP-Signatures-RFC9421-Spike-2026-10-15.zip`.

- Initial `main` / PR base: `f0db6bad34a86ebe12ec71e19191829d2656d28f`.
- Unchanged import: `f6f5160a6bf0939d6804bfa04cd53d3012f7045c`.
- Import Git tree: `566f204b620864b28d302fca585490931d9871a7`.
- Retention branch: `baseline/hms-00-recovered`. Preserve this reference without
  rewriting it even if the implementation PR is squashed; identify the baseline
  by its immutable commit SHA, not merely by branch name.
- Archive SHA-256: `43b180880533d1005b1883c9eb7eee8a6a9066292439030632428c3951aaaa2c`.
- `packages/http-signatures/` moved to the repo root; all four imported files were
  byte-identical in the import commit. File SHA-256 values are in
  [recovery-manifest.json](recovery-manifest.json).
- The later bootstrap commit changes README/package metadata and adds tooling,
  license, and documentation. `src/index.js` and `test/rfc9421.test.js` remain
  byte-identical to the archive. No protocol behavior or test vectors were added.

The final head SHA and PR URL are recorded in the PR description after commit
creation, avoiding a self-referential SHA in this file.

## Verification receipt

Local runtime: Node `v24.19.0`, npm `11.9.0`, Linux. This is the sole pinned Node
qualification version in HMS-00. The original `>=22` engine claim was narrowed
without changing JavaScript behavior; no other version has been qualified here.

| Command / check | Observed result |
|---|---|
| `node --test test/rfc9421.test.js` on recovered archive | 6 passed, 0 failed; 99.51 ms total |
| `npm ci --ignore-scripts --no-audit --no-fund --offline` | Pass, no external dependencies |
| `npm run check` | Syntax checks pass; package-name ESM import resolves all four named functions; private guard passes |
| `npm test` in prepared checkout | 6 passed, 0 failed; 138.02 ms total |
| `npm pack --dry-run --json` | Only LICENSE, README, package.json, src/index.js; nothing published |

The environment reports an npm `http-proxy` configuration warning; it did not
require network access or affect these checks. CI uses a clean checkout and the
same Node pin, with a five-minute job limit and read-only permissions. The PR
records the remote CI outcome separately; local success is not a CI receipt.

## Recovered coverage

1. RFC 9421 Appendix B.2.5: exact base, `Signature-Input`, HMAC bytes, verification.
2. Altered method; absent required coverage; stale creation time; wrong key ID,
   algorithm and malformed signature failures.
3. Repeated component, missing field, unsupported selector, repeated signature
   label and repeated metadata parameter rejection.
4. Non-ASCII raw field rejection.
5. Selection of one signature from two labels; changed-query rejection.
6. Response status and empty query bases; invalid request/response use and
   unsupported signing algorithm rejection.

Only item 1 is the exact published RFC crypto vector. The remaining tests are
local positive/negative examples, not a complete RFC corpus or external interop
qualification.

## Initial capability / target status

| Surface | Status and evidence |
|---|---|
| Node JS, HMAC-SHA256 restricted profile | Experimental reference available; the six tests above pass |
| ASCII fields and selected derived components | Implemented; only the cases above are tested, not every representation |
| Other algorithms and parameterized components | Unsupported by this spike |
| Body digest calculation/validation and replay store | Unsupported; caller responsibility, no body-integrity claim |
| Required missing field | Operation fails in the recovered test; host capability availability is otherwise unqualified |
| Fastly JS | Unqualified; no host execution evidence |
| Node Native / Fastly Native | Unavailable in this repo; no lowerer or execution evidence |

## Known gaps and next dependency

No failures in the recovered six-test suite. This is not a security assessment.
Known limitations include restricted Structured Fields syntax; incomplete
canonicalization/interoperability coverage; URL-parser normalization; no replay
state or body validation; and no host authority proof. Limits are provisional
spike constants, not measured production bounds. The ambient `globalThis.crypto`
default is inherited and needs review against the explicit-capability contract.
Do not promote the package from these six tests alone.

Next: **HMS-01** (High reasoning effort) defines the message/API contract,
capability matrix, security profile and threat model. HMS-02–06 handle parser,
canonicalization, crypto/policy, hostile input, and interoperability work.
HMS-07 investigates Pulse integration before any conditional HMS-08 change.
No new architecture approval is needed for this bootstrap. Human architectural
approval remains required before compiler/host or lowerer authority changes.

## Files in this ticket

Recovered: `src/index.js`, `test/rfc9421.test.js`, `package.json`, `README.md`.
Added: `LICENSE`, `CONTRIBUTING.md`, `.nvmrc`, `.gitignore`, `package-lock.json`,
`scripts/check-package.mjs`, `.github/workflows/test.yml`, `docs/hms-00.md`,
`docs/recovery-manifest.json`.
