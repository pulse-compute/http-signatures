# HMS-03 implementation receipt

Ticket: canonical HTTP components and signature-base bytes.
Repository: `pulse-compute/http-signatures`; PR target: `main`; human merge.
Base: `71053b6f309473be904927ad8f97d9621221c56f` (merged HMS-02).
Base tree: `72b0e5afeed8d7bd3d99e9146c31324984006190`.
The PR records the final head/tree/CI receipt without self-referential SHA edits.

## Implementation

- `src/signature-base.js`: separate `/base` API, complete bounded snapshot,
  indexed fields, contexts, ordered components and exact byte output.
- `src/target.js`: lossless lexical target validation/consistency, RFC derived
  values and indexed query-parameter selection.
- `src/structured-field.js` and `src/base-support.js`: bounded internal strict
  SF serialization, schema-driven selectors and byte-safe field wrapping.
- `test/signature-base.test.js`, `test/httpwg-base.test.js`, and fixtures:
  exact examples, independent corpus, adversarial input and boundary coverage.
- `scripts/measure-base-work.mjs`: deterministic work/output receipts.
- Package export checks and documentation include the explicit `/base` path.

Compatibility: root `src/index.js`, its six recovered tests, and the HMS-02
fields implementation remain unchanged. No new dependencies. The future design
Profile gains a required `structuredFields` schema map, and its Limits gains
`structuredMembers` / `structuredParameters`; example profiles and authoring
checks change together. These design types are not an exported runtime profile.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Exact signature-base bytes | RFC B.2.1–B.2.6, §2.4; no trailing LF; parsed and sign-side models agree |
| Correct cryptographic input | New B.2.5 bytes verify the independently published HMAC using Node Web Crypto |
| Ordinary and distinct repeated fields | OWS, obs-fold, empty values, order and binary wrapping, all 256 byte values |
| Structured selectors | RFC dictionary/member examples, explicit schemas, sf/key/tr/req combinations, 177 HTTPWG cases |
| Target fidelity | Original four HTTP/1 forms, case/default-port rules, percent/dot/query spelling, lexical consistency failures |
| Query ambiguity | Canonical encoded names, duplicates/aliases, empty fields, UTF-8 replacement, no body/proxy fallback |
| Request/response scope | Every request-derived component with req, status boundaries, associated headers/trailers, missing/unknown distinctions |
| Bounded hostile input | Exact byte/count/work boundaries; 500 deterministic mutations; iterative SF; field/query indexes |
| Subset honesty | Explicit unsupported forms and fixed codes in API/capability docs; no production or target-parity claim |

Local result: **452/452 tests pass** (165 retained, 109 base cases, 177 HTTPWG
cases plus one inventory assertion), approximately 0.42 seconds. All checks run
on Node 24.19.0 / npm 11.9.0. Validation commands:

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node scripts/measure-reference-limits.mjs
node scripts/measure-base-work.mjs
npm pack --dry-run
git -c core.whitespace=-blank-at-eof diff --check
```

The pinned upstream `boolean.json` retains its original trailing blank line;
the whitespace check permits that upstream formatting. Source/docs have no
whitespace errors. All nine added corpus blobs match their upstream Git hashes.

The [work receipt](evidence/hms-03-work.json) includes all six appendix bases,
a 65,536-byte output/65,537-byte rejection, the 128-field/32-component case,
form decoding expansion and a dense repeated SF selection. These counters
bound logical package work; they do not establish worst-case heap, CPU, RSS,
host deadlines or safe application concurrency. Native/host qualification is
still HMS-07–09 work.

Known failures in the declared surface: none. Exclusions include general SF
parser conformance (duplicates and capacity), RFC 9651 forms, pseudo-header
request-target synthesis, scoped/IPvFuture addresses and non-HTTP schemes.
Complete signature selection, key/time/profile policy, body verification and
replay are not implemented by the base primitive.

Next gate: HMS-04, explicit HMAC signing/verification policy. No Pulse core,
compiler/ABI/lowering, publication, deployment or automatic merge changes.
