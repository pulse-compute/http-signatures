# HMS-04 implementation receipt

Ticket: explicit HMAC signing and verification policy.
Repository: `pulse-compute/http-signatures`; PR target: `main`; human merge.
Base: `4b5b9369929bb9d9703e233be811d060bad6aef5` (merged HMS-03).
Base tree: `ae83da6eb14a7c6ad20da94d9bee6b302a3ba021`.
The PR records the final head/tree/CI receipt without self-referential SHA edits.

## Changes and ownership

- `src/protocol.js` and `src/profile.js`: closed HMAC profile, fixed envelope
  selection, target/full-descriptor coverage, metadata/time and scoped key policy,
  one shared logical-work budget and redacted Result failures.
- `src/webcrypto.js`: optional explicit backend/key adapter, strict fixed-size
  output and boolean checks; no ambient crypto or raw-key import.
- `src/base-engine.js`: internal extraction of HMS-03's snapshot/budget/base
  engine for one owned snapshot and one budget across the protocol operation.
  `/base` keeps its API and exact recorded output/work counts.
- Protocol and adapter tests, public fixture helpers, runnable HMAC example and
  profile, API/contract/matrix documentation, package checks and CI example step.

Package owns parsing, canonicalization and profile policy. Backend owns HMAC,
key material and constant-time MAC checking. Host owns adapter authority, key
provisioning/resolver scope, trusted time and authorization. No Pulse core,
compiler, ABI, lowering or host bridge changes; no architectural approval sought
or implied. No dependencies, publication, deployment or automatic merge.

Compatibility: root `src/index.js`, its six tests, and the HMS-02 implementation
are unchanged. `/protocol` and `/webcrypto` are additive exports. Contract
refinements bound local accepted key IDs to 32 and require a response's associated
request to share its configured trust domain. Original body/replay-required
profiles remain future examples; the new example exercises implemented behavior.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Correct RFC HMAC input/output | Exact B.2.5 base, MAC and Signature field through explicit adapter; tampered base/MAC fail |
| Strict profile round trips | Request/response receipts, independently computed Node createHmac result, same sign/verify base |
| Fixed label and full coverage | No weaker-label fallback or union; complete envelope agreement; sf/key/tr/req descriptor identity |
| Key authority | Local allowlist before one scoped resolver; wrong key/ID/algorithm/domain/size/version negatives |
| Time and metadata | Mandatory created/keyid/alg/tag; nonce shape; optional/required expiry; inclusive skew/age/lifetime boundaries and overflow |
| Failure containment | Invalid crypto output, non-boolean verify, invalid clock, thrown backend details, malformed snapshots/envelopes |
| Bounded operations | Shared work-budget exact threshold/one-below tests; raw envelope size, emitted field bytes/count and adapter byte bounds |
| Async ownership | Snapshot, policy and capability metadata mutation during callbacks/awaits cannot alter checked inputs |
| Honest deferred features | Body/replay-required profiles fail before callbacks even if capabilities supplied; excluded body mutation never claims integrity |
| Runtime scope | Node 24.19.0 / npm 11.9.0 only; no Native or Fastly inference |

Local result: **609/609 tests pass**: 452 retained, 129 protocol tests, 28 adapter
tests; approximately 0.49 seconds. Known failures in the declared subset: none.

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node examples/hmac.mjs
node scripts/measure-reference-limits.mjs
node scripts/measure-base-work.mjs
npm pack --dry-run
git diff --check
```

The base work output is byte-identical to `docs/evidence/hms-03-work.json`.
Shared protocol limits cover package logical work, not backend CPU, host waits,
heap/RSS or safe concurrency. Backend/host timeout policy remains external.

Next dependency: **HMS-05, body integrity and replay enforcement**. HMS-04 only
accepts body excluded / replay none and reports both as not checked. Covering a
digest header or nonce does not implement those checks. The original B.2.5 vector
is valid for the primitive adapter but lacks this stricter profile's required
target/alg/tag; it is not relaxed into a profile round trip. Additional algorithms
and Native integration remain separately gated work.
