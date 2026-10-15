# HMS-06 implementation receipt

Ticket: algorithm interoperability beyond HMAC.
Repository: `pulse-compute/http-signatures`; PR target: `main`; human merge.
Base: `bee21e6fa0d07e00955fab61bcf7f6f46290be09` (merged HMS-05).
Base tree: `23c59102f07866d5fe669c89868a6ec436e2320e`.
The PR records the final head/tree/CI receipt without self-referential SHA edits.

## Implementation and ownership

- `src/algorithms.js`: explicit algorithm/signature/key-size contract table.
- `src/profile.js` / `src/protocol.js`: one locally fixed algorithm and exact
  width per profile; algorithm/width binding, serialization preflight and receipt.
- `src/webcrypto.js`: additive explicit P-256/SHA-256 and RSA PKCS#1 v1.5/SHA-256
  signer/verifier factories. Opaque private/public keys, fixed primitive options,
  strict output sizes, bounded copies and redacted failures. No crypto implementation.
- `/fields` and shared `/base` budget: explicit signature capacity up to 512;
  default 32 and every other byte/count/work ceiling remain unchanged.
- RFC public fixture keys/signatures, an independently generated frozen RSA
  reference signature, algorithm/adapter tests, two-way OpenSSL CLI gate and
  capacity/work measurements. New runnable asymmetric example, CI steps,
  export checks, contract/API updates and [support matrix](algorithms.md).

Package owns policy, exact signature-base bytes, wire formats and capability
binding. Backend owns cryptographic primitives, secure randomness, key protection
and cryptographic verification. Host owns key provisioning, snapshot authority,
time, replay-store durability, deadlines and capacity. OpenSSL CLI and DER
conversion are development-only evidence tools; no package runtime shell-out,
raw-key loader, network discovery or backend fallback is added.

No dependencies, Pulse core/compiler/ABI/provider changes, publication or
deployment. Native implementation remains separately gated. Existing HMAC
profiles, original JSON request/response examples and the root spike retain
behavior. `src/index.js` and `test/rfc9421.test.js` retain their baseline hashes.
HMS-01/02/03/05 measurement receipts reproduce byte-for-byte.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| P-256 first | RFC B.2.4 exact base and 64-byte r||s signature verified by Web Crypto, classic Node and OpenSSL CLI |
| RSA v1.5 next | Explicit SHA-256/PKCS#1 v1.5; two-way CLI/classic-Node checks and frozen deterministic RSA-2048 fixture; real RSA-3072/4096 protocol round trips |
| Explicit primitive/key policy | Curve, hash, modulus, exponent, purpose/usage, key identity/domain/algorithm/size binding; no algorithm negotiation or aliases |
| Correct signature semantics | DER rejected in production; strict raw widths; wrong key, hash, padding, malformed scalar and tamper failures; verify never re-signs |
| Strict-profile interoperability | Literal expected base/Signature-Input assembled outside production helpers; OpenSSL signs for package verify and verifies package sign |
| Body/replay composition | Both algorithms enforce captured body digest and final replay hook; valid alternate ECDSA s cannot reuse consumed nonce |
| Bounded operation | Exact envelope/work boundaries, output preflight before crypto, defensive copies, strict backend outputs and fixed failures |
| Separate algorithm assessment | Published PSS B.2.1–B.2.3 and Ed25519 B.2.6 verify through classic Node only; package profiles/adapters deliberately unsupported |
| Target honesty | Node reference evidence only; no Fastly/Native qualification or independently implemented crypto-engine claim |

Local result: **863/863 tests pass** on Node 24.19.0 / npm 11.9.0. This includes
758 existing tests (one ceiling-boundary expectation updated), 53 algorithm/
interop cases and 52 asymmetric adapter cases. All three runnable examples pass.
Syntax/export/contract checks, packaging dry run and diff checks pass. The
OpenSSL CLI gate passes on 3.0.13; Node reports OpenSSL 3.5.7. CI repeats the gate
and records its own executable version. No known failures in the new subset.

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node examples/hmac.mjs
node examples/webhook.mjs
node examples/asymmetric.mjs
npm run check:interop
node scripts/measure-reference-limits.mjs
node scripts/measure-field-work.mjs
node scripts/measure-base-work.mjs
node scripts/measure-content-work.mjs
node scripts/measure-algorithm-work.mjs
npm pack --dry-run
git diff --check
```

[Interop receipt](evidence/hms-06-interop.json) distinguishes published RFC
signatures from the CLI-generated RSA v1.5 reference over a published base.
Node Web Crypto, classic Node and the CLI share OpenSSL lineage; separate API
and build checks do not establish independent crypto implementations. Published
RFC expected bytes/signatures add external reference evidence. Test-only RFC
keys are public fixture material, with the existing RFC attribution/license.

[Work receipt](evidence/hms-06-work.json) records eight signatures at widths
64/256/384/512. The largest case contains 4,096 decoded bytes and a 5,526-byte
Signature field, requiring 392,776 envelope work units. Representative strict
P-256 sign/verify minimum budgets are 10,212/15,793; RSA-2048 11,966/34,891.
One-below fails before crypto. The unchanged 2,097,152 work ceiling admits these
cases; no peak heap/RSS, backend CPU, elapsed-time or concurrency guarantee follows.

Next: **HMS-07**, read-only Pulse integration investigation of authoritative
HTTP snapshots, opaque keys and primitive availability. Future additional
algorithms and Native realization need their own contracts, receipts and owner
approvals; the assessment probes do not enable them.
