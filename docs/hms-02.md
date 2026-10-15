# HMS-02 — bounded signature fields

**Status:** implementation ready for review. Owner: `http-signatures` protocol
package. This ticket implements signature-field syntax, not component resolution,
cryptographic policy, body integrity or Native execution.

## Receipt

- Base: merged HMS-01 `main`, `37339c0060bfb7a91e1cbdbc0202be05d6cc1354`.
- Base Git tree: `5a85664f51854f5c46edf5b91f6511bafd06749a`.
- Branch: `hms-02/signature-fields`, PR target `main`, human merge.
- Final head SHA and PR URL are recorded in the PR description after creation.
- Root `src/index.js` and the six original tests remain byte-identical to the
  HMS-00 archive; their behavior is not silently replaced by the new parser.

## Delivered

A dependency-free iterative parser/serializer for the declared RFC 8941 subset
needed by RFC 9421 signature envelopes, exposed explicitly as
`@pulse-compute/http-signatures/fields`.

| Acceptance | Evidence |
|---|---|
| Signature-Input inner lists and Signature byte dictionaries | Public field operations and complete envelope helper |
| Ordered components/parameters and exact canonical output | Exact RFC B.2.5 fields and signature-params; escape/OWS/boolean/integer fixtures |
| Multiple labels and fail-closed ambiguous encodings | Complete label-set match; duplicate labels/parameters/equivalent descriptors rejected |
| Illegal type/parameter combinations | Positive and negative local fixtures; unsupported derived names get a fixed code |
| Base64 validation | RFC optional padding cases; malformed data rejection; all 256 one-byte values and seeded lengths 0–32 against Node base64 |
| Independent validation | 57 adapted HTTPWG corpus cases, upstream blob hashes and license retained |
| Bounded input/output/work | Byte/count ceilings, exact budget/one-under tests and dense-envelope counter receipt |
| No runtime dependency or host access | New module imports nothing; no network, clock, key or crypto calls |
| Honest unsupported surface | `docs/signature-fields.md`, capability and limit matrix updates |

The 57 HTTPWG cases are 17 binary, 14 string and 26 selected number cases adapted
to envelope positions. Generic lists and valid decimal cases are explicitly
outside the subset; this is not blanket RFC 8941 conformance. Expected values
come from the external corpus. The extra-padding case is rejected using the
upstream `can_fail` allowance. Full selection/provenance is documented next to
the unchanged source fixtures.

## Validation

Node 24.19.0, Linux:

- `npm run check`: all source/test/script JS syntax, root exports and `/fields`
  package-name imports pass; private publication guard remains.
- `npm run check:contract`: existing HMS-01 design profile authoring checks pass.
- `npm test`: **165 passed, 0 failed** (6 recovered + 102 new local + 57 HTTPWG).
  B.2.5's expected HMAC verifies using Node Web Crypto. The local mutation test
  exercises 500 deterministic ASCII mutations with bounded results.
- `node scripts/measure-reference-limits.mjs`: all 21 old spike observations
  remain unchanged; output byte-matches HMS-01 evidence.
- `node scripts/measure-field-work.mjs`: recorded in
  `docs/evidence/hms-02-work.json`; B.2.5 envelope uses 4,228 logical units, a
  16,384-byte padded field 65,546, and 8 signatures × 32 parameterized components
  683,656, below the 2,097,152 ceiling. These are not CPU or MiB measurements.
- `npm pack --dry-run --json`: both source entry points included; test corpus and
  implementation receipts excluded; nothing published.
- Remote CI outcome is recorded separately in the PR.

## Known limitations and next owner

No known failures in the declared test surface. Signature-item parameters,
generic Structured Fields, extension metadata, larger authenticator bytes and
additional algorithms remain outside the subset. The 32-byte envelope ceiling
must change explicitly for future algorithms. Parsing a component parameter
never proves the host can resolve it. Parsing an empty/short signature or a
negative timestamp is not acceptance by an authentication policy.

Work accounting covers bounded logical operations over wire data. It does not
bound a malicious JS proxy/iterator, a compromised host, cryptographic callbacks,
wall time or total VM allocation. Serializer callers supply ordinary trusted
records and stable buffers. No source-to-Native translation is asserted.

Next: **HMS-03 — canonical component resolution and signature-base generation**
(Extra High). Reuse `serializeSignatureParameters` for exact member encoding;
retain full descriptors for duplicate/coverage checks. HMS-04 must apply explicit
policy and exact HMAC length, and HMS-05 adds content and replay validation.

No architecture approval is needed for this standalone package slice. Host,
compiler, ABI or trusted-lowering changes still require the HMS-07 gate and
explicit architectural review before HMS-08. No Pulse core or release change.

## Files

New implementation: `src/signature-fields.js`.
Tests/fixtures: `test/signature-fields.test.js`, `test/httpwg-fields.test.js`,
`test/fixtures/signature-fields.json`, `test/fixtures/httpwg/{binary.json,string.json,number.json,LICENSE.md,README.md}`.
Tooling: new `scripts/check-syntax.mjs`, `scripts/measure-field-work.mjs`; updated
`scripts/check-package.mjs`, `package.json`.
Documentation: `docs/signature-fields.md`, `docs/hms-02.md`,
`docs/evidence/hms-02-work.json`, README and contract/matrix/limit updates.
