# Explicit HMAC operations (HMS-04)

Experimental Node 24.19.0 reference API. Import `sign` and `verify` from
`@pulse-compute/http-signatures/protocol`. Both are async and return exactly
`{ok:true,value}` or `{ok:false,code}`. There is no ambient clock, crypto, key
lookup, label selection or algorithm fallback. The four root spike exports
remain unchanged and have different, weaker semantics.

Run `node examples/hmac.mjs` for a complete explicit composition using the
[HMAC request profile](../examples/profiles/hmac-request.json). The key is public
fixture material. Hosts own trusted snapshot capture, key provisioning, trusted
time, transport and authorization; plain JS records cannot establish provenance.

## Calls and results

```js
const signed = await sign(message, {
  profile, covered, parameters, capabilities: { signer, clock }
});
const verified = await verify(message, {
  profile, capabilities: { keys, clock }
});
```

The [contract types](contract/types.ts) define the records; they are not an
exported declaration bundle. Inputs are closed records: unknown members fail.
The [base API](signature-base.md) defines authoritative snapshots, descriptor
support and exact byte construction. Profile limits are all required, positive
safe integers no larger than `signatureBaseLimits`; `signatureBytes` is exactly
32. A single logical work budget covers policy, envelope parsing, base building
and serialization. Crypto/host work and elapsed time are outside that counter.

Signing validates caller-ordered components and metadata, then returns
`{signatureInput, signature}` strings for one label. It does not mutate the
snapshot. Existing primary Signature/Signature-Input fields prevent signing;
append is unsupported. Both generated fields must fit the configured per-field,
aggregate byte and field-count limits, including fields in the snapshot.

Verification extracts the complete envelope from the same snapshot's headers,
validates all labels and their agreement, and selects exactly `profile.label`.
It never combines coverage or tries another label. Known envelope fields in
trailers are rejected. Combined raw header lengths (including joining overhead)
are bounded before parsing, so whitespace cannot evade the envelope limit.
Successful verification returns contextId, profileId, label, keyId, keyVersion,
algorithm, copied covered descriptors, and explicit body/replay outcomes.

## Enforced profile

- Only `hmac-sha256`, with a 32-byte signature and a key capability attesting at
  least 256 key bits. The backend owns the actual key and constant-time MAC
  comparison; JS identity checks cannot validate backend honesty.
- One fixed label, nonempty profile/tag/resolver/domain identities, and 1–32
  distinct locally accepted key IDs. Metadata strings follow the configured
  bounds. The local allowlist is checked before any resolver invocation.
- HTTPS context with expected kind, direction, trust domain and authority.
  Configured authority receives the same RFC normalization as message authority.
  Responses require an associated request in the same trust domain.
- Requests require `@method` and `@target-uri`; responses require `@status`,
  `@method;req`, and `@target-uri;req`. Additional coverage compares full
  descriptors including parameter values, independent of parameter order.
- `created`, `keyid`, `alg`, `tag` are mandatory. Tag must equal requiredTag.
  Optional nonce must be nonempty; it does not establish replay protection.
  `expires` is mandatory when the profile requires it.
- One synchronous clock sample must be a nonnegative safe integer within the
  RFC structured integer range. With now N, created C, expiry E, skew S, age A
  and lifetime L: C <= N+S; N <= C+A+S; when E exists, C <= E <= C+L and
  N <= E+S. Boundaries are inclusive; unsafe arithmetic fails. L <= A.

HMS-04 implements **body excluded / replay none** only. Valid profiles requiring
body integrity or replay return `CAPABILITY_UNAVAILABLE` before callbacks, even
if a digest/replay capability is supplied. HMS-05 owns those operations. Success
always reports `bodyIntegrity:'not-checked'` and `replay:'not-checked'`. Covering a
Content-Digest field alone never verifies body bytes. The original webhook and
response design profiles require HMS-05 and cannot yet run.

## Capability behavior and failures

Validate profile/capability shapes, bound and own the snapshot, parse/select the
envelope, check supported components/context/coverage, check metadata/time,
build the base, bind one key, and perform one crypto operation. Sign-side field
serialization and output capacity are preflighted before crypto. Required target
availability can fail during context checks; signer identity can fail during
initial capability validation. Limits can terminate any phase. Body/replay
phases of the full contract remain gated as described above.

Successful sign invokes clock once and signer once. Successful verify invokes
clock once, the configured resolver once with `{keyId,algorithm,trustDomain,
profileId}`, and its returned verifier once. Null resolver output is rejected.
Key ID, algorithm and trust domain must match; keyVersion is nonempty. No retry,
network key discovery or alternate backend is built in. Values used after a
callback or await are owned/captured first; the host must still supply a stable
snapshot during synchronous validation. Getters/proxies are not a trusted
adapter interface.

| Outcome | Fixed code |
|---|---|
| Invalid trusted configuration | PROFILE_INVALID (capacity violations may be LIMIT_EXCEEDED) |
| Absent complete envelope or selected label | SIGNATURE_NOT_FOUND |
| Broken envelope or wrong selected MAC length | MALFORMED_SIGNATURE (oversize may hit LIMIT_EXCEEDED) |
| Unsupported algorithm / component | UNSUPPORTED_ALGORITHM / UNSUPPORTED_COMPONENT |
| Wrong context / insufficient full-descriptor coverage | CONTEXT_MISMATCH / COVERAGE_REQUIRED |
| Missing or mismatched required metadata / invalid time | METADATA_REQUIRED / TIME_INVALID |
| Missing authority / known absent component | COMPONENT_UNAVAILABLE / COMPONENT_MISSING |
| Missing required capability | CAPABILITY_UNAVAILABLE |
| Unapproved or mismatched key capability | KEY_REJECTED |
| Backend returns false | SIGNATURE_INVALID |
| Backend throws, returns wrong shape, or clock is invalid | OPERATION_FAILED |

Other snapshot failures use MALFORMED_MESSAGE; all resource failures use
LIMIT_EXCEEDED. Failures contain no raw input, base, keys, backend text or partial
success. Map local diagnostics to a uniform external authentication response.
A successful receipt is not an authorization grant or permission to trust
unsigned fields or content.

## Optional Web Crypto adapter

Import `createHmacSigner` / `createHmacVerifier` from
`@pulse-compute/http-signatures/webcrypto`. Each takes
`{subtle,key,keyId,keyVersion,trustDomain}` and returns a Result containing one
frozen bound capability. The caller imports/provisions a CryptoKey and passes
SubtleCrypto explicitly; the adapter never imports raw keys or reads global
crypto. Required key attributes are secret HMAC/SHA-256, 256–32768 bits, and the
appropriate usage. Identity strings are nonempty ASCII, at most 512 bytes.

Adapter methods defensively copy Uint8Array inputs, bound bases to 65,536 bytes,
and require 32-byte MACs. They call the supplied backend's HMAC sign/verify
method exactly once and enforce ArrayBuffer(32)/boolean results. Direct callback
failures reject with a fixed OPERATION_FAILED; protocol operations convert them
to Result failures. Backend key secrecy and trustworthy capability installation
remain host responsibilities.

The exact RFC B.2.5 bytes, MAC and Signature field pass through this adapter.
That RFC example lacks this profile's target coverage, alg and tag, so it is a
primitive interoperability fixture, not a valid strict-profile message. No
Fastly, Pulse Native or other host qualification follows from Node tests.
