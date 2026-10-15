# Content integrity and replay (HMS-05)

The experimental fixed-algorithm profiles support signed-and-verified SHA-256 content
integrity and explicit replay consumption. Run `node examples/webhook.mjs` for
request and response exchanges using the original contract JSON profiles. The
example uses public fixture keys, fixed time/nonce and a bounded process-local
store; it is not a production host or storage adapter.

## Exact content bytes

For `profile.body = {mode:'required', algorithm:'sha-256'}`:

1. The profile must require the plain, unparameterized `content-digest` header.
   The selected signature must cover that exact descriptor. A request field,
   trailer, dictionary member or another label cannot supply that coverage.
2. The host supplies `body:{state:'available',bytes:Uint8Array}` containing the
   actual content. The package checks aggregate body limits, charges work and
   takes one private copy of the primary body before any callback. Associated
   request bytes count toward the limit but do not substitute for response bytes.
3. Signing verifies the existing digest before invoking the signer. Verification
   checks the digest only after successful MAC verification. One explicit
   `digest.sha256(content)` invocation must return exactly 32 Uint8Array bytes.
4. A complete fixed-size comparison checks all 32 declared digest bytes.
   Mismatch or malformed digest is `BODY_DIGEST_INVALID`; resource exhaustion is
   `LIMIT_EXCEEDED`. Missing bytes yield `COMPONENT_UNAVAILABLE`, absent required
   header yields `COMPONENT_MISSING`. Invalid backend output or exceptions yield
   `OPERATION_FAILED`. Nothing returns a partial verified receipt.

Content is opaque: no streams, fetches, buffering from unknown lengths, Unicode
conversion, JSON normalization or decompression. Empty available bytes are valid;
missing/transformed bytes are unavailable. Content-Encoding applies to the bytes
being hashed; transfer framing does not. The host must prove it captured those
bytes correctly and must continue to use the same immutable snapshot after the
operation. A receipt does not authenticate later mutations of the caller object.

`body.mode='excluded'` makes no content integrity claim, even with a signed digest
header. It does not invoke a supplied digest callback and reports `not-checked`.
The package can length-check excluded bytes without hashing them. No `bodyVerified`
or equivalent caller assertion bypasses hashing in required mode.

## Digest field grammar

The implementation follows the RFC 9530 Dictionary shape using the existing
bounded RFC 8941 reader. All dictionary values must be Byte Sequences; all
members are parsed. Exactly one `sha-256` member with 32 bytes is required.
Other algorithm members are syntactically checked but never chosen as fallback
or cryptographically verified. Duplicate algorithms or parameters, invalid SF
syntax/base64, wrong types, empty dictionaries and missing sha-256 fail closed.
Syntactically valid member parameters are ignored for hash selection; they remain
covered by the signature. As in the existing SF reader, omitted base64 padding
and nonzero pad bits decode under RFC 8941's lenient base64 rules; signing the
plain field still binds its actual canonical HTTP text.

Distinct repeated Content-Digest headers combine in occurrence order. Their
normalized combined value must fit `fieldValueBytes`; every raw instance and
aggregate message bytes are separately bounded. Header-only integrity is the
v1 profile rule. A known Content-Digest in both primary headers and trailers is
rejected; trailer-only content does not satisfy required header coverage. An
unavailable trailer block does not prevent checking a complete authoritative
header block. Legacy Digest, Repr-Digest and Want-* fields are not substitutions.

## Generate a digest explicitly

```js
import { createContentDigest } from '@pulse-compute/http-signatures/content-digest';
import { createSha256Digest } from '@pulse-compute/http-signatures/webcrypto';

const capability = createSha256Digest({ subtle: explicitSubtleCrypto });
if (!capability.ok) throw new Error(capability.code);
const result = await createContentDigest(capturedBytes, {
  digest: capability.value,
  limits: { bodyBytes: 65536 }
});
// On success, result.value is the complete "sha-256=:...:" field value.
```

The generation helper returns `{ok:true,value,workUnits}` or
`{ok:false,code,workUnits}`. It takes Uint8Array content and closed options
`{digest,limits?}`. Optional limits follow the [base capacity rules](signature-base.md); the
helper uses bodyBytes, fieldValueBytes, signatureBaseBytes and workUnits. Other
ceilings remain schema-validated but are not message/profile checks here.
Defaults permit up to 1 MiB. Its 54-byte field output and fixed serialization
work are preflighted before one hash call; the input is defensively copied.
It does not install a header, sign a message or authenticate content. The caller
installs the field into the authoritative snapshot before signing; sign validates
rather than repairs an incorrect existing digest.

`createSha256Digest({subtle})` returns a frozen Digest capability. It captures
`subtle.digest`, accepts at most 1 MiB of Uint8Array input, copies it, calls
`digest('SHA-256', bytes)` once and requires ArrayBuffer(32) output. No ambient
backend is selected. Factory failures return `CAPABILITY_UNAVAILABLE`; direct
method failures reject with fixed `OPERATION_FAILED`. Protocol/helper boundaries
convert them to redacted Result failures. Backend allocation/CPU is outside the
package work counter.

## Replay contract

For `profile.replay = {mode:'required', namespace:'application/scope'}`, both sign
and verify require a nonempty signed nonce. The host generates it with suitable
uniqueness; the package does not generate nonces. Signing never consumes replay
state and takes no replay capability. Verification requires `{consume}` and
invokes it once, only after time, context, coverage, key, MAC and required body
checks succeed:

```js
await replay.consume({
  namespace, profileId, trustDomain, keyId, nonce, retainUntilSeconds
});
```

The host store must atomically check and insert the tuple
`(namespace, profileId, trustDomain, keyId, nonce)` across concurrent requests and
all relevant instances. Key version and signature label are excluded so rotation
or relabeling cannot reopen the same nonce. Use unambiguous tuple encoding.
Namespace/profile migrations require the host to preserve protection across
overlapping acceptance windows; changing either changes the tuple.

The deadline is `min(created + maxAgeSeconds, expires if present) + clockSkewSeconds`,
computed from validated metadata with safe integer arithmetic. Retention is
inclusive: evict only when trusted time is strictly greater than the deadline.
The store must also reject attempts arriving after the deadline using its own
trusted time. This closes the gap when async verification crosses expiry after
the package's one clock sample. Define store capacity, durability, atomicity,
TTL precision, time quality and failures in the host integration contract.

Only boolean true is success; false yields `REPLAY_REJECTED`, including a
host-chosen capacity/expiry rejection. Exceptions or invalid results yield
`OPERATION_FAILED`. There is no retry, rollback or downgrade. A backend may have
consumed the nonce before throwing; the package cannot undo an ambiguous store
commit. A successful nonce remains consumed after later application rejection.
Business idempotency and authorization are separate responsibilities.

The package contains no global registry or production replay-store adapter.
`replay.mode='none'` invokes no replay capability and reports `not-checked`, even
if a nonce is signed. Success reports `bodyIntegrity:'verified'` and/or
`replay:'consumed'` only for completed required operations. Store/hashing failures
never return a success receipt.

## Evidence and limits

Tests cover concurrent duplicates (24 verifications, exactly one accepted),
inclusive expiry and skew, delayed store arrival, scope/rotation/label behavior,
invalid backend results, callback mutation, byte/work limits, CRLF/header
ambiguity, coverage downgrade, body mutation and complete envelope validation.
The [work receipt](evidence/hms-05-work.json) includes empty, 64 KiB and 1 MiB
content and exact call counts; it makes no timing, RSS or constant-time claim.
Only Node 24.19.0 is qualified as a reference runtime; Native and production
host/store qualification remain separate work.

Published vectors cover RFC 9530 B.1, B.2, B.3 and D. The original B.4 Brotli bytes
hash to a different value than its published digest. This is recorded in
[reported erratum 8890](https://www.rfc-editor.org/errata/eid8890), not a verified
erratum as of 2026-10-15. Tests reject the original bytes against that digest and
separately test the proposed two-byte correction; they never silently rewrite
content. The corrected bytes hash to the published value in both Node createHash
and explicit Web Crypto. Fixture attribution is retained alongside the vectors.
