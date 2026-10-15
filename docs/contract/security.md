# Application profiles and threat model

The application chooses a trusted profile before examining the incoming label,
keyid, algorithm or tag. The package never chooses a policy from attacker input.
Both examples are design fixtures requiring HMS-02–05 implementation.

## Mandatory policy

| Profile field | Rule |
|---|---|
| `id`, `contractVersion` | Stable local policy identity; v1 only; changing security semantics needs a new policy ID |
| `label` | Exactly one configured label; no label search or fallback |
| `context` | Exact kind, direction and host trust domain; require HTTPS and expected authority |
| `requiredComponents` | Nonempty set matched against the selected signature's full descriptors; no coverage across signatures |
| `allowedAlgorithms` | Initial v1 is exactly `['hmac-sha256']`; no negotiation from incoming alg |
| `keyPolicy` | Explicit resolver capability ID and nonempty allowlist of key IDs scoped to trust domain/profile |
| `time` | Created required; expiry requirement, maximum age/lifetime and clock skew all explicit |
| `requiredTag` | Nonempty application domain-separation tag, emitted and checked in signed parameters |
| `body` | Explicit `required` with sha-256, or `excluded` with no body-integrity claim |
| `replay` | Explicit required nonce consumption, or `none` with no replay claim |
| `limits` | Every ceiling specified; no unlimited/default-by-omission path |

Profile schema is closed: unknown fields, wrong types, duplicate set members,
empty strings, non-safe integers or inconsistent constraints fail before message
processing. Context authority is the request authority; for a response, it is
the associated request authority. Missing trusted context is unavailable. An
otherwise available but different context is `CONTEXT_MISMATCH`.

A profile must require signed target binding: `@method` plus `@target-uri` for
requests; `@status` plus request `@method;req` and `@target-uri;req` for responses.
A body-required profile must require the unparameterized message-header
`content-digest` descriptor. A request's digest cannot satisfy a response's body
policy. V1 uses the full URI; alternate decomposed target profiles require an
explicit later contract decision.

## Keys and cryptography

The sign capability and each returned verify capability bind an opaque key to
one algorithm, key ID, key version and trust domain. They hold key material in
the trusted backend; protocol inputs, errors and receipts never contain secrets.
The backend attests that HMAC keys contain at least 256 bits of suitable key
material; length alone does not prove entropy. A raw `Uint8Array` key belongs to
the old spike, not the new protocol API.

The bounded incoming keyid is an untrusted selector, never a URL, file path,
secret name or permission to retrieve any key. Check the explicit allowlist
before calling the configured resolver. The resolver can only return an already
authorized verification capability for this profile/domain. No ambient key
lookup, remote discovery, retries with alternate keys or refresh loop. A missing
or disallowed key and algorithm/key/domain mismatch all yield `KEY_REJECTED`.
Resolver exceptions yield `OPERATION_FAILED`. Key rotation is host-owned; the
resolver selects exactly one version. It cannot accept a list of keys to try.

Require signed `alg='hmac-sha256'` even though the RFC can omit alg. The original
B.2.5 vector omits alg and tag: it remains a low-level canonicalization/crypto
vector, not an accepted application-profile example. Exactly 32 signature bytes
are required. Verification uses the backend verify primitive; do not compare
recomputed MACs with ordinary JS equality. HMAC verifiers can forge messages;
this profile provides neither non-repudiation nor separation of verifier and
signer authority at the cryptographic level.

## Time and nonce rules

`Clock.nowSeconds()` returns one trusted nonnegative integer Unix timestamp per
operation. No `Date.now()` fallback, incoming Date header, or wall-clock value
from the attacker. The host is responsible for clock quality. All profile times
are nonnegative safe integers; timestamps also fit the supported Structured
Fields integer range. Reject arithmetic overflow.

For trusted time N, skew S, max age A and maximum lifetime L:

- Require `created <= N + S` and `N <= created + A + S`.
- If expires is present, require `created <= expires <= created + L` and
  `N <= expires + S`. Equality at a boundary is accepted.
- If profile requires expiry and it is absent, return `METADATA_REQUIRED`.
  Require `L <= A`; an optional expiry may shorten, never extend the age bound.
- Reject mismatched/missing tag, keyid, alg or required nonce. Empty nonce is
  invalid. Metadata values are bounded before capability calls.

Required replay protection consumes a nonce **after** MAC, time, context,
coverage and body verification. The store atomically rejects an existing tuple
`(namespace, profileId, trustDomain, keyId, nonce)` across concurrent requests.
Key version and signature label are deliberately excluded, so rotation or label
changes cannot reopen the same nonce. The namespace must isolate applications;
profile migrations must retain replay protection for overlapping acceptance
windows (the host may additionally share/dedupe across profile IDs).

Retain through `min(created + A, expires if present) + S`, inclusive. The store
must not evict at the inclusive boundary and must reject consumption after the
retention deadline using its trusted clock. Package computes this deadline from
validated metadata; the backend uses trusted time. Store unavailability or
exception never degrades to age-only acceptance. `false` means replay rejected.
A nonce consumed by a successful verify stays consumed even if later application
authorization or processing fails; durable business idempotency remains outside
this package. Signing receives the nonce explicitly from a trusted generator
and does not consume the verification store.

## Payload ownership

For `body.mode='required'`, demand signed Content-Digest, parse its sha-256
member, hash the bounded exact content bytes with the explicit digest capability,
and compare digest bytes. A signed digest string alone is insufficient. Missing
or transformed body bytes fail unavailable; known absence of Content-Digest
fails missing. Digest mismatch or malformed digest is `BODY_DIGEST_INVALID`.
No boolean `bodyVerified` input can bypass hashing. The host controls stream
consumption and supplies a bounded snapshot; no implicit buffering.

`body.mode='excluded'` yields `bodyIntegrity:'not-checked'` even if a
content-digest field happens to be signed. `replay.mode='none'` yields
`replay:'not-checked'`. These flags prevent a signature success from overstating
what was checked. Required modes with missing capabilities fail closed.

## Example profiles

[request.json](../../examples/profiles/request.json) is an inbound webhook policy:
method, URI, content-type and content-digest are covered; HMAC key ID and tag are
fixed; created/expires, 60-second age/lifetime, 5-second skew and atomic nonce
consumption are required. Payloads are bounded to 64 KiB. Keys/clock/body bytes
are injected by the receiving host. The outbound signer uses a separately
trusted copy with direction `outbound`; wire coverage, tag and trust domain stay
the same. Direction is local policy, not a signed assertion.

[response.json](../../examples/profiles/response.json) covers status, content-type,
content-digest and the associated request's method, URI and x-request-id. The
host must retain the exact originating request and validate its request ID
against its outstanding transaction. This example has no replay store and makes
no replay-protection claim: the application must prevent duplicate delivery or
choose a nonce-required variant. A response for the same URI alone is not a
unique transaction. Request cross-signing is unsupported by the current spike.

## Threats, ownership and qualification

Assume the attacker controls network fields, signatures, bodies, metadata,
ordering, repetition, timing and concurrency. They may replay or transform
messages and cause capability calls to fail. Trusted adapter/backend compromise
is outside what the protocol can detect; inconsistent inputs still fail closed.

| Threat | Required mitigation / owner | Evidence status / next ticket |
|---|---|---|
| Proxy rewrite or fabricated original URI | Host proves sources; package refuses unavailable components | No adapter qualification; HMS-03/07 |
| Field/query normalization changes signed bytes | Preserve instances/encoding; exact base fixtures | Only selected spike cases; HMS-02/03 |
| Weaker signature or unsigned required field | Fixed label; full descriptor coverage; no union/fallback | Basic spike negatives; HMS-04/05 |
| Algorithm/key confusion; key lookup SSRF | Fixed algorithm, local allowlist and bound key capabilities | Contract only; HMS-04 |
| Body tampering with valid MAC | Signed and recomputed Content-Digest over exact bytes | Unsupported; HMS-05 |
| Replay inside a valid time window | Atomic nonce store after verification | Unsupported; HMS-05 |
| Cross-service/tenant/response substitution | Profile tag, key scope, signed target and associated request binding | Contract only; HMS-04/05/07 |
| Slow or oversized malicious input | Pre-allocation bounds, work budget, one key/crypto call; host deadlines | Boundary probes only; HMS-02–05/09 |
| Mutation between checking and use | Host immutable snapshot; bounded package copies | Contract only; HMS-03/05 |
| Errors/logs expose secrets or create a key oracle | Fixed local codes; uniform external failure; no raw sensitive output | Contract only; HMS-04/05 |
| Treat valid MAC as permission or confidentiality | Application authorization; TLS; explicit result scope | Application/host responsibility |
| Hidden Native fallback or widened compiler authority | Separate go/no-go and human architectural review | HMS-07 before HMS-08 |

References for implementation review: RFC 9421 §§2, 3.2, 7–8 and RFC 9530 §2.
The profile choices above (fixed alg/tag/label, time windows, limits) are this
workstream's restrictions, not universal RFC requirements.

## HMS-04 implementation boundary

The [explicit HMAC API](../protocol.md) now enforces this profile for body excluded /
replay none. Valid body-required or replay-required configurations fail with
CAPABILITY_UNAVAILABLE until HMS-05, even when callbacks are supplied. Success
never claims body integrity or replay protection. Key allowlists contain 1–32
unique IDs; responses bind an associated request in the same trust domain.
Node Web Crypto tests establish only the reference backend behavior.
