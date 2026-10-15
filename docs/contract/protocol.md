# Message and operation contract

The types in [types.ts](types.ts) describe the future API. Structural types are
not validators or proof of trust. Every limit and semantic rule below must be
enforced at runtime when that API is implemented. The current spike does not
implement this contract. The separate [HMS-03 base primitive](../signature-base.md)
implements snapshot validation and canonicalization; the full policy operation
ordering below remains an HMS-04–05 implementation contract.

## One authoritative snapshot

A trusted adapter supplies one immutable request or response snapshot. The
package receives no server socket or privileged HTTP SDK. The adapter binds all
fields, target parts, body bytes and associated request to that same message.
It must prevent mutation through the entire async operation; the package must
validate lengths before taking bounded defensive copies. Readonly types alone
do not prevent byte-array mutation.

| Input | Required meaning |
|---|---|
| `contextId` | Host-local opaque correlation ID; never a network assertion or authorization identity |
| `direction`, `trustDomain` | Trusted adapter configuration, not request headers |
| `headers`, `trailers` | Separate ordered field instances, preserving repeated names and value bytes; no lossy dictionary or pre-joining |
| `Field.name` | Valid HTTP field-name token; normalize ASCII case only; reject pseudo-fields here |
| `Field.value` | Exact exposed field-value bytes, excluding field-line framing; retained HTTP/1 obs-fold is unfolded, other CR/LF rejected. Ordinary components require ASCII; `bs` preserves obs-text octets. |
| Request `method` | Case-sensitive authoritative method token; no automatic uppercasing |
| Request `target.original` | Original request-target form and bytes, or explicit unavailability; HTTP/2/3 adapters document the exact pseudo-header representation |
| Target URI and parts | Authoritative RFC component source values, including original percent encoding and query ordering; never reparsed through a normalizing URL API to manufacture lost values |
| Response `status` | Authoritative integer status; validity checked against HTTP and RFC component rules |
| `associatedRequest` | Host-bound request for this response; absent retention is unavailable, not permission to use a caller-provided URL |
| `body.bytes` | Exact HTTP message content bytes for Content-Digest; no text conversion, JSON reserialization, decompression or transfer framing |

An available empty field array proves there are no such fields. A name absent
from an available complete block is `COMPONENT_MISSING`; an inaccessible or
lossily transformed block is `COMPONENT_UNAVAILABLE`. An empty body is an
available zero-length array, never an omitted body. Trailers not yet received
are unavailable. The package must not consume streams, buffer an unbounded
body, or reinterpret absence as emptiness.

The host may derive a component only where its transport inputs support the
RFC operation without guessing. It documents that derivation and its tests.
The package checks consistency wherever available target values overlap (URI
scheme/authority/path/query, original target form); inconsistent snapshots fail
`MALFORMED_MESSAGE`. Lack of raw target visibility alone does not forbid a
component proven independently by an adapter. A normalizing Fetch API is not
automatically sufficient. Forwarded headers never establish original authority
without an explicit trusted proxy contract outside this package.

The package can inspect bytes, syntax, coverage and internal consistency. It
cannot prove who created a plain object or that a key/clock/context is trusted.
The application composition root owns adapter installation. A caller-set
`state: 'available'` or `trustDomain` does not turn untrusted input into authority.
A future Pulse boundary must enforce this separately; these types grant no
Native capability.

HMS-03 representation refinement: `target.query` is empty for absent or begins
with `?` for present, while `target.path` excludes the query. The URI spelling is
preserved; separate scheme/authority/path components apply their defined RFC
normalizations. Components require their explicit source; no unavailable part
is reconstructed from another source. See the base API for target-form limits.

## Covered component descriptors

Components are ordered discriminated records, not strings containing `;req` or
other embedded syntax. Field names are lowercase tokens. Derived names are the
explicit union in `types.ts`. Parameters are ordered typed name/value pairs.
Duplicate parameter names are malformed. Unknown names/types and unsupported
combinations fail; never strip a parameter to make a descriptor work.

| Form | Model / constraint |
|---|---|
| Ordinary field | `{kind:'field', name:'content-digest', parameters:[]}` |
| Request field of a response | Field plus `{name:'req', value:true}`; associated request required |
| Structured field | `sf=true`; field schema must be known; no inference from arbitrary strings |
| Dictionary member | `key='member'`; dictionary schema required; may accompany `sf=true` |
| Binary wrapper | `bs=true`; cannot combine with `sf` or `key` |
| Trailer | `tr=true`; use the separate trailers block; combined `req` means request trailers |
| Query parameter | Derived `@query-param` with exactly one `name` string; decoding rules belong to HMS-03 |
| Response status | Derived `@status`; response context only, never `req` |
| Request-derived value | Method/URI/parts on request; response requires `req=true` and retained request |

The Profile's `structuredFields` map supplies the application-known RFC 8941
type (`item`, `list`, `dictionary`) for `sf`/`key`; an empty map enables neither.
This is schema data, not a hook for replacing canonicalization. Both peers must
use the same schema. The bounded parser rejects duplicate keys/parameters.

`name` is only valid for `@query-param`. `sf`, `key`, `bs`, `tr` are field-only.
`req` is valid only in a response, on a request-applicable component. Modeling
these forms reserves their representation; it does not enable them. The matrix
specifies actual supported forms.

Coverage and duplicate detection compare the component name and full parameter
name/value set, independent of parameter order. Wire serialization preserves
received parameter order and covered-component order. A plain field cannot
satisfy the same field with `req`, `tr` or `key`. Required coverage is a subset
of the one selected signature, never a union across labels. Equal descriptors
cannot appear twice. The package appends `@signature-params` last; callers may
not include it. Signing `signature` or `signature-input` fields is outside v1.

## Explicit operations

`Protocol.sign(message, options)` and `Protocol.verify(message, options)` are
reserved **design names**, not new exports. There is no implicit crypto, clock,
key resolver, profile, signature label, algorithm or backend fallback.

Signing receives ordered `covered` and ordered `parameters` plus one bound
signer. Parameters must include created, keyid, alg, tag and any profile-required
expires/nonce. Their order is preserved. `keyid`/`alg` must match the signer and
profile; the package does not silently rewrite parameters. The supplied clock
validates the signing window. If body integrity is required, the package checks
existing Content-Digest against supplied bytes before signing; it does not
silently replace a digest or mutate the message. A digest-generation helper is
HMS-05 work.

Capability results are bounded and checked before use: HMAC signatures and
sha-256 digests must be exactly 32 bytes, verify/consume results must be booleans,
and the clock must return a valid timestamp. Invalid backend results yield
`OPERATION_FAILED`; they never trigger another implementation or a retry.

Successful signing returns two complete field values for the selected label.
V1 requires the snapshot to contain no existing Signature/Signature-Input
fields for signing; otherwise `MALFORMED_MESSAGE`. This prevents silent loss of
other signatures. Multi-signature append requires a later explicit API. The
host installs the returned pair once and transmits the exact signed snapshot.

Verification extracts both envelope fields from the same message's header
block. There is no independently injectable envelope argument. It selects only
`profile.label`, with no attempt to find a weaker passing label. Other labels
may be parsed within bounds, but never trigger key lookup or crypto. Duplicate
labels, malformed dictionaries or ambiguous field combination fail. No
application side effects may precede a successful result.

Success reports the checked context, profile, key identity/version and explicit
body/replay outcomes. It contains no raw fields, body, signature base, key bytes
or capabilities. It is not an authorization grant. A caller must not reuse a
result for another message or trust unsigned data because some fields passed.

## Deterministic failures and order

Return `Result<T>`; expected invalid input and capability failures do not escape
as exceptions. Capability exceptions become `OPERATION_FAILED` with no exception
text. Process these phases in order, and stop at the first failure. In a phase,
use documented schema field order, then wire order. A programming fault outside
the operation boundary is not silently reinterpreted as a valid signature.

| Phase | Failure codes, in precedence order |
|---|---|
| 1. Validate trusted profile and required capability shapes | `PROFILE_INVALID`, `CAPABILITY_UNAVAILABLE` |
| 2. Bound snapshot, fields and envelope before copying/parsing | `LIMIT_EXCEEDED`, `MALFORMED_MESSAGE` |
| 3. Parse complete envelope and select fixed label (verify only) | `MALFORMED_SIGNATURE`, `SIGNATURE_NOT_FOUND` |
| 4. Validate supported algorithm/components, context and coverage | `UNSUPPORTED_ALGORITHM`, `UNSUPPORTED_COMPONENT`, `CONTEXT_MISMATCH`, `COVERAGE_REQUIRED` |
| 5. Validate required metadata and one trusted time sample | `METADATA_REQUIRED`, `TIME_INVALID` |
| 6. Resolve components in covered order, build bounded base | `COMPONENT_UNAVAILABLE`, `COMPONENT_MISSING`, `LIMIT_EXCEEDED`, `MALFORMED_MESSAGE` |
| 7. Resolve one approved key and perform one crypto operation | `KEY_REJECTED`, `CAPABILITY_UNAVAILABLE`, `SIGNATURE_INVALID` |
| 8. Verify required body digest (before crypto on signing) | `COMPONENT_UNAVAILABLE`, `COMPONENT_MISSING`, `BODY_DIGEST_INVALID` |
| 9. Atomically consume required nonce (verification only) | `CAPABILITY_UNAVAILABLE`, `REPLAY_REJECTED` |

Resource checks run before every allocation/work step, so `LIMIT_EXCEEDED` may
also terminate later phases. Capability exceptions always become
`OPERATION_FAILED` in their phase. Unsupported means package implementation
absent; unavailable means the operation's trusted host/backend cannot provide a
supported input or primitive. Known absence and unavailability must not be
collapsed internally.

Signing follows phases 1–2, 4–6, 8, then 7; it neither resolves a verifier key
nor consumes replay state. Its required capabilities are signer, clock and
digest when body integrity is required. Verification requires the configured
resolver, clock, and mode-dependent digest/replay capabilities.

Return only fixed failure codes, never interpolated attacker strings. These
codes are local diagnostics: applications map every external authentication
failure to a uniform response. Do not expose key existence, parser position,
signature material or backend error details. This ordering is deterministic for
a fixed snapshot/profile/capability outcome; it makes no constant-time claim.

## Compatibility boundary

HMS-00 takes `url`, JS header objects, raw key bytes, explicit time integers and
returns booleans or throws. It also defaults to global Web Crypto. None of these
are the v1 capability contract. Preserve it as reference evidence while HMS-02–05
build and test the new contract explicitly. Do not retrofit a permissive adapter
that labels arbitrary arguments as authoritative. Changing package exports or
retiring the spike API requires an explicit implementation PR and tests.
