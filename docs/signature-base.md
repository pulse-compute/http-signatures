# Authoritative signature bases

HMS-03 adds the experimental `@pulse-compute/http-signatures/base` entry point.
It resolves the [HMS message snapshot](contract/types.ts) into **ASCII octets**
for one ordered covered-components list. It does not sign, verify, select a
signature label, enforce an application profile, or authenticate body bytes.
The four root spike exports remain unchanged.

```js
import { createSignatureBase } from '@pulse-compute/http-signatures/base';

const result = createSignatureBase(snapshot, {
  components: [
    { kind: 'derived', name: '@method', parameters: [] },
    { kind: 'field', name: 'content-digest', parameters: [
      { name: 'key', value: 'sha-256' },
    ] },
  ],
  parameters: [
    { name: 'created', value: 1618884473 },
    { name: 'keyid', value: 'example-key' },
  ],
}, { structuredFields: { 'content-digest': 'dictionary' } });
// { ok: true, value: Uint8Array, workUnits } or { ok: false, code, workUnits }
```

`snapshot` must come from a trusted adapter bound to the actual message. The
package cannot establish that authority from an object, a URL, or proxy headers.
Both sign-side descriptors and descriptors from `parseSignatureInput` use this
same primitive. Pass only `{components, parameters}` from a parsed entry, without
its `label`. The caller owns envelope selection and all verification policy.
Do not use the returned bytes as an authorization result or log sensitive bases.

## Sources and exact transformations

Every snapshot includes the common fields in `types.ts`, including explicit
availability wrappers. Available headers/trailers are complete ordered arrays
of `{name, value: Uint8Array}`. An empty array proves known absence. A missing
wrapper is malformed, not shorthand for absence. Bodies are length-checked
across the message and associated request but are neither copied nor hashed.

| Component | Authoritative source and behavior |
|---|---|
| Plain field | ASCII case-insensitive name lookup; trim outer SP/HTAB per instance, unfold valid CRLF + OWS to SP, join instances in order with comma + SP. Other internal spaces/tabs remain. |
| `;bs` | Apply the same per-instance normalization, then wrap each byte string in padded base64. Join the distinct wrappers; obs-text bytes 128–255 are preserved. |
| `;sf` | Require an explicit field schema; combine instances, parse as the declared RFC 8941 item/list/dictionary, serialize strictly. No type inference. |
| `;key="k"` | Require a dictionary schema; parse the complete dictionary, select `k`, serialize its item/inner list with parameters. Missing key is an error. `sf` may also be present. |
| `;tr` | Only the trailers block; never combine with header values. Unreceived trailers must be unavailable. |
| `;req` | Only on a response, using its explicitly retained associated request; combines with field selectors and request-derived components. |
| `@method` | `method.value`, preserving case. |
| `@target-uri` | `target.uri.value`, preserving the supplied URI spelling. No URL reconstruction. |
| `@scheme` | `target.scheme.value`, ASCII lowercase. HTTP and HTTPS only. |
| `@authority` | `target.authority.value`, lowercase host and omit an empty/default port. A nonempty port also requires the explicit scheme. |
| `@request-target` | Exact bytes of `target.original` in origin, absolute, authority/CONNECT, or asterisk/OPTIONS form. |
| `@path` | `target.path.value`; preserve percent escapes, dot segments and slashes; an empty path becomes `/`. |
| `@query` | `target.query.value`; preserve spelling/order/percent escapes. An absent query becomes `?`. |
| `@query-param` | Parse only that authoritative query as a WHATWG UTF-8 form; re-encode names/values using the form percent-encode set and `%20` for space. Select the exact encoded `name` parameter. |
| `@status` | Response integer 100–599 serialized as three digits; never valid on a request. |

For this snapshot API, `target.query` is **`''` for absent**, or a string starting
with `?` for present (including `'?'` for present-but-empty). `target.path` is the
encoded path without query. `target.uri` is an absolute HTTP(S) URI without
userinfo or fragment. It retains its own case/default port/empty path spelling;
only the separately defined components receive their RFC transformations.
`target.original.raw` excludes method, spaces and HTTP version.

All supplied target overlaps are checked lexically. Scheme/authority comparisons
allow the specified case/default-port normalization, and empty/slash paths are
equivalent for consistency checks. Query spelling, percent escapes and dot
segments must match. Raw target/URI overlaps are checked even when the separate
path/query inputs are unavailable. Inconsistent snapshots fail even when the
conflicting component is not covered. The package never round-trips through
`URL`, consults `Host`/`Forwarded`, or fills an unavailable input from another
source. Adapters must provide the explicit sources for the components they use.

An encoded query name occurring more than once cannot be selected, even when
its values match or alternate percent encodings produced the same name. The
whole `@query` remains usable, as do other unique names. Empty values/names are
retained; matching is case sensitive. Invalid UTF-8 uses the WHATWG replacement
behavior. Invalid URI percent escapes fail snapshot validation. Query parsing
uses `URLSearchParams` only for the RFC-prescribed form algorithm; it never
rewrites the raw query or imports body form fields.

Each identifier preserves component and parameter order. `@signature-params`
is appended last with exactly one LF between lines and **no final LF**. HMS-02
validates descriptors, duplicate identities, metadata and escaping. The result
is a fresh byte array, independent of input arrays.

## Structured Fields subset

`options.structuredFields` is a trusted, lowercase-name map to `item`, `list`,
or `dictionary`; default `{}`. It supplies schema knowledge, not a custom parser
or precomputed canonical value. Both peers must agree on that schema. The future
Profile now includes this map; both design examples use `{}` since their digest
coverage is plain. No profile operation is implemented by this change.

The internal parser supports RFC 8941 integers, exact decimal canonicalization,
strings/escapes, tokens, booleans, byte sequences, parameters, items, lists,
dictionaries and non-nesting inner lists within the limits below. Member and
parameter order remains intact. Missing base64 padding/nonzero pad bits are
accepted and canonicalized; excess/interior padding is rejected.

This is a security-oriented subset, not a general RFC 8941 parser API:

- Duplicate dictionary keys and parameter names are rejected instead of the
  RFC's last-wins handling. The two relevant HTTPWG cases assert this restriction.
- Multiple field instances of a declared Item are rejected. List/dictionary
  instances combine in their original order.
- RFC 9651 dates/display strings and unknown extensions are outside the grammar.
- Repeated Set-Cookie values require `bs`. Other ambiguous non-list field
  semantics remain an application responsibility; use `bs` when boundaries matter.
- Non-ASCII ordinary values require `bs`; no guessed text encoding.
- HTTP/2/3 pseudo-header request-target synthesis, non-HTTP schemes, scoped IPv6
  and IPvFuture literals are unsupported. Ordinary IPv6 literals, including
  embedded IPv4, are validated without changing their address spelling.
- Signature and Signature-Input fields cannot themselves be covered in this v1
  subset. Trailer transport, proxy trust and host adapter qualification remain
  separate work. Raw obs-fold is only appropriate for retained HTTP/1 input;
  adapters must reject it for transports where it is prohibited.

## Bounded operation and fixed failures

The frozen `signatureBaseLimits` contains the HMS-02 ceilings plus these enforced
snapshot/base limits. `options.limits` may lower known positive-integer ceilings;
it cannot raise them. This low-level API has defaults; the future Profile remains
explicit. Envelope-specific limits apply to descriptor serialization here, not
complete-envelope verification. Body length checks do not prove body integrity.

| Resource | Ceiling |
|---|---:|
| All field names + values, across headers/trailers/message/associated request | 131,072 octets |
| All field instances across those blocks | 128 |
| One field value / one name | 16,384 / 256 octets |
| Instances per case-insensitive name per block | 16 |
| Method + original target + URI + all parts, per request | 16,384 octets |
| Complete signature base | 65,536 octets |
| Supplied bodies combined, without reading their contents | 1,048,576 octets |
| SF top-level members / items within one inner list | 128 each |
| SF parameters on one item or inner list | 32 |
| Context ID / trust domain strings | 512 ASCII octets each |
| Covered components / signature parameters | 32 / 6 |
| Shared logical work, including HMS-02 serialization | 2,097,152 units |

Input lengths/counts are checked before scanning/copying each bounded object.
All blocks, including uncovered fields and associated-request data, are bounded
and validated. They are indexed once; body bytes are not scanned. Output appends
and the final byte allocation are charged before allocation. SF parsing is
iterative with at most one inner-list layer. Form parsing reserves a conservative
64 units per source byte for parsing, UTF-8 expansion, copies and indexing.
Other loops charge visits/output bytes; bounded built-in scans/copies are reserved
in advance. These deterministic counters are not a JS-engine CPU, heap, RSS or
deadline guarantee. [Measurements](evidence/hms-03-work.json) are reproducible
with `node scripts/measure-base-work.mjs`.

As with `/fields`, the composition root must supply ordinary trusted containers
and an immutable snapshot. Getters on required record fields and sparse arrays
are rejected. Hostile proxies, custom iterators, modified intrinsics and concurrently
mutated shared buffers are outside the wire-input guarantee; these belong at
the adapter isolation boundary. No package can prove object provenance.

| Code | Meaning |
|---|---|
| `PROFILE_INVALID` | Invalid options, limit or schema map |
| `LIMIT_EXCEEDED` | A byte/count/output/work ceiling was reached |
| `MALFORMED_MESSAGE` | Invalid snapshot/HTTP/SF syntax, conflicting targets, or repeated selected query name |
| `MALFORMED_SIGNATURE` | Invalid descriptors, metadata or duplicate coverage |
| `UNSUPPORTED_COMPONENT` | Unknown derived component, unavailable schema implementation, or an explicit subset exclusion |
| `CONTEXT_MISMATCH` | A component/`req` used on the wrong request/response kind |
| `COMPONENT_UNAVAILABLE` | Explicitly unavailable source/block/associated request |
| `COMPONENT_MISSING` | Name/member absent from an available complete source |
| `OPERATION_FAILED` | Unexpected operation exception, without its text |

Order is options, complete snapshot validation/indexing, complete descriptor
serialization/validation, then component resolution in covered order. Resource
checks can stop any phase. Every error is a fixed code; no input text, stack,
key information or partial base is returned. This primitive's ordering is not
the future sign/verify policy ordering; HMS-04 owns composition with that API.

## Evidence and next gate

Tests compare all six RFC Appendix B.2 bases exactly, plus §2.4 request binding
and §2.1/§2.2 selector examples. Every positive case exercises a signing model
and/or parsed Signature-Input model with the same expected bytes; all supported
request-derived components also have `req` cases. The new B.2.5 base verifies
the published HMAC using test-only Node Web Crypto. This does not add RSA,
ECDSA or Ed25519 execution support merely because their bases match.

The internal SF parser runs all 177 cases from 12 pinned HTTPWG files, with two
documented duplicate-rejection restrictions. Positive canonical results also
run through the public base API. Tests include all 256 field byte values, 500
seeded SF mutations, exact bounds, malformed targets, missing contexts and
unchanged input/independent output ownership. See [the receipt](hms-03.md).

Next: **HMS-04**, explicit signing/verifying capabilities and HMAC policy;
**HMS-05**, body/replay enforcement. No host adapter or Native target is qualified.
