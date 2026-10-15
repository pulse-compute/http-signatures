# Signature fields API — experimental HMS-02 subset

```js
import {
  parseSignatureEnvelope,
  serializeSignatureParameters,
} from '@pulse-compute/http-signatures/fields';

const parsed = parseSignatureEnvelope({
  signatureInput: 'sig1=("@method" "@target-uri");created=1618884473',
  signature: 'sig1=:AA==:', // Syntax example only, not a valid HMAC.
});
if (parsed.ok) {
  const { components, parameters } = parsed.value.inputs[0];
  const innerList = serializeSignatureParameters({ components, parameters });
  // innerList.value is the canonical @signature-params value when innerList.ok.
}
```

This entry point parses and serializes field syntax. It does not resolve HTTP
components, validate application profiles, access keys, perform crypto, select an
authentication label or grant authorization. The original four root exports
remain unchanged and do not call this parser yet. HMS-03 and HMS-04 integrate
component resolution and the explicit profile API.

## Operations and records

Every operation is synchronous and returns either
`{ok:true, value, workUnits}` or `{ok:false, code, workUnits}`. No partial parsed
value is returned on failure. Counters describe logical work, not elapsed time.
No raw input or exception text appears in diagnostics.

| Export | Input → successful value |
|---|---|
| `parseSignatureInput(fields, options?)` | Field input → ordered InputEntry array |
| `parseSignature(fields, options?)` | Field input → ordered SignatureEntry array |
| `parseSignatureEnvelope({signatureInput, signature}, options?)` | Both fields → `{inputs, signatures}` after complete label-set equality check |
| `serializeSignatureInput(entries, options?)` | InputEntry array → canonical field string |
| `serializeSignature(entries, options?)` | SignatureEntry array → canonical field string |
| `serializeSignatureParameters({components, parameters}, options?)` | One member → canonical inner-list string without label or equals sign |
| `signatureFieldLimits` | Frozen resource ceilings; no application-policy defaults |

`InputEntry = {label, components, parameters}`. Components use the HMS-01
`{kind, name, parameters}` descriptor. Every parameter is an ordered
`{name, value}` record. Signature metadata uses integer `created`/`expires` or
string `keyid`/`alg`/`nonce`/`tag`. `SignatureEntry = {label, signature}` holds a
fresh `Uint8Array` of decoded bytes. Entries, descriptors and metadata preserve
wire order. Result containers are ordinary caller-owned values, not proofs of
trusted message origin.

Field input is an ASCII string, a `Uint8Array`, or an ordered array of those field
instances. Array instances combine with `, ` after aggregate size checks; labels
must be unique across the complete field. Values must already belong to the
same HTTP field/section. The caller must not merge headers with trailers. A
missing field can be represented by `[]`; an empty dictionary parses as `[]`.
The envelope helper permits two empty dictionaries; the later verifier must
return SIGNATURE_NOT_FOUND when its configured label is absent.

Serializer models must use plain records, dense arrays and Uint8Array bytes;
unknown record fields, accessors and malformed values are rejected. JavaScript
callers must supply ordinary trusted containers: proxies, customized iterators,
concurrently mutated/shared buffers and hostile JS object behavior are outside
the wire-input threat model. This layer does not certify such objects as safe.

## Declared syntax

- Dictionaries of inner lists of component strings (`Signature-Input`) or byte
  sequences (`Signature`); multiple labels, including empty dictionaries/lists.
- RFC key syntax, ASCII strings with quote/backslash escapes, signed integers in
  the 15-digit range, boolean-true component flags, and exact parameter ordering.
- Legal dictionary OWS, inner-list SP and SP after semicolons; no HTAB inside an
  inner list or a string, no whitespace around equals, no trailing comma.
- Typed known component parameters `sf`, `key`, `bs`, `tr`, `req`, `name` with
  context-independent combination checks. Unknown derived names return
  UNSUPPORTED_COMPONENT. Message-dependent checks are HMS-03 work.
- Standard base64 byte sequences. RFC 8941 optional missing/partial padding and
  nonzero pad bits decode to the same bytes; output uses canonical padding and
  zero pad bits. Excess/interior padding, invalid lengths, whitespace, base64url
  symbols and nonalphabet characters are rejected. These permitted alternate
  spellings are normalization, not ambiguous decoded byte values.

Covered identifiers compare by name and full parameter name/value set, ignoring
parameter order for duplicate detection. Their original order is never sorted
for serialization. Dictionary labels and parameter names cannot repeat, even if
their values agree. This deliberately rejects generic RFC 8941 duplicate-key
replacement behavior, as required by this workstream's strict signature profile.

Canonical input round-trips byte-for-byte. Noncanonical accepted whitespace,
integer spellings, true-flag spelling (`;sf=?1`) and base64 padding normalize;
serialize-then-parse preserves the ordered model. Do not use raw noncanonical
substrings for @signature-params; use the canonical member serializer.

## Explicit exclusions

This is **not a general RFC 8941 implementation**. Generic lists/items, decimals,
tokens, arbitrary extension metadata/parameters, Signature-item parameters,
RFC 9651 dates/display strings, and non-ASCII strings are outside the subset.
Unknown metadata and invalid parameter types/combinations fail
MALFORMED_SIGNATURE; nothing is ignored to recover a selected signature.

Recognizing `sf`, `req`, `tr`, `key`, `bs` or `@query-param` syntax does not make
those components resolvable. The old signer still rejects them. Unknown `alg`
strings can be parsed as metadata, but do not enable an algorithm. Negative
integer times and empty metadata strings are syntax values; HMS-04 must reject
them wherever application policy requires. Empty or short decoded signatures
can be parsed; HMAC verification must require exactly 32 bytes later.

## Bounds and errors

The low-level API has bounded defaults; `options = {limits: {name: lowerValue}}`
can lower individual ceilings. Every supplied value is a positive safe integer
at or below the ceiling. Unknown option/limit keys or invalid values return
PROFILE_INVALID. Do not pass the full HMS-01 Profile limits object: only the
field-specific keys listed here are accepted. HMS-04 must deliberately map its
explicit profile configuration to this primitive.

| Limit | Ceiling |
|---|---:|
| envelopeFieldBytes | 16,384 per combined field, separators included |
| instancesPerName | 16 |
| signatures | 8 per dictionary |
| components | 32 per inner list |
| componentParameters / signatureParameters | 5 / 6 per owner |
| fieldNameBytes / labelBytes | 256 / 64 |
| metadataStringBytes | 512 decoded ASCII bytes per string |
| signatureBytes | 32 decoded bytes per entry |
| workUnits | 2,097,152 per call |

The 32-byte parser ceiling follows the initial HMAC workstream. It is a ceiling,
not an exact-length cryptographic check. Larger algorithm signatures require an
explicit future ceiling change and fixtures; passing alg alone cannot raise it.

Length checks precede input conversion/join, decoded-byte allocation and output
appends. Parsing is iterative. Work is charged for scans, output, structure
visits and conservative bounded sort/hash costs. Envelope parsing shares one
budget across both fields, including unselected labels. Counter values may
change with implementation revisions; no CPU, memory-in-MiB, or wall-time bound
is inferred from these units.

Failure codes: PROFILE_INVALID, LIMIT_EXCEEDED, MALFORMED_SIGNATURE,
UNSUPPORTED_COMPONENT, OPERATION_FAILED (unexpected local execution failures).
Checks stop at the first encountered failure; config and aggregate byte bounds
precede field parsing. These are local diagnostics, not HTTP response bodies.

Measured examples and reproduction:

```sh
node scripts/measure-field-work.mjs
npm test
```

See [work measurements](evidence/hms-02-work.json) and the
[HMS-02 receipt](hms-02.md). No host adapter or Native execution is qualified.

References: [RFC 8941 §4](https://www.rfc-editor.org/rfc/rfc8941.html#section-4),
[RFC 9421 §§2,4](https://www.rfc-editor.org/rfc/rfc9421.html#section-4),
[HTTPWG fixture provenance](../test/fixtures/httpwg/README.md).
