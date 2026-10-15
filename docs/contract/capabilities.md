# Capability and execution matrix

Status has a precise scope:

- **supported**: the named reference feature is implemented, within stated
  restrictions; evidence is listed. It does not imply product support.
- **unsupported**: the package has no implementation for this feature/profile;
  reject the operation rather than degrade it.
- **unavailable**: a required input, capability or execution realization is not
  supplied by the selected host/backend. Do not infer or synthesize it.

Qualification is a separate column. An untested target is never a passing proxy.
HMS-01 adds a design contract; it does not widen any runtime support cell.

| Feature | HMS-00 runtime status | Evidence / remaining implementation |
|---|---|---|
| HMAC-SHA256 sign/verify with raw JS bytes | supported, reference only | Exact B.2.5; policy negatives; raw key minimum differs from v1 |
| Ordered plain covered components / signature parameters | supported, restricted | Exact B.2.5 base and fields; no general SF parser claim |
| Plain ASCII fields | supported, restricted | date/content-type and missing/non-ASCII rejection; not full whitespace/multivalue qualification |
| `@method`, `@target-uri`, `@authority`, `@query`, `@status` | supported, selected cases | Existing tests; no host authority proof |
| `@scheme`, `@path`, `@request-target` origin form | supported in source, unqualified | No dedicated recovered vector; URL normalization review in HMS-03 |
| One selected label among multiple signatures | supported, restricted | Two-label test and duplicate-label rejection |
| Required coverage, keyid, created age bound | supported, restricted | Existing negative tests; no full v1 policy |
| `sf`, `key`, `bs`, `tr`, `req`, `@query-param` | unsupported | Types reserve shapes; HMS-02/03 and host visibility required |
| General RFC 8941 syntax / all RFC metadata | unsupported | Partial parser only; HMS-02 |
| RSA, ECDSA, Ed25519 sign or verify | unsupported | HMS-06 primitive and vector gates |
| New message/result/profile API and typed capabilities | unsupported at runtime | Defined by HMS-01; HMS-02–05 implementation |
| Mandatory alg/tag, skew, scoped resolver and 256-bit minimum | unsupported as v1 policy | Some old checks exist; cannot use them as v1 enforcement |
| Content-Digest body computation/verification | unsupported | Digest is currently an opaque header; HMS-05 |
| Atomic replay state | unsupported | Nonce metadata is not replay protection; HMS-05 |
| Associated-request response binding | unsupported | No `req` support; response profile cannot run yet |
| Required field known absent | unavailable input (known absence) | Old missing-field test; v1 distinguishes `COMPONENT_MISSING` |
| Raw target, retained body/trailer/request not exposed | unavailable input | Host adapter must report reason; no reconstruction fallback |
| Explicit crypto backend missing | unavailable capability | Old calls reject/fail; global Web Crypto default remains an inherited gap |
| Accept-Signature negotiation / signature append | unsupported | Outside v1; no automatic label/policy downgrade |

| Target | Realization status | Qualification |
|---|---|---|
| Node JS 24.19.0, old spike API | supported reference | Six recovered tests plus boundary observations; no production security qualification |
| Node JS, HMS v1 profile API | unsupported | Contract only; not implemented |
| Fastly JS | unavailable adapter/qualification | No execution evidence; source portability is insufficient |
| Node Native | unavailable realization | No approved lowerer or host bridge |
| Fastly Native / Viceroy | unavailable realization | No compile, local host or deployed receipt |

## Migration and owner gates

| Gap | Owner / next ticket |
|---|---|
| Structured fields, deterministic parse errors and bounds | Package, HMS-02 |
| Component sources, descriptors and exact base | Package plus host evidence, HMS-03 |
| Capability crypto/key policy and result API | Package/backend, HMS-04 |
| Content and nonce/replay enforcement | Package/host/store, HMS-05 |
| Additional algorithms | Crypto primitive owner and package, HMS-06 |
| Host authority, opaque key handles and Native fit | Pulse contract owners, read-only investigation in HMS-07 |
| Trusted lowering authority / ABI/provider modifications | Human architectural approval before HMS-08, separate Pulse PRs |

No repo membership or type declaration grants compiler-extension trust. There
is no hidden JavaScript interpreter, Native-to-JS fallback or automatic backend
selection in the intended contract. A host cannot satisfy an unavailable
required component with an untrusted caller assertion.
