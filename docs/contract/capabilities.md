# Capability and execution matrix

Status has a precise scope:

- **supported**: the named reference feature is implemented, within stated
  restrictions; evidence is listed. It does not imply product support.
- **unsupported**: the package has no implementation for this feature/profile;
  reject the operation rather than degrade it.
- **unavailable**: a required input, capability or execution realization is not
  supplied by the selected host/backend. Do not infer or synthesize it.

Qualification is a separate column. An untested target is never a passing proxy.
HMS-01 defines the profile contract. HMS-02 adds an isolated fields API and
HMS-03 adds a separate authoritative base API. The original signer/verifier and
full profile API support are unchanged. New capabilities below apply to `/base`.

| Feature | Current runtime status | Evidence / remaining implementation |
|---|---|---|
| HMAC-SHA256 sign/verify with raw JS bytes | supported, reference only | Exact B.2.5; policy negatives; raw key minimum differs from v1 |
| Ordered plain covered components / signature parameters | supported, restricted | Exact B.2.5 base and fields; no general SF parser claim |
| Plain ASCII fields | supported via `/base` | Per-instance OWS/obs-fold, ordered duplicate instances, empty values, strict control rejection |
| `@method`, `@target-uri`, `@authority`, `@query`, `@status` | supported via `/base` | Exact appendix bases, target consistency, status/context/availability tests; host authority still external |
| `@scheme`, `@path`, `@request-target` HTTP/1 forms | supported via `/base` | Preserved percent spelling; exact origin/absolute/authority/asterisk target forms |
| One selected label among multiple signatures | supported, restricted | Two-label test and duplicate-label rejection |
| Required coverage, keyid, created age bound | supported, restricted | Existing negative tests; no full v1 policy |
| `sf`, `key` resolution | supported bounded subset via `/base` | Explicit field schema, 177 HTTPWG cases with duplicate-rejection restrictions, RFC examples |
| `bs`, `tr`, `req` resolution | supported via `/base` | Per-instance byte wrapping, retained separate trailer/request blocks, exact context/order tests |
| `@query-param` resolution | supported via `/base` | RFC form encoding; empty/case/UTF-8 cases; reject repeated selected names and aliases |
| Bounded signature dictionaries, ordered typed parameters and byte sequences | supported via `/fields` | HMS-02 exact B.2.5, 57 adapted HTTPWG cases and local syntax/limit tests |
| Complete envelope label agreement and duplicate rejection | supported via `/fields` | All labels validated; no union/fallback; independent of old verifier |
| Unrestricted RFC 8941 / all RFC metadata | unsupported | `/fields` remains signature-specific; `/base` has broader internal grammar with explicit count and duplicate restrictions; RFC 9651 forms excluded |
| RSA, ECDSA, Ed25519 sign or verify | unsupported | HMS-06 primitive and vector gates |
| New message/result/profile API and typed capabilities | unsupported at runtime | Defined by HMS-01; HMS-02–05 implementation |
| Mandatory alg/tag, skew, scoped resolver and 256-bit minimum | unsupported as v1 policy | Some old checks exist; cannot use them as v1 enforcement |
| Content-Digest body computation/verification | unsupported | Digest is currently an opaque header; HMS-05 |
| Atomic replay state | unsupported | Nonce metadata is not replay protection; HMS-05 |
| Associated-request component binding | supported via `/base` | Exact §2.4; all request-derived components with req; full response profile enforcement still future |
| Required field known absent | unavailable input (known absence) | Old missing-field test; v1 distinguishes `COMPONENT_MISSING` |
| Raw target, retained body/trailer/request not exposed | unavailable input | Host adapter must report reason; no reconstruction fallback |
| Explicit crypto backend missing | unavailable capability | Old calls reject/fail; global Web Crypto default remains an inherited gap |
| Accept-Signature negotiation / signature append | unsupported | Outside v1; no automatic label/policy downgrade |

| Target | Realization status | Qualification |
|---|---|---|
| Node JS 24.19.0, old spike API | supported reference | Six recovered tests plus boundary observations; no production security qualification |
| Node JS 24.19.0, `/fields` API | supported experimental subset | HMS-02 tests and logical-work counters; no host/crypto policy |
| Node JS 24.19.0, `/base` API | supported experimental subset | HMS-03 exact byte/corpus/negative tests and logical-work counters; no adapter provenance proof |
| Node JS, HMS v1 profile API | unsupported | Contract only; not implemented |
| Fastly JS | unavailable adapter/qualification | No execution evidence; source portability is insufficient |
| Node Native | unavailable realization | No approved lowerer or host bridge |
| Fastly Native / Viceroy | unavailable realization | No compile, local host or deployed receipt |

## Migration and owner gates

| Gap | Owner / next ticket |
|---|---|
| Signature-envelope parsing and serialization | Package, HMS-02 implemented; see `../signature-fields.md` for exclusions |
| Component sources, descriptors and exact base | Package HMS-03 implemented; host adapter qualification remains open |
| Capability crypto/key policy and result API | Package/backend, HMS-04 |
| Content and nonce/replay enforcement | Package/host/store, HMS-05 |
| Additional algorithms | Crypto primitive owner and package, HMS-06 |
| Host authority, opaque key handles and Native fit | Pulse contract owners, read-only investigation in HMS-07 |
| Trusted lowering authority / ABI/provider modifications | Human architectural approval before HMS-08, separate Pulse PRs |

No repo membership or type declaration grants compiler-extension trust. There
is no hidden JavaScript interpreter, Native-to-JS fallback or automatic backend
selection in the intended contract. A host cannot satisfy an unavailable
required component with an untrusted caller assertion.
