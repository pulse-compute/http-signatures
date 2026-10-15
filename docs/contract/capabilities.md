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
root API are unchanged. HMS-04 adds `/protocol` and explicit `/webcrypto`;
HMS-05 adds bounded SHA-256 content integrity and explicit replay hooks.

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
| Message/result/profile API and explicit capabilities | supported HMAC profile via `/protocol` | Explicit required/excluded body and required/none replay modes; exact coverage, scoped keys, bounded work and fixed failures |
| Mandatory alg/tag, skew, scoped resolver and 256-bit minimum | supported via `/protocol` | Tamper, time boundaries, resolver scoping and invalid backend tests |
| Content-Digest body computation/verification | supported SHA-256 subset | HMS-05 exact RFC vectors, header dictionary checks, signed coverage and actual bounded content hash |
| Replay enforcement hook | supported with host-owned atomic store | HMS-05 ordering, scoped tuple, inclusive retention, concurrency and store failure tests; no package registry or production store adapter |
| Associated-request component binding | supported via `/base` | Exact §2.4; all request-derived components with req; HMS-04 response target/coverage/domain enforcement; HMS-05 verifies response content independently of request content |
| Required field known absent | unavailable input (known absence) | Old missing-field test; v1 distinguishes `COMPONENT_MISSING` |
| Raw target, retained body/trailer/request not exposed | unavailable input | Host adapter must report reason; no reconstruction fallback |
| Explicit crypto backend missing | unavailable capability | New `/protocol` rejects; `/webcrypto` requires explicit SubtleCrypto and key. Root spike retains global default |
| Accept-Signature negotiation / signature append | unsupported | Outside v1; no automatic label/policy downgrade |

| Target | Realization status | Qualification |
|---|---|---|
| Node JS 24.19.0, old spike API | supported reference | Six recovered tests plus boundary observations; no production security qualification |
| Node JS 24.19.0, `/fields` API | supported experimental subset | HMS-02 tests and logical-work counters; no host/crypto policy |
| Node JS 24.19.0, `/base` API | supported experimental subset | HMS-03 exact byte/corpus/negative tests and logical-work counters; no adapter provenance proof |
| Node JS 24.19.0, `/protocol` and `/webcrypto` | supported experimental HMAC subset | HMS-04–05 tests, RFC B.2.5 and RFC 9530 digest vectors; no host provenance or production replay-store qualification |
| Fastly JS | unavailable adapter/qualification | No execution evidence; source portability is insufficient |
| Node Native | unavailable realization | No approved lowerer or host bridge |
| Fastly Native / Viceroy | unavailable realization | No compile, local host or deployed receipt |

## Migration and owner gates

| Gap | Owner / next ticket |
|---|---|
| Signature-envelope parsing and serialization | Package, HMS-02 implemented; see `../signature-fields.md` for exclusions |
| Component sources, descriptors and exact base | Package HMS-03 implemented; host adapter qualification remains open |
| Capability crypto/key policy and result API | Package/backend, HMS-04 implemented; see `../protocol.md` |
| Content and nonce/replay enforcement | Package HMS-05 implemented; host body capture and atomic durable store qualification remain external |
| Additional algorithms | Crypto primitive owner and package, HMS-06 |
| Host authority, opaque key handles and Native fit | Pulse contract owners, read-only investigation in HMS-07 |
| Trusted lowering authority / ABI/provider modifications | Human architectural approval before HMS-08, separate Pulse PRs |

No repo membership or type declaration grants compiler-extension trust. There
is no hidden JavaScript interpreter, Native-to-JS fallback or automatic backend
selection in the intended contract. A host cannot satisfy an unavailable
required component with an untrusted caller assertion.
