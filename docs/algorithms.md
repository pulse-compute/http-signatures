# Algorithm contracts and interoperability (HMS-06)

Experimental reference support on **Node 24.19.0** only. This is a bounded
RFC 9421 subset, not full RFC conformance or a production cryptography review.
Every `/protocol` profile fixes one algorithm and one exact signature width.
The original root spike remains HMAC-only and unchanged.

## Implemented matrix

| RFC algorithm | Sign / verify | Primitive and signature bytes | Explicit Web Crypto key contract | Evidence |
|---|---|---|---|---|
| `hmac-sha256` | yes / yes | HMAC, SHA-256; exactly 32 bytes | secret HMAC/SHA-256 CryptoKey, 256–32768 bits, appropriate usage | Existing RFC B.2.5 bytes/MAC and HMS-04–05 policy tests |
| `ecdsa-p256-sha256` | yes / yes | ECDSA, P-256, SHA-256; exactly 64 bytes: 32-byte unsigned big-endian r followed by 32-byte s | ECDSA/P-256 private CryptoKey with `sign`, public CryptoKey with `verify` | Exact RFC B.2.4 base/signature; both directions with classic Node crypto and OpenSSL CLI; request/response, body/replay and negative tests |
| `rsa-v1_5-sha256` | yes / yes | RSASSA-PKCS1-v1_5, SHA-256; exactly 256/384/512 bytes for 2048/3072/4096-bit modulus | RSASSA-PKCS1-v1_5/SHA-256 private/public CryptoKey with appropriate usage; public exponent 65537 | RSA-2048 both directions with classic Node crypto and OpenSSL CLI; deterministic signature equality; real RSA-3072/4096 protocol round trips |

`/webcrypto` exports `createHmacSigner` / `createHmacVerifier`,
`createEcdsaP256Signer` / `createEcdsaP256Verifier`, and
`createRsaV15Signer` / `createRsaV15Verifier`. Each accepts the same closed record:
`{subtle,key,keyId,keyVersion,trustDomain}`. The host provides SubtleCrypto and an
already provisioned CryptoKey; no global backend, raw-key import, discovery or
fallback occurs. Sign uses the private key; verify uses the public key and the
backend's verification primitive. It never re-signs or compares signatures in JS.

Tested asymmetric import paths are **PKCS#8 DER for private keys** and **SPKI DER
for public keys**, with explicit algorithm/curve/hash and usage. Tests import
private keys as nonextractable. The RFC fixture source encodings are PKCS#1 RSA
and SEC1 EC private PEM, PKCS#1 RSA public PEM and SPKI EC public PEM; test-only
Node conversion produces PKCS#8/SPKI before Web Crypto import. The production
adapter accepts none of these raw encodings directly. JWK, certificate/keychain
loading and production provisioning are not qualified by this work. HMAC's
existing explicit raw import remains demonstrated separately.

Adapters validate purpose, usage, curve/hash, RSA modulus/exponent and bounded
identity strings before returning frozen capabilities. `keyBits` means HMAC key
length, EC field size (256), or RSA modulus size; it is not an entropy or uniform
security-strength claim. Other backends must attest the same primitive contract.
The protocol checks this attestation and bindings; it cannot inspect opaque keys
or establish the honesty of a caller-supplied backend. Backend randomness,
constant-time behavior and private-key protection remain backend obligations.

## Policy, format and limits

`allowedAlgorithms` must contain exactly one supported RFC identifier. The
signed `alg`, selected key's algorithm and profile algorithm must agree. Key ID,
version, trust domain and profile-scoped resolver rules remain in force. RSA
profiles fix `limits.signatureBytes` to one modulus width; mismatched keys fail
`KEY_REJECTED`. No modulus search, algorithm negotiation, JWS alias (`ES256`,
`RS256`) or incoming metadata may choose or widen policy.

ECDSA uses Web Crypto's IEEE P1363-style raw r||s, **never ASN.1 DER**. Leading
zero octets retain the fixed 32-byte scalar widths. The backend validates scalar
ranges and signatures. Low-s normalization is not required: valid s and n−s
signatures are accepted. Replay protection keys on the scoped nonce, not on
signature bytes; tests verify that a valid alternate s cannot reopen a consumed
nonce. ECDSA signatures are randomized, so interoperability asserts verification
and fixed encoding rather than equality of freshly produced signatures.

`/fields` exports `signatureByteCeiling = 512`. Its default and
`signatureBaseLimits.signatureBytes` remain **32**, preserving existing HMAC
behavior. Only explicit signature capacity may rise to 512; every other ceiling
and the 2,097,152 logical-work default remain unchanged. Protocol profiles require
an exact algorithm width, while low-level parsers treat capacity as a maximum.
All envelope entries, including unselected labels, must fit the configured
capacity. Mixed-algorithm envelopes exceeding it are deliberately rejected.

Byte/output/work preflight precedes cryptography, with one signer or verifier
call, no retry, and fixed redacted failures. Adapter bases are bounded to 65,536
bytes, inputs are copied, signatures must have the exact width and backend
results must be ArrayBuffer(width) or boolean. Wrong curve, hash, key purpose,
usage, padding, size, malformed signature and backend outputs fail closed.
Body integrity, time/coverage policy and final replay consumption compose with
each enabled algorithm. See [protocol](protocol.md) and [content](content-integrity.md).

## Separate assessments, not enabled algorithms

| Algorithm | Assessment evidence | Missing package contract / status |
|---|---|---|
| `rsa-pss-sha512` | Classic Node verify accepts published RFC B.2.1–B.2.3 using SHA-512, RSA-PSS padding and exact 64-byte salt; tampering fails. Published PSS private fixture is converted to a public SPKI for tests; no PSS private key is retained in the fixture. | Unsupported profile and adapter. A future implementation needs explicit SHA-512/MGF1/salt/key restriction binding, sign/verify and cross-backend gates. No inference from RSA v1.5. |
| `ed25519` | Classic Node verifies published RFC B.2.6 with a SPKI public key and pure Ed25519 (no external digest); tampering fails. | Unsupported profile and adapter. A future implementation needs an explicit pure-Ed25519 key/purpose contract and two-way target evidence, distinct from prehash/context variants. |
| `ecdsa-p384-sha384` | RFC identifier recognized as out of scope; no execution qualification performed. | Unsupported. Would require P-384/SHA-384 binding and exact 96-byte r||s tests. |
| Other/extension/JWS names | No package capability contract. | Unsupported; no name alias or fallback. |

Backend availability is not package support. Unsupported profile algorithms fail
`PROFILE_INVALID`; a wire alg outside a valid local profile fails
`UNSUPPORTED_ALGORITHM`. No new cryptographic implementation is introduced to
extend this table.

## Targets and reproducible evidence

| Target/interface | Status |
|---|---|
| Node 24.19.0 Web Crypto | Implemented and tested reference support as listed above; no production host qualification |
| Node classic crypto | Test-only cross-interface verification/signing and separate PSS/Ed25519 assessment |
| OpenSSL 3 CLI | Development-only two-way P-256/RSA-2048 gate; separate executable/build, no package runtime dependency |
| Fastly JS | Unqualified; adapter/key provisioning and target execution receipts absent |
| Pulse Node Native | Unavailable realization; no approved primitive lowering or host bridge |
| Fastly Native / Viceroy | Unavailable realization; no compilation/host/deployment evidence |

`node scripts/check-interop.mjs` requires OpenSSL 3 and fails if missing or if any
comparison fails. It uses literal expected RFC/strict-profile bases, externally
signs and verifies both ways, rejects changed data, and verifies the published
P-256 signature. Its narrow DER/r||s bridge exists only in the test script. The
[RSA signature in the receipt](evidence/hms-06-interop.json) is independently
produced by the CLI over the RFC B.2.3 base, then frozen in a
[reference fixture](../test/fixtures/rsa-v15-openssl.json) checked by unit tests
and the CLI gate; it is **not** a published RFC RSA-v1.5
signature (B.2.3 uses PSS). RFC examples lacking mandatory target/alg/tag policy
are primitive fixtures, not accepted strict-profile messages.

Node classic crypto, Node Web Crypto and the CLI share OpenSSL lineage; these
are separate API/build interoperability checks, not three independent crypto
implementations. The local receipt records Node's OpenSSL 3.5.7 and external
OpenSSL 3.0.13; CI records its own CLI version. Independently published RFC
expected bytes/signatures provide an additional check against a shared local
round-trip error. Published keys are public test material, never production keys.

`node scripts/measure-algorithm-work.mjs` checks eight-entry envelope boundaries
at each new width and exact shared-work thresholds (one-below fails before
crypto). At width 512, eight decoded signatures total 4,096 bytes and the
Signature field is 5,526 bytes, within the unchanged 16,384-byte limit.
[Work evidence](evidence/hms-06-work.json) records 392,776 envelope work units
for that case. These are bounded logical counters and payload sizes, not peak
heap, RSS, cryptographic CPU, latency or concurrency qualifications.

Run `node examples/asymmetric.mjs` for complete explicit P-256/RSA compositions.
CI also runs both scripts, the full test suite and the existing HMAC/body examples.
Known failures in the declared new subset: none. Remaining integration work is
HMS-07's read-only Pulse investigation; no Pulse core, ABI, compiler, provider,
Native fallback or trusted-lowering changes are part of HMS-06.

Sources: [RFC 9421 §3.3 and Appendix B](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.3),
[Node Web Crypto](https://nodejs.org/docs/latest-v24.x/api/webcrypto.html),
[Node classic crypto](https://nodejs.org/docs/latest-v24.x/api/crypto.html).
Fixture attribution: [RFC 9421 license](../test/fixtures/rfc9421-LICENSE.txt).
