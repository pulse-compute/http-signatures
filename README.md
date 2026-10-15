# HTTP Message Signatures

**Experimental, private JavaScript reference. Not a supported or published package.**

This repository investigates bounded HMAC-SHA256, P-256/SHA-256 and RSA v1.5/SHA-256
profiles of RFC 9421. HMS-00
recovers the original spike without changing its source or six tests. Passing
those tests does not establish full RFC conformance, production security, or
Pulse Native support.

## Run locally

Use Node **24.19.0** (pinned in `.nvmrc` and CI). This is the only qualification
runtime for HMS-00; other Node versions are unqualified. The package has **no
runtime or development dependencies**, build step, or install scripts.

```sh
git clone https://github.com/pulse-compute/http-signatures.git
cd http-signatures
nvm install
nvm use
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm test
```

`nvm` is optional; any installation of the pinned Node version works. Tests can
also run directly without installation: `node --test test/rfc9421.test.js`.

## Experimental API

The root entry point is `@pulse-compute/http-signatures`. Its unchanged spike API exports:

| Export | Purpose |
|---|---|
| `serializeSignatureParams` | Serialize the ordered components and signature parameters |
| `createSignatureBase` | Build the canonical base for the restricted profile |
| `signMessage` | Produce `Signature-Input` and `Signature` fields with HMAC-SHA256 |
| `verifyMessage` | Check the selected signature against explicit caller policy |

These four exports are ESM named exports from `src/index.js`. There is no default
export, CommonJS entry point or TypeScript declaration bundle. A checkout consumer can use
`import { signMessage } from './src/index.js'`. The package-name import works
inside this package or from an explicitly installed local copy; nothing is
available from npm through this workstream.

The root spike source imports no modules. It needs standard `URL`, `TextEncoder`
and `Uint8Array` globals, plus a Web Crypto backend. Pass `crypto` explicitly
(for Node, `webcrypto` from `node:crypto`); the recovered API also defaults to
`globalThis.crypto`. This inherited fallback is recorded for HMS-01 review.
The tests import only Node built-ins.

## Boundaries and limitations

The host must supply authoritative HTTP fields/target, trusted keys, and trusted
time. The package does not retrieve keys, capture time, grant authorization, or own
replay storage. The new `/protocol` API can require signed-and-verified RFC 9530
`Content-Digest` and explicit atomic replay consumption. The unchanged root spike
does neither; a valid signature alone does not establish body integrity.

The spike implements unparameterized ASCII HTTP fields and selected derived
components (`@method`, `@target-uri`, `@authority`, `@scheme`, `@path`, `@query`,
origin-form `@request-target`, `@status`). It selects one explicitly labeled
signature from a restricted dictionary representation. This is implemented
surface, not a complete interoperability qualification.

Unsupported in the unchanged root spike: other algorithms; `;sf`, `;key`, `;bs`, `;tr`, `;req`; `@query-param`;
request/response cross-signing; `Accept-Signature`; complete RFC 8941 parsing;
non-ASCII field values; proxy/CONNECT target forms and ambiguous repeated
`set-cookie` values. URL normalization and field joining need further review.

See the [HMS-00 receipt](docs/hms-00.md) for provenance, immutable baseline,
actual test coverage, target status, and known gaps. [CONTRIBUTING.md](CONTRIBUTING.md)
describes the small PR/test workflow. The [HMS-01 contract](docs/contract/README.md) defines the intended message model,
profiles and explicit capabilities enforced by the new protocol API. The [HMS-02 fields API](docs/signature-fields.md) is now
available through `@pulse-compute/http-signatures/fields` for bounded parsing and
serialization. It does not alter the original signer/verifier or establish full
RFC conformance. The [HMS-03 base API](docs/signature-base.md) is available through
`@pulse-compute/http-signatures/base` for authoritative snapshots, ordinary and
structured field selectors, binary wrapping, trailers, derived components and
request-bound responses. It returns exact signature-base bytes; it does not
implement the new authentication policy or change the old signer/verifier.
The [HMS-04 protocol API](docs/protocol.md) adds explicit HMAC `sign`/`verify`
through `/protocol`, with an optional explicit `/webcrypto` adapter. It enforces
context, coverage, metadata, time and scoped keys. Run `node examples/hmac.mjs`.
The [HMS-05 content/replay API](docs/content-integrity.md) adds exact body digest
verification, a `/content-digest` generation helper, and atomic host replay hooks.
Run `node examples/webhook.mjs` for both original request/response profiles.
Required capabilities fail closed; excluded modes remain explicitly not checked.
See the [HMS-05 receipt](docs/hms-05.md). The [HMS-06 algorithm matrix](docs/algorithms.md)
adds explicit P-256 and RSA v1.5 adapters, fixed-size profiles and RFC/OpenSSL
interoperability evidence. Run `node examples/asymmetric.mjs` and
`npm run check:interop` (development-only OpenSSL 3 CLI required for the latter).
See the [HMS-06 receipt](docs/hms-06.md). Next: **HMS-07 Pulse integration investigation**. Native work is
conditional on a later integration investigation and human architectural approval.

Standards: [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421),
[RFC 8941](https://www.rfc-editor.org/rfc/rfc8941),
[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530).

Licensed under [Apache-2.0](LICENSE), matching the recovered package metadata.
