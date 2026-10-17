# HTTP Message Signatures

Bounded [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) signing and verification
with explicit coverage, keys, trusted time, body integrity and replay policy.

**Experimental and private.** The JavaScript reference supports HMAC-SHA256,
P-256/SHA-256 and RSA v1.5/SHA-256. A narrow Pulse Node HMAC profile runs as
package-owned Wasm. Neither is published or qualified for production.
See the [capability matrix](docs/contract/capabilities.md).

## Usage

Use `@pulse-compute/http-signatures/protocol` for signing and verification.
Package-name imports work from this checkout or an installed local copy;
there is no npm release. Run the complete HMAC example with Node **24.19.0**:

```sh
node examples/hmac.mjs
```

**Sign a request.** The host supplies `message`, an authoritative HTTP snapshot;
`profile`, the local policy; ordered signature `parameters`; a scoped `signer`;
and a trusted `clock`. The [complete setup](examples/hmac-context.mjs) provides
these values for an empty-body GET using a public fixture key and fixed time.

<!-- usage:sign -->
```js
import { sign } from '@pulse-compute/http-signatures/protocol';

const signed = await sign(message, {
  profile,
  covered: profile.requiredComponents,
  parameters,
  capabilities: { signer, clock },
});
if (!signed.ok) throw new Error(signed.code);

const signatureHeaders = {
  'Signature-Input': signed.value.signatureInput,
  Signature: signed.value.signature,
};
```

Install both fields before sending the exact signed message. Signing returns
fields; it does not mutate the snapshot or send a request.

**Verify a request.** The receiving host captures `received`, including both
signature fields, and supplies its `receivingProfile`, scoped key resolver
`keys`, and trusted `clock`.

<!-- usage:verify -->
```js
import { verify } from '@pulse-compute/http-signatures/protocol';

const checked = await verify(received, {
  profile: receivingProfile,
  capabilities: { keys, clock },
});
if (!checked.ok) throw new Error(checked.code);

console.log(checked.value); // Verified identity, coverage and policy outcomes.
```

Both operations return `{ ok: true, value }` or `{ ok: false, code }`.
Applications decide authorization after verification and should map failures to
a uniform external authentication response.

This GET example explicitly excludes body integrity and replay protection.
For body-bearing messages, require signed `content-digest` coverage and verify
the captured body bytes; a valid signature alone does not authenticate a body.
The webhook example shows that setup and an atomic replay hook:

```sh
node examples/webhook.mjs     # Content-Digest, request/response, replay rejection
node examples/asymmetric.mjs # P-256 and RSA signing/verification
```

The example keys, clock and in-memory replay store are fixtures. Real hosts own
snapshot provenance, key provisioning, trusted time, transport and replay storage.
See [protocol options](docs/protocol.md) and [body/replay policy](docs/content-integrity.md).

**Pulse handler (Node Native or JavaScript).** With the accompanying generic
Pulse runtime binding and an explicit host key grant:

```ts
import { signatures } from '@pulse-compute/http-signatures/pulse';

app.post('/events', async ctx => {
  const result = await signatures.verify(ctx, {
    binding: 'webhook',
    profile: {
      id: 'webhook', label: 'sig1', authority: 'api.example.test',
      tag: 'webhook', trustDomain: 'partner-a',
      maxAgeSeconds: 60, clockSkewSeconds: 5,
    },
  });
  return ctx.text(result); // JSON verification receipt; authorize separately.
});
```

The host captures HTTP bytes and supplies private crypto; the handler receives a
bounded JSON Result string. This profile requires signed SHA-256 Content-Digest
and does not check replay. See [complete configuration and limits](docs/pulse-native.md).

## API

All entry points use named ESM exports. There is no default export, CommonJS
entry point or exported TypeScript declaration bundle.

| Import | Purpose |
|---|---|
| `/pulse` | Request-owned Node sign/verify effects with literal profile and host binding |
| `/protocol` | `sign` and `verify` with explicit profile and capabilities |
| `/webcrypto` | Explicit HMAC, P-256, RSA v1.5 and SHA-256 capability adapters |
| `/content-digest` | `createContentDigest` for bounded SHA-256 body bytes |
| `/fields` | Parse and serialize bounded Signature-Input/Signature dictionaries |
| `/base` | Construct exact signature-base bytes from authoritative snapshots |
| Package root | Original HMS-00 spike: `signMessage`, `verifyMessage`, `createSignatureBase`, `serializeSignatureParams` |

The root spike is preserved for provenance and has weaker policy and parsing
semantics. New integrations should use `/protocol`. The optional `/webcrypto`
adapter requires an explicitly supplied `SubtleCrypto` and key; the strict
protocol has no ambient key lookup, clock or backend fallback.

## Supported scope

The JavaScript reference implements bounded signature dictionaries; ordered
HTTP fields and derived components; structured selectors, binary wrapping,
trailers and associated-request coverage when authoritative inputs exist;
explicit algorithm/key/time/coverage policy; and SHA-256 content integrity with
host-owned replay hooks. Each feature has restrictions and negative tests.

Unsupported features include Accept-Signature negotiation, appending signatures,
RSA-PSS, Ed25519 and unrestricted Structured Fields. Missing authoritative
components fail closed. This is a tested bounded profile, not blanket RFC
conformance or a guarantee that a host preserves signed bytes.

| Documentation | Details |
|---|---|
| [Contract and threat model](docs/contract/README.md) | Message model, authority, limits and security policy |
| [Signature fields](docs/signature-fields.md) | RFC 8941 envelope parsing and serialization |
| [Signature bases](docs/signature-base.md) | RFC 9421 components and canonical bytes |
| [Algorithms](docs/algorithms.md) | Exact keys, signature forms and independent interoperability |
| [Capability matrix](docs/contract/capabilities.md) | Supported, unsupported and unavailable features/targets |

## Pulse integration

HMS-08 implements package-owned Native protocol Wasm with a generic versioned
Pulse runtime/host contract, explicit Node capture and host-owned keys. It needs
the accompanying Pulse runtime-binding change. No HTTP Signatures registration,
package pin or matching release version is required in Pulse. See
[the implemented profile](docs/pulse-native.md) and [acceptance evidence](docs/hms-08.md).
Fastly and the broader target qualification remain HMS-09 work.

[HMS-07](docs/pulse-integration.md) remains the historical investigation against
its pinned Pulse revision. Its former allowlist, synchronized bridge and 32 KiB
constraints have been superseded by the merged Pulse prerequisites.

## Development

Use Node **24.19.0**, pinned in `.nvmrc` and CI. The reference has no runtime dependencies or install scripts. The `/pulse`
entry has an optional runtime peer, and the committed Native artifact has a
separate reproducible AssemblyScript build. See the [integration guide](docs/pulse-native.md).

```sh
git clone https://github.com/pulse-compute/http-signatures.git
cd http-signatures
nvm install
nvm use
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run check:contract
npm test
```

`nvm` is optional; any installation of the pinned Node version works.
`npm run check:interop` additionally requires the development-only OpenSSL 3 CLI.
See [CONTRIBUTING.md](CONTRIBUTING.md), the [HMS-00 provenance receipt](docs/hms-00.md)
and the [HMS-08 implementation](docs/hms-08.md).

Standards: [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421),
[RFC 8941](https://www.rfc-editor.org/rfc/rfc8941),
[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530).
Licensed under [Apache-2.0](LICENSE).
