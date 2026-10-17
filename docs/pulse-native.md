# Pulse integration: bounded Node HMAC profile

The `/pulse` facade runs package-owned protocol Wasm through Pulse's generic,
versioned runtime binding. The package is independently versioned: Pulse needs
no HTTP Signatures registration or synchronized npm release. This development
implementation requires the accompanying Pulse runtime-binding change; the
released compiler alone does not provide it. No npm release is made here.

## Handler

```ts
import { Pulse } from '@pulse-compute/pulse';
import { signatures } from '@pulse-compute/http-signatures/pulse';

const app = new Pulse({ auto: true });
app.post('/events', async ctx => {
  const result = await signatures.verify(ctx, {
    binding: 'webhook',
    profile: {
      id: 'webhook', label: 'sig1', authority: 'api.example.test',
      tag: 'webhook', trustDomain: 'partner-a',
      maxAgeSeconds: 60, clockSkewSeconds: 5,
    },
  });
  return ctx.text(result);
});
export default app;
```

This example exposes a verification receipt for demonstration. An application
must use successful verification and its local authorization rules before
performing protected work; it should give callers a uniform failure response.
The effect resolves to a bounded JSON **string** containing `{ok:true,value}`
or `{ok:false,code}`. The `/protocol` reference returns an object directly.
Host capability/configuration/lifecycle failures reject the effect instead of
returning an authentication Result. No key or HTTP snapshot enters the handler.

Calls must be directly awaited into a variable, with the current handler context
and literal options. Shared dynamic options, unsupported components, algorithms,
replay settings and unknown fields fail Native compilation. Named imports,
`signatures.verify`, and namespace imports are recognized. Distinct policies
need distinct profile IDs; conflicting artifacts fail compilation.

## Development host configuration

```ts
import { defineConfig } from '@pulse-compute/pulse';

export default defineConfig((_scope) => ({
  pulse: {
    entry: 'src/index.ts', defaultProfile: 'node',
    crypto: ['SHA-256', 'HMAC-SHA256'],
  },
  node: {
    host: 'node', target: 'native',
    node: {
      bindings: {
        packages: {
          webhook: {
            package: '@pulse-compute/http-signatures',
            contractId: 'pulse.http-signatures',
            artifact: 'pulse.http-signatures:webhook',
            operations: ['verify'],
            secret: 'WEBHOOK_KEY', keyId: 'partner-key', keyVersion: '1',
            trustDomain: 'partner-a', origin: 'https://api.example.test',
          },
        },
      },
    },
  },
}));
```

The host supplies `WEBHOOK_KEY` through Pulse's existing secret binding. It is a
32–4,096 byte UTF-8 secret, not a base64-decoded key; do not place its value in
source, artifacts or request data. `keyId` is local metadata, never a wire-driven
secret-store lookup. Restrict `operations` to those the host intends to allow.
The key, domain, profile authority and captured direction must match.

`origin` is the operator's trusted HTTPS termination setting. The host must
actually serve that external origin, including through any trusted TLS proxy;
Pulse does not trust forwarded headers or infer the origin from `Host`.
Node captures the original target/method, ordered fields and exact body before
Web Request normalization. Body forwarding/transformation is incompatible.
Built Node launchers receive the same map through their explicit
`packageBindings` option and key values through host `secrets`. Development
configuration is not implicitly imported into a production launcher.

The same explicit package effect can execute on Node's JavaScript target; its
protocol still runs in the package Wasm, while Crypto explicitly uses the
JavaScript byte backend. Native uses Pulse's Native guest-source SHA-256/HMAC.
There is no Native JavaScript protocol or crypto fallback.

## Fixed profile and limits

- HTTPS requests with uppercase methods and origin-form raw targets; configured
  lowercase DNS authority (optional port), one label and one signature.
- Exact ordered coverage: `@method`, `@target-uri`, plain `content-digest`.
- HMAC-SHA256, 32-byte signatures; SHA-256 Content-Digest over exact body bytes,
  including an empty body. The sender must supply that digest before signing.
- Required `created`, `expires`, `keyid`, `alg` and `tag`; one trusted time sample.
  Lifetime/max age is 1–3,600 seconds, skew 0–300 seconds. Duplicate, additional
  or missing metadata and unsupported envelope/coverage forms fail closed.
- Replay is explicitly unchecked (`not-checked`), so the same otherwise-valid
  message may verify again. Required replay configuration is unsupported.
- Body and signature base: at most 65,536 bytes. Original target: 16,384 bytes.
  At most 128 ASCII fields; values at most 16,384 bytes, combined field name/value
  bytes at most 131,072. Header parsing, OWS normalization and canonical base
  serialization execute in package Wasm.
- Protocol Wasm memory maximum: 32 pages (2 MiB); fresh instance per operation.
  The host permits at most four crypto commands, checks all byte ranges and
  fences late results after cancellation. Keys stay in host/Crypto memory;
  private buffers and protocol memory are wiped after operation settlement.

The profile deliberately excludes responses, associated requests, trailers,
structured selectors, binary wrapping, query components, multiple labels,
asymmetric algorithms and replay stores. Their existing JavaScript reference
support remains available through `/protocol`. Fastly is unavailable and fails
provider capability planning. HMS-09 owns broader target/operational qualification.
Trusted package Wasm is not a CPU-preempted sandbox.

## Outbound signing and evidence

`signatures.sign` uses the same literal options and an **outbound host capture**.
The inbound HTTP server cannot supply that authority. An outbound integration
freezes its intended method, target, fields and body, captures them through the
Node host integration API, runs the effect, installs both returned signature
fields and sends those exact bytes. Signing neither sends nor proves a later
send. The host closes captures in `finally`. There is no portable handler API
that can mint captures or read the key.

`integration/node.mjs` is the executable complete host example and acceptance
fixture. It installs a copy of this independently versioned package into an
isolated application, compiles real Native Wasm, executes sign/verify on Native
and JavaScript, compares strict reference output, and builds/launches both Node
targets over real HTTP with a raw dot-segment target. It also checks RFC B.2.5
base/MAC at the primitive boundary (that vector is outside the strict profile),
64 KiB bodies, missing authority, negative cases, redaction and static refusal.

```sh
npm ci --prefix spikes/hms-07/toolchain --ignore-scripts
node scripts/build-native.mjs
node integration/node.mjs /path/to/prepared/pulse
```

The optional toolchain uses its committed lockfile and AssemblyScript 0.28.18.
The integration accepts a prepared compatible Pulse checkout; its contract does
not require one particular Pulse commit. Validation receipts identify the exact
tested trees for reproducibility, not as a package admission pin.
