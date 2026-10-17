# HMS-08 — package-owned Native realization

Implemented the first bounded Node HMAC profile after the user approved the
generic runtime/host contract expansion. The README has a Usage section directly
after the introduction with executable sign/verify examples and a Pulse handler.

The package owns its `/pulse` facade, product contract, trusted manifest/builder,
AssemblyScript protocol, deterministic Wasm artifact and integration fixtures.
The accompanying Pulse change owns generic invocation, static artifact/ABI
validation, authoritative Node capture, private key/crypto staging, lifecycle
fences and redaction. Pulse contains no HTTP Signatures registration, policy,
parser or dependency pin. Existing independent npm version admission is retained.

## Acceptance evidence

`node integration/node.mjs /path/to/prepared/pulse` checks:

- Emitted Native application sign/verify and exact strict-profile output parity
  with the JavaScript reference, plus Node JavaScript target execution.
- Exact RFC 9421 B.2.5 base bytes from the Native serializer and expected MAC from
  the emitted application's selected Native Crypto guest. This is a primitive
  vector, not a strict-profile message.
- 65,536-byte body success, 65,537-byte capture refusal; body, method, URI,
  signature, key, time, envelope, duplicate metadata and coverage failures.
- Forged/missing snapshots, missing grants/artifacts/keys, private trace output,
  unsupported static options and real HTTP execution of both built Node targets.
  The transport fixture preserves dot segments and percent-escape case.

Pulse's independent `package-runtime` contract test covers Wasm memory/ABI and
hash refusal, operation grants, bounded crypto calls, host capture disposal,
private staging wipe and cancellation during crypto with late-result fencing.
Runtime bridge tests prove live-context admission and observation redaction.
Existing compiler, runtime, continuation, package, provider and CLI profiles
provide regression coverage; exact results and tested trees belong in the PR
receipt. Local integration is not a release or production qualification.

See [Pulse usage and exact supported scope](pulse-native.md) and the
[approved contract record](hms-08-contract.md). The earlier
[boundary receipt](evidence/hms-08-boundary.json) remains historical evidence at
Pulse `c42b23e78d32114b69647f6ea6cc3b2d3150b36a`; its expected refusals describe
that pre-extension tree, not current behavior.

Fastly, replay-store realization, response signatures, asymmetric Native
profiles and broad operational qualification remain outside this first profile.
HMS-09 owns the target matrix and further qualification. No merge, publication
or deployment is performed by this work.
