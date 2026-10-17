# HMS-09 — qualification and operational handoff

HMS-09 qualifies the implemented **narrow Node HMAC request profile**. It adds a
repeatable cross-target runner, a machine-readable target × feature matrix,
independent HMAC checks, lifecycle/resource evidence and this handoff. It does
not promote the experimental package to production or add a Fastly realization.

The [recorded receipt](qualification/hms-09.json) contains exact source commits
and trees, tool versions and lockfile hashes, 61 individual check outcomes, backend
realizations, RFC bytes, resource observations and every target/feature cell.
`completed-with-gaps` means all planned checks completed; it is not an all-target
or full-RFC pass. `fail` and `not-run` cells make the command exit nonzero.
Refusal probes can pass while the corresponding target remains `unavailable`.

## Scope and evidence

The shared fixture is a POST request with authoritative original target bytes,
trusted `https://example.test` origin, SHA-256 Content-Digest, ordered coverage
of `@method`, `@target-uri`, `content-digest`, HMAC-SHA256, one `sig1` label,
explicit key/version/domain, created=1000, expires=1060 and 5 seconds of skew.
Both Node targets run the same package-owned protocol Wasm. Native uses emitted
`guest-source:pulse-hmac-as` crypto; JavaScript uses `runtime-builtin` Web Crypto.
Neither is an independent protocol implementation of the other.

The standalone `/protocol` implementation supplies the independent JS protocol
comparison. OpenSSL CLI computes HMAC over **literal expected base text**, signs
input verified by both targets, checks their output MACs, and rejects a changed
base. Node Web Crypto and the CLI share OpenSSL lineage. This is an independent
interface/build and serialization oracle, not an independent crypto lineage or
a general external RFC 9421 parser.

| Feature | Node Native | Node JavaScript | Reference JS | OpenSSL CLI |
|---|---|---|---|---|
| Exact strict-profile fields, sign/verify | Pass | Pass | Pass | Literal-base HMAC oracle |
| Negative policy/message cases | 13 cases | Same 13 cases | Shared in-profile subset | Changed base |
| Body boundaries | 0 / 65536 accepted; 65537 refused | Same | Same, exact fields compared | Not qualified |
| Raw target / host authority | Pass | Pass | Snapshot only; host unavailable | No host adapter |
| Built and dev HTTP capture | Pass, separately recorded | Pass, separately recorded | Unavailable | Unavailable |
| Missing grants/artifacts/capture/key | Five refusals | Same five | Not qualified here | Unavailable |
| Private data redaction | Trace, build output, host errors | Result, build output, host errors | Fixed replay-store failure | Unavailable |
| Cancellation / deadline | Selected-crypto host seam | Selected-crypto host seam | Not qualified here | Unavailable |
| Replay enforcement | **Unsupported**; `not-checked` | **Unsupported**; `not-checked` | Fixture atomic store, duplicate and failure | Unavailable |
| RFC B.2.5 | Exact base + emitted crypto | Same package base + selected crypto | JS base + Web Crypto | Exact published MAC |
| Resources | Physical Wasm, compile/RSS observations | Shared package Wasm ceiling | Not measured here | Not measured |

The complete JSON matrix also retains these separate rows:

| Target/environment | Outcome | Evidence boundary |
|---|---|---|
| Fastly JavaScript, local | Unavailable | `package.invoke` capability classification is blocked |
| Fastly JavaScript, Viceroy | Unavailable | No generic host binding or Viceroy execution |
| Fastly Native, Viceroy | Unavailable | Provider lowering refuses package capability; no Viceroy execution |
| Fastly Native, deployed | Unavailable | Same missing binding; no deployment performed |

The Fastly probes inspect the actual provider admission paths at the recorded
Pulse revision. They do not compile or run a Fastly application. CLI/Viceroy
availability is recorded separately; installing those tools alone cannot supply
the missing binding. A future admission change deliberately fails these probes
so maintainers must update the evidence instead of retaining stale refusals.

## Cases and limits

Negative fixtures cover signature tampering, a wrong key, expired/future time,
method and target changes, mixed-case unsupported methods, body tampering,
missing fields, unknown key ID, duplicate created parameters, an unsupported
component and duplicate Signature fields. Missing capture, artifact, binding,
secret and operation grant all refuse. Dynamic options, replay-required options,
shadowed imports and missing compiler grants also refuse.

Raw target tests retain dot segments, percent spelling, query order and repeated
query values; normalization or a one-byte target change invalidates the MAC.
Absolute/authority-like targets, fragments, backslashes and whitespace refuse.
Host and Forwarded headers cannot replace the configured trusted origin, and a
mismatched binding origin refuses. Built and dev launchers verify a real HTTP
request containing `/a/../verify?x=%2f`. These are loopback HTTP tests with a
configured HTTPS origin representing a trusted termination boundary; they are
not TLS, proxy-chain, outbound-send or deployed-service qualification.

Lifecycle cases invoke the actual compiler-produced package artifact and
operation at the Node host seam with each selected crypto implementation. They
check an already-cancelled operation, cancellation and monotonic deadline expiry
while HMAC completion is withheld, rejection of late results, staging-buffer
wiping, redacted secret-lookup errors, and closed capture refusal. The deadline
uses the real Pulse request-budget implementation with a controlled clock.
These are host-seam tests, not socket-disconnect or deployed cancellation tests.
Trusted synchronous Wasm cannot be CPU-preempted by this contract.

Pulse verification twice returns `replay:not-checked`; replay-required options
refuse. The reference-only replay fixture atomically consumes a nonce, admits
only one of two concurrent checks, rejects the duplicate, and fails closed when
the store throws. It is process-local test storage, not a production replay store.

The exact RFC 9421 B.2.5 receipt contains the 200-byte base, SHA-256
`82faed1b67e492cfc8fe50fee1b6fdbdcf9f4d6384af8282339dcad5e44310e7`
and MAC `pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=`.
B.2.5 lacks this profile's required body/time/tag/coverage policy: the receipt
proves base and crypto primitives, not acceptance by the narrow verifier.
Other RFC/HTTPWG vectors remain in the ordinary package suite.

## Resource interpretation

The package protocol module is **24,565 bytes**, SHA-256
`45b1b8b80c8b074b0e11a85ee17565c43c93b4a551b85a0da47af5e4e42fba87`.
It initially allocates 5 Wasm pages (320 KiB); growth to 32 pages succeeds and
beyond 32 pages refuses (2 MiB maximum). Body and private crypto-message limits
are 65,536 bytes; the host contract bounds crypto commands to four.

The emitted Native fixture is 7,179 bytes. A two-route constant-text baseline
without the package, crypto declarations or package grants is 1,922 bytes.
Incremental app Wasm is **5,257 bytes**; adding the protocol module once gives
**29,822 additional physical Wasm bytes**. This excludes base64/JSON/JS carriers.
JavaScript shares the protocol module but does not use the Native app module.

The receipt includes initial compile time, then a baseline/full compile pair,
RSS changes and their signed differences. They are single-process observations
with warm caches and GC, not isolated incremental cost or performance gates.
Runtime peak RSS, per-request peak memory and production latency budgets remain
unavailable. Do not interpret a negative time/RSS delta as a performance benefit.

## Reproduce

Use Node 24.19.0, npm 11.9.0, pnpm 12.14.0, AssemblyScript 0.28.18 and an OpenSSL
3 CLI. The receipt records the exact versions actually used. These revisions
identify evidence; they are **not runtime admission pins**. Any trusted package
matching the versioned lowering/runtime contracts remains admissible.

Prepare Pulse separately (the qualification runner does not install or build it):

```sh
git clone --branch latest https://github.com/pulse-compute/pulse.git ../pulse
git -C ../pulse checkout 833eab56a5f8d17437878a7420c0748ffe915dcc
(cd ../pulse && corepack pnpm install --frozen-lockfile --ignore-scripts)
(cd ../pulse && corepack pnpm build)
```

From the package checkout at the receipt's `sources.package.commit`:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm ci --prefix spikes/hms-07/toolchain --ignore-scripts --no-audit --no-fund
npm run build:native
git diff --exit-code -- native/module.json
npm run check
npm run check:contract
npm test
npm run check:interop
npm run qualify -- ../pulse /tmp/hms-09.json
```

`npm run test:integration -- ../pulse /tmp/hms-09.json` invokes the same runner.
The second argument is an optional output file; use a path outside the checkout
for clean-source receipts. Generated reports include commit/tree identity and,
for dirty sources, diff/untracked-file hashes. Qualification failures retain
failed and unrun checks; raw exception messages and fixture secrets are omitted.
Run a failing check under a local debugger for details. The temporary app and
loopback servers are disposed after the run.

The normal PR CI runs package checks, reproducible Native artifact generation,
OpenSSL reference interoperability, examples and unit tests (including report
failure semantics). It does **not** run this cross-repository checkpoint: the
committed receipt is local evidence against the explicit prepared Pulse source.
No additional runtime dependencies, exports or production code are introduced.

## Handoff and next gates

| Remaining work | Owner and prerequisite |
|---|---|
| Fastly generic host binding | Pulse provider/runtime owners; discuss any contract expansion before implementation, then separate Pulse PR |
| Viceroy and deployed Fastly receipts | Provider/integration owners after binding support; deployment requires separate authorization |
| Production replay storage | Host/application owner; atomic durable scoped consume, trusted time, capacity and expiry policy |
| Pulse replay-required profile | Package and host owners; contract discussion before expanding the current profile |
| TLS/proxy origin provenance and outbound-send integrity | Deploying host owner; preserve authoritative bytes and trusted termination configuration |
| Socket cancellation, isolated memory and production latency | Runtime/operator owners; environment-specific qualification |
| Responses, selectors, trailers, multiple labels, asymmetric Native | Separate profile expansion, explicit limits and new conformance evidence |
| Release promotion / publication | HMS-10 optional follow-up; human decision, not implied by this receipt |

Package owners retain parsing, canonicalization and policy. Crypto owns primitive
realizations. Pulse owns capture, grants, private staging, lifecycle and execution.
HMS-09 changes no monorepo contract and requires no new architectural exception.
Human review/merge remains required; no merge, release, deployment or publication
is performed by this workstream step.

## Recorded checkpoint

- Base: HTTP Signatures `7befdc329fd25f3f370f082b85941aad07caef16`.
- Tested implementation: `0d1d20e798059b6864779e71672daee2c756ee3c`, tree
  `c66a5fc54561eb77181f1c22e14454691a239bd0`, clean checkout.
- Pulse: `833eab56a5f8d17437878a7420c0748ffe915dcc`, tree
  `1b0893e20dbee7b0c2a86add7415d19205734ffb`, clean checkout, no Pulse edits.
- Qualification: **61/61 checks passed**, `completed-with-gaps`; all four Fastly
  environment rows remain unavailable, both Pulse replay cells unsupported.
- Package: `npm run check`, `npm run check:contract`, `npm test` (**872/872**),
  `npm run check:interop` and reproducible `npm run build:native` passed.
- Pulse prerequisites: frozen install, build, `corepack pnpm maintainer:check`,
  and `node wasm/test/contracts/assert-package-runtime.cjs` passed. The generic
  host test is supplemental seam evidence, not a proxy for a missing target.
- No unresolved failures in the recorded run. Broader monorepo release tests,
  production deployment, Fastly execution and production performance are not
  claimed. The receipt follow-up changes only this document and the JSON report;
  its parent is the exact tested implementation commit.

Changed files are the shared integration runner, two qualification helpers,
report tests, the `qualify` script, README/contributor/capability documentation,
this handoff and its JSON receipt. Contract ownership is unchanged. The next
optional step is an explicitly scoped HMS-10 promotion decision; closing any
Fastly or replay gap first requires the owner gates above.
