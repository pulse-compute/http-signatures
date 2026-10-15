# HMS-07 implementation receipt

Ticket: read-only Pulse integration investigation and decision gate.
Repository: `pulse-compute/http-signatures`; PR target: `main`; human merge.
Base: `7d7826468ecf46f2f2de35cf03bd48b252cd573e` (merged HMS-06).
Base tree: `8d388fca2a0a45b9a7fc2b9147e38e3659ed34e1`.
Pulse reference: `latest` at `e6a78640928a93f0e41813f55d9847895ea9be41`.
The PR records the final head/tree/CI receipt without self-referential SHA edits.

**Decision: no-go for unchanged-source Native or automatic HMS-08.** The existing
HMAC primitive works; a narrow first-party bridge and authoritative host snapshot
need explicit architectural approval. The [decision record](pulse-integration.md)
contains compiler/host diagrams, exact diagnostics, bounds, four target lanes and
the smallest proposed owner changes. It does not authorize those changes.

## Changes and ownership

- `spikes/hms-07/`: executable assertions against pinned, unchanged Pulse sources,
  a Git-object source inventory, isolated exact toolchain lock and reproduction
  instructions. No Pulse implementation is vendored.
- `docs/evidence/hms-07-feasibility.json`: executed primitive, compiler, budget
  and normalization results, including expected Native failures.
- `docs/evidence/hms-07-targets.json`: source-inspected versus executed evidence
  and the unresolved adapter/authority gaps for each target.
- `docs/pulse-integration.md`: go/no-go decision and reviewable HMS-08 proposal.
  README, algorithm and capability documentation link this checkpoint.

The independent package owns HTTP semantics, profiles, bounded parsing and
conformance fixtures. Pulse package/lowerer owners would own a synchronized
trusted bridge; providers own snapshots, keys, wall time, replay and request
lifetime; Crypto owns primitives and private secret staging. No runtime API,
dependency, limit, source export, original spike or production behavior changes.
The optional investigation toolchain is not part of the root package or tarball.
No Pulse source, manifest, provider, ABI, compiler, trust catalog or release
metadata is changed. No publication, deployment or merge is included.

## Acceptance evidence

| Requirement | Evidence and scope |
|---|---|
| One HMAC sign/verify path | Exact RFC B.2.5 via actual Pulse JS crypto seam and unchanged HMAC Wasm; strict JS protocol composition verifies body and replay policy with both |
| Negative primitive/policy evidence | Changed base/body rejected, duplicate nonce rejected, 32,768 signing bytes accepted and 32,769 rejected; missing Native crypto selection unavailable |
| Compiler fit and exact refusal | Actual `/protocol` npm export resolves, Native source graph rejects eight modules; two control plans accepted, eight unsupported syntax/context probes reject with expected codes |
| Compiler and host ownership | Two diagrams and source-pinned contract references in the decision record |
| Host/context gaps | Raw-target normalization, field instance fidelity, body bytes, trailers, request association, opaque keys, wall time, cancellation and replay addressed individually |
| Target matrix | Node/Fastly, JS/Native kept separate; no provider or complete Native HMS application qualified |
| Minimal change set | Proposed package sidecar, synchronized bridge, Node authority adapter and separate qualification; no broad compiler expansion or public generic signing required |
| HMS-08 gate | No-go checkpoint; conditional HMAC bridge proposal requires explicit human approval of trust, snapshot and secret/lifetime boundaries |

The protocol still executes in JavaScript in both crypto tests. The compiled
8,535-byte Wasm is only the existing Crypto primitive, selected by a synthetic
explicit plan. Its SHA-256 is
`e5d7d3c12a743c97877a814df33d22dfdbe6564d606497c05b9761421877fb71`.
The verifier's observed linear-memory growth is recorded, not treated as a
production allocation/concurrency guarantee. No full Pulse project emission,
socket adapter, Fastly, Viceroy, deployed service or durable replay store is
claimed. The source graph's incomplete sample call is never executed.

## Validation

Node **24.19.0**, npm **11.9.0**. Isolated probe tools match the pinned Pulse
lockfile: TypeScript **5.9.3**, AssemblyScript **0.28.18**, Binaryen
**129.0.0-nightly.20260428**, long **5.3.2**. All 332 source-file Git blob
identities are checked before and after execution. The reproduced receipt is
deterministic. Both backend paths, every expected diagnostic and the deadline
late-result check pass. Root suite: **863/863 tests pass**; syntax/export/contract
checks and diff checks pass. The original spike and six-test file retain their
HMS-00 hashes. No protocol source changed, so existing algorithm/body/work
receipts retain their scope.

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm ci --prefix spikes/hms-07/toolchain --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node --check spikes/hms-07/run.mjs
node spikes/hms-07/run.mjs --pulse-root /path/to/pinned-pulse --out /tmp/hms07.json
cmp /tmp/hms07.json docs/evidence/hms-07-feasibility.json
git diff --check
```

See [the spike README](../spikes/hms-07/README.md) for the complete clean-checkout
recipe and source acquisition details. Root CI retains its existing package and
interoperability gates; the optional cross-repository probe is run explicitly.
Pulse mutation gates do not apply to this read-only source investigation; no
Pulse release/support gate result is claimed.

Known failures are the expected, recorded Native admission and context
refusals. There are no unexpected failures in the declared probe subset.
Next dependency: human architectural approval of the bounded HMS-08 proposal,
followed by separate Pulse PRs against `latest` and target-specific qualification.
