# HMS-08 checkpoint — contract expansion required

**Incomplete.** This PR completes the README request and prepares the concrete
runtime/host contract decision that blocks Native implementation. It does not
claim the HMS-08 compile, byte parity or host-authority acceptance criteria.

Repository: `pulse-compute/http-signatures`.
Integration branch: `hms-08/host-contract`, based on the open HMS-07 PR #8 at
`00b9f4e87a9c70ceb40142eb7c9b5845f1194463`, tree
`ef115a1a9bb818ff4f151ccfcca4bc18b814582e`.
PR target: `main`, explicitly stacked on #8; human merge only.
Final head/tree/PR URL and validation are recorded in the PR body.
Pulse inspected: merged prerequisites at
`c42b23e78d32114b69647f6ea6cc3b2d3150b36a`, tree
`5da4aa501ed2b7d725d3455064bb0de9a5627392`.

## Changes

- README rewritten around the current `/protocol` API, with Usage immediately
  after the introduction, short sign/verify snippets, complete linked setup,
  body/replay examples, concise entry-point reference and honest target status.
- HMAC example split into explicit host fixture setup and the short API flow.
  `test/readme.test.js` executes the actual README snippets, checks their receipt
  and proves a changed method fails verification.
- `spikes/hms-08/check-boundary.mjs` and its reproduction guide demonstrate the
  remaining fixed runtime/provider admission boundary and adapter normalization.
  `docs/evidence/hms-08-boundary.json` records exact observed outcomes.
- [Runtime contract proposal](hms-08-contract.md) specifies generic external
  package binding, provider-owned snapshots, private crypto and request lifetime,
  preserving independent package ownership without monorepo registration.
- Current capability documentation identifies the merged prerequisites and the
  remaining decision; HMS-07 findings retain their original evidence scope.

Protocol source, package exports/dependencies, recovered spike hashes, Pulse
source, runtime contracts, provider operations, ABI and release metadata are
unchanged. The new example setup is development-only, like existing examples.

## Ownership and decision

The user approved trusted external lowering and 64 KiB HMAC, while explicitly
reserving expansion of the contract for discussion. The remaining change adds
runtime/provider authority beyond build-time lowering. The Library HMS-08 stop
condition independently requires a separate decision for a new provider
operation or ABI. No additional approval of build-dependency trust is requested.

The package owns protocol/Native source and fixtures. Pulse runtime/provider
owners must review the generic operation, capture and authority contracts.
Crypto continues to own primitives and private key staging. No new primitive is
proposed. The generic contract is recommended instead of registering this
package in fixed Pulse catalogs.

## Validation scope

Node 24.19.0: package/contract checks pass, **864/864 reference tests pass**
(including the exact README snippets), and all three existing examples pass.
Commands:

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node examples/hmac.mjs
node examples/webhook.mjs
node examples/asymmetric.mjs
node --check spikes/hms-08/check-boundary.mjs
node spikes/hms-08/check-boundary.mjs --pulse-root /path/to/pulse --out /tmp/hms08-boundary.json
cmp /tmp/hms08-boundary.json docs/evidence/hms-08-boundary.json
git diff --check
```

New documentation links resolve and diff checks pass. No unexpected failure
remains in the exercised checks.
The optional boundary probe requires seven exact refusals and one normalization
observation. Pulse's existing `external-lowerers` acceptance test independently
passes Native/JavaScript execution and contract rejection at the pinned tree.
Its command is `node wasm/test/contracts/assert-external-lowerers.cjs` from the
prepared Pulse checkout. Neither receipt is a full Pulse release qualification.

No RFC implementation changes are made. Existing RFC 9421 B.2.4/B.2.5, RFC 8941
and RFC 9530 coverage retains its JavaScript scope. No Native HMS compile,
sign/verify, cancellation, private-memory or real-host qualification is claimed.
Node/Fastly HMS integration cells remain unavailable. Expected refusals are the
blocker evidence; unexpected validation failures must be reported in the PR.

Next dependency: discuss and approve the proposed generic runtime/host contract,
then implement it in separately scoped Pulse PRs and finish the package-owned
Native realization before HMS-09 qualification.
