# HMS-08 runtime boundary reproduction

This checkpoint reproduces why the approved external-lowerer and 64 KiB HMAC
changes are necessary but insufficient for the Native HMS bridge. It changes no
Pulse sources and does not implement an HMS runtime adapter.

Use Node 24.19.0 and a prepared Pulse checkout at
`c42b23e78d32114b69647f6ea6cc3b2d3150b36a`, tree
`5da4aa501ed2b7d725d3455064bb0de9a5627392`. A local mirror with this exact tree is
also accepted. The probe checks tree identity and unchanged tracked files before
and after execution. From that Pulse checkout, follow its pinned toolchain setup:

```sh
corepack pnpm install --frozen-lockfile --ignore-scripts
corepack pnpm build
node wasm/test/contracts/assert-external-lowerers.cjs
```

The last command is Pulse's existing independent-package acceptance test. It
compiles and executes a header helper through Native and JavaScript and checks
nested dependency resolution and invalid contracts. It does not exercise HMS.

Then, from this repository:

```sh
node --check spikes/hms-08/check-boundary.mjs
node spikes/hms-08/check-boundary.mjs --pulse-root /path/to/pulse --out /tmp/hms08-boundary.json
cmp /tmp/hms08-boundary.json docs/evidence/hms-08-boundary.json
```

Seven assertions require the exact runtime/provider/context refusal codes. An
eighth assertion observes Node's lossy method/target adaptation while confirming
that raw header pairs are retained. A changed diagnostic, newly admitted
operation or changed adaptation fails this checkpoint for re-evaluation.

Only public fixture values are used. The JSON stores fixed codes and booleans,
not requests, secret values, body bytes or signature bases. The fixture's
`ack` result is only an admission probe, not a proposed HMS result ABI. This
check does not test a network socket, Native HMS artifact, Fastly, cancellation,
body ownership or crypto staging. Those remain implementation acceptance work
under the [proposed contract](../../docs/hms-08-contract.md).
