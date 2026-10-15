# HMS-07 reproducible feasibility probe

This experiment reads Pulse at `e6a78640928a93f0e41813f55d9847895ea9be41`.
It does not install an HTTP-signatures lowerer, change Pulse sources, add an
application capability, or qualify a provider. The executable assertions cover:

- published RFC B.2.5 sign/verify through the actual internal JS byte seam;
- the unchanged Pulse HMAC AssemblyScript source compiled to Wasm and bound
  through Pulse's existing Native crypto wrapper, with no JS crypto fallback;
- both primitives composed with the **JavaScript** strict protocol, body digest
  and replay hooks, plus changed base/body and duplicate nonce rejection;
- 32,768-byte HMAC signing acceptance and 32,769-byte rejection;
- actual Native source-graph refusal for this unchanged npm package;
- accepted control/header Native plans and exact rejection diagnostics for
  typed arrays, maps, regex, callbacks, try/catch, ordinary awaits and absent
  raw-target/trailer context fields;
- JavaScript source-graph admission/inspection, lowerer catalog exclusion,
  host deadline late-result rejection and Web-platform normalization examples.

Run from a clean checkout of this package. Use Node 24.19.0 and an unchanged
checkout of the exact Pulse revision. The root package keeps zero dependencies;
only this isolated development toolchain needs installation. Its four versions
match the corresponding entries in Pulse's pinned `pnpm-lock.yaml`.

```sh
git clone https://github.com/pulse-compute/pulse.git /tmp/hms07-pulse
git -C /tmp/hms07-pulse checkout --detach e6a78640928a93f0e41813f55d9847895ea9be41
npm ci --prefix spikes/hms-07/toolchain --ignore-scripts --no-audit --no-fund
node spikes/hms-07/run.mjs \
  --pulse-root /tmp/hms07-pulse \
  --out /tmp/hms-07-feasibility.json
```

`--toolchain-root /absolute/path` can select another directory with these exact
four installed versions. The runner creates temporary package-resolution links,
transpiles four original Crypto TypeScript modules into a private test directory,
compiles the original HMAC source, runs the probes, then removes its temporary
files. It does not build, install into, or write source under the Pulse checkout.
Native crypto receives an explicit synthetic realization selection, not an
application plan emitted by a lowerer. The graph probe intentionally supplies
an incomplete call; it tests admission, never execution of that handler.

The [source pin](pulse-source-pin.json) contains Git blob identities for all 332
retrieved source/contract files. The runner verifies them before and after the
experiment. A full checkout works; a sparse source snapshot containing all
listed files also works. The captured run used a GitHub API snapshot after Git
transport lacked credentials. No source was substituted or edited to make a
probe pass. Retry-only source retrieval failures occurred before execution;
all final bytes passed the Git-object identity check.

Recorded evidence: [feasibility receipt](../../docs/evidence/hms-07-feasibility.json).
It contains no real keys, body content or sensitive headers. The public RFC key
is identified in the script and covered by the existing
[RFC fixture attribution](../../test/fixtures/rfc9421-LICENSE.txt).
The 8,535-byte Wasm and its hash are primitive-build observations, not the size
or qualification of a Pulse HTTP-signatures application. The existing verifier
increases linear memory when staging input; the receipt records one call's
before/after values. It is not a peak-memory or safe-concurrency measurement.

A successful exit means all expected passes **and expected refusals** matched.
It does not mean Native package eligibility. Fastly/Viceroy/deployed runs are
absent. Routine package CI remains local and inexpensive; this pinned cross-repo
probe is an explicit investigation command, not a new mandatory network gate.
See [decision and owner gaps](../../docs/pulse-integration.md) before HMS-08.
