# HMS-08 — approved runtime/host contract

**Approved and implemented for the first Node profile.** The user explicitly
accepted the generic versioned runtime/host expansion. This document preserves
the decision rationale and pre-extension evidence; the concrete implementation
and limits are in [Pulse usage](pulse-native.md) and [HMS-08 evidence](hms-08.md).

## What is already settled

[Pulse #366](https://github.com/pulse-compute/pulse/pull/366) raises HMAC signing
input to 65,536 bytes. [Pulse #367](https://github.com/pulse-compute/pulse/pull/367)
admits trusted external lowerers by versioned contracts, without monorepo package
registration, synchronized npm versions or a special external-package pin.

The earlier HMS-07 synchronized first-party bridge proposal is superseded.
`http-signatures` should own its facade, manifest, builder, Native protocol
source, policy and fixtures in this independent repository. Pulse should not
contain an HMS package name, RFC parser, signature profile or release entry to
admit it. Ordinary application dependency locking is separate from compiler
compatibility and does not become a Pulse-maintained pin.

## Executed gap evidence

At Pulse merge `c42b23e78d32114b69647f6ea6cc3b2d3150b36a`:

| Boundary | Executed result |
|---|---|
| External lowerer admission | Existing independent-version fixture compiles and executes Native and JavaScript, with equal output |
| Request-owned HMS sign/verify definition | `PULSE_RUNTIME_PACKAGE_EFFECT_UNTRUSTED` |
| Node provider planning for HMS sign/verify | `PULSE_PROVIDER_CAPABILITY_UNSUPPORTED` |
| Provider descriptor declaring a new operation | `PULSE_PROVIDER_CAPABILITY_UNKNOWN` |
| Application-created request context | `PULSE_RUNTIME_PACKAGE_CONTEXT_REQUIRED` |
| Node HTTP adaptation | Retains ordered raw field pairs, but uppercases the method and normalizes dot segments in the target; no original-target member in the adapted record |

The [probe](../spikes/hms-08/check-boundary.mjs) and
[receipt](evidence/hms-08-boundary.json) distinguish expected refusal from success.
They do not compile or execute a Native HMS application. The existing external
lowerer acceptance test is separate from this receipt.

The runtime's `packages/runtime/src/internal/package-runtime.js` still uses
`TRUSTED_PACKAGE_EFFECT_CATALOG`. The provider vocabulary in
`wasm/packages/contracts/src/provider/canonical-provider.js` is also closed.
`packages/provider-node/src/capabilities.js` and the provider dispatchers have
fixed implementations. Build-time trust alone supplies none of the missing
request capture, private key binding or runtime dispatch.

## Approved decision

Extend the trusted-package contract with **statically selected, versioned runtime
bindings and explicit provider-owned host capabilities**. This makes runtime
composition usable by independent packages without adding each package to Pulse.
It is broader than the merged builder-admission change; the user approved it.

| Contract addition | Proposed rule |
|---|---|
| Runtime declaration | A reachable trusted package declares its operation identities, bounded input/result schemas, host requirements and JS/Native realization entries. Paths stay package-contained; package/contract ownership and exact supported protocol versions must match. No scanning unused packages or runtime self-registration. |
| Compiled plan | The compiler seals the selected operation declarations and requirements into the ordinary effect/continuation plan. Unknown versions, ownership collisions, unsupported target realizations and undeclared operations fail before execution. |
| Provider binding | The explicitly selected provider must implement each requested generic host capability. A package declaration cannot create authority; application records cannot mint handles or install providers. No package-specific provider catalog entry is required. |
| HTTP snapshot | A provider captures method, original target, trusted effective scheme/authority, ordered field instances and exact bounded body bytes before lossy adaptation. It exposes a request-owned opaque reference to the operation; unavailable data stays unavailable. |
| Outbound snapshot | The host freezes the intended message and owns the operation reference and returned-field installation. Signing alone does not claim a send; later mutation or transport rewriting invalidates the proof. |
| Key and crypto binding | Local host configuration binds profile/key ID/domain to a private key capability. Wire key IDs never become secret-store names. Reuse existing SHA-256, HMAC-SHA256 and HS256 primitives; key bytes stay in provider/Crypto staging and never enter protocol guest inputs or application values. |
| Time and lifecycle | One trusted wall-time sample per operation; active request identity before and after async boundaries; existing cancellation/timeout settlement and late-result fencing. Neither a JavaScript callback nor Wasm may outlive the request through an untracked task. |
| Native execution | Package protocol logic executes as bounded Wasm with an explicit selected crypto realization. Host code only captures authority, marshals bounded inputs/results and handles effects. No JavaScript protocol or crypto fallback for Native. |
| Reports | Record operation/schema/realization identities and fixed outcomes. Exclude keys, bodies, signature bases and raw sensitive headers. |

The implemented envelopes are `pulse.package-runtime-definition.v1`,
`pulse.package-runtime-binding.v1` and `pulse.package-wasm.v1`.
The implementation must version any changed envelopes and preserve existing
first-party behavior. The initial host realization is Node; unsupported
Fastly cells remain unavailable until separate implementation and qualification.

## First HMS profile

HTTPS requests, HMAC-SHA256, one configured label and local profile; required
`@method`, `@target-uri`, plain `content-digest`, created/expires/keyid/alg/tag;
SHA-256 verification of at most 64 KiB of exact body bytes; base at most 64 KiB;
keys 32–4,096 bytes and 32-byte signatures. Retain bounded field, metadata and
work limits. Reject unknown options and unsupported components explicitly.

Initially select `replay: none` and report `not-checked`; configuring required
replay must fail until a qualified atomic host store is supplied. Response
association, trailers, structured selectors, binary wrapping, query extraction
and asymmetric algorithms remain outside this first Native profile. These
restrictions do not reduce the JavaScript reference's existing profile support.

## Review and implementation split

| Owner / PR | Implemented scope |
|---|---|
| Pulse runtime/contracts | Generic runtime declaration and invocation validation, request ownership, operation admission and bounded results; no HMS identity in core |
| Pulse provider/host/Crypto | Explicit Node snapshot and private crypto capability binding, Native source/crypto composition, cancellation and redaction; separate protected contract review |
| HTTP Signatures | Package facade/manifest/builder and bounded protocol sidecar using those contracts; exact JS/Native positive and negative vectors |
| HMS-09 qualification | Full target matrix, real-host fidelity, memory/time cost, lifecycle and operational evidence; no passing proxy for missing targets |

Required acceptance before calling HMS-08 complete: an independently versioned
package with no core registration compiles the declared Native profile;
unsupported forms refuse predictably; RFC B.2.5 base/MAC matches exactly at the
primitive boundary (it is not itself a strict-profile message); strict-profile
sign/verify and body tampering match JavaScript; forged snapshots, missing
capabilities, wrong key/time, cancellation and late results fail closed; and
unrelated effects/continuations retain their existing semantics.

Adding HMS to the current fixed catalogs would introduce the per-package
monorepo awareness the user excluded. Reading secrets into application values,
relabeling HMS as JWT/Crypto, or reconstructing original bytes from normalized
URLs would cross existing authority boundaries. None is used here.
