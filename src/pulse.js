// Request-owned Pulse adapter. Host authority comes from the selected binding.
import runtime from '@pulse-compute/runtime/package';
import profile from '../pulse-profile.cjs';
const bridge = runtime.createPackageRuntime({
  version: 'pulse.package-runtime-definition.v1', package: '@pulse-compute/http-signatures',
  contractId: 'pulse.http-signatures', providerKind: 'package',
  operations: { invoke: { kind: 'package.invoke', capability: 'package.invoke', result: 'string' } },
});
export function sign(ctx, options) { return bridge.effect(ctx, 'invoke', profile.invocation('sign', options)); }
export function verify(ctx, options) { return bridge.effect(ctx, 'invoke', profile.invocation('verify', options)); }
export const signatures = Object.freeze({ sign, verify });
