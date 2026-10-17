'use strict';
module.exports = Object.freeze({
  version: 'pulsewasm.lowerable-library-manifest.v2', kind: 'pulsewasm.lowerable-library-manifest',
  contractId: 'pulse.http-signatures', npmPackage: '@pulse-compute/http-signatures',
  lowerableSubpath: '@pulse-compute/http-signatures/pulse',
  facade: { namespace: 'signatures', import: '@pulse-compute/http-signatures/pulse', symbols: ['sign', 'verify'] },
  publicApi: { package: '@pulse-compute/http-signatures', symbols: ['signatures', 'sign', 'verify'], compatibilitySubpaths: [], loweringIntentionallyNarrow: true },
  compiler: { version: 'pulsewasm.lowerable-compiler-builder.v1', entry: './pulsewasm.compiler.cjs', export: 'build',
    builderOwner: '@pulse-compute/http-signatures', trust: 'build-dependency' },
  modes: { typescript: { entry: './src/pulse.js' }, jsEngine: { entry: './src/pulse.js', behavior: 'javascript-package-runtime' },
    wasm: { mode: 'wasm-sidecar', sidecar: './as/protocol.ts', hostCapabilities: [], lowerings: [
      { tsSymbol: 'signatures.sign', asSymbol: 'start', hostCapabilities: [] },
      { tsSymbol: 'signatures.verify', asSymbol: 'start', hostCapabilities: [] },
    ] } },
  policy: { packageOwnsFacadeMapping: true, automaticFallback: false, loweringIntentionallyNarrow: true },
});
