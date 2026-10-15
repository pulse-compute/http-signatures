/** Internal closed profile validation and bounded policy helpers. */
import { Budget, signatureBaseLimits } from './base-engine.js';
import { BaseFailure, fail, record, array, ascii } from './base-support.js';
import { normalizeAuthority } from './target.js';
import { signatureFieldLimits } from './signature-fields.js';

export const ALGORITHM = 'hmac-sha256';
export const MAX_TIMESTAMP = 999999999999999;
export function fieldOperation(fn, value, b) {
  if (b.used === b.limits.workUnits) fail('LIMIT_EXCEEDED');
  const limits = {};
  for (const key of Object.keys(signatureFieldLimits)) limits[key] = b.limits[key];
  limits.workUnits -= b.used;
  const result = fn(value, { limits }); b.spend(result.workUnits);
  if (!result.ok) fail(result.code);
  return result;
}
export function copyMember(value, b) {
  b.spend(value.components.length + value.parameters.length);
  return { components: value.components.map(c => {
    b.spend(c.parameters.length);
    return { kind: c.kind, name: c.name, parameters: c.parameters.map(p => ({ name: p.name, value: p.value })) };
  }), parameters: value.parameters.map(p => ({ name: p.name, value: p.value })) };
}
export function identity(c, b) {
  // Inputs have already passed HMS-02 validation; five parameters at most.
  const n = c.name.length + c.parameters.reduce((n, p) => n + p.name.length + String(p.value).length, 0);
  b.spend(n * 4 + 128 + c.parameters.length * c.parameters.length * b.limits.fieldNameBytes);
  return JSON.stringify([c.name, [...c.parameters].sort((a, z) => a.name < z.name ? -1 : a.name > z.name ? 1 : 0).map(p => [p.name, p.value])]);
}
export function supported(components, kind, types, b) {
  for (const c of components) {
    b.spend(1 + c.name.length + c.parameters.length);
    const params = new Map(c.parameters.map(p => [p.name, p.value]));
    if (c.kind === 'field') {
      if (['signature', 'signature-input'].includes(c.name)) fail('UNSUPPORTED_COMPONENT');
      if ((params.has('sf') || params.has('key')) && !types.has(c.name)) fail('UNSUPPORTED_COMPONENT');
      if (params.has('key') && types.get(c.name) !== 'dictionary') fail('UNSUPPORTED_COMPONENT');
    }
    if ((params.has('req') && kind !== 'response') ||
        (c.kind === 'derived' && (c.name === '@status' ? kind !== 'response' : kind === 'response' && !params.has('req')))) fail('CONTEXT_MISMATCH');
  }
}
export function coverage(required, covered, b) {
  const set = new Set(covered.map(c => identity(c, b)));
  for (const c of required) if (!set.has(identity(c, b))) fail('COVERAGE_REQUIRED');
}
export function nonempty(value, b, max = b.limits.metadataStringBytes) {
  ascii(value, max, b); if (!value) fail(); return value;
}
export function validateProfile(input) {
  let b;
  try {
    record(input, ['contractVersion', 'id', 'label', 'context', 'requiredComponents', 'structuredFields',
      'allowedAlgorithms', 'keyPolicy', 'time', 'requiredTag', 'body', 'replay', 'limits']);
    if (input.contractVersion !== 1) fail();
    record(input.limits, Object.keys(signatureBaseLimits));
    if (input.limits.signatureBytes !== 32) fail();
    b = new Budget({ limits: input.limits, structuredFields: input.structuredFields });
    nonempty(input.id, b); nonempty(input.requiredTag, b);
    ascii(input.label, b.limits.labelBytes, b, /^[a-z*][a-z0-9_.*-]*$/);
    record(input.context, ['kind', 'direction', 'trustDomain', 'scheme', 'authority']);
    const ctx = input.context;
    if (!['request', 'response'].includes(ctx.kind) || !['inbound', 'outbound'].includes(ctx.direction) || ctx.scheme !== 'https') fail();
    nonempty(ctx.trustDomain, b); nonempty(ctx.authority, b, b.limits.targetBytes);
    const context = { kind: ctx.kind, direction: ctx.direction, trustDomain: ctx.trustDomain,
      scheme: 'https', authority: normalizeAuthority(ctx.authority, 'https', b) };
    if (!Array.isArray(input.allowedAlgorithms) || input.allowedAlgorithms.length !== 1) fail();
    array(input.allowedAlgorithms, 1, b);
    if (input.allowedAlgorithms[0] !== ALGORITHM) fail();
    record(input.keyPolicy, ['resolverId', 'acceptedKeyIds']); nonempty(input.keyPolicy.resolverId, b);
    array(input.keyPolicy.acceptedKeyIds, 32, b); if (!input.keyPolicy.acceptedKeyIds.length) fail();
    const keys = new Set();
    for (const key of input.keyPolicy.acceptedKeyIds) {
      nonempty(key, b); b.spend(key.length); if (keys.has(key)) fail(); keys.add(key);
    }
    record(input.time, ['requireCreated', 'requireExpires', 'maxAgeSeconds', 'maxLifetimeSeconds', 'clockSkewSeconds']);
    const t = input.time;
    if (t.requireCreated !== true || typeof t.requireExpires !== 'boolean') fail();
    for (const k of ['maxAgeSeconds', 'maxLifetimeSeconds', 'clockSkewSeconds']) {
      if (!Number.isSafeInteger(t[k]) || t[k] < 0) fail();
    }
    if (t.maxLifetimeSeconds > t.maxAgeSeconds || !Number.isSafeInteger(t.maxAgeSeconds + t.clockSkewSeconds)) fail();
    record(input.body, ['mode'], ['algorithm']);
    if (input.body.mode === 'required') { if (input.body.algorithm !== 'sha-256') fail(); }
    else if (input.body.mode !== 'excluded' || Object.hasOwn(input.body, 'algorithm')) fail();
    record(input.replay, ['mode'], ['namespace']);
    if (input.replay.mode === 'required') nonempty(input.replay.namespace, b);
    else if (input.replay.mode !== 'none' || Object.hasOwn(input.replay, 'namespace')) fail();
    const value = { components: input.requiredComponents, parameters: [] };
    b.serialize(value); if (!value.components.length) fail();
    supported(value.components, context.kind, b.types, b);
    const binding = context.kind === 'request' ? ['@method', '@target-uri'] : ['@status', '@method', '@target-uri'];
    const required = binding.map(name => ({ kind: 'derived', name,
      parameters: context.kind === 'response' && name !== '@status' ? [{ name: 'req', value: true }] : [] }));
    if (input.body.mode === 'required') required.push({ kind: 'field', name: 'content-digest', parameters: [] });
    coverage(required, value.components, b);
    return { b, profile: { id: input.id, label: input.label, context, requiredTag: input.requiredTag,
      requiredComponents: copyMember(value, b).components, acceptedKeyIds: keys, resolverId: input.keyPolicy.resolverId,
      time: { ...t }, bodyMode: input.body.mode, replayMode: input.replay.mode } };
  } catch (error) {
    if (error instanceof BaseFailure && error.code === 'LIMIT_EXCEEDED') throw error;
    fail('PROFILE_INVALID');
  }
}
export function keyCapability(cap, operation, b) {
  try {
    record(cap, ['keyId', 'algorithm', 'trustDomain', 'keyVersion', 'keyBits', operation]);
    for (const name of ['keyId', 'trustDomain', 'keyVersion']) nonempty(cap[name], b);
    if (cap.algorithm !== ALGORITHM || !Number.isSafeInteger(cap.keyBits) || cap.keyBits < 256) fail();
    if (typeof cap[operation] !== 'function') fail('CAPABILITY_UNAVAILABLE');
    // Capture metadata and callback identity before any subsequent callback/await.
    return { keyId: cap.keyId, algorithm: cap.algorithm, trustDomain: cap.trustDomain,
      keyVersion: cap.keyVersion, keyBits: cap.keyBits, call: cap[operation].bind(cap) };
  } catch (error) {
    if (error instanceof BaseFailure && ['LIMIT_EXCEEDED', 'CAPABILITY_UNAVAILABLE'].includes(error.code)) throw error;
    fail('KEY_REJECTED');
  }
}
export function capabilities(caps, mode, p, b) {
  try {
    record(caps, [mode === 'sign' ? 'signer' : 'keys', 'clock'], mode === 'sign' ? ['digest'] : ['digest', 'replay']);
    record(caps.clock, ['nowSeconds']); if (typeof caps.clock.nowSeconds !== 'function') fail();
    if (p.bodyMode !== 'excluded' || p.replayMode !== 'none') fail(); // HMS-05, never downgrade
    const clock = caps.clock.nowSeconds.bind(caps.clock);
    if (mode === 'sign') return { clock, signer: keyCapability(caps.signer, 'sign', b) };
    record(caps.keys, ['id', 'resolve']);
    nonempty(caps.keys.id, b);
    if (caps.keys.id !== p.resolverId || typeof caps.keys.resolve !== 'function') fail();
    return { clock, resolve: caps.keys.resolve.bind(caps.keys) };
  } catch (error) {
    if (error instanceof BaseFailure && ['LIMIT_EXCEEDED', 'KEY_REJECTED'].includes(error.code)) throw error;
    fail('CAPABILITY_UNAVAILABLE');
  }
}
