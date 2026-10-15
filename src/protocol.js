/** Experimental fixed-algorithm profile. All authority, clock and crypto are explicit. */
import { snapshot, buildBase } from './base-engine.js';
import { BaseFailure, fail, record, need } from './base-support.js';
import { checkBody } from './content-integrity.js';
import { normalizeAuthority } from './target.js';
import { parseSignatureEnvelope, serializeSignatureInput, serializeSignature } from './signature-fields.js';
import { MAX_TIMESTAMP, validateProfile, capabilities, keyCapability,
  fieldOperation, copyMember, supported, coverage } from './profile.js';

function context(current, p, b) {
  b.spend(current.kind.length + current.direction.length + current.trustDomain.length +
    p.context.kind.length + p.context.direction.length + p.context.trustDomain.length);
  if (current.kind !== p.context.kind || current.direction !== p.context.direction || current.trustDomain !== p.context.trustDomain) fail('CONTEXT_MISMATCH');
  const request = current.kind === 'request' ? current : need(current.request);
  b.spend(request.trustDomain.length + p.context.trustDomain.length);
  if (request.trustDomain !== p.context.trustDomain) fail('CONTEXT_MISMATCH');
  const t = request.target, scheme = need(t.scheme);
  if (scheme !== p.context.scheme || normalizeAuthority(need(t.authority), scheme, b) !== p.context.authority) fail('CONTEXT_MISMATCH');
}
function envelopeSources(message, current, mode, b) {
  const headers = need(current.headers);
  const names = ['signature-input', 'signature'];
  // Check combined raw lengths before parsing normalized HTTP field values.
  // Snapshot already validated the field array and byte types; no callbacks ran.
  const sizes = [0, 0], counts = [0, 0];
  b.spend(message.headers.value.length);
  for (const f of message.headers.value) {
    b.spend(f.name.length * 2); const name = f.name.toLowerCase(), i = names.indexOf(name);
    if (i < 0) continue;
    sizes[i] += f.value.length + (counts[i]++ ? 2 : 0);
    if (sizes[i] > b.limits.envelopeFieldBytes) fail('LIMIT_EXCEEDED');
  }
  if (names.some(n => current.trailers?.has(n))) fail(mode === 'sign' ? 'MALFORMED_MESSAGE' : 'MALFORMED_SIGNATURE');
  if (mode === 'sign') {
    if (names.some(n => headers.has(n))) fail('MALFORMED_MESSAGE');
    return;
  }
  const input = headers.get('signature-input'), signature = headers.get('signature');
  if (!input && !signature) fail('SIGNATURE_NOT_FOUND');
  if (!input || !signature) fail('MALFORMED_SIGNATURE');
  return fieldOperation(parseSignatureEnvelope, { signatureInput: input, signature }, b).value;
}
function metadata(value, p, clock, b) {
  b.spend(value.parameters.length + p.requiredTag.length + 1);
  for (const param of value.parameters) b.spend(param.name.length + String(param.value).length * 2);
  const meta = new Map(value.parameters.map(p => [p.name, p.value]));
  for (const k of ['created', 'keyid', 'alg', 'tag']) if (!meta.has(k) || meta.get(k) === '') fail('METADATA_REQUIRED');
  if (meta.get('tag') !== p.requiredTag || ((meta.has('nonce') || p.replayMode === 'required') && !meta.get('nonce')) || (p.time.requireExpires && !meta.has('expires'))) fail('METADATA_REQUIRED');
  const created = meta.get('created'), expires = meta.get('expires');
  let n; try { n = clock(); } catch { fail('OPERATION_FAILED'); }
  if (!Number.isSafeInteger(n) || n < 0 || n > MAX_TIMESTAMP) fail('OPERATION_FAILED');
  const add = (a, z) => { const sum = a + z; if (!Number.isSafeInteger(sum)) fail('TIME_INVALID'); return sum; };
  const { maxAgeSeconds: age, maxLifetimeSeconds: life, clockSkewSeconds: skew } = p.time;
  if (created < 0 || created > add(n, skew) || n > add(add(created, age), skew)) fail('TIME_INVALID');
  if (expires !== undefined && (expires < created || expires > add(created, life) || n > add(expires, skew))) fail('TIME_INVALID');
  const retainUntilSeconds = add(Math.min(add(created, age), expires ?? Infinity), skew);
  return { meta, retainUntilSeconds };
}
function matchKey(key, keyId, p, b) {
  b.spend(keyId.length * 2 + key.keyId.length + key.algorithm.length + key.trustDomain.length + p.context.trustDomain.length);
  if (!p.acceptedKeyIds.has(keyId) || key.keyId !== keyId || key.algorithm !== p.algorithm || key.signatureBytes !== p.signatureBytes || key.trustDomain !== p.context.trustDomain) fail('KEY_REJECTED');
}
function validateSelected(current, value, p, b) {
  b.spend(value.parameters.length + p.algorithm.length + 2);
  const alg = value.parameters.find(p => p.name === 'alg');
  if (alg && alg.value !== p.algorithm) fail('UNSUPPORTED_ALGORITHM');
  supported(value.components, current.kind, b.types, b);
  context(current, p, b); coverage(p.requiredComponents, value.components, b);
}
function init(options, mode) {
  try { record(options, mode === 'sign' ? ['profile', 'covered', 'parameters', 'capabilities'] : ['profile', 'capabilities']); }
  catch { fail('PROFILE_INVALID'); }
  const { profile: p, b } = validateProfile(options.profile);
  return { p, b, caps: capabilities(options.capabilities, mode, p, b) };
}
const FAILURE_CODES = new Set(['PROFILE_INVALID', 'LIMIT_EXCEEDED', 'MALFORMED_MESSAGE', 'MALFORMED_SIGNATURE',
  'SIGNATURE_NOT_FOUND', 'UNSUPPORTED_COMPONENT', 'UNSUPPORTED_ALGORITHM', 'CONTEXT_MISMATCH',
  'COMPONENT_UNAVAILABLE', 'COMPONENT_MISSING', 'COVERAGE_REQUIRED', 'METADATA_REQUIRED', 'TIME_INVALID',
  'CAPABILITY_UNAVAILABLE', 'KEY_REJECTED', 'SIGNATURE_INVALID', 'BODY_DIGEST_INVALID', 'REPLAY_REJECTED', 'OPERATION_FAILED']);
const failure = error => ({ ok: false, code: error instanceof BaseFailure && FAILURE_CODES.has(error.code) ? error.code : 'OPERATION_FAILED' });
async function invoke(fn, ...args) {
  try { return await fn(...args); } catch { fail('OPERATION_FAILED'); }
}

export async function sign(message, options) {
  try {
    const { p, b, caps } = init(options, 'sign'), current = snapshot(message, b, false, p.bodyMode === 'required');
    envelopeSources(message, current, 'sign', b);
    const supplied = { components: options.covered, parameters: options.parameters };
    b.serialize(supplied); const value = copyMember(supplied, b);
    validateSelected(current, value, p, b);
    const { meta } = metadata(value, p, caps.clock, b), base = buildBase(current, value, b);
    matchKey(caps.signer, meta.get('keyid'), p, b);
    const signatureInput = fieldOperation(serializeSignatureInput, [{ label: p.label, ...value }], b).value;
    b.spend(p.signatureBytes);
    const template = fieldOperation(serializeSignature, [{ label: p.label, signature: new Uint8Array(p.signatureBytes) }], b);
    // Reserve the exact second serialization cost and result copy before crypto.
    // The profile fixes output size; all values take the same writer path.
    b.spend(template.workUnits + p.signatureBytes);
    if (signatureInput.length > b.limits.fieldValueBytes || template.value.length > b.limits.fieldValueBytes ||
        b.fields + 2 > b.limits.fieldCount || b.fieldBytes + 24 + signatureInput.length + template.value.length > b.limits.totalFieldBytes) fail('LIMIT_EXCEEDED');
    if (p.bodyMode === 'required') await checkBody(current, b, caps.digest);
    const output = await invoke(caps.signer.call, base);
    if (!(output instanceof Uint8Array) || output.length !== p.signatureBytes) fail('OPERATION_FAILED');
    const signature = serializeSignature([{ label: p.label, signature: new Uint8Array(output) }],
      { limits: { envelopeFieldBytes: b.limits.envelopeFieldBytes, labelBytes: b.limits.labelBytes, signatureBytes: p.signatureBytes, workUnits: template.workUnits } });
    if (!signature.ok || signature.workUnits !== template.workUnits) fail('OPERATION_FAILED');
    return { ok: true, value: { signatureInput, signature: signature.value } };
  } catch (error) { return failure(error); }
}

export async function verify(message, options) {
  try {
    const { p, b, caps } = init(options, 'verify'), current = snapshot(message, b, false, p.bodyMode === 'required');
    const envelope = envelopeSources(message, current, 'verify', b);
    b.spend(envelope.inputs.length + envelope.signatures.length);
    const input = envelope.inputs.find(e => e.label === p.label);
    if (!input) fail('SIGNATURE_NOT_FOUND');
    const signature = envelope.signatures.find(e => e.label === p.label).signature;
    if (signature.length !== p.signatureBytes) fail('MALFORMED_SIGNATURE');
    const value = { components: input.components, parameters: input.parameters };
    validateSelected(current, value, p, b);
    const { meta, retainUntilSeconds } = metadata(value, p, caps.clock, b), base = buildBase(current, value, b), keyId = meta.get('keyid');
    b.spend(keyId.length);
    if (!p.acceptedKeyIds.has(keyId)) fail('KEY_REJECTED');
    // All message/policy data is owned before awaiting resolver/crypto. Capture
    // the result coverage before callbacks; no caller object is re-read later.
    const covered = copyMember(value, b).components;
    let replayEntry;
    if (p.replayMode === 'required') {
      b.spend(p.replayNamespace.length + p.id.length + p.context.trustDomain.length + keyId.length + meta.get('nonce').length + 6);
      replayEntry = { namespace: p.replayNamespace, profileId: p.id, trustDomain: p.context.trustDomain,
        keyId, nonce: meta.get('nonce'), retainUntilSeconds };
    }
    const capability = await invoke(caps.resolve, { keyId, algorithm: p.algorithm, trustDomain: p.context.trustDomain, profileId: p.id });
    if (capability === null) fail('KEY_REJECTED');
    const key = keyCapability(capability, 'verify', b); matchKey(key, keyId, p, b);
    const valid = await invoke(key.call, base, signature);
    if (typeof valid !== 'boolean') fail('OPERATION_FAILED');
    if (!valid) fail('SIGNATURE_INVALID');
    if (p.bodyMode === 'required') await checkBody(current, b, caps.digest);
    if (replayEntry) {
      const consumed = await invoke(caps.consume, replayEntry);
      if (typeof consumed !== 'boolean') fail('OPERATION_FAILED');
      if (!consumed) fail('REPLAY_REJECTED');
    }
    return { ok: true, value: { contextId: current.contextId, profileId: p.id, label: p.label,
      keyId, keyVersion: key.keyVersion, algorithm: p.algorithm, covered,
      bodyIntegrity: p.bodyMode === 'required' ? 'verified' : 'not-checked',
      replay: p.replayMode === 'required' ? 'consumed' : 'not-checked' } };
  } catch (error) { return failure(error); }
}
