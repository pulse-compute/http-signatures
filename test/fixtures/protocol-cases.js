import { webcrypto } from 'node:crypto';
import { signatureBaseLimits } from '../../src/signature-base.js';
import { createHmacSigner, createHmacVerifier } from '../../src/webcrypto.js';
import { request, response, component, field } from './base-cases.js';

// Fixed public fixture material, never a production key.
export const rawKey = Uint8Array.from({ length: 32 }, (_, i) => i);
const key = await webcrypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
export const backend = {
  signer: createHmacSigner({ subtle: webcrypto.subtle, key, keyId: 'test-key', keyVersion: 'v1', trustDomain: 'test' }).value,
  verifier: createHmacVerifier({ subtle: webcrypto.subtle, key, keyId: 'test-key', keyVersion: 'v1', trustDomain: 'test' }).value,
};
export function profile(kind = 'request', direction = 'outbound') {
  return { contractVersion: 1, id: 'hmac-' + kind + '-v1', label: 'sig1',
    context: { kind, direction, trustDomain: 'test', scheme: 'https', authority: 'example.com' },
    requiredComponents: kind === 'request' ? [component('@method'), component('@target-uri')] :
      [component('@status'), component('@method', ['req']), component('@target-uri', ['req'])],
    structuredFields: {}, allowedAlgorithms: ['hmac-sha256'],
    keyPolicy: { resolverId: 'test-resolver', acceptedKeyIds: ['test-key'] },
    time: { requireCreated: true, requireExpires: true, maxAgeSeconds: 60, maxLifetimeSeconds: 60, clockSkewSeconds: 5 },
    requiredTag: 'test-domain', body: { mode: 'excluded' }, replay: { mode: 'none' }, limits: { ...signatureBaseLimits } };
}
export const parameters = () => [
  { name: 'created', value: 1000 }, { name: 'expires', value: 1060 },
  { name: 'keyid', value: 'test-key' }, { name: 'alg', value: 'hmac-sha256' }, { name: 'tag', value: 'test-domain' },
];
export function setup(kind = 'request') {
  const message = kind === 'request' ? request() : response(); message.direction = 'outbound';
  const p = profile(kind), counts = { clock: 0, sign: 0, resolve: 0, verify: 0 }, queries = [], bases = [];
  const signer = { ...backend.signer, sign(base) { counts.sign++; bases.push(new Uint8Array(base)); return backend.signer.sign(base); } };
  const verifier = { ...backend.verifier, verify(base, sig) { counts.verify++; bases.push(new Uint8Array(base)); return backend.verifier.verify(base, sig); } };
  const clock = { nowSeconds() { counts.clock++; return 1000; } };
  const keys = { id: 'test-resolver', resolve(q) { counts.resolve++; queries.push(q); return verifier; } };
  return { message, profile: p, covered: [...p.requiredComponents, component('date'), component('content-type')], parameters: parameters(),
    signer, verifier, clock, keys, counts, queries, bases };
}
export const signOptions = h => ({ profile: h.profile, covered: h.covered, parameters: h.parameters,
  capabilities: { signer: h.signer, clock: h.clock } });
export const verifyOptions = h => ({ profile: h.profile, capabilities: { keys: h.keys, clock: h.clock } });
export function install(message, signed) {
  const result = structuredClone(message);
  result.headers.value.push(field('Signature-Input', signed.signatureInput), field('Signature', signed.signature));
  return result;
}
