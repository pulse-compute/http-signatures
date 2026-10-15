// Explicit Node reference composition. This public fixture key is not a secret.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import profile from './profiles/hmac-request.json' with { type: 'json' };
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { createHmacSigner, createHmacVerifier } from '@pulse-compute/http-signatures/webcrypto';

const unwrap = result => { assert.equal(result.ok, true, result.code); return result.value; };
const key = await webcrypto.subtle.importKey('raw', Uint8Array.from({ length: 32 }, (_, i) => i),
  { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const binding = { subtle: webcrypto.subtle, key, keyId: 'example-key', keyVersion: 'fixture-v1', trustDomain: 'example' };
const signer = unwrap(createHmacSigner(binding)), verifier = unwrap(createHmacVerifier(binding));
const clock = { nowSeconds: () => 1000 }; // Host-owned trusted time, fixed for reproducibility.
const available = value => ({ state: 'available', value });
const bytes = text => new TextEncoder().encode(text);
// A real host adapter must establish this snapshot's provenance and completeness.
const message = { kind: 'request', contextId: 'example-1', direction: 'outbound', trustDomain: 'example',
  headers: available([]), trailers: available([]), body: { state: 'available', bytes: new Uint8Array() },
  method: available('GET'), target: {
    original: available({ form: 'origin', raw: bytes('/resource') }), uri: available('https://example.com/resource'),
    scheme: available('https'), authority: available('example.com'), path: available('/resource'), query: available(''),
  } };
const parameters = [
  { name: 'created', value: 1000 }, { name: 'expires', value: 1060 },
  { name: 'keyid', value: 'example-key' }, { name: 'alg', value: 'hmac-sha256' }, { name: 'tag', value: 'example-http' },
];
const signed = unwrap(await sign(message, { profile, covered: profile.requiredComponents, parameters, capabilities: { signer, clock } }));
const received = structuredClone(message);
received.direction = 'inbound'; // Set by the receiving adapter, never a wire field.
received.headers.value.push({ name: 'Signature-Input', value: bytes(signed.signatureInput) }, { name: 'Signature', value: bytes(signed.signature) });
const receivingProfile = { ...profile, context: { ...profile.context, direction: 'inbound' } };
const keys = { id: 'example-local', async resolve(query) {
  return query.keyId === binding.keyId && query.algorithm === 'hmac-sha256' &&
    query.trustDomain === binding.trustDomain && query.profileId === profile.id ? verifier : null;
} };
const verified = unwrap(await verify(received, { profile: receivingProfile, capabilities: { keys, clock } }));
console.log(JSON.stringify(verified, null, 2));
