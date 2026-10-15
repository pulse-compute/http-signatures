// Runnable reference for both original contract profiles. Public fixture key,
// fixed clock/nonce and a bounded process-local demonstration store only.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import requestProfile from './profiles/request.json' with { type: 'json' };
import responseProfile from './profiles/response.json' with { type: 'json' };
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { createContentDigest } from '@pulse-compute/http-signatures/content-digest';
import { createHmacSigner, createHmacVerifier, createSha256Digest } from '@pulse-compute/http-signatures/webcrypto';

const unwrap = result => { assert.equal(result.ok, true, result.code); return result.value; };
const av = value => ({ state: 'available', value }), bytes = text => new TextEncoder().encode(text);
const field = (name, value) => ({ name, value: bytes(value) });
const digest = unwrap(createSha256Digest({ subtle: webcrypto.subtle }));
const key = await webcrypto.subtle.importKey('raw', Uint8Array.from({ length: 32 }, (_, i) => i),
  { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const clock = { nowSeconds: () => 1000 };
const entries = new Map();
// Check + insert is one synchronous turn. Production stores must provide atomic
// durable consumption across instances, trusted time, bounded capacity and TTLs.
const replay = { async consume(entry) {
  const now = clock.nowSeconds(); if (now > entry.retainUntilSeconds) return false;
  const tuple = JSON.stringify([entry.namespace, entry.profileId, entry.trustDomain, entry.keyId, entry.nonce]);
  for (const [k, expiry] of entries) if (expiry < now) entries.delete(k); // Inclusive retention.
  if (entries.has(tuple) || entries.size >= 16) return false;
  entries.set(tuple, entry.retainUntilSeconds); return true;
} };
async function exchange(message, profile) {
  const binding = { subtle: webcrypto.subtle, key, keyId: profile.keyPolicy.acceptedKeyIds[0],
    keyVersion: 'public-fixture-v1', trustDomain: profile.context.trustDomain };
  const signer = unwrap(createHmacSigner(binding)), verifier = unwrap(createHmacVerifier(binding));
  const parameters = [{ name: 'created', value: 1000 }, { name: 'expires', value: 1060 },
    { name: 'keyid', value: binding.keyId }, { name: 'alg', value: 'hmac-sha256' }, { name: 'tag', value: profile.requiredTag }];
  if (profile.replay.mode === 'required') parameters.push({ name: 'nonce', value: 'public-example-nonce' });
  // Host installs the helper output before signing; sign validates rather than rewrites it.
  message.headers.value.push(field('Content-Digest', unwrap(await createContentDigest(message.body.bytes, { digest, limits: profile.limits }))));
  const outbound = { ...profile, context: { ...profile.context, direction: 'outbound' } };
  const signed = unwrap(await sign(message, { profile: outbound, covered: profile.requiredComponents, parameters, capabilities: { signer, clock, digest } }));
  const incoming = structuredClone(message); incoming.direction = 'inbound';
  incoming.headers.value.push(field('Signature-Input', signed.signatureInput), field('Signature', signed.signature));
  const keys = { id: profile.keyPolicy.resolverId, async resolve(q) {
    return q.profileId === profile.id && q.trustDomain === binding.trustDomain && q.keyId === binding.keyId && q.algorithm === 'hmac-sha256' ? verifier : null;
  } };
  const options = { profile, capabilities: { keys, clock, digest, replay } };
  const receipt = unwrap(await verify(incoming, options));
  console.log(JSON.stringify(receipt));
  if (profile.replay.mode === 'required') {
    assert.deepEqual(await verify(incoming, options), { ok: false, code: 'REPLAY_REJECTED' });
    console.log('Duplicate webhook: REPLAY_REJECTED');
  }
  return incoming;
}
// Illustrative host-authoritative snapshots, not a transport adapter.
const request = { kind: 'request', contextId: 'webhook-1', direction: 'outbound', trustDomain: 'example-webhooks',
  headers: av([field('Content-Type', 'application/json'), field('X-Request-ID', 'request-1')]), trailers: av([]),
  body: { state: 'available', bytes: bytes('{"event":"example"}\n') }, method: av('POST'), target: {
    original: av({ form: 'origin', raw: bytes('/events') }), uri: av('https://webhooks.example.test/events'),
    scheme: av('https'), authority: av('webhooks.example.test'), path: av('/events'), query: av(''),
  } };
const received = await exchange(request, requestProfile);
await exchange({ kind: 'response', contextId: 'response-1', direction: 'outbound', trustDomain: 'example-webhooks',
  headers: av([field('Content-Type', 'application/json')]), trailers: av([]), status: av(200),
  body: { state: 'available', bytes: bytes('{"accepted":true}\n') }, associatedRequest: av(received),
}, responseProfile);
