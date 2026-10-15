import { createHash } from 'node:crypto';
import { setup, signOptions, verifyOptions, install } from './protocol-cases.js';
import { component, field } from './base-cases.js';
import { sign } from '../../src/protocol.js';

export const expectedDigest = content => 'sha-256=:' + createHash('sha256').update(content).digest('base64') + ':';
// Test-only atomic store: one JS turn performs check+insert. No exported registry.
// Use a production host store with atomic insertion, capacity and trusted time.
export function atomicStore(now = () => 1000) {
  const entries = new Map();
  return { entries, consume(entry) {
    const n = now(); if (n > entry.retainUntilSeconds) return false;
    const key = JSON.stringify([entry.namespace, entry.profileId, entry.trustDomain, entry.keyId, entry.nonce]);
    if (entries.has(key) && entries.get(key) >= n) return false;
    entries.set(key, entry.retainUntilSeconds); return true;
  } };
}
export function bodySetup(kind = 'request', replay = true) {
  const h = setup(kind); h.profile.body = { mode: 'required', algorithm: 'sha-256' };
  h.profile.requiredComponents.push(component('content-digest')); h.covered.push(component('content-digest'));
  if (replay) { h.profile.replay = { mode: 'required', namespace: 'test/nonces' }; h.parameters.push({ name: 'nonce', value: 'public-nonce' }); }
  h.message.headers.value = h.message.headers.value.filter(f => f.name.toLowerCase() !== 'content-digest');
  h.message.headers.value.push(field('Content-Digest', expectedDigest(h.message.body.bytes)));
  h.events = []; h.counts.digest = 0; h.counts.consume = 0; h.now = 1000; h.storeNow = 1000;
  for (const [cap, fn] of [[h.signer, 'sign'], [h.keys, 'resolve'], [h.verifier, 'verify']]) {
    const original = cap[fn]; cap[fn] = (...args) => { h.events.push(fn); return original(...args); };
  }
  h.clock.nowSeconds = () => { h.counts.clock++; h.events.push('clock'); return h.now; };
  h.digest = { async sha256(content) { h.counts.digest++; h.events.push('digest'); return new Uint8Array(createHash('sha256').update(content).digest()); } };
  const store = atomicStore(() => h.storeNow); h.entries = store.entries; h.consumed = [];
  h.replay = { async consume(entry) { h.counts.consume++; h.events.push('consume'); h.consumed.push({ ...entry }); return store.consume(entry); } };
  return h;
}
export const bodySignOptions = h => { const o = signOptions(h); o.capabilities.digest = h.digest; return o; };
export const bodyVerifyOptions = h => { const o = verifyOptions(h); o.capabilities.digest = h.digest; o.capabilities.replay = h.replay; return o; };
export function reset(h) { for (const k of Object.keys(h.counts)) h.counts[k] = 0; h.events.length = 0; }
export async function signedBody(kind = 'request', replay = true) {
  const h = bodySetup(kind, replay), result = await sign(h.message, bodySignOptions(h));
  if (!result.ok) throw Error(JSON.stringify(result));
  h.message = install(h.message, result.value); h.signed = result.value; reset(h); return h;
}
// Produce a valid MAC over arbitrary digest syntax without asserting integrity.
export async function signUnchecked(h) {
  const profile = { ...h.profile, body: { mode: 'excluded' } };
  const result = await sign(h.message, { ...bodySignOptions(h), profile });
  if (!result.ok) throw Error(JSON.stringify(result));
  h.message = install(h.message, result.value); reset(h); return h;
}
