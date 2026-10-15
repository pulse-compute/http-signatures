import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, sign as primitiveSign, constants } from 'node:crypto';
import { algorithmCases, binding } from './fixtures/algorithm-cases.js';
import keys from './fixtures/rfc9421-crypto.json' with { type: 'json' };

const fake = (c, operation) => ({ type: operation === 'sign' ? 'private' : 'public', usages: [operation],
  algorithm: c.name === 'p256' ? { name: 'ECDSA', namedCurve: 'P-256' } :
    { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' }, modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) } });
const rejects = promise => assert.rejects(promise, e => e.code === 'OPERATION_FAILED' && !String(e).includes('secret'));
for (const c of algorithmCases) for (const [name, mutate] of [
  ['private verifier/public signer', k => { k.type = 'secret'; }], ['missing usage', k => { k.usages = []; }],
  ['primitive mixup', k => { k.algorithm.name = 'HMAC'; }],
  ['wrong curve/hash', k => { if (c.name === 'p256') k.algorithm.namedCurve = 'P-384'; else k.algorithm.hash.name = 'SHA-512'; }],
]) for (const operation of ['sign', 'verify']) test(`${c.algorithm} ${operation} rejects ${name}`, () => {
  const key = fake(c, operation); mutate(key); const factory = operation === 'sign' ? c.signer : c.verifier;
  assert.deepEqual(factory({ ...binding(c, operation), key }), { ok: false, code: 'KEY_REJECTED' });
});
for (const [name, mutate] of [
  ['1024 bits', k => k.algorithm.modulusLength = 1024], ['8192 bits', k => k.algorithm.modulusLength = 8192],
  ['non-whole bits', k => k.algorithm.modulusLength = 2048.5], ['unknown size', k => k.algorithm.modulusLength = 2056],
  ['exponent 3', k => k.algorithm.publicExponent = Uint8Array.of(3)], ['untyped exponent', k => k.algorithm.publicExponent = [1, 0, 1]],
  ['oversize exponent', k => k.algorithm.publicExponent = Uint8Array.of(0, 1, 0, 1)], ['RSA-PSS key', k => k.algorithm.name = 'RSA-PSS'],
]) test('RSA key policy rejects ' + name, () => {
  const c = algorithmCases[1], key = fake(c, 'verify'); mutate(key);
  assert.deepEqual(c.verifier({ ...binding(c, 'verify'), key }), { ok: false, code: 'KEY_REJECTED' });
});
for (const c of algorithmCases) test(`${c.algorithm} capability identity, purpose and explicit backend are enforced`, () => {
  assert.deepEqual(c.signer({ ...binding(c, 'sign'), key: c.publicKey }), { ok: false, code: 'KEY_REJECTED' });
  assert.deepEqual(c.verifier({ ...binding(c, 'verify'), key: c.privateKey }), { ok: false, code: 'KEY_REJECTED' });
  for (const key of [new Uint8Array(32), keys[c.name].private, {}]) assert.deepEqual(c.signer({ ...binding(c, 'sign'), key }), { ok: false, code: 'KEY_REJECTED' });
  assert.deepEqual(c.signer({ ...binding(c, 'sign'), subtle: undefined }), { ok: false, code: 'CAPABILITY_UNAVAILABLE' });
  assert.deepEqual(c.signer({ ...binding(c, 'sign'), keyId: '' }), { ok: false, code: 'KEY_REJECTED' });
  assert.deepEqual(c.signer({ ...binding(c, 'sign'), trustDomain: 'x'.repeat(513) }), { ok: false, code: 'KEY_REJECTED' });
  assert.deepEqual(c.signer({ ...binding(c, 'sign'), extra: true }), { ok: false, code: 'CAPABILITY_UNAVAILABLE' });
});
for (const c of algorithmCases) test(`${c.algorithm} adapter snapshots backend, copies buffers, bounds lengths`, async () => {
  let calls = 0; const subtle = { sign(primitive, key, data) {
    calls++; assert.deepEqual(primitive, c.name === 'p256' ? { name: 'ECDSA', hash: 'SHA-256' } : 'RSASSA-PKCS1-v1_5');
    assert.equal(key, c.privateKey); data[0] = 1; return new ArrayBuffer(c.size);
  } };
  const signer = c.signer({ ...binding(c, 'sign'), subtle }).value; assert.equal(Object.isFrozen(signer), true);
  subtle.sign = () => { throw Error('changed'); }; const base = new Uint8Array(65536);
  assert.equal((await signer.sign(base)).length, c.size); assert.equal(base[0], 0);
  await rejects(signer.sign(new Uint8Array(65537))); await rejects(signer.sign('text')); assert.equal(calls, 1);
  let checks = 0; const verifier = c.verifier({ ...binding(c, 'verify'), subtle: { verify(p, k, sig, data) { checks++; sig[0] = 1; data[0] = 1; return true; } } }).value;
  const sig = new Uint8Array(c.size); assert.equal(await verifier.verify(base, sig), true); assert.equal(sig[0], 0); assert.equal(base[0], 0);
  await rejects(verifier.verify(base, new Uint8Array(c.size - 1))); await rejects(verifier.verify(base, new Uint8Array(c.size + 1))); assert.equal(checks, 1);
});
for (const c of algorithmCases) for (const output of ['array', 'short', 'long', 'truthy', 'throw']) test(`${c.algorithm} sign rejects backend ${output}`, async () => {
  const cap = c.signer({ ...binding(c, 'sign'), subtle: { sign() {
    if (output === 'throw') throw Error('secret');
    if (output === 'array') return new Uint8Array(c.size);
    if (output === 'truthy') return true;
    return new ArrayBuffer(c.size + (output === 'short' ? -1 : 1));
  } } }).value;
  await rejects(cap.sign(new Uint8Array()));
});
for (const c of algorithmCases) for (const output of [0, 1, 'true', {}, undefined]) test(`${c.algorithm} verify result must be boolean (${String(output)})`, async () => {
  const cap = c.verifier({ ...binding(c, 'verify'), subtle: { verify: () => output } }).value;
  await rejects(cap.verify(new Uint8Array(), new Uint8Array(c.size)));
});
for (const c of algorithmCases) test(`${c.algorithm} rejects genuinely wrong key and wrong hash/primitive`, async () => {
  const pair = await webcrypto.subtle.generateKey(c.name === 'p256' ? c.primitive : { ...c.primitive, modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, false, ['sign', 'verify']);
  const base = Uint8Array.of(1, 2, 3), signature = await c.signer(binding(c, 'sign')).value.sign(base);
  assert.equal(await c.verifier({ ...binding(c, 'verify'), key: pair.publicKey }).value.verify(base, signature), false);
  const wrong = primitiveSign(c.name === 'p256' ? 'sha384' : 'sha256', base,
    { key: keys[c.name].private, ...(c.name === 'p256' ? { dsaEncoding: 'ieee-p1363' } : { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }) });
  assert.equal(await c.verifier(binding(c, 'verify')).value.verify(base, wrong), false);
});
test('P-256 DER and zero/out-of-range scalar encodings are not accepted as valid signatures', async () => {
  const c = algorithmCases[0], base = Uint8Array.of(1, 2, 3), verifier = c.verifier(binding(c, 'verify')).value;
  const der = primitiveSign('sha256', base, keys.p256.private); assert.notEqual(der.length, 64); await rejects(verifier.verify(base, der));
  assert.equal(await verifier.verify(base, new Uint8Array(64)), false);
  assert.equal(await verifier.verify(base, new Uint8Array(64).fill(255)), false);
});
test('asymmetric adapters never select ambient global crypto', async () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, get() { throw Error('ambient'); } });
    for (const c of algorithmCases) {
      const signer = c.signer(binding(c, 'sign')).value, verifier = c.verifier(binding(c, 'verify')).value;
      const base = new Uint8Array(); assert.equal(await verifier.verify(base, await signer.sign(base)), true);
    }
  } finally { if (saved) Object.defineProperty(globalThis, 'crypto', saved); else delete globalThis.crypto; }
});
