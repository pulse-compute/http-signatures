import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createHmacSigner, createHmacVerifier } from '../src/webcrypto.js';
import { createSignatureBase } from '../src/signature-base.js';
import { serializeSignature } from '../src/signature-fields.js';
import { appendix } from './fixtures/base-cases.js';

const raw = Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64');
const key = await webcrypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
const options = () => ({ subtle: webcrypto.subtle, key, keyId: 'test-shared-secret', keyVersion: 'rfc-b25', trustDomain: 'rfc-example' });
const fakeKey = () => ({ type: 'secret', algorithm: { name: 'HMAC', hash: { name: 'SHA-256' }, length: 256 }, usages: ['sign', 'verify'] });

test('explicit adapter reproduces RFC 9421 B.2.5 bytes, MAC and field', async () => {
  const v = appendix[4];
  const base = createSignatureBase(v.message(), { components: v.components, parameters: v.parameters });
  assert.equal(base.ok, true);
  assert.equal(new TextDecoder().decode(base.value), [...v.lines, '"@signature-params": ' + v.input].join('\n'));
  const signer = createHmacSigner(options()).value, verifier = createHmacVerifier(options()).value;
  const mac = await signer.sign(base.value);
  assert.equal(Buffer.from(mac).toString('base64'), 'pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=');
  assert.equal(serializeSignature([{ label: 'sig-b25', signature: mac }]).value,
    'sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:');
  assert.equal(await verifier.verify(base.value, mac), true);
  const changed = new Uint8Array(base.value); changed[0] ^= 1;
  assert.equal(await verifier.verify(changed, mac), false);
  mac[0] ^= 1; assert.equal(await verifier.verify(base.value, mac), false);
  assert.equal(Object.isFrozen(signer), true);
  assert.deepEqual(Object.keys(signer), ['keyId', 'keyVersion', 'trustDomain', 'algorithm', 'keyBits', 'sign']);
});

for (const [name, change] of [
  ['raw key', o => o.key = raw], ['public key', o => o.key.type = 'public'],
  ['wrong primitive', o => o.key.algorithm.name = 'RSA'], ['wrong hash', o => o.key.algorithm.hash.name = 'SHA-512'],
  ['short key', o => o.key.algorithm.length = 255], ['oversize key', o => o.key.algorithm.length = 32769],
  ['fractional bits', o => o.key.algorithm.length = 256.5], ['wrong usage', o => o.key.usages = ['verify']],
  ['empty identity', o => o.keyId = ''], ['large identity', o => o.keyVersion = 'x'.repeat(513)],
  ['non-ASCII domain', o => o.trustDomain = '\u0080'],
]) test('adapter rejects ' + name, () => {
  const o = { ...options(), key: fakeKey() }; change(o);
  assert.deepEqual(createHmacSigner(o), { ok: false, code: 'KEY_REJECTED' });
});
for (const o of [undefined, {}, { ...options(), subtle: undefined }, { ...options(), subtle: {} }]) {
  test('adapter requires explicit backend and closed options', () => {
    assert.deepEqual(createHmacSigner(o), { ok: false, code: 'CAPABILITY_UNAVAILABLE' });
  });
}
const rejected = async promise => assert.rejects(promise, error => error.code === 'OPERATION_FAILED' && !String(error).includes('sensitive'));
test('adapter bounds inputs before backend, copies data and captures backend identity', async () => {
  let calls = 0;
  const subtle = { async sign(alg, k, data) { calls++; assert.equal(alg, 'HMAC'); assert.equal(k, key); data[0] = 9; return new ArrayBuffer(32); } };
  const o = { ...options(), subtle }, signer = createHmacSigner(o).value;
  o.keyId = 'changed'; subtle.sign = () => { throw Error('wrong callback'); };
  const bytes = new Uint8Array(65536);
  await signer.sign(bytes); assert.equal(bytes[0], 0); assert.equal(signer.keyId, 'test-shared-secret');
  await rejected(signer.sign(new Uint8Array(65537)));
  await rejected(signer.sign('text')); assert.equal(calls, 1);
  let seen;
  const verifier = createHmacVerifier({ ...options(), subtle: { verify(alg, k, sig, data) { seen = [sig, data]; sig[0] = 9; return true; } } }).value;
  const sig = new Uint8Array(32), data = new Uint8Array(1);
  assert.equal(await verifier.verify(data, sig), true);
  assert.equal(sig[0], 0); assert.notEqual(seen[1], data);
  await rejected(verifier.verify(data, new Uint8Array(31)));
  await rejected(verifier.verify(data, new Uint8Array(33)));
});
for (const output of [undefined, true, new Uint8Array(32), new ArrayBuffer(31), new ArrayBuffer(33)]) {
  test('adapter rejects invalid signer output', async () => {
    const signer = createHmacSigner({ ...options(), subtle: { sign: () => output } }).value;
    await rejected(signer.sign(new Uint8Array()));
  });
}
for (const output of [undefined, 1, 'true', {}]) {
  test('adapter rejects non-boolean verifier output', async () => {
    const verifier = createHmacVerifier({ ...options(), subtle: { verify: () => output } }).value;
    await rejected(verifier.verify(new Uint8Array(), new Uint8Array(32)));
  });
}
for (const operation of ['sign', 'verify']) test('adapter sanitizes ' + operation + ' backend failures', async () => {
  const factory = operation === 'sign' ? createHmacSigner : createHmacVerifier;
  const cap = factory({ ...options(), subtle: { [operation]() { throw Error('sensitive'); } } }).value;
  await rejected(cap[operation](new Uint8Array(), new Uint8Array(32)));
});
