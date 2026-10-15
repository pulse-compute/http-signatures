import test from 'node:test';
import assert from 'node:assert/strict';
import { brotliDecompressSync } from 'node:zlib';
import { webcrypto, createHash } from 'node:crypto';
import { createContentDigest } from '@pulse-compute/http-signatures/content-digest';
import { createSha256Digest } from '@pulse-compute/http-signatures/webcrypto';
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { bodySetup, bodySignOptions, bodyVerifyOptions, signUnchecked } from './fixtures/content-cases.js';
import { install } from './fixtures/protocol-cases.js';
import { field, bytes } from './fixtures/base-cases.js';
import { digestVectors, originalBrotliBytes } from './fixtures/digest-vectors.js';

const digest = createSha256Digest({ subtle: webcrypto.subtle }).value;
const failure = (result, code) => { assert.equal(result.ok, false); assert.equal(result.code, code); assert.deepEqual(Object.keys(result), ['ok', 'code', 'workUnits']); };
for (const vector of digestVectors) test('published RFC 9530 ' + vector.name, async () => {
  const result = await createContentDigest(vector.content, { digest }); assert.equal(result.ok, true);
  assert.equal(result.value, 'sha-256=:' + vector.digest + ':');
  assert.equal(result.value, 'sha-256=:' + createHash('sha256').update(vector.content).digest('base64') + ':');
  const h = bodySetup(); h.digest = digest; h.message.body.bytes = vector.content;
  h.message.headers.value = h.message.headers.value.filter(f => f.name.toLowerCase() !== 'content-digest');
  h.message.headers.value.push(field('content-digest', result.value));
  const signed = await sign(h.message, bodySignOptions(h)); assert.equal(signed.ok, true);
  assert.equal((await verify(install(h.message, signed.value), bodyVerifyOptions(h))).ok, true);
});
test('digest generator owns content and captures explicit callback before await', async () => {
  const content = bytes('abc'), original = new Uint8Array(content); let resume;
  const gate = new Promise(resolve => { resume = resolve; }); let calls = 0;
  const capability = { async sha256(data) { calls++; await gate; return digest.sha256(data); } };
  const pending = createContentDigest(content, { digest: capability }); content.fill(0); capability.sha256 = () => { throw Error('changed'); }; resume();
  const result = await pending; assert.equal(result.ok, true); assert.equal(calls, 1);
  assert.equal(result.value, 'sha-256=:' + createHash('sha256').update(original).digest('base64') + ':');
});
test('generator body/field/work boundaries precede digest calls', async () => {
  let calls = 0; const capability = { sha256(content) { calls++; return digest.sha256(content); } };
  const content = new Uint8Array(128);
  const exact = await createContentDigest(content, { digest: capability, limits: { bodyBytes: 128, fieldValueBytes: 54 } }); assert.equal(exact.ok, true);
  for (const limits of [{ bodyBytes: 127 }, { fieldValueBytes: 53 }, { signatureBaseBytes: 45 }, { workUnits: exact.workUnits - 1 }]) {
    calls = 0; failure(await createContentDigest(content, { digest: capability, limits }), 'LIMIT_EXCEEDED'); assert.equal(calls, 0);
  }
  calls = 0; assert.equal((await createContentDigest(content, { digest: capability, limits: { workUnits: exact.workUnits } })).ok, true); assert.equal(calls, 1);
});
test('generator accepts 1 MiB, rejects one byte over without hashing', async () => {
  const content = new Uint8Array(1048576); assert.equal((await createContentDigest(content, { digest })).ok, true);
  let calls = 0; failure(await createContentDigest(new Uint8Array(1048577), { digest: { sha256() { calls++; } } }), 'LIMIT_EXCEEDED'); assert.equal(calls, 0);
});
for (const value of [null, undefined, 'body', new ArrayBuffer(0), {}, []]) test('generator rejects non-byte content ' + String(value), async () => {
  failure(await createContentDigest(value, { digest }), 'MALFORMED_MESSAGE');
});
for (const options of [undefined, {}, { digest, unknown: true }, { digest, limits: { bodyBytes: 1048577 } }, { digest, limits: { workUnits: 0 } }]) test('generator closed options and limits', async () => {
  failure(await createContentDigest(new Uint8Array(), options), 'PROFILE_INVALID');
});
for (const capability of [undefined, null, {}, { sha256: true }]) test('generator requires digest capability', async () => {
  failure(await createContentDigest(new Uint8Array(), { digest: capability }), 'CAPABILITY_UNAVAILABLE');
});
for (const output of [undefined, true, new ArrayBuffer(32), new Uint8Array(31), new Uint8Array(33)]) test('generator rejects invalid digest result', async () => {
  failure(await createContentDigest(new Uint8Array(), { digest: { sha256: () => output } }), 'OPERATION_FAILED');
});
test('generator redacts backend details', async () => {
  const result = await createContentDigest(bytes('sensitive'), { digest: { sha256() { throw Error('private'); } } });
  failure(result, 'OPERATION_FAILED'); assert.equal(JSON.stringify(result).includes('private'), false);
});
test('explicit SHA-256 adapter is frozen, bounded and copies bytes', async () => {
  let calls = 0;
  const subtle = { digest(algorithm, content) { calls++; assert.equal(algorithm, 'SHA-256'); content[0] = 99; return new ArrayBuffer(32); } };
  const cap = createSha256Digest({ subtle }); assert.equal(cap.ok, true); assert.equal(Object.isFrozen(cap.value), true);
  subtle.digest = () => { throw Error('changed'); };
  const content = new Uint8Array(1048576); assert.equal((await cap.value.sha256(content)).length, 32); assert.equal(content[0], 0);
  for (const input of ['string', new ArrayBuffer(1), new Uint8Array(1048577)]) {
    await assert.rejects(cap.value.sha256(input), e => e.code === 'OPERATION_FAILED');
  }
  assert.equal(calls, 1);
});
for (const subtle of [undefined, null, {}, { digest: true }]) test('digest adapter requires explicit backend', () => {
  assert.deepEqual(createSha256Digest({ subtle }), { ok: false, code: 'CAPABILITY_UNAVAILABLE' });
});
for (const output of [null, true, new Uint8Array(32), new ArrayBuffer(31), new ArrayBuffer(33)]) test('digest adapter checks backend output', async () => {
  const cap = createSha256Digest({ subtle: { digest: () => output } }).value;
  await assert.rejects(cap.sha256(new Uint8Array()), e => e.code === 'OPERATION_FAILED');
});
test('digest adapter redacts exceptions and never reads ambient crypto', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, get() { throw Error('ambient'); } });
    assert.equal((await createContentDigest(bytes('a'), { digest })).ok, true);
    const cap = createSha256Digest({ subtle: { digest() { throw Error('sensitive'); } } }).value;
    await assert.rejects(cap.sha256(new Uint8Array()), e => e.code === 'OPERATION_FAILED' && !String(e).includes('sensitive'));
  } finally { if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor); else delete globalThis.crypto; }
});

test('RFC 9530 original B.4 bytes do not match its published digest (reported erratum 8890)', async () => {
  const v = digestVectors.at(-1);
  const actual = await createContentDigest(originalBrotliBytes, { digest });
  assert.equal(actual.value, 'sha-256=:MklYnI/SsUF/5X7enJ2TU+DFjodRObdKLFaPPLe/Kcw=:');
  assert.notEqual(actual.value, 'sha-256=:' + v.digest + ':');
  const h = bodySetup(); h.message.body.bytes = originalBrotliBytes;
  h.message.headers.value.find(f => f.name === 'Content-Digest').value = bytes('sha-256=:' + v.digest + ':');
  await signUnchecked(h);
  assert.deepEqual(await verify(h.message, bodyVerifyOptions(h)), { ok: false, code: 'BODY_DIGEST_INVALID' });
});
test('content encoding is opaque: valid compressed bytes hash as received, decoded bytes differ', async () => {
  const v = digestVectors.at(-1), decoded = brotliDecompressSync(v.content);
  assert.equal(decoded.toString(), '{"hello": "world"}\n');
  const h = bodySetup(); h.digest = digest; h.message.body.bytes = v.content;
  h.message.headers.value.find(f => f.name === 'Content-Digest').value = bytes('sha-256=:' + v.digest + ':');
  const signed = await sign(h.message, bodySignOptions(h)); assert.equal(signed.ok, true);
  const wire = install(h.message, signed.value); wire.body.bytes = decoded;
  assert.deepEqual(await verify(wire, bodyVerifyOptions(h)), { ok: false, code: 'BODY_DIGEST_INVALID' });
});
