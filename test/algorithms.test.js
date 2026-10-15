import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto, sign as primitiveSign, verify as primitiveVerify, constants } from 'node:crypto';
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { createSignatureBase } from '@pulse-compute/http-signatures/base';
import { parseSignature, serializeSignature, parseSignatureInput, serializeSignatureInput, signatureByteCeiling } from '@pulse-compute/http-signatures/fields';
import { algorithmCases, algorithmSetup, binding } from './fixtures/algorithm-cases.js';
import { signOptions, verifyOptions, install } from './fixtures/protocol-cases.js';
import { bodySignOptions, bodyVerifyOptions } from './fixtures/content-cases.js';
import { appendix, bytes } from './fixtures/base-cases.js';
import keys from './fixtures/rfc9421-crypto.json' with { type: 'json' };
import rsaGolden from './fixtures/rsa-v15-openssl.json' with { type: 'json' };

const error = (r, code) => assert.deepEqual(r, { ok: false, code });
const sfOptions = size => ({ limits: { signatureBytes: size } });
const expectedBase = vector => bytes([...vector.lines, '"@signature-params": ' + vector.input].join('\n'));
function replaceSignature(message, signature, size) {
  const f = message.headers.value.find(f => f.name === 'Signature');
  const wire = serializeSignature([{ label: 'sig1', signature }], sfOptions(size)); assert.equal(wire.ok, true); f.value = bytes(wire.value);
}
for (const c of algorithmCases) for (const kind of ['request', 'response']) test(`${c.algorithm} ${kind}: explicit sign/verify profile`, async () => {
  const h = algorithmSetup(c, kind), s = await sign(h.message, signOptions(h)); assert.equal(s.ok, true, JSON.stringify(s));
  const parsed = parseSignature(s.value.signature, sfOptions(c.size)); assert.equal(parsed.ok, true); assert.equal(parsed.value[0].signature.length, c.size);
  const result = await verify(install(h.message, s.value), verifyOptions(h)); assert.equal(result.ok, true);
  assert.equal(result.value.algorithm, c.algorithm); assert.equal(result.value.keyVersion, 'rfc-fixture');
  assert.deepEqual(h.bases[0], h.bases[1]); assert.equal(h.counts.sign, 1); assert.equal(h.counts.verify, 1); assert.equal(h.counts.resolve, 1);
  assert.equal(h.queries[0].algorithm, c.algorithm);
});
for (const c of algorithmCases) test(`${c.algorithm} composes body integrity and replay without resigning to verify`, async () => {
  const h = algorithmSetup(c, 'request', true), s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  const wire = install(h.message, s.value); h.signer.sign = () => { throw Error('verify must not sign'); };
  const result = await verify(wire, bodyVerifyOptions(h)); assert.equal(result.ok, true); assert.equal(result.value.bodyIntegrity, 'verified'); assert.equal(result.value.replay, 'consumed');
  error(await verify(wire, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
  wire.body.bytes[0] ^= 1; error(await verify(wire, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID'); assert.equal(h.counts.consume, 2);
});
test('RFC B.2.4 exact response bytes verify using fixed-width P-256 signature', async () => {
  const c = algorithmCases[0], v = appendix[3], base = createSignatureBase(v.message(), { components: v.components, parameters: v.parameters });
  assert.equal(base.ok, true); assert.deepEqual(base.value, expectedBase(v));
  const signature = Buffer.from(keys.signatures.b24, 'base64'); assert.equal(signature.length, 64);
  const verifier = c.verifier(binding(c, 'verify')).value;
  assert.equal(await verifier.verify(base.value, signature), true);
  assert.equal(primitiveVerify('sha256', base.value, { key: keys.p256.public, dsaEncoding: 'ieee-p1363' }, signature), true);
  signature[0] ^= 1; assert.equal(await verifier.verify(base.value, signature), false);
});
for (const c of algorithmCases) test(`${c.algorithm} interoperates both directions with classic Node crypto`, async () => {
  const v = appendix[c.name === 'p256' ? 3 : 2], base = expectedBase(v);
  const signer = c.signer(binding(c, 'sign')).value, verifier = c.verifier(binding(c, 'verify')).value;
  const options = { key: keys[c.name].public, ...(c.name === 'p256' ? { dsaEncoding: 'ieee-p1363' } : { padding: constants.RSA_PKCS1_PADDING }) };
  const signature = await signer.sign(base);
  assert.equal(primitiveVerify('sha256', base, options, signature), true);
  const external = primitiveSign('sha256', base, { ...options, key: keys[c.name].private });
  assert.equal(external.length, c.size); assert.equal(await verifier.verify(base, external), true);
  if (c.name === 'rsa') assert.deepEqual(signature, new Uint8Array(external)); // Deterministic RSA v1.5.
});
test('ECDSA accepts valid alternate s values; nonce policy does not key replay on signature bytes', async () => {
  const c = algorithmCases[0], h = algorithmSetup(c, 'request', true), s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  const wire = install(h.message, s.value); assert.equal((await verify(wire, bodyVerifyOptions(h))).ok, true);
  const signature = parseSignature(s.value.signature, sfOptions(64)).value[0].signature;
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const scalar = BigInt('0x' + Buffer.from(signature.subarray(32)).toString('hex'));
  signature.set(Buffer.from((order - scalar).toString(16).padStart(64, '0'), 'hex'), 32);
  replaceSignature(wire, signature, 64); error(await verify(wire, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
});
for (const c of algorithmCases) for (const mutation of ['signature', 'header', 'uri', 'algorithm']) test(`${c.algorithm} rejects changed ${mutation}`, async () => {
  const h = algorithmSetup(c), s = await sign(h.message, signOptions(h)); const wire = install(h.message, s.value);
  if (mutation === 'signature') { const sig = parseSignature(s.value.signature, sfOptions(c.size)).value[0].signature; sig[0] ^= 1; replaceSignature(wire, sig, c.size); }
  if (mutation === 'header') wire.headers.value.find(f => f.name === 'Date').value = bytes('Wed, 21 Apr 2021 02:07:55 GMT');
  if (mutation === 'uri') { wire.target.uri.value += 'x'; wire.target.query.value += 'x'; wire.target.original.value.raw = bytes('/foo?param=Value&Pet=dogx'); }
  if (mutation === 'algorithm') { const f = wire.headers.value.find(f => f.name === 'Signature-Input'); const parsed = parseSignatureInput(f.value).value; parsed[0].parameters.find(p => p.name === 'alg').value = 'hmac-sha256'; f.value = bytes(serializeSignatureInput(parsed).value); }
  error(await verify(wire, verifyOptions(h)), mutation === 'algorithm' ? 'UNSUPPORTED_ALGORITHM' : 'SIGNATURE_INVALID');
});
for (const c of algorithmCases) for (const [field, value] of [['algorithm', 'hmac-sha256'], ['keyBits', 384], ['keyId', 'other'], ['trustDomain', 'other']]) test(`${c.algorithm} resolver binding rejects ${field}`, async () => {
  const h = algorithmSetup(c), s = await sign(h.message, signOptions(h)); h.verifier[field] = value;
  error(await verify(install(h.message, s.value), verifyOptions(h)), 'KEY_REJECTED'); assert.equal(h.counts.verify, 0);
});
for (const c of algorithmCases) for (const size of [32, c.size - 1, c.size + 1]) test(`${c.algorithm} invalid configured size ${size}`, async () => {
  const h = algorithmSetup(c); h.profile.limits.signatureBytes = size;
  error(await sign(h.message, signOptions(h)), 'PROFILE_INVALID'); assert.equal(h.counts.sign, 0);
});
for (const c of algorithmCases) test(`${c.algorithm} rejects short wire signature, oversize output and work exhaustion`, async () => {
  const h = algorithmSetup(c), s = await sign(h.message, signOptions(h)); const wire = install(h.message, s.value);
  replaceSignature(wire, new Uint8Array(c.size - 1), c.size); error(await verify(wire, verifyOptions(h)), 'MALFORMED_SIGNATURE'); assert.equal(h.counts.resolve, 0);
  h.signer.sign = async () => new Uint8Array(c.size + 1); error(await sign(h.message, signOptions(h)), 'OPERATION_FAILED');
  const limited = algorithmSetup(c); limited.profile.limits.workUnits = 1;
  error(await sign(limited.message, signOptions(limited)), 'LIMIT_EXCEEDED'); assert.equal(limited.counts.sign, 0);
});
for (const name of ['rsa-pss-sha512', 'ed25519', 'ecdsa-p384-sha384', 'ES256', 'RS256', '__proto__']) test(`unsupported profile algorithm ${name} cannot trigger fallback`, async () => {
  const h = algorithmSetup(algorithmCases[0]); h.profile.allowedAlgorithms = [name];
  error(await sign(h.message, signOptions(h)), 'PROFILE_INVALID'); assert.equal(h.counts.clock, 0); assert.equal(h.counts.sign, 0);
});
test('no algorithm negotiation list, even when every member is supported', async () => {
  const h = algorithmSetup(algorithmCases[0]); h.profile.allowedAlgorithms.push('rsa-v1_5-sha256');
  error(await sign(h.message, signOptions(h)), 'PROFILE_INVALID');
});
for (const size of [64, 256, 384, 512]) test(`explicit envelope capacity ${size}; default remains 32`, () => {
  assert.equal(signatureByteCeiling, 512);
  const signature = new Uint8Array(size), options = sfOptions(size);
  const wire = serializeSignature([{ label: 'a', signature }], options); assert.equal(wire.ok, true);
  assert.deepEqual(parseSignature(wire.value, options).value[0].signature, signature);
  assert.equal(parseSignature(wire.value).code, 'LIMIT_EXCEEDED');
  assert.equal(serializeSignature([{ label: 'a', signature: new Uint8Array(size + 1) }], options).code, 'LIMIT_EXCEEDED');
});
test('hard signature-byte maximum rejects before writing or parsing', () => {
  assert.equal(serializeSignature([{ label: 'a', signature: new Uint8Array(513) }], sfOptions(513)).code, 'PROFILE_INVALID');
  assert.equal(parseSignature('a=::', sfOptions(513)).code, 'PROFILE_INVALID');
});
for (const [i, algorithm] of [[0, 'rsa-pss-sha512'], [1, 'rsa-pss-sha512'], [2, 'rsa-pss-sha512'], [5, 'ed25519']]) test(`assessment only: RFC ${appendix[i].name} external ${algorithm} verification`, () => {
  const base = expectedBase(appendix[i]), signature = Buffer.from(keys.signatures['b2' + (i + 1)], 'base64');
  const key = algorithm === 'ed25519' ? keys.ed25519.public : keys.pss.public;
  const options = { key, ...(algorithm === 'ed25519' ? {} : { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 }) };
  assert.equal(primitiveVerify(algorithm === 'ed25519' ? null : 'sha512', base, options, signature), true);
  base[0] ^= 1; assert.equal(primitiveVerify(algorithm === 'ed25519' ? null : 'sha512', base, options, signature), false);
  // No production adapter/profile support follows from this backend probe.
});
for (const bits of [3072, 4096]) test(`RSA ${bits}-bit explicit profile and fixed signature width`, async () => {
  const c = { ...algorithmCases[1], bits, size: bits / 8 };
  const pair = await webcrypto.subtle.generateKey({ ...c.primitive, modulusLength: bits, publicExponent: Uint8Array.of(1, 0, 1) }, false, ['sign', 'verify']);
  c.privateKey = pair.privateKey; c.publicKey = pair.publicKey;
  const h = algorithmSetup(c), s = await sign(h.message, signOptions(h)); assert.equal(s.ok, true);
  assert.equal((await verify(install(h.message, s.value), verifyOptions(h))).ok, true);
  h.profile.limits.signatureBytes = 256; error(await sign(h.message, signOptions(h)), 'KEY_REJECTED');
});

test('RSA v1.5 frozen OpenSSL reference signature verifies and matches deterministic signing', async () => {
  const c = algorithmCases[1], base = expectedBase(appendix[2]);
  const expected = Buffer.from(rsaGolden.signatureBase64, 'base64');
  assert.equal(expected.length, 256);
  assert.equal(await c.verifier(binding(c, 'verify')).value.verify(base, expected), true);
  assert.deepEqual(Buffer.from(await c.signer(binding(c, 'sign')).value.sign(base)), expected);
});
