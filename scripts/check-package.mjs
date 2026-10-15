import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '@pulse-compute/http-signatures';
import * as fields from '@pulse-compute/http-signatures/fields';
import * as base from '@pulse-compute/http-signatures/base';
import * as protocol from '@pulse-compute/http-signatures/protocol';
import * as digest from '@pulse-compute/http-signatures/content-digest';
import * as webcrypto from '@pulse-compute/http-signatures/webcrypto';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url)));
assert.equal(pkg.private, true, 'The experimental package must remain private');
assert.deepEqual(pkg.exports, { '.': './src/index.js', './fields': './src/signature-fields.js', './base': './src/signature-base.js',
  './protocol': './src/protocol.js', './webcrypto': './src/webcrypto.js', './content-digest': './src/content-digest.js', './pulse': './src/pulse.js' });
assert.deepEqual(Object.keys(api).sort(), [
  'createSignatureBase', 'serializeSignatureParams', 'signMessage', 'verifyMessage',
].sort());
for (const value of Object.values(api)) assert.equal(typeof value, 'function');
assert.deepEqual(Object.keys(fields).sort(), ['parseSignature', 'parseSignatureInput',
  'parseSignatureEnvelope', 'serializeSignature', 'serializeSignatureInput',
  'serializeSignatureParameters', 'signatureFieldLimits', 'signatureByteCeiling'].sort());
assert.ok(Object.isFrozen(fields.signatureFieldLimits));
for (const [key, fn] of Object.entries(fields)) if (!['signatureFieldLimits', 'signatureByteCeiling'].includes(key)) assert.equal(typeof fn, 'function');
assert.deepEqual(Object.keys(base).sort(), ['createSignatureBase', 'signatureBaseLimits']);
assert.equal(typeof base.createSignatureBase, 'function');
assert.ok(Object.isFrozen(base.signatureBaseLimits));
assert.deepEqual(Object.keys(protocol).sort(), ['sign', 'verify']);
assert.deepEqual(Object.keys(webcrypto).sort(), ['createEcdsaP256Signer', 'createEcdsaP256Verifier', 'createHmacSigner', 'createHmacVerifier', 'createRsaV15Signer', 'createRsaV15Verifier', 'createSha256Digest']);
assert.deepEqual(Object.keys(digest), ['createContentDigest']);
for (const value of [...Object.values(digest), ...Object.values(protocol), ...Object.values(webcrypto)]) assert.equal(typeof value, 'function');
console.log('Original root, fields, base, protocol, content digest and explicit Web Crypto exports resolve; private guard retained.');
