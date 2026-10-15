import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '@pulse-compute/http-signatures';
import * as fields from '@pulse-compute/http-signatures/fields';
import * as base from '@pulse-compute/http-signatures/base';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url)));
assert.equal(pkg.private, true, 'The experimental package must remain private');
assert.deepEqual(pkg.exports, { '.': './src/index.js', './fields': './src/signature-fields.js', './base': './src/signature-base.js' });
assert.deepEqual(Object.keys(api).sort(), [
  'createSignatureBase', 'serializeSignatureParams', 'signMessage', 'verifyMessage',
].sort());
for (const value of Object.values(api)) assert.equal(typeof value, 'function');
assert.deepEqual(Object.keys(fields).sort(), ['parseSignature', 'parseSignatureInput',
  'parseSignatureEnvelope', 'serializeSignature', 'serializeSignatureInput',
  'serializeSignatureParameters', 'signatureFieldLimits'].sort());
assert.ok(Object.isFrozen(fields.signatureFieldLimits));
for (const [key, fn] of Object.entries(fields)) if (key !== 'signatureFieldLimits') assert.equal(typeof fn, 'function');
assert.deepEqual(Object.keys(base).sort(), ['createSignatureBase', 'signatureBaseLimits']);
assert.equal(typeof base.createSignatureBase, 'function');
assert.ok(Object.isFrozen(base.signatureBaseLimits));
console.log('Original four exports, fields and base subpaths resolve; private guard retained.');
