import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import * as api from '@pulse-compute/http-signatures';

const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url)));
assert.equal(pkg.private, true, 'The experimental package must remain private');
assert.deepEqual(pkg.exports, { '.': './src/index.js' });
assert.deepEqual(Object.keys(api).sort(), [
  'createSignatureBase', 'serializeSignatureParams', 'signMessage', 'verifyMessage',
].sort());
for (const value of Object.values(api)) assert.equal(typeof value, 'function');
console.log('Package entry point resolves; four named exports; private publication guard.');
