// Measures the unchanged HMS-00 spike, not enforcement of the HMS-01 contract.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createSignatureBase, serializeSignatureParams, signMessage, verifyMessage } from '../src/index.js';
const params = { created: 1000, keyid: 'measurement', alg: 'hmac-sha256' };
const key = new Uint8Array(32).fill(7); // Public test material only.
const message = { method: 'POST', url: 'https://example.test/a', headers: { x: 'a' } };
const rows = [];
async function record(name, size, expected, fn) {
  let accepted;
  try { accepted = (await fn()) !== false; } catch { accepted = false; }
  assert.equal(accepted, expected, `${name} at ${size}`);
  rows.push({ name, size, accepted });
}
for (const n of [16384, 16385]) await record('single-field-bytes', n, n === 16384,
  () => createSignatureBase({ ...message, headers: { x: 'a'.repeat(n) } }, { components: ['x'], params }));
for (const n of [32, 33]) {
  const components = Array.from({ length: n }, (_, i) => `x${i}`);
  await record('covered-components', n, n === 32, () => createSignatureBase(
    { ...message, headers: Object.fromEntries(components.map(c => [c, 'a'])) }, { components, params }));
}
for (const n of [16, 17]) await record('instances-of-covered-field', n, n === 16,
  () => createSignatureBase({ ...message, headers: Array.from({ length: n }, () => ['x', 'a']) }, { components: ['x'], params }));
for (const n of [512, 513]) await record('metadata-string-bytes', n, n === 512,
  () => serializeSignatureParams(['x'], { ...params, nonce: 'a'.repeat(n) }));
for (const n of [65536, 65537]) {
  const components = ['a', 'b', 'c', 'd', 'e'];
  const headers = Object.fromEntries(components.map(c => [c, '']));
  let remainder = n - new TextEncoder().encode(createSignatureBase({ ...message, headers }, { components, params })).length;
  for (const c of components) { const count = Math.min(remainder, 16384); headers[c] = 'a'.repeat(count); remainder -= count; }
  assert.equal(remainder, 0);
  await record('signature-base-bytes', n, n === 65536, () => createSignatureBase({ ...message, headers }, { components, params }));
}
for (const n of [15, 16, 4096, 4097]) await record('raw-hmac-key-bytes', n, n >= 16 && n <= 4096,
  () => signMessage(message, { components: ['x'], params, key: new Uint8Array(n).fill(7), crypto: webcrypto }));
const wire = await signMessage(message, { components: ['x'], params, key, crypto: webcrypto });
const policy = { ...wire, label: 'sig1', key, requiredKeyId: params.keyid,
  requiredComponents: ['x'], nowSeconds: 1000, maxAgeSeconds: 30, crypto: webcrypto };
for (const field of ['signatureInput', 'signature']) for (const n of [16384, 16385]) {
  await record(`${field}-bytes`, n, n === 16384, () => verifyMessage(message, {
    ...policy, [field]: wire[field].padEnd(n, ' '),
  }));
}
for (const n of [8, 9]) {
  const input = [], signatures = [];
  for (let i = 0; i < n; i++) {
    const signed = await signMessage(message, { label: `s${i}`, components: ['x'], params, key, crypto: webcrypto });
    input.push(signed.signatureInput); signatures.push(signed.signature);
  }
  await record('signature-labels', n, n === 8, () => verifyMessage(message, {
    ...policy, label: 's0', signatureInput: input.join(', '), signature: signatures.join(', '),
  }));
}
await record('total-header-count-no-spike-cap', 129, true, () => createSignatureBase({
  ...message, headers: [...Array.from({ length: 128 }, (_, i) => [`unused${i}`, 'a']), ['x', 'a']],
}, { components: ['x'], params }));
const source = await readFile(new URL('../src/index.js', import.meta.url));
console.log(JSON.stringify({ schemaVersion: 1, runtime: process.version,
  sourceSha256: createHash('sha256').update(source).digest('hex'),
  scope: 'Boundary acceptance observations; no throughput, memory, adversarial-work, or security qualification',
  observations: rows }, null, 2));
