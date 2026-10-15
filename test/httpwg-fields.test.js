import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { parseSignature, parseSignatureInput, serializeSignature, serializeSignatureInput } from '../src/signature-fields.js';
const directory = new URL('./fixtures/httpwg/', import.meta.url);
const binary = JSON.parse(await readFile(new URL('binary.json', directory)));
const strings = JSON.parse(await readFile(new URL('string.json', directory)));
const numbers = JSON.parse(await readFile(new URL('number.json', directory)));
// Adapt upstream bare items to signature-envelope positions; source files are unchanged.
for (const fixture of binary) test(`HTTPWG binary: ${fixture.name}`, () => {
  const parsed = parseSignature(`a=${fixture.raw.join(', ')}`);
  if (fixture.must_fail || fixture.name === 'extra padding') {
    // Upstream permits rejecting extra padding; this subset deliberately rejects it.
    assert.equal(parsed.ok, false); return;
  }
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  const canonical = (fixture.canonical ?? fixture.raw)[0];
  assert.equal(serializeSignature(parsed.value).value, `a=${canonical}`);
  assert.deepEqual(parsed.value[0].signature, new Uint8Array(Buffer.from(canonical.slice(1, -1), 'base64')));
});
for (const fixture of strings) test(`HTTPWG string in keyid: ${fixture.name}`, () => {
  const parsed = parseSignatureInput(`a=();keyid=${fixture.raw.join(', ')}`);
  if (fixture.must_fail) { assert.equal(parsed.ok, false); return; }
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  assert.equal(parsed.value[0].parameters[0].value, fixture.expected[0]);
  assert.equal(serializeSignatureInput(parsed.value).value, `a=();keyid=${(fixture.canonical ?? fixture.raw).join(', ')}`);
});
// Generic lists and valid decimals are outside the envelope's integer-metadata subset.
const integerFixtures = numbers.filter(f => f.header_type === 'item' && (f.must_fail || Number.isInteger(f.expected[0])));
for (const fixture of integerFixtures) test(`HTTPWG integer in created: ${fixture.name}`, () => {
  const parsed = parseSignatureInput(`a=();created=${fixture.raw.join(', ')}`);
  if (fixture.must_fail) { assert.equal(parsed.ok, false); return; }
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  assert.equal(parsed.value[0].parameters[0].value, fixture.expected[0]);
  assert.equal(serializeSignatureInput(parsed.value).value, `a=();created=${(fixture.canonical ?? fixture.raw)[0]}`);
});
