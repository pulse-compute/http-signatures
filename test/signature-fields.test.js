import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import {
  parseSignatureInput, parseSignature, parseSignatureEnvelope,
  serializeSignatureInput, serializeSignature, serializeSignatureParameters, signatureFieldLimits,
} from '../src/signature-fields.js';
const fixtures = JSON.parse(await readFile(new URL('./fixtures/signature-fields.json', import.meta.url)));
const value = result => { assert.equal(result.ok, true, JSON.stringify(result)); return result.value; };
const rejects = (result, code = 'MALFORMED_SIGNATURE') => {
  assert.equal(result.ok, false, JSON.stringify(result)); assert.equal(result.code, code);
  assert.deepEqual(Object.keys(result).sort(), ['code', 'ok', 'workUnits']);
};
const plain = name => ({ kind: 'field', name, parameters: [] });
const entry = (label = 'a') => ({ label, components: [plain('x')], parameters: [] });
const rfc = fixtures.rfcB25;

test('RFC 9421 B.2.5 exact fields, bytes, ordered params and independent Web Crypto verification', async () => {
  const { inputs, signatures } = value(parseSignatureEnvelope({ signatureInput: rfc.signatureInput, signature: rfc.signature }));
  assert.equal(value(serializeSignatureInput(inputs)), rfc.signatureInput);
  assert.equal(value(serializeSignature(signatures)), rfc.signature);
  assert.equal(Buffer.from(signatures[0].signature).toString('hex'), rfc.hex);
  assert.equal(value(serializeSignatureParameters({ components: inputs[0].components, parameters: inputs[0].parameters })), rfc.parameters);
  const base = '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@authority": example.com\n"content-type": application/json\n"@signature-params": ' + rfc.parameters;
  const rawKey = Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64');
  const key = await webcrypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await webcrypto.subtle.verify('HMAC', key, signatures[0].signature, new TextEncoder().encode(base)), true);
});
for (const [wire, canonical] of fixtures.inputCanonicalization) test(`input syntax: ${JSON.stringify(wire)}`, () => {
  if (canonical === null) return rejects(parseSignatureInput(wire));
  const parsed = value(parseSignatureInput(wire));
  assert.equal(value(serializeSignatureInput(parsed)), canonical);
  assert.deepEqual(value(parseSignatureInput(canonical)), parsed);
});
for (const wire of fixtures.malformedInput) test(`reject input: ${JSON.stringify(wire)}`, () => rejects(parseSignatureInput(wire)));
for (const [wire, canonical, hex] of fixtures.bytes) test(`RFC 8941 bytes: ${wire}`, () => {
  const parsed = value(parseSignature(wire));
  assert.equal(Buffer.from(parsed[0].signature).toString('hex'), hex);
  assert.equal(value(serializeSignature(parsed)), canonical);
  assert.deepEqual(value(parseSignature(canonical)), parsed);
});
for (const wire of fixtures.malformedSignature) test(`reject signature: ${JSON.stringify(wire)}`, () => rejects(parseSignature(wire)));

test('multiple labels, repeated field instances and byte inputs preserve ordering', () => {
  const encoder = new TextEncoder();
  const fields = { signatureInput: ['b=("@method");tag="second"', encoder.encode('a=("x");created=1')],
    signature: [encoder.encode('a=:AA==:'), 'b=:AQ==:'] };
  const result = value(parseSignatureEnvelope(fields));
  assert.deepEqual(result.inputs.map(e => e.label), ['b', 'a']);
  assert.deepEqual(result.signatures.map(e => e.label), ['a', 'b']);
  assert.equal(value(serializeSignatureInput(result.inputs)), 'b=("@method");tag="second", a=("x");created=1');
  rejects(parseSignatureInput(['a=()', 'a=()']));
  rejects(parseSignatureInput(['a=("split', 'across")']));
  rejects(parseSignature(new Uint8Array([255])));
});
test('complete envelope labels must match, including unselected labels', () => {
  rejects(parseSignatureEnvelope({ signatureInput: 'a=(), b=()', signature: 'a=::' }));
  rejects(parseSignatureEnvelope({ signatureInput: 'a=()', signature: 'a=::, b=::' }));
  rejects(parseSignatureEnvelope({ signatureInput: 'a=()', signature: 'b=::' }));
  rejects(parseSignatureEnvelope({ signatureInput: 'a=(), b=?0', signature: 'a=::, b=::' }));
  assert.deepEqual(value(parseSignatureEnvelope({ signatureInput: '', signature: [] })), { inputs: [], signatures: [] });
});
test('ordered parameter serialization; duplicate identity ignores parameter/property order', () => {
  const first = { kind: 'field', name: 'x', parameters: [{ name: 'req', value: true }, { name: 'sf', value: true }] };
  const equal = { kind: 'field', name: 'x', parameters: [{ value: true, name: 'sf' }, { value: true, name: 'req' }] };
  rejects(serializeSignatureInput([{ ...entry(), components: [first, equal] }]));
  assert.equal(value(serializeSignatureInput([{ ...entry(), components: [first] }])), 'a=("x";req;sf)');
  assert.equal(value(serializeSignatureInput([{ ...entry(), components: [equal] }])), 'a=("x";sf;req)');
  const distinct = value(parseSignatureInput('a=("x" "x";req "x";tr "x";key="a" "x";key="b")'));
  assert.equal(distinct[0].components.length, 5);
  rejects(parseSignatureInput('a=("@unknown")'), 'UNSUPPORTED_COMPONENT');
  rejects(parseSignatureInput('a=("@signature-params")'), 'UNSUPPORTED_COMPONENT');
});
test('envelope parsing does not impose application alg/key/time/coverage policy', () => {
  const entries = value(parseSignatureInput('a=();created=-1;alg="ed25519"'));
  assert.deepEqual(entries[0].parameters, [{ name: 'created', value: -1 }, { name: 'alg', value: 'ed25519' }]);
  assert.equal(value(parseSignature('a=::'))[0].signature.length, 0);
});
test('byte and structural limits at the ceiling and one over', () => {
  value(parseSignatureInput('a=()'.padEnd(16384, ' ')));
  rejects(parseSignatureInput('a=()'.padEnd(16385, ' ')), 'LIMIT_EXCEEDED');
  rejects(parseSignatureInput(['a=()'.padEnd(8192, ' '), 'b=()'.padEnd(8192, ' ')]), 'LIMIT_EXCEEDED');
  rejects(parseSignatureInput(Array.from({ length: 16 }, () => ''))); // Count allowed; comma-only dictionary is malformed.
  rejects(parseSignatureInput(Array.from({ length: 17 }, () => '')), 'LIMIT_EXCEEDED');
  const inputs = Array.from({ length: 8 }, (_, i) => entry(`a${i}`));
  value(serializeSignatureInput(inputs));
  rejects(serializeSignatureInput([...inputs, entry('extra')]), 'LIMIT_EXCEEDED');
  value(parseSignatureInput(inputs.map(e => `${e.label}=()`).join(', ')));
  rejects(parseSignatureInput([...inputs.map(e => `${e.label}=()`), 'extra=()'].join(', ')), 'LIMIT_EXCEEDED');
  value(parseSignatureInput('a=(' + Array.from({ length: 32 }, (_, i) => `"x${i}"`).join(' ') + ')'));
  rejects(parseSignatureInput('a=(' + Array.from({ length: 33 }, (_, i) => `"x${i}"`).join(' ') + ')'), 'LIMIT_EXCEEDED');
  value(parseSignatureInput(`${'a'.repeat(64)}=("${'x'.repeat(256)}");keyid="${'k'.repeat(512)}"`));
  for (const input of [`${'a'.repeat(65)}=()`, `a=("${'x'.repeat(257)}")`, `a=();keyid="${'k'.repeat(513)}"`]) rejects(parseSignatureInput(input), 'LIMIT_EXCEEDED');
  value(serializeSignature([{ label: 'a', signature: new Uint8Array(32) }]));
  rejects(serializeSignature([{ label: 'a', signature: new Uint8Array(33) }]), 'LIMIT_EXCEEDED');
  rejects(parseSignature(`a=:${Buffer.alloc(33).toString('base64')}:`), 'LIMIT_EXCEEDED');
});
test('lower limits and deterministic shared work budget cannot be bypassed', () => {
  const fields = { signatureInput: rfc.signatureInput, signature: rfc.signature };
  const result = parseSignatureEnvelope(fields);
  assert.ok(result.ok && result.workUnits > 0 && result.workUnits < signatureFieldLimits.workUnits);
  assert.deepEqual(parseSignatureEnvelope(fields, { limits: { workUnits: result.workUnits } }), result);
  rejects(parseSignatureEnvelope(fields, { limits: { workUnits: result.workUnits - 1 } }), 'LIMIT_EXCEEDED');
  const written = serializeSignatureInput(value(parseSignatureInput(rfc.signatureInput)));
  assert.deepEqual(serializeSignatureInput(value(parseSignatureInput(rfc.signatureInput)), { limits: { workUnits: written.workUnits } }), written);
  rejects(serializeSignatureInput(value(parseSignatureInput(rfc.signatureInput)), { limits: { workUnits: written.workUnits - 1 } }), 'LIMIT_EXCEEDED');
  rejects(parseSignatureInput('a=("x" "y")', { limits: { components: 1 } }), 'LIMIT_EXCEEDED');
  rejects(parseSignatureInput('a=("x";sf;req)', { limits: { componentParameters: 1 } }), 'LIMIT_EXCEEDED');
  rejects(parseSignatureInput('a=();keyid="a";tag="b"', { limits: { signatureParameters: 1 } }), 'LIMIT_EXCEEDED');
  rejects(serializeSignatureInput([entry()], { limits: { envelopeFieldBytes: 1 } }), 'LIMIT_EXCEEDED');
  for (const options of [null, { bad: 1 }, { limits: null }, { limits: { unknown: 1 } },
    { limits: { workUnits: 0 } }, { limits: { signatures: 9 } }, { limits: { workUnits: NaN } }]) rejects(parseSignatureInput('a=()', options), 'PROFILE_INVALID');
});
test('serializer rejects malformed models, sparse arrays, accessors and wrong byte types', () => {
  const getter = Object.defineProperty({}, 'label', { get() { throw new Error('secret'); }, enumerable: true });
  Object.assign(getter, { components: [], parameters: [] });
  const bad = [null, {}, [null], Array(1), [getter], [{ ...entry(), extra: true }],
    [{ ...entry(), components: [plain('UPPER')] }], [{ ...entry(), parameters: [{ name: 'created', value: Infinity }] }],
    [{ ...entry(), parameters: [{ name: 'nonce', value: '\nsecret' }] }], [entry(), entry()]];
  for (const model of bad) rejects(serializeSignatureInput(model));
  rejects(serializeSignature([{ label: 'a', signature: [0] }]));
  rejects(parseSignatureInput(undefined));
  rejects(parseSignatureInput(Array(1)));
});
test('exhaustive one-byte and seeded multi-byte canonical round trips against Node base64', () => {
  let state = 1;
  for (let n = 0; n <= 256; n++) {
    const length = n < 256 ? 1 : 32;
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; bytes[i] = n < 256 ? n : state >>> 24; }
    const wire = `a=:${Buffer.from(bytes).toString('base64')}:`;
    assert.equal(value(serializeSignature([{ label: 'a', signature: bytes }])), wire);
    assert.deepEqual(value(parseSignature(wire))[0].signature, bytes);
  }
  for (let length = 0; length <= 32; length++) {
    const bytes = Uint8Array.from({ length }, () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state >>> 24; });
    const wire = value(serializeSignature([{ label: 'a', signature: bytes }]));
    assert.deepEqual(value(parseSignature(wire))[0].signature, bytes);
    assert.deepEqual(value(parseSignature(wire.replace(/=+:$/, ':')))[0].signature, bytes);
  }
});
test('bounded arbitrary ASCII mutations never throw and accepted forms round trip', () => {
  let state = 7;
  for (let i = 0; i < 500; i++) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    const at = state % rfc.signatureInput.length;
    const wire = rfc.signatureInput.slice(0, at) + String.fromCharCode((state >>> 16) & 127) + rfc.signatureInput.slice(at + 1);
    const parsed = parseSignatureInput(wire, { limits: { workUnits: 50000 } });
    assert.ok(parsed.workUnits <= 50000);
    if (parsed.ok) {
      const canonical = value(serializeSignatureInput(parsed.value));
      assert.deepEqual(value(parseSignatureInput(canonical)), parsed.value);
    }
  }
});
