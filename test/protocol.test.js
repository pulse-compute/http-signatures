import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac, webcrypto } from 'node:crypto';
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { createSignatureBase } from '@pulse-compute/http-signatures/base';
import { createHmacVerifier } from '@pulse-compute/http-signatures/webcrypto';
import { BaseFailure } from '../src/base-support.js';
import { parseSignatureInput, serializeSignatureInput, serializeSignature } from '@pulse-compute/http-signatures/fields';
import { setup, signOptions, verifyOptions, install, rawKey, backend } from './fixtures/protocol-cases.js';
import { av, unavailable, field, bytes, component } from './fixtures/base-cases.js';

const error = (r, code) => assert.deepEqual(r, { ok: false, code });
async function signed(kind = 'request') {
  const h = setup(kind), r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true, JSON.stringify(r));
  h.signed = r.value; h.message = install(h.message, r.value);
  for (const key of Object.keys(h.counts)) h.counts[key] = 0;
  h.bases.length = 0; return h;
}
function editInput(h, fn) {
  const f = h.message.headers.value.find(f => f.name.toLowerCase() === 'signature-input');
  const parsed = parseSignatureInput(f.value); assert.equal(parsed.ok, true); fn(parsed.value);
  const wire = serializeSignatureInput(parsed.value); assert.equal(wire.ok, true); f.value = bytes(wire.value);
}
function param(h, name, value) {
  editInput(h, entries => { const p = entries[0].parameters.find(p => p.name === name); if (value === undefined) entries[0].parameters = entries[0].parameters.filter(p => p.name !== name); else if (p) p.value = value; else entries[0].parameters.push({ name, value }); });
}
function noCrypto(h) { assert.equal(h.counts.sign, 0); assert.equal(h.counts.resolve, 0); assert.equal(h.counts.verify, 0); }

for (const kind of ['request', 'response']) test(`explicit ${kind} sign/verify and scoped receipt`, async () => {
  const h = setup(kind), r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(h.counts.sign, 1); assert.equal(h.counts.clock, 1);
  const signBase = h.bases[0], wire = install(h.message, r.value); wire.direction = 'inbound'; h.profile.context.direction = 'inbound';
  const result = await verify(wire, verifyOptions(h)); assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(result.value, { contextId: wire.contextId, profileId: h.profile.id, label: 'sig1', keyId: 'test-key', keyVersion: 'v1',
    algorithm: 'hmac-sha256', covered: h.covered, bodyIntegrity: 'not-checked', replay: 'not-checked' });
  assert.deepEqual(h.bases[1], signBase); assert.equal(h.counts.resolve, 1); assert.equal(h.counts.verify, 1); assert.equal(h.counts.clock, 2);
  assert.deepEqual(h.queries, [{ keyId: 'test-key', algorithm: 'hmac-sha256', trustDomain: 'test', profileId: h.profile.id }]);
  const expected = createHmac('sha256', rawKey).update(signBase).digest('base64');
  assert.equal(r.value.signature, 'sig1=:' + expected + ':');
});
test('signing fields and exact base include mandatory metadata in supplied order', async () => {
  const h = setup(); h.parameters.reverse();
  const r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true);
  const expectedInput = 'sig1=("@method" "@target-uri" "date" "content-type");tag="test-domain";alg="hmac-sha256";keyid="test-key";expires=1060;created=1000';
  assert.equal(r.value.signatureInput, expectedInput);
  const expectedBase = '"@method": POST\n"@target-uri": https://example.com/foo?param=Value&Pet=dog\n"date": Tue, 20 Apr 2021 02:07:55 GMT\n"content-type": application/json\n"@signature-params": ' + expectedInput.slice(5);
  assert.deepEqual(h.bases[0], bytes(expectedBase));
  assert.equal(r.value.signature, 'sig1=:' + createHmac('sha256', rawKey).update(expectedBase).digest('base64') + ':');
});
for (const [name, mutate] of [
  ['covered header', h => h.message.headers.value.find(f => f.name === 'Date').value.fill(65)],
  ['method', h => { h.message.method = av('GET'); }],
  ['URI', h => { h.message.target.path = av('/other'); h.message.target.uri = av('https://example.com/other?param=Value&Pet=dog'); h.message.target.original.value.raw = bytes('/other?param=Value&Pet=dog'); }],
  ['authenticator', h => { h.message.headers.value.find(f => f.name === 'Signature').value = bytes('sig1=:' + Buffer.alloc(32).toString('base64') + ':'); }],
]) test(`changed ${name} fails the authenticator`, async () => {
  const h = await signed(); mutate(h); error(await verify(h.message, verifyOptions(h)), 'SIGNATURE_INVALID');
  assert.equal(h.counts.resolve, 1); assert.equal(h.counts.verify, 1);
});
test('a genuinely wrong HMAC key is rejected by the backend primitive', async () => {
  const h = await signed();
  const key = await webcrypto.subtle.importKey('raw', new Uint8Array(32).fill(255), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const wrong = createHmacVerifier({ subtle: webcrypto.subtle, key, keyId: 'test-key', keyVersion: 'v1', trustDomain: 'test' }).value;
  h.verifier.verify = (base, sig) => { h.counts.verify++; return wrong.verify(base, sig); };
  error(await verify(h.message, verifyOptions(h)), 'SIGNATURE_INVALID'); assert.equal(h.counts.verify, 1);
});
for (const alg of ['ed25519', 'rsa-v1_5-sha256', 'HMAC-SHA256', 'none']) test(`algorithm substitution ${alg} makes no capability call`, async () => {
  const h = await signed(); param(h, 'alg', alg); error(await verify(h.message, verifyOptions(h)), 'UNSUPPORTED_ALGORITHM'); noCrypto(h); assert.equal(h.counts.clock, 0);
});
for (const name of ['created', 'keyid', 'alg', 'tag', 'expires']) test(`missing ${name} fails metadata policy`, async () => {
  const h = await signed(); param(h, name, undefined); error(await verify(h.message, verifyOptions(h)), 'METADATA_REQUIRED'); noCrypto(h); assert.equal(h.counts.clock, 0);
});
for (const [name, value] of [['tag', 'other-domain'], ['tag', ''], ['keyid', ''], ['nonce', '']]) test(`invalid ${name} ${JSON.stringify(value)} is not accepted`, async () => {
  const h = await signed(); param(h, name, value); error(await verify(h.message, verifyOptions(h)), 'METADATA_REQUIRED'); noCrypto(h);
});
test('optional nonempty nonce is signed but does not claim replay protection', async () => {
  const h = setup(); h.parameters.push({ name: 'nonce', value: 'public-test-nonce' });
  const r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true);
  const wire = install(h.message, r.value);
  for (let i = 0; i < 2; i++) { const result = await verify(wire, verifyOptions(h)); assert.equal(result.ok, true); assert.equal(result.value.replay, 'not-checked'); }
});
for (const keyId of ['other-key', 'https://evil.example/key', '../secret']) test(`disallowed keyid ${keyId} never reaches resolver`, async () => {
  const h = await signed(); param(h, 'keyid', keyId); error(await verify(h.message, verifyOptions(h)), 'KEY_REJECTED'); noCrypto(h);
});
for (const [name, value] of [['keyId', 'wrong'], ['algorithm', 'ed25519'], ['trustDomain', 'other'], ['keyBits', 255], ['keyBits', NaN], ['keyVersion', '']])
  test(`resolver key ${name} mismatch is rejected`, async () => {
    const h = await signed(); h.verifier[name] = value; error(await verify(h.message, verifyOptions(h)), 'KEY_REJECTED'); assert.equal(h.counts.resolve, 1); assert.equal(h.counts.verify, 0);
  });
for (const value of [null, undefined, [], new Uint8Array(32), 'secret']) test(`invalid resolver result ${String(value).slice(0, 12)}`, async () => {
  const h = await signed(); h.keys.resolve = () => { h.counts.resolve++; return value; };
  error(await verify(h.message, verifyOptions(h)), 'KEY_REJECTED'); assert.equal(h.counts.resolve, 1); assert.equal(h.counts.verify, 0);
});
test('signer key/domain binding cannot be overridden by parameters', async () => {
  for (const change of [h => { h.signer.keyId = 'wrong'; }, h => { h.signer.trustDomain = 'wrong'; }, h => { h.parameters.find(p => p.name === 'keyid').value = 'other-key'; }]) {
    const h = setup(); change(h); error(await sign(h.message, signOptions(h)), 'KEY_REJECTED'); assert.equal(h.counts.sign, 0);
  }
});
for (const [name, mutate] of [
  ['kind', h => { h.profile.context.kind = 'response'; h.profile.requiredComponents = [component('@status'), component('@method', ['req']), component('@target-uri', ['req'])]; }],
  ['direction', h => { h.message.direction = 'inbound'; }], ['trust domain', h => { h.message.trustDomain = 'other'; }],
  ['authority', h => { h.profile.context.authority = 'evil.example'; }],
  ['scheme', h => { h.message.target.scheme = av('http'); h.message.target.uri.value = h.message.target.uri.value.replace('https:', 'http:'); }],
]) test(`context ${name} fails before key lookup`, async () => {
  const h = await signed(); mutate(h); const r = await verify(h.message, verifyOptions(h));
  // A request with a response policy is a mismatch independent of required coverage.
  error(r, 'CONTEXT_MISMATCH'); noCrypto(h); assert.equal(h.counts.clock, 0);
});
test('normalized configured authority matches the same HTTPS origin', async () => {
  const h = await signed(); h.profile.context.authority = 'EXAMPLE.COM:443'; assert.equal((await verify(h.message, verifyOptions(h))).ok, true);
});
for (const source of ['scheme', 'authority', 'uri', 'method']) test(`missing authoritative ${source} fails closed`, async () => {
  const h = await signed(); if (source === 'method') h.message.method = unavailable(); else h.message.target[source] = unavailable();
  error(await verify(h.message, verifyOptions(h)), 'COMPONENT_UNAVAILABLE'); noCrypto(h);
});
test('response needs its bound request, including its trust domain and URI', async () => {
  const h = await signed('response'); h.message.associatedRequest = unavailable(); error(await verify(h.message, verifyOptions(h)), 'COMPONENT_UNAVAILABLE'); noCrypto(h);
  const s = await signed('response'); s.message.associatedRequest.value.trustDomain = 'other'; error(await verify(s.message, verifyOptions(s)), 'CONTEXT_MISMATCH'); noCrypto(s);
});
test('required coverage belongs to one selected signature with exact full descriptors', async () => {
  const h = await signed(); editInput(h, entries => { entries[0].components = entries[0].components.filter(c => c.name !== '@method'); });
  error(await verify(h.message, verifyOptions(h)), 'COVERAGE_REQUIRED'); noCrypto(h);
  const s = await signed(); s.profile.requiredComponents.push(component('date', ['tr']));
  error(await verify(s.message, verifyOptions(s)), 'COVERAGE_REQUIRED'); noCrypto(s);
});
test('SF/tr/req coverage compares parameter sets but preserves signed parameter order', async () => {
  const h = setup('response'), c = component('x', ['tr', 'req', ['key', 'a']]);
  h.message.associatedRequest.value.trailers = av([field('x', 'a=1, b=2')]); h.profile.structuredFields.x = 'dictionary';
  h.profile.requiredComponents.push(component('x', [['key', 'a'], 'req', 'tr'])); h.covered.push(c);
  const r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true, JSON.stringify(r));
  assert.ok(r.value.signatureInput.includes('"x";tr;req;key="a"'));
  const result = await verify(install(h.message, r.value), verifyOptions(h)); assert.equal(result.ok, true);
  assert.deepEqual(result.value.covered.at(-1), c);
});
test('additional labels cannot downgrade fixed selection or contribute coverage', async () => {
  const h = await signed();
  const weak = serializeSignatureInput([{ label: 'weak', components: [], parameters: [] }]).value;
  h.message.headers.value.find(f => f.name === 'Signature-Input').value = bytes(weak + ', ' + h.signed.signatureInput);
  h.message.headers.value.find(f => f.name === 'Signature').value = bytes('weak=::, ' + h.signed.signature);
  assert.equal((await verify(h.message, verifyOptions(h))).ok, true); assert.equal(h.counts.resolve, 1);
  h.profile.label = 'weak'; error(await verify(h.message, verifyOptions(h)), 'MALFORMED_SIGNATURE'); assert.equal(h.counts.resolve, 1);
  h.profile.label = 'absent'; error(await verify(h.message, verifyOptions(h)), 'SIGNATURE_NOT_FOUND'); assert.equal(h.counts.resolve, 1);
  h.profile.label = 'sig1';
  editInput(h, entries => { entries.find(e => e.label === 'sig1').components = [component('@target-uri')]; entries.find(e => e.label === 'weak').components = [component('@method')]; });
  error(await verify(h.message, verifyOptions(h)), 'COVERAGE_REQUIRED'); assert.equal(h.counts.resolve, 1);
});
for (const [name, input, signature, code] of [
  ['duplicate label', 'sig1=(), sig1=()', 'sig1=::', 'MALFORMED_SIGNATURE'],
  ['mismatched labels', 'sig1=()', 'other=::', 'MALFORMED_SIGNATURE'],
  ['malformed unused signature', null, 'unused=:@@:', 'MALFORMED_SIGNATURE'],
  ['empty dictionaries', '', '', 'SIGNATURE_NOT_FOUND'],
  ['short authenticator', null, 'sig1=::', 'MALFORMED_SIGNATURE'],
  ['oversized authenticator', null, 'sig1=:' + Buffer.alloc(33).toString('base64') + ':', 'LIMIT_EXCEEDED'],
]) test(`entire envelope rejects ${name}`, async () => {
  const h = await signed(); const si = h.message.headers.value.find(f => f.name === 'Signature-Input'), sig = h.message.headers.value.find(f => f.name === 'Signature');
  if (input !== null) si.value = bytes(input);
  sig.value = bytes(signature); if (name === 'malformed unused signature') { si.value = bytes(h.signed.signatureInput + ', unused=()'); sig.value = bytes(h.signed.signature + ', ' + signature); }
  error(await verify(h.message, verifyOptions(h)), code); noCrypto(h);
});
test('envelope fields must be from complete headers, with no trailer ambiguity', async () => {
  const h = await signed(); h.message.headers = unavailable(); error(await verify(h.message, verifyOptions(h)), 'COMPONENT_UNAVAILABLE'); noCrypto(h);
  const s = setup(); error(await verify(s.message, verifyOptions(s)), 'SIGNATURE_NOT_FOUND');
  s.message.headers.value.push(field('Signature', 'sig1=::')); error(await verify(s.message, verifyOptions(s)), 'MALFORMED_SIGNATURE');
  const t = await signed(); t.message.trailers.value.push(field('Signature', 'sig1=::')); error(await verify(t.message, verifyOptions(t)), 'MALFORMED_SIGNATURE'); noCrypto(t);
});
test('signing refuses existing target signatures and never mutates its input', async () => {
  for (const name of ['Signature', 'Signature-Input']) {
    const h = setup(); h.message.headers.value.push(field(name, '')); error(await sign(h.message, signOptions(h)), 'MALFORMED_MESSAGE'); noCrypto(h);
  }
  const h = setup(), before = structuredClone(h.message); assert.equal((await sign(h.message, signOptions(h))).ok, true); assert.deepEqual(h.message, before);
});

for (const [name, created, expires, now, expected] of [
  ['future inclusive skew', 1005, 1065, 1000, true], ['future beyond skew', 1006, 1066, 1000, false],
  ['age inclusive skew', 1000, 1060, 1065, true], ['age beyond skew', 1000, 1060, 1066, false],
  ['expiry inclusive skew', 1000, 1000, 1005, true], ['expired', 1000, 1000, 1006, false],
  ['expiry before creation', 1000, 999, 1000, false], ['excess lifetime', 1000, 1061, 1000, false],
  ['negative creation', -1, 0, 0, false], ['SF maximum timestamp', 999999999999999, 999999999999999, 999999999999999, true],
]) test(`time policy: ${name}`, async () => {
  const h = setup(); h.parameters.find(p => p.name === 'created').value = created; h.parameters.find(p => p.name === 'expires').value = expires;
  h.clock.nowSeconds = () => { h.counts.clock++; return now; };
  const r = await sign(h.message, signOptions(h));
  if (expected) { assert.equal(r.ok, true, JSON.stringify(r)); assert.equal((await verify(install(h.message, r.value), verifyOptions(h))).ok, true); assert.equal(h.counts.clock, 2); }
  else { error(r, 'TIME_INVALID'); assert.equal(h.counts.clock, 1); assert.equal(h.counts.sign, 0); }
});
test('verifier time checks cannot be satisfied by the Date field', async () => {
  const h = await signed(); h.clock.nowSeconds = () => { h.counts.clock++; return 1066; };
  error(await verify(h.message, verifyOptions(h)), 'TIME_INVALID'); noCrypto(h); assert.equal(h.counts.clock, 1);
});
test('optional expiry still enforces age; overflowing timestamp arithmetic rejects', async () => {
  const h = setup(); h.profile.time.requireExpires = false; h.parameters = h.parameters.filter(p => p.name !== 'expires');
  const r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true);
  const wire = install(h.message, r.value); h.clock.nowSeconds = () => 1065; assert.equal((await verify(wire, verifyOptions(h))).ok, true);
  h.clock.nowSeconds = () => 1066; error(await verify(wire, verifyOptions(h)), 'TIME_INVALID');
  const s = setup(); s.profile.time.maxAgeSeconds = Number.MAX_SAFE_INTEGER; s.profile.time.clockSkewSeconds = 0;
  error(await sign(s.message, signOptions(s)), 'TIME_INVALID'); assert.equal(s.counts.sign, 0);
});
for (const n of [NaN, Infinity, -1, 1000.5, 1000000000000000, '1000', Promise.resolve(1000)]) test(`invalid clock result ${String(n)}`, async () => {
  const h = setup(); h.clock.nowSeconds = () => n; error(await sign(h.message, signOptions(h)), 'OPERATION_FAILED'); assert.equal(h.counts.sign, 0);
});
test('body-required profiles require an explicit digest capability', async () => {
  const h = setup(); h.profile.body = { mode: 'required', algorithm: 'sha-256' };
  h.profile.requiredComponents.push(component('content-digest'));
  error(await sign(h.message, signOptions(h)), 'CAPABILITY_UNAVAILABLE'); noCrypto(h); assert.equal(h.counts.clock, 0);
  error(await verify(h.message, verifyOptions(h)), 'CAPABILITY_UNAVAILABLE'); noCrypto(h);
});
test('replay-required verification requires a store; signing requires a nonce', async () => {
  const h = setup(); h.profile.replay = { mode: 'required', namespace: 'test' };
  error(await verify(h.message, verifyOptions(h)), 'CAPABILITY_UNAVAILABLE'); noCrypto(h);
  error(await sign(h.message, signOptions(h)), 'METADATA_REQUIRED'); noCrypto(h); assert.equal(h.counts.clock, 0);
});
test('excluded body is visibly unchecked, even if a digest field was signed', async () => {
  const h = setup(); h.covered.push(component('content-digest')); const r = await sign(h.message, signOptions(h)); assert.equal(r.ok, true);
  const wire = install(h.message, r.value); wire.body.bytes = bytes('changed body');
  const result = await verify(wire, verifyOptions(h)); assert.equal(result.ok, true); assert.equal(result.value.bodyIntegrity, 'not-checked');
});

for (const [name, mutate] of [
  ['unknown field', p => { p.extra = true; }], ['missing limits', p => { delete p.limits; }], ['missing one limit', p => { delete p.limits.workUnits; }],
  ['wrong version', p => { p.contractVersion = 2; }], ['algorithm negotiation', p => { p.allowedAlgorithms.push('ed25519'); }],
  ['wrong algorithm', p => { p.allowedAlgorithms = ['ed25519']; }], ['missing binding', p => { p.requiredComponents = [component('@method')]; }],
  ['duplicate coverage', p => { p.requiredComponents.push(component('@method')); }], ['unknown component', p => { p.requiredComponents.push(component('@unknown')); }],
  ['unknown SF schema', p => { p.requiredComponents.push(component('x', ['sf'])); }], ['wrong context', p => { p.requiredComponents.push(component('@status')); }],
  ['HTTP context', p => { p.context.scheme = 'http'; }], ['empty tag', p => { p.requiredTag = ''; }], ['duplicate keys', p => { p.keyPolicy.acceptedKeyIds.push('test-key'); }],
  ['empty key list', p => { p.keyPolicy.acceptedKeyIds = []; }], ['invalid label', p => { p.label = 'UPPER'; }], ['optional creation', p => { p.time.requireCreated = false; }],
  ['excess lifetime', p => { p.time.maxLifetimeSeconds = 61; }], ['negative skew', p => { p.time.clockSkewSeconds = -1; }],
  ['age overflow', p => { p.time.maxAgeSeconds = Number.MAX_SAFE_INTEGER; }], ['short HMAC limit', p => { p.limits.signatureBytes = 31; }],
  ['unknown body mode', p => { p.body.mode = 'optional'; }], ['required digest missing coverage', p => { p.body = { mode: 'required', algorithm: 'sha-256' }; }],
  ['empty replay namespace', p => { p.replay = { mode: 'required', namespace: '' }; }],
]) test(`invalid profile: ${name}`, async () => {
  const h = setup(); mutate(h.profile); error(await sign(h.message, signOptions(h)), 'PROFILE_INVALID'); noCrypto(h); assert.equal(h.counts.clock, 0);
});
test('oversized profile key allowlist is bounded', async () => {
  const h = setup(); h.profile.keyPolicy.acceptedKeyIds = Array.from({ length: 33 }, (_, i) => 'key' + i);
  error(await sign(h.message, signOptions(h)), 'LIMIT_EXCEEDED'); noCrypto(h);
});
test('missing/incorrect capability IDs and callbacks do not trigger fallback', async () => {
  for (const change of [o => { delete o.capabilities.clock; }, o => { o.capabilities.clock = {}; }, o => { delete o.capabilities.signer; }]) {
    const h = setup(), o = signOptions(h); change(o); error(await sign(h.message, o), 'CAPABILITY_UNAVAILABLE'); noCrypto(h);
  }
  const h = await signed(); h.keys.id = 'wrong-resolver'; error(await verify(h.message, verifyOptions(h)), 'CAPABILITY_UNAVAILABLE'); noCrypto(h);
  const s = setup(); const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  Object.defineProperty(globalThis, 'crypto', { configurable: true, get() { throw new Error('ambient crypto read'); } });
  try { assert.equal((await sign(s.message, signOptions(s))).ok, true); }
  finally { if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor); else delete globalThis.crypto; }
});
for (const which of ['clock', 'sign', 'resolve', 'verify']) test(`${which} exceptions are redacted and never retried`, async () => {
  const h = which === 'clock' || which === 'sign' ? setup() : await signed();
  let calls = 0;
  const thrower = () => { calls++; throw new BaseFailure('SENSITIVE-key-backend-detail'); };
  if (which === 'clock') h.clock.nowSeconds = thrower;
  if (which === 'sign') h.signer.sign = thrower;
  if (which === 'resolve') h.keys.resolve = thrower;
  if (which === 'verify') h.verifier.verify = thrower;
  const r = which === 'clock' || which === 'sign' ? await sign(h.message, signOptions(h)) : await verify(h.message, verifyOptions(h));
  error(r, 'OPERATION_FAILED'); assert.equal(JSON.stringify(r).includes('SENSITIVE'), false); assert.equal(calls, 1);
});
for (const output of [null, true, 'bytes', new ArrayBuffer(32), new Uint8Array(31), new Uint8Array(33)]) test(`invalid sign output ${Object.prototype.toString.call(output)}/${output?.byteLength}`, async () => {
  const h = setup(); h.signer.sign = () => output; error(await sign(h.message, signOptions(h)), 'OPERATION_FAILED');
});
for (const output of [0, 1, 'true', null, undefined, new Boolean(true)]) test(`invalid verify result ${String(output)} is not truthy success`, async () => {
  const h = await signed(); h.verifier.verify = () => output; error(await verify(h.message, verifyOptions(h)), 'OPERATION_FAILED');
});
test('profile/message/descriptor mutations during resolver await cannot change checked inputs', async () => {
  const h = await signed(); let release;
  h.keys.resolve = q => { h.counts.resolve++; h.queries.push(q); return new Promise(r => { release = r; }); };
  const pending = verify(h.message, verifyOptions(h)); assert.equal(typeof release, 'function');
  h.profile.label = 'weaker'; h.profile.requiredTag = 'changed'; h.profile.context.trustDomain = 'changed'; h.profile.requiredComponents.length = 0;
  h.message.contextId = 'changed'; h.message.method.value = 'GET'; h.message.headers.value.forEach(f => f.value.fill(65));
  h.clock.nowSeconds = () => { throw new Error('must not reread'); }; h.keys.resolve = () => { throw new Error('must not retry'); };
  release(h.verifier); const result = await pending; assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.value.contextId, 'test-request'); assert.equal(result.value.label, 'sig1'); assert.equal(result.value.covered[0].name, '@method'); assert.equal(h.counts.resolve, 1);
});
test('clock and async signer cannot rewrite captured metadata, identity or fields', async () => {
  const h = setup(); let release;
  h.clock.nowSeconds = () => { h.profile.requiredTag = 'changed'; h.parameters[0].value = 9999; h.signer.keyId = 'changed'; return 1000; };
  h.signer.sign = base => new Promise(resolve => { release = () => backend.signer.sign(base).then(resolve); });
  const pending = sign(h.message, signOptions(h)); assert.equal(typeof release, 'function');
  h.covered.length = 0; h.profile.label = 'changed'; h.message.headers.value[1].value.fill(65); release();
  const result = await pending; assert.equal(result.ok, true, JSON.stringify(result)); assert.ok(result.value.signatureInput.startsWith('sig1='));
  assert.ok(result.value.signatureInput.includes('created=1000')); assert.ok(result.value.signatureInput.includes('tag="test-domain"'));
});
test('verifier capability identity is captured before its async callback', async () => {
  const h = await signed(); h.verifier.verify = async (base, sig) => { h.verifier.keyVersion = 'changed'; return backend.verifier.verify(base, sig); };
  const result = await verify(h.message, verifyOptions(h)); assert.equal(result.ok, true); assert.equal(result.value.keyVersion, 'v1');
});
test('oversized/ambiguous envelopes and signing outputs fail before crypto', async () => {
  const h = await signed(); h.message.headers.value.push(field('Signature-Input', ' '.repeat(16384)));
  error(await verify(h.message, verifyOptions(h)), 'LIMIT_EXCEEDED'); noCrypto(h);
  const s = setup(); s.profile.limits.fieldCount = s.message.headers.value.length + 1;
  error(await sign(s.message, signOptions(s)), 'LIMIT_EXCEEDED'); assert.equal(s.counts.sign, 0);
  const t = setup(); t.profile.limits.envelopeFieldBytes = 100;
  error(await sign(t.message, signOptions(t)), 'LIMIT_EXCEEDED'); assert.equal(t.counts.sign, 0);
});
test('sign output fits ordinary-field and total-message ceilings before capability invocation', async () => {
  const h = setup(); h.covered = h.profile.requiredComponents; h.message.headers.value = [];
  const baseline = await sign(h.message, signOptions(h)); assert.equal(baseline.ok, true);
  const size = baseline.value.signatureInput.length + baseline.value.signature.length + 24;
  h.counts.sign = 0; h.profile.limits.totalFieldBytes = size - 1;
  error(await sign(h.message, signOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.sign, 0);
  h.profile.limits.totalFieldBytes = size;
  const result = await sign(h.message, signOptions(h)); assert.equal(result.ok, true); assert.equal((await verify(install(h.message, result.value), verifyOptions(h))).ok, true);
  h.counts.sign = 0; h.profile.limits.fieldValueBytes = result.value.signatureInput.length - 1;
  error(await sign(h.message, signOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.sign, 0);
});
test('one shared work budget spans profile, snapshot, envelope, base and output', async () => {
  for (const mode of ['sign', 'verify']) {
    const h = mode === 'sign' ? setup() : await signed();
    let lo = 1, hi = h.profile.limits.workUnits;
    const run = n => { h.profile.limits.workUnits = n; return mode === 'sign' ? sign(h.message, signOptions(h)) : verify(h.message, verifyOptions(h)); };
    while (lo < hi) { const mid = Math.floor((lo + hi) / 2); const r = await run(mid); if (r.ok) hi = mid; else { error(r, 'LIMIT_EXCEEDED'); lo = mid + 1; } }
    assert.equal((await run(lo)).ok, true); error(await run(lo - 1), 'LIMIT_EXCEEDED');
    const base = createSignatureBase(mode === 'sign' ? h.message : setup().message, { components: h.covered, parameters: h.parameters });
    assert.ok(lo > base.workUnits, 'policy/envelope must not each receive a fresh full budget');
  }
});
