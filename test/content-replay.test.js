import test from 'node:test';
import assert from 'node:assert/strict';
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { parseSignatureInput, serializeSignatureInput } from '@pulse-compute/http-signatures/fields';
import { component, field, bytes } from './fixtures/base-cases.js';
import { install } from './fixtures/protocol-cases.js';
import { bodySetup, bodySignOptions, bodyVerifyOptions, signedBody, signUnchecked, expectedDigest, reset } from './fixtures/content-cases.js';
import { BaseFailure } from '../src/base-support.js';

const error = (r, code) => assert.deepEqual(r, { ok: false, code });
const digestField = h => h.message.headers.value.find(f => f.name.toLowerCase() === 'content-digest');
const setDigest = (h, s) => { digestField(h).value = bytes(s); };
function changeInput(h, fn) {
  const f = h.message.headers.value.find(f => f.name.toLowerCase() === 'signature-input');
  const parsed = parseSignatureInput(f.value); assert.equal(parsed.ok, true); fn(parsed.value);
  const serialized = serializeSignatureInput(parsed.value); assert.equal(serialized.ok, true); f.value = bytes(serialized.value);
}
for (const kind of ['request', 'response']) test(`${kind} verifies actual body and consumes once after MAC and digest`, async () => {
  const h = bodySetup(kind), before = structuredClone(h.message);
  const signed = await sign(h.message, bodySignOptions(h)); assert.equal(signed.ok, true);
  assert.deepEqual(h.message, before); assert.deepEqual(h.events, ['clock', 'digest', 'sign']);
  assert.equal(h.counts.consume, 0); assert.equal(h.counts.resolve, 0);
  h.message = install(h.message, signed.value); reset(h);
  const result = await verify(h.message, bodyVerifyOptions(h)); assert.equal(result.ok, true);
  assert.equal(result.value.bodyIntegrity, 'verified'); assert.equal(result.value.replay, 'consumed');
  assert.deepEqual(h.events, ['clock', 'resolve', 'verify', 'digest', 'consume']);
  assert.deepEqual(h.consumed, [{ namespace: 'test/nonces', profileId: 'hmac-' + kind + '-v1', trustDomain: 'test',
    keyId: 'test-key', nonce: 'public-nonce', retainUntilSeconds: 1065 }]);
  error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
});
for (const kind of ['request', 'response']) test(`${kind} body tamper with unchanged valid MAC fails`, async () => {
  const h = await signedBody(kind); h.message.body.bytes[0] ^= 1;
  error(await verify(h.message, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID');
  assert.deepEqual(h.events, ['clock', 'resolve', 'verify', 'digest']); assert.equal(h.counts.consume, 0);
});
test('signing checks existing digest against body, never rewrites it', async () => {
  const h = bodySetup(); h.message.body.bytes[0] ^= 1; const before = structuredClone(h.message);
  error(await sign(h.message, bodySignOptions(h)), 'BODY_DIGEST_INVALID');
  assert.equal(h.counts.sign, 0); assert.deepEqual(h.message, before);
});
test('changing both body and unsigned digest cannot preserve signature validity', async () => {
  const h = await signedBody(); h.message.body.bytes[0] ^= 1; setDigest(h, expectedDigest(h.message.body.bytes));
  error(await verify(h.message, bodyVerifyOptions(h)), 'SIGNATURE_INVALID');
  assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
});
for (const content of [new Uint8Array(), Uint8Array.from({ length: 256 }, (_, i) => i), bytes('{ "x": 1 }\n'), Uint8Array.of(0xc3, 0xa9, 0, 255)]) {
  test(`exact content bytes including empty/binary (${content.length})`, async () => {
    const h = bodySetup(); h.message.body.bytes = content; setDigest(h, expectedDigest(content));
    const r = await sign(h.message, bodySignOptions(h)); assert.equal(r.ok, true);
    const result = await verify(install(h.message, r.value), bodyVerifyOptions(h)); assert.equal(result.ok, true);
  });
}
test('whitespace reserialization and text transcoding change content identity', async () => {
  const h = bodySetup(); h.message.body.bytes = bytes('{ "x": 1 }'); setDigest(h, expectedDigest(h.message.body.bytes));
  const s = await sign(h.message, bodySignOptions(h)); h.message = install(h.message, s.value); h.message.body.bytes = bytes('{"x":1}');
  error(await verify(h.message, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID');
});
for (const reason of ['not-exposed', 'transformed', 'not-retained']) test(`unavailable body ${reason} is not empty`, async () => {
  const h = await signedBody(); h.message.body = { state: 'unavailable', reason };
  error(await verify(h.message, bodyVerifyOptions(h)), 'COMPONENT_UNAVAILABLE'); assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
  const s = bodySetup(); s.message.body = h.message.body;
  error(await sign(s.message, bodySignOptions(s)), 'COMPONENT_UNAVAILABLE'); assert.equal(s.counts.sign, 0);
});
test('missing Content-Digest cannot be replaced by legacy, representation, or trailer digest', async () => {
  for (const replacement of ['Digest', 'Repr-Digest', 'trailer']) {
    const h = await signedBody(); const f = digestField(h); h.message.headers.value = h.message.headers.value.filter(v => v !== f);
    if (replacement === 'trailer') h.message.trailers.value.push(f); else h.message.headers.value.push({ ...f, name: replacement });
    error(await verify(h.message, bodyVerifyOptions(h)), 'COMPONENT_MISSING'); assert.equal(h.counts.resolve, 0);
  }
});
for (const parameters of [[], ['sf'], ['bs'], ['tr'], [['key', 'sha-256']]]) test(`digest coverage must match unparameterized header (${JSON.stringify(parameters)})`, async () => {
  const h = await signedBody();
  changeInput(h, entries => { entries[0].components = entries[0].components.filter(c => c.name !== 'content-digest');
    if (parameters.length) entries[0].components.push(component('content-digest', parameters)); });
  h.profile.structuredFields['content-digest'] = 'dictionary';
  error(await verify(h.message, bodyVerifyOptions(h)), 'COVERAGE_REQUIRED'); assert.equal(h.counts.resolve, 0);
});
test('request digest coverage and bytes cannot satisfy a response body policy', async () => {
  const h = await signedBody('response'); changeInput(h, es => { es[0].components.find(c => c.name === 'content-digest').parameters = [{ name: 'req', value: true }]; });
  error(await verify(h.message, bodyVerifyOptions(h)), 'COVERAGE_REQUIRED');
  const s = await signedBody('response'); s.message.body.bytes = new Uint8Array(s.message.associatedRequest.value.body.bytes);
  error(await verify(s.message, bodyVerifyOptions(s)), 'BODY_DIGEST_INVALID');
});
const zero = ':' + Buffer.alloc(32).toString('base64') + ':';
for (const wire of ['', 'sha-256', 'sha-256=?1', 'sha-256=123', 'sha-256="abc"', 'sha-256=(' + zero + ')',
  'SHA-256=' + zero, 'sha-256=:a=:', 'sha-256=:AA===:', 'sha-256=:A:', 'sha-256=:!:',
  'sha-256=::', 'sha-256=:' + Buffer.alloc(31).toString('base64') + ':', 'sha-256=:' + Buffer.alloc(33).toString('base64') + ':',
  'sha-256=' + zero + ',', 'sha-256=' + zero + ', sha-256=' + zero, 'sha-256=' + zero + ';x=1;x=2',
  'sha-512=' + zero, 'md5=' + zero, 'sha-256=' + zero + ', unknown=?1']) {
  test(`malformed or missing sha-256 in MAC-valid digest: ${wire.slice(0, 45)}`, async () => {
    const h = bodySetup(); setDigest(h, wire); await signUnchecked(h);
    error(await verify(h.message, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID');
    assert.equal(h.counts.verify, 1); assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
  });
}
test('well-typed unknown algorithm and SF parameters do not replace sha-256', async () => {
  const h = bodySetup(); const original = expectedDigest(h.message.body.bytes);
  setDigest(h, 'future=:AQID:;note="x", ' + original + ';v=1;enabled');
  const signed = await sign(h.message, bodySignOptions(h)); assert.equal(signed.ok, true);
  assert.equal((await verify(install(h.message, signed.value), bodyVerifyOptions(h))).ok, true);
});
test('distinct repeated digest fields combine in order; duplicate algorithms fail', async () => {
  const h = bodySetup(); h.message.headers.value.push(field('content-digest', 'other=:AQID:'));
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  assert.equal((await verify(install(h.message, s.value), bodyVerifyOptions(h))).ok, true);
  const d = bodySetup(); d.message.headers.value.push({ ...digestField(d) }); await signUnchecked(d);
  error(await verify(d.message, bodyVerifyOptions(d)), 'BODY_DIGEST_INVALID');
});
test('known header/trailer digest ambiguity fails, not merged or used as fallback', async () => {
  const h = await signedBody(); h.message.trailers.value.push(field('Content-Digest', expectedDigest(h.message.body.bytes)));
  error(await verify(h.message, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID'); assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
});
for (const bad of ['a\r\nb', 'a\nb', 'a\rb', 'a\0b', 'a\x7fb']) test('CRLF/control injection rejected before authority calls', async () => {
  const h = await signedBody(); h.message.headers.value.push(field('uncovered', bad));
  error(await verify(h.message, bodyVerifyOptions(h)), 'MALFORMED_MESSAGE');
  assert.equal(h.counts.clock, 0); assert.equal(h.counts.resolve, 0); assert.equal(h.counts.consume, 0);
});
test('HTTP obs-fold unfolding is compatible but no digest recomputation by intermediaries', async () => {
  const h = bodySetup(); const d = expectedDigest(h.message.body.bytes);
  setDigest(h, d + ',\r\n other=:AQID:');
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  const wire = install(h.message, s.value); wire.headers.value.find(f => f.name === 'Content-Digest').value = bytes(d + ', other=:AQID:');
  assert.equal((await verify(wire, bodyVerifyOptions(h))).ok, true);
});
for (const name of ['nonce', 'tag', 'alg', 'created', 'expires']) test(`required metadata downgrade ${name} never consumes`, async () => {
  const h = await signedBody(); changeInput(h, es => { es[0].parameters = es[0].parameters.filter(p => p.name !== name); });
  error(await verify(h.message, bodyVerifyOptions(h)), 'METADATA_REQUIRED');
  assert.equal(h.counts.clock, 0); assert.equal(h.counts.resolve, 0); assert.equal(h.counts.consume, 0);
});
test('empty required nonce fails on both sign and verify before clock', async () => {
  const h = bodySetup(); h.parameters.find(p => p.name === 'nonce').value = '';
  error(await sign(h.message, bodySignOptions(h)), 'METADATA_REQUIRED'); assert.equal(h.counts.clock, 0);
  const v = await signedBody(); changeInput(v, es => { es[0].parameters.find(p => p.name === 'nonce').value = ''; });
  error(await verify(v.message, bodyVerifyOptions(v)), 'METADATA_REQUIRED'); assert.equal(v.counts.clock, 0);
});
test('weaker second signature cannot donate coverage or bypass selected label', async () => {
  const h = await signedBody();
  const input = h.message.headers.value.find(f => f.name === 'Signature-Input');
  const mac = h.message.headers.value.find(f => f.name === 'Signature');
  input.value = bytes(new TextDecoder().decode(input.value) + ', weak=("@method");created=1000');
  mac.value = bytes(new TextDecoder().decode(mac.value) + ', weak=' + zero);
  changeInput(h, es => { es[0].components = es[0].components.filter(c => c.name !== 'content-digest'); es[1].components.push(component('content-digest')); });
  error(await verify(h.message, bodyVerifyOptions(h)), 'COVERAGE_REQUIRED'); assert.equal(h.counts.consume, 0);
});
test('duplicate labels remain malformed before replay or body work', async () => {
  const h = await signedBody(); const f = h.message.headers.value.find(f => f.name === 'Signature'); h.message.headers.value.push({ ...f });
  error(await verify(h.message, bodyVerifyOptions(h)), 'MALFORMED_SIGNATURE'); assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
});

test('concurrent verification atomically admits exactly one nonce', async () => {
  const h = await signedBody();
  const results = await Promise.all(Array.from({ length: 24 }, () => verify(h.message, bodyVerifyOptions(h))));
  assert.equal(results.filter(r => r.ok).length, 1);
  assert.equal(results.filter(r => !r.ok && r.code === 'REPLAY_REJECTED').length, 23);
  assert.equal(h.counts.verify, 24); assert.equal(h.counts.digest, 24); assert.equal(h.counts.consume, 24); assert.equal(h.entries.size, 1);
});
for (const [expiry, age, skew, deadline] of [[1060, 60, 5, 1065], [1020, 60, 5, 1025], [undefined, 60, 5, 1065], [1000, 0, 0, 1000]]) {
  test(`nonce retention is inclusive min(age, expiry)+skew (${expiry}, ${age}, ${skew})`, async () => {
    const h = bodySetup(); h.profile.time = { ...h.profile.time, requireExpires: expiry !== undefined, maxAgeSeconds: age, maxLifetimeSeconds: age, clockSkewSeconds: skew };
    h.parameters = h.parameters.filter(p => p.name !== 'expires'); if (expiry !== undefined) h.parameters.push({ name: 'expires', value: expiry });
    const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
    h.message = install(h.message, s.value); h.now = deadline; h.storeNow = deadline; reset(h);
    assert.equal((await verify(h.message, bodyVerifyOptions(h))).ok, true);
    assert.equal(h.consumed[0].retainUntilSeconds, deadline);
    error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
    h.now = deadline + 1; reset(h);
    error(await verify(h.message, bodyVerifyOptions(h)), 'TIME_INVALID'); assert.equal(h.counts.consume, 0);
  });
}
test('clock skew for future creation is included in replay retention', async () => {
  const h = bodySetup(); h.parameters.find(p => p.name === 'created').value = 1005; h.parameters.find(p => p.name === 'expires').value = 1065;
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  assert.equal((await verify(install(h.message, s.value), bodyVerifyOptions(h))).ok, true);
  assert.equal(h.consumed[0].retainUntilSeconds, 1070);
});
test('store rechecks trusted time after an asynchronous verifier crossed expiry', async () => {
  const h = await signedBody(); h.now = 1065; h.storeNow = 1065;
  const original = h.verifier.verify; h.verifier.verify = async (...args) => { const valid = await original(...args); h.storeNow = 1066; return valid; };
  error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED'); assert.equal(h.counts.clock, 1); assert.equal(h.entries.size, 0);
});
test('failed body or MAC validation cannot burn a nonce', async () => {
  const h = await signedBody(), original = structuredClone(h.message);
  h.message.body.bytes[0] ^= 1; error(await verify(h.message, bodyVerifyOptions(h)), 'BODY_DIGEST_INVALID'); assert.equal(h.entries.size, 0);
  h.message = structuredClone(original); h.verifier.verify = async () => false;
  error(await verify(h.message, bodyVerifyOptions(h)), 'SIGNATURE_INVALID'); assert.equal(h.entries.size, 0);
  const fresh = bodySetup(); h.verifier.verify = fresh.verifier.verify;
  assert.equal((await verify(original, bodyVerifyOptions(h))).ok, true); assert.equal(h.entries.size, 1);
});
test('key rotation and label changes cannot reopen the same nonce', async () => {
  const h = await signedBody(); assert.equal((await verify(h.message, bodyVerifyOptions(h))).ok, true);
  h.verifier.keyVersion = 'rotated-v2'; error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
  const next = bodySetup(); next.profile.label = 'rotated-label'; next.signer.keyVersion = 'rotated-v2'; next.verifier.keyVersion = 'rotated-v2'; next.replay = h.replay;
  const s = await sign(next.message, bodySignOptions(next)); assert.equal(s.ok, true);
  error(await verify(install(next.message, s.value), bodyVerifyOptions(next)), 'REPLAY_REJECTED');
});
for (const dimension of ['namespace', 'profileId', 'trustDomain', 'keyId', 'nonce']) test(`replay tuple explicitly scopes ${dimension}`, async () => {
  const h = await signedBody(); assert.equal((await verify(h.message, bodyVerifyOptions(h))).ok, true);
  const next = bodySetup(); next.replay = h.replay;
  if (dimension === 'namespace') next.profile.replay.namespace = 'other';
  if (dimension === 'profileId') next.profile.id = 'other';
  if (dimension === 'trustDomain') next.profile.context.trustDomain = next.message.trustDomain = next.signer.trustDomain = next.verifier.trustDomain = 'other';
  if (dimension === 'keyId') { next.profile.keyPolicy.acceptedKeyIds = ['other']; next.signer.keyId = next.verifier.keyId = 'other'; next.parameters.find(p => p.name === 'keyid').value = 'other'; }
  if (dimension === 'nonce') next.parameters.find(p => p.name === 'nonce').value = 'other';
  const s = await sign(next.message, bodySignOptions(next)); assert.equal(s.ok, true);
  assert.equal((await verify(install(next.message, s.value), bodyVerifyOptions(next))).ok, true); assert.equal(h.entries.size, 2);
});
test('nonce stays consumed after application rejection, not rolled back by package', async () => {
  const h = await signedBody(); assert.equal((await verify(h.message, bodyVerifyOptions(h))).ok, true);
  // Application declines business authorization after the receipt.
  error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED');
});
test('replay required with excluded body is explicit; none mode invokes no store', async () => {
  const h = bodySetup(); h.profile.body = { mode: 'excluded' };
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true); h.message = install(h.message, s.value);
  h.message.body.bytes[0] ^= 1;
  const r = await verify(h.message, bodyVerifyOptions(h)); assert.equal(r.ok, true); assert.equal(r.value.bodyIntegrity, 'not-checked'); assert.equal(r.value.replay, 'consumed'); assert.equal(h.counts.digest, 0);
  const n = await signedBody('request', false); n.replay.consume = () => { throw Error('unused'); };
  for (let i = 0; i < 2; i++) { const result = await verify(n.message, bodyVerifyOptions(n)); assert.equal(result.ok, true); assert.equal(result.value.replay, 'not-checked'); }
});
for (const capability of ['digest', 'replay']) for (const invalid of [undefined, {}, null, { other: () => true }, { [capability === 'digest' ? 'sha256' : 'consume']: true }]) {
  test(`${capability} required shape fails closed (${String(invalid)})`, async () => {
    const h = await signedBody(); const options = bodyVerifyOptions(h); options.capabilities[capability] = invalid;
    error(await verify(h.message, options), 'CAPABILITY_UNAVAILABLE'); assert.equal(h.counts.clock, 0); assert.equal(h.counts.resolve, 0);
  });
}
for (const [cap, method] of [['digest', 'sha256'], ['replay', 'consume']]) test(`${cap} backend exceptions are fixed and redacted without retry`, async () => {
  const h = await signedBody(); let calls = 0;
  h[cap][method] = () => { calls++; throw new BaseFailure('sensitive-key-clock-store-detail'); };
  error(await verify(h.message, bodyVerifyOptions(h)), 'OPERATION_FAILED'); assert.equal(calls, 1);
  if (cap === 'digest') assert.equal(h.counts.consume, 0);
});
for (const output of [undefined, false, 'digest', new ArrayBuffer(32), new Uint8Array(31), new Uint8Array(33)]) test(`invalid digest output fails closed (${String(output).slice(0, 15)})`, async () => {
  const h = await signedBody(); h.digest.sha256 = () => output;
  error(await verify(h.message, bodyVerifyOptions(h)), 'OPERATION_FAILED'); assert.equal(h.counts.consume, 0);
  const s = bodySetup(); s.digest.sha256 = () => output;
  error(await sign(s.message, bodySignOptions(s)), 'OPERATION_FAILED'); assert.equal(s.counts.sign, 0);
});
for (const output of [undefined, 0, 1, 'true', {}, [true]]) test(`non-boolean replay result is not success (${String(output)})`, async () => {
  const h = await signedBody(); h.replay.consume = () => output;
  error(await verify(h.message, bodyVerifyOptions(h)), 'OPERATION_FAILED');
});
test('bounded/full store returns rejection, never age-only acceptance', async () => {
  const h = await signedBody(); let calls = 0; h.replay.consume = () => { calls++; return false; };
  error(await verify(h.message, bodyVerifyOptions(h)), 'REPLAY_REJECTED'); assert.equal(calls, 1);
});
test('body, digest fields and callbacks are captured before trusted clock callback', async () => {
  const h = bodySetup(), before = structuredClone(h.message), originalDigest = h.digest.sha256;
  h.clock.nowSeconds = () => { h.message.body.bytes.fill(0); digestField(h).value.fill(0); h.digest.sha256 = () => { throw Error('changed callback'); }; return 1000; };
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  h.clock.nowSeconds = () => 1000; h.digest.sha256 = originalDigest;
  assert.equal((await verify(install(before, s.value), bodyVerifyOptions(h))).ok, true);
});
test('async resolver cannot change owned body or replay namespace, nonce and callback', async () => {
  const h = await signedBody(); const original = h.keys.resolve;
  h.keys.resolve = async q => {
    await Promise.resolve(); h.message.body.bytes.fill(0); digestField(h).value.fill(0);
    h.profile.replay.namespace = 'changed'; h.replay.consume = () => { throw Error('changed callback'); };
    h.digest.sha256 = () => { throw Error('changed hash'); };
    return original(q);
  };
  const r = await verify(h.message, bodyVerifyOptions(h)); assert.equal(r.ok, true);
  assert.equal(h.consumed[0].namespace, 'test/nonces'); assert.equal(h.consumed[0].nonce, 'public-nonce');
});
test('invalid caller body containers cannot invoke streams or bodyVerified bypass', async () => {
  for (const body of [{ state: 'available', bytes: 'text' }, { state: 'available', bytes: new ArrayBuffer(0) },
    { state: 'available', bytes: new Uint8Array(), bodyVerified: true }, { stream: () => { throw Error('read'); } }]) {
    const h = await signedBody(); h.message.body = body;
    error(await verify(h.message, bodyVerifyOptions(h)), 'MALFORMED_MESSAGE'); assert.equal(h.counts.clock, 0);
  }
});
test('body length is bounded before copy/hash, including associated request bodies', async () => {
  const h = bodySetup(); h.profile.limits.bodyBytes = 64; h.message.body.bytes = new Uint8Array(64); setDigest(h, expectedDigest(h.message.body.bytes));
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  assert.equal((await verify(install(h.message, s.value), bodyVerifyOptions(h))).ok, true);
  h.message.body.bytes = new Uint8Array(65); reset(h);
  error(await sign(h.message, bodySignOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.clock, 0); assert.equal(h.counts.digest, 0);
  const r = bodySetup('response'); r.profile.limits.bodyBytes = r.message.body.bytes.length + r.message.associatedRequest.value.body.bytes.length - 1;
  error(await sign(r.message, bodySignOptions(r)), 'LIMIT_EXCEEDED'); assert.equal(r.counts.digest, 0);
});
test('digest dictionary member and parameter counts share profile ceilings', async () => {
  for (const dimension of ['members', 'parameters']) {
    const h = bodySetup(), good = expectedDigest(h.message.body.bytes);
    if (dimension === 'members') { h.profile.limits.structuredMembers = 2; setDigest(h, good + ', a=:AQ==:, b=:Ag==:'); }
    else { h.profile.limits.structuredParameters = 2; setDigest(h, good + ';a;b;c'); }
    await signUnchecked(h); error(await verify(h.message, bodyVerifyOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.digest, 0); assert.equal(h.counts.consume, 0);
  }
});
test('combined normalized digest values obey fieldValueBytes', async () => {
  const h = bodySetup(); const extra = 'other=:' + Buffer.alloc(12500).toString('base64') + ':';
  // Keep every raw field within the default field-value limit while exceeding the combined limit.
  h.message.headers.value.push(field('Content-Digest', extra.slice(0, 16000)), field('content-digest', extra.slice(16000)));
  await signUnchecked(h); error(await verify(h.message, bodyVerifyOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.digest, 0);
});
test('work exhaustion never consumes a nonce; exact full-operation threshold succeeds', async () => {
  const h = await signedBody(); h.replay.consume = () => { h.counts.consume++; return true; };
  let lo = 1, hi = h.profile.limits.workUnits;
  while (lo < hi) { const mid = Math.floor((lo + hi) / 2); h.profile.limits.workUnits = mid;
    const r = await verify(h.message, bodyVerifyOptions(h)); if (r.ok) hi = mid; else { assert.equal(r.code, 'LIMIT_EXCEEDED'); lo = mid + 1; } }
  h.profile.limits.workUnits = lo - 1; reset(h); error(await verify(h.message, bodyVerifyOptions(h)), 'LIMIT_EXCEEDED'); assert.equal(h.counts.consume, 0);
  h.profile.limits.workUnits = lo; assert.equal((await verify(h.message, bodyVerifyOptions(h))).ok, true);
});
test('opaque digest and replay errors have no backend or input text', async () => {
  const h = await signedBody(); h.replay.consume = () => Promise.reject(Error('secret/key?clock=1000'));
  const r = await verify(h.message, bodyVerifyOptions(h)); assert.deepEqual(Object.keys(r), ['ok', 'code']); assert.equal(JSON.stringify(r), '{"ok":false,"code":"OPERATION_FAILED"}');
});
