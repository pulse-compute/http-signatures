import assert from 'node:assert/strict';
import { test } from 'node:test';
import { webcrypto } from 'node:crypto';
import { createSignatureBase, signatureBaseLimits } from '@pulse-compute/http-signatures/base';
import { parseSignatureInput, serializeSignatureInput } from '@pulse-compute/http-signatures/fields';
import { av, unavailable, bytes, field, component, request, response, partsOnly, appendix, requestDigest } from './fixtures/base-cases.js';

const model = (components, parameters = []) => ({ components: components.map(c => typeof c === 'string' ? component(c) : c), parameters });
const text = result => { assert.equal(result.ok, true, JSON.stringify(result)); return Buffer.from(result.value).toString('ascii'); };
function equivalent(message, value, options = {}) {
  const signed = createSignatureBase(message, value, options);
  assert.equal(signed.ok, true, JSON.stringify(signed));
  const wire = serializeSignatureInput([{ label: 'sig', ...value }]); assert.equal(wire.ok, true);
  const parsed = parseSignatureInput(wire.value); assert.equal(parsed.ok, true);
  const { components, parameters } = parsed.value[0];
  assert.deepEqual(createSignatureBase(message, { components, parameters }, options).value, signed.value);
  return text(signed);
}
function reject(message, components, code, options) {
  const result = createSignatureBase(message, model(components), options);
  assert.equal(result.ok, false); assert.equal(result.code, code);
  assert.deepEqual(Object.keys(result).sort(), ['code', 'ok', 'workUnits']);
  return result;
}
for (const v of appendix) test(`RFC 9421 ${v.name}: exact bytes from signing model and parsed input`, () => {
  const expected = [...v.lines, '"@signature-params": ' + v.input].join('\n');
  assert.equal(equivalent(v.message(), { components: v.components, parameters: v.parameters }), expected);
  const parsed = parseSignatureInput('sig=' + v.input); assert.equal(parsed.ok, true);
  const { components, parameters } = parsed.value[0];
  assert.deepEqual(createSignatureBase(v.message(), { components, parameters }).value, bytes(expected));
});
test('new base bytes verify the independent B.2.5 HMAC', async () => {
  const v = appendix[4], result = createSignatureBase(v.message(), { components: v.components, parameters: v.parameters });
  assert.equal(result.ok, true);
  const key = await webcrypto.subtle.importKey('raw', Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64'), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  assert.equal(await webcrypto.subtle.verify('HMAC', key, Buffer.from('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=', 'base64'), result.value), true);
});
test('ordinary fields retain instance order, empty values, internal whitespace and case of values', () => {
  const r = request(); r.headers = av([field('X-Test', ' \tone\t two \t'), field('x-test', '\tthree\r\n  \tfour'), field('X-Empty', ' \t')]);
  assert.equal(equivalent(r, model(['x-test', 'x-empty'])), '"x-test": one\t two, three four\n"x-empty": \n"@signature-params": ("x-test" "x-empty")');
  const reordered = structuredClone(r); reordered.headers.value.reverse();
  assert.notEqual(text(createSignatureBase(reordered, model(['x-test']))), text(createSignatureBase(r, model(['x-test']))));
});
test('binary wrapping preserves separate instances and obs-text octets', () => {
  const r = request(); r.headers = av([field('Example-Header', 'value, with, lots'), field('example-header', 'of, commas')]);
  const c = component('example-header', ['bs']);
  assert.equal(equivalent(r, model([c])), '"example-header";bs: :dmFsdWUsIHdpdGgsIGxvdHM=:, :b2YsIGNvbW1hcw==:\n"@signature-params": ("example-header";bs)');
  const distinct = text(createSignatureBase(r, model([c])));
  r.headers = av([field('example-header', 'value, with, lots, of, commas')]);
  assert.notEqual(text(createSignatureBase(r, model([c]))), distinct);
  r.headers = av([field('x', new Uint8Array([32, 128, 255, 9]))]);
  assert.equal(equivalent(r, model([component('x', ['bs'])])), '"x";bs: :gP8=:\n"@signature-params": ("x";bs)');
  reject(r, ['x'], 'UNSUPPORTED_COMPONENT');
});
test('all field byte values: legal octets wrap exactly, invalid controls fail', () => {
  for (let c = 0; c <= 255; c++) {
    const r = request(); r.headers = av([field('x', Uint8Array.of(65, c, 66))]);
    const result = createSignatureBase(r, model([component('x', ['bs'])]));
    if (c === 9 || (c >= 32 && c !== 127)) {
      assert.ok(text(result).startsWith('"x";bs: :' + Buffer.from([65, c, 66]).toString('base64') + ':'));
    } else assert.equal(result.code, 'MALFORMED_MESSAGE');
  }
});
test('Set-Cookie instances need explicit binary wrapping', () => {
  const r = request(); r.headers = av([field('Set-Cookie', 'a=1'), field('set-cookie', 'b=2')]);
  reject(r, ['set-cookie'], 'UNSUPPORTED_COMPONENT'); equivalent(r, model([component('set-cookie', ['bs'])]));
});
test('trailer and associated request scopes stay separate; parameter order stays exact', () => {
  const r = response(); r.headers = av([field('x', 'response header')]); r.trailers = av([field('x', 'response trailer')]);
  r.associatedRequest.value.headers = av([field('x', 'request header')]);
  r.associatedRequest.value.trailers = av([field('x', 'request trailer')]);
  const cs = [component('x'), component('x', ['tr']), component('x', ['req']), component('x', ['tr', 'req']), component('@method', ['req']), component('@status')];
  assert.equal(equivalent(r, model(cs)), '"x": response header\n"x";tr: response trailer\n"x";req: request header\n"x";tr;req: request trailer\n"@method";req: POST\n"@status": 200\n"@signature-params": ("x" "x";tr "x";req "x";tr;req "@method";req "@status")');
});
test('RFC §2.4 exact response-to-request binding base', () => {
  const r = response(); r.status = av(503);
  const digest = 'sha-512=:0Y6iCBzGg5rZtoXS95Ijz03mslf6KAMCloESHObfwnHJDbkkWWQz6PhhU9kxsTbARtY2PTBOzq24uJFpHsMuAg==:';
  r.headers = av([field('content-digest', digest), field('content-type', 'application/json')]);
  const cs = ['@status', 'content-digest', 'content-type', ...['@authority', '@method', '@path', 'content-digest'].map(n => component(n, ['req']))];
  assert.equal(equivalent(r, model(cs, [{ name: 'created', value: 1618884479 }, { name: 'keyid', value: 'test-key-ecc-p256' }])),
    '"@status": 503\n"content-digest": ' + digest + '\n"content-type": application/json\n"@authority";req: example.com\n"@method";req: POST\n"@path";req: /foo\n"content-digest";req: ' + requestDigest + '\n"@signature-params": ("@status" "content-digest" "content-type" "@authority";req "@method";req "@path";req "content-digest";req);created=1618884479;keyid="test-key-ecc-p256"');
});
test('RFC structured dictionary and selected member canonicalization', () => {
  const r = request(); r.headers = av([field('example-dict', ' a=1,    b=2;x=1;y=2'), field('example-dict', 'c=(a   b    c), d')]);
  const options = { structuredFields: { 'example-dict': 'dictionary' } };
  const cs = [component('example-dict', ['sf']), ...['a', 'd', 'b', 'c'].map(k => component('example-dict', [['key', k]]))];
  const base = equivalent(r, model(cs), options);
  assert.equal(base.split('\n').slice(0, 5).join('\n'), '"example-dict";sf: a=1, b=2;x=1;y=2, c=(a b c), d\n"example-dict";key="a": 1\n"example-dict";key="d": ?1\n"example-dict";key="b": 2;x=1;y=2\n"example-dict";key="c": (a b c)');
  equivalent(r, model([component('example-dict', ['sf', ['key', 'd']])]), options);
  reject(r, [component('example-dict', [['key', 'absent']])], 'COMPONENT_MISSING', options);
  reject(r, [component('example-dict', ['sf'])], 'UNSUPPORTED_COMPONENT');
  reject(r, [component('example-dict', [['key', 'a']])], 'UNSUPPORTED_COMPONENT', { structuredFields: { 'example-dict': 'list' } });
});
test('structured selectors combine with trailers and associated request', () => {
  const r = response(); r.associatedRequest.value.trailers = av([field('x', 'digest=:YQ:;valid=?1')]);
  const c = component('x', ['tr', ['key', 'digest'], 'req', 'sf']);
  assert.ok(equivalent(r, model([c]), { structuredFields: { x: 'dictionary' } }).startsWith('"x";tr;key="digest";req;sf: :YQ==:;valid\n'));
});
for (const [type, raw, expected] of [
  ['item', '-000.000;z=?1;a="a\\"b"', '0.0;z;a="a\\"b"'],
  ['list', 'one,  (02.300   "three");a=?0', 'one, (2.3 "three");a=?0'],
  ['dictionary', 'z=?1;a, a=:Zh==:', 'z;a, a=:Zg==:'],
]) test(`strict ${type} keeps semantic ordering`, () => {
  const r = request(); r.headers = av([field('x', raw)]);
  assert.ok(equivalent(r, model([component('x', ['sf'])]), { structuredFields: { x: type } }).startsWith('"x";sf: ' + expected + '\n'));
});
for (const [type, raw] of [
  ['dictionary', 'a=1,a=2'], ['item', 'a;x=1;x=2'], ['list', '((a))'], ['list', '(a\tb)'], ['item', '1.2345'],
  ['item', '1000000000000.0'], ['item', '1000000000000000'], ['item', ':a:'], ['item', ':YQ===:'],
  ['item', '"x\\n"'], ['item', '@123'], ['item', '%"date"'], ['dictionary', 'a=1,'],
]) test(`reject malformed/extension SF ${type} ${JSON.stringify(raw)}`, () => {
  const r = request(); r.headers = av([field('x', raw)]);
  reject(r, [component('x', ['sf'])], 'MALFORMED_MESSAGE', { structuredFields: { x: type } });
});
test('method case, authority/default port normalization, and URI spelling', () => {
  const r = partsOnly({ scheme: 'HTTPS', authority: 'EXAMPLE.com:443', uri: 'HTTPS://EXAMPLE.com:443/a/../%2f?', path: '/a/../%2f', query: '?' });
  r.method = av('pOsT');
  const base = equivalent(r, model(['@method', '@scheme', '@authority', '@target-uri', '@path', '@query']));
  assert.ok(base.startsWith('"@method": pOsT\n"@scheme": https\n"@authority": example.com\n"@target-uri": HTTPS://EXAMPLE.com:443/a/../%2f?\n"@path": /a/../%2f\n"@query": ?\n'));
});
for (const [authority, scheme, expected] of [['Example.com:80', 'http', 'example.com'], ['Example.com:443', 'http', 'example.com:443'],
  ['[2001:DB8::1]:443', 'https', '[2001:db8::1]'], ['[::ffff:192.0.2.1]:8443', 'https', '[::ffff:192.0.2.1]:8443'], ['EXAMPLE.com:', 'https', 'example.com']])
  test(`authority ${authority} under ${scheme}`, () => {
    assert.ok(equivalent(partsOnly({ authority, scheme }), model(['@authority'])).startsWith('"@authority": ' + expected + '\n'));
  });
test('empty path and absent query use required slash/question mark', () => {
  assert.equal(equivalent(partsOnly({ path: '', query: '' }), model(['@path', '@query'])), '"@path": /\n"@query": ?\n"@signature-params": ("@path" "@query")');
});
for (const [form, method, raw] of [['origin', 'POST', '/a/%2F?b=2&b=1'], ['absolute', 'GET', 'http://EXAMPLE.com:80/a?'],
  ['authority', 'CONNECT', '[::1]:443'], ['asterisk', 'OPTIONS', '*']]) test(`original ${form} request-target is exact`, () => {
  const r = partsOnly({ original: { form, raw: bytes(raw) } }); r.method = av(method);
  assert.ok(equivalent(r, model(['@request-target'])).startsWith('"@request-target": ' + raw + '\n'));
});
test('query parameter names/values follow RFC form decoding and percent encoding', () => {
  const r = partsOnly({ query: '?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&empty=&flag&x=%2B%26%3D%7E*' });
  const cs = ['var', 'bar', 'fa%C3%A7ade%22%3A%20', 'empty', 'flag', 'x'].map(n => component('@query-param', [['name', n]]));
  assert.equal(equivalent(r, model(cs)).split('\n').slice(0, 6).join('\n'), '"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value\n"@query-param";name="bar": with%20plus%20whitespace\n"@query-param";name="fa%C3%A7ade%22%3A%20": something\n"@query-param";name="empty": \n"@query-param";name="flag": \n"@query-param";name="x": %2B%26%3D%7E*');
});
test('repeated query names including encoding aliases cannot be selected', () => {
  for (const query of ['?a=1&a=2', '?a=1&%61=2', '?a+b=1&a%20b=2', '?a=1&a=1']) {
    const r = partsOnly({ query }), name = query.includes('+') ? 'a%20b' : 'a';
    reject(r, [component('@query-param', [['name', name]])], 'MALFORMED_MESSAGE');
    equivalent(r, model(['@query']));
  }
  equivalent(partsOnly({ query: '?a=1&a=2&b=3' }), model([component('@query-param', [['name', 'b']])]));
});
test('query is case sensitive, empty names retained, UTF-8 replacement is canonical', () => {
  const r = partsOnly({ query: '?=empty&x=%FF&Pet=dog&pet=cat&&' });
  for (const [name, expected] of [['', 'empty'], ['x', '%EF%BF%BD'], ['Pet', 'dog'], ['pet', 'cat']]) {
    assert.ok(equivalent(r, model([component('@query-param', [['name', name]])])).includes(': ' + expected + '\n'));
  }
  reject(r, [component('@query-param', [['name', 'PET']])], 'COMPONENT_MISSING');
});
for (const name of ['@method', '@target-uri', '@authority', '@scheme', '@request-target', '@path', '@query', '@query-param'])
  test(`response resolves ${name};req from the bound request`, () => {
    const parameters = name === '@query-param' ? [['name', 'Pet']] : [];
    const plain = equivalent(request(), model([component(name, parameters)])).split('\n')[0].split(': ').slice(1).join(': ');
    const bound = equivalent(response(), model([component(name, [...parameters, 'req'])])).split('\n')[0].split(': ').slice(1).join(': ');
    assert.equal(bound, plain);
  });
test('component and metadata order/escaping survive the received field representation', () => {
  const r = response(); r.associatedRequest.value.trailers = av([field('x', 'v')]);
  const v = model([component('x', ['req', 'tr']), '@status'], [{ name: 'tag', value: 'a"b\\c' }, { name: 'created', value: 42 }]);
  assert.equal(equivalent(r, v), '"x";req;tr: v\n"@status": 200\n"@signature-params": ("x";req;tr "@status");tag="a\\"b\\\\c";created=42');
});
for (const [form, method, raw] of [['origin', 'GET', 'not-a-path'], ['origin', 'CONNECT', '/'], ['absolute', 'CONNECT', 'https://example.com/'],
  ['authority', 'POST', 'example.com:443'], ['authority', 'CONNECT', 'example.com'], ['asterisk', 'GET', '*'], ['asterisk', 'OPTIONS', '**']])
  test(`reject inconsistent original form ${form}/${method}/${raw}`, () => {
    const r = partsOnly({ original: { form, raw: bytes(raw) } }); r.method = av(method); reject(r, ['@request-target'], 'MALFORMED_MESSAGE');
  });
test('CONNECT and OPTIONS asterisk are consistent with an empty target URI path', () => {
  for (const [method, form, raw, authority] of [['CONNECT', 'authority', 'example.com:443', 'example.com:443'], ['OPTIONS', 'asterisk', '*', 'example.com']]) {
    const r = partsOnly({ original: { form, raw: bytes(raw) }, uri: 'https://' + authority, scheme: 'https', authority, path: '', query: '' });
    r.method = av(method); equivalent(r, model(['@request-target', '@target-uri', '@path', '@query']));
  }
});
for (const [name, source] of [['@method', 'method'], ['@target-uri', 'uri'], ['@scheme', 'scheme'], ['@authority', 'authority'],
  ['@path', 'path'], ['@query', 'query'], ['@request-target', 'original']]) test(`unavailable ${name} is never guessed`, () => {
    const r = request(); if (source === 'method') r.method = unavailable(); else r.target[source] = unavailable();
    reject(r, [name], 'COMPONENT_UNAVAILABLE');
  });
test('authority with explicit port needs scheme; bare host does not', () => {
  reject(partsOnly({ authority: 'example.com:443' }), ['@authority'], 'COMPONENT_UNAVAILABLE');
  equivalent(partsOnly({ authority: 'example.com' }), model(['@authority']));
});
test('known absence, unavailable blocks and wrong contexts have distinct errors', () => {
  const r = request(); reject(r, ['missing'], 'COMPONENT_MISSING');
  r.headers = unavailable(); reject(r, ['missing'], 'COMPONENT_UNAVAILABLE');
  reject(request(), [component('date', ['tr'])], 'COMPONENT_MISSING');
  r.trailers = unavailable(); reject(r, [component('date', ['tr'])], 'COMPONENT_UNAVAILABLE');
  reject(request(), [component('@method', ['req'])], 'CONTEXT_MISMATCH');
  reject(request(), ['@status'], 'CONTEXT_MISMATCH');
  reject(response(), ['@method'], 'CONTEXT_MISMATCH');
  const s = response(); s.associatedRequest = unavailable(); reject(s, [component('@method', ['req'])], 'COMPONENT_UNAVAILABLE');
  s.status = unavailable(); reject(s, ['@status'], 'COMPONENT_UNAVAILABLE');
});
for (const [key, value] of [['uri', 'https://evil.example/foo?param=Value&Pet=dog'], ['scheme', 'http'], ['authority', 'evil.example'],
  ['path', '/foo/../foo'], ['query', '?Pet=dog&param=Value'], ['query', ''], ['path', '/%66oo']]) test(`inconsistent ${key} fails before signing any component`, () => {
    const r = request(); r.target[key] = av(value); reject(r, ['date'], 'MALFORMED_MESSAGE');
  });
test('URI/raw consistency is checked even with missing explicit parts', () => {
  reject(partsOnly({ uri: 'https://example.com/a?b=1', original: { form: 'origin', raw: bytes('/b?b=1') } }), ['@target-uri'], 'MALFORMED_MESSAGE');
  reject(partsOnly({ uri: 'https://example.com/a', original: { form: 'absolute', raw: bytes('https://evil.example/a') } }), ['@target-uri'], 'MALFORMED_MESSAGE');
});
test('proxy headers cannot fill a missing authoritative target', () => {
  const r = partsOnly(); r.headers = av([field('Forwarded', 'host=example.com;proto=https'), field('X-Forwarded-Host', 'example.com'), field('Host', 'example.com')]);
  reject(r, ['@authority'], 'COMPONENT_UNAVAILABLE');
});
for (const uri of ['https://user@example.com/', 'https://example.com/#fragment', 'https://example.com/a\\b', 'https://example.com/%zz', 'https://example.com/ bad', 'https://[::::]/', 'https://[::ffff:999.0.0.1]/'])
  test(`reject malformed URI ${uri}`, () => reject(partsOnly({ uri }), ['@target-uri'], 'MALFORMED_MESSAGE'));
test('unsupported pseudo-header request-target, URI schemes and IPvFuture are explicit', () => {
  reject(partsOnly({ original: { form: 'pseudo-headers', raw: bytes('/foo') } }), ['@request-target'], 'UNSUPPORTED_COMPONENT');
  reject(partsOnly({ scheme: 'ftp' }), ['@scheme'], 'UNSUPPORTED_COMPONENT');
  reject(partsOnly({ authority: '[v1.foo]' }), ['@authority'], 'UNSUPPORTED_COMPONENT');
});
for (const value of [99, 600, 200.1, '200', NaN]) test(`reject invalid status ${value}`, () => { const r = response(); r.status = av(value); reject(r, ['@status'], 'MALFORMED_MESSAGE'); });
for (const value of [100, 599]) test(`accept HTTP status boundary ${value}`, () => { const r = response(); r.status = av(value); equivalent(r, model(['@status'])); });
for (const value of ['x\ny', 'x\ry', 'x\r\ny', 'x\0y', 'x\x7fy']) test(`reject field controls ${JSON.stringify(value)} even when uncovered`, () => {
  const r = request(); r.headers.value.push(field('unused', value)); reject(r, ['date'], 'MALFORMED_MESSAGE');
});
test('invalid containers, accessors, descriptors and errors remain bounded and redacted', () => {
  reject(null, [], 'MALFORMED_MESSAGE');
  const r = request(); r.headers = av(new Array(2)); reject(r, [], 'MALFORMED_MESSAGE');
  let reads = 0; const s = request(); Object.defineProperty(s, 'headers', { get() { reads++; throw new Error('secret'); } });
  reject(s, [], 'MALFORMED_MESSAGE'); assert.equal(reads, 0);
  reject(request(), [component('@unknown')], 'UNSUPPORTED_COMPONENT');
  reject(request(), ['signature-input'], 'UNSUPPORTED_COMPONENT'); reject(request(), ['signature'], 'UNSUPPORTED_COMPONENT');
  reject(request(), [component('date', ['bs', 'sf'])], 'MALFORMED_SIGNATURE');
  reject(request(), ['date', 'date'], 'MALFORMED_SIGNATURE');
  reject(response(), [component('date', ['tr', 'req']), component('date', ['req', 'tr'])], 'MALFORMED_SIGNATURE');
});
test('caller snapshot is unchanged and base bytes are a defensive independent allocation', () => {
  const r = request(), before = structuredClone(r), value = model(['date']);
  const first = createSignatureBase(r, value); assert.deepEqual(r, before);
  r.headers.value[1].value.fill(65); assert.equal(text(first).split('\n')[0], '"date": Tue, 20 Apr 2021 02:07:55 GMT');
  first.value.fill(0); assert.notDeepEqual(createSignatureBase(before, value).value, first.value);
});

test('all ceilings can only be lowered with positive safe integers', () => {
  for (const [name, max] of Object.entries(signatureBaseLimits)) {
    for (const n of [0, -1, 1.2, (name === 'signatureBytes' ? 512 : max) + 1, Infinity]) reject(request(), ['date'], 'PROFILE_INVALID', { limits: { [name]: n } });
  }
  reject(request(), ['date'], 'PROFILE_INVALID', { limits: { unknown: 1 } });
  reject(request(), ['date'], 'PROFILE_INVALID', { structuredFields: { X: 'dictionary' } });
  reject(request(), ['date'], 'PROFILE_INVALID', { structuredFields: { x: 'guess' } });
});
test('field value, instance and count ceilings accept the boundary and reject one over', () => {
  const r = request(); r.headers = av([field('x', 'a'.repeat(16384))]); equivalent(r, model(['x']));
  r.headers.value[0].value = bytes('a'.repeat(16385)); reject(r, ['x'], 'LIMIT_EXCEEDED');
  r.headers = av(Array.from({ length: 16 }, () => field('x', 'a'))); equivalent(r, model(['x']));
  r.headers.value.push(field('X', 'a')); reject(r, ['x'], 'LIMIT_EXCEEDED');
  r.headers = av(Array.from({ length: 128 }, (_, i) => field('x' + i, 'a'))); equivalent(r, model(['x0']));
  r.trailers = av([field('y', 'a')]); reject(r, ['x0'], 'LIMIT_EXCEEDED');
});
test('total field bytes and names are counted across every block and associated request', () => {
  const r = response(); r.headers = av([]); r.associatedRequest.value.headers = av([]);
  const blocks = [r.headers.value, r.trailers.value, r.associatedRequest.value.headers.value, r.associatedRequest.value.trailers.value];
  for (let i = 0; i < 8; i++) blocks[i % 4].push(field('x', 'a'.repeat(16383)));
  equivalent(r, model(['@status'])); blocks[0][0].value = bytes('a'.repeat(16384)); reject(r, ['@status'], 'LIMIT_EXCEEDED');
  const s = request(); s.headers = av([field('x'.repeat(256), 'a')]); equivalent(s, model(['x'.repeat(256)]));
  s.headers.value[0].name += 'x'; reject(s, ['date'], 'LIMIT_EXCEEDED');
});
test('target and body limits account for supplied inputs without reading body contents', () => {
  const r = partsOnly({ path: '/' + 'a'.repeat(16379) }); // 4 method bytes + 16,380 path bytes
  equivalent(r, model(['@path'])); r.target.path.value += 'a'; reject(r, ['@path'], 'LIMIT_EXCEEDED');
  const s = response(); s.body.bytes = new Uint8Array(1048576 - s.associatedRequest.value.body.bytes.length);
  equivalent(s, model(['@status'])); s.body.bytes = new Uint8Array(s.body.bytes.length + 1); reject(s, ['@status'], 'LIMIT_EXCEEDED');
});
test('base byte limit is enforced exactly, including separators and final parameters', () => {
  const r = request(); r.headers = av(['a', 'b', 'c', 'd'].map(n => field(n, 'x'.repeat(n === 'd' ? 16000 : 16384))));
  const value = model(['a', 'b', 'c', 'd']), initial = createSignatureBase(r, value); assert.equal(initial.ok, true);
  r.headers.value[3].value = bytes('x'.repeat(16000 + 65536 - initial.value.length));
  assert.equal(createSignatureBase(r, value).value.length, 65536);
  r.headers.value[3].value = bytes('x'.repeat(r.headers.value[3].value.length + 1)); reject(r, value.components, 'LIMIT_EXCEEDED');
});
test('structured member and parameter boundaries and exact work budgets', () => {
  const r = request(), options = { structuredFields: { x: 'list' } }, value = model([component('x', ['sf'])]);
  r.headers = av([field('x', Array(128).fill('a').join(','))]); equivalent(r, value, options);
  r.headers.value[0] = field('x', Array(129).fill('a').join(',')); reject(r, value.components, 'LIMIT_EXCEEDED', options);
  r.headers.value[0] = field('x', 'a' + Array.from({ length: 32 }, (_, i) => ';p' + i).join('')); equivalent(r, value, options);
  r.headers.value[0] = field('x', 'a' + Array.from({ length: 33 }, (_, i) => ';p' + i).join('')); reject(r, value.components, 'LIMIT_EXCEEDED', options);
  for (const [message, m, opts] of [[request(), model(['date']), {}], [response(), model([component('@query-param', ['req', ['name', 'Pet']])]), {}],
    [request(), model([component('content-digest', ['sf'])]), { structuredFields: { 'content-digest': 'dictionary' } }]]) {
    const n = createSignatureBase(message, m, opts).workUnits;
    assert.equal(createSignatureBase(message, m, { ...opts, limits: { workUnits: n } }).ok, true);
    reject(message, m.components, 'LIMIT_EXCEEDED', { ...opts, limits: { workUnits: n - 1 } });
  }
});
test('deterministic hostile mutations either fail closed or preserve base byte equivalence', () => {
  let seed = 9421;
  const next = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0);
  const value = model([component('x', ['sf'])]), options = { structuredFields: { x: 'dictionary' } };
  for (let i = 0; i < 500; i++) {
    const source = bytes('a=1;b="x", c=(foo :YQ==:)'), r = request(); source[next() % source.length] = next() & 255;
    r.headers = av([field('x', source)]); const result = createSignatureBase(r, value, options);
    assert.ok(result.workUnits <= signatureBaseLimits.workUnits);
    if (result.ok) equivalent(r, value, options); else assert.ok(['MALFORMED_MESSAGE', 'UNSUPPORTED_COMPONENT'].includes(result.code), result.code);
  }
});
