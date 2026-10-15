// RFC 9421 §§2.1–2.4 and Appendix B.2 examples; RFC 8792 wrapping removed.
// Public fixture content, no production secrets. See rfc9421-LICENSE.txt.
export const av = value => ({ state: 'available', value });
export const unavailable = () => ({ state: 'unavailable', reason: 'not-retained' });
export const bytes = s => Uint8Array.from(s, c => c.charCodeAt(0));
export const field = (name, value) => ({ name, value: typeof value === 'string' ? bytes(value) : value });
export const component = (name, parameters = []) => ({ kind: name.startsWith('@') ? 'derived' : 'field', name,
  parameters: parameters.map(p => typeof p === 'string' ? { name: p, value: true } : { name: p[0], value: p[1] }) });
export const requestDigest = 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:';
export const responseDigest = 'sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:';
export function request() {
  return { kind: 'request', contextId: 'test-request', direction: 'inbound', trustDomain: 'test',
    headers: av([field('Host', 'example.com'), field('Date', 'Tue, 20 Apr 2021 02:07:55 GMT'),
      field('Content-Type', 'application/json'), field('Content-Digest', requestDigest), field('Content-Length', '18')]),
    trailers: av([]), body: { state: 'available', bytes: bytes('{"hello": "world"}') }, method: av('POST'),
    target: { original: av({ form: 'origin', raw: bytes('/foo?param=Value&Pet=dog') }),
      uri: av('https://example.com/foo?param=Value&Pet=dog'), scheme: av('https'), authority: av('example.com'),
      path: av('/foo'), query: av('?param=Value&Pet=dog') } };
}
export function response() {
  return { kind: 'response', contextId: 'test-response', direction: 'outbound', trustDomain: 'test',
    headers: av([field('Date', 'Tue, 20 Apr 2021 02:07:56 GMT'), field('Content-Type', 'application/json'),
      field('Content-Digest', responseDigest), field('Content-Length', '23')]),
    trailers: av([]), body: { state: 'available', bytes: bytes('{"message": "good dog"}') },
    status: av(200), associatedRequest: av(request()) };
}
export function partsOnly(values = {}) {
  const r = request();
  for (const key of Object.keys(r.target)) r.target[key] = unavailable();
  for (const [key, value] of Object.entries(values)) r.target[key] = av(value);
  return r;
}
const created = { name: 'created', value: 1618884473 };
const key = value => ({ name: 'keyid', value });
const names = list => list.map(n => typeof n === 'string' ? component(n) : n);
export const appendix = [
  { name: 'B.2.1', message: request, components: [], parameters: [created, key('test-key-rsa-pss'), { name: 'nonce', value: 'b3k2pp5k7z-50gnwp.yemd' }],
    input: '();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"', lines: [] },
  { name: 'B.2.2', message: request, components: names(['@authority', 'content-digest', component('@query-param', [['name', 'Pet']])]),
    parameters: [created, key('test-key-rsa-pss'), { name: 'tag', value: 'header-example' }],
    input: '("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    lines: ['"@authority": example.com', '"content-digest": ' + requestDigest, '"@query-param";name="Pet": dog'] },
  { name: 'B.2.3', message: request, components: names(['date', '@method', '@path', '@query', '@authority', 'content-type', 'content-digest', 'content-length']),
    parameters: [created, key('test-key-rsa-pss')],
    input: '("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
    lines: ['"date": Tue, 20 Apr 2021 02:07:55 GMT', '"@method": POST', '"@path": /foo', '"@query": ?param=Value&Pet=dog',
      '"@authority": example.com', '"content-type": application/json', '"content-digest": ' + requestDigest, '"content-length": 18'] },
  { name: 'B.2.4', message: response, components: names(['@status', 'content-type', 'content-digest', 'content-length']),
    parameters: [created, key('test-key-ecc-p256')],
    input: '("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    lines: ['"@status": 200', '"content-type": application/json', '"content-digest": ' + responseDigest, '"content-length": 23'] },
  { name: 'B.2.5', message: request, components: names(['date', '@authority', 'content-type']), parameters: [created, key('test-shared-secret')],
    input: '("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
    lines: ['"date": Tue, 20 Apr 2021 02:07:55 GMT', '"@authority": example.com', '"content-type": application/json'] },
  { name: 'B.2.6', message: request, components: names(['date', '@method', '@path', '@authority', 'content-type', 'content-length']),
    parameters: [created, key('test-key-ed25519')],
    input: '("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    lines: ['"date": Tue, 20 Apr 2021 02:07:55 GMT', '"@method": POST', '"@path": /foo', '"@authority": example.com',
      '"content-type": application/json', '"content-length": 18'] },
];
