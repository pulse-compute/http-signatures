// Reproducible logical-work/output receipts. No wall-clock or peak-memory claim.
import assert from 'node:assert/strict';
import { createSignatureBase } from '../src/signature-base.js';
import { appendix, request, response, partsOnly, av, bytes, field, component } from '../test/fixtures/base-cases.js';
const measurements = [];
function measure(name, message, components, parameters = [], options = {}, expected = true) {
  const r = createSignatureBase(message, { components, parameters }, options);
  assert.equal(r.ok, expected, name);
  if (!r.ok) assert.equal(r.code, 'LIMIT_EXCEEDED');
  measurements.push({ name, ok: r.ok, workUnits: r.workUnits, ...(r.ok ? { outputBytes: r.value.length } : { code: r.code }) });
  return r;
}
for (const v of appendix) measure(v.name, v.message(), v.components, v.parameters);
const r = request();
r.headers = av(Array.from({ length: 128 }, (_, i) => field('x' + i, 'a'.repeat(1000))));
measure('128 fields; 32 covered; index once', r, r.headers.value.slice(0, 32).map(f => component(f.name)));
const maximum = request(); maximum.headers = av(['a', 'b', 'c', 'd'].map(n => field(n, 'x'.repeat(n === 'd' ? 16000 : 16384))));
const covered = maximum.headers.value.map(f => component(f.name));
const initial = createSignatureBase(maximum, { components: covered, parameters: [] }); assert.ok(initial.ok);
maximum.headers.value[3].value = bytes('x'.repeat(16000 + 65536 - initial.value.length));
measure('65,536-byte base', maximum, covered);
maximum.headers.value[3].value = bytes('x'.repeat(maximum.headers.value[3].value.length + 1));
measure('65,537-byte base rejected', maximum, covered, [], {}, false);
const query = partsOnly({ query: '?a=' + '%FF'.repeat(1000) });
measure('form UTF-8 replacement expansion', query, [component('@query-param', [['name', 'a']])]);
const sf = request(); sf.headers = av([field('x', Array.from({ length: 128 }, (_, i) => 'p' + i + '=(' + 'a '.repeat(16).trimEnd() + ')').join(','))]);
measure('128 SF members; 16 items each', sf, [component('x', ['sf'])], [], { structuredFields: { x: 'dictionary' } });
measure('same SF field with 32 selected members shares work ceiling', sf,
  Array.from({ length: 32 }, (_, i) => component('x', [['key', 'p' + i]])), [], { structuredFields: { x: 'dictionary' } });
measure('same SF workload; lowered work ceiling rejects', sf,
  Array.from({ length: 32 }, (_, i) => component('x', [['key', 'p' + i]])), [],
  { structuredFields: { x: 'dictionary' }, limits: { workUnits: 1000000 } }, false);
measure('response and associated request', response(), [component('@status'), component('@method', ['req']), component('content-digest', ['req'])]);
console.log(JSON.stringify({ runtime: process.version, kind: 'logical package work; not CPU, heap or RSS bounds', measurements }, null, 2));
