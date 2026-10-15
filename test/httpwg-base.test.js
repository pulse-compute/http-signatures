import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { structured } from '../src/structured-field.js';
import { BaseFailure } from '../src/base-support.js';
import { signatureBaseLimits, createSignatureBase } from '@pulse-compute/http-signatures/base';
import { request, av, field, component } from './fixtures/base-cases.js';

const files = ['binary', 'boolean', 'dictionary', 'item', 'list', 'listlist', 'number',
  'param-dict', 'param-list', 'param-listlist', 'string', 'token'];
// RFC 8941 permits last-wins duplicates; this security subset deliberately rejects
// them. These cases are tested as profile rejections, not silently skipped.
const restricted = new Set(['dictionary:duplicate key dictionary',
  'param-list:duplicate parameter with different positions']);
let cases = 0;
for (const file of files) {
  const fixtures = JSON.parse(await readFile(new URL(`fixtures/httpwg/${file}.json`, import.meta.url)));
  for (const f of fixtures) {
    cases++;
    test(`HTTPWG base ${file}: ${f.name}`, () => {
      const b = { limits: signatureBaseLimits, used: 0, spend(n) {
        this.used += n; assert.ok(this.used <= this.limits.workUnits);
      } };
      const source = f.raw.join(', ');
      let result, error;
      try { result = structured(source, f.header_type, undefined, b); } catch (e) { error = e; }
      const rejected = restricted.has(file + ':' + f.name) || f.must_fail || (file === 'binary' && f.name === 'extra padding');
      if (rejected) { assert.ok(error instanceof BaseFailure); assert.equal(error.code, 'MALFORMED_MESSAGE'); return; }
      assert.equal(error, undefined);
      assert.equal(result, (f.canonical ?? f.raw).join(', '));
      // Canonical output also reaches the public component path and remains stable.
      const r = request(); r.headers = av([field('x', result)]);
      const base = createSignatureBase(r, { components: [component('x', ['sf'])], parameters: [] }, { structuredFields: { x: f.header_type } });
      assert.equal(base.ok, true, JSON.stringify(base));
      assert.equal(Buffer.from(base.value).toString('ascii'), '"x";sf: ' + result + '\n"@signature-params": ("x";sf)');
    });
  }
}
test('HTTPWG corpus inventory is explicit', () => assert.equal(cases, 177));
