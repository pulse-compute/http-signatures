// Logical counters only. This does not measure cryptographic CPU or peak memory.
import assert from 'node:assert/strict';
import { serializeSignature, parseSignatureEnvelope } from '../src/signature-fields.js';
import { sign, verify } from '../src/protocol.js';
import { algorithmCases, algorithmSetup } from '../test/fixtures/algorithm-cases.js';
import { signOptions, verifyOptions, install } from '../test/fixtures/protocol-cases.js';
const measurements = [];
for (const signatureBytes of [64, 256, 384, 512]) {
  const entries = Array.from({ length: 8 }, (_, i) => ({ label: 's' + i, signature: new Uint8Array(signatureBytes) }));
  const options = { limits: { signatureBytes } }, wire = serializeSignature(entries, options); assert.equal(wire.ok, true);
  const signatureInput = entries.map(e => e.label + '=()').join(', ');
  const run = limits => parseSignatureEnvelope({ signatureInput, signature: wire.value }, { limits });
  const parsed = run(options.limits); assert.equal(parsed.ok, true);
  assert.equal(run({ signatureBytes, workUnits: parsed.workUnits }).ok, true);
  assert.equal(run({ signatureBytes, workUnits: parsed.workUnits - 1 }).code, 'LIMIT_EXCEEDED');
  assert.equal(serializeSignature([...entries, { label: 's8', signature: new Uint8Array(signatureBytes) }], options).code, 'LIMIT_EXCEEDED');
  measurements.push({ signatureBytes, labels: 8, decodedSignatureBytes: 8 * signatureBytes,
    signatureFieldBytes: wire.value.length, serializeWorkUnits: wire.workUnits, parseEnvelopeWorkUnits: parsed.workUnits });
}
const protocol = [];
for (const c of algorithmCases) {
  const h = algorithmSetup(c), signed = await sign(h.message, signOptions(h)); assert.equal(signed.ok, true);
  const message = install(h.message, signed.value), maximum = h.profile.limits.workUnits, thresholds = {};
  for (const operation of ['sign', 'verify']) {
    const run = () => operation === 'sign' ? sign(h.message, signOptions(h)) : verify(message, verifyOptions(h));
    let lo = 1, hi = maximum;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2); h.profile.limits.workUnits = mid;
      const r = await run(); if (r.ok) hi = mid; else { assert.equal(r.code, 'LIMIT_EXCEEDED'); lo = mid + 1; }
    }
    h.profile.limits.workUnits = lo - 1; h.counts.sign = 0; h.counts.verify = 0;
    assert.deepEqual(await run(), { ok: false, code: 'LIMIT_EXCEEDED' });
    assert.equal(h.counts.sign, 0); assert.equal(h.counts.verify, 0);
    h.profile.limits.workUnits = lo; assert.equal((await run()).ok, true); thresholds[operation] = lo;
  }
  protocol.push({ algorithm: c.algorithm, minimumProtocolWorkUnits: thresholds });
}
console.log(JSON.stringify({ runtime: process.version, scope: 'Logical package work; not CPU, heap, RSS, backend or store bounds', measurements, protocol }, null, 2));
