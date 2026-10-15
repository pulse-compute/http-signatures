// Deterministic logical-work/call receipts; no CPU, heap, RSS or host capacity claim.
import assert from 'node:assert/strict';
import { createContentDigest } from '../src/content-digest.js';
import { sign, verify } from '../src/protocol.js';
import { install } from '../test/fixtures/protocol-cases.js';
import { field } from '../test/fixtures/base-cases.js';
import { bodySetup, bodySignOptions, bodyVerifyOptions, expectedDigest, reset } from '../test/fixtures/content-cases.js';
const measurements = [];
for (const size of [0, 65536, 1048576]) {
  const h = bodySetup(); h.message.body.bytes = new Uint8Array(size);
  h.message.headers.value = h.message.headers.value.filter(f => f.name.toLowerCase() !== 'content-digest');
  h.message.headers.value.push(field('Content-Digest', expectedDigest(h.message.body.bytes)));
  const generated = await createContentDigest(h.message.body.bytes, { digest: h.digest }); assert.equal(generated.ok, true);
  const s = await sign(h.message, bodySignOptions(h)); assert.equal(s.ok, true);
  const wire = install(h.message, s.value); const original = h.replay.consume;
  h.replay.consume = async () => { h.counts.consume++; return true; }; // Threshold probes have no storage side effects.
  const maximum = h.profile.limits.workUnits, thresholds = {};
  for (const operation of ['sign', 'verify']) {
    let lo = 1, hi = maximum;
    const run = () => operation === 'sign' ? sign(h.message, bodySignOptions(h)) : verify(wire, bodyVerifyOptions(h));
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2); h.profile.limits.workUnits = mid;
      const r = await run(); if (r.ok) hi = mid; else { assert.equal(r.code, 'LIMIT_EXCEEDED'); lo = mid + 1; }
    }
    h.profile.limits.workUnits = lo - 1; reset(h); assert.deepEqual(await run(), { ok: false, code: 'LIMIT_EXCEEDED' });
    assert.equal(h.counts.consume, 0); if (operation === 'sign') assert.equal(h.counts.sign, 0);
    h.profile.limits.workUnits = lo; assert.equal((await run()).ok, true); thresholds[operation] = lo;
  }
  h.profile.limits.workUnits = maximum; h.replay.consume = original; reset(h);
  assert.equal((await verify(wire, bodyVerifyOptions(h))).ok, true);
  measurements.push({ bodyBytes: size, helperWorkUnits: generated.workUnits, minimumProtocolWorkUnits: thresholds, verifyCalls: { ...h.counts } });
}
console.log(JSON.stringify({ runtime: process.version, kind: 'logical package work; not CPU, heap, RSS, backend or store bounds', measurements }, null, 2));
