// Authoring checks for the two design fixtures, not a runtime profile validator.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const fields = ['contractVersion', 'id', 'label', 'context', 'requiredComponents',
  'allowedAlgorithms', 'keyPolicy', 'time', 'requiredTag', 'body', 'replay', 'limits'];
const ceilings = { envelopeFieldBytes: 16384, totalFieldBytes: 131072,
  fieldValueBytes: 16384, fieldNameBytes: 256, fieldCount: 128, instancesPerName: 16,
  signatures: 8, components: 32, componentParameters: 5, signatureParameters: 6,
  metadataStringBytes: 512, labelBytes: 64, targetBytes: 16384,
  signatureBaseBytes: 65536, signatureBytes: 32, bodyBytes: 1048576, workUnits: 2097152 };
for (const kind of ['request', 'response']) {
  const profile = JSON.parse(await readFile(new URL(`../examples/profiles/${kind}.json`, import.meta.url)));
  assert.deepEqual(Object.keys(profile).sort(), fields.sort());
  assert.equal(profile.contractVersion, 1);
  for (const field of ['id', 'label', 'requiredTag']) assert.ok(profile[field].length > 0);
  assert.deepEqual(profile.allowedAlgorithms, ['hmac-sha256']);
  assert.equal(profile.context.kind, kind);
  assert.equal(profile.context.direction, 'inbound');
  assert.equal(profile.context.scheme, 'https');
  assert.ok(profile.context.authority && profile.context.trustDomain);
  assert.ok(profile.keyPolicy.resolverId && profile.keyPolicy.acceptedKeyIds.length);
  assert.equal(new Set(profile.keyPolicy.acceptedKeyIds).size, profile.keyPolicy.acceptedKeyIds.length);
  assert.equal(profile.time.requireCreated, true);
  assert.equal(profile.time.requireExpires, true);
  for (const key of ['maxAgeSeconds', 'maxLifetimeSeconds', 'clockSkewSeconds']) {
    assert.ok(Number.isSafeInteger(profile.time[key]) && profile.time[key] >= 0);
  }
  assert.ok(profile.time.maxLifetimeSeconds <= profile.time.maxAgeSeconds);
  assert.deepEqual(profile.body, { mode: 'required', algorithm: 'sha-256' });
  assert.deepEqual(Object.keys(profile.limits).sort(), Object.keys(ceilings).sort());
  for (const [key, value] of Object.entries(profile.limits)) {
    assert.ok(Number.isSafeInteger(value) && value > 0 && value <= ceilings[key], key);
  }
  assert.equal(profile.limits.signatureBytes, 32);
  const identities = profile.requiredComponents.map(c => {
    assert.deepEqual(Object.keys(c).sort(), ['kind', 'name', 'parameters']);
    assert.equal(c.kind, c.name.startsWith('@') ? 'derived' : 'field');
    assert.notEqual(c.name, '@signature-params');
    const names = c.parameters.map(p => p.name);
    assert.equal(new Set(names).size, names.length);
    for (const p of c.parameters) assert.deepEqual(p, { name: 'req', value: true });
    return `${c.name}${names.includes('req') ? ';req' : ''}`;
  });
  assert.equal(new Set(identities).size, identities.length);
  assert.ok(identities.includes('content-digest'));
  for (const needed of kind === 'request' ? ['@method', '@target-uri'] : ['@status', '@method;req', '@target-uri;req', 'x-request-id;req']) {
    assert.ok(identities.includes(needed), needed);
  }
  if (kind === 'request') { assert.equal(profile.replay.mode, 'required'); assert.ok(profile.replay.namespace); }
  else assert.deepEqual(profile.replay, { mode: 'none' });
}
console.log('Two design profiles have required policy fields, scoped coverage and bounded limits.');
