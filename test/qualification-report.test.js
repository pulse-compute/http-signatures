import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { QualificationReport, qualificationPlan, targets, features } from '../integration/qualification-report.mjs';

test('qualification retains every target/feature when no execution was possible', () => {
  const result = new QualificationReport().result();
  assert.equal(result.outcome, 'failed');
  assert.equal(result.matrix.length, Object.keys(targets).length);
  for (const row of result.matrix) {
    assert.deepEqual(Object.keys(row.features), features);
    for (const feature of Object.values(row.features)) assert.notEqual(feature.status, 'pass');
  }
  assert.ok(result.checks.every(c => c.status === 'not-run'));
});
test('successful refusal probes cannot qualify Fastly or add Pulse replay protection', async () => {
  const report = new QualificationReport();
  for (const check of qualificationPlan()) await report.check(check.id, () => { });
  const result = report.result();
  assert.equal(result.outcome, 'completed-with-gaps');
  for (const row of result.matrix.filter(r => r.target.startsWith('fastly-'))) {
    for (const feature of Object.values(row.features)) assert.equal(feature.status, 'unavailable');
  }
  for (const row of result.matrix.filter(r => ['native', 'javascript'].includes(r.target))) {
    assert.equal(row.features.replay.status, 'unsupported');
    assert.equal(row.features.sign.status, 'pass');
  }
});
test('failed and unrun checks remain visible; failure details cannot leak fixture secrets', async () => {
  const report = new QualificationReport();
  await report.check('native:exchange', () => { throw Object.assign(new Error('private fixture'), { code: 'PRIVATE_FIXTURE' }); });
  await report.check('javascript:exchange', () => { });
  const result = report.result();
  assert.equal(result.outcome, 'failed');
  assert.equal(result.matrix.find(r => r.target === 'native').features.sign.status, 'fail');
  assert.equal(result.matrix.find(r => r.target === 'javascript').features.sign.status, 'not-run');
  assert.ok(!JSON.stringify(result).includes('PRIVATE_FIXTURE'));
  assert.ok(!JSON.stringify(result).includes('private fixture'));
  assert.equal(result.checks.find(c => c.id === 'native:exchange').failure, 'EXECUTION_FAILED');
});
test('an unexpected Fastly admission success fails the probe without hiding other targets', async () => {
  const report = new QualificationReport();
  await report.check('fastly-refusal', () => assert.fail('Expected a refusal'));
  for (const row of report.result().matrix.filter(r => r.target.startsWith('fastly-'))) {
    assert.equal(row.features.admission.status, 'fail');
    assert.equal(row.features.sign.status, 'unavailable');
  }
});
test('required setup failures and unknown/repeated checks never produce a green result', async () => {
  const report = new QualificationReport();
  await assert.rejects(report.check('setup', () => { throw Error('private setup'); }, true));
  await assert.rejects(report.check('setup', () => { }));
  await assert.rejects(report.check('unknown', () => { }));
  report.fatal = true;
  assert.equal(report.result().outcome, 'failed');
});

test('missing Pulse prerequisites still emit the full failed report and exit nonzero', () => {
  const directory = mkdtempSync(join(tmpdir(), 'hms-report-test-'));
  try {
    const output = join(directory, 'result.json');
    const run = spawnSync(process.execPath, [fileURLToPath(new URL('../integration/node.mjs', import.meta.url)), join(directory, 'missing-pulse'), output], { encoding: 'utf8', timeout: 10000 });
    assert.ifError(run.error); assert.equal(run.status, 1);
    const result = JSON.parse(readFileSync(output, 'utf8'));
    assert.equal(result.outcome, 'failed'); assert.equal(result.fatalHarnessFailure, true);
    assert.equal(result.matrix.length, Object.keys(targets).length);
    assert.equal(result.checks.length, qualificationPlan().length);
    assert.ok(result.checks.every(c => c.status === 'not-run'));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
