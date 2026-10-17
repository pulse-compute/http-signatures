// Development evidence only. No private inputs, exception messages or key bytes are retained.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

export const features = ['admission', 'canonicalization', 'sign', 'verify', 'negative',
  'host-normalization', 'body-boundary', 'grants', 'redaction', 'cancellation',
  'deadline', 'replay', 'rfc-b25', 'http-build', 'http-dev', 'resources'];
export const targets = {
  native: { backend: 'package Wasm + guest-source:pulse-hmac-as', environment: 'Node Native' },
  javascript: { backend: 'package Wasm + runtime-builtin', environment: 'Node JavaScript' },
  reference: { backend: 'independent package JS protocol + explicit Web Crypto', environment: 'Node reference' },
  openssl: { backend: 'OpenSSL CLI HMAC over literal fixture base', environment: 'Independent CLI interface; shared OpenSSL lineage with Node' },
  'fastly-js-local': { unavailable: 'No generic package.invoke host binding; local JS is not Viceroy evidence.' },
  'fastly-js-viceroy': { unavailable: 'No generic package.invoke host binding; no Viceroy execution.' },
  'fastly-native-viceroy': { unavailable: 'No generic package.invoke host binding; no Viceroy execution.' },
  'fastly-native-deployed': { unavailable: 'No generic package.invoke host binding; no deployment requested or performed.' },
};
export const negativeIds = ['signature', 'key', 'expired', 'future', 'method', 'target', 'mixed-method',
  'body', 'missing', 'key-id', 'duplicate-created', 'component', 'duplicate-signature'];
export function qualificationPlan() {
  const plan = [];
  const add = (id, target, covered, scope = 'strict-profile') => plan.push({ id, targets: [target].flat(), features: [covered].flat(), scope });
  add('setup', ['native', 'javascript'], 'admission', 'compile/prepare actual imported package');
  for (const target of ['native', 'javascript']) {
    add(`${target}:exchange`, target, ['canonicalization', 'sign', 'verify', 'redaction']);
    for (const id of negativeIds) add(`${target}:negative:${id}`, target, 'negative');
    for (let i = 0; i < 5; i++) add(`${target}:grant:${i}`, target, 'grants');
    add(`${target}:body`, target, 'body-boundary');
    add(`${target}:normalization`, target, 'host-normalization');
    add(`${target}:lifecycle`, target, ['cancellation', 'deadline', 'redaction'], 'actual package artifact/effect at Node host seam with selected crypto, including late completion fencing');
    add(`${target}:replay`, target, 'replay', 'repeated verification is explicitly not-checked; no replay protection');
    add(`${target}:build`, target, ['http-build', 'redaction']);
    add(`${target}:dev`, target, 'http-dev');
    add(`${target}:openssl`, [target, 'openssl'], ['canonicalization', 'sign', 'verify', 'negative'], 'literal-base HMAC interoperability; no general external HTTP parser');
  }
  add('reference:exchange', 'reference', ['canonicalization', 'sign', 'verify']);
  add('reference:body', ['reference', 'native', 'javascript'], 'body-boundary', 'same boundary fixtures and exact fields across both targets and independent JS protocol');
  add('reference:negative', 'reference', 'negative');
  add('reference:replay', 'reference', 'replay', 'explicit fixture-only atomic store, duplicate and store failure');
  add('rfc-b25', ['native', 'javascript', 'reference', 'openssl'], 'rfc-b25', 'exact published base/MAC primitives; outside narrow strict profile');
  add('static-refusals', ['native', 'javascript'], 'admission', 'shared literal-option validator; Native compile diagnostics');
  add('fastly-refusal', Object.keys(targets).filter(t => t.startsWith('fastly-')), 'admission', 'provider admission probe only; never execution evidence');
  add('resources', ['native', 'javascript'], 'resources', 'physical Wasm and same-process incremental compile/RSS observations');
  return plan;
}
export class QualificationReport {
  constructor(metadata = {}) {
    this.metadata = metadata;
    this.checks = qualificationPlan().map(check => ({ ...check, status: 'not-run' }));
    this.fatal = false;
  }
  async check(id, run, required = false) {
    const check = this.checks.find(c => c.id === id);
    if (!check || check.status !== 'not-run') throw new Error('Unknown or repeated qualification check');
    const start = performance.now();
    try {
      const value = await run();
      check.status = 'pass';
      return value;
    } catch (error) {
      check.status = 'fail';
      // Untrusted exception text can contain the very secret being tested.
      check.failure = error?.code === 'ERR_ASSERTION' ? 'ASSERTION_FAILED' : 'EXECUTION_FAILED';
      if (required) throw new Error('Required qualification check failed');
    } finally { check.durationMs = Math.round((performance.now() - start) * 1000) / 1000; }
  }
  result() {
    const matrix = Object.entries(targets).map(([target, description]) => ({
      target, ...description,
      features: Object.fromEntries(features.map(feature => {
        const evidence = this.checks.filter(c => c.targets.includes(target) && c.features.includes(feature));
        let status = evidence.some(c => c.status === 'fail') ? 'fail'
          : description.unavailable ? 'unavailable'
            : !evidence.length ? 'unavailable'
              : evidence.some(c => c.status === 'not-run') ? 'not-run' : 'pass';
        if (feature === 'replay' && ['native', 'javascript'].includes(target) && status === 'pass') status = 'unsupported';
        return [feature, {
          status, checks: evidence.map(c => c.id),
          ...(status === 'unavailable' ? { reason: description.unavailable || 'Not exercised for this target by this qualification.' } : {}),
          ...(status === 'unsupported' ? { reason: 'Verification reports replay:not-checked; replay-required profile is refused.' } : {})
        }];
      }))
    }));
    const complete = !this.fatal && this.checks.every(c => c.status === 'pass');
    return {
      schema: 'hms.qualification.v1', ticket: 'HMS-09', ...this.metadata,
      outcome: complete ? 'completed-with-gaps' : 'failed', fatalHarnessFailure: this.fatal,
      checks: this.checks, matrix
    };
  }
}
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export function sourceIdentity(root) {
  function git(args, trim = true) {
    const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    if (result.error || result.status !== 0) throw new Error('Cannot identify qualification source');
    return trim ? result.stdout.trim() : result.stdout;
  }
  const status = git(['status', '--porcelain']);
  const untracked = git(['ls-files', '--others', '--exclude-standard', '-z']).split('\0').filter(Boolean);
  return {
    commit: git(['rev-parse', 'HEAD']), tree: git(['rev-parse', 'HEAD^{tree}']), dirty: Boolean(status),
    ...(status ? {
      trackedDiffSha256: sha256(git(['diff', 'HEAD', '--binary'], false)),
      untracked: untracked.map(path => ({ path, sha256: sha256(readFileSync(`${root}/${path}`)) }))
    } : {})
  };
}
