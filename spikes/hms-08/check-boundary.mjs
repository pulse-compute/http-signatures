// Read-only boundary evidence, not a runtime adapter or Native HMS realization.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  assert.ok(['--pulse-root', '--out'].includes(process.argv[i]));
  assert.ok(process.argv[i + 1]);
  args.set(process.argv[i], process.argv[i + 1]);
}
assert.ok(args.has('--pulse-root'), 'Supply the prepared Pulse checkout.');
const root = resolve(args.get('--pulse-root'));
const revision = 'c42b23e78d32114b69647f6ea6cc3b2d3150b36a';
const tree = '5da4aa501ed2b7d725d3455064bb0de9a5627392';
const git = (...arguments_) => execFileSync('git', arguments_, { cwd: root, encoding: 'utf8' }).trim();
function checkSources() {
  assert.equal(git('rev-parse', 'HEAD^{tree}'), tree, 'Unexpected Pulse source tree.');
  assert.equal(git('diff', '--name-only', 'HEAD'), '', 'Pulse tracked sources must be unchanged.');
}
checkSources();
const require = createRequire(join(root, 'package.json'));
const runtime = require('./packages/runtime/src/package.js');
const provider = require('./wasm/packages/contracts/src/provider/canonical-provider.js');
const { NODE_PROVIDER_DESCRIPTOR } = require('./packages/provider-node/src/runtime/canonical-api-runtime.js');
const adapter = require('./packages/provider-node/src/javascript/node-adapter.js');
const cases = [];
function refuses(name, code, operation) {
  assert.throws(operation, error => error.code === code);
  cases.push({ name, status: 'expected-refusal', code });
}

for (const operation of ['sign', 'verify']) {
  const capability = `http-signatures.${operation}`;
  refuses(`external-runtime-${operation}`, 'PULSE_RUNTIME_PACKAGE_EFFECT_UNTRUSTED', () =>
    runtime.createPackageRuntime({
      package: '@pulse-compute/http-signatures', contractId: 'pulse.http-signatures',
      providerKind: 'http-signatures', operations: {
        [operation]: { kind: capability, capability, result: 'ack' },
      },
    }));
  refuses(`node-provider-${operation}`, 'PULSE_PROVIDER_CAPABILITY_UNSUPPORTED', () =>
    provider.assertProviderSupports({ providerOperations: [{
      kind: capability, capability, operation, package: '@pulse-compute/http-signatures',
    }] }, NODE_PROVIDER_DESCRIPTOR));
  refuses(`provider-descriptor-cannot-add-${operation}`, 'PULSE_PROVIDER_CAPABILITY_UNKNOWN', () =>
    provider.createProviderDescriptor({
      id: 'fixture', capabilities: [capability], lowering: { [capability]: 'fixture.operation' },
    }));
}

// An application's record cannot mint an active request-owned context, even
// for an existing operation with an admitted runtime definition.
const digest = runtime.createPackageRuntime({
  package: '@pulse-compute/crypto', contractId: 'pulse.crypto', providerKind: 'crypto',
  operations: { digestText: { kind: 'crypto.digestText', capability: 'crypto.digestText', result: 'text-digest-result' } },
});
refuses('forged-request-context', 'PULSE_RUNTIME_PACKAGE_CONTEXT_REQUIRED', () => digest.context({
  req: { method: 'GET', url: 'https://fixture.test/', headers: [] }, trusted: true,
}));

// Public, synthetic metadata only. Adaptation loses original target and method
// spelling, so reconstruction from Web Request cannot establish HMS authority.
const input = { method: 'get', url: '/a/../b?x=%2f', rawHeaders: ['X-Fixture', 'one', 'x-fixture', 'two'] };
const adapted = await adapter.nodeRequestToWebRequest(input, { baseUrl: 'https://fixture.test' });
assert.equal(adapted.method, 'GET');
assert.equal(adapted.request.url, 'https://fixture.test/b?x=%2f');
assert.equal(Object.hasOwn(adapted, 'originalTarget'), false);
assert.deepEqual(adapted.headerPairs, [['X-Fixture', 'one'], ['x-fixture', 'two']]);
cases.push({ name: 'node-adapter-normalization', status: 'observed',
  methodChanged: true, targetChanged: true, rawFieldPairsRetained: true, originalTargetExposed: false });
checkSources();
const receipt = { ticket: 'HMS-08', status: 'blocked-on-contract-decision',
  pulse: { revision, tree }, runtime: process.version,
  scope: 'Runtime/provider admission and Node adapter probe; no Native HMS compile or execution.', cases };
const output = JSON.stringify(receipt, null, 2) + '\n';
if (args.has('--out')) writeFileSync(args.get('--out'), output);
process.stdout.write(output);
