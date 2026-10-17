import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve, join, dirname } from 'node:path';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, cpSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { request as httpRequest } from 'node:http';
import { spawnSync } from 'node:child_process';
import { appendix } from '../test/fixtures/base-cases.js';
import { createHash, webcrypto } from 'node:crypto';
import { sign as referenceSign, verify as referenceVerify } from '../src/protocol.js';
import { QualificationReport, sourceIdentity, negativeIds, sha256 } from './qualification-report.mjs';
import { additionalQualification } from './qualification-cases.mjs';
import { signatureBaseLimits } from '../src/signature-base.js';
import { createHmacSigner, createHmacVerifier, createSha256Digest } from '../src/webcrypto.js';
if (!process.argv[2]) throw new Error('Usage: node integration/node.mjs /path/to/prepared/pulse [report.json]');
const pulseRoot = resolve(process.argv[2]);
const reportPath = process.argv[3] && resolve(process.argv[3]);
const require = createRequire(join(pulseRoot, 'package.json'));
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const report = new QualificationReport({
  startedAt: new Date().toISOString(),
  command: 'node integration/node.mjs /path/to/prepared/pulse [report.json]',
  fixture: { id: 'strict-hmac-post-v1', nowSeconds: 1000, maxBodyBytes: 65536 },
});
const root = mkdtempSync(join(tmpdir(), 'hms-integration-'));
function write(path, content) { const file = join(root, path); mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, content); }
const profile = { id: 'fixture', label: 'sig1', authority: 'example.test', tag: 'hms-example', trustDomain: 'fixture', maxAgeSeconds: 60, clockSkewSeconds: 5 };
const key = 'public-fixture-key-32-bytes-long!!';
const body = Buffer.from('{"message":"hello"}\n');
const headers = [['Content-Digest', 'sha-256=:' + createHash('sha256').update(body).digest('base64') + ':'], ['Authorization', 'private-authorization-fixture']];
const binding = {
  package: '@pulse-compute/http-signatures', contractId: 'pulse.http-signatures', artifact: 'pulse.http-signatures:fixture',
  operations: ['sign', 'verify'], secret: 'HMS_KEY', keyId: 'fixture-key', keyVersion: 'v1', trustDomain: 'fixture', origin: 'https://example.test'
};
try {
  report.metadata.profile = {
    algorithm: 'hmac-sha256', bodyDigest: 'sha-256', components: ['@method', '@target-uri', 'content-digest'],
    context: 'HTTPS request, origin-form target, uppercase method', replay: 'not-checked',
    unsupported: ['response', 'trailers', 'selectors', 'multiple labels', 'asymmetric crypto', 'required replay'],
    configuration: profile
  };
  report.metadata.sources = { package: sourceIdentity(packageRoot), pulse: sourceIdentity(pulseRoot) };
  report.metadata.toolchain = {
    node: process.version, v8: process.versions.v8, nodeOpenSSL: process.versions.openssl,
    platform: process.platform, architecture: process.arch,
    assemblyscript: JSON.parse(readFileSync(join(packageRoot, 'spikes/hms-07/toolchain/node_modules/assemblyscript/package.json'))).version,
    typescript: require('typescript/package.json').version,
    packageLockSha256: sha256(readFileSync(join(packageRoot, 'package-lock.json'))),
    assemblyscriptLockSha256: sha256(readFileSync(join(packageRoot, 'spikes/hms-07/toolchain/package-lock.json'))),
    pulseLockSha256: sha256(readFileSync(join(pulseRoot, 'pnpm-lock.yaml'))),
  };
  for (const [name, command, args] of [['npm', 'npm', ['--version']], ['pnpm', 'corepack', ['pnpm', '--version']],
  ['fastly', 'fastly', ['version']], ['viceroy', 'viceroy', ['--version']]]) {
    const result = spawnSync(command, args, { cwd: name === 'pnpm' ? pulseRoot : packageRoot, encoding: 'utf8', timeout: 10000 });
    report.metadata.toolchain[name] = result.status === 0 ? result.stdout.trim() : { status: 'unavailable' };
  }
  const { acceptanceToolchain } = require('./wasm/test/s3/acceptance-toolchain.cjs');
  const { capturePackageHttp, closePackageHttp } = require('./packages/provider-node/src/runtime/package-operations.js');
  const toolchain = acceptanceToolchain();
  const modules = join(root, 'node_modules/@pulse-compute'); mkdirSync(modules, { recursive: true });
  for (const [name, path] of [['pulse', 'packages/pulse'], ['runtime', 'packages/runtime'], ['wasm-contracts', 'wasm/packages/contracts']]) symlinkSync(join(pulseRoot, path), join(modules, name), 'dir');
  const pkg = join(modules, 'http-signatures'); mkdirSync(pkg);
  for (const path of ['package.json', 'README.md', 'src', 'as', 'native', 'pulse-profile.cjs', 'pulse.package.json', 'pulsewasm.manifest.cjs', 'pulsewasm.compiler.cjs']) cpSync(join(packageRoot, path), join(pkg, path), { recursive: true });
  write('package.json', JSON.stringify({ name: 'hms-integration', private: true, type: 'module' }));
  const configuration = {
    pulse: { entry: 'src/index.ts', defaultProfile: 'native', crypto: ['SHA-256', 'HMAC-SHA256'] },
    native: { host: 'node', target: 'native', dev: { secrets: { HMS_KEY: key } }, node: { bindings: { packages: { fixture: binding } } } },
    javascript: { host: 'node', target: 'javascript', dev: { secrets: { HMS_KEY: key } }, node: { bindings: { packages: { fixture: binding } } } }
  };
  write('.pulse/config.ts', `import {defineConfig} from '@pulse-compute/pulse'; export default defineConfig((_scope) => (${JSON.stringify(configuration)}));`);
  write('src/index.ts', `import {Pulse} from '@pulse-compute/pulse'; import {signatures} from '@pulse-compute/http-signatures/pulse';
const app = new Pulse({auto:true});
app.post('/sign',async ctx => { const result = await signatures.sign(ctx,${JSON.stringify({ binding: 'fixture', profile })}); return ctx.text(result); });
app.post('/verify',async ctx => { const result = await signatures.verify(ctx,${JSON.stringify({ binding: 'fixture', profile })}); return ctx.text(result); }); export default app;`);
  const source = readFileSync(join(root, 'src/index.ts'), 'utf8');
  const { project, compiled, jsProject, js, compileMeasurement } = await report.check('setup', () => {
    const project = toolchain.resolveProject({ cwd: root });
    const before = process.memoryUsage().rss, start = performance.now();
    const compiled = toolchain.compileNativeProjectInMemory(project);
    const compileMeasurement = { milliseconds: performance.now() - start, rssDeltaBytes: process.memoryUsage().rss - before };
    const jsProject = toolchain.resolveProject({ cwd: root, profile: 'javascript' });
    const js = toolchain.prepareJavascriptApplication(jsProject);
    return { project, compiled, jsProject, js, compileMeasurement };
  }, true);
  async function run(operation, fields, data, direction, target = 'native', override = {}, original = {}) {
    const handle = capturePackageHttp({ method: 'POST', target: '/events', headers: fields, body: data, ...original }, { origin: binding.origin, direction });
    try {
      const options = {
        ...toolchain.driver.executionOptions(project.providerConfig, {
          request: { method: 'POST', path: '/' + operation, url: 'https://example.test/' + operation, headers: [] },
          secrets: { HMS_KEY: key }, packageHttp: handle, packageWallClock: () => 1000, packageArtifacts: compiled.native.realizationArtifacts
        }), ...override
      };
      if (target === 'javascript') {
        const response = await toolchain.executeNodeJavascriptApplication(js.loaded.application, new Request('https://example.test/' + operation, { method: 'POST' }), options);
        assert.equal(response.status, 200); const result = await response.text();
        for (const sensitive of [key, 'private-authorization-fixture', body.toString()]) assert.ok(!result.includes(sensitive));
        return JSON.parse(result);
      }
      const execution = await toolchain.executeCanonicalNativeModule(compiled.native, options);
      assert.equal(execution.response.status, 200);
      const trace = JSON.stringify(execution.trace);
      for (const sensitive of [key, 'private-authorization-fixture', body.toString(), fields.find(pair => pair[0] === 'Signature')?.[1]].filter(Boolean)) assert.ok(!trace.includes(sensitive), 'private effect trace');
      return JSON.parse(execution.response.body);
    } finally { closePackageHttp(handle); }
  }
  const { signed, verified } = await report.check('native:exchange', async () => {
    const signed = await run('sign', headers, body, 'outbound'); assert.equal(signed.ok, true);
    const fields = [...headers, ['Signature-Input', signed.value.signatureInput], ['Signature', signed.value.signature]];
    const verified = await run('verify', fields, body, 'inbound');
    assert.equal(verified.ok, true);
    return { signed, verified };
  }, true);
  const incoming = [...headers, ['Signature-Input', signed.value.signatureInput], ['Signature', signed.value.signature]];
  await report.check('javascript:exchange', async () => {
    assert.deepEqual(await run('sign', headers, body, 'outbound', 'javascript'), signed);
    assert.deepEqual(await run('verify', incoming, body, 'inbound', 'javascript'), verified);
  });
  const bytes = value => new TextEncoder().encode(value), av = value => ({ state: 'available', value });
  const message = {
    kind: 'request', contextId: 'fixture', direction: 'outbound', trustDomain: 'fixture',
    method: av('POST'), headers: av(headers.map(([name, value]) => ({ name, value: bytes(value) }))), trailers: av([]), body: { state: 'available', bytes: body },
    target: { original: av({ form: 'origin', raw: bytes('/events') }), uri: av('https://example.test/events'), scheme: av('https'), authority: av('example.test'), path: av('/events'), query: av('') }
  };
  const refProfile = {
    contractVersion: 1, id: 'fixture', label: 'sig1', context: { kind: 'request', direction: 'outbound', trustDomain: 'fixture', scheme: 'https', authority: 'example.test' },
    requiredComponents: ['@method', '@target-uri', 'content-digest'].map(name => ({ kind: name[0] === '@' ? 'derived' : 'field', name, parameters: [] })),
    structuredFields: {}, allowedAlgorithms: ['hmac-sha256'], keyPolicy: { resolverId: 'fixture', acceptedKeyIds: ['fixture-key'] },
    time: { requireCreated: true, requireExpires: true, maxAgeSeconds: 60, maxLifetimeSeconds: 60, clockSkewSeconds: 5 }, requiredTag: 'hms-example',
    body: { mode: 'required', algorithm: 'sha-256' }, replay: { mode: 'none' }, limits: { ...signatureBaseLimits, bodyBytes: 65536 }
  };
  const cryptoKey = await webcrypto.subtle.importKey('raw', bytes(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const keyBinding = { subtle: webcrypto.subtle, key: cryptoKey, keyId: 'fixture-key', keyVersion: 'v1', trustDomain: 'fixture' };
  const signer = createHmacSigner(keyBinding).value, verifier = createHmacVerifier(keyBinding).value;
  const digest = createSha256Digest({ subtle: webcrypto.subtle }).value, clock = { nowSeconds: () => 1000 };
  const params = [{ name: 'created', value: 1000 }, { name: 'expires', value: 1060 }, { name: 'keyid', value: 'fixture-key' }, { name: 'alg', value: 'hmac-sha256' }, { name: 'tag', value: 'hms-example' }];
  await report.check('reference:exchange', async () => {
    assert.deepEqual(await referenceSign(message, { profile: refProfile, covered: refProfile.requiredComponents, parameters: params, capabilities: { signer, digest, clock } }), signed);
    const received = { ...message, direction: 'inbound', headers: av(incoming.map(([name, value]) => ({ name, value: bytes(value) }))) };
    const verifyProfile = { ...refProfile, context: { ...refProfile.context, direction: 'inbound' } };
    const checked = await referenceVerify(received, { profile: verifyProfile, capabilities: { keys: { id: 'fixture', resolve: () => verifier }, digest, clock } });
    assert.equal(checked.ok, true);
    for (const [key, value] of Object.entries(verified.value)) assert.deepEqual(checked.value[key], value);
  });
  const received = { ...message, direction: 'inbound', headers: av(incoming.map(([name, value]) => ({ name, value: bytes(value) }))) };
  const verifyProfile = { ...refProfile, context: { ...refProfile.context, direction: 'inbound' } };
  const referenceNegatives = [];
  const replace = (fields, name, value) => fields.map(pair => pair[0] === name ? [name, value] : pair);
  for (const target of ['native', 'javascript']) {
    const cases = [
      [replace(incoming, 'Signature', signed.value.signature.replace(/=:[A-Za-z0-9+/]/, '=:A')), body, {}, {}, 'SIGNATURE_INVALID'],
      [incoming, body, { secrets: { HMS_KEY: 'another-private-key-at-least-32-bytes' } }, {}, 'SIGNATURE_INVALID'],
      [incoming, body, { packageWallClock: () => 1100 }, {}, 'TIME_INVALID'],
      [incoming, body, { packageWallClock: () => 990 }, {}, 'TIME_INVALID'],
      [incoming, body, {}, { method: 'PUT' }, 'SIGNATURE_INVALID'],
      [incoming, body, {}, { target: '/elsewhere' }, 'SIGNATURE_INVALID'],
      [incoming, body, {}, { method: 'pOsT' }, 'UNSUPPORTED_COMPONENT'],
      [incoming, Buffer.from('changed'), {}, {}, 'BODY_DIGEST_INVALID'],
      [headers, body, {}, {}, 'SIGNATURE_NOT_FOUND'],
      [replace(incoming, 'Signature-Input', signed.value.signatureInput.replace('fixture-key', 'unknown-key')), body, {}, {}, 'KEY_REJECTED'],
      [replace(incoming, 'Signature-Input', signed.value.signatureInput + ';created=1000'), body, {}, {}, 'MALFORMED_SIGNATURE'],
      [replace(incoming, 'Signature-Input', signed.value.signatureInput.replace('@method', '@path')), body, {}, {}, 'UNSUPPORTED_COMPONENT'],
      [[...incoming, ['Signature', signed.value.signature]], body, {}, {}, 'SIGNATURE_NOT_FOUND'],
    ];
    for (const [index, [fields, data, override, original, code]] of cases.entries()) {
      await report.check(`${target}:negative:${negativeIds[index]}`, async () => {
        assert.deepEqual(await run('verify', fields, data, 'inbound', target, override, original), { ok: false, code });
      });
      // Compare failures inside the declared profile with the independent JS
      // protocol, not just the JS target running the same Wasm implementation.
      if (target === 'native' && ['SIGNATURE_INVALID', 'BODY_DIGEST_INVALID', 'TIME_INVALID', 'KEY_REJECTED'].includes(code)) {
        const rawTarget = original.target || '/events', split = rawTarget.indexOf('?');
        const refMessage = {
          ...received, method: av(original.method || 'POST'), headers: av(fields.map(([name, value]) => ({ name, value: bytes(value) }))),
          body: { state: 'available', bytes: data }, target: {
            ...received.target, original: av({ form: 'origin', raw: bytes(rawTarget) }),
            uri: av('https://example.test' + rawTarget), path: av(split < 0 ? rawTarget : rawTarget.slice(0, split)), query: av(split < 0 ? '' : rawTarget.slice(split))
          }
        };
        let selectedVerifier = verifier;
        if (override.secrets) {
          const alternate = await webcrypto.subtle.importKey('raw', bytes(override.secrets.HMS_KEY), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
          selectedVerifier = createHmacVerifier({ ...keyBinding, key: alternate }).value;
        }
        referenceNegatives.push(async () => {
          const result = await referenceVerify(refMessage, {
            profile: verifyProfile, capabilities: {
              keys: { id: 'fixture', resolve: () => selectedVerifier }, digest,
              clock: { nowSeconds: override.packageWallClock || clock.nowSeconds }
            }
          });
          assert.deepEqual(result, { ok: false, code });
        });
      }
    }
    for (const [index, override] of [{ packageHttp: {} }, { packageArtifacts: [] }, { packageBindings: {} }, { secrets: {} },
    { packageBindings: { fixture: { ...binding, operations: ['sign'] } } }].entries()) {
      await report.check(`${target}:grant:${index}`, () => assert.rejects(run('verify', incoming, body, 'inbound', target, override), error => !String(error).includes(key)));
    }
    await report.check(`${target}:body`, async () => {
      for (const length of [0, 65536]) {
        const large = new Uint8Array(length).fill(97);
        const digestHeaders = [['Content-Digest', 'sha-256=:' + createHash('sha256').update(large).digest('base64') + ':']];
        const largeSigned = await run('sign', digestHeaders, large, 'outbound', target);
        assert.equal(largeSigned.ok, true);
        assert.equal((await run('verify', [...digestHeaders, ['Signature-Input', largeSigned.value.signatureInput], ['Signature', largeSigned.value.signature]], large, 'inbound', target)).ok, true);
      }
      await assert.rejects(run('sign', headers, new Uint8Array(65537), 'outbound', target));
    });
  }
  await report.check('reference:negative', async () => { for (const check of referenceNegatives) await check(); });
  // RFC B.2.5 is a primitive vector, deliberately outside the strict profile.
  // Exercise the same package-owned Native base serializer, then the real
  // compiler-selected Crypto guest exports from this emitted application.
  await report.check('rfc-b25', async () => {
    const vector = appendix[4], expectedBase = [...vector.lines, '"@signature-params": ' + vector.input].join('\n');
    const testSource = join(root, 'base-vector.ts'), testWasm = join(root, 'base-vector.wasm');
    cpSync(join(packageRoot, 'as/base.ts'), join(root, 'base.ts'));
    writeFileSync(testSource, `import {signatureBase} from './base';
const value=String.UTF8.encode(signatureBase(['"date"','"@authority"','"content-type"'],['Tue, 20 Apr 2021 02:07:55 GMT','example.com','application/json'],${JSON.stringify(vector.input)}));
export function pointer():usize{return changetype<usize>(value);} export function length():i32{return value.byteLength;}`);
    const asc = spawnSync(process.execPath, [join(packageRoot, 'spikes/hms-07/toolchain/node_modules/assemblyscript/bin/asc.js'), testSource, '--outFile', testWasm, '--runtime', 'stub', '--maximumMemory', '32', '--optimize'], { encoding: 'utf8' });
    assert.ifError(asc.error); assert.equal(asc.status, 0, asc.stderr);
    const baseInstance = new WebAssembly.Instance(new WebAssembly.Module(readFileSync(testWasm)), { env: { abort() { throw Error('base vector aborted'); } } });
    const baseBytes = new Uint8Array(baseInstance.exports.memory.buffer, baseInstance.exports.pointer(), baseInstance.exports.length());
    assert.equal(new TextDecoder().decode(baseBytes), expectedBase);
    const controller = toolchain.instantiateCanonicalNativeModule(compiled.native);
    try {
      const { createNativeGuestSourceCryptoVerifier } = require('./wasm/packages/host-runtime/src/runtime/native-crypto-verifier.js');
      const nativeCrypto = createNativeGuestSourceCryptoVerifier({ plan: compiled.native.plan, exports: controller.exports });
      const rfcKey = Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64');
      assert.equal(Buffer.from(await nativeCrypto.verifier.bytes.hmacSha256(rfcKey, baseBytes)).toString('base64'), 'pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=');
    } finally { controller.close(); }
    await additionalQualification.rfc({ report, expectedBase, baseBytes, require });
  });
  // Build and launch both selected targets over real HTTP. Dot segments must
  // survive independently of the Web Request used for routing.
  const { createNodeLauncher } = require('./packages/provider-node/src/server/index.js');
  for (const target of ['native', 'javascript']) {
    await report.check(`${target}:build`, async () => {
      const selected = target === 'native' ? project : jsProject;
      const built = toolchain.buildProject(selected);
      assert.equal(built.status, 'built');
      function inspectOutput(directory) {
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
          const file = join(directory, entry.name);
          if (entry.isDirectory()) inspectOutput(file);
          else for (const sensitive of [key, 'private-authorization-fixture']) assert.ok(!readFileSync(file).includes(Buffer.from(sensitive)), 'private data excluded from build artifacts');
        }
      }
      inspectOutput(built.outDir);
      const launcher = createNodeLauncher({ target, buildDir: built.outDir, port: 0, packageBindings: { fixture: binding }, secrets: { HMS_KEY: key } });
      const ready = await launcher.start();
      try {
        const now = Math.floor(Date.now() / 1000), rawTarget = '/a/../verify?x=%2f';
        const outgoing = await run('sign', headers, body, 'outbound', target, { packageWallClock: () => now }, { target: rawTarget });
        const requestHeaders = Object.fromEntries([...headers, ['Signature-Input', outgoing.value.signatureInput], ['Signature', outgoing.value.signature], ['Content-Length', String(body.length)]]);
        const send = port => new Promise((resolve, reject) => {
          const req = httpRequest({ hostname: '127.0.0.1', port, path: rawTarget, method: 'POST', headers: requestHeaders }, res => {
            const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString() }));
          });
          req.setTimeout(10000, () => req.destroy(new Error('Fixture HTTP timeout')));
          req.on('error', reject); req.end(body);
        });
        const result = await send(ready.address.port);
        assert.equal(result.status, 200, result.text); assert.equal(JSON.parse(result.text).ok, true, result.text);
        await report.check(`${target}:dev`, async () => {
          const dev = await toolchain.startDevServer(selected, { port: 0, watch: false });
          try { const result = await send(dev.ready.port); assert.equal(result.status, 200, result.text); assert.equal(JSON.parse(result.text).ok, true, result.text); }
          finally { dev.server.close(); await dev.closed; }
        });
      } finally { await launcher.close(); }
    });
  }
  // Unsupported static forms are rejected while the known subset is compiled.
  await report.check('static-refusals', async () => {
    const entry = join(root, 'src/index.ts');
    try {
      for (const replacement of [JSON.stringify({ binding: 'fixture', profile: { ...profile, replay: 'required' } }), 'dynamicOptions']) {
        writeFileSync(entry, source.replace(JSON.stringify({ binding: 'fixture', profile }), replacement));
        assert.throws(() => toolchain.compileNativeProjectInMemory(toolchain.resolveProject({ cwd: root })), error => error.code === 'PULSE_PACKAGE_LOWERING_FAILED' && error.diagnostics.some(d => d.code === 'HMS_NATIVE_OPTIONS_STATIC'));
      }
      writeFileSync(entry, source.replace("const app =", "function unrelated(signatures: unknown) { return signatures; } const app ="));
      assert.throws(() => toolchain.compileNativeProjectInMemory(toolchain.resolveProject({ cwd: root })), error => error.diagnostics?.some(d => d.code === 'HMS_NATIVE_IMPORT_SHADOWED'));
    } finally { writeFileSync(entry, source); }
    assert.throws(() => toolchain.driver.createLoweringPlan(compiled.compiled.metadata, { bindings: { s3: {}, packages: {} } }), error => error.code === 'PULSE_PACKAGE_CAPABILITY_UNAVAILABLE');
  });
  await report.check('fastly-refusal', async () => {
    const fastlyDriver = require('./packages/provider-fastly/src/toolchain/index.js').createDriver();
    assert.throws(() => fastlyDriver.createLoweringPlan(compiled.compiled.metadata, {}), error => error.code === 'PULSE_PROVIDER_CAPABILITY_UNSUPPORTED');
    const decision = toolchain.classifyFastlyJavascriptCapability('package.invoke');
    assert.equal(decision.status, 'blocked');
    assert.equal(decision.reasonId, 'unknown-fastly-javascript-capability-fail-closed');
    report.metadata.fastly = {
      nativeAdmission: 'PULSE_PROVIDER_CAPABILITY_UNSUPPORTED', javascriptAdmission: decision,
      execution: 'unavailable', viceroy: 'not-run', deployed: 'not-run'
    };
  });
  await additionalQualification({
    report, toolchain, require, root, packageRoot, project, jsProject, compiled, compileMeasurement,
    source, configuration, run, profile, binding, key, body, headers, incoming, signed, verified, message, refProfile, verifyProfile, signer, verifier, digest, clock, params
  });
} catch {
  report.fatal = true;
} finally {
  rmSync(root, { recursive: true, force: true });
  report.metadata.finishedAt = new Date().toISOString();
  const result = report.result();
  if (reportPath) { mkdirSync(dirname(reportPath), { recursive: true }); writeFileSync(reportPath, JSON.stringify(result, null, 2) + '\n'); }
  console.log(JSON.stringify({
    outcome: result.outcome, checks: result.checks.length,
    failures: result.checks.filter(c => c.status !== 'pass').map(c => ({ id: c.id, status: c.status, failure: c.failure })), report: reportPath || null
  }));
  if (result.outcome === 'failed') process.exitCode = 1;
}
