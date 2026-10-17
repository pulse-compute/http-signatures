import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash, webcrypto } from 'node:crypto';
import { sign, verify } from '../src/protocol.js';
import { createSignatureBase } from '../src/signature-base.js';
import { appendix } from '../test/fixtures/base-cases.js';
import { sha256 } from './qualification-report.mjs';

const bytes = value => new TextEncoder().encode(value);
const av = value => ({ state: 'available', value });
function externalMac(key, base) {
  // Public test keys only. Neither the CLI nor its output is a package dependency.
  const result = spawnSync('openssl', ['dgst', '-sha256', '-mac', 'HMAC', '-macopt',
    'hexkey:' + Buffer.from(key).toString('hex'), '-binary'], { input: Buffer.from(base), timeout: 10000 });
  assert.ifError(result.error); assert.equal(result.status, 0); assert.equal(result.stdout.length, 32);
  return result.stdout;
}

export async function additionalQualification(c) {
  const { report, toolchain, require, root, packageRoot, project, compiled, compileMeasurement, source, configuration,
    run, profile, binding, key, body, headers, incoming, signed, verified, message, refProfile, verifyProfile,
    signer, verifier, digest, clock, params } = c;
  const host = require('./packages/provider-node/src/runtime/package-operations.js');
  const version = spawnSync('openssl', ['version'], { encoding: 'utf8', timeout: 10000 });
  assert.ifError(version.error); assert.equal(version.status, 0);
  report.metadata.toolchain.externalOpenSSL = version.stdout.trim();
  report.metadata.fixture.bodyBytes = body.length;
  const input = '("@method" "@target-uri" "content-digest");created=1000;expires=1060;keyid="fixture-key";alg="hmac-sha256";tag="hms-example"';
  // Explicit expected serialization independent of both production serializers.
  const strictBase = '"@method": POST\n"@target-uri": https://example.test/events\n"content-digest": ' + headers[0][1] + '\n"@signature-params": ' + input;
  report.metadata.fixture.baseSha256 = sha256(strictBase);

  for (const target of ['native', 'javascript']) {
    await report.check(`${target}:openssl`, async () => {
      const mac = externalMac(bytes(key), bytes(strictBase));
      assert.equal(signed.value.signatureInput, 'sig1=' + input);
      const generated = await run('sign', headers, body, 'outbound', target);
      assert.equal(generated.value.signature, 'sig1=:' + mac.toString('base64') + ':');
      const independent = [...headers, ['Signature-Input', 'sig1=' + input], ['Signature', 'sig1=:' + mac.toString('base64') + ':']];
      assert.equal((await run('verify', independent, body, 'inbound', target)).ok, true);
      const changed = strictBase.replace('/events', '/changed');
      assert.notDeepEqual(externalMac(bytes(key), bytes(changed)), mac);
      assert.deepEqual(await run('verify', independent, body, 'inbound', target, {}, { target: '/changed' }), { ok: false, code: 'SIGNATURE_INVALID' });
    });
    await report.check(`${target}:replay`, async () => {
      for (let i = 0; i < 2; i++) {
        const result = await run('verify', incoming, body, 'inbound', target);
        assert.equal(result.ok, true); assert.equal(result.value.replay, 'not-checked');
      }
      // Both targets use the same package invocation validator.
      const { invocation } = require(join(packageRoot, 'pulse-profile.cjs'));
      assert.throws(() => invocation('verify', { binding: 'fixture', profile: { ...profile, replay: 'required' } }));
    });
    await report.check(`${target}:normalization`, async () => {
      const raw = '/a/../events?x=%2f&x=%2F';
      const outgoing = await run('sign', headers, body, 'outbound', target, {}, { target: raw });
      assert.equal(outgoing.ok, true);
      const fields = [...headers, ['Signature-Input', outgoing.value.signatureInput], ['Signature', outgoing.value.signature]];
      assert.equal((await run('verify', fields, body, 'inbound', target, {}, { target: raw })).ok, true);
      for (const targetPath of ['/events?x=%2f&x=%2F', '/a/../events?x=%2F&x=%2F', '/a/../events?x=%2F&x=%2f']) {
        assert.deepEqual(await run('verify', fields, body, 'inbound', target, {}, { target: targetPath }), { ok: false, code: 'SIGNATURE_INVALID' });
      }
      // Forwarded/Host headers cannot replace the explicit trusted HTTPS origin.
      assert.deepEqual(await run('verify', [...incoming, ['Host', 'attacker.test'], ['Forwarded', 'proto=http;host=attacker.test']], body, 'inbound', target), verified);
      for (const invalid of ['https://other.test/events', '//other.test/events', '/events#fragment', '/a\\b', '/a b']) {
        await assert.rejects(run('sign', headers, body, 'outbound', target, {}, { target: invalid }));
      }
      await assert.rejects(run('verify', incoming, body, 'inbound', target, { packageBindings: { fixture: { ...binding, origin: 'https://other.test' } } }));
    });
    await report.check(`${target}:lifecycle`, async () => {
      const controller = toolchain.instantiateCanonicalNativeModule(compiled.native);
      const selected = target === 'native' ? { bytes: controller.cryptoVerifier.bytes, realization: controller.cryptoRealization }
        : require('./packages/crypto/src/provider.cjs').bindJavascriptDigestMac(['SHA-256', 'HMAC-SHA256']);
      const expected = target === 'native' ? 'guest-source:pulse-hmac-as' : 'runtime-builtin';
      assert.ok(selected.realization.algorithms.every(a => a.available && a.realization === expected));
      report.metadata.realizations ??= {};
      report.metadata.realizations[target] = selected.realization;
      const handle = host.capturePackageHttp({ method: 'POST', target: '/events', headers, body }, { origin: binding.origin, direction: 'outbound' });
      const operation = compiled.compiled.metadata.providerOperations.find(e => e.capability === 'package.invoke' && e.payload.operation === 'sign');
      assert.ok(operation);
      const effect = { ...operation, kind: 'package.invoke', providerKind: 'package' };
      const options = {
        packageBindings: { fixture: binding }, packageArtifacts: compiled.native.realizationArtifacts,
        packageHttp: handle, packageWallClock: () => 1000, cryptoTarget: target,
        cryptoVerifier: selected, cryptoRealization: selected.realization
      };
      try {
        assert.deepEqual(JSON.parse(await host.executePackageOperation(effect, options, async () => key)), signed);
        const cancelled = new AbortController(); cancelled.abort(new Error('fixture cancellation'));
        let calls = 0;
        await assert.rejects(host.executePackageOperation(effect, { ...options, signal: cancelled.signal }, async () => { calls++; return key; }));
        assert.equal(calls, 0);
        // Expiry at the host budget checkpoint must fence a late crypto result.
        for (const mode of ['abort', 'deadline']) {
          const abort = new AbortController(); let release, entered, keyCopy, baseCopy, late;
          const pending = new Promise(resolve => { entered = resolve; });
          const failure = new Error(mode === 'abort' ? 'fixture cancellation' : 'fixture deadline');
          let now = 0;
          const { createRequestBudget } = require('./packages/runtime/src/internal/request-budget.js');
          const budget = createRequestBudget({ maxDurationMs: 10, requestClock: { now: () => now, setTimeout: () => 0, clearTimeout() { } } });
          const execution = host.executePackageOperation(effect, {
            ...options, signal: abort.signal,
            requestBudget: budget,
            cryptoVerifier: {
              bytes: {
                ...selected.bytes, hmacSha256: async (k, data) => {
                  keyCopy = k; baseCopy = data;
                  late = await selected.bytes.hmacSha256(k, data);
                  entered(); await new Promise(resolve => { release = resolve; }); return late;
                }
              }
            }
          }, async () => key);
          try {
            await Promise.race([pending, execution.then(() => { throw new Error('Crypto checkpoint was not reached'); })]);
            if (mode === 'abort') abort.abort(failure); else now = 10;
            release();
            await assert.rejects(execution, error => mode === 'abort' ? error === failure : error.code === 'PULSE_REQUEST_DEADLINE_EXCEEDED');
          } finally { budget.close(); }
          assert.ok(keyCopy.every(n => n === 0)); assert.ok(baseCopy.every(n => n === 0)); assert.ok(late.every(n => n === 0));
        }
        await assert.rejects(host.executePackageOperation(effect, options, async () => { throw new Error(key); }), error => {
          assert.equal(error.message, 'Package operation could not complete.'); return !String(error).includes(key);
        });
        await assert.rejects(host.executePackageOperation(effect, options, async () => { host.closePackageHttp(handle); return key; }), { code: 'PULSE_PACKAGE_SNAPSHOT_UNAVAILABLE' });
        await assert.rejects(host.executePackageOperation(effect, options, async () => key), { code: 'PULSE_PACKAGE_SNAPSHOT_UNAVAILABLE' });
      } finally { host.closePackageHttp(handle); controller.close(); }
    });
  }
  await report.check('reference:body', async () => {
    for (const length of [0, 65536, 65537]) {
      const data = new Uint8Array(length).fill(97);
      const fields = [['Content-Digest', 'sha-256=:' + createHash('sha256').update(data).digest('base64') + ':']];
      const outgoing = {
        ...message, body: { state: 'available', bytes: data },
        headers: av(fields.map(([name, value]) => ({ name, value: bytes(value) })))
      };
      const result = await sign(outgoing, {
        profile: refProfile, covered: refProfile.requiredComponents,
        parameters: params, capabilities: { signer, digest, clock }
      });
      if (length > 65536) { assert.deepEqual(result, { ok: false, code: 'LIMIT_EXCEEDED' }); continue; }
      assert.equal(result.ok, true);
      const received = {
        ...outgoing, direction: 'inbound', headers: av([...fields,
        ['Signature-Input', result.value.signatureInput], ['Signature', result.value.signature]].map(([name, value]) => ({ name, value: bytes(value) })))
      };
      assert.equal((await verify(received, { profile: verifyProfile, capabilities: { keys: { id: 'fixture', resolve: () => verifier }, digest, clock } })).ok, true);
      for (const target of ['native', 'javascript']) assert.deepEqual(await run('sign', fields, data, 'outbound', target), result);
    }
  });
  await report.check('reference:replay', async () => {
    const replayProfile = { ...refProfile, replay: { mode: 'required', namespace: 'fixture' } };
    const outgoing = await sign(message, {
      profile: replayProfile, covered: refProfile.requiredComponents,
      parameters: [...params, { name: 'nonce', value: 'qualification-nonce' }], capabilities: { signer, digest, clock }
    });
    assert.equal(outgoing.ok, true);
    const received = {
      ...message, direction: 'inbound', headers: av([...headers, ['Signature-Input', outgoing.value.signatureInput],
      ['Signature', outgoing.value.signature]].map(([name, value]) => ({ name, value: bytes(value) })))
    };
    const entries = new Set();
    const replay = { consume(entry) { const tuple = JSON.stringify(entry); if (entries.has(tuple)) return false; entries.add(tuple); return true; } };
    const options = { profile: { ...verifyProfile, replay: replayProfile.replay }, capabilities: { keys: { id: 'fixture', resolve: () => verifier }, digest, clock, replay } };
    const results = await Promise.all([verify(received, options), verify(received, options)]);
    assert.equal(results.filter(r => r.ok).length, 1);
    assert.deepEqual(results.find(r => !r.ok), { ok: false, code: 'REPLAY_REJECTED' });
    assert.deepEqual(await verify(received, { ...options, capabilities: { ...options.capabilities, replay: { consume() { throw new Error(key); } } } }), { ok: false, code: 'OPERATION_FAILED' });
  });
  await report.check('resources', async () => {
    const artifact = compiled.native.realizationArtifacts.find(a => a.kind === 'package-runtime-wasm');
    assert.ok(artifact);
    const wasm = Buffer.from(artifact.data.wasm, 'base64');
    const instance = new WebAssembly.Instance(new WebAssembly.Module(wasm), {
      env: { abort() { throw Error('abort'); } },
      pulse_package: { input_len() { return -1; }, input_read() { return -1; } }
    });
    const memory = instance.exports.memory;
    const initialPages = memory.buffer.byteLength / 65536;
    memory.grow(32 - initialPages);
    assert.throws(() => memory.grow(1), RangeError);
    const entry = join(root, 'src/index.ts'), configPath = join(root, '.pulse/config.ts');
    const configSource = readFileSync(configPath, 'utf8');
    const measure = () => {
      const rss = process.memoryUsage().rss, start = performance.now();
      const result = toolchain.compileNativeProjectInMemory(toolchain.resolveProject({ cwd: root }));
      return {
        wasmBytes: result.native.wasm.length, wasmSha256: sha256(result.native.wasm),
        milliseconds: performance.now() - start, rssDeltaBytes: process.memoryUsage().rss - rss
      };
    };
    let baseline, full;
    try {
      const baselineConfig = structuredClone(configuration);
      baselineConfig.pulse.crypto = [];
      for (const target of ['native', 'javascript']) { baselineConfig[target].node.bindings.packages = {}; delete baselineConfig[target].dev; }
      writeFileSync(configPath, `import {defineConfig} from '@pulse-compute/pulse'; export default defineConfig((_scope) => (${JSON.stringify(baselineConfig)}));`);
      writeFileSync(entry, `import {Pulse} from '@pulse-compute/pulse'; const app=new Pulse({auto:true}); app.post('/sign',async ctx=>{return ctx.text('ok');}); app.post('/verify',async ctx=>{return ctx.text('ok');}); export default app;`);
      baseline = measure();
    } finally { writeFileSync(entry, source); writeFileSync(configPath, configSource); }
    full = measure();
    report.metadata.resources = {
      packageWasm: { bytes: wasm.length, sha256: sha256(wasm), initialPages, maximumPages: 32, maximumBytes: 2097152 },
      appWasm: { bytes: compiled.native.wasm.length, sha256: sha256(compiled.native.wasm) },
      baselineRecipe: 'Two constant-text POST routes; no package imports, crypto declarations or package bindings.',
      baseline, full, initialCompile: compileMeasurement,
      incremental: {
        appWasmBytes: full.wasmBytes - baseline.wasmBytes, physicalWasmBytes: full.wasmBytes + wasm.length - baseline.wasmBytes,
        compileMilliseconds: full.milliseconds - baseline.milliseconds, rssDeltaBytes: full.rssDeltaBytes - baseline.rssDeltaBytes
      },
      limits: { bodyBytes: 65536, privateCryptoMessageBytes: 65536, cryptoCommands: 4, packageMemoryBytes: 2097152 },
      caveats: ['Single process, baseline then full, warm caches and GC: timings and signed RSS deltas are observations, not isolated overhead or regression thresholds.',
        'JS uses the same package Wasm; app Wasm and compile deltas describe Native only.',
        'Runtime peak RSS, isolated per-request memory and production latency budgets unavailable.',
        'Cancellation/deadline probes cover host checkpoints and late-result fencing; trusted synchronous Wasm is not CPU-preempted.',
        'Physical Wasm delta counts app module plus package module once; excludes base64/JSON/JS carrier size.'],
    };
  });
}
additionalQualification.rfc = async ({ report, expectedBase, baseBytes, require }) => {
  const vector = appendix[4];
  const result = createSignatureBase(vector.message(), { components: vector.components, parameters: vector.parameters });
  assert.equal(result.ok, true);
  assert.equal(new TextDecoder().decode(result.value), expectedBase);
  const key = Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64');
  const expected = 'pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=';
  const cryptoKey = await webcrypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  assert.equal(Buffer.from(await webcrypto.subtle.sign('HMAC', cryptoKey, baseBytes)).toString('base64'), expected);
  const selected = require('./packages/crypto/src/provider.cjs').bindJavascriptDigestMac(['SHA-256', 'HMAC-SHA256']);
  assert.equal(Buffer.from(await selected.bytes.hmacSha256(key, baseBytes)).toString('base64'), expected);
  assert.equal(externalMac(key, baseBytes).toString('base64'), expected);
  report.metadata.vectors = [{
    id: 'RFC9421-B.2.5', scope: 'primitive base/MAC; not accepted strict profile',
    baseUtf8: expectedBase, baseBytes: baseBytes.length, baseSha256: sha256(baseBytes), signatureBase64: expected
  }];
};
