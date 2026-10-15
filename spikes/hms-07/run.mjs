// Read-only Pulse feasibility probe. This is development evidence, not an adapter.
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, symlinkSync, rmSync } from 'node:fs';
import { join, resolve, dirname, delimiter } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import pin from './pulse-source-pin.json' with { type: 'json' };
import toolchain from './toolchain/package.json' with { type: 'json' };
import { sign, verify } from '../../src/protocol.js';
import { bodySetup, bodySignOptions, bodyVerifyOptions } from '../../test/fixtures/content-cases.js';
import { install } from '../../test/fixtures/protocol-cases.js';
import { appendix, bytes } from '../../test/fixtures/base-cases.js';

const here = dirname(fileURLToPath(import.meta.url)), packageRoot = resolve(here, '../..');
const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  assert.ok(['--pulse-root', '--toolchain-root', '--out', '--worker'].includes(process.argv[i]));
  assert.ok(process.argv[i + 1]); args.set(process.argv[i], process.argv[i + 1]);
}
assert.ok(args.has('--pulse-root'), 'Supply an unchanged Pulse checkout/snapshot at the pinned revision.');
const pulseRoot = resolve(args.get('--pulse-root'));
const toolRoot = resolve(args.get('--toolchain-root') || join(here, 'toolchain'));
const json = file => JSON.parse(readFileSync(file, 'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function verifySources() {
  for (const entry of pin.files) {
    const data = readFileSync(join(pulseRoot, entry.path));
    const sha = createHash('sha1').update(`blob ${data.length}\0`).update(data).digest('hex');
    assert.equal(sha, entry.gitBlobSha, 'Changed Pulse source: ' + entry.path);
  }
}
verifySources();
for (const [name, version] of Object.entries(toolchain.dependencies)) {
  assert.equal(json(join(toolRoot, 'node_modules', name, 'package.json')).version, version);
}

// Resolve only explicitly selected source packages in a private temporary search
// path. Do not install into Pulse, register lowerers or modify its manifests.
if (!args.has('--worker')) {
  const temporary = mkdtempSync(join(tmpdir(), 'hms07-'));
  try {
    const modules = join(temporary, 'node_modules'); mkdirSync(join(modules, '@pulse-compute'), { recursive: true });
    for (const directory of ['wasm/packages/contracts', 'wasm/packages/compiler', 'wasm/packages/library-kit', 'wasm/packages/schema-json', 'packages/crypto']) {
      const source = join(pulseRoot, directory), name = json(join(source, 'package.json')).name;
      symlinkSync(source, join(modules, name), 'dir');
    }
    const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), ...process.argv.slice(2), '--worker', temporary], {
      env: { ...process.env, NODE_PATH: [modules, join(toolRoot, 'node_modules')].join(delimiter) },
      stdio: 'inherit', timeout: 120000,
    });
    assert.ifError(child.error); assert.equal(child.status, 0, 'Feasibility probe failed.');
    verifySources();
  } finally { rmSync(temporary, { recursive: true, force: true }); }
} else {
  const temporary = args.get('--worker'), require = createRequire(join(pulseRoot, 'package.json'));
  const ts = require('typescript');
  assert.equal(ts.version, toolchain.dependencies.typescript, 'Unexpected resolved TypeScript version.');
  // Emit a private JS test copy of four original Crypto TS modules. No source
  // edits, injected implementation or ambient backend selection in this probe.
  const transpiled = join(temporary, 'crypto'); mkdirSync(join(transpiled, 'internal'), { recursive: true });
  writeFileSync(join(transpiled, 'package.json'), '{"type":"module"}');
  for (const path of ['contracts', 'internal/data', 'internal/verification', 'internal/realization']) {
    const source = readFileSync(join(pulseRoot, 'packages/crypto/src', path + '.ts'), 'utf8');
    writeFileSync(join(transpiled, path + '.js'), ts.transpileModule(source, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    }).outputText);
  }
  const { normalizeMacVerifyRequest } = await import(pathToFileURL(join(transpiled, 'internal/verification.js')));
  const { verifyHs256WithSubtle } = await import(pathToFileURL(join(transpiled, 'internal/realization.js')));
  const provider = require(join(pulseRoot, 'packages/crypto/src/provider.cjs'));
  const javascript = provider.bindJavascriptDigestMac(['SHA-256', 'HMAC-SHA256'], webcrypto.subtle);
  const jsVerify = async request => {
    const normalized = normalizeMacVerifyRequest(request);
    return normalized.ok ? verifyHs256WithSubtle(normalized.request, webcrypto.subtle) : normalized.result;
  };

  const wasmFile = join(temporary, 'pulse-hmac.wasm');
  const recipe = ['--runtime', 'incremental', '--exportRuntime', '--optimizeLevel', '2', '--shrinkLevel', '1', '--noAssert'];
  const compiled = spawnSync(process.execPath, [join(toolRoot, 'node_modules/assemblyscript/bin/asc.js'),
    join(pulseRoot, 'packages/crypto/as/pulse-hmac-as.ts'), '--outFile', wasmFile, ...recipe],
  { encoding: 'utf8', timeout: 30000 });
  assert.ifError(compiled.error); assert.equal(compiled.status, 0, compiled.stderr);
  const wasm = readFileSync(wasmFile), module = await WebAssembly.compile(wasm);
  const instance = await WebAssembly.instantiate(module, { env: { abort() { throw Error('Crypto guest aborted.'); } } });
  const contracts = require('@pulse-compute/wasm-contracts/crypto/contracts');
  const { createNativeGuestSourceCryptoVerifier } = require(join(pulseRoot, 'wasm/packages/host-runtime/src/runtime/native-crypto-verifier.js'));
  // Explicit test selection, not a compiler-produced application or authority proof.
  const plan = { crypto: { version: contracts.CRYPTO_REALIZATION_PLAN_VERSION, target: 'native', automaticFallback: false,
    algorithms: ['HS256', 'HMAC-SHA256', 'SHA-256'].map(algorithm => ({ algorithm, realization: 'guest-source:pulse-hmac-as',
      kind: 'guest-source', implementation: contracts.CRYPTO_GUEST_SOURCE_IMPLEMENTATION, automaticFallback: false, targetImplemented: true })) } };
  const native = createNativeGuestSourceCryptoVerifier({ plan, exports: instance.exports });
  assert.equal(native.realization.available, true);
  const noSelection = createNativeGuestSourceCryptoVerifier({ plan: {}, exports: instance.exports });
  assert.equal(noSelection.realization.available, false);

  // RFC 9421 B.1.5/B.2.5 public test key and literal expected signature base.
  const key = new Uint8Array(Buffer.from('uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ==', 'base64'));
  const v = appendix[4], base = bytes([...v.lines, '"@signature-params": ' + v.input].join('\n'));
  const expected = Buffer.from('pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=', 'base64');
  const request = (data, tag) => ({ algorithm: 'HS256', key: { type: 'hmac-key-bytes', bytes: key }, data, tag });
  const primitive = [];
  for (const backend of [
    { name: 'pulse-javascript-byte-seam', bytes: javascript.bytes, verify: jsVerify },
    { name: 'pulse-wasm-primitive-in-node', bytes: native.verifier.bytes, verify: native.verifier.mac.verify },
  ]) {
    const signature = await backend.bytes.hmacSha256(key, base); assert.deepEqual(Buffer.from(signature), expected);
    const before = instance.exports.memory.buffer.byteLength;
    assert.equal((await backend.verify(request(base, signature))).status, 'valid');
    const after = instance.exports.memory.buffer.byteLength;
    const changed = new Uint8Array(base); changed[0] ^= 1;
    assert.equal((await backend.verify(request(changed, signature))).status, 'invalid-authenticator');
    assert.equal((await backend.bytes.hmacSha256(key, new Uint8Array(32768))).length, 32);
    await assert.rejects(async () => backend.bytes.hmacSha256(key, new Uint8Array(32769)));
    const h = bodySetup(); h.profile.limits.signatureBaseBytes = 32768; h.profile.limits.bodyBytes = 65536;
    const identity = { keyId: 'test-key', keyVersion: 'hms07-public-fixture', trustDomain: 'test', algorithm: 'hmac-sha256', keyBits: key.length * 8 };
    h.signer = { ...identity, sign: data => backend.bytes.hmacSha256(key, data) };
    h.verifier = { ...identity, async verify(data, tag) {
      const result = await backend.verify(request(data, tag));
      if (result.status === 'valid') return true;
      if (result.status === 'invalid-authenticator') return false;
      throw Error('Crypto operation unavailable.');
    } };
    h.keys.resolve = () => h.verifier; h.digest = { sha256: data => backend.bytes.sha256(data) };
    const signed = await sign(h.message, bodySignOptions(h)); assert.equal(signed.ok, true);
    const wire = install(h.message, signed.value), checked = await verify(wire, bodyVerifyOptions(h));
    assert.equal(checked.ok, true); assert.equal(checked.value.bodyIntegrity, 'verified'); assert.equal(checked.value.replay, 'consumed');
    assert.deepEqual(await verify(wire, bodyVerifyOptions(h)), { ok: false, code: 'REPLAY_REJECTED' });
    wire.body.bytes[0] ^= 1;
    assert.deepEqual(await verify(wire, bodyVerifyOptions(h)), { ok: false, code: 'BODY_DIGEST_INVALID' });
    primitive.push({ backend: backend.name, rfcB25: 'pass', changedBase: 'rejected', input32768: 'pass', input32769: 'rejected',
      strictProfileSignVerify: 'pass', bodyIntegrity: 'verified', replay: 'consumed-and-duplicate-rejected', changedBody: 'rejected',
      protocolExecution: 'JavaScript reference, not compiled Native',
      ...(backend.name.includes('wasm') ? { verifyMemoryBytesBefore: before, verifyMemoryBytesAfter: after } : {}) });
  }

  const { compileCanonicalSource } = require(join(pulseRoot, 'wasm/packages/compiler/src/canonical-api-compiler.js'));
  const { buildCanonicalNativePlan } = require(join(pulseRoot, 'wasm/packages/compiler/src/canonical-native-plan.js'));
  const diagnostics = [];
  const cases = {
    control: ['return ctx.text("ok");', null],
    headers: ['const h = ctx.req.headers; return ctx.text("ok");', null],
    typedArray: ['const b = new Uint8Array(32); return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
    map: ['const m = new Map(); return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
    regexp: ['const ok = /^[a-z]+$/.test(ctx.req.method); return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
    callback: ['const fn = () => 1; const value = fn(); return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
    tryCatch: ['try { return ctx.text("ok"); } catch { return ctx.text("bad"); }', 'PULSE_CANONICAL_CONTROL_FLOW_UNSUPPORTED'],
    ordinaryAwait: ['const value = await signer.sign("base"); return ctx.text("ok");', 'PULSE_NATIVE_AWAIT_UNSUPPORTED'],
    rawTarget: ['const value = ctx.req.rawTarget; return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
    trailers: ['const value = ctx.req.trailers; return ctx.text("ok");', 'PULSE_CANONICAL_NATIVE_EXPRESSION_UNSUPPORTED'],
  };
  for (const [name, [body, expectedCode]] of Object.entries(cases)) {
    let result;
    try {
      const plan = buildCanonicalNativePlan(compileCanonicalSource('export default async function handler(ctx) {' + body + '}', { target: 'native', fileName: name + '.ts' }));
      result = { case: name, status: 'accepted-plan', version: plan.version };
    } catch (error) {
      assert.ok(error.diagnostics?.some(d => d.code === expectedCode), error.stack);
      result = { case: name, status: 'rejected', error: error.code, diagnostics: error.diagnostics.map(d => ({ code: d.code, message: d.message })) };
    }
    assert.equal(result.status, expectedCode ? 'rejected' : 'accepted-plan'); diagnostics.push(result);
  }
  const { buildReachableProjectGraph } = require(join(pulseRoot, 'wasm/packages/compiler/src/project/reachable-graph-builder.js'));
  const project = join(temporary, 'project'); mkdirSync(join(project, 'node_modules/@pulse-compute'), { recursive: true });
  symlinkSync(packageRoot, join(project, 'node_modules/@pulse-compute/http-signatures'), 'dir');
  writeFileSync(join(project, 'package.json'), '{"name":"hms07-source-probe","version":"0.0.0","private":true,"type":"module"}');
  const imported = 'import { sign } from "@pulse-compute/http-signatures/protocol"; export default async function handler(ctx) { const result = await sign(ctx.req, {}); return ctx.text("ok"); }';
  const entry = join(project, 'handler.ts'); writeFileSync(entry, imported);
  let graphFailure;
  try { buildReachableProjectGraph(entry, { rootDir: project, workspaceRoot: project, target: 'native' }); }
  catch (error) { graphFailure = error; }
  assert.equal(graphFailure?.code, 'PULSE_NATIVE_IMPORT_UNSUPPORTED');
  const jsGraph = buildReachableProjectGraph(entry, { rootDir: project, workspaceRoot: project, target: 'javascript' });
  assert.equal(jsGraph.summary.unsupportedBoundaries, 0);
  const jsInspection = compileCanonicalSource(imported, { target: 'javascript', fileName: 'handler.ts' });
  assert.equal(jsInspection.ok, true); assert.equal(jsInspection.generatedSource, undefined);
  const { TRUSTED_LOWERER_PACKAGES } = require('@pulse-compute/wasm-contracts/library/manifest');
  assert.equal(TRUSTED_LOWERER_PACKAGES.includes('@pulse-compute/http-signatures'), false);

  // Existing host budget is exercised separately. This does not make ordinary
  // imported JS calls request-owned Pulse effects or preempt synchronous Wasm.
  const { createRequestBudget } = require(join(pulseRoot, 'packages/runtime/src/internal/request-budget.js'));
  let now = 0, settle;
  const budget = createRequestBudget({ maxDurationMs: 10, requestClock: { now: () => now, setTimeout: () => 0, clearTimeout() {} } });
  const pending = budget.race(new Promise(resolve => { settle = resolve; }));
  now = 11; assert.throws(() => budget.check(), e => e.code === 'PULSE_REQUEST_DEADLINE_EXCEEDED');
  settle('late result'); await assert.rejects(pending, e => e.code === 'PULSE_REQUEST_DEADLINE_EXCEEDED'); budget.close();

  // Web-platform observations reproduce transformations used by the inspected
  // providers; no Fastly host, socket adapter or deployed service is claimed.
  const target = '/a/../b?x=%2f', normalized = new URL(target, 'https://example.com').pathname;
  assert.equal(normalized, '/b');
  const pairs = [['X-Test', ' a '], ['X-Test', 'b']], headers = new Headers(pairs);
  assert.equal(headers.get('x-test'), 'a, b');
  const binary = Uint8Array.of(0xff), reencoded = new TextEncoder().encode(new TextDecoder().decode(binary));
  assert.notDeepEqual(binary, reencoded);

  verifySources();
  const receipt = { version: 'hms07.feasibility.v1', pulseCommit: pin.commit,
    packageBaseCommit: '7d7826468ecf46f2f2de35cf03bd48b252cd573e', runtime: process.version,
    toolchain: toolchain.dependencies, pulseSourceFilesVerified: pin.files.length,
    wasm: { bytes: wasm.length, sha256: sha256(wasm), recipe, imports: WebAssembly.Module.imports(module),
      selectedWithoutFallback: true, missingSelectionRejected: true, scope: 'Crypto primitive only; not a Pulse Native HTTP-signatures application' },
    primitive, sourceGraph: { native: { status: 'rejected', code: graphFailure.code,
      diagnostics: graphFailure.diagnostics.map(d => ({ code: d.code, message: d.message, file: d.file })) },
      javascript: { status: 'admitted-and-inspected', summary: jsGraph.summary, runtimeProviderIntegration: 'not-qualified' } },
    nativeSyntax: diagnostics, lowerer: { trusted: false, catalog: TRUSTED_LOWERER_PACKAGES },
    hostObservations: { dotSegmentTarget: { input: target, normalizedPath: normalized }, combinedHeader: headers.get('x-test'),
      invalidUtf8ReencodingChangesBytes: true, lateResultRejected: 'PULSE_REQUEST_DEADLINE_EXCEEDED',
      scope: 'Node web-platform and existing budget probes; provider adapter observations are source inspection' },
    decision: 'NO-GO for unchanged-source Native or automatic HMS-08; conditional HMAC bridge proposal requires human architectural approval' };
  if (args.has('--out')) writeFileSync(resolve(args.get('--out')), JSON.stringify(receipt, null, 2) + '\n');
  console.log(JSON.stringify(receipt, null, 2));
}
