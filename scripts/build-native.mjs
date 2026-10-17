import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const root = resolve(new URL('..', import.meta.url).pathname);
const toolchain = resolve(process.argv[2] || join(root, 'spikes/hms-07/toolchain'));
assert.equal(JSON.parse(readFileSync(join(toolchain, 'node_modules/assemblyscript/package.json'))).version, '0.28.18');
const dir = mkdtempSync(join(tmpdir(), 'hms-native-'));
try {
  const file = join(dir, 'protocol.wasm');
  const run = spawnSync(process.execPath, [join(toolchain, 'node_modules/assemblyscript/bin/asc.js'),
    join(root, 'as/protocol.ts'), '--outFile', file, '--runtime', 'stub', '--maximumMemory', '32', '--optimize', '--noAssert'], { encoding: 'utf8' });
  assert.ifError(run.error); assert.equal(run.status, 0, run.stderr);
  const bytes = readFileSync(file), sha256 = value => createHash('sha256').update(value).digest('hex');
  writeFileSync(join(root, 'native/module.json'), JSON.stringify({ abi: 'pulse.package-wasm.v1',
    sourceSha256: sha256(['as/protocol.ts', 'as/base.ts'].map(path => readFileSync(join(root, path), 'utf8')).join('\0')), sha256: sha256(bytes), wasm: bytes.toString('base64') }, null, 2) + '\n');
  console.log(JSON.stringify({ bytes: bytes.length, sha256: sha256(bytes) }));
} finally { rmSync(dir, { recursive: true, force: true }); }
