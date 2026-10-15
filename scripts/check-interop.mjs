// Development-only OpenSSL CLI gate. The package never shells out or parses DER.
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { sign, verify } from '../src/protocol.js';
import { parseSignature } from '../src/signature-fields.js';
import { algorithmCases, algorithmSetup, binding } from '../test/fixtures/algorithm-cases.js';
import { signOptions, verifyOptions, install } from '../test/fixtures/protocol-cases.js';
import { appendix, bytes } from '../test/fixtures/base-cases.js';
import keys from '../test/fixtures/rfc9421-crypto.json' with { type: 'json' };
import golden from '../test/fixtures/rsa-v15-openssl.json' with { type: 'json' };

function openssl(args, success = true) {
  const r = spawnSync('openssl', args, { encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
  assert.ifError(r.error);
  if (success) assert.equal(r.status, 0, r.stderr);
  else assert.equal(r.status, 1, r.stderr);
  return r.stdout.trim();
}
// Narrow test-only ASN.1 bridge for OpenSSL's P-256 DER output, not a general codec.
function rawToDer(raw) {
  assert.equal(raw.length, 64);
  const integers = [raw.subarray(0, 32), raw.subarray(32)].map(value => {
    let i = 0; while (i < 31 && value[i] === 0) i++;
    const body = Buffer.concat([value[i] & 128 ? Buffer.of(0) : Buffer.alloc(0), value.subarray(i)]);
    return Buffer.concat([Buffer.of(2, body.length), body]);
  });
  const body = Buffer.concat(integers); return Buffer.concat([Buffer.of(48, body.length), body]);
}
function derToRaw(der) {
  assert.equal(der[0], 48); assert.equal(der[1], der.length - 2);
  let pos = 2; const raw = Buffer.alloc(64);
  for (let offset = 0; offset < 64; offset += 32) {
    assert.equal(der[pos++], 2); const length = der[pos++];
    assert.ok(length > 0 && length <= 33 && pos + length <= der.length);
    let integer = der.subarray(pos, pos + length); pos += length;
    assert.equal(integer[0] & 128, 0);
    if (integer.length > 1 && integer[0] === 0) { assert.ok(integer[1] & 128); integer = integer.subarray(1); }
    assert.ok(integer.length <= 32); raw.set(integer, offset + 32 - integer.length);
  }
  assert.equal(pos, der.length); assert.deepEqual(rawToDer(raw), der); return raw;
}
const version = openssl(['version']); assert.match(version, /^OpenSSL 3\./);
const directory = await mkdtemp(join(tmpdir(), 'hms06-interop-'));
const file = name => join(directory, name);
const measurements = [];
try {
  for (const c of algorithmCases) {
    await writeFile(file('private.pem'), keys[c.name].private, { mode: 0o600 });
    await writeFile(file('public.pem'), keys[c.name].public);
    const externalSign = async base => {
      await writeFile(file('base.bin'), base);
      openssl(['dgst', '-sha256', '-sign', file('private.pem'), '-out', file('signature.bin'), file('base.bin')]);
      const result = await readFile(file('signature.bin'));
      return c.name === 'p256' ? derToRaw(result) : result;
    };
    const externalVerify = async (base, signature, valid = true) => {
      await writeFile(file('base.bin'), base);
      await writeFile(file('signature.bin'), c.name === 'p256' ? rawToDer(signature) : signature);
      openssl(['dgst', '-sha256', '-verify', file('public.pem'), '-signature', file('signature.bin'), file('base.bin')], valid);
    };
    // Published base text, independent of the package builder/serializer.
    const vector = appendix[c.name === 'p256' ? 3 : 2];
    const base = bytes([...vector.lines, '"@signature-params": ' + vector.input].join('\n'));
    const signer = c.signer(binding(c, 'sign')).value, verifier = c.verifier(binding(c, 'verify')).value;
    const external = await externalSign(base); assert.equal(external.length, c.size);
    assert.equal(await verifier.verify(base, external), true);
    const generated = await signer.sign(base); await externalVerify(base, generated);
    if (c.name === 'rsa') {
      assert.deepEqual(Buffer.from(generated), external);
      assert.equal(external.toString('base64'), golden.signatureBase64);
    }
    const tampered = new Uint8Array(base); tampered[0] ^= 1;
    assert.equal(await verifier.verify(tampered, external), false);
    await externalVerify(tampered, generated, false);
    if (c.name === 'p256') await externalVerify(base, Buffer.from(keys.signatures.b24, 'base64'));

    // A strict-profile base assembled from literal expected bytes, not production output.
    const h = algorithmSetup(c);
    const input = '("@method" "@target-uri" "date" "content-type");created=1000;expires=1060;keyid="test-key";alg="' + c.algorithm + '";tag="test-domain"';
    const strictBase = bytes('"@method": POST\n"@target-uri": https://example.com/foo?param=Value&Pet=dog\n"date": Tue, 20 Apr 2021 02:07:55 GMT\n"content-type": application/json\n"@signature-params": ' + input);
    const strictSignature = await externalSign(strictBase);
    const wire = install(h.message, { signatureInput: 'sig1=' + input, signature: 'sig1=:' + strictSignature.toString('base64') + ':' });
    assert.equal((await verify(wire, verifyOptions(h))).ok, true);
    const signed = await sign(h.message, signOptions(h)); assert.equal(signed.ok, true);
    assert.equal(signed.value.signatureInput, 'sig1=' + input);
    const parsed = parseSignature(signed.value.signature, { limits: { signatureBytes: c.size } }); assert.equal(parsed.ok, true);
    await externalVerify(strictBase, parsed.value[0].signature);
    measurements.push({ algorithm: c.algorithm, keyBits: c.bits, signatureBytes: c.size,
      primitiveBothDirections: true, strictProfileBothDirections: true, tamperRejectedBothDirections: true,
      publishedSignature: c.name === 'p256' ? 'RFC 9421 B.2.4 verified by OpenSSL CLI and Web Crypto' : 'none; independently generated RSA v1.5 signature over RFC B.2.3 base',
      ...(c.name === 'rsa' ? { deterministicSignatureBase64: external.toString('base64') } : {}) });
  }
} finally { await rm(directory, { recursive: true, force: true }); }
console.log(JSON.stringify({ runtime: process.version, nodeOpenSSL: process.versions.openssl, externalOpenSSL: version,
  scope: 'Separate Node Web Crypto and OpenSSL CLI interfaces/builds; shared OpenSSL lineage, not independent crypto implementations. Published RFC data is independent expected evidence.', measurements }, null, 2));
