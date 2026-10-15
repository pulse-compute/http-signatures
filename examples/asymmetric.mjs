// Node reference only. Ephemeral demonstration keys; hosts provision real keys.
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import template from './profiles/hmac-request.json' with { type: 'json' };
import { sign, verify } from '@pulse-compute/http-signatures/protocol';
import { createEcdsaP256Signer, createEcdsaP256Verifier, createRsaV15Signer, createRsaV15Verifier } from '@pulse-compute/http-signatures/webcrypto';
const unwrap = result => { assert.equal(result.ok, true, result.code); return result.value; };
const available = value => ({ state: 'available', value });
const bytes = text => new TextEncoder().encode(text);
for (const config of [
  { algorithm: 'ecdsa-p256-sha256', size: 64, primitive: { name: 'ECDSA', namedCurve: 'P-256' }, signer: createEcdsaP256Signer, verifier: createEcdsaP256Verifier },
  { algorithm: 'rsa-v1_5-sha256', size: 256, primitive: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, signer: createRsaV15Signer, verifier: createRsaV15Verifier },
]) {
  // Algorithm and width come from local configuration, never incoming metadata.
  const profile = structuredClone(template); profile.id = config.algorithm + '-example';
  profile.allowedAlgorithms = [config.algorithm]; profile.limits.signatureBytes = config.size;
  const pair = await webcrypto.subtle.generateKey(config.primitive, false, ['sign', 'verify']);
  const binding = { subtle: webcrypto.subtle, keyId: 'example-key', keyVersion: 'ephemeral-v1', trustDomain: 'example' };
  const signer = unwrap(config.signer({ ...binding, key: pair.privateKey }));
  const verifier = unwrap(config.verifier({ ...binding, key: pair.publicKey }));
  const clock = { nowSeconds: () => 1000 }; // Fixed trusted host time for demonstration.
  // Real adapters must establish this snapshot's provenance and completeness.
  const message = { kind: 'request', contextId: 'example-1', direction: 'outbound', trustDomain: 'example',
    headers: available([]), trailers: available([]), body: { state: 'available', bytes: new Uint8Array() },
    method: available('GET'), target: {
      original: available({ form: 'origin', raw: bytes('/resource') }), uri: available('https://example.com/resource'),
      scheme: available('https'), authority: available('example.com'), path: available('/resource'), query: available(''),
    } };
  const parameters = [
    { name: 'created', value: 1000 }, { name: 'expires', value: 1060 },
    { name: 'keyid', value: binding.keyId }, { name: 'alg', value: config.algorithm }, { name: 'tag', value: profile.requiredTag },
  ];
  const signed = unwrap(await sign(message, { profile, covered: profile.requiredComponents, parameters, capabilities: { signer, clock } }));
  const received = structuredClone(message); received.direction = 'inbound';
  received.headers.value.push({ name: 'Signature-Input', value: bytes(signed.signatureInput) }, { name: 'Signature', value: bytes(signed.signature) });
  const receivingProfile = { ...profile, context: { ...profile.context, direction: 'inbound' } };
  const keys = { id: profile.keyPolicy.resolverId, async resolve(query) {
    return query.keyId === binding.keyId && query.algorithm === config.algorithm &&
      query.trustDomain === binding.trustDomain && query.profileId === profile.id ? verifier : null;
  } };
  console.log(JSON.stringify(unwrap(await verify(received, { profile: receivingProfile, capabilities: { keys, clock } })), null, 2));
}
