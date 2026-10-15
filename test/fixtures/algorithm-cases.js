import { webcrypto, createPrivateKey, createPublicKey } from 'node:crypto';
import * as adapter from '../../src/webcrypto.js';
import keys from './rfc9421-crypto.json' with { type: 'json' };
import { setup } from './protocol-cases.js';
import { bodySetup } from './content-cases.js';

export const algorithmCases = [
  { algorithm: 'ecdsa-p256-sha256', name: 'p256', bits: 256, size: 64, primitive: { name: 'ECDSA', namedCurve: 'P-256' },
    signer: adapter.createEcdsaP256Signer, verifier: adapter.createEcdsaP256Verifier },
  { algorithm: 'rsa-v1_5-sha256', name: 'rsa', bits: 2048, size: 256, primitive: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    signer: adapter.createRsaV15Signer, verifier: adapter.createRsaV15Verifier },
];
for (const c of algorithmCases) {
  c.privateKey = await webcrypto.subtle.importKey('pkcs8', createPrivateKey(keys[c.name].private).export({ format: 'der', type: 'pkcs8' }), c.primitive, false, ['sign']);
  c.publicKey = await webcrypto.subtle.importKey('spki', createPublicKey(keys[c.name].public).export({ format: 'der', type: 'spki' }), c.primitive, false, ['verify']);
}
export const binding = (c, operation) => ({ subtle: webcrypto.subtle, key: operation === 'sign' ? c.privateKey : c.publicKey,
  keyId: 'test-key', keyVersion: 'rfc-fixture', trustDomain: 'test' });
export function algorithmSetup(c, kind = 'request', body = false) {
  const h = body ? bodySetup(kind) : setup(kind);
  h.profile.allowedAlgorithms = [c.algorithm]; h.profile.limits.signatureBytes = c.size;
  h.parameters.find(p => p.name === 'alg').value = c.algorithm;
  const signer = c.signer(binding(c, 'sign')).value, verifier = c.verifier(binding(c, 'verify')).value;
  h.signer = { ...signer, sign(base) { h.counts.sign++; h.bases.push(new Uint8Array(base)); return signer.sign(base); } };
  h.verifier = { ...verifier, verify(base, sig) { h.counts.verify++; h.bases.push(new Uint8Array(base)); return verifier.verify(base, sig); } };
  h.keys.resolve = q => { h.counts.resolve++; h.queries.push(q); return h.verifier; };
  return h;
}
