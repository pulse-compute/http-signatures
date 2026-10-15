/** Explicit SHA-256 Content-Digest generation; no authenticity claim. */
import { Budget } from './base-engine.js';
import { BaseFailure, fail, record, binary } from './base-support.js';
import { digestCapability, hash } from './content-integrity.js';

export async function createContentDigest(content, options) {
  let b;
  try {
    try { record(options, ['digest'], ['limits']); } catch { fail('PROFILE_INVALID'); }
    b = new Budget(Object.hasOwn(options, 'limits') ? { limits: options.limits } : {});
    const digest = digestCapability(options.digest);
    if (!(content instanceof Uint8Array)) fail('MALFORMED_MESSAGE');
    if (content.length > b.limits.bodyBytes) fail('LIMIT_EXCEEDED');
    // Preflight the fixed output and serialize/copy work before hashing.
    if (b.limits.fieldValueBytes < 54 || b.limits.signatureBaseBytes < 46) fail('LIMIT_EXCEEDED');
    b.spend(content.length + 32 + 54);
    if (78 > b.limits.workUnits - b.used) fail('LIMIT_EXCEEDED');
    const input = new Uint8Array(content);
    const output = await hash(input, digest);
    let octets = '';
    for (let i = 0; i < 32; i++) octets += String.fromCharCode(output[i]);
    // The fixed 32 input + 46 output charge was preflighted before hashing.
    return { ok: true, value: 'sha-256=' + binary(octets, b), workUnits: b.used };
  } catch (error) {
    const codes = ['PROFILE_INVALID', 'CAPABILITY_UNAVAILABLE', 'MALFORMED_MESSAGE', 'LIMIT_EXCEEDED'];
    return { ok: false, code: error instanceof BaseFailure && codes.includes(error.code) ? error.code : 'OPERATION_FAILED', workUnits: b?.used ?? 0 };
  }
}
