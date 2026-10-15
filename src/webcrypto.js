/** Optional explicit Web Crypto HMAC adapter. No global crypto/key fallback. */
import { BaseFailure, fail, record } from './base-support.js';
const ALGORITHM = 'hmac-sha256';
const identityString = value => typeof value === 'string' && value.length > 0 && value.length <= 512 && /^[\x20-\x7e]+$/.test(value);
function capability(options, operation) {
  try {
    try { record(options, ['subtle', 'key', 'keyId', 'keyVersion', 'trustDomain']); }
    catch { fail('CAPABILITY_UNAVAILABLE'); }
    const { subtle, key, keyId, keyVersion, trustDomain } = options;
    if (!subtle || typeof subtle[operation] !== 'function') fail('CAPABILITY_UNAVAILABLE');
    const fn = subtle[operation].bind(subtle);
    if (![keyId, keyVersion, trustDomain].every(identityString)) fail('KEY_REJECTED');
    if (!key || key.type !== 'secret' || key.algorithm?.name !== 'HMAC' || key.algorithm?.hash?.name !== 'SHA-256' ||
        !Number.isSafeInteger(key.algorithm.length) || key.algorithm.length < 256 || key.algorithm.length > 32768 ||
        !Array.isArray(key.usages) || key.usages.length > 8 || !key.usages.includes(operation)) fail('KEY_REJECTED');
    const keyBits = key.algorithm.length;
    const call = async (base, signature) => {
      try {
        if (!(base instanceof Uint8Array) || base.length > 65536) fail('OPERATION_FAILED');
        if (operation === 'verify' && (!(signature instanceof Uint8Array) || signature.length !== 32)) fail('OPERATION_FAILED');
        const data = new Uint8Array(base);
        if (operation === 'verify') {
          const result = await fn('HMAC', key, new Uint8Array(signature), data);
          if (typeof result !== 'boolean') fail('OPERATION_FAILED'); return result;
        }
        const result = await fn('HMAC', key, data);
        if (!(result instanceof ArrayBuffer) || result.byteLength !== 32) fail('OPERATION_FAILED');
        return new Uint8Array(result);
      } catch { fail('OPERATION_FAILED'); }
    };
    return { ok: true, value: Object.freeze({ keyId, keyVersion, trustDomain, algorithm: ALGORITHM, keyBits, [operation]: call }) };
  } catch (error) {
    return { ok: false, code: error instanceof BaseFailure && ['KEY_REJECTED', 'CAPABILITY_UNAVAILABLE'].includes(error.code) ? error.code : 'OPERATION_FAILED' };
  }
}
export function createHmacSigner(options) { return capability(options, 'sign'); }
export function createHmacVerifier(options) { return capability(options, 'verify'); }
