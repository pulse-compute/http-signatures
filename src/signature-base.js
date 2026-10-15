/** Experimental authoritative-snapshot RFC 9421 signature-base primitive. */
import { BaseFailure } from './base-support.js';
import { Budget, snapshot, buildBase } from './base-engine.js';
export { signatureBaseLimits } from './base-engine.js';

/** Returns {ok:true,value:Uint8Array,workUnits} or a fixed, redacted failure. */
export function createSignatureBase(message, value, options = {}) {
  let b;
  try {
    b = new Budget(options);
    return { ok: true, value: buildBase(snapshot(message, b), value, b), workUnits: b.used };
  } catch (error) {
    return { ok: false, code: error instanceof BaseFailure ? error.code : 'OPERATION_FAILED', workUnits: b?.used ?? 0 };
  }
}
