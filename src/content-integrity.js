/** Internal bounded content integrity. No buffering, decoding or ambient hash. */
import { BaseFailure, fail, record, need, join } from './base-support.js';
import { sha256Digest } from './structured-field.js';

export function digestCapability(digest) {
  try {
    record(digest, ['sha256']); if (typeof digest.sha256 !== 'function') fail();
    return digest.sha256.bind(digest);
  } catch { fail('CAPABILITY_UNAVAILABLE'); }
}
export async function hash(content, digest) {
  let result;
  try { result = await digest(content); } catch { fail('OPERATION_FAILED'); }
  if (!(result instanceof Uint8Array) || result.length !== 32) fail('OPERATION_FAILED');
  return result;
}
export async function checkBody(current, b, digest) {
  const content = need(current.body), fields = need(current.headers).get('content-digest');
  if (!fields) fail('COMPONENT_MISSING');
  if (current.trailers?.has('content-digest')) fail('BODY_DIGEST_INVALID');
  let expected;
  try {
    expected = sha256Digest(join(fields, ', ', b.limits.fieldValueBytes, b), b);
  } catch (error) {
    if (error instanceof BaseFailure && error.code === 'LIMIT_EXCEEDED') throw error;
    fail('BODY_DIGEST_INVALID');
  }
  // Reserve fixed-size comparison work before invoking the backend. Content
  // was bounded and copied before the first clock/capability callback.
  b.spend(64);
  const actual = await hash(content, digest);
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= actual[i] ^ expected[i];
  if (difference !== 0) fail('BODY_DIGEST_INVALID');
}
