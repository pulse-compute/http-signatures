/** Internal bounded primitives; not a public package entry point. */
export class BaseFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
export const fail = (code = 'MALFORMED_MESSAGE') => { throw new BaseFailure(code); };
export const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
export function own(o, k) {
  if (!o || typeof o !== 'object') fail();
  const d = Object.getOwnPropertyDescriptor(o, k);
  if (!d || !Object.hasOwn(d, 'value')) fail();
  return d.value;
}
export function record(o, required, optional = []) {
  if (!o || typeof o !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(o))) fail();
  const keys = Reflect.ownKeys(o);
  if (keys.some(k => !required.includes(k) && !optional.includes(k))) fail();
  for (const k of required) own(o, k);
  for (const k of keys) own(o, k);
}
export function array(a, max, b) {
  if (!Array.isArray(a)) fail();
  if (a.length > max) fail('LIMIT_EXCEEDED');
  b.spend(a.length);
  for (let i = 0; i < a.length; i++) own(a, String(i));
  return a;
}
export function ascii(s, max, b, pattern = /^[\x20-\x7e]*$/) {
  if (typeof s !== 'string') fail();
  if (s.length > max) fail('LIMIT_EXCEEDED');
  b.spend(s.length);
  if (!pattern.test(s)) fail();
  return s;
}
export function available(a, read) {
  if (!a || typeof a !== 'object') fail();
  const state = own(a, 'state');
  if (state === 'available') { record(a, ['state', 'value']); return read(a.value); }
  record(a, ['state', 'reason']);
  if (state !== 'unavailable' || !['not-exposed', 'transformed', 'not-retained'].includes(a.reason)) fail();
  return undefined;
}
export function need(v) {
  if (v === undefined) fail('COMPONENT_UNAVAILABLE');
  return v;
}
export function join(parts, separator, max, b) {
  b.spend(parts.length);
  let n = Math.max(0, parts.length - 1) * separator.length;
  for (const s of parts) n += s.length;
  if (n > max) fail('LIMIT_EXCEEDED');
  b.spend(n);
  return parts.join(separator);
}
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export function binary(s, b) {
  const size = 2 + Math.ceil(s.length / 3) * 4;
  if (size > b.limits.signatureBaseBytes) fail('LIMIT_EXCEEDED');
  b.spend(s.length + size);
  let out = ':';
  for (let i = 0; i < s.length; i += 3) {
    const a = s.charCodeAt(i), c = s.charCodeAt(i + 1), d = s.charCodeAt(i + 2);
    out += B64[a >> 2] + B64[((a & 3) << 4) | ((c || 0) >> 4)] +
      (i + 1 < s.length ? B64[((c & 15) << 2) | ((d || 0) >> 6)] : '=') +
      (i + 2 < s.length ? B64[d & 63] : '=');
  }
  return out + ':';
}
export function decodeBinary(s, b) {
  b.spend(s.length * 3);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) fail();
  const at = s.indexOf('='), n = at < 0 ? s.length : at, rem = n % 4;
  if (rem === 1 || s.length - n > (rem ? 4 - rem : 0)) fail();
  let bits = 0, acc = 0, out = '';
  b.spend(n * 65 + Math.floor(n * 6 / 8));
  for (let i = 0; i < n; i++) {
    acc = (acc << 6) | B64.indexOf(s[i]); bits += 6;
    if (bits >= 8) { bits -= 8; out += String.fromCharCode((acc >>> bits) & 255); }
  }
  return out;
}
