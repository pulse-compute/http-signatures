/** Internal prepared-snapshot engine shared by /base and /protocol. */
import { serializeSignatureParameters, signatureFieldLimits } from './signature-fields.js';
import { BaseFailure, fail, own, record, array, ascii, available, need, join, binary, TOKEN } from './base-support.js';
import { target, normalizeAuthority, queryParameter } from './target.js';
import { structured } from './structured-field.js';

export const signatureBaseLimits = Object.freeze({ ...signatureFieldLimits,
  totalFieldBytes: 131072, fieldValueBytes: 16384, fieldCount: 128,
  targetBytes: 16384, signatureBaseBytes: 65536, bodyBytes: 1048576,
  structuredMembers: 128, structuredParameters: 32,
});
export class Budget {
  constructor(options) {
    this.used = 0; this.fields = 0; this.fieldBytes = 0; this.bodyBytes = 0;
    this.limits = { ...signatureBaseLimits }; this.types = new Map();
    try {
      record(options, [], ['limits', 'structuredFields']);
      if (Object.hasOwn(options, 'limits')) {
        const limits = own(options, 'limits'); record(limits, [], Object.keys(signatureBaseLimits));
        for (const key of Object.keys(limits)) {
          const n = limits[key];
          if (!Number.isSafeInteger(n) || n < 1 || n > signatureBaseLimits[key]) fail();
          this.limits[key] = n;
        }
      }
      if (Object.hasOwn(options, 'structuredFields')) {
        const types = own(options, 'structuredFields');
        if (!types || typeof types !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(types))) fail();
        const keys = Reflect.ownKeys(types); if (keys.length > this.limits.fieldCount) fail();
        for (const key of keys) {
          ascii(key, this.limits.fieldNameBytes, this, /^[!#$%&'*+.^_`|~0-9a-z-]+$/);
          const type = own(types, key); if (!['item', 'list', 'dictionary'].includes(type)) fail();
          this.spend(key.length + 1); this.types.set(key, type);
        }
      }
    } catch (error) { if (error instanceof BaseFailure && error.code === 'LIMIT_EXCEEDED') throw error; fail('PROFILE_INVALID'); }
  }
  spend(n) { if (n > this.limits.workUnits - this.used) fail('LIMIT_EXCEEDED'); this.used += n; }
  serialize(value) {
    if (this.used === this.limits.workUnits) fail('LIMIT_EXCEEDED');
    const limits = {};
    for (const key of Object.keys(signatureFieldLimits)) limits[key] = this.limits[key];
    limits.workUnits -= this.used;
    const result = serializeSignatureParameters(value, { limits });
    this.spend(result.workUnits);
    if (!result.ok) fail(result.code);
    return result.value;
  }
}
function fieldValue(bytes, b) {
  // Raw HTTP/1 obs-fold is accepted only as CRLF followed by one or more OWS
  // bytes. All other framing/control bytes are rejected, including in unused fields.
  b.spend(bytes.length * 3);
  let start = 0, end = bytes.length;
  while (start < end && (bytes[start] === 32 || bytes[start] === 9)) start++;
  while (end > start && (bytes[end - 1] === 32 || bytes[end - 1] === 9)) end--;
  let value = '';
  for (let i = start; i < end; i++) {
    const c = bytes[i];
    if (c === 13 && bytes[i + 1] === 10 && (bytes[i + 2] === 32 || bytes[i + 2] === 9)) {
      i += 2;
      while (i + 1 < end && (bytes[i + 1] === 32 || bytes[i + 1] === 9)) i++;
      value += ' ';
    } else {
      if ((c < 32 && c !== 9) || c === 127) fail();
      value += String.fromCharCode(c);
    }
  }
  return value;
}
function block(a, b) {
  return available(a, fields => {
    array(fields, b.limits.fieldCount - b.fields, b); b.fields += fields.length;
    const index = new Map();
    for (const f of fields) {
      record(f, ['name', 'value']);
      if (typeof f.name !== 'string' || !(f.value instanceof Uint8Array)) fail();
      if (f.name.length > b.limits.fieldNameBytes || f.value.length > b.limits.fieldValueBytes) fail('LIMIT_EXCEEDED');
      b.fieldBytes += f.name.length + f.value.length;
      if (b.fieldBytes > b.limits.totalFieldBytes) fail('LIMIT_EXCEEDED');
      ascii(f.name, b.limits.fieldNameBytes, b, TOKEN); b.spend(f.name.length * 2);
      const name = f.name.toLowerCase(), values = index.get(name) ?? [];
      if (values.length >= b.limits.instancesPerName) fail('LIMIT_EXCEEDED');
      values.push(fieldValue(f.value, b)); index.set(name, values);
    }
    return index;
  });
}
export function snapshot(message, b, associated = false, copyBody = false) {
  if (!message || typeof message !== 'object') fail();
  const kind = own(message, 'kind');
  if (!['request', 'response'].includes(kind) || (associated && kind !== 'request')) fail();
  record(message, ['kind', 'contextId', 'direction', 'trustDomain', 'headers', 'trailers', 'body',
    ...(kind === 'request' ? ['method', 'target'] : ['status', 'associatedRequest'])]);
  for (const key of ['contextId', 'trustDomain']) {
    ascii(message[key], b.limits.metadataStringBytes, b); if (!message[key]) fail();
  }
  if (!['inbound', 'outbound'].includes(message.direction)) fail();
  const headers = block(message.headers, b), trailers = block(message.trailers, b);
  const body = message.body; let content;
  if (own(body, 'state') === 'available') {
    record(body, ['state', 'bytes']); if (!(body.bytes instanceof Uint8Array)) fail();
    b.bodyBytes += body.bytes.length; if (b.bodyBytes > b.limits.bodyBytes) fail('LIMIT_EXCEEDED');
    if (copyBody) { b.spend(body.bytes.length); content = new Uint8Array(body.bytes); }
  } else available(body, () => fail());
  const common = { body: content, kind, headers, trailers, contextId: message.contextId,
    direction: message.direction, trustDomain: message.trustDomain };
  if (kind === 'request') return { ...common, target: target(message, b) };
  const status = available(message.status, n => {
    if (!Number.isInteger(n) || n < 100 || n > 599) fail(); return String(n);
  });
  const request = available(message.associatedRequest, r => snapshot(r, b, true));
  return { ...common, status, request };
}
function resolve(message, component, b) {
  b.spend(1 + component.parameters.length + component.name.length);
  const params = new Map(component.parameters.map(p => [p.name, p.value]));
  let context = message;
  if (params.has('req')) {
    if (message.kind !== 'response') fail('CONTEXT_MISMATCH');
    context = need(message.request);
  }
  if (component.kind === 'field') {
    if (component.name === 'signature' || component.name === 'signature-input') fail('UNSUPPORTED_COMPONENT');
    let type;
    if (params.has('sf') || params.has('key')) {
      type = b.types.get(component.name);
      if (!type || (params.has('key') && type !== 'dictionary')) fail('UNSUPPORTED_COMPONENT');
    }
    const values = need(params.has('tr') ? context.trailers : context.headers).get(component.name);
    if (!values) fail('COMPONENT_MISSING');
    if (params.has('bs')) return join(values.map(v => binary(v, b)), ', ', b.limits.signatureBaseBytes, b);
    if (component.name === 'set-cookie' && values.length > 1) fail('UNSUPPORTED_COMPONENT');
    for (const v of values) { b.spend(v.length); if (/[^\x09\x20-\x7e]/.test(v)) fail('UNSUPPORTED_COMPONENT'); }
    const combined = join(values, ', ', b.limits.signatureBaseBytes, b);
    if (type) {
      if (type === 'item' && values.length !== 1) fail();
      return structured(combined, type, params.get('key'), b);
    }
    return combined;
  }
  if (component.name === '@status') {
    if (context.kind !== 'response') fail('CONTEXT_MISMATCH'); return need(context.status);
  }
  if (context.kind !== 'request') fail('CONTEXT_MISMATCH');
  const t = context.target;
  switch (component.name) {
    case '@method': return need(t.method);
    case '@target-uri': return need(t.uri);
    case '@scheme': return need(t.scheme);
    case '@authority': return normalizeAuthority(need(t.authority), t.scheme, b);
    case '@path': return need(t.path) || '/';
    case '@query': return need(t.query) || '?';
    case '@query-param': return queryParameter(t, params.get('name'), b);
    case '@request-target': {
      const original = need(t.original);
      if (original.form === 'pseudo-headers') fail('UNSUPPORTED_COMPONENT');
      return original.raw;
    }
    default: fail('UNSUPPORTED_COMPONENT');
  }
}

export function buildBase(current, value, b) {
  const signatureParams = b.serialize(value), parts = []; let size = 0;
  const put = s => {
    if (s.length > b.limits.signatureBaseBytes - size) fail('LIMIT_EXCEEDED');
    b.spend(s.length); size += s.length; parts.push(s);
  };
  for (const component of value.components) {
    const item = b.serialize({ components: [component], parameters: [] });
    b.spend(item.length); put(item.slice(1, -1)); put(': ');
    put(resolve(current, component, b)); put('\n');
  }
  put('"@signature-params": '); put(signatureParams);
  // Every output character is ASCII (field HTAB is an ASCII octet). Allocate
  // once, after charging output traversal and the complete byte array.
  b.spend(size * 2); const bytes = new Uint8Array(size); let at = 0;
  for (const part of parts) for (let i = 0; i < part.length; i++) bytes[at++] = part.charCodeAt(i);
  return bytes;
}
