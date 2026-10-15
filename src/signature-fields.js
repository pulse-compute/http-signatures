/** Bounded RFC 8941/9421 signature-envelope subset. No host or crypto access. */
export const signatureFieldLimits = Object.freeze({
  envelopeFieldBytes: 16384, instancesPerName: 16, signatures: 8,
  components: 32, componentParameters: 5, signatureParameters: 6,
  metadataStringBytes: 512, labelBytes: 64, fieldNameBytes: 256,
  signatureBytes: 32, workUnits: 2097152,
});
const DERIVED = new Set(['@method', '@target-uri', '@authority', '@scheme',
  '@request-target', '@path', '@query', '@query-param', '@status']);
const META = new Set(['created', 'expires', 'keyid', 'alg', 'nonce', 'tag']);
const FLAGS = new Set(['sf', 'bs', 'tr', 'req']);
const KEY = /^[a-z*][a-z0-9_.*-]*$/;
const FIELD = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
class FieldFailure extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = (code = 'MALFORMED_SIGNATURE') => { throw new FieldFailure(code); };
const own = (o, k) => {
  const d = Object.getOwnPropertyDescriptor(o, k);
  if (!d || !Object.hasOwn(d, 'value')) fail();
  return d.value;
};
function record(value, keys) {
  if (!value || typeof value !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const names = Reflect.ownKeys(value);
  if (names.length !== keys.length || names.some(k => !keys.includes(k))) fail();
  for (const key of keys) own(value, key);
}
function array(value, max, b) {
  if (!Array.isArray(value)) fail();
  if (value.length > max) fail('LIMIT_EXCEEDED');
  b.spend(value.length);
  for (let i = 0; i < value.length; i++) own(value, String(i));
  return value;
}
class Budget {
  constructor(options) {
    this.used = 0;
    this.limits = { ...signatureFieldLimits };
    try {
      record(options, Object.hasOwn(options, 'limits') ? ['limits'] : []);
      if (Object.hasOwn(options, 'limits')) {
        const overrides = own(options, 'limits');
        if (!overrides || typeof overrides !== 'object' ||
            ![Object.prototype, null].includes(Object.getPrototypeOf(overrides))) fail();
        for (const key of Reflect.ownKeys(overrides)) {
          if (!Object.hasOwn(signatureFieldLimits, key)) fail();
          const value = own(overrides, key);
          if (!Number.isSafeInteger(value) || value < 1 || value > signatureFieldLimits[key]) fail();
          this.limits[key] = value;
        }
      }
    } catch { fail('PROFILE_INVALID'); }
  }
  spend(n) {
    if (n > this.limits.workUnits - this.used) fail('LIMIT_EXCEEDED');
    this.used += n;
  }
}
function operation(options, action) {
  let b;
  try {
    b = new Budget(options);
    return { ok: true, value: action(b), workUnits: b.used };
  } catch (error) {
    return { ok: false, code: error instanceof FieldFailure ? error.code : 'OPERATION_FAILED', workUnits: b?.used ?? 0 };
  }
}
function text(value, max, b, pattern) {
  if (typeof value !== 'string') fail();
  if (value.length > max) fail('LIMIT_EXCEEDED');
  b.spend(value.length);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 32 || c > 126) fail();
  }
  if (pattern) { b.spend(value.length); if (!pattern.test(value)) fail(); }
  return value;
}
function inputFields(input, b) {
  const fields = Array.isArray(input) ? array(input, b.limits.instancesPerName, b) : [input];
  let size = fields.length ? 2 * (fields.length - 1) : 0;
  // Bound all lengths before converting bytes or joining any field instances.
  for (const field of fields) {
    if (typeof field !== 'string' && !(field instanceof Uint8Array)) fail();
    size += field.length;
    if (size > b.limits.envelopeFieldBytes) fail('LIMIT_EXCEEDED');
  }
  const parts = [];
  for (const field of fields) {
    b.spend(field.length);
    let s = '';
    for (let i = 0; i < field.length; i++) {
      const c = typeof field === 'string' ? field.charCodeAt(i) : field[i];
      if (c > 126 || (c < 32 && c !== 9)) fail();
      if (typeof field !== 'string') { b.spend(1); s += String.fromCharCode(c); }
    }
    parts.push(typeof field === 'string' ? field : s);
  }
  b.spend(size);
  return parts.join(', ');
}
class Reader {
  constructor(source, b) { this.s = source; this.i = 0; this.b = b; }
  peek() { this.b.spend(1); return this.s[this.i]; }
  take() { this.b.spend(1); if (this.i >= this.s.length) fail(); return this.s[this.i++]; }
  expect(c) { if (this.take() !== c) fail(); }
  spaces(ows = false) {
    while (this.peek() === ' ' || (ows && this.peek() === '\t')) this.take();
  }
  key(max) {
    let s = '';
    const first = this.peek();
    if (!first || !/[a-z*]/.test(first)) fail();
    while (this.peek() && /[a-z0-9_.*-]/.test(this.peek())) {
      if (s.length >= max) fail('LIMIT_EXCEEDED');
      this.b.spend(1); s += this.take();
    }
    return s;
  }
  string(max) {
    this.expect('"');
    let s = '';
    while (true) {
      let c = this.take();
      if (c === '"') return s;
      if (c === '\\') { c = this.take(); if (c !== '\\' && c !== '"') fail(); }
      else if (c.charCodeAt(0) < 32 || c.charCodeAt(0) > 126) fail();
      if (s.length >= max) fail('LIMIT_EXCEEDED');
      this.b.spend(1); s += c;
    }
  }
  integer() {
    const negative = this.peek() === '-';
    if (negative) this.take();
    let digits = 0, value = 0;
    while (this.peek() && /[0-9]/.test(this.peek())) {
      if (++digits > 15) fail();
      value = value * 10 + Number(this.take());
    }
    if (!digits) fail();
    return negative && value ? -value : value;
  }
  parameters(component) {
    const params = [], seen = new Set();
    const max = component ? this.b.limits.componentParameters : this.b.limits.signatureParameters;
    while (this.peek() === ';') {
      if (params.length >= max) fail('LIMIT_EXCEEDED');
      this.b.spend(1); this.take(); this.spaces();
      const name = this.key(this.b.limits.fieldNameBytes);
      this.b.spend(name.length);
      if (seen.has(name)) fail();
      seen.add(name);
      let value = true;
      if (this.peek() === '=') {
        this.take();
        if (this.peek() === '"') value = this.string(this.b.limits.metadataStringBytes);
        else if (this.peek() === '?') {
          this.take(); const bit = this.take(); if (bit !== '0' && bit !== '1') fail(); value = bit === '1';
        } else value = this.integer();
      }
      params.push({ name, value });
    }
    return params;
  }
  bytes() {
    this.expect(':');
    let encoded = '';
    const max = Math.ceil(this.b.limits.signatureBytes / 3) * 4;
    while (this.peek() !== ':') {
      if (encoded.length >= max) fail('LIMIT_EXCEEDED');
      const c = this.take();
      if (!/[A-Za-z0-9+/=]/.test(c)) fail();
      this.b.spend(1); encoded += c;
    }
    this.expect(':');
    this.b.spend(encoded.length);
    const eq = encoded.indexOf('=');
    const dataLength = eq < 0 ? encoded.length : eq;
    const remainder = dataLength % 4;
    if (remainder === 1) fail();
    const padding = remainder ? 4 - remainder : 0;
    if (encoded.length - dataLength > padding) fail();
    for (let i = dataLength; i < encoded.length; i++) {
      this.b.spend(1); if (encoded[i] !== '=') fail();
    }
    const size = Math.floor(dataLength * 6 / 8);
    if (size > this.b.limits.signatureBytes) fail('LIMIT_EXCEEDED');
    this.b.spend(size); // charge output before allocation
    const result = new Uint8Array(size);
    let bits = 0, acc = 0, at = 0;
    for (let i = 0; i < dataLength; i++) {
      this.b.spend(65); // bounded alphabet lookup + input byte
      acc = (acc << 6) | B64.indexOf(encoded[i]); bits += 6;
      if (bits >= 8) { bits -= 8; result[at++] = (acc >>> bits) & 255; }
    }
    // RFC 8941 permits missing padding and non-zero pad bits; emit canonical padding.
    return result;
  }
}
function parameters(params, component, b) {
  array(params, component ? b.limits.componentParameters : b.limits.signatureParameters, b);
  const seen = new Set();
  for (const p of params) {
    record(p, ['name', 'value']);
    text(p.name, b.limits.fieldNameBytes, b, KEY);
    b.spend(p.name.length);
    if (seen.has(p.name)) fail();
    seen.add(p.name);
    if (!component && (p.name === 'created' || p.name === 'expires')) {
      if (!Number.isSafeInteger(p.value) || Math.abs(p.value) > 999999999999999) fail();
    } else if ((!component && META.has(p.name)) || (component && ['key', 'name'].includes(p.name))) {
      text(p.value, b.limits.metadataStringBytes, b);
      if (component && p.name === 'key') { b.spend(p.value.length); if (!KEY.test(p.value)) fail(); }
    } else if (component && FLAGS.has(p.name)) {
      if (p.value !== true) fail();
    } else fail();
  }
}
function component(c, b) {
  record(c, ['kind', 'name', 'parameters']);
  text(c.name, b.limits.fieldNameBytes, b);
  if (c.kind === 'field') {
    b.spend(c.name.length); if (!FIELD.test(c.name)) fail();
  } else if (c.kind === 'derived') {
    b.spend(c.name.length); if (!DERIVED.has(c.name)) fail('UNSUPPORTED_COMPONENT');
  } else fail();
  parameters(c.parameters, true, b);
  b.spend(c.parameters.length);
  const names = new Set(c.parameters.map(p => p.name));
  if (c.kind === 'field') {
    if (names.has('name') || (names.has('bs') && (names.has('sf') || names.has('key')))) fail();
  } else {
    if (['sf', 'key', 'bs', 'tr'].some(n => names.has(n))) fail();
    if ((c.name === '@query-param') !== names.has('name')) fail();
    if (c.name === '@status' && names.has('req')) fail();
  }
}
function identity(c, b) {
  // At most five parameters. Reserve work before copies, sorting and escaping.
  b.spend(c.parameters.length);
  const size = c.name.length + c.parameters.reduce((n, p) => n + p.name.length + String(p.value).length, 0);
  b.spend(size * 2 + 128 + c.parameters.length * c.parameters.length * b.limits.fieldNameBytes);
  const sorted = [...c.parameters].sort((a, z) => a.name < z.name ? -1 : a.name > z.name ? 1 : 0);
  const key = JSON.stringify([c.name, sorted.map(p => [p.name, p.value])]);
  b.spend(key.length); // subsequent set hashing
  return key;
}
function member(value, b) {
  record(value, ['components', 'parameters']);
  array(value.components, b.limits.components, b);
  const seen = new Set();
  for (const c of value.components) {
    component(c, b);
    const key = identity(c, b);
    if (seen.has(key)) fail();
    seen.add(key);
  }
  parameters(value.parameters, false, b);
}
function parseDictionary(source, kind, b) {
  const r = new Reader(source, b), entries = [], labels = new Set();
  r.spaces(); // RFC top-level leading SP, not HTAB
  while (r.i < source.length) {
    if (entries.length >= b.limits.signatures) fail('LIMIT_EXCEEDED');
    b.spend(1);
    const label = r.key(b.limits.labelBytes);
    b.spend(label.length);
    if (labels.has(label)) fail();
    labels.add(label); r.expect('=');
    if (kind === 'input') {
      r.expect('(');
      const components = [];
      r.spaces();
      while (r.peek() !== ')') {
        if (components.length >= b.limits.components) fail('LIMIT_EXCEEDED');
        b.spend(1);
        const name = r.string(b.limits.fieldNameBytes);
        components.push({ kind: name.startsWith('@') ? 'derived' : 'field', name, parameters: r.parameters(true) });
        if (r.peek() !== ')' && r.peek() !== ' ') fail();
        r.spaces();
      }
      r.expect(')');
      const parameters = r.parameters(false);
      const value = { components, parameters };
      member(value, b);
      entries.push({ label, ...value });
    } else {
      const signature = r.bytes();
      if (r.peek() === ';') fail(); // signature-item extensions are outside this subset
      entries.push({ label, signature });
    }
    r.spaces(true);
    if (r.i === source.length) break;
    r.expect(','); r.spaces(true);
    if (r.i === source.length) fail();
  }
  return entries;
}
class Writer {
  constructor(b) { this.b = b; this.parts = []; this.length = 0; }
  put(s) {
    if (s.length > this.b.limits.envelopeFieldBytes - this.length) fail('LIMIT_EXCEEDED');
    this.b.spend(s.length); this.length += s.length; this.parts.push(s);
  }
  string(s) {
    this.put('"');
    for (const c of s) { this.b.spend(1); if (c === '"' || c === '\\') this.put('\\'); this.put(c); }
    this.put('"');
  }
  parameters(params) {
    for (const p of params) {
      this.b.spend(1); this.put(';'); this.put(p.name);
      if (p.value === true) continue;
      this.put('=');
      if (typeof p.value === 'string') this.string(p.value);
      else this.put(String(p.value));
    }
  }
  member(value) {
    this.put('(');
    value.components.forEach((c, i) => {
      this.b.spend(1); if (i) this.put(' '); this.string(c.name); this.parameters(c.parameters);
    });
    this.put(')'); this.parameters(value.parameters);
  }
  bytes(bytes) {
    this.put(':');
    for (let i = 0; i < bytes.length; i += 3) {
      this.b.spend(Math.min(3, bytes.length - i));
      const a = bytes[i], c = bytes[i + 1], d = bytes[i + 2];
      this.put(B64[a >> 2] + B64[((a & 3) << 4) | ((c ?? 0) >> 4)] +
        (c === undefined ? '=' : B64[((c & 15) << 2) | ((d ?? 0) >> 6)]) +
        (d === undefined ? '=' : B64[d & 63]));
    }
    this.put(':');
  }
  finish() { this.b.spend(this.length); return this.parts.join(''); }
}
function serialize(entries, kind, b) {
  array(entries, b.limits.signatures, b);
  const labels = new Set(), writer = new Writer(b);
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    record(e, kind === 'input' ? ['label', 'components', 'parameters'] : ['label', 'signature']);
    text(e.label, b.limits.labelBytes, b, KEY);
    b.spend(e.label.length);
    if (labels.has(e.label)) fail();
    labels.add(e.label);
    if (kind === 'input') member({ components: e.components, parameters: e.parameters }, b);
    else {
      if (!(e.signature instanceof Uint8Array)) fail();
      if (e.signature.length > b.limits.signatureBytes) fail('LIMIT_EXCEEDED');
    }
    if (i) writer.put(', ');
    writer.put(e.label); writer.put('=');
    if (kind === 'input') writer.member(e);
    else writer.bytes(e.signature);
  }
  return writer.finish();
}
export function parseSignatureInput(fields, options = {}) {
  return operation(options, b => parseDictionary(inputFields(fields, b), 'input', b));
}
export function parseSignature(fields, options = {}) {
  return operation(options, b => parseDictionary(inputFields(fields, b), 'signature', b));
}
export function serializeSignatureInput(entries, options = {}) {
  return operation(options, b => serialize(entries, 'input', b));
}
export function serializeSignature(entries, options = {}) {
  return operation(options, b => serialize(entries, 'signature', b));
}
export function serializeSignatureParameters(value, options = {}) {
  return operation(options, b => { member(value, b); const w = new Writer(b); w.member(value); return w.finish(); });
}
export function parseSignatureEnvelope(fields, options = {}) {
  return operation(options, b => {
    record(fields, ['signatureInput', 'signature']);
    const input = inputFields(fields.signatureInput, b), signature = inputFields(fields.signature, b);
    const inputs = parseDictionary(input, 'input', b), signatures = parseDictionary(signature, 'signature', b);
    if (inputs.length !== signatures.length) fail();
    b.spend(inputs.length + signatures.length);
    const labels = new Set(signatures.map(e => { b.spend(e.label.length); return e.label; }));
    for (const e of inputs) { b.spend(e.label.length); if (!labels.has(e.label)) fail(); }
    return { inputs, signatures };
  });
}
