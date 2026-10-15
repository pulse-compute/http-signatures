/** Internal RFC 8941 strict serialization for explicitly typed HTTP fields.
 * Deliberate restrictions: duplicate keys/parameters rejected, bounded counts,
 * no RFC 9651 date/display-string extensions. Inner Lists cannot nest.
 */
import { fail, binary, decodeBinary, join } from './base-support.js';

class Reader {
  constructor(s, b) { this.s = s; this.i = 0; this.b = b; }
  peek() { this.b.spend(1); return this.s[this.i] ?? ''; }
  take() { this.b.spend(1); if (this.i >= this.s.length) fail(); return this.s[this.i++]; }
  expect(c) { if (this.take() !== c) fail(); }
  spaces(ows = false) { while (this.peek() === ' ' || (ows && this.peek() === '\t')) this.take(); }
  key() {
    let s = '';
    if (!/^[a-z*]$/.test(this.peek())) fail();
    while (/^[a-z0-9_.*-]$/.test(this.peek())) { this.b.spend(1); s += this.take(); }
    return s;
  }
  bare() {
    const c = this.peek();
    if (c === '"') {
      this.take(); let out = '"';
      while (this.peek() !== '"') {
        let c = this.take();
        if (c === '\\') { c = this.take(); if (c !== '"' && c !== '\\') fail(); }
        else if (c.charCodeAt(0) < 32 || c.charCodeAt(0) > 126) fail();
        this.b.spend(2); out += c === '"' || c === '\\' ? '\\' + c : c;
      }
      this.take(); return out + '"';
    }
    if (c === ':') {
      this.take(); let s = '';
      while (this.peek() !== ':') { this.b.spend(1); s += this.take(); }
      this.take(); return binary(decodeBinary(s, this.b), this.b);
    }
    if (c === '?') { this.take(); const bit = this.take(); if (bit !== '0' && bit !== '1') fail(); return '?' + bit; }
    if (c === '-' || /^[0-9]$/.test(c)) {
      const negative = c === '-'; if (negative) this.take();
      let whole = '', fraction = '';
      while (/^[0-9]$/.test(this.peek())) { if (whole.length === 15) fail(); whole += this.take(); }
      if (!whole) fail();
      const decimal = this.peek() === '.';
      if (decimal) {
        if (whole.length > 12) fail(); this.take();
        while (/^[0-9]$/.test(this.peek())) { if (fraction.length === 3) fail(); fraction += this.take(); }
        if (!fraction) fail();
      }
      // Decimal canonicalization stays in strings; no floating point rounding.
      this.b.spend(whole.length + fraction.length);
      whole = String(Number(whole)); fraction = fraction.replace(/0+$/, '') || '0';
      const sign = negative && (whole !== '0' || fraction !== '0') ? '-' : '';
      return sign + whole + (decimal ? '.' + fraction : '');
    }
    if (/^[A-Za-z*]$/.test(c)) {
      let s = '';
      while (/^[!#$%&'*+.^_`|~0-9A-Za-z:/-]$/.test(this.peek())) { this.b.spend(1); s += this.take(); }
      return s;
    }
    fail();
  }
  parameters() {
    const parts = [], seen = new Set();
    while (this.peek() === ';') {
      if (parts.length >= this.b.limits.structuredParameters) fail('LIMIT_EXCEEDED');
      this.take(); this.spaces(); const key = this.key(); this.b.spend(key.length);
      if (seen.has(key)) fail(); seen.add(key);
      let value = '?1'; if (this.peek() === '=') { this.take(); value = this.bare(); }
      this.b.spend(key.length + value.length + 2);
      parts.push(';' + key + (value === '?1' ? '' : '=' + value));
    }
    return join(parts, '', this.b.limits.signatureBaseBytes, this.b);
  }
  item() {
    const bare = this.bare(), params = this.parameters();
    return { bare, params, text: join([bare, params], '', this.b.limits.signatureBaseBytes, this.b) };
  }
  member() {
    if (this.peek() !== '(') return this.item();
    this.take(); this.spaces(); const items = [];
    while (this.peek() !== ')') {
      if (items.length >= this.b.limits.structuredMembers) fail('LIMIT_EXCEEDED');
      items.push(this.item().text);
      if (this.peek() !== ')' && this.peek() !== ' ') fail();
      this.spaces();
    }
    this.take(); const params = this.parameters();
    return { bare: null, params, text: join(['(', join(items, ' ', this.b.limits.signatureBaseBytes, this.b), ')', params], '', this.b.limits.signatureBaseBytes, this.b) };
  }
}

export function structured(source, type, selectedKey, b) {
  const r = new Reader(source, b), members = [], seen = new Set();
  r.spaces();
  if (type === 'item') {
    const value = r.item().text; r.spaces();
    if (r.i !== source.length) fail(); return value;
  }
  let selected;
  while (r.i < source.length) {
    if (members.length >= b.limits.structuredMembers) fail('LIMIT_EXCEEDED');
    b.spend(1); let key, value;
    if (type === 'dictionary') {
      key = r.key(); b.spend(key.length);
      if (seen.has(key)) fail(); seen.add(key);
      if (r.peek() === '=') { r.take(); value = r.member(); }
      else { const params = r.parameters(); value = { bare: '?1', params, text: '?1' + params }; }
      b.spend(key.length + value.text.length + 1);
      members.push(key + (value.bare === '?1' ? value.params : '=' + value.text));
      if (key === selectedKey) selected = value.text;
    } else members.push(r.member().text);
    r.spaces(true);
    if (r.i === source.length) break;
    r.expect(','); r.spaces(true); if (r.i === source.length) fail();
  }
  if (selectedKey !== undefined) {
    if (selected === undefined) fail('COMPONENT_MISSING');
    return selected;
  }
  return join(members, ', ', b.limits.signatureBaseBytes, b);
}
