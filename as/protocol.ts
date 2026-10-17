import { signatureBase as createBase } from './base';
// Narrow HMS Native protocol; all cryptography and HTTP authority stay in the host.
@external('pulse_package', 'input_len') declare function inputLen(id: i32): i32;
@external('pulse_package', 'input_read') declare function inputRead(id: i32, ptr: usize, capacity: i32): i32;
const frame = new ArrayBuffer(262144);
let outputSize: i32 = 0;
let tag = new Uint8Array(32);
let phase: i32 = 0;
let signing: bool = false;
let names = new Array<string>(), values = new Array<string>();
let policy = new Array<string>();
let signatureInput: string = '', signatureBase: string = '', digestText: string = '';
let keyId: string = '', keyVersion: string = '', domain: string = '', method: string = '', uri: string = '';
export function buffer(): usize { return changetype<usize>(frame); }
export function capacity(): i32 { return frame.byteLength; }
export function output_ptr(): usize { return buffer(); }
export function output_len(): i32 { return outputSize; }
export function aux_ptr(): usize { return tag.dataStart; }
export function aux_len(): i32 { return tag.length; }
function read(id: i32, max: i32): Uint8Array {
  const n = inputLen(id);
  if (n < 0 || n > max) return new Uint8Array(0);
  const out = new Uint8Array(n);
  if (inputRead(id, out.dataStart, n) != n) return new Uint8Array(0);
  return out;
}
function ascii(bytes: Uint8Array): string {
  for (let i = 0; i < bytes.length; i++) if (bytes[i] > 127) return '';
  return String.UTF8.decodeUnsafe(bytes.dataStart, bytes.length);
}
function text(id: i32, max: i32 = 512): string { return ascii(read(id, max)); }
function put(bytes: Uint8Array, status: i32): i32 {
  if (bytes.length > 65536) return fail('LIMIT_EXCEEDED');
  memory.copy(buffer(), bytes.dataStart, bytes.length); outputSize = bytes.length; return status;
}
function emit(value: string): i32 { return put(Uint8Array.wrap(String.UTF8.encode(value)), 0); }
function fail(code: string): i32 { phase = -1; return emit('{"ok":false,"code":"' + code + '"}'); }
function quoted(value: string): string {
  let result = '"';
  for (let i = 0; i < value.length; i++) {
    const c = value.charAt(i); if (c == '"' || c == '\\') result += '\\'; result += c;
  }
  return result + '"';
}
function trim(value: string): string {
  let a = 0, b = value.length;
  while (a < b && (value.charCodeAt(a) == 32 || value.charCodeAt(a) == 9)) a++;
  while (b > a && (value.charCodeAt(b - 1) == 32 || value.charCodeAt(b - 1) == 9)) b--;
  return value.substring(a, b);
}
function readHeaders(): bool {
  const data = read(7, 132100); if (data.length < 4) return false;
  let pos = 0, count = load<u32>(data.dataStart); pos += 4;
  if (count > 128) return false;
  for (let i: u32 = 0; i < count; i++) {
    let name = '', value = '';
    for (let j = 0; j < 2; j++) {
      if (pos + 4 > data.length) return false;
      const n = load<u32>(data.dataStart + pos); pos += 4;
      if (n > 16384 || pos + n > data.length) return false;
      const s = String.UTF8.decodeUnsafe(data.dataStart + pos, n); pos += n;
      if (j == 0) name = s.toLowerCase(); else value = trim(s);
    }
    names.push(name); values.push(value);
  }
  return pos == data.length;
}
function count(name: string): i32 { let n = 0; for (let i = 0; i < names.length; i++) if (names[i] == name) n++; return n; }
function field(name: string): string {
  let result = '', first = true;
  for (let i = 0; i < names.length; i++) if (names[i] == name) {
    if (!first) result += ', '; result += values[i]; first = false;
  }
  return result;
}
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function base64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = i32(bytes[i]), b = i + 1 < bytes.length ? i32(bytes[i + 1]) : 0, c = i + 2 < bytes.length ? i32(bytes[i + 2]) : 0;
    out += alphabet.charAt(a >> 2) + alphabet.charAt(((a & 3) << 4) | (b >> 4));
    out += i + 1 < bytes.length ? alphabet.charAt(((b & 15) << 2) | (c >> 6)) : '=';
    out += i + 2 < bytes.length ? alphabet.charAt(c & 63) : '=';
  }
  return out;
}
function parseTag(value: string): bool {
  if (value.length != 44 || value.charAt(43) != '=') return false;
  let pos = 0;
  for (let i = 0; i < 44; i += 4) {
    const a = alphabet.indexOf(value.charAt(i)), b = alphabet.indexOf(value.charAt(i + 1)), c = alphabet.indexOf(value.charAt(i + 2));
    const d = i == 40 ? 0 : alphabet.indexOf(value.charAt(i + 3));
    if (a < 0 || b < 0 || c < 0 || d < 0) return false;
    tag[pos++] = u8((a << 2) | (b >> 4)); tag[pos++] = u8((b << 4) | (c >> 2));
    if (i < 40) tag[pos++] = u8((c << 6) | d);
  }
  return base64(tag) == value;
}
function uint(value: string): i64 {
  if (!value.length || value.length > 15) return -1;
  let result: i64 = 0;
  for (let i = 0; i < value.length; i++) { const c = value.charCodeAt(i); if (c < 48 || c > 57) return -1; result = result * 10 + c - 48; }
  return result;
}
const covered = '("@method" "@target-uri" "content-digest")';
// Bounded metadata grammar. No permissive recovery, duplicate parameters or labels.
function parseParameters(input: string, now: i64): string {
  if (!input.startsWith(covered)) return 'UNSUPPORTED_COMPONENT';
  let pos = covered.length, created: i64 = -1, expires: i64 = -1;
  const seen = new Array<string>(); let canonical = covered;
  while (pos < input.length) {
    if (input.charAt(pos++) != ';') return 'MALFORMED_SIGNATURE';
    while (pos < input.length && input.charAt(pos) == ' ') pos++;
    const start = pos;
    while (pos < input.length && input.charAt(pos) >= 'a' && input.charAt(pos) <= 'z') pos++;
    const name = input.substring(start, pos);
    if (!name.length || seen.includes(name) || seen.length >= 5 || input.charAt(pos++) != '=') return 'MALFORMED_SIGNATURE';
    seen.push(name); let value = '', serialized = '';
    if (name == 'created' || name == 'expires') {
      const a = pos; while (pos < input.length && input.charAt(pos) >= '0' && input.charAt(pos) <= '9') pos++;
      const number = uint(input.substring(a, pos)); if (number < 0) return 'MALFORMED_SIGNATURE';
      if (name == 'created') created = number; else expires = number;
      serialized = number.toString();
    } else {
      if (input.charAt(pos++) != '"') return 'MALFORMED_SIGNATURE';
      let closed = false;
      while (pos < input.length) {
        let c = input.charAt(pos++);
        if (c == '"') { closed = true; break; }
        if (c == '\\') { if (pos == input.length) return 'MALFORMED_SIGNATURE'; c = input.charAt(pos++); if (c != '"' && c != '\\') return 'MALFORMED_SIGNATURE'; }
        if (c.charCodeAt(0) < 32 || c.charCodeAt(0) > 126 || value.length >= 512) return 'MALFORMED_SIGNATURE';
        value += c;
      }
      if (!closed) return 'MALFORMED_SIGNATURE';
      if (name == 'keyid') { if (value != keyId) return 'KEY_REJECTED'; }
      else if (name == 'alg') { if (value != 'hmac-sha256') return 'UNSUPPORTED_ALGORITHM'; }
      else if (name == 'tag') { if (value != policy[3]) return 'METADATA_REQUIRED'; }
      else return 'METADATA_REQUIRED';
      serialized = quoted(value);
    }
    canonical += ';' + name + '=' + serialized;
  }
  if (seen.length != 5 || created < 0 || expires < 0) return 'METADATA_REQUIRED';
  const age = uint(policy[5]), skew = uint(policy[6]);
  if (created > now + skew || now > created + age + skew || expires < created || expires > created + age || now > expires + skew) return 'TIME_INVALID';
  signatureInput = policy[1] + '=' + canonical;
  signatureBase = createBase(['"@method"', '"@target-uri"', '"content-digest"'], [method, uri, digestText], canonical);
  return '';
}
export function start(): i32 {
  if (phase != 0) return fail('OPERATION_FAILED');
  policy = text(0, 8192).split('\n');
  if (policy.length != 7 || policy[0].length == 0 || uint(policy[5]) < 1 || uint(policy[5]) > 3600 || uint(policy[6]) < 0 || uint(policy[6]) > 300) return fail('PROFILE_INVALID');
  const operation = text(1); if (operation != 'sign' && operation != 'verify') return fail('PROFILE_INVALID');
  signing = operation == 'sign';
  if (text(13) != (signing ? 'outbound' : 'inbound')) return fail('CONTEXT_MISMATCH');
  method = text(3, 32); const target = text(4, 16384), scheme = text(5), authority = text(6);
  keyId = text(10); keyVersion = text(11); domain = text(12);
  if (!method.length || method != method.toUpperCase()) return fail('UNSUPPORTED_COMPONENT');
  if (!target.length || scheme != 'https' || authority != policy[2] || domain != policy[4] || !keyId.length || !keyVersion.length) return fail('CONTEXT_MISMATCH');
  uri = scheme + '://' + authority + target;
  if (!readHeaders()) return fail('MALFORMED_MESSAGE');
  if (count('content-digest') != 1) return fail('BODY_DIGEST_INVALID');
  digestText = field('content-digest');
  if (!digestText.startsWith('sha-256=:') || !digestText.endsWith(':') || !parseTag(digestText.substring(9, digestText.length - 1))) return fail('BODY_DIGEST_INVALID');
  const now = uint(text(9)); if (now < 0) return fail('OPERATION_FAILED');
  if (signing) {
    if (count('signature') || count('signature-input')) return fail('MALFORMED_SIGNATURE');
    const params = covered + ';created=' + now.toString() + ';expires=' + (now + uint(policy[5])).toString()
      + ';keyid=' + quoted(keyId) + ';alg="hmac-sha256";tag=' + quoted(policy[3]);
    const error = parseParameters(params, now); if (error.length) return fail(error);
    phase = 1; return put(read(8, 65536), 1);
  }
  if (count('signature-input') != 1 || count('signature') != 1) return fail('SIGNATURE_NOT_FOUND');
  const si = field('signature-input'), sig = field('signature'), prefix = policy[1] + '=';
  if (!si.startsWith(prefix) || !sig.startsWith(prefix + ':') || !sig.endsWith(':')) return fail('SIGNATURE_NOT_FOUND');
  const error = parseParameters(si.substring(prefix.length), now); if (error.length) return fail(error);
  if (!parseTag(sig.substring(prefix.length + 1, sig.length - 1))) return fail('MALFORMED_SIGNATURE');
  phase = 2; return put(Uint8Array.wrap(String.UTF8.encode(signatureBase)), 3);
}
export function resume(length: i32): i32 {
  if (phase == 2) {
    if (length != 1 || load<u8>(buffer()) != 1) return fail('SIGNATURE_INVALID');
    phase = 3; return put(read(8, 65536), 1);
  }
  if (phase == 1 || phase == 3) {
    if (length != 32) return fail('OPERATION_FAILED');
    const bytes = new Uint8Array(32); memory.copy(bytes.dataStart, buffer(), 32);
    if (digestText != 'sha-256=:' + base64(bytes) + ':') return fail('BODY_DIGEST_INVALID');
    if (phase == 1) { phase = 4; return put(Uint8Array.wrap(String.UTF8.encode(signatureBase)), 2); }
    phase = 5;
    return emit('{"ok":true,"value":{"profileId":' + quoted(policy[0]) + ',"label":' + quoted(policy[1])
      + ',"keyId":' + quoted(keyId) + ',"keyVersion":' + quoted(keyVersion)
      + ',"algorithm":"hmac-sha256","bodyIntegrity":"verified","replay":"not-checked"}}');
  }
  if (phase == 4) {
    if (length != 32) return fail('OPERATION_FAILED');
    const bytes = new Uint8Array(32); memory.copy(bytes.dataStart, buffer(), 32); phase = 5;
    return emit('{"ok":true,"value":{"signatureInput":' + quoted(signatureInput)
      + ',"signature":' + quoted(policy[1] + '=:' + base64(bytes) + ':') + '}}');
  }
  return fail('OPERATION_FAILED');
}
