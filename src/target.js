/** Lexical HTTP target handling: never round-trip a target through URL. */
import { fail, record, available, ascii, need, TOKEN } from './base-support.js';

function authorityParts(s, b) {
  b.spend(s.length * 3);
  let host, port;
  if (s.startsWith('[')) {
    const end = s.indexOf(']'); if (end < 0) fail();
    host = s.slice(0, end + 1); const rest = s.slice(end + 1);
    if (rest && !rest.startsWith(':')) fail(); port = rest ? rest.slice(1) : undefined;
    let ip = host.slice(1, -1);
    // IPvFuture and scoped IPv6 are outside this HTTP snapshot subset.
    if (/^[vV]/.test(ip) || ip.includes('%')) fail('UNSUPPORTED_COMPONENT');
    if (ip.includes('.')) {
      const colon = ip.lastIndexOf(':'), tail = ip.slice(colon + 1).split('.');
      if (tail.length !== 4 || tail.some(x => !/^(0|[1-9][0-9]{0,2})$/.test(x) || Number(x) > 255)) fail();
      ip = ip.slice(0, colon + 1) + '0:0';
    }
    const halves = ip.split('::');
    if (halves.length > 2) fail();
    const groups = halves.flatMap(h => h ? h.split(':') : []);
    if (groups.some(x => !/^[0-9A-Fa-f]{1,4}$/.test(x)) ||
        (halves.length === 1 ? groups.length !== 8 : groups.length >= 8)) fail();
  } else {
    const parts = s.split(':'); if (parts.length > 2) fail(); [host, port] = parts;
    if (!host || !/^(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})+$/.test(host)) fail();
  }
  if (port !== undefined && !/^[0-9]*$/.test(port)) fail();
  return { host, port };
}
export function normalizeAuthority(s, scheme, b) {
  const { host, port } = authorityParts(s, b);
  if (port && scheme === undefined) fail('COMPONENT_UNAVAILABLE');
  b.spend(s.length);
  const defaultPort = scheme === 'https' ? 443 : scheme === 'http' ? 80 : undefined;
  return host.toLowerCase() + (port && Number(port) !== defaultPort ? ':' + port : '');
}
const PATH = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$/;
const QUERY = /^(?:[A-Za-z0-9._~!$&'()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$/;
function path(s, b) { b.spend(s.length); if ((s && !s.startsWith('/')) || !PATH.test(s)) fail(); return s; }
function query(s, b) { b.spend(s.length); if (s && (!s.startsWith('?') || !QUERY.test(s.slice(1)))) fail(); return s; }
function splitPath(s, b) {
  b.spend(s.length * 2); const at = s.indexOf('?');
  return { path: path(at < 0 ? s : s.slice(0, at), b), query: query(at < 0 ? '' : s.slice(at), b) };
}
function uri(s, b) {
  b.spend(s.length * 3);
  const match = /^(https?):\/\/([^/?#]+)(.*)$/i.exec(s);
  if (!match) fail();
  authorityParts(match[2], b);
  return { scheme: match[1].toLowerCase(), authority: match[2], ...splitPath(match[3], b) };
}
export function target(request, b) {
  let bytes = 0;
  const read = s => { ascii(s, b.limits.targetBytes, b, /^[\x21-\x7e]*$/); bytes += s.length;
    if (bytes > b.limits.targetBytes) fail('LIMIT_EXCEEDED'); return s; };
  const method = available(request.method, s => { read(s); b.spend(s.length); if (!TOKEN.test(s)) fail(); return s; });
  const t = request.target;
  record(t, ['original', 'uri', 'scheme', 'authority', 'path', 'query']);
  const out = { method };
  out.original = available(t.original, o => {
    record(o, ['form', 'raw']);
    if (!['origin', 'absolute', 'authority', 'asterisk', 'pseudo-headers'].includes(o.form)) fail();
    if (!(o.raw instanceof Uint8Array)) fail();
    if (o.raw.length > b.limits.targetBytes - bytes) fail('LIMIT_EXCEEDED');
    b.spend(o.raw.length * 2); let raw = '';
    for (const c of o.raw) { if (c < 33 || c > 126) fail(); raw += String.fromCharCode(c); }
    bytes += o.raw.length; return { form: o.form, raw };
  });
  for (const key of ['uri', 'scheme', 'authority', 'path', 'query']) out[key] = available(t[key], read);
  if (out.scheme !== undefined) {
    b.spend(out.scheme.length * 2);
    if (!/^https?$/i.test(out.scheme)) fail('UNSUPPORTED_COMPONENT');
    out.scheme = out.scheme.toLowerCase();
  }
  if (out.authority !== undefined) authorityParts(out.authority, b);
  if (out.path !== undefined) path(out.path, b);
  if (out.query !== undefined) query(out.query, b);
  const check = other => {
    for (const key of ['scheme', 'authority', 'path', 'query']) {
      const a = out[key], z = other[key]; if (a === undefined || z === undefined) continue;
      b.spend(a.length + z.length);
      const scheme = out.scheme ?? other.scheme;
      if (key === 'authority') {
        // Without a scheme, compare authority spelling case-insensitively only.
        if (scheme === undefined ? a.toLowerCase() !== z.toLowerCase() :
            normalizeAuthority(a, scheme, b) !== normalizeAuthority(z, scheme, b)) fail();
      } else if (key === 'path' ? (a || '/') !== (z || '/') : a !== z) fail();
    }
  };
  const parsed = out.uri === undefined ? undefined : uri(out.uri, b);
  if (parsed) check(parsed);
  const original = out.original;
  if (original) {
    let parts;
    if (original.form === 'origin') {
      if (!original.raw.startsWith('/')) fail(); parts = splitPath(original.raw, b);
      if (method === 'CONNECT') fail();
    } else if (original.form === 'absolute') {
      parts = uri(original.raw, b);
      if (method === 'CONNECT') fail();
    } else if (original.form === 'authority') {
      const p = authorityParts(original.raw, b); if (!p.port || (method !== undefined && method !== 'CONNECT')) fail();
      parts = { authority: original.raw, path: '', query: '' };
    } else if (original.form === 'asterisk') {
      if (original.raw !== '*' || (method !== undefined && method !== 'OPTIONS')) fail();
      parts = { path: '', query: '' };
    }
    if (parts) {
      check(parts);
      if (parsed) {
        // Check URI/raw overlaps even when the corresponding explicit parts are unavailable.
        for (const key of ['scheme', 'authority', 'path', 'query']) {
          if (parts[key] === undefined) continue;
          b.spend(parts[key].length + parsed[key].length);
          const a = key === 'authority' ? normalizeAuthority(parts[key], parsed.scheme, b) : key === 'path' ? parts[key] || '/' : parts[key];
          const z = key === 'authority' ? normalizeAuthority(parsed[key], parsed.scheme, b) : key === 'path' ? parsed[key] || '/' : parsed[key];
          if (a !== z) fail();
        }
      }
    }
  }
  return out;
}
export function queryParameter(t, name, b) {
  if (!t.queryIndex) {
    const source = need(t.query);
    // WHATWG form parsing is required here. URL itself is never used. Reserve
    // input, UTF-8 replacement/encoding expansion, copies, hashing and scans.
    b.spend(source.length * 64 + 1);
    const index = new Map();
    for (const [key, value] of new URLSearchParams(source)) {
      const encode = s => new URLSearchParams([['', s]]).toString().slice(1).replace(/\+/g, '%20');
      const encoded = encode(key), output = encode(value);
      index.set(encoded, index.has(encoded) ? null : output);
    }
    t.queryIndex = index;
  }
  b.spend(name.length);
  if (!t.queryIndex.has(name)) fail('COMPONENT_MISSING');
  const value = t.queryIndex.get(name);
  if (value === null) fail('MALFORMED_MESSAGE');
  return value;
}
