// RFC 9530 Appendices B.1–B.3, B.4/§2 and D. Public data; no keys.
// https://www.rfc-editor.org/rfc/rfc9530.html ; see rfc9530-LICENSE.txt.
const bytes = text => new TextEncoder().encode(text);
export const digestVectors = [
  { name: 'D: JSON without LF', content: bytes('{"hello": "world"}'), digest: 'X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=' },
  { name: 'B.1: JSON with LF', content: bytes('{"hello": "world"}\n'), digest: 'RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=' },
  { name: 'B.2: empty message content', content: new Uint8Array(), digest: '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' },
  { name: 'B.3: partial content', content: bytes('"world"}\n'), digest: 'jjcgBDWNAtbYUXI37CVG3gRuGOAjaaDRGpIUFsdyepQ=' },
  // Reported erratum 8890 (not Verified): first two bytes corrected.
  // https://www.rfc-editor.org/errata/eid8890
  { name: 'B.4 with reported erratum 8890: Brotli content bytes', content: Uint8Array.from([0x0b, 0x09, 0x80, 0x7b, 0x22, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    0x22, 0x3a, 0x20, 0x22, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x22, 0x7d, 0x0a, 0x03]), digest: 'd435Qo+nKZ+gLcUHn7GQtQ72hiBVAgqoLsZnZPiTGPk=' },
];

export const originalBrotliBytes = new Uint8Array(digestVectors.at(-1).content);
originalBrotliBytes[0] = 0x8b; originalBrotliBytes[1] = 0x08;
