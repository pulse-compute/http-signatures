# Independent Structured Fields fixtures

Source: https://github.com/httpwg/structured-field-tests (IETF HTTP Working Group).
The following original files were retrieved on 2026-10-15 and are preserved
unchanged, with their upstream Git blob IDs:

| File | Git blob SHA |
|---|---|
| binary.json | 79e4ab13bb7db971ca2dcf2470bd4fb82fd85dff |
| string.json | bebfa72a3db6678ff8229b2a8050abb1bffd2273 |
| number.json | f13d401e97174e2999cd98139d6e4531d106b68d |
| LICENSE.md | 93424948182020c2706613b21d22f59910bc6baa |

The upstream IETF Trust license is included alongside the fixtures. These files
are test-only and excluded from the npm artifact by its existing files allowlist.

`test/httpwg-fields.test.js` adapts bare byte items into Signature dictionary
values, string items into keyid parameters, and integer items into created
parameters. It checks all 17 binary, 14 string and 26 selected number cases.
Expected values/canonical encodings come from upstream, not the implementation.

Of the 37 number cases, 3 generic-list cases and 8 valid decimal cases are
excluded explicitly because the envelope subset supports neither. Invalid
number forms still must fail. This does not certify a general RFC 8941 parser.

Upstream `can_fail` cases have an explicit decision: unpadded/partially padded
base64, nonzero pad bits and a split string are accepted/canonicalized; excess
base64 padding is rejected. No test is silently skipped because it fails.
