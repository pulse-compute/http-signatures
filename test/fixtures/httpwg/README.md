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
# HMS-03 additions

The internal field-selector parser runs **177 cases** across the original three
files and nine added files. Nothing is silently skipped. Two RFC last-wins cases
are asserted as deliberate subset rejections: `dictionary:duplicate key dictionary`
and `param-list:duplicate parameter with different positions`. Optional-failure
base64 cases follow the HMS-02 decisions. Other successful cases assert exact
upstream canonical text; canonical values also pass through the public base API.

Additional files retrieved 2026-10-15 from `httpwg/structured-field-tests`:

| File | Upstream Git blob SHA |
|---|---|
| boolean.json | e3fc092262b71c00c35f3b98fea097c74306a3cd |
| dictionary.json | 0a7a7dda6c5ffffc47172d239dbf9bede8e8f726 |
| item.json | e86cea0e9a6b360f3377feccd4706f6a2577e03c |
| list.json | c1d047d0fc8e9e3e373ac7ddea04e507e7d474a9 |
| listlist.json | 27cf3a62fde777c7dad3d7285f574e7c24b9ac59 |
| param-dict.json | 5d03c8dcaa3f5742b90d0665c807578856105b7d |
| param-list.json | 04d6859d523505c8cc0399ac82c402b1c8b7b03a |
| param-listlist.json | 937fa4a1b2d8bc9b43b4ae2d2d1079fe0c7a1416 |
| token.json | 001327ba6728fdfccdb97a08ee4c6376914eb552 |

Raw JSON bytes and the existing upstream license are retained unchanged. Dates,
display strings, generated stress corpora and serialization-only suites were
not imported; this is not a claim of passing the entire upstream project.
