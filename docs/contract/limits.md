# Provisional resource limits

These are package profile choices, **not RFC constants**. All sizes are octets;
strings are measured after the defined encoding, not JS UTF-16 code units.
`node scripts/measure-reference-limits.mjs` reproduces
[the captured measurements](../evidence/hms-01-limits.json) on Node 24.19.0 and
asserts each observation. The probe uses synthetic public keys and inputs.

| Resource | Measured unchanged spike boundary | Proposed v1 ceiling |
|---|---|---|
| Each Signature-Input / Signature field value | 16,384 accepts; 16,385 rejects | 16,384 each, including combined repeated instances |
| One ordinary field value | 16,384 accepts; 16,385 rejects | 16,384 |
| Base bytes | 65,536 accepts; 65,537 rejects | 65,536 |
| Covered components | 32 accepts; 33 rejects | 32 per signature, including every parsed label |
| Instances of one covered field | 16 accepts; 17 rejects | 16 per name per block, checked before joining |
| Signature labels | 8 accepts; 9 rejects | 8 per dictionary |
| Metadata string | 512 accepts; 513 rejects | 512 per string |
| Raw HMAC key bytes | 16 and 4,096 accept; 15 and 4,097 reject | Backend-owned; v1 requires at least 256-bit keys, never raw key input to protocol |
| Total field instances | 129 accepted; no global cap demonstrated | 128 across all supplied header/trailer blocks, including associated request |
| Total input field bytes | Not globally bounded in spike | 131,072 across names and values in all blocks |
| Field-name bytes | No individual spike limit demonstrated | 256 |
| Target input bytes | No safe pre-allocation bound qualified | 16,384 total across supplied method, raw target and URI/parts per request |
| Signature parameters | Six known names in source; not a new measured boundary | 6 per signature |
| Component parameters | Unsupported by spike | 5 per descriptor, subject to combination rules |
| Label bytes | No individual spike limit demonstrated | 64 |
| Authenticator bytes | HMAC implementation requires 32; no new boundary probe | Default 32; HMS-06 explicit maximum 512, exact per algorithm (see revision below) |
| Body bytes | Not inspected by spike | 1,048,576 across supplied message/request bodies; provisional, unmeasured |
| Work units | No global spike work budget | 2,097,152; provisional, unmeasured |

Proposed limits absent from the spike must not be reported as enforced. The
measurement establishes acceptance boundaries only; it does not show bounded
peak allocation, runtime under hostile input, or safe concurrency. In particular,
the spike can allocate before checking limits and can scan unused headers.

## HMS-02 implementation status

The isolated `/fields` API now enforces the envelope-specific ceilings and a
shared logical-work budget. It does not enforce body/target/total-message limits,
which require later integration. [API limits](../signature-fields.md) and
[work measurements](../evidence/hms-02-work.json) distinguish current behavior
from the unchanged spike observations above. The full Profile remains explicit;
the low-level fields primitive has bounded defaults and optional lower ceilings.

## Enforcement contract for later tickets

HMS-03's `/base` now enforces the snapshot field/count/target/base/body-length
ceilings above, together with HMS-02 descriptor limits and shared work charging.
It adds **128 SF members/items per list** and **32 parameters per SF item or inner
list**, reflected in the design types/examples. These deliberately bounded
capacities do not establish generic RFC 8941 parser conformance. See
[the base API](../signature-base.md) and [HMS-03 work measurements](../evidence/hms-03-work.json).
Body bytes are only length-checked by `/base`; HMS-05 `/protocol` separately
copies and hashes content when required.
No body allocation or scan is performed by `/base`.

Profiles explicitly supply every ceiling (see the two JSON examples). Accept
positive safe integers at or below the table; a smaller ceiling is allowed, but
an empty/zero work budget is invalid. Algorithm-fixed sizes remain exact.
Unknown limit names or absent fields are `PROFILE_INVALID`. Widening a ceiling
needs measurements and a contract change, not a runtime flag to bypass checks.

Before scanning/copying, bound array lengths and string/byte lengths; reject
sparse arrays, proxies/accessors or non-plain host containers at the adapter
boundary. Bound the entire envelope, including unselected signatures. Limit
checks happen before allocations and before invoking keys/crypto/body work.
No recursive parser, unbounded regex backtracking, auto key retries or automatic
backend fallback. Index fields once so component lookup does not repeatedly
scan the complete field collection.

Work charging is deterministic: one unit per input/output byte visited or
emitted per pass, plus one per field/component/parameter/label visited. Charge
repeated visits again; check remaining budget before a scan or output append.
This accounts for package parser/canonicalization/digest-byte preparation work,
not backend cryptographic CPU or network latency. HMS-02 must instrument actual
passes and demonstrate normal fixtures fit the budget; adjust the provisional
ceiling with evidence if needed. The body ceiling is not a promise that every
body at that size fits the work budget.

Each operation invokes the clock once, key resolver at most once, signature sign or
verify at most once, digest at most once and replay store at most once. The
trusted host wraps async capabilities with its own deadline/cancellation and
capacity limits. The package cannot preempt a hung JavaScript callback; never
claim that these byte counts provide a wall-clock deadline. Pulse cancellation
and resource semantics are an HMS-07 owner question.

HMS-02/03 qualify parser/base allocation and work, HMS-04 qualifies key/crypto
limits, HMS-05 qualifies bounded content/replay paths, HMS-09 qualifies target
memory and latency. No production limit is declared by HMS-01.

## HMS-04 enforcement

`/protocol` requires every limit explicitly, at or below the `/base` defaults,
with signatureBytes exactly 32. Profile validation, envelope operations, base
construction and output serialization share one logical-work budget. The local
accepted-key list has a schema ceiling of 32 unique nonempty IDs. Raw combined
envelope lengths include joining overhead before normalization; emitted sign
fields must fit per-field and aggregate bytes/counts before invoking crypto.
Tests exercise exact work thresholds and one-below failures for sign/verify.
Backend cryptography and async host work are not package work-counter units.
The explicit Web Crypto adapter separately bounds base inputs to 65,536 bytes,
MACs to 32 bytes and key metadata to 256–32768 bits. These are reference bounds,
not a Native capacity qualification or worst-case resource guarantee.

## HMS-05 enforcement

Required message bodies are length-checked and charged before one private copy,
prior to clock/key callbacks. Associated-request bytes count toward the aggregate
body ceiling but are not copied/hashed as the response's body. `/base` still does
no body scan or allocation, and its recorded work counts remain unchanged.
Digest parsing uses the same remaining budget and SF member/parameter limits.
Combined normalized Content-Digest values are capped by fieldValueBytes (raw
instances and aggregate input bytes are already bounded by snapshot validation).
Digest comparison visits all 32 bytes without an early mismatch return; this is
not a JavaScript constant-time guarantee. No package work can fail a limit check
after successful replay consumption.

The [content work receipt](../evidence/hms-05-work.json) records helper work,
minimum protocol work budgets, one-below rejections and exact capability counts
for 0, 65,536 and 1,048,576 content bytes. The default work ceiling admits these
cases; dense headers/selectors can still exhaust it. The explicit SHA-256 adapter
bounds one input to 1 MiB and owns its own defensive copy. Neither the receipt nor
package counters bound backend cryptographic work, store CPU, wall time or RSS.

## HMS-06 signature capacity revision

The earlier 32-byte signature ceiling is now the unchanged **default**, with an
explicit hard capacity ceiling of 512 bytes. `/fields` exports
`signatureByteCeiling`; `/base` shares the same limit validation. Only
`signatureBytes` can rise above its default. All other byte/count/work ceilings
remain unchanged. Protocol sizes are exact: HMAC 32, P-256 64, and RSA
256/384/512, matched to a 2048/3072/4096-bit key. Every parsed envelope member,
selected or not, must fit the configured signature capacity.

The [HMS-06 work receipt](../evidence/hms-06-work.json) checks eight labels at
64/256/384/512 bytes, exact work success and one-below failure. Eight RSA-4096
signatures contain 4,096 decoded bytes and serialize to 5,526 field bytes;
392,776 envelope work units fit the unchanged default. Protocol sign/verify
thresholds are 10,212/15,793 for the P-256 fixture and 11,966/34,891 for RSA-2048.
A one-below budget fails before crypto. This evidence supports the bounded
capacity change; it is not a target memory, latency or safe-concurrency claim.
See the [algorithm matrix](../algorithms.md) for key constraints and target gates.
