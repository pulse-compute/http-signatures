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
| Authenticator bytes | HMAC implementation requires 32; no new boundary probe | 32, exact for HMAC-SHA256 |
| Body bytes | Not inspected by spike | 1,048,576 across supplied message/request bodies; provisional, unmeasured |
| Work units | No global spike work budget | 2,097,152; provisional, unmeasured |

Proposed limits absent from the spike must not be reported as enforced. The
measurement establishes acceptance boundaries only; it does not show bounded
peak allocation, runtime under hostile input, or safe concurrency. In particular,
the spike can allocate before checking limits and can scan unused headers.

## Enforcement contract for later tickets

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

Each operation invokes the clock once, key resolver at most once, MAC sign or
verify at most once, digest at most once and replay store at most once. The
trusted host wraps async capabilities with its own deadline/cancellation and
capacity limits. The package cannot preempt a hung JavaScript callback; never
claim that these byte counts provide a wall-clock deadline. Pulse cancellation
and resource semantics are an HMS-07 owner question.

HMS-02/03 qualify parser/base allocation and work, HMS-04 qualifies key/crypto
limits, HMS-05 qualifies bounded content/replay paths, HMS-09 qualifies target
memory and latency. No production limit is declared by HMS-01.
