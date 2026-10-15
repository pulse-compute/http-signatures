# HMS-05 implementation receipt

Ticket: body integrity and defensive verification.
Repository: `pulse-compute/http-signatures`; PR target: `main`; human merge.
Base: `112e03fe8099e044095053f9f7f5f0bcc6b3aadc` (merged HMS-04).
Base tree: `f83b8594faac50e517337babcae57b918a735f74`.
The PR records the final head/tree/CI receipt without self-referential SHA edits.

## Implementation and ownership

- `src/content-integrity.js`: complete bounded digest dictionary validation,
  explicit SHA-256 call and fixed-size comparison over owned content bytes.
- `src/content-digest.js`: additive `/content-digest` helper for explicit field
  generation with byte/work/output preflight; no header mutation or auth claim.
- `src/protocol.js` / `src/profile.js`: enable required digest/replay capabilities,
  mandatory nonce, inclusive safe retention deadline and final atomic consume
  after MAC/body success. No retry, downgrade, rollback or global nonce registry.
- `src/base-engine.js`: copy only the required primary body, before callbacks,
  under existing aggregate byte/work bounds. `/base` still does no body copying.
- `src/structured-field.js`: reuse the bounded SF reader for byte-sequence-only
  digest dictionaries, rejecting duplicates and validating unselected members.
- `src/webcrypto.js`: additive explicit bounded SHA-256 capability factory.
- New content/replay and helper/adapter tests, RFC 9530 vectors and attribution,
  content-work measurement script/receipt, runnable request/response webhook
  example, export checks, CI steps, API and contract/matrix updates.

Package owns content digest syntax, required coverage, checked byte preparation
and replay policy/ordering. Backend owns SHA-256/HMAC. Host owns authentic body
capture, time, nonce generation and atomic durable replay storage across relevant
instances. Test/example stores are local demonstrations, not product adapters.
No dependencies, Pulse core/compiler/ABI changes, publication or deployment.
No architecture approval is needed for this standalone reference work; Native
integration remains separately gated.

Compatibility: root spike and HMS-02 implementation remain unchanged. HMS-03
base outputs/work counts remain byte-identical. Existing HMAC-only profiles
retain their behavior. Two HMS-04 temporary gating tests now assert missing
capability/nonce rejection; required modes are deliberately enabled by HMS-05.
Original request/response JSON profiles now execute without schema changes.

## Acceptance evidence

| Requirement | Evidence |
|---|---|
| Same exact content bytes | Empty, binary, UTF-8, JSON/LF, partial and compressed payloads; reserialization/decompression mutations fail |
| Signed-and-verified body | Request/response round trips; valid MAC with changed body rejected; changed body+digest fails MAC |
| Required coverage | Plain header descriptor required; sf/bs/key/tr/req substitutions and weaker-label coverage union fail |
| Digest grammar | Complete typed dictionary, duplicate algorithm/parameter rejection, malformed base64/length/type, unknown-algorithm no-fallback |
| HTTP ambiguity and injection | Repeated header combination, header/trailer separation, unavailable sources, CRLF/control failures before key calls |
| Atomic replay | 24 concurrent verifications admit one; failures cannot burn nonce; rotation/label do not reopen tuple |
| Time/store semantics | Inclusive age/expiry/skew deadline, optional expiry, future creation, delayed arrival and bounded-store rejection |
| Capability failures and ownership | Invalid result types, fixed/redacted exceptions, no retries, async mutation of bytes/policy/callbacks |
| Bounds | Exact helper/protocol work thresholds, one-below failures, 1 MiB body boundary, associated-request aggregate and dictionary limits |
| Honest scope | Excluded/none flags remain not checked; no authorization, production storage, Fastly or Native qualification claim |

Local result: **758/758 tests pass** on Node 24.19.0 / npm 11.9.0, approximately
0.48 seconds. Includes 609 prior tests (two updated for enabled required modes),
107 content/replay cases and 42 digest/helper/adapter cases. Both examples pass.

```sh
npm ci --ignore-scripts --no-audit --no-fund --offline
npm run check
npm run check:contract
npm test
node examples/hmac.mjs
node examples/webhook.mjs
node scripts/measure-reference-limits.mjs
node scripts/measure-base-work.mjs
node scripts/measure-content-work.mjs
npm pack --dry-run
git diff --check
```

[Content work evidence](evidence/hms-05-work.json) records 0 / 65,536 / 1,048,576
bytes. A 1 MiB body fits these representative sign/verify profiles at minimum
work budgets 1,067,455 / 1,070,019. Successful verify invokes clock, resolver,
MAC, digest and consume exactly once. Counters bound package logical work, not
backend/store CPU, elapsed time, RSS, heap or safe concurrency. Host deadlines
and store durability/capacity remain external qualification obligations.

RFC evidence: RFC 9421 B.2.5 remains passing. RFC 9530 B.1, B.2, B.3 and D
published SHA-256 values pass through explicit Web Crypto and Node createHash.
B.4's displayed Brotli bytes conflict with its published hash; this matches
[reported erratum 8890](https://www.rfc-editor.org/errata/eid8890), not Verified
as of 2026-10-15. Original bytes are retained as a rejection fixture; a separately
labeled proposed correction passes. The implementation does not repair content.
Known failures in the declared implementation subset: none. The original RFC
example inconsistency is tracked explicitly, not counted as a conformance pass.

Next dependencies: HMS-06 additional algorithm/independent interoperability
matrix and HMS-07 read-only Pulse integration investigation. Qualified Native
lowering and production host/store behavior remain later owner/approval gates.
