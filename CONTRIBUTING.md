# Contributing

This is an experimental reference package. Preserve honest, profile-scoped claims.

- Branch from `main` using `hms-NN/short-description`; open one scoped PR against
  `main`. Maintainers merge after human review. Do not auto-merge or publish.
- Use Node 24.19.0 (`.nvmrc`). Run `npm ci --ignore-scripts --no-audit --no-fund`,
  `npm run check`, and `npm test`. Direct test command: `node --test test/rfc9421.test.js`.
- Keep dependencies explicit. None are needed for the initial six-test reference.
  No formatter/type-checker dependency is imposed on the unchanged spike.
- Keep implementation changes separate from bootstrap. Add exact positive and
  negative vectors when widening protocol behavior; document unsupported cases.
- Include ticket ID, base/head SHAs, changed files, contract owner, commands and
  results, RFC vectors, target/capability status, known failures, next dependency,
  and architecture approval needs in each PR receipt.
- The package owns HTTP parsing/canonicalization and verification policy; crypto
  backends own cryptography; hosts own authoritative context, keys, and time.
- Pulse compiler/host changes require separate PRs against `pulse-compute/pulse`
  `latest` and explicit architectural review. No hidden JS fallback or expanded
  lowerer authority to accommodate this package.

The initial `main` commit is only an anchor for review. The unchanged import is
recorded in `docs/hms-00.md`; keep that baseline traceable if squashing a PR.
Never add real signing keys or production signed messages as fixtures.
