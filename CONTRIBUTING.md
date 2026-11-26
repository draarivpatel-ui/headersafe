# Contributing

Thanks for helping improve headersafe. Security headers are easy to get subtly
wrong, so contributions are reviewed with a focus on precise, testable behavior.

## Setup

```sh
npm test
```

There are no dependencies to install. Node 18 or newer is required.

## Repository layout

- `src/index.mjs`: the single source of truth, pure Web Standards JavaScript
- `src/*.mjs`: subpath re-exports for tree-shaking
- `cjs/index.cjs`: generated CommonJS build
- `types/index.d.ts`: strict TypeScript declarations
- `tests/`: deterministic Node test files
- `scripts/build-cjs.mjs`: generator for the CommonJS build

After editing `src/index.mjs`, regenerate the CommonJS build:

```sh
node scripts/build-cjs.mjs
```

Never edit `cjs/index.cjs` by hand. The ESM and CJS outputs must behave
identically, and the parity suite checks this.

## Rules for changes

1. Add a test for every behavior change, including rejected inputs.
2. Keep the core import-free. No `node:` built-ins, no environment globals that
   are absent in Workers or Deno, and no runtime dependencies.
3. Every rejection must throw `HeaderSafeError` with a code from `CODE`.
4. Do not weaken an existing invariant without a documented security rationale.
5. Keep error messages stable where practical; codes are part of the API.
6. Avoid em dashes and en dashes in docs so text stays ASCII friendly.

## Testing

```sh
npm test
```

The suite exercises both `import()` and `require()`, real Node `http.Server`
responses, real Fetch `Headers` and `Response` objects, CSP and cookie audits,
CORS bypass matrices, and injection attempts.

## Pull requests

- Keep changes focused and explain the security impact in the description.
- Reference the issue number when one exists.
- Confirm `npm test` passes on Node 18, 20 and 22 where possible.
- Add a short note to the README only when a public API changes.

## Code of conduct

Be respectful and constructive. Assume good intent, review code rather than
people, and keep discussions tied to reproducible behavior.
