# headersafe

Zero-dependency HTTP security headers for Node.js and Web Standards.

Strict CSP Level 3, hardened CORS, RFC 6265bis cookie prefixes, and a complete
security header bundle in one small package. Works with Node `http.ServerResponse`,
Fetch `Headers` and `Response`, Cloudflare Workers, Deno, Bun, and Next.js Edge.
Ships ESM, CommonJS and strict TypeScript definitions from a single source of truth.

- Zero runtime dependencies and zero `node:` imports in the core
- 239 deterministic tests (verified live with `npm test`), run under both `import()` and `require()`
- Every rejection is a typed `HeaderSafeError` with a stable machine-readable code
- CRLF, control-character, semicolon and non-Latin-1 truncation injection rejected at every boundary

## Install

```sh
npm install headersafe
```

Node 18 or newer. No build step and no peer dependencies.

## Quick start (Node)

```js
import http from 'node:http';
import { applySecurityHeaders } from 'headersafe';

http.createServer((req, res) => {
  applySecurityHeaders(res, {
    hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }
  });
  res.end('ok');
}).listen(3000);
```

The bundle sets `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, a default-deny `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`,
`Cross-Origin-Embedder-Policy`, `X-Frame-Options: DENY`, and a strict CSP.

## Fetch, Workers and Edge

```js
import { withSecurityHeaders, createCorsPolicy } from 'headersafe';

const cors = createCorsPolicy({
  origin: ['https://app.example', 'https://*.admin.example'],
  credentials: true
});

export default withSecurityHeaders(async (request) => {
  const headers = new Headers();
  cors.apply(headers, request.headers.get('origin'));
  return new Response('{"ok":true}', {
    status: 200,
    headers
  });
});
```

`withSecurityHeaders` detects Node responses by their `setHeader`/`getHeader`
pair. Otherwise it wraps the returned `Response` (or awaited promise) and copies
the security headers onto it. Non-Response return values pass through unchanged.

Subpath imports are available for tree-shaking: `headersafe/csp`,
`headersafe/cors`, `headersafe/cookies`, `headersafe/headers` and
`headersafe/adapters`. CommonJS consumers use `require('headersafe')`.

## Express

```js
import express from 'express';
import { withSecurityHeaders, createCorsPolicy } from 'headersafe';

const app = express();
const cors = createCorsPolicy({ origin: 'https://app.example' });

app.use((req, res, next) => {
  cors.apply(res, req.headers.origin);
  next();
});
app.get('/health', withSecurityHeaders((req, res) => res.json({ ok: true })));
```

`apply()` merges `Vary: Origin` with any existing `Vary` value, case-insensitively,
accepting a string or a Node-style array. A `Vary: *` value stays terminal.

## Next.js (Edge and Node middleware)

```js
import { applySecurityHeaders } from 'headersafe';

export function middleware(request) {
  const response = NextResponse.next();
  applySecurityHeaders(response.headers);
  return response;
}
```

## Strict CSP Level 3

```js
import { buildCsp, auditCsp, generateNonce } from 'headersafe';

const nonce = generateNonce();
const csp = buildCsp({ preset: 'strict' }, { nonces: nonce });
// script-src 'self' 'nonce-...' 'strict-dynamic'

const report = auditCsp(csp);
// { ok: true, score: 100, findings: [], directives: { ... } }
```

`buildCsp` rejects CRLF and semicolon injection in directive names and sources,
rejects comma injection and `'none'` combined with other sources, and emits
`'strict-dynamic'` automatically when a nonce or hash is supplied.

`auditCsp` flags `'unsafe-inline'`, `'unsafe-eval'`, wildcard `script-src`,
`data:` script sources, SHA-1 hashes, missing or non-`'none'` `object-src`,
missing `base-uri`, missing `frame-ancestors`, and weak `form-action` and
`default-src` policies. Findings carry `critical`, `warning` or `info` severity
plus a concrete recommendation.

## CORS

```js
import { createCorsPolicy } from 'headersafe';

const policy = createCorsPolicy({
  origin: 'https://trusted.com',
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
  maxAge: 600
});

policy.isAllowed('https://trusted.com.evil.com'); // false
policy.headers('https://trusted.com'); // ACAO + credentials + Vary: Origin
```

Important behaviors:

- `origin: '*'` with `credentials: true` throws `ERR_HEADSAFE_CORS_CONFIG`.
- The `null` origin is rejected unless `allowNullOrigin: true` is set.
- Origins are compared as full scheme plus host plus port values. Substring,
  prefix, userinfo, path and regex-bypass shapes never match.
- `https://*.example.com` matches one or more label prefixes only.
- Reflected origins are checked for CRLF and control characters before output.
- Disallowed origins receive `Vary: Origin` only, with no `Access-Control-Allow-Origin`.

## Cookie hardening

```js
import { serializeSafeCookie, auditSetCookie } from 'headersafe';

const header = serializeSafeCookie('__Host-session', 'tokenValue123', {
  sameSite: 'Strict',
  maxAge: 1800
});
// __Host-session=tokenValue123; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Strict

auditSetCookie('sid=abc; Path=/').findings; // MISSING_SECURE, MISSING_HTTPONLY, MISSING_SAMESITE
```

Enforced invariants:

- `Secure` and `HttpOnly` are on by default.
- `SameSite` is `Lax` by default; `None` requires `Secure`.
- `__Host-` requires `Secure`, `Path=/` and no `Domain`.
- `__Secure-` requires `Secure`.
- Cookie names, values, paths and domains reject CRLF, semicolons and control characters.

## API

| Function | Purpose |
| --- | --- |
| `buildCsp(policy, options)` | Serialize a strict CSP header |
| `parseCsp(header)` | Parse a CSP header into directives |
| `auditCsp(policy)` | Score a policy and list findings |
| `generateNonce(size)` | CSPRNG base64 nonce (8 to 64 bytes) |
| `createCorsPolicy(config)` | Build an origin validator and header emitter |
| `validateCorsOrigin(origin, options)` | Validate and canonicalize one origin |
| `serializeSafeCookie(name, value, options)` | Serialize a hardened `Set-Cookie` |
| `parseSetCookie(header)` | Parse a `Set-Cookie` header |
| `auditSetCookie(header)` | Score a cookie and list findings |
| `buildSecurityHeaders(options)` | Produce the full header record |
| `applySecurityHeaders(target, options)` | Apply the bundle to a response |
| `applyHeaderRecord(target, record, options)` | Apply an arbitrary safe record |
| `withSecurityHeaders(handler, options)` | Wrap a Node or Fetch handler |
| `toFetchHeaders(record, options)` / `fromFetchHeaders(headers)` | Convert between records and Fetch `Headers` |
| `assertSafeHeaderName` / `assertSafeHeaderValue` / `hasCrlf` / `mergeVary` | Low-level header guards |
| `isNodeResponse` / `isFetchHeaders` | Adapter detection |

## Threat model

headersafe protects the server-side header construction boundary. It assumes
callers pass untrusted origins, cookie values and policy fragments through its
validators, and that the runtime itself correctly enforces the emitted headers.

In scope: header injection (CRLF, NUL, control characters, semicolon and comma
smuggling, and code points above U+00FF that a latin-1 encoder would truncate
into CR or LF), CORS origin confusion, unsafe CSP construction, cookie prefix
violations, and misconfigured cross-origin isolation headers.

Out of scope: application authorization, CSRF token management, TLS termination,
proxy or CDN header stripping, browser CSP Level 3 implementation differences,
and attacks that occur after a malicious header has been accepted by the runtime.
Always terminate TLS correctly and verify headers in production with a real browser.

## Development

```sh
npm test
```

The suite is deterministic: no network access, no clock dependence, no snapshot
drift. It runs the full API under both module formats and includes live Node
`http.Server` and Fetch `Headers`/`Response` integration checks.

Regenerate the CommonJS build after editing `src/index.mjs`:

```sh
node scripts/build-cjs.mjs
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md).
Security reports: see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
