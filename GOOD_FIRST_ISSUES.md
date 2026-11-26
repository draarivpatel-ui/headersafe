# Good first issues

Fifteen concrete, scoped tasks for new contributors. Each one lists the file to
change and the tests to add. Claim one by opening an issue before starting work.

## Framework adapters

1. **Fastify plugin.** Add `src/adapters-fastify.mjs` exporting a Fastify plugin
   that calls `applySecurityHeaders(reply.raw)`. Add a test that stubs a reply
   with `setHeader`/`getHeader` and checks every default header.

2. **Koa middleware.** Add `src/adapters-koa.mjs` exporting `koaSecurity(options)`
   returning `async (ctx, next) => { applySecurityHeaders(ctx.res, options); await next(); }`.
   Test that downstream middleware can still override `Content-Type`.

3. **Hono middleware.** Add a Hono-style adapter that calls
   `applySecurityHeaders(c.res.headers, options)` before `next()`. Test with a
   Fetch `Headers` object.

4. **Express static preset.** Add `presets/express.mjs` exporting a config object
   that keeps `X-Frame-Options: SAMEORIGIN` for pages that legitimately embed
   themselves. Test that the preset only changes that one header.

5. **Next.js middleware helper.** Add `presets/next.mjs` exporting
   `nextMiddlewareHeaders(options)` returning a record suitable for
   `NextResponse.next({ headers })`. Test that CSP is report-only when
   `reportOnly` is set.

6. **Cloudflare Workers helper.** Add `presets/workers.mjs` exporting a helper
   that combines `withSecurityHeaders` with `createCorsPolicy` and always emits
   `Vary: Origin`. Test with a constructed `Request`/`Response` pair.

7. **Deno `serve` helper.** Add `presets/deno.mjs` exporting a function that
   merges the bundle into a `ResponseInit`. Test that it does not mutate the
   caller's `headers` object.

8. **Bun `Bun.serve` helper.** Add a preset that returns a `headers` record for
   `Bun.serve({ fetch })`. Test that the returned record is frozen.

## Policy presets

9. **API-only preset.** Add `presets/api.mjs` with `default-src 'none'`,
   `frame-ancestors 'none'`, no `form-action` sources and no `img-src`. Test that
   `auditCsp` reports `ok: true`.

10. **SPA preset with hashed assets.** Add `presets/spa.mjs` that accepts a nonce
    and sets `script-src` and `style-src` accordingly. Test that no
    `'unsafe-inline'` appears unless explicitly requested.

11. **Strict cookie presets.** Add `presets/cookies.mjs` exporting
    `sessionCookie(name, value)` and `csrfCookie(name, value)` using `__Host-`
    and `__Secure-` prefixes. Test both with `auditSetCookie`.

12. **Intranet CORS preset.** Add `presets/cors-intranet.mjs` accepting a list of
    internal domains and producing exact-origin plus subdomain patterns. Test
    that a sibling domain such as `trusted.com.evil.com` is rejected.

13. **GraphQL CORS preset.** Add `presets/cors-graphql.mjs` allowing only
    `POST`, `Content-Type` and an application-specific auth header. Test the
    preflight header set exactly.

14. **HSTS preload preset.** Add `presets/hsts-preload.mjs` exporting a config
    with `maxAge: 63072000`, `includeSubDomains: true` and `preload: true`. Test
    the exact serialized value.

15. **Permissions-Policy privacy preset.** Add `presets/privacy.mjs` that denies
    camera, microphone, geolocation, payment, usb and sensors in one call. Test
    that the output is alphabetically ordered and has no wildcard allowlists.

## General notes

- Add new files under `src/` or `presets/` and export them through `package.json`
  `exports` when they form a public entry point.
- Every task requires at least one deterministic test in `tests/`.
- Regenerate `cjs/index.cjs` only if you edit `src/index.mjs` itself.
- Run `npm test` before opening a pull request.
