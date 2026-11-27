# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/headersafe/security/advisories/new). Do not open a public issue for an exploitable finding.

Include:

- the affected version and module format (ESM or CJS)
- a minimal reproduction with the exact input
- the expected and actual header output
- the browser or runtime where the impact was observed

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, release a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure. Fixes are released as patch versions with a regression test added to the deterministic suite.

## Scope

headersafe is a header construction library. Reports are in scope when untrusted
input can produce a header that violates the library's documented invariants,
including:

- CRLF, NUL or control-character injection in any emitted header
- CORS origin acceptance that violates the exact-match or wildcard pattern rules
- wildcard origin combined with credentials
- cookie prefix invariant bypasses
- CSP serialization that introduces an unsafe directive from a safe input
- divergence between the ESM and CommonJS builds

Out of scope: vulnerabilities in a consumer's own request routing, TLS setup,
reverse proxy configuration, or browser behavior that ignores a correctly
formed header.

## Security design notes

The core module has no imports and no runtime dependencies. The CommonJS build
is generated from the same ESM source, so the two formats cannot drift
semantically. Header values pass through a single guard that rejects CR, LF,
NUL and C0/DEL/U+2028/U+2029 control characters. Sensitive headers add stricter
token, semicolon or comma checks before serialization.

All failures throw `HeaderSafeError` with a stable `code` property. Callers
should treat these exceptions as a hard failure of the response, not as input
to be logged and ignored.
