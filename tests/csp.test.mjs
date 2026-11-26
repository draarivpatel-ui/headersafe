import assert from 'node:assert/strict';
import { test } from 'node:test';
import { APIs, esm, throwsCode, STRICT_CSP } from './helpers.mjs';

for (const [label, api] of APIs.map((api, i) => [i === 0 ? 'ESM' : 'CJS', api])) {
  const { buildCsp, parseCsp, auditCsp, generateNonce, CODE } = api;

  test(label + ': buildCsp strict preset denies by default', () => {
    const header = buildCsp({ preset: 'strict' });
    assert.match(header, /default-src 'none'/);
    assert.match(header, /object-src 'none'/);
    assert.match(header, /base-uri 'none'/);
    assert.match(header, /frame-ancestors 'none'/);
    assert.match(header, /upgrade-insecure-requests/);
    assert.equal(header.includes('\n'), false);
    assert.equal(header.includes('\r'), false);
  });

  test(label + ': buildCsp preserves directive ordering', () => {
    const header = buildCsp({ 'img-src': ['https://a.example'], 'default-src': ["'none'"] });
    assert.ok(header.indexOf('default-src') < header.indexOf('img-src'));
    assert.equal(header, "default-src 'none'; img-src https://a.example");
  });

  test(label + ': buildCsp merges string policies', () => {
    const header = buildCsp("default-src 'self'; img-src data:");
    assert.equal(header, "default-src 'self'; img-src data:");
  });

  test(label + ': buildCsp merges array policies', () => {
    const header = buildCsp(["default-src 'self'", "img-src https://cdn.example"]);
    assert.equal(header, "default-src 'self'; img-src https://cdn.example");
  });

  test(label + ': buildCsp merges array policies with boolean directives', () => {
    const header = buildCsp([
      { 'default-src': ["'none'"], 'upgrade-insecure-requests': true },
      'img-src https://cdn.example'
    ]);
    assert.equal(header, "default-src 'none'; img-src https://cdn.example; upgrade-insecure-requests");
  });

  test(label + ': buildCsp honors inline build options in the policy object', () => {
    const header = buildCsp({ preset: 'strict', nonces: 'abcdefgh1234' });
    assert.match(header, /'nonce-abcdefgh1234'/);
    assert.doesNotMatch(header, /(?:^|; )nonces /);
    const audited = auditCsp({ preset: 'strict', nonces: 'abcdefgh1234' });
    assert.equal(audited.ok, true);
    assert.equal(audited.directives.nonces, undefined);
  });

  test(label + ': buildCsp accepts boolean directives', () => {
    const header = buildCsp({ 'upgrade-insecure-requests': true, 'block-all-mixed-content': true });
    assert.equal(header, 'upgrade-insecure-requests; block-all-mixed-content');
  });

  test(label + ': buildCsp rejects CRLF and semicolon injection in directives', () => {
    for (const directive of ['script-src\r\nX-Evil: 1', 'script-src;base-uri', 'img\n-src']) {
      throwsCode(() => buildCsp({ [directive]: ["'self'"] }), CODE.CSP_DIRECTIVE, label + ' directive ' + JSON.stringify(directive));
    }
  });

  test(label + ': buildCsp rejects CRLF and semicolon injection in sources', () => {
    for (const source of ["'self';base-uri *", "https://a.example\r\nX-Evil: 1", "https://x\u0000y"]) {
      const expected = source.includes('\r') || source.includes('\n') || source.includes('\u0000') ? CODE.CRLF : CODE.CSP_SOURCE;
      throwsCode(() => buildCsp({ 'script-src': [source] }), expected, label + ' source ' + JSON.stringify(source));
    }
    throwsCode(() => buildCsp("default-src 'self'; script-src 'self'\r\nX-Evil: 1"), CODE.CRLF, label + ' header CRLF');
    throwsCode(() => buildCsp({ 'script-src': ["'self'č"] }), CODE.HEADER_VALUE, label + ' latin-1 truncation');
    throwsCode(() => parseCsp("default-src 'self'ĊX-Evil: 1"), CODE.HEADER_VALUE, label + ' parsed latin-1 truncation');
  });

  test(label + ': buildCsp rejects comma injection in sources', () => {
    throwsCode(() => buildCsp({ 'script-src': ['https://a.example, https://evil.example'] }), CODE.CSP_SOURCE);
  });

  test(label + ": buildCsp rejects 'none' combined with other sources", () => {
    throwsCode(() => buildCsp({ 'script-src': ["'none'", "'self'"] }), CODE.CSP_SOURCE);
  });

  test(label + ': buildCsp rejects non-string sources', () => {
    throwsCode(() => buildCsp({ 'script-src': [42] }), CODE.CSP_SOURCE);
  });

  test(label + ': buildCsp rejects values on boolean directives', () => {
    throwsCode(() => buildCsp({ 'upgrade-insecure-requests': ['https://x'] }), CODE.CSP_SOURCE);
  });

  test(label + ': buildCsp nonce option produces strict-dynamic policy', () => {
    const header = buildCsp({}, { preset: 'strict', nonces: 'abcdefgh1234' });
    assert.match(header, /script-src .*'nonce-abcdefgh1234'/);
    assert.match(header, /script-src .*'strict-dynamic'/);
    assert.match(header, /style-src .*'nonce-abcdefgh1234'/);
    assert.doesNotMatch(header, /script-src 'none'/);
  });

  test(label + ': buildCsp hash option produces strict-dynamic policy', () => {
    const header = buildCsp({}, { hashes: { algorithm: 'sha256', value: 'YWJjZA==' } });
    assert.match(header, /'sha256-YWJjZA=='/);
    assert.match(header, /'strict-dynamic'/);
  });

  test(label + ': buildCsp rejects malformed hashes and nonces', () => {
    throwsCode(() => buildCsp({}, { nonces: 'short' }), CODE.INVALID_INPUT);
    throwsCode(() => buildCsp({}, { nonces: 'has;evil' }), CODE.INVALID_INPUT);
    throwsCode(() => buildCsp({}, { hashes: "'md5-abc'" }), CODE.CSP_SOURCE);
    throwsCode(() => buildCsp({}, { hashes: { algorithm: 'md5', value: 'abc' } }), CODE.CSP_SOURCE);
  });

  test(label + ': buildCsp accepts base64url hash values', () => {
    assert.match(buildCsp({}, { hashes: { algorithm: 'sha256', value: 'YWJjZA-_' } }), /'sha256-YWJjZA-_'/);
  });

  test(label + ': parseCsp handles repeated directives and casing', () => {
    const parsed = parseCsp("Default-Src 'self'; IMG-SRC data: https://a.example; img-src blob:");
    assert.deepEqual(parsed['default-src'], ["'self'"]);
    assert.deepEqual(parsed['img-src'], ['data:', 'https://a.example', 'blob:']);
  });

  test(label + ': parseCsp rejects injection', () => {
    throwsCode(() => parseCsp("default-src 'self'\r\nX-Evil: 1"), CODE.CRLF);
  });

  test(label + ': auditCsp accepts a strict policy', () => {
    const result = auditCsp(STRICT_CSP);
    assert.equal(result.ok, true);
    assert.equal(result.score, 100);
    assert.deepEqual(result.findings, []);
  });

  test(label + ': auditCsp flags unsafe-inline', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-inline'");
    assert.ok(result.findings.some((f) => f.id === 'UNSAFE_INLINE' && f.severity === 'critical'));
    assert.equal(result.ok, false);
  });

  test(label + ': auditCsp flags unsafe-eval', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'unsafe-eval'");
    assert.ok(result.findings.some((f) => f.id === 'UNSAFE_EVAL' && f.severity === 'critical'));
  });

  test(label + ': auditCsp flags wildcard script-src', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src *");
    assert.ok(result.findings.some((f) => f.id === 'WILDCARD_SCRIPT_SRC'));
  });

  test(label + ': auditCsp flags missing object-src none', () => {
    const missing = auditCsp("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'none'");
    assert.ok(missing.findings.some((f) => f.id === 'MISSING_OBJECT_SRC_NONE'));
    const weak = auditCsp("default-src 'none'; object-src 'self'; base-uri 'none'; frame-ancestors 'none'; script-src 'none'");
    assert.ok(weak.findings.some((f) => f.id === 'MISSING_OBJECT_SRC_NONE'));
  });

  test(label + ': auditCsp flags missing base-uri', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; frame-ancestors 'none'; script-src 'none'");
    assert.ok(result.findings.some((f) => f.id === 'MISSING_BASE_URI'));
  });

  test(label + ': auditCsp flags missing frame-ancestors', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; script-src 'none'");
    assert.ok(result.findings.some((f) => f.id === 'MISSING_FRAME_ANCESTORS'));
  });

  test(label + ': auditCsp flags data: scripts and SHA-1', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src data: 'sha1-abc'");
    assert.ok(result.findings.some((f) => f.id === 'DATA_URI_SCRIPT'));
    assert.ok(result.findings.some((f) => f.id === 'WEAK_HASH_ALGORITHM'));
  });

  test(label + ': auditCsp treats nonce policy as mitigating unsafe-inline', () => {
    const result = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src 'nonce-abcdefgh' 'unsafe-inline'");
    const finding = result.findings.find((f) => f.id === 'UNSAFE_INLINE');
    assert.equal(finding.severity, 'warning');
  });

  test(label + ': auditCsp audits an object policy', () => {
    const result = auditCsp(buildCsp({ preset: 'strict' }, { nonces: 'abcdefgh1234' }));
    assert.equal(result.ok, true);
  });

  test(label + ': auditCsp accepts boolean and string directive values', () => {
    const base = { 'object-src': "'none'", 'base-uri': "'none'", 'frame-ancestors': "'none'", 'form-action': "'self'" };
    const bool = auditCsp({ ...base, 'default-src': "'none'", 'script-src': "'self'", 'upgrade-insecure-requests': true });
    assert.equal(bool.ok, true);
    assert.deepEqual(bool.directives['upgrade-insecure-requests'], []);
    const stringValue = auditCsp({ ...base, 'default-src': "'none'", 'script-src': "'self' 'unsafe-eval'" });
    assert.ok(stringValue.findings.some((f) => f.id === 'UNSAFE_EVAL'));
  });

  test(label + ': auditCsp flags bare scheme sources and script-src-attr', () => {
    const scheme = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src https:");
    assert.ok(scheme.findings.some((f) => f.id === 'SCHEME_WILDCARD_SCRIPT_SRC' && f.severity === 'critical'));
    const attr = auditCsp("default-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; script-src-attr 'unsafe-inline'");
    assert.ok(attr.findings.some((f) => f.id === 'UNSAFE_SCRIPT_SRC_ATTR' && f.severity === 'critical'));
    const frames = auditCsp("default-src 'none'; object-src 'none'; base-uri https:; frame-ancestors https:; form-action https:; script-src 'self'");
    const ids = frames.findings.map((f) => f.id);
    for (const id of ['UNSAFE_BASE_URI', 'WILDCARD_FRAME_ANCESTORS', 'WEAK_FORM_ACTION']) {
      assert.ok(ids.includes(id), 'missing ' + id);
    }
  });

  test(label + ': auditCsp score is clamped between 0 and 100', () => {
    const result = auditCsp("default-src *; object-src *; base-uri *; frame-ancestors *; script-src * 'unsafe-eval' 'unsafe-inline' data:");
    assert.equal(result.score >= 0, true);
    assert.equal(result.ok, false);
  });

  test(label + ': generateNonce returns unique base64 values', () => {
    const a = generateNonce();
    const b = generateNonce();
    assert.notEqual(a, b);
    assert.match(a, /^[A-Za-z0-9+/]{22}$/);
    assert.equal(api.buildCsp({}, { nonces: a }).includes("'nonce-" + a + "'"), true);
  });

  test(label + ': generateNonce validates size', () => {
    for (const bad of [0, 4, 65, 1.5, '16', null]) {
      throwsCode(() => generateNonce(bad), CODE.INVALID_INPUT, label + ' size ' + String(bad));
    }
    assert.equal(generateNonce(8).length, 11);
    assert.equal(generateNonce(32).length, 43);
  });
}

test('CSP audit detects all required unsafe families', () => {
  const weak = "default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval' * http://cdn.example; object-src 'self'";
  const result = esm.auditCsp(weak);
  const ids = result.findings.map((f) => f.id);
  for (const id of ['UNSAFE_INLINE', 'UNSAFE_EVAL', 'WILDCARD_SCRIPT_SRC', 'MISSING_OBJECT_SRC_NONE', 'MISSING_BASE_URI', 'MISSING_FRAME_ANCESTORS']) {
    assert.ok(ids.includes(id), 'missing finding ' + id);
  }
});
